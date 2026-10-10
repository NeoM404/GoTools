package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"nedctl/internal/audit"
	"nedctl/internal/change"
	"nedctl/internal/cloud"
	"nedctl/internal/config"
	"nedctl/internal/execx"
	"nedctl/internal/inventory"
	"nedctl/internal/kube"
)

// addOutputFlag registers -o/--output (table|json) on a flag set, both names
// bound to the same variable so either spelling works (kubectl-style -o).
func addOutputFlag(fs *flag.FlagSet) *string {
	out := new(string)
	fs.StringVar(out, "o", "table", "output format: table|json")
	fs.StringVar(out, "output", "table", "output format: table|json")
	return out
}

// writeJSON marshals v as indented JSON to w. Returns exit code.
func writeJSON(w io.Writer, stderr io.Writer, v any) int {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "encoding json: %v\n", err)
		return ExitFailure
	}
	fmt.Fprintln(w, string(b))
	return ExitOK
}

// badOutput reports an invalid -o value.
func badOutput(stderr io.Writer, v string) int {
	fmt.Fprintf(stderr, "invalid output format %q (want: table|json)\n", v)
	return ExitUsage
}

// loadFleet resolves config then loads the inventory from URL (preferred) or
// file. Returns the config too, since callers need prod patterns / target.
func loadFleet(cfgPath string, stderr io.Writer) (config.Config, inventory.Fleet, bool) {
	cfg, used, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return cfg, inventory.Fleet{}, false
	}
	var fleet inventory.Fleet
	switch {
	case cfg.InventoryURL != "":
		fleet, err = inventory.LoadURL(cfg.InventoryURL)
	case cfg.InventoryPath != "":
		fleet, err = inventory.LoadFile(cfg.InventoryPath)
	default:
		hint := "set inventoryPath or inventoryUrl in your config"
		if used != "" {
			hint = fmt.Sprintf("%s (loaded %s)", hint, used)
		}
		fmt.Fprintf(stderr, "no inventory source configured — %s\n", hint)
		return cfg, inventory.Fleet{}, false
	}
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return cfg, inventory.Fleet{}, false
	}
	if err := fleet.Validate(cfg.Environments); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return cfg, inventory.Fleet{}, false
	}
	return cfg, fleet, true
}

func cmdClusters(cfgPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: nedctl clusters <list|get> ...")
		return ExitUsage
	}
	switch args[0] {
	case "list":
		return clustersList(cfgPath, args[1:], stdout, stderr)
	case "get":
		return clustersGet(cfgPath, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown clusters subcommand %q\n", args[0])
		return ExitUsage
	}
}

func clustersList(cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("clusters list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cloudFlag := fs.String("cloud", "", "filter by cloud (aws|azure)")
	envFlag := fs.String("env", "", "filter by environment")
	ownerFlag := fs.String("owner", "", "filter by owner substring")
	output := addOutputFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	if cfg, _, err := config.Load(cfgPath); err == nil && cfg.InventoryURL == "" && cfg.InventoryPath == "" && cfg.AWS.Configured() {
		return liveClusters(cfgPath, cfg, *cloudFlag, *envFlag, *output, stdout, stderr)
	}
	_, fleet, ok := loadFleet(cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	matches := fleet.Filter(*cloudFlag, *envFlag, *ownerFlag)
	if *output == "json" {
		// Always emit an array (never null) so `jq` / scripts are happy.
		if matches == nil {
			matches = []inventory.Cluster{}
		}
		return writeJSON(stdout, stderr, matches)
	}
	if len(matches) == 0 {
		fmt.Fprintln(stdout, "no clusters match")
		return ExitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tCLOUD\tENV\tREGION\tVERSION\tOWNER\tCOST-CENTRE")
	for _, c := range matches {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			c.Name, c.Cloud, c.Environment, c.Region, c.Version, c.Owner, c.CostCentre)
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\n%d cluster(s)\n", len(matches))
	return ExitOK
}

func clustersGet(cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("clusters get", flag.ContinueOnError)
	fs.SetOutput(stderr)
	output := addOutputFlag(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "usage: nedctl clusters get <name> [-o table|json]")
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	_, fleet, ok := loadFleet(cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	c, err := fleet.Find(pos[0])
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return ExitFailure
	}
	if *output == "json" {
		return writeJSON(stdout, stderr, c)
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "Name:\t%s\n", c.Name)
	fmt.Fprintf(tw, "Cloud:\t%s\n", c.Cloud)
	fmt.Fprintf(tw, "Environment:\t%s\n", c.Environment)
	fmt.Fprintf(tw, "Region:\t%s\n", c.Region)
	fmt.Fprintf(tw, "Version:\t%s\n", c.Version)
	fmt.Fprintf(tw, "Owner:\t%s\n", c.Owner)
	fmt.Fprintf(tw, "Cost centre:\t%s\n", c.CostCentre)
	if c.Cloud == inventory.AWS {
		fmt.Fprintf(tw, "Account:\t%s\n", c.Account)
	}
	if c.Cloud == inventory.Azure {
		fmt.Fprintf(tw, "Subscription:\t%s\n", c.Subscription)
		fmt.Fprintf(tw, "Resource group:\t%s\n", c.ResourceGroup)
	}
	tw.Flush()
	return ExitOK
}

// parseInterspersed parses flags that may appear before OR after positional
// args (the Go flag package stops at the first positional by default). It
// returns the collected positionals.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		positionals = append(positionals, args[0])
		args = args[1:]
	}
	return positionals, nil
}

func cmdKubeconfig(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	code, _ := fetchCredentials(ctx, cfgPath, "kubeconfig", args, stdout, stderr)
	return code
}

// fetched is what a successful fetchCredentials resolved, for login.
type fetched struct {
	cfg     config.Config
	cluster inventory.Cluster
}

// fetchCredentials implements `kubeconfig` and `login`: resolve the cluster,
// apply change control, record the access, verify the cloud identity, then
// fetch. The order is deliberate — nothing reaches the cloud unless the
// access is permitted and on record.
func fetchCredentials(ctx context.Context, cfgPath, name string, args []string, stdout, stderr io.Writer) (int, *fetched) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fileFlag := fs.String("file", "", "write to an isolated kubeconfig file instead of the default")
	dryRun := fs.Bool("dry-run", false, "print the CLI command without running it")
	crFlag := fs.String("change-record", "", "change record authorising this access (e.g. CHG0012345)")
	glassFlag := fs.String("break-glass", "", "emergency access without a change record; the reason is recorded and flagged")
	ctxFlag := fs.String("context", "", "bastion mode: which of the cluster's kube-contexts to use, when it has several")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage, nil
	}
	if len(pos) != 1 {
		fmt.Fprintf(stderr, "usage: nedctl %s <cluster> [--file PATH] [--dry-run] [--change-record CHG…|--break-glass REASON]\n", name)
		return ExitUsage, nil
	}
	cfg, fleet, ok := loadFleet(cfgPath, stderr)
	if !ok {
		return ExitFailure, nil
	}
	c, err := fleet.Find(pos[0])
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return ExitFailure, nil
	}
	if code := checkModeFlags(cfg, name, *fileFlag, *ctxFlag, stderr); code != ExitOK {
		return code, nil
	}
	var hostCtx kube.HostContext
	if cfg.Bastion() {
		if hostCtx, err = bastionContext(ctx, fleet, c, *ctxFlag); err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", name, err)
			return ExitFailure, nil
		}
		if *dryRun {
			fmt.Fprintln(stdout, "kubectl config use-context "+hostCtx.Name)
			return ExitOK, &fetched{cfg, c}
		}
	}
	file := *fileFlag
	if file == "" && cfg.KubeconfigDir != "" {
		file = cfg.KubeconfigDir + "/" + c.Name + ".kubeconfig"
	}
	opts := cloud.KubeconfigOptions{File: file, DryRun: *dryRun, Stdout: stdout, Stderr: stderr, Timeout: cfg.Timeout()}
	if *dryRun {
		cmdArgs, err := cloud.UpdateKubeconfig(ctx, c, opts)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", name, err)
			return ExitFailure, nil
		}
		fmt.Fprintln(stdout, strings.Join(cmdArgs, " "))
		return ExitOK, &fetched{cfg, c}
	}

	cr, glass := strings.TrimSpace(*crFlag), strings.TrimSpace(*glassFlag)
	switch {
	case cr != "" && glass != "":
		fmt.Fprintln(stderr, "use --change-record or --break-glass, not both")
		return ExitUsage, nil
	case glass != "" && len(glass) < config.MinBreakGlassReason:
		fmt.Fprintf(stderr, "--break-glass needs a real reason (at least %d characters): it is recorded and reviewed\n", config.MinBreakGlassReason)
		return ExitUsage, nil
	case cr != "":
		if err := change.ValidateFormat(cr, cfg.ChangeControl.Pattern); err != nil {
			fmt.Fprintln(stderr, err)
			return ExitUsage, nil
		}
	}

	// Every credential fetch is recorded before it happens; if the record
	// cannot be written, the fetch does not happen. Refused attempts are
	// recorded too.
	production := cfg.IsProdEnvironment(c.Environment) || kube.IsProd(c.Name, cfg.ProdPatterns)
	action := "credentials"
	if cfg.Bastion() {
		action = "use-context"
	}
	tr, err := beginAudit(ctx, cfg, action, &c, production, changeInfo{record: cr, breakGlassReason: glass}, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing to fetch credentials: every credential fetch must be recorded\n", err)
		return ExitFailure, nil
	}
	if code := applyChangeControl(ctx, cfg, c, cr, glass, tr, stderr); code != ExitOK {
		return code, nil
	}
	if cfg.Bastion() {
		return useHostContext(ctx, cfg, c, hostCtx, tr, stdout, stderr)
	}

	// Confirm the CLI will act in the cluster's own account/subscription:
	// otherwise a same-named cluster elsewhere could be fetched and labelled
	// as this one.
	id, err := cloud.VerifyIdentity(ctx, c, cfg.Timeout())
	if err != nil {
		var wrong *cloud.ErrWrongAccount
		if errors.As(err, &wrong) {
			tr.end(ctx, audit.OutcomeRefused, wrong.Principal, err.Error(), stderr)
			fmt.Fprintf(stderr, "%s refused: %v\n", name, err)
			return ExitFailure, nil
		}
		tr.end(ctx, audit.OutcomeFailure, "", err.Error(), stderr)
		reportCLIFailure(stderr, c, err)
		return ExitFailure, nil
	}

	if _, err := cloud.UpdateKubeconfig(ctx, c, opts); err != nil {
		tr.end(ctx, audit.OutcomeFailure, id.Principal, err.Error(), stderr)
		reportCLIFailure(stderr, c, err)
		return ExitFailure, nil
	}
	tr.end(ctx, audit.OutcomeSuccess, id.Principal, "", stderr)

	fmt.Fprintf(stdout, "credentials for %q ready", c.Name)
	if file != "" {
		fmt.Fprintf(stdout, " in %s (use: KUBECONFIG=%s kubectl ...)", file, file)
	} else {
		fmt.Fprint(stdout, " — run `nedctl current` to confirm the active context")
	}
	fmt.Fprintln(stdout)

	// Drift hint: if the cloud CLI stamped a removed exec-auth apiVersion, the
	// kubeconfig will fail against a modern cluster. Warn (stderr) so scripting
	// stays clean. Best-effort — skip silently if kubectl can't be inspected.
	if ver, verr := kube.ExecAuthAPIVersion(ctx, file); verr == nil && kube.IsDeprecatedExecAPIVersion(ver) {
		fmt.Fprintf(stderr, "⚠  kubeconfig uses a deprecated auth plugin apiVersion (%s) — "+
			"update your %s CLI and run `nedctl doctor`.\n", ver, cliForCloud(c.Cloud))
	}
	return ExitOK, &fetched{cfg, c}
}

// checkModeFlags rejects flags that do not apply in the configured mode, and
// `kubeconfig` on a bastion, where nedctl never fetches credentials.
func checkModeFlags(cfg config.Config, name, file, context string, stderr io.Writer) int {
	switch {
	case cfg.Bastion() && name == "kubeconfig":
		fmt.Fprintln(stderr, "this host is a bastion (config mode \"bastion\"): its credentials are provisioned by the platform and nedctl does not fetch any — use `nedctl login <cluster>` to select them")
		return ExitUsage
	case cfg.Bastion() && file != "":
		fmt.Fprintln(stderr, "--file does not apply on a bastion: login selects a context in the existing kubeconfig")
		return ExitUsage
	case !cfg.Bastion() && context != "":
		fmt.Fprintln(stderr, "--context applies only in bastion mode")
		return ExitUsage
	}
	return ExitOK
}

// bastionContext finds the kube-context the platform provisioned for c. It
// refuses to guess: no match, an ambiguous match, or a --context that does
// not belong to c is an error.
func bastionContext(ctx context.Context, fleet inventory.Fleet, c inventory.Cluster, want string) (kube.HostContext, error) {
	k, err := kube.View(ctx)
	if err != nil {
		return kube.HostContext{}, fmt.Errorf("reading the kubeconfig: %w", err)
	}
	found := kube.ContextsFor(k, fleet, c)
	names := make([]string, len(found))
	for i, h := range found {
		names[i] = h.Name
	}
	if want != "" {
		for _, h := range found {
			if h.Name == want {
				return h, nil
			}
		}
		if len(found) == 0 {
			return kube.HostContext{}, fmt.Errorf("context %q does not belong to %s, and no context on this host does", want, c.Name)
		}
		return kube.HostContext{}, fmt.Errorf("context %q does not belong to %s (its contexts: %s)", want, c.Name, strings.Join(names, ", "))
	}
	switch len(found) {
	case 0:
		return kube.HostContext{}, fmt.Errorf("no kube-context for %s on this host — its credentials are not provisioned here, "+
			"or no context identifies it by context name, cluster entry or clusterUser_<resourceGroup>_<name> user", c.Name)
	case 1:
		return found[0], nil
	}
	return kube.HostContext{}, fmt.Errorf("%d contexts belong to %s (%s) — choose one with --context", len(found), c.Name, strings.Join(names, ", "))
}

// useHostContext completes a bastion login: switch to the context and close
// the audit record. The kubeconfig user is recorded as the principal; when it
// is a shared AKS local account the record says so, because the cluster's own
// audit log cannot tell the operators using it apart.
func useHostContext(ctx context.Context, cfg config.Config, c inventory.Cluster, h kube.HostContext, tr *trail, stdout, stderr io.Writer) (int, *fetched) {
	principal := "kubeconfig-user:" + h.User
	if err := kube.UseContext(ctx, h.Name); err != nil {
		tr.end(ctx, audit.OutcomeFailure, principal, err.Error(), stderr)
		fmt.Fprintf(stderr, "login failed: %v\n", err)
		return ExitFailure, nil
	}
	detail := "selected kube-context " + h.Name
	if h.SharedLocalAccount() {
		detail += "; it authenticates as a shared AKS local account, so the cluster audit log cannot attribute actions to this operator"
	}
	tr.end(ctx, audit.OutcomeSuccess, principal, detail, stderr)
	fmt.Fprintf(stdout, "switched to context %q for %q\n", h.Name, c.Name)
	return ExitOK, &fetched{cfg, c}
}

// newChangeChecker builds the ServiceNow client; tests replace it to reach a
// TLS test server.
var newChangeChecker = func(s config.ServiceNowConfig, token string) *change.ServiceNow {
	return &change.ServiceNow{Instance: s.InstanceURL, Token: token, Scheme: s.Scheme,
		AllowedStates: s.AllowedStates, Timeout: s.SNOWTimeout()}
}

// applyChangeControl enforces the change-record policy for one access. It
// ends the audit trail itself when it refuses. Fail closed: if a required
// record cannot be verified, access is refused — break-glass exists for
// emergencies.
func applyChangeControl(ctx context.Context, cfg config.Config, c inventory.Cluster, cr, glass string, tr *trail, stderr io.Writer) int {
	cc := cfg.ChangeControl
	refuse := func(msg string) int {
		tr.end(ctx, audit.OutcomeRefused, "", msg, stderr)
		fmt.Fprintln(stderr, "access refused: "+msg)
		return ExitFailure
	}
	switch {
	case glass != "":
		fmt.Fprintf(stderr, "\n⚠  BREAK-GLASS access to %q (%s) without a change record.\n   Reason: %s\n   This access is recorded and flagged for review.\n\n", c.Name, c.Environment, glass)
		return ExitOK
	case !cc.On():
		if cr != "" {
			fmt.Fprintf(stderr, "note: change control is switched off (changeControl.enabled=false) — %s is recorded but not verified\n", cr)
		} else if cc.Listed(c.Environment) {
			fmt.Fprintf(stderr, "note: change control is switched off (changeControl.enabled=false), so no change record is required for %s\n", c.Environment)
		}
		return ExitOK
	case cr == "" && cc.Requires(c.Environment):
		return refuse(fmt.Sprintf("a change record is required for %s clusters — pass --change-record CHG… (or --break-glass \"<reason>\" in an emergency)", c.Environment))
	case cr == "":
		return ExitOK
	case cc.ServiceNow.InstanceURL == "":
		fmt.Fprintf(stderr, "note: change record %s was format-checked only — configure changeControl.serviceNow to verify it\n", cr)
		return ExitOK
	}
	token := os.Getenv(cc.ServiceNow.TokenEnv)
	if token == "" {
		return refuse(fmt.Sprintf("cannot verify change record %s: $%s is empty (or use --break-glass in an emergency)", cr, cc.ServiceNow.TokenEnv))
	}
	rec, err := newChangeChecker(cc.ServiceNow, token).Check(ctx, cr, now())
	switch {
	case change.IsRejection(err):
		return refuse(err.Error())
	case err != nil:
		return refuse(fmt.Sprintf("could not verify change record %s: %v (use --break-glass in an emergency)", cr, err))
	}
	tr.base.ChangeVerified = true
	fmt.Fprintf(stderr, "change record %s verified: %s — %s, window until %s UTC\n", rec.Number, rec.Summary, rec.State, rec.WindowEnd)
	return ExitOK
}

// reportCLIFailure prints a cloud CLI failure, with a doctor hint when the
// cause could be a missing or outdated CLI.
func reportCLIFailure(stderr io.Writer, c inventory.Cluster, err error) {
	fmt.Fprintf(stderr, "kubeconfig failed: %v\n", err)
	var notFound *execx.NotFoundError
	if !errors.As(err, &notFound) && !errors.Is(err, execx.ErrInterrupted) {
		fmt.Fprintf(stderr, "→ if this looks like a CLI/version problem, run `nedctl doctor` (check your %s CLI)\n", cliForCloud(c.Cloud))
	}
}

func cliForCloud(c inventory.Cloud) string {
	if c == inventory.Azure {
		return "az"
	}
	return "aws"
}

func cmdLogin(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	code, f := fetchCredentials(ctx, cfgPath, "login", args, stdout, stderr)
	if code != ExitOK || f == nil {
		return code
	}
	if f.cfg.IsProdEnvironment(f.cluster.Environment) || kube.IsProd(f.cluster.Name, f.cfg.ProdPatterns) {
		fmt.Fprintf(stdout, "\n⚠  %q is a PRODUCTION cluster. Changes require a change record.\n", f.cluster.Name)
	}
	return ExitOK
}

// contextStatus is the machine-readable shape shared by guard and current,
// so scripts parse one schema regardless of which command they call.
type contextStatus struct {
	Context     string   `json:"context"`
	Production  bool     `json:"production"`
	Cluster     string   `json:"cluster,omitempty"`     // inventory cluster the context resolves to
	Environment string   `json:"environment,omitempty"` // that cluster's environment
	Reasons     []string `json:"reasons"`               // why it is (or is not) production
}

// resolveContext loads config, reads the current kube-context and classifies
// it using both the inventory and the name patterns.
func resolveContext(ctx context.Context, cfgPath string, stderr io.Writer) (contextStatus, bool) {
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return contextStatus{}, false
	}
	k, err := kube.ViewCurrent(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "could not read current kube-context: %v\n", err)
		return contextStatus{}, false
	}
	cl := kube.ClassifyCurrent(k, guardFleet(cfg, stderr), cfg.ProdEnvs(), cfg.ProdPatterns)
	return contextStatus{Context: k.CurrentContext, Production: cl.Production, Cluster: cl.Cluster,
		Environment: cl.Environment, Reasons: cl.Reasons}, true
}

// guardFleet loads the inventory for context classification without ever
// failing the command: guard must keep working (on name patterns) when the
// inventory is unreachable or broken, and it says so on stderr. A URL
// inventory is served from the local cache so a shell prompt stays fast.
func guardFleet(cfg config.Config, stderr io.Writer) *inventory.Fleet {
	var (
		fleet inventory.Fleet
		err   error
	)
	switch {
	case cfg.InventoryURL != "":
		var dir string
		if dir, err = inventory.DefaultCacheDir(); err == nil {
			var src inventory.Source
			fleet, src, err = inventory.LoadURLCached(cfg.InventoryURL, dir, cfg.CacheTTL())
			if err == nil && src.Kind == "stale-cache" {
				fmt.Fprintf(stderr, "warning: using cached inventory from %s ago — refresh failed: %s\n",
					src.Age.Round(time.Second), src.FetchErr)
			}
		}
	case cfg.InventoryPath != "":
		fleet, err = inventory.LoadFile(cfg.InventoryPath)
	default:
		return nil // no inventory configured: name patterns only, by design
	}
	if err == nil {
		err = fleet.Validate(cfg.Environments)
	}
	if err != nil {
		fmt.Fprintf(stderr, "warning: inventory unavailable, classifying by name patterns only: %v\n", err)
		return nil
	}
	return &fleet
}

func reasonSuffix(st contextStatus) string {
	if len(st.Reasons) == 0 {
		return ""
	}
	return "  (" + strings.Join(st.Reasons, "; ") + ")"
}

func cmdGuard(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("guard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	block := fs.Bool("block", false, "exit 3 (not 0) when the current context is production")
	output := addOutputFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	st, ok := resolveContext(ctx, cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	if *output == "json" {
		if rc := writeJSON(stdout, stderr, st); rc != ExitOK {
			return rc
		}
	} else if st.Production {
		fmt.Fprintf(stdout, "PROD  %s%s\n", st.Context, reasonSuffix(st))
	} else {
		fmt.Fprintf(stdout, "ok    %s\n", st.Context)
	}
	if st.Production && *block {
		return ExitProdContext
	}
	return ExitOK
}

func cmdCurrent(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("current", flag.ContinueOnError)
	fs.SetOutput(stderr)
	output := addOutputFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	st, ok := resolveContext(ctx, cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	if *output == "json" {
		return writeJSON(stdout, stderr, st)
	}
	status := "non-prod"
	if st.Production {
		status = "PRODUCTION"
	}
	fmt.Fprintf(stdout, "context: %s\nstatus:  %s\n", st.Context, status)
	if st.Cluster != "" {
		fmt.Fprintf(stdout, "cluster: %s (%s)\n", st.Cluster, st.Environment)
	}
	for _, r := range st.Reasons {
		fmt.Fprintf(stdout, "reason:  %s\n", r)
	}
	return ExitOK
}

// liveClusters answers `clusters list` from AWS when there is no fleet
// inventory: the EKS clusters of the account signed in to, in every region
// they are found in.
func liveClusters(_ string, cfg config.Config, cloud, env, output string, stdout, stderr io.Writer) int {
	if cloud != "" && !strings.EqualFold(cloud, "aws") {
		fmt.Fprintln(stderr, "no inventory is configured, so only the AWS account you are signed in to can be listed")
		return ExitFailure
	}
	ctx := context.Background()
	pc, ok := loadProfileContext(ctx, cfg, "", stderr)
	if !ok {
		return ExitFailure
	}
	rows, searched, err := searchRegions(ctx, cfg, pc, regionSearch{}, "eks", stderr, func(region string) ([]eksAuthRow, error) {
		return authRows(ctx, cfg, pc.Name, region)
	})
	if err != nil {
		fmt.Fprintf(stderr, "listing clusters with %s: %v\n", pc.Name, err)
		return ExitFailure
	}
	if env != "" && !strings.EqualFold(env, pc.Environment) {
		rows = nil
	}
	for i := range rows {
		rows[i].Account, rows[i].Environment = pc.AccountID, pc.Environment
	}
	if output == "json" {
		if rows == nil {
			rows = []eksAuthRow{}
		}
		return writeJSON(stdout, stderr, rows)
	}
	if len(rows) == 0 {
		fmt.Fprintf(stdout, "no EKS clusters in %s (searched %s)\n", pc.label(), strings.Join(searched, ", "))
		return ExitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tENV\tACCOUNT\tREGION\tVERSION\tENDPOINT\tAUTH MODE")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Cluster, dash(r.Environment), dash(r.Account), r.Region, r.Version, r.Endpoint, r.AuthMode)
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\n%d cluster(s) in %s, live from AWS (no inventory configured) · connect with: nedctl kube <name>\n", len(rows), pc.label())
	return ExitOK
}
