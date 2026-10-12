package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/httpx"
	"nedctl/internal/tools"
	"nedctl/internal/ui"
)

// doctorTool is one row of `doctor -o json`.
type doctorTool struct {
	Name       string `json:"name"`
	Required   bool   `json:"required"`
	Status     string `json:"status"` // ok | missing | outdated
	Version    string `json:"version,omitempty"`
	MinVersion string `json:"minVersion,omitempty"`
	Purpose    string `json:"purpose"`
	Install    string `json:"install"`
}

// doctorReport is the `doctor -o json` document. Healthy mirrors the exit code
// (true ⇔ exit 0 under the same flags), so a CI step can read either.
type doctorReport struct {
	Healthy bool          `json:"healthy"`
	Strict  bool          `json:"strict"`
	Tools   []doctorTool  `json:"tools"`
	Checks  []doctorCheck `json:"checks"`
}

// doctorCheck is one environment check: config, network, sign-in.
type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | info | warn | fail
	Detail string `json:"detail"`
}

// ssmProbe is how doctor reaches the Session Manager messaging endpoint
// (the SSO region stands in for the clusters' region); a seam for tests.
var ssmProbe = func(region string) (*http.Client, string) {
	return httpx.Client(8*time.Second, nil), "https://ssmmessages." + region + ".amazonaws.com/"
}

// ssmRouteHint is what to check when a Session Manager shell or tunnel
// does not open although listing instances works: the plugin's websocket
// to ssmmessages goes through the proxy too.
func ssmRouteHint() string {
	msg := "→ listing instances only needs the EC2 API; shells and tunnels also need the Session Manager plugin to reach ssmmessages.<region>.amazonaws.com — `nedctl doctor` checks that route and your proxy variables\n"
	if len(proxyConsistency()) > 0 {
		msg += "→ HTTPS_PROXY and https_proxy differ here: the plugin uses HTTPS_PROXY — make them the same\n"
	}
	return msg + "→ meanwhile `nedctl shell --via legacy` uses your existing tool and its own route\n"
}

// redactProxy hides a proxy URL's password.
func redactProxy(p string) string {
	if u, err := url.Parse(p); err == nil {
		return u.Redacted()
	}
	return "(unparsable)"
}

// proxyConsistency warns when the capital and lower-case proxy variables
// disagree: Go programs (nedctl, kubectl, the Session Manager plugin) read
// HTTPS_PROXY first, the AWS CLI lets https_proxy win — so one works and
// the other is refused (407) or times out.
func proxyConsistency() []doctorCheck {
	var cs []doctorCheck
	for _, pair := range [][2]string{{"HTTPS_PROXY", "https_proxy"}, {"HTTP_PROXY", "http_proxy"}, {"NO_PROXY", "no_proxy"}} {
		up, low := os.Getenv(pair[0]), os.Getenv(pair[1])
		if up == "" || low == "" || up == low {
			continue
		}
		detail := fmt.Sprintf("%s and %s differ — Go tools (nedctl, kubectl, Session Manager) use %s, the AWS CLI uses %s; make them the same", pair[0], pair[1], pair[0], pair[1])
		if pair[0] != "NO_PROXY" {
			detail = fmt.Sprintf("%s=%s but %s=%s — Go tools (nedctl, kubectl, Session Manager) use the first, the AWS CLI the second; make them the same",
				pair[0], redactProxy(up), pair[1], redactProxy(low))
		}
		cs = append(cs, doctorCheck{"proxy variables", "warn", detail})
	}
	return cs
}

// portalProbe is how doctor reaches the Identity Center portal; a seam for
// tests.
var portalProbe = func(region string) (*http.Client, string) {
	return httpx.Client(8*time.Second, nil), "https://portal.sso." + region + ".amazonaws.com/"
}

// environmentChecks diagnoses what stopped the first real runs: a broken
// config, a missing proxy or corporate CA, an expired sign-in.
func environmentChecks(ctx context.Context, cfg config.Config, used string, cfgErr error, offline bool) []doctorCheck {
	var cs []doctorCheck
	add := func(name, status, detail string) { cs = append(cs, doctorCheck{name, status, detail}) }
	switch {
	case cfgErr != nil:
		add("config", "fail", cfgErr.Error())
		return cs
	case config.OrgDefaultsErr() != nil:
		add("config", "fail", config.OrgDefaultsErr().Error()+" — this build is broken; get a fresh release")
	case used == "" && config.HasOrgDefaults():
		add("config", "ok", "built-in organisation settings (no file needed)")
	case used == "":
		add("config", "info", "no config file — run `nedctl setup`")
	default:
		add("config", "ok", used)
	}
	if p := firstNonBlank(os.Getenv("HTTPS_PROXY"), os.Getenv("https_proxy")); p != "" {
		add("proxy", "ok", redactProxy(p))
	} else {
		add("proxy", "info", "HTTPS_PROXY not set: connecting directly")
	}
	cs = append(cs, proxyConsistency()...)
	switch bundle := os.Getenv("AWS_CA_BUNDLE"); {
	case bundle == "":
		add("aws ca bundle", "info", "AWS_CA_BUNDLE not set: the AWS CLI trusts only its own CA list — behind a TLS-inspecting proxy, export it (in ~/.bashrc) as the corporate root CA bundle")
	default:
		if _, err := os.Stat(bundle); err != nil {
			add("aws ca bundle", "fail", "AWS_CA_BUNDLE="+bundle+": "+err.Error())
		} else {
			add("aws ca bundle", "ok", bundle)
		}
	}
	if !cfg.AWS.Configured() {
		add("aws sign-in", "info", "aws.startUrl not set — AWS commands are off; run `nedctl setup`")
		return cs
	}
	add("aws sign-in", "ok", cfg.AWS.StartURL+" ("+cfg.AWS.SSORegion+")")
	if !offline {
		client, target := portalProbe(cfg.AWS.SSORegion)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err == nil {
			var resp *http.Response
			if resp, err = client.Do(req); err == nil {
				resp.Body.Close() // any HTTP answer means the portal is reachable
			}
		}
		if err != nil {
			add("identity center portal", "fail", strings.TrimRight(err.Error()+"\n"+networkHint(err), "\n"))
		} else {
			add("identity center portal", "ok", "reachable")
		}
		// Session Manager shells and tunnels need a websocket to
		// ssmmessages; listing instances working says nothing about it.
		if cfg.AWS.Configured() {
			client, target := ssmProbe(cfg.AWS.SSORegion)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err == nil {
				var resp *http.Response
				if resp, err = client.Do(req); err == nil {
					resp.Body.Close()
				}
			}
			if err != nil {
				add("session manager endpoint", "fail", strings.TrimRight(target+": "+err.Error()+"\n→ shells and tunnels (nedctl shell, kube, connect) open a websocket here; --via legacy uses your Windows tool and its own route\n"+networkHint(err), "\n"))
			} else {
				add("session manager endpoint", "ok", target+" reachable")
			}
		}
	}
	if left, ok := signInLeft(cfg.AWS.Session()); !ok {
		add("signed in", "info", "not yet — run `nedctl aws login`")
	} else if left <= 0 {
		add("signed in", "warn", "sign-in expired — run `nedctl aws login`")
	} else {
		add("signed in", "ok", "valid for "+left.Round(time.Minute).String())
	}
	if noLocalBrowser() {
		add("sign-in method", "info", "no local browser (WSL, SSH or headless): aws login uses a device code")
	}
	return cs
}

func toolStatus(r tools.Result) string {
	switch {
	case !r.Found:
		return "missing"
	case r.Outdated:
		return "outdated"
	default:
		return "ok"
	}
}

func cmdDoctor(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	strict := fs.Bool("strict", false, "exit 1 if any tool with a floor is below it (for CI)")
	offline := fs.Bool("offline", false, "skip the network check")
	all := fs.Bool("all", false, "list every optional tool, not only required ones and problems")
	hygiene := fs.Bool("hygiene", false, "check this machine for risky leftovers: AWS keys, static kubeconfig credentials, unprotected SSH keys, secrets in shell history")
	output := addOutputFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	if *hygiene {
		return doctorHygiene(stdout, stderr, *output)
	}

	// Config is optional; used only for minVersions overrides. Ignore errors so
	// doctor always runs (its job is to diagnose a broken setup).
	cfg, used, cfgErr := config.Load(cfgPath)
	var notRequired []string
	switch {
	case cfg.Bastion():
		// Credentials are provisioned on a bastion; nedctl needs only kubectl.
		notRequired = []string{"aws", "az"}
	case !cfg.AWS.Configured() && cfg.Azure.Configured() && len(cfg.Discovery.Azure) == 0:
		// Azure through the bastions only: SSH, no cloud CLI.
		notRequired = []string{"aws", "az"}
	case (cfg.AWS.Configured() || cfg.Azure.Configured()) && len(cfg.Discovery.Azure) == 0:
		// Nothing it runs needs the Azure CLI: AKS is reached on the bastions.
		notRequired = []string{"az"}
	}
	results := tools.Inspect(ctx, cfg.MinVersions, notRequired...)
	for i := range results {
		switch {
		case results[i].Name == "session-manager-plugin" && cfg.AWS.Configured():
			results[i].Required = true // shell, connect and kube cannot work without it
		case results[i].Name == "ssh" && cfg.Azure.Configured():
			results[i].Required = true // the azure commands go through it
		}
	}
	checks := environmentChecks(ctx, cfg, used, cfgErr, *offline)
	if cfgErr == nil && cfg.Azure.Configured() {
		checks = append(checks, azureChecks(ctx, cfg, *offline)...)
	}

	missing := tools.MissingRequired(results)
	outdatedReq := tools.OutdatedRequired(results)
	outdatedAll := tools.AnyOutdated(results)

	// Exit policy: a missing REQUIRED tool always fails. An outdated REQUIRED
	// tool fails too (nedctl's own commands may misbehave). --strict escalates
	// ANY outdated tool (incl. optional) to a failure, for a CI hygiene gate.
	code := ExitOK
	if len(missing) > 0 || len(outdatedReq) > 0 || (*strict && len(outdatedAll) > 0) {
		code = ExitFailure
	}
	for _, c := range checks {
		if c.Status == "fail" {
			code = ExitFailure
		}
	}

	if *output == "json" {
		rep := doctorReport{Healthy: code == ExitOK, Strict: *strict, Tools: make([]doctorTool, 0, len(results)), Checks: checks}
		for _, r := range results {
			rep.Tools = append(rep.Tools, doctorTool{
				Name: r.Name, Required: r.Required, Status: toolStatus(r),
				Version: r.Detected, MinVersion: r.MinVersion, Purpose: r.Purpose, Install: r.InstallHint(goos),
			})
		}
		if rc := writeJSON(stdout, stderr, rep); rc != ExitOK {
			return rc
		}
		return code
	}

	tw := newTable(stdout)
	fmt.Fprintln(tw, "TOOL\tREQUIRED\tSTATUS\tVERSION\tMIN\tPURPOSE")
	hidden := 0
	for _, r := range results {
		status := toolStatus(r)
		// Optional tools are listed only when they need attention, or with
		// --all: a squad engineer needs to see what blocks them.
		if !*all && !r.Required && status != "outdated" {
			hidden++
			continue
		}
		if status == "outdated" {
			status = "OUTDATED"
		}
		req := ""
		if r.Required {
			req = "required"
		}
		version := r.Detected
		if r.Found && version == "" {
			version = "-"
		}
		min := r.MinVersion
		if min == "" {
			min = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, req, status, version, min, r.Purpose)
	}
	tw.Flush()

	st := ui.Style{Color: colorOn(stdout)}
	if len(missing) > 0 {
		fmt.Fprintln(stderr, "\n"+ui.Style{Color: colorOn(stderr)}.Fail("missing REQUIRED tools:"))
		for _, m := range missing {
			fmt.Fprintf(stderr, "  %s — install: %s\n", m.Name, m.InstallHint(goos))
		}
	}
	if len(outdatedAll) > 0 {
		fmt.Fprintln(stderr, "\n"+ui.Style{Color: colorOn(stderr)}.Warn("below version floor (update these):"))
		for _, o := range outdatedAll {
			fmt.Fprintf(stderr, "  %s %s < %s — %s\n", o.Name, o.Detected, o.MinVersion, o.InstallHint(goos))
		}
	}
	if len(missing) == 0 && len(outdatedAll) == 0 {
		fmt.Fprintln(stdout, "\n"+st.OK("all required tools present and current"))
	}
	if hidden > 0 {
		fmt.Fprintln(stdout, st.Hint(fmt.Sprintf("%d optional tools not shown — nedctl doctor --all", hidden)))
	}
	fmt.Fprintln(stdout)
	tw = newTable(stdout)
	fmt.Fprintln(tw, "CHECK\tSTATUS\tDETAIL")
	for _, c := range checks {
		lines := strings.Split(c.Detail, "\n")
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Name, strings.ToUpper(c.Status), lines[0])
		for _, l := range lines[1:] {
			fmt.Fprintf(tw, "\t\t%s\n", l)
		}
	}
	tw.Flush()
	return code
}

// doctorHygiene is `doctor --hygiene`: local checks only.
func doctorHygiene(stdout, stderr io.Writer, output string) int {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(stderr, "finding your home directory: %v\n", err)
		return ExitFailure
	}
	checks := hygieneChecks(home)
	code := ExitOK
	for _, c := range checks {
		if c.Status == "fail" {
			code = ExitFailure
		}
	}
	if output == "json" {
		if rc := writeJSON(stdout, stderr, map[string]any{"healthy": code == ExitOK, "checks": checks}); rc != ExitOK {
			return rc
		}
		return code
	}
	tw := newTable(stdout)
	fmt.Fprintln(tw, "CHECK\tSTATUS\tDETAIL")
	for _, c := range checks {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Name, strings.ToUpper(c.Status), c.Detail)
	}
	tw.Flush()
	fmt.Fprintln(stdout, "\n"+ui.Style{Color: colorOn(stdout)}.Hint("nothing secret is printed or sent anywhere: only where it is, and how to fix it"))
	return code
}
