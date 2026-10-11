package app

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"nedctl/internal/audit"
	"nedctl/internal/config"
	"nedctl/internal/inventory"
	"nedctl/internal/ui"
)

// Runbooks are the team's procedures as data: named steps, each one
// kubectl command with {parameters}. `nedctl run` shows the whole runbook
// filled in, runs the reading steps, and for each step that changes
// something does a server-side dry run where kubectl offers one, then asks
// before running it — and records it. A runbook cannot run a shell or
// point kubectl at another cluster; parameters must match their pattern.
// A few are built in; the team's own (runbooksDir, or ./runbooks) are
// added and may replace them.

//go:embed runbooks/*.json
var builtinRunbooks embed.FS

type runbookParam struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Default     string `json:"default,omitempty"`
	Pattern     string `json:"pattern,omitempty"`
}

type runbookStep struct {
	Name    string   `json:"name"`
	Kubectl []string `json:"kubectl"`
	// Change marks a step that changes the cluster: shown, dry-run when
	// DryRun is set (kubectl --dry-run=server), approved, recorded.
	Change bool `json:"change,omitempty"`
	DryRun bool `json:"dryRun,omitempty"`
}

type runbook struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Params      []runbookParam `json:"params"`
	Steps       []runbookStep  `json:"steps"`
	Source      string         `json:"-"`
}

var (
	runbookNameRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	paramRefRe         = regexp.MustCompile(`\{([a-z][a-z0-9_]*)\}`)
	defaultParamRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/=-]{0,252}$`)
	forbiddenStepFlags = map[string]bool{"kubeconfig": true, "context": true, "cluster": true, "server": true, "s": true, "token": true,
		"user": true, "as": true, "as-group": true, "as-uid": true, "insecure-skip-tls-verify": true}
)

func (rb runbook) validate() error {
	if !runbookNameRe.MatchString(rb.Name) {
		return fmt.Errorf("name %q: lower-case letters, digits and -", rb.Name)
	}
	if len(rb.Steps) == 0 {
		return errors.New("no steps")
	}
	params := map[string]bool{}
	for _, p := range rb.Params {
		if !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(p.Name) {
			return fmt.Errorf("parameter name %q", p.Name)
		}
		if p.Pattern != "" {
			if _, err := regexp.Compile(p.Pattern); err != nil {
				return fmt.Errorf("parameter %s: pattern: %w", p.Name, err)
			}
		}
		params[p.Name] = true
	}
	for i, s := range rb.Steps {
		if len(s.Kubectl) == 0 || s.Name == "" {
			return fmt.Errorf("step %d needs a name and a kubectl command", i+1)
		}
		if s.Kubectl[0] == "kubectl" {
			return fmt.Errorf("step %d: leave \"kubectl\" out of the command", i+1)
		}
		for _, a := range s.Kubectl {
			if strings.HasPrefix(a, "-") && forbiddenStepFlags[strings.SplitN(strings.TrimLeft(a, "-"), "=", 2)[0]] {
				return fmt.Errorf("step %d: %s is not allowed — nedctl chooses the cluster", i+1, a)
			}
			for _, m := range paramRefRe.FindAllStringSubmatch(a, -1) {
				if !params[m[1]] {
					return fmt.Errorf("step %d uses {%s}, which is not a parameter", i+1, m[1])
				}
			}
		}
	}
	return nil
}

// loadRunbooks reads the built-in runbooks, then the team's, which may
// replace a built-in of the same name.
func loadRunbooks(cfg config.Config) (map[string]runbook, []error) {
	all := map[string]runbook{}
	var errs []error
	add := func(data []byte, source string) {
		var rb runbook
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rb); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", source, err))
			return
		}
		if err := rb.validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", source, err))
			return
		}
		rb.Source = source
		all[rb.Name] = rb
	}
	entries, _ := builtinRunbooks.ReadDir("runbooks")
	for _, e := range entries {
		data, _ := builtinRunbooks.ReadFile("runbooks/" + e.Name())
		add(data, "built in")
	}
	for _, dir := range runbookDirs(cfg) {
		files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		sort.Strings(files)
		for _, f := range files {
			if data, err := os.ReadFile(f); err == nil {
				add(data, f)
			}
		}
	}
	return all, errs
}

func runbookDirs(cfg config.Config) []string {
	if cfg.RunbooksDir != "" {
		return []string{cfg.RunbooksDir}
	}
	return []string{"runbooks"}
}

// render fills in the parameters.
func (rb runbook) render(values map[string]string) ([][]string, error) {
	vals := map[string]string{}
	for _, p := range rb.Params {
		v, ok := values[p.Name]
		if !ok || v == "" {
			v = p.Default
		}
		if v == "" {
			return nil, fmt.Errorf("%s=… is needed: %s", p.Name, p.Description)
		}
		re := defaultParamRe
		if p.Pattern != "" {
			re = regexp.MustCompile(p.Pattern)
		}
		if !re.MatchString(v) || strings.HasPrefix(v, "-") {
			return nil, fmt.Errorf("%s=%q is not allowed (%s)", p.Name, v, firstNonBlank(p.Pattern, "letters, digits and . _ : / = -"))
		}
		vals[p.Name] = v
	}
	for k := range values {
		if _, ok := vals[k]; !ok {
			return nil, fmt.Errorf("%s is not a parameter of %s", k, rb.Name)
		}
	}
	steps := make([][]string, len(rb.Steps))
	for i, s := range rb.Steps {
		args := make([]string, len(s.Kubectl))
		for j, a := range s.Kubectl {
			args[j] = paramRefRe.ReplaceAllStringFunc(a, func(m string) string { return vals[m[1:len(m)-1]] })
		}
		steps[i] = args
	}
	return steps, nil
}

func cmdRun(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	books, errs := loadRunbooks(cfg)
	for _, e := range errs {
		fmt.Fprintf(stderr, "warning: runbook %v (skipped)\n", e)
	}
	if len(args) == 0 || args[0] == "ls" {
		names := make([]string, 0, len(books))
		for n := range books {
			names = append(names, n)
		}
		sort.Strings(names)
		tw := newTable(stdout)
		fmt.Fprintln(tw, "RUNBOOK\tWHAT IT DOES\tFROM")
		for _, n := range names {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", n, books[n].Description, books[n].Source)
		}
		tw.Flush()
		return ExitOK
	}
	if args[0] == "show" {
		if len(args) != 2 {
			fmt.Fprintln(stderr, "usage: nedctl run show RUNBOOK")
			return ExitUsage
		}
		rb, ok := books[args[1]]
		if !ok {
			fmt.Fprintf(stderr, "no runbook %q — nedctl run ls\n", args[1])
			return ExitFailure
		}
		showRunbook(stdout, rb)
		return ExitOK
	}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, false)
	yes := fs.Bool("yes", false, "run the changing steps without asking (they are still shown and dry-run)")
	dryRun := fs.Bool("dry-run", false, "run the reading steps and the dry runs only; change nothing")
	cr := fs.String("change-record", "", "change record, when change control requires one")
	glass := fs.String("break-glass", "", "emergency access without a change record; recorded and flagged")
	if strings.HasPrefix(args[0], "-") {
		_ = fs.Parse(args) // -h lists the flags
		fmt.Fprintln(stderr, "usage: nedctl run <RUNBOOK|ls|show RUNBOOK> [name=value…] [--cluster C] [--dry-run] [--yes]")
		return ExitUsage
	}
	rb, ok := books[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "no runbook %q — nedctl run ls\n", args[0])
		return ExitFailure
	}
	pos, err := parseInterspersed(fs, args[1:])
	if err != nil {
		return ExitUsage
	}
	values := map[string]string{}
	for _, p := range pos {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			fmt.Fprintf(stderr, "%q: give parameters as name=value (nedctl run show %s)\n", p, rb.Name)
			return ExitUsage
		}
		values[k] = v
	}
	steps, err := rb.render(values)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	s, code := openKubeSession(ctx, cfg, sessionFlags{cluster: sel.cluster, env: sel.env, awsProfile: sel.awsProfile}, stderr)
	if code != ExitOK {
		return code
	}
	defer s.close()
	return runRunbook(ctx, cfg, s, rb, steps, values, *yes, *dryRun, strings.TrimSpace(*cr), strings.TrimSpace(*glass), stdout, stderr)
}

func showRunbook(w io.Writer, rb runbook) {
	st := ui.Style{Color: colorOn(w)}
	fmt.Fprintf(w, "%s — %s\n%s\n", st.Bold(rb.Name), rb.Description, st.Dim("from "+rb.Source))
	if len(rb.Params) > 0 {
		fmt.Fprintf(w, "\n%s\n", st.Heading("Parameters"))
		for _, p := range rb.Params {
			def := ""
			if p.Default != "" {
				def = " (default " + p.Default + ")"
			}
			fmt.Fprintf(w, "  %s  %s%s\n", ui.Pad(st.Bold(p.Name), 14), p.Description, def)
		}
	}
	fmt.Fprintf(w, "\n%s\n", st.Heading("Steps"))
	for i, s := range rb.Steps {
		mark := "  "
		if s.Change {
			mark = st.Fg(ui.Amber, "✎ ")
		}
		fmt.Fprintf(w, "  %d. %s%s\n     kubectl %s\n", i+1, mark, s.Name, strings.Join(s.Kubectl, " "))
	}
}

func runRunbook(ctx context.Context, cfg config.Config, s *kubeSession, rb runbook, steps [][]string, values map[string]string,
	yes, dryRun bool, cr, glass string, stdout, stderr io.Writer) int {
	st := ui.Style{Color: colorOn(stderr)}
	fmt.Fprintf(stderr, "\n%s %s on %s (%s)\n", st.Bold("Runbook"), rb.Name, st.BoldFg(cfg.ColorFor(s.env), s.label()), s.where)
	for i, args := range steps {
		mark := "  "
		if rb.Steps[i].Change {
			mark = st.Fg(ui.Amber, "✎ ")
		}
		fmt.Fprintf(stderr, "  %d. %s%s: kubectl %s\n", i+1, mark, rb.Steps[i].Name, strings.Join(args, " "))
	}
	fmt.Fprintln(stderr)
	if !confirmProduction(cfg, s.pc, s.cluster, false, stderr) {
		return ExitFailure
	}
	keys := make([]string, 0, len(values))
	for k, v := range values {
		keys = append(keys, k+"="+v)
	}
	sort.Strings(keys)
	base := audit.Event{Action: "runbook", Cloud: s.cloud, Cluster: s.cluster, Account: s.pc.AccountID, Environment: s.env, Production: s.pc.Production,
		ChangeRecord: cr, BreakGlass: glass != "", BreakGlassReason: glass,
		Detail: fmt.Sprintf("runbook %s (%s) %s, %s", rb.Name, rb.Source, strings.Join(keys, " "), s.where)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing: every change must be recorded\n", err)
		return ExitFailure
	}
	if code := applyChangeControl(ctx, cfg, inventory.Cluster{Name: s.cluster, Environment: s.env}, cr, glass, tr, stderr); code != ExitOK {
		return code
	}
	done := 0
	for i, args := range steps {
		step := rb.Steps[i]
		fmt.Fprintf(stderr, "%s %d/%d %s\n", st.Bold("▶"), i+1, len(steps), step.Name)
		if step.Change {
			if step.DryRun {
				out, err := s.output(ctx, "", append(append([]string{}, args...), "--dry-run=server")...)
				if err != nil {
					fmt.Fprintf(stderr, "%s %v\n", st.Fail("The cluster refuses it (server-side dry run):"), err)
					tr.end(ctx, audit.OutcomeFailure, s.pc.Role, fmt.Sprintf("%s; step %d dry run refused: %v", base.Detail, i+1, err), stderr)
					return ExitFailure
				}
				fmt.Fprintf(stderr, "  %s\n%s", st.OK("the cluster accepts it (server-side dry run):"), indentLines(indentLines(string(out))))
			}
			if dryRun {
				fmt.Fprintln(stderr, "  skipped (--dry-run)")
				continue
			}
			if !yes {
				if !stdinIsTerminal() {
					fmt.Fprintln(stderr, "stopped before a change: pass --yes to run changing steps without a terminal")
					tr.end(ctx, audit.OutcomeRefused, s.pc.Role, fmt.Sprintf("%s; stopped before step %d", base.Detail, i+1), stderr)
					return ExitUsage
				}
				fmt.Fprintf(stderr, "  Run it: kubectl %s ? [y/N] ", strings.Join(args, " "))
				line, _ := bufio.NewReader(stdin).ReadString('\n')
				if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
					fmt.Fprintln(stderr, "  stopped — nothing more was changed")
					tr.end(ctx, audit.OutcomeRefused, s.pc.Role, fmt.Sprintf("%s; stopped before step %d", base.Detail, i+1), stderr)
					return ExitFailure
				}
			}
		}
		out, err := s.output(ctx, "", args...)
		fmt.Fprint(stdout, indentLines(string(out)))
		if err != nil {
			fmt.Fprintf(stderr, "%s %v\n", st.Fail(fmt.Sprintf("step %d failed:", i+1)), err)
			tr.end(ctx, audit.OutcomeFailure, s.pc.Role, fmt.Sprintf("%s; step %d failed: %v", base.Detail, i+1, err), stderr)
			return ExitFailure
		}
		done++
	}
	tr.end(ctx, audit.OutcomeSuccess, s.pc.Role, fmt.Sprintf("%s; %d step(s) done", base.Detail, done), stderr)
	fmt.Fprintln(stderr, st.OK(fmt.Sprintf("%s done", rb.Name)))
	return ExitOK
}

func indentLines(s string) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	return "  " + strings.ReplaceAll(s, "\n", "\n  ") + "\n"
}
