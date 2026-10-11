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
		redacted := p
		if u, err := url.Parse(p); err == nil {
			redacted = u.Redacted()
		}
		add("proxy", "ok", redacted)
	} else {
		add("proxy", "info", "HTTPS_PROXY not set: connecting directly")
	}
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
	output := addOutputFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
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
