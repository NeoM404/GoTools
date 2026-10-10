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
	"text/tabwriter"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/httpx"
	"nedctl/internal/tools"
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
	case used == "":
		add("config", "info", "no config file — run `nedctl init`")
	default:
		add("config", "ok", used)
	}
	if !cfg.AWS.Configured() {
		add("aws sign-in", "info", "aws.startUrl not set — AWS commands are off")
		return cs
	}
	add("aws sign-in", "ok", cfg.AWS.StartURL+" ("+cfg.AWS.SSORegion+")")
	if p := firstNonBlank(os.Getenv("HTTPS_PROXY"), os.Getenv("https_proxy")); p != "" {
		redacted := p
		if u, err := url.Parse(p); err == nil {
			redacted = u.Redacted()
		}
		add("proxy", "ok", redacted)
	} else {
		add("proxy", "info", "HTTPS_PROXY not set: connecting directly")
	}
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
	if cfg.Bastion() {
		// Credentials are provisioned on a bastion; nedctl needs only kubectl.
		notRequired = []string{"aws", "az"}
	}
	results := tools.Inspect(ctx, cfg.MinVersions, notRequired...)
	if cfg.AWS.Configured() {
		// shell, connect and kube cannot work without it.
		for i := range results {
			if results[i].Name == "session-manager-plugin" {
				results[i].Required = true
			}
		}
	}
	checks := environmentChecks(ctx, cfg, used, cfgErr, *offline)

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
				Version: r.Detected, MinVersion: r.MinVersion, Purpose: r.Purpose, Install: r.Install,
			})
		}
		if rc := writeJSON(stdout, stderr, rep); rc != ExitOK {
			return rc
		}
		return code
	}

	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TOOL\tREQUIRED\tSTATUS\tVERSION\tMIN\tPURPOSE")
	for _, r := range results {
		status := toolStatus(r)
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

	if len(missing) > 0 {
		fmt.Fprintln(stderr, "\nmissing REQUIRED tools:")
		for _, m := range missing {
			fmt.Fprintf(stderr, "  %s — install: %s\n", m.Name, m.Install)
		}
	}
	if len(outdatedAll) > 0 {
		fmt.Fprintln(stderr, "\nbelow version floor (update these):")
		for _, o := range outdatedAll {
			fmt.Fprintf(stderr, "  %s %s < %s — %s\n", o.Name, o.Detected, o.MinVersion, o.Install)
		}
	}
	if len(missing) == 0 && len(outdatedAll) == 0 {
		fmt.Fprintln(stdout, "\nall required tools present and current")
	}
	fmt.Fprintln(stdout)
	tw = tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
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
