package app

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/inventory"
	"nedctl/internal/support"
	"nedctl/internal/ui"
)

// `nedctl health` is one line per cluster, then what needs attention:
// nodes not ready or under pressure, pods crash-looping or stuck, workloads
// below their replicas, volume claims not bound, TLS certificates close to
// expiry, and the Kubernetes version's support status. Over --env qa it is
// the morning check of a whole environment, one SSH connection per bastion.
// Read-only.

var healthProbes = []probe{
	{"get", "--raw", "/version"},
	{"get", "nodes", "-o", `jsonpath={range .items[*]}{.metadata.name}{"\t"}{range .status.conditions[*]}{.type}={.status},{end}{"\t"}{.spec.unschedulable}{"\n"}{end}`},
	{"get", "pods", "-A", "-o", `jsonpath={range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.phase}{"\t"}{.status.containerStatuses[*].state.waiting.reason}{"\t"}{.status.containerStatuses[*].restartCount}{"\t"}{.metadata.creationTimestamp}{"\t"}{.status.reason}{"\n"}{end}`},
	{"get", "deployments,statefulsets", "-A", "-o", `jsonpath={range .items[*]}{.kind}{"\t"}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.replicas}{"\t"}{.status.readyReplicas}{"\n"}{end}`},
	{"get", "pvc", "-A", "-o", `jsonpath={range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.phase}{"\n"}{end}`},
	// Only the certificate is printed; the key never leaves kubectl.
	{"get", "secrets", "-A", "--field-selector", "type=kubernetes.io/tls", "-o", `jsonpath={range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.data.tls\.crt}{"\n"}{end}`},
}

// clusterHealth is one cluster's result.
type clusterHealth struct {
	Environment string   `json:"environment"`
	Cluster     string   `json:"cluster"`
	Status      string   `json:"status"` // ok | warn | fail | unreachable
	Version     string   `json:"version,omitempty"`
	Support     string   `json:"support,omitempty"`
	Nodes       string   `json:"nodes,omitempty"`
	Pods        string   `json:"pods,omitempty"`
	Workloads   string   `json:"workloads,omitempty"`
	Problems    []string `json:"problems,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
}

func cmdHealth(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, true)
	certDays := fs.Int("cert-days", 30, "warn about TLS certificates expiring within this many days")
	output := addOutputFlag(fs)
	if pos, err := parseInterspersed(fs, args); err != nil || len(pos) > 0 || *certDays < 1 {
		fmt.Fprintln(stderr, "usage: nedctl health [--cluster C | --env qa | --aws] [--match WORD] [--cert-days 30] [-o json]")
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	results, code := runProbes(ctx, cfg, sel, healthProbes, stderr)
	if code != ExitOK {
		return code
	}
	report := make([]clusterHealth, 0, len(results))
	for _, r := range results {
		report = append(report, assessHealth(cfg, r, now(), *certDays))
	}
	if *output == "json" {
		if code := writeJSON(stdout, stderr, report); code != ExitOK {
			return code
		}
	} else {
		printHealth(stdout, report)
	}
	for _, h := range report {
		if h.Status == "fail" || h.Status == "unreachable" {
			return ExitFailure
		}
	}
	return ExitOK
}

func assessHealth(cfg config.Config, r clusterOut, today time.Time, certDays int) clusterHealth {
	h := clusterHealth{Environment: r.Env, Cluster: firstNonBlank(r.Cluster, r.Where), Status: "ok"}
	if err := r.reachErr(); err != nil {
		h.Status, h.Problems = "unreachable", []string{err.Error()}
		return h
	}
	fail := func(f string, a ...any) { h.Problems = append(h.Problems, fmt.Sprintf(f, a...)) }
	warn := func(f string, a ...any) { h.Warnings = append(h.Warnings, fmt.Sprintf(f, a...)) }
	out := func(i int) []string {
		if i >= len(r.Outs) || r.Outs[i].Err != nil {
			return nil
		}
		return nonEmptyLines(string(r.Outs[i].Out))
	}

	// Version and support.
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if len(r.Outs) > 0 && json.Unmarshal(r.Outs[0].Out, &v) == nil && v.GitVersion != "" {
		h.Version = strings.TrimPrefix(strings.SplitN(v.GitVersion, "-", 2)[0], "v")
		cloud := inventory.AWS
		if r.Cloud == "azure" {
			cloud = inventory.Azure
		}
		a := support.Assess(cfg.SupportCalendar, cfg.CostRates, cloud, h.Version, today, 90)
		h.Support = string(a.Status)
		switch a.Status {
		case support.Unsupported:
			fail("Kubernetes %s is out of support — upgrade", h.Version)
		case support.Extended:
			warn("Kubernetes %s is in extended (paid) support until %s", h.Version, a.PhaseEnds)
		case support.Ending:
			warn("Kubernetes %s leaves standard support on %s", h.Version, a.PhaseEnds)
		case support.Unknown:
			h.Support = ""
		}
	}

	// Nodes.
	nodes, notReady, pressure, cordoned := out(1), 0, 0, 0
	for _, l := range nodes {
		f := strings.Split(l, "\t")
		if len(f) < 2 {
			continue
		}
		if !strings.Contains(f[1], "Ready=True") {
			notReady++
			fail("node %s is not Ready", f[0])
		}
		for _, p := range []string{"MemoryPressure=True", "DiskPressure=True", "PIDPressure=True"} {
			if strings.Contains(f[1], p) {
				pressure++
				warn("node %s: %s", f[0], strings.TrimSuffix(p, "=True"))
			}
		}
		if len(f) > 2 && f[2] == "true" {
			cordoned++
		}
	}
	h.Nodes = fmt.Sprintf("%d/%d ready", len(nodes)-notReady, len(nodes))
	if cordoned > 0 {
		h.Nodes += fmt.Sprintf(", %d cordoned", cordoned)
	}

	// Pods.
	pods, bad := out(2), 0
	for _, l := range pods {
		f := strings.Split(l, "\t")
		if len(f) < 7 {
			continue
		}
		ns, name, phase, waiting, created, reason := f[0], f[1], f[2], f[3], f[5], f[6]
		switch {
		case strings.Contains(waiting, "CrashLoopBackOff") || strings.Contains(waiting, "ImagePull") || strings.Contains(waiting, "ErrImage") ||
			strings.Contains(waiting, "CreateContainerConfigError"):
			bad++
			fail("pod %s/%s: %s", ns, name, strings.Fields(waiting)[0])
		case phase == "Pending":
			if t, err := time.Parse(time.RFC3339, created); err == nil && today.Sub(t) > 10*time.Minute {
				bad++
				warn("pod %s/%s pending for %s", ns, name, shortDuration(today.Sub(t)))
			}
		case phase == "Failed" && reason == "Evicted":
			warn("pod %s/%s was evicted", ns, name)
		}
	}
	h.Pods = fmt.Sprintf("%d, %d failing", len(pods), bad)

	// Workloads below their replicas.
	wls, short := out(3), 0
	for _, l := range wls {
		f := strings.Split(l, "\t")
		if len(f) < 5 {
			continue
		}
		want, err := strconv.Atoi(f[3])
		if err != nil {
			want = 1
		}
		have, _ := strconv.Atoi(f[4])
		if have < want {
			short++
			if have == 0 {
				fail("%s %s/%s has no ready replicas (0/%d)", strings.ToLower(f[0]), f[1], f[2], want)
			} else {
				warn("%s %s/%s: %d/%d ready", strings.ToLower(f[0]), f[1], f[2], have, want)
			}
		}
	}
	h.Workloads = fmt.Sprintf("%d, %d short", len(wls), short)

	// Volume claims.
	for _, l := range out(4) {
		if f := strings.Split(l, "\t"); len(f) >= 3 && f[2] != "Bound" {
			warn("volume claim %s/%s is %s", f[0], f[1], f[2])
		}
	}

	// TLS certificates.
	for _, l := range out(5) {
		f := strings.Split(l, "\t")
		if len(f) < 3 {
			continue
		}
		notAfter, ok := certExpiry(f[2])
		if !ok {
			continue
		}
		days := int(notAfter.Sub(today).Hours() / 24)
		switch {
		case days < 0:
			fail("TLS certificate %s/%s expired on %s", f[0], f[1], notAfter.Format("2006-01-02"))
		case days <= certDays:
			warn("TLS certificate %s/%s expires in %d days (%s)", f[0], f[1], days, notAfter.Format("2006-01-02"))
		}
	}

	sort.Strings(h.Problems)
	sort.Strings(h.Warnings)
	switch {
	case len(h.Problems) > 0:
		h.Status = "fail"
	case len(h.Warnings) > 0:
		h.Status = "warn"
	}
	return h
}

// certExpiry reads the first certificate's NotAfter from base64 PEM.
func certExpiry(b64 string) (time.Time, bool) {
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return time.Time{}, false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, false
	}
	return cert.NotAfter, true
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, strings.TrimRight(l, "\r"))
		}
	}
	return out
}

// healthDetailLimit is how many problems and warnings each cluster shows.
const healthDetailLimit = 12

func printHealth(w io.Writer, report []clusterHealth) {
	st := ui.Style{Color: colorOn(w)}
	tw := newTable(w)
	fmt.Fprintln(tw, "ENV\tCLUSTER\tSTATUS\tNODES\tPODS\tWORKLOADS\tVERSION")
	for _, h := range report {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", h.Environment, h.Cluster, h.Status, h.Nodes, h.Pods, h.Workloads, strings.TrimSpace(h.Version+" "+h.Support))
	}
	tw.Flush()
	for _, h := range report {
		if len(h.Problems)+len(h.Warnings) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s\n", st.Bold(strings.TrimSpace(strings.ToUpper(h.Environment)+" "+h.Cluster)))
		shown := 0
		for _, p := range h.Problems {
			if shown < healthDetailLimit {
				fmt.Fprintf(w, "  %s\n", st.Fail(p))
			}
			shown++
		}
		for _, p := range h.Warnings {
			if shown < healthDetailLimit {
				fmt.Fprintf(w, "  %s\n", st.Warn(p))
			}
			shown++
		}
		if shown > healthDetailLimit {
			fmt.Fprintf(w, "  %s\n", st.Dim(fmt.Sprintf("… and %d more (-o json lists all)", shown-healthDetailLimit)))
		}
	}
	if len(report) == 0 {
		fmt.Fprintln(w, "no clusters")
	}
}
