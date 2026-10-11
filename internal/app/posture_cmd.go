package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// `nedctl posture` checks what runs on clusters for the settings that turn
// a compromised container into a compromised node or a leak: privileged
// containers, host namespaces and paths, root, added capabilities, no
// memory limit, untagged images or ones from unapproved registries,
// secrets written into environment variables, and public load balancers.
// It reads only the fields it judges (never a secret's value) and gives a
// pass/fail report that serves as evidence. Read-only.

// The pod probe prints a P line per pod and a C line per container. Env
// variables with a literal value are listed by name only.
var postureProbes = []probe{
	{"get", "pods", "-A", "-o", `jsonpath={range .items[*]}P{"\t"}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.hostNetwork}{"\t"}{.spec.hostPID}{"\t"}{.spec.hostIPC}{"\t"}{.spec.securityContext.runAsNonRoot}{"\t"}{.spec.securityContext.runAsUser}{"\t"}{.spec.volumes[*].hostPath.path}{"\n"}{range .spec.containers[*]}C{"\t"}{.name}{"\t"}{.image}{"\t"}{.securityContext.privileged}{"\t"}{.securityContext.runAsNonRoot}{"\t"}{.securityContext.runAsUser}{"\t"}{.securityContext.allowPrivilegeEscalation}{"\t"}{.securityContext.capabilities.add[*]}{"\t"}{.resources.limits.memory}{"\t"}{range .env[?(@.value)]}{.name}{" "}{end}{"\n"}{end}{end}`},
	{"get", "services", "-A", "-o", `jsonpath={range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.type}{"\t"}{.metadata.annotations}{"\n"}{end}`},
}

// postureCheck is one rule.
type postureCheck struct {
	ID, Severity, Title, Fix string
}

var postureChecks = []postureCheck{
	{"privileged", "fail", "privileged containers", "drop privileged: true; grant only the capability needed"},
	{"host-namespaces", "fail", "pods sharing the node's network, PIDs or IPC", "remove hostNetwork/hostPID/hostIPC"},
	{"secret-in-env", "fail", "secrets written into environment variables", "use valueFrom.secretKeyRef (or a mounted Secret) instead of a literal value"},
	{"public-load-balancer", "fail", "services on a public load balancer", "annotate the service as internal, or put it behind the ingress"},
	{"unapproved-registry", "fail", "images from registries not approved", "mirror the image into an approved registry (security.approvedRegistries)"},
	{"dangerous-capabilities", "fail", "containers adding SYS_ADMIN, NET_ADMIN, ALL or similar", "remove the capability, or justify it as an exception"},
	{"host-path", "warn", "pods mounting paths from the node", "use a volume type that does not expose the node's files"},
	{"root", "warn", "containers that may run as root", "set runAsNonRoot: true (and a non-zero runAsUser)"},
	{"no-memory-limit", "warn", "containers without a memory limit", "set resources.limits.memory, so one container cannot starve the node"},
	{"mutable-image-tag", "warn", "images tagged latest (or untagged)", "deploy a fixed version tag or a digest"},
	{"privilege-escalation", "info", "containers that do not forbid privilege escalation", "set allowPrivilegeEscalation: false"},
}

var (
	secretNameRe   = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api_?key|private_?key|credential|conn(ection)?_?str)`)
	dangerousCapRe = regexp.MustCompile(`^(ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH|BPF|PERFMON)$`)
	internalLBRe   = regexp.MustCompile(`azure-load-balancer-internal":"true"|aws-load-balancer-internal":"(true|0\.0\.0\.0/0)"|aws-load-balancer-scheme":"internal"|networking\.gke\.io/load-balancer-type":"Internal"`)
)

// postureFinding is one object failing one check.
type postureFinding struct {
	Check  string `json:"check"`
	Object string `json:"object"` // namespace/pod[/container] or namespace/service
	Detail string `json:"detail,omitempty"`
}

// clusterPosture is one cluster's report.
type clusterPosture struct {
	Environment string           `json:"environment"`
	Cluster     string           `json:"cluster"`
	Status      string           `json:"status"` // pass | warn | fail | unreachable
	Error       string           `json:"error,omitempty"`
	Pods        int              `json:"podsChecked"`
	Findings    []postureFinding `json:"findings"`
}

// registryOf is the registry part of an image reference (docker.io when
// none is named).
func registryOf(image string) string {
	first, rest, ok := strings.Cut(image, "/")
	if !ok || (!strings.ContainsAny(first, ".:") && first != "localhost") || rest == "" {
		return "docker.io"
	}
	return strings.ToLower(first)
}

func assessPosture(cfg config.Config, r clusterOut, includeSystem bool) clusterPosture {
	cp := clusterPosture{Environment: r.Env, Cluster: firstNonBlank(r.Cluster, r.Where), Status: "pass", Findings: []postureFinding{}}
	if err := r.reachErr(); err != nil {
		cp.Status, cp.Error = "unreachable", err.Error()
		return cp
	}
	add := func(check, object, detail string) {
		cp.Findings = append(cp.Findings, postureFinding{check, object, detail})
	}
	var ns, pod string
	var podNonRoot, podUser string
	skip := false
	for _, l := range strings.Split(string(r.Outs[0].Out), "\n") {
		f := strings.Split(l, "\t")
		switch {
		case len(f) >= 9 && f[0] == "P":
			ns, pod = f[1], f[2]
			skip = !includeSystem && cfg.Security.Ignored(ns)
			if skip {
				continue
			}
			cp.Pods++
			podNonRoot, podUser = f[6], f[7]
			var host []string
			for i, n := range map[int]string{3: "hostNetwork", 4: "hostPID", 5: "hostIPC"} {
				if f[i] == "true" {
					host = append(host, n)
				}
			}
			sort.Strings(host)
			if len(host) > 0 {
				add("host-namespaces", ns+"/"+pod, strings.Join(host, ", "))
			}
			if strings.TrimSpace(f[8]) != "" {
				add("host-path", ns+"/"+pod, strings.Join(strings.Fields(f[8]), ", "))
			}
		case len(f) >= 10 && f[0] == "C" && !skip && pod != "":
			obj := ns + "/" + pod + "/" + f[1]
			image := f[2]
			if f[3] == "true" {
				add("privileged", obj, "")
			}
			nonRoot := f[4] == "true" || (f[4] == "" && podNonRoot == "true")
			user := firstNonBlank(f[5], podUser)
			if !nonRoot && (user == "" || user == "0") {
				add("root", obj, "")
			}
			if f[6] != "false" {
				add("privilege-escalation", obj, "")
			}
			var bad []string
			for _, c := range strings.Fields(f[7]) {
				if dangerousCapRe.MatchString(strings.TrimPrefix(strings.ToUpper(c), "CAP_")) {
					bad = append(bad, c)
				}
			}
			if len(bad) > 0 {
				add("dangerous-capabilities", obj, strings.Join(bad, ", "))
			}
			if f[8] == "" {
				add("no-memory-limit", obj, "")
			}
			if t := imageTag(image); t == "latest" {
				add("mutable-image-tag", obj, image)
			}
			if reg := registryOf(image); !cfg.Security.RegistryApproved(reg) {
				add("unapproved-registry", obj, image)
			}
			var secrets []string
			for _, n := range strings.Fields(f[9]) {
				if secretNameRe.MatchString(n) {
					secrets = append(secrets, n)
				}
			}
			if len(secrets) > 0 {
				add("secret-in-env", obj, strings.Join(secrets, ", "))
			}
		}
	}
	if len(r.Outs) > 1 && r.Outs[1].Err == nil {
		for _, l := range nonEmptyLines(string(r.Outs[1].Out)) {
			f := strings.SplitN(l, "\t", 4)
			if len(f) < 3 || f[2] != "LoadBalancer" || (!includeSystem && cfg.Security.Ignored(f[0])) {
				continue
			}
			ann := ""
			if len(f) == 4 {
				ann = strings.ReplaceAll(f[3], " ", "")
			}
			if !internalLBRe.MatchString(ann) {
				add("public-load-balancer", f[0]+"/"+f[1], "")
			}
		}
	}
	sev := map[string]string{}
	for _, c := range postureChecks {
		sev[c.ID] = c.Severity
	}
	for _, fd := range cp.Findings {
		switch sev[fd.Check] {
		case "fail":
			cp.Status = "fail"
		case "warn":
			if cp.Status == "pass" {
				cp.Status = "warn"
			}
		}
	}
	return cp
}

func cmdPosture(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("posture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, true)
	includeSystem := fs.Bool("include-system", false, "also check the platform namespaces (security.ignoreNamespaces)")
	failOn := fs.String("fail-on", "fail", "exit 1 when a cluster reaches: fail or warn")
	output := addOutputFlag(fs)
	if pos, err := parseInterspersed(fs, args); err != nil || len(pos) > 0 || (*failOn != "fail" && *failOn != "warn") {
		fmt.Fprintln(stderr, "usage: nedctl posture [--cluster C | --env prod | --aws] [--match WORD] [--fail-on fail|warn] [-o json]")
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
	results, code := runProbes(ctx, cfg, sel, postureProbes, stderr)
	if code != ExitOK {
		return code
	}
	report := make([]clusterPosture, 0, len(results))
	for _, r := range results {
		report = append(report, assessPosture(cfg, r, *includeSystem))
	}
	if *output == "json" {
		if code := writeJSON(stdout, stderr, map[string]any{"generated": now().UTC().Format("2006-01-02T15:04:05Z"), "checks": postureChecks, "clusters": report}); code != ExitOK {
			return code
		}
	} else {
		printPosture(stdout, cfg, report)
	}
	for _, c := range report {
		if c.Status == "fail" || c.Status == "unreachable" || (*failOn == "warn" && c.Status == "warn") {
			return ExitFailure
		}
	}
	return ExitOK
}

func printPosture(w io.Writer, cfg config.Config, report []clusterPosture) {
	st := ui.Style{Color: colorOn(w)}
	for i, c := range report {
		if i > 0 {
			fmt.Fprintln(w)
		}
		head := strings.TrimSpace(strings.ToUpper(c.Environment) + " " + c.Cluster)
		if c.Error != "" {
			fmt.Fprintf(w, "%s  %s\n", st.Bold(head), st.Fail("unreachable: "+c.Error))
			continue
		}
		fmt.Fprintf(w, "%s  %d pods checked\n", st.BoldFg(cfg.ColorFor(c.Environment), head), c.Pods)
		by := map[string][]postureFinding{}
		for _, f := range c.Findings {
			by[f.Check] = append(by[f.Check], f)
		}
		tw := newTable(w)
		fmt.Fprintln(tw, "CHECK\tRESULT\tCOUNT\tEXAMPLES")
		for _, chk := range postureChecks {
			fs := by[chk.ID]
			result := "ok"
			if len(fs) > 0 {
				result = chk.Severity
			}
			var ex []string
			for j, f := range fs {
				if j == 2 {
					ex = append(ex, fmt.Sprintf("+%d more", len(fs)-2))
					break
				}
				ex = append(ex, strings.TrimSpace(f.Object+" "+parens(f.Detail)))
			}
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", chk.ID, result, len(fs), strings.Join(ex, "; "))
		}
		tw.Flush()
	}
	fmt.Fprintf(w, "\n%s\n", st.Hint("-o json gives every finding with the fixes — evidence for a review"))
}

func parens(s string) string {
	if s == "" {
		return ""
	}
	return "(" + s + ")"
}
