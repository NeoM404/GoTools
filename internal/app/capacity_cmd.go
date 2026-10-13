package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// `nedctl capacity` is headroom before it becomes an incident: per node
// pool, what is requested against what is allocatable (what the scheduler
// sees) and, with metrics-server, what is actually used; nodes under
// pressure; pending pods grouped by why they cannot be placed; autoscalers
// pinned at their maximum; quotas nearly full; and, with --namespaces,
// requests far above use (money spent on nothing). Read-only, gentle: one
// paged list per kind, node metrics from metrics-server.

func capacityProbes(namespaces bool) []probe {
	p := []probe{
		versionProbe,
		clusterProbe("nodes", `{range .items[*]}{.metadata.name}{"\t"}{.status.allocatable.cpu}{"\t"}{.status.allocatable.memory}{"\t"}{.status.allocatable.pods}{"\t"}{.metadata.labels.eks\.amazonaws\.com/nodegroup}{.metadata.labels.karpenter\.sh/nodepool}{.metadata.labels.kubernetes\.azure\.com/agentpool}{"\t"}{range .status.conditions[?(@.status=="True")]}{.type}{","}{end}{"\t"}{.spec.unschedulable}{"\n"}{end}`),
		listProbe("pods", "", `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.nodeName}{"\t"}{.status.phase}{"\t"}{.spec.containers[*].resources.requests.cpu}{"\t"}{.spec.containers[*].resources.requests.memory}{"\t"}{.status.conditions[?(@.type=="PodScheduled")].reason}{"\t"}{.status.conditions[?(@.type=="PodScheduled")].message}{"\n"}{end}`,
			"--field-selector", "status.phase!=Succeeded,status.phase!=Failed"),
		listProbe("horizontalpodautoscalers", "", `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.minReplicas}{"\t"}{.spec.maxReplicas}{"\t"}{.status.currentReplicas}{"\t"}{.status.desiredReplicas}{"\t"}{.status.conditions[?(@.type=="ScalingLimited")].status}{"\t"}{.status.conditions[?(@.type=="ScalingLimited")].reason}{"\n"}{end}`),
		listProbe("resourcequotas", "", `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.hard}{"\t"}{.status.used}{"\n"}{end}`),
		{"get", "--raw", "/apis/metrics.k8s.io/v1beta1/nodes"},
	}
	if namespaces {
		p = append(p, probe{"get", "--raw", "/apis/metrics.k8s.io/v1beta1/pods"})
	}
	return p
}

const (
	caNodes = iota + 1
	caPods
	caHPA
	caQuotas
	caNodeMetrics
	caPodMetrics
)

// quantity reads a Kubernetes quantity: CPU in cores, memory in bytes.
func quantity(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	mult := map[string]float64{"n": 1e-9, "u": 1e-6, "m": 1e-3, "k": 1e3, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15,
		"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40, "Pi": 1 << 50}
	for _, suf := range []string{"Ki", "Mi", "Gi", "Ti", "Pi", "n", "u", "m", "k", "K", "M", "G", "T", "P"} {
		if strings.HasSuffix(s, suf) {
			v, err := strconv.ParseFloat(strings.TrimSuffix(s, suf), 64)
			if err != nil {
				return 0
			}
			return v * mult[suf]
		}
	}
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

func sumQuantities(list string) float64 {
	total := 0.0
	for _, q := range strings.Fields(list) {
		total += quantity(q)
	}
	return total
}

// poolUse is one node pool's numbers.
type poolUse struct {
	Pool                          string  `json:"pool"`
	Nodes                         int     `json:"nodes"`
	CPU, Memory, Pods             float64 `json:"-"`
	CPUReq, MemReq, PodCount      float64 `json:"-"`
	CPUUsed, MemUsed              float64 `json:"-"`
	CPUReqPct, MemReqPct, PodsPct int     `json:"-"`
	CPUUsedPct                    *int    `json:"cpuUsedPercent,omitempty"`
	MemUsedPct                    *int    `json:"memoryUsedPercent,omitempty"`
	Pending                       int     `json:"pending"`
}

func pct(a, b float64) int {
	if b <= 0 {
		return 0
	}
	return int(a * 100 / b)
}

func assessCapacity(cfg config.Config, r clusterOut, warn int) (clusterFindings, []poolUse) {
	cf := newClusterFindings(r)
	if err := r.reachErr(); err != nil {
		cf.Status, cf.Error = "unreachable", err.Error()
		return cf, nil
	}
	lines := func(i int, what string) []string {
		if i >= len(r.Outs) {
			return nil
		}
		if err := r.Outs[i].Err; err != nil {
			cf.unassessed("%s: %v", what, err)
			return nil
		}
		return nonEmptyLines(string(r.Outs[i].Out))
	}
	add := func(sev, check, title, object, detail, fix string) {
		cf.add(checkFinding{Check: check, Area: "capacity", Severity: sev, Title: title, Object: object, Detail: detail, Fix: fix, Source: "kubernetes"})
	}
	pools := map[string]*poolUse{}
	nodePool := map[string]string{}
	for _, l := range lines(caNodes, "nodes") {
		f := strings.Split(l, "\t")
		if len(f) < 7 {
			continue
		}
		name := firstNonBlank(f[4], "(no pool)")
		nodePool[f[0]] = name
		p := pools[name]
		if p == nil {
			p = &poolUse{Pool: name}
			pools[name] = p
		}
		if f[6] == "true" {
			nodePool[f[0]] = "" // cordoned: not capacity
			continue
		}
		p.Nodes++
		p.CPU += quantity(f[1])
		p.Memory += quantity(f[2])
		p.Pods += quantity(f[3])
		for _, c := range strings.Split(f[5], ",") {
			if strings.HasSuffix(c, "Pressure") {
				add("high", "node-pressure", "the node is under "+strings.TrimSuffix(c, "Pressure")+" pressure: the kubelet evicts pods", "node/"+f[0], "pool "+name, "find what grew (nedctl changes, kubectl top pods) and add capacity")
			}
		}
	}
	pending := map[string][]string{} // reason → pods
	for _, l := range lines(caPods, "pods") {
		f := strings.SplitN(l, "\t", 8)
		if len(f) < 8 {
			continue
		}
		if f[3] == "Pending" && f[2] == "" {
			why := pendingReason(f[7])
			pending[why] = append(pending[why], f[0]+"/"+f[1])
			continue
		}
		if p := pools[nodePool[f[2]]]; p != nil && nodePool[f[2]] != "" {
			p.CPUReq += sumQuantities(f[4])
			p.MemReq += sumQuantities(f[5])
			p.PodCount++
		}
	}
	for why, list := range pending {
		sort.Strings(list)
		sev := "high"
		if strings.HasPrefix(why, "waiting") {
			sev = "medium"
		}
		add(sev, "pending-pods", fmt.Sprintf("%d pod(s) cannot be placed: %s", len(list), why), list[0], strings.Join(list[1:min(4, len(list))], ", "),
			map[bool]string{true: "add capacity to the pool (or let the autoscaler); check requests are realistic", false: "check the pods' node selectors, affinity, tolerations and volumes against the nodes"}[strings.Contains(why, "Insufficient")])
	}
	// Node metrics, when metrics-server is there.
	metrics := false
	if len(r.Outs) > caNodeMetrics && r.Outs[caNodeMetrics].Err == nil {
		var m struct {
			Items []struct {
				Metadata struct{ Name string }
				Usage    struct{ CPU, Memory string }
			}
		}
		if json.Unmarshal(r.Outs[caNodeMetrics].Out, &m) == nil {
			metrics = true
			for _, it := range m.Items {
				if p := pools[nodePool[it.Metadata.Name]]; p != nil && nodePool[it.Metadata.Name] != "" {
					p.CPUUsed += quantity(it.Usage.CPU)
					p.MemUsed += quantity(it.Usage.Memory)
				}
			}
		}
	} else {
		cf.unassessed("actual use: metrics-server is not answering (requests are shown; kubectl top needs it too)")
	}
	var out []poolUse
	names := make([]string, 0, len(pools))
	for n := range pools {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := pools[n]
		if p.Nodes == 0 {
			continue
		}
		p.CPUReqPct, p.MemReqPct, p.PodsPct = pct(p.CPUReq, p.CPU), pct(p.MemReq, p.Memory), pct(p.PodCount, p.Pods)
		if metrics {
			c, m := pct(p.CPUUsed, p.CPU), pct(p.MemUsed, p.Memory)
			p.CPUUsedPct, p.MemUsedPct = &c, &m
			if m >= 90 {
				add("high", "memory-used", fmt.Sprintf("the pool uses %d%% of its memory: pods will be evicted or OOM-killed", m), "pool/"+n, "", "add nodes, or find the pods using more than they request")
			}
		}
		for _, x := range []struct {
			what string
			v    int
		}{{"CPU", p.CPUReqPct}, {"memory", p.MemReqPct}, {"pod slots", p.PodsPct}} {
			switch {
			case x.v >= 95:
				add("high", "pool-full", fmt.Sprintf("%d%% of the pool's %s is requested: new pods will not fit", x.v, x.what), "pool/"+n, fmt.Sprintf("%d node(s)", p.Nodes), "add nodes (raise the node group's maximum, or the autoscaler's)")
			case x.v >= warn:
				add("medium", "pool-headroom", fmt.Sprintf("%d%% of the pool's %s is requested", x.v, x.what), "pool/"+n, fmt.Sprintf("%d node(s)", p.Nodes), "plan more nodes before the next rollout or node failure")
			}
		}
		out = append(out, *p)
	}
	for _, l := range lines(caHPA, "autoscalers") {
		f := strings.Split(l, "\t")
		if len(f) < 8 {
			continue
		}
		max, cur, want := atoi(f[3]), atoi(f[4]), atoi(f[5])
		if max > 0 && cur >= max && (want >= max || f[7] == "TooManyReplicas") {
			add("medium", "hpa-at-max", fmt.Sprintf("the autoscaler is at its maximum (%d) and wants more", max), "hpa/"+f[0]+"/"+f[1], fmt.Sprintf("running %d, desired %d", cur, want), "raise maxReplicas (with the capacity for it), or find why load grew")
		}
	}
	for _, l := range lines(caQuotas, "resource quotas") {
		f := strings.Split(l, "\t")
		if len(f) < 4 {
			continue
		}
		hard, used := jsonLabels(f[2]), jsonLabels(f[3])
		keys := make([]string, 0, len(hard))
		for k := range hard {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			h, u := quantity(hard[k]), quantity(used[k])
			if h <= 0 {
				continue
			}
			switch p := pct(u, h); {
			case p >= 100:
				add("high", "quota-full", "a quota is used up: no more "+k+" can be created", "resourcequota/"+f[0]+"/"+f[1], used[k]+" of "+hard[k], "raise the quota (with its owner) or free some")
			case p >= 90:
				add("medium", "quota-nearly-full", fmt.Sprintf("a quota is %d%% used", p), "resourcequota/"+f[0]+"/"+f[1], k+": "+used[k]+" of "+hard[k], "raise the quota before the next rollout needs it")
			}
		}
	}
	// Requests far above use, per namespace (--namespaces).
	if len(r.Outs) > caPodMetrics {
		if r.Outs[caPodMetrics].Err != nil {
			cf.unassessed("namespace use: %v", r.Outs[caPodMetrics].Err)
		} else {
			namespaceWaste(cfg, r, add)
		}
	}
	cf.Summary = map[string]any{"pools": out, "pending": countPending(pending), "metrics": metrics}
	cf.finish()
	return cf, out
}

func countPending(m map[string][]string) int {
	n := 0
	for _, v := range m {
		n += len(v)
	}
	return n
}

// pendingReason turns the scheduler's message into a short reason.
func pendingReason(msg string) string {
	msg = strings.TrimSpace(msg)
	switch {
	case msg == "":
		return "waiting to be scheduled"
	case strings.Contains(msg, "Insufficient cpu") && strings.Contains(msg, "Insufficient memory"):
		return "Insufficient cpu and memory"
	case strings.Contains(msg, "Insufficient cpu"):
		return "Insufficient cpu"
	case strings.Contains(msg, "Insufficient memory"):
		return "Insufficient memory"
	case strings.Contains(msg, "Too many pods"):
		return "no pod slots left on the nodes"
	case strings.Contains(msg, "untolerated taint"), strings.Contains(msg, "had taint"):
		return "taints the pods do not tolerate"
	case strings.Contains(msg, "affinity"), strings.Contains(msg, "selector"):
		return "node selector or affinity matches no node"
	case strings.Contains(msg, "volume"), strings.Contains(msg, "PersistentVolumeClaim"):
		return "its volume cannot be bound or attached there"
	}
	if len(msg) > 80 {
		msg = msg[:77] + "…"
	}
	return msg
}

func namespaceWaste(cfg config.Config, r clusterOut, add func(sev, check, title, object, detail, fix string)) {
	var m struct {
		Items []struct {
			Metadata   struct{ Namespace string }
			Containers []struct {
				Usage struct{ CPU, Memory string }
			}
		}
	}
	if json.Unmarshal(r.Outs[caPodMetrics].Out, &m) != nil {
		return
	}
	used := map[string][2]float64{}
	for _, it := range m.Items {
		u := used[it.Metadata.Namespace]
		for _, c := range it.Containers {
			u[0] += quantity(c.Usage.CPU)
			u[1] += quantity(c.Usage.Memory)
		}
		used[it.Metadata.Namespace] = u
	}
	req := map[string][2]float64{}
	for _, l := range nonEmptyLines(string(r.Outs[caPods].Out)) {
		f := strings.SplitN(l, "\t", 8)
		if len(f) >= 6 && f[3] == "Running" {
			q := req[f[0]]
			q[0] += sumQuantities(f[4])
			q[1] += sumQuantities(f[5])
			req[f[0]] = q
		}
	}
	type waste struct {
		ns          string
		cpu, mem, x float64
	}
	var list []waste
	for ns, q := range req {
		if cfg.Security.Ignored(ns) || q[0] < 1 { // under one core requested: not worth a finding
			continue
		}
		u := used[ns]
		if u[0] > 0 && q[0]/u[0] >= 4 {
			list = append(list, waste{ns, q[0], u[0], q[0] / u[0]})
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].cpu-list[i].mem > list[j].cpu-list[j].mem })
	for i, w := range list {
		if i == 5 {
			break
		}
		add("info", "over-requested", fmt.Sprintf("requests %.0f× the CPU it uses", w.x), "namespace/"+w.ns, fmt.Sprintf("%.1f cores requested, %.2f used", w.cpu, w.mem), "right-size the requests: the nodes are paid for whether used or not")
	}
}

func cmdCapacity(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("capacity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, true)
	warn := fs.Int("warn", 85, "medium when a pool's requests reach this percent (95 is high)")
	namespaces := fs.Bool("namespaces", false, "also compare each namespace's requests with its use (reads every pod's metrics)")
	minSev := fs.String("min", "low", "show findings at least this severe")
	failOn := failOnFlag(fs, "high")
	output := addOutputFlag(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) > 0 || *warn < 50 || *warn > 99 || severityRank(*minSev) < 0 || !validFailOn(*failOn) {
		fmt.Fprintln(stderr, "usage: nedctl capacity [--cluster C | --env qa | --aws | --aws-env ete,qa] [--match WORD] [--warn 85] [--namespaces] [-o json]")
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	if *namespaces {
		*minSev = "info"
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	results, code := runProbes(ctx, cfg, sel, capacityProbes(*namespaces), stderr)
	if code != ExitOK {
		return code
	}
	var report []clusterFindings
	var pools [][]poolUse
	for _, r := range results {
		cf, p := assessCapacity(cfg, r, *warn)
		report = append(report, cf)
		pools = append(pools, p)
	}
	if *output == "json" {
		if code := writeJSON(stdout, stderr, findingsDoc("capacity", report, nil)); code != ExitOK {
			return code
		}
	} else {
		st := ui.Style{Color: colorOn(stdout)}
		tw := newTable(stdout)
		fmt.Fprintln(tw, "CLUSTER\tPOOL\tNODES\tCPU REQ\tMEM REQ\tCPU USED\tMEM USED\tPOD SLOTS")
		for i, c := range report {
			for _, p := range pools[i] {
				used := func(v *int) string {
					if v == nil {
						return "-"
					}
					return gauge(*v)
				}
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n", strings.TrimSpace(strings.ToUpper(c.Environment)+" "+c.Cluster), p.Pool, p.Nodes,
					gauge(p.CPUReqPct), gauge(p.MemReqPct), used(p.CPUUsedPct), used(p.MemUsedPct), gauge(p.PodsPct))
			}
		}
		tw.Flush()
		fmt.Fprintln(stdout)
		printReport(stdout, cfg, report, *minSev)
		printFixes(stdout, report, *minSev)
		fmt.Fprintf(stdout, "\n%s\n", st.Dim("REQ is what pods asked for (the scheduler's view); USED is metrics-server's · cordoned nodes are left out"))
	}
	if failed(report, *failOn) {
		return ExitFailure
	}
	return ExitOK
}

// gauge is a percent with a ten-step bar: 72% ███████░░░.
func gauge(p int) string {
	n := min(10, max(0, (p+5)/10))
	return fmt.Sprintf("%3d%% %s%s", p, strings.Repeat("█", n), strings.Repeat("░", 10-n))
}
