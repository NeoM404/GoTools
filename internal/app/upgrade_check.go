package app

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"nedctl/internal/config"
)

// The assessment behind `nedctl upgrade-check`: EKS facts (upgrade_facts.go)
// and a few paged kubectl lists, judged against the rules (upgrade_rules.go)
// in eight areas — version and support, breaking changes, removed APIs,
// add-ons, Karpenter, nodes, workloads, EKS Upgrade Insights — plus
// fail-closed webhooks and CRD stored versions. Each finding carries the
// points it costs; the readiness score is 100 less the points (capped per
// area), and a hard blocker caps it at 59. Checks that could not run are
// listed as not assessed and make the score provisional: never a pass.

func upgradeProbes(target int) []probe {
	nsKinds := "deployments,daemonsets,statefulsets,cronjobs,ingresses,networkpolicies,poddisruptionbudgets,horizontalpodautoscalers"
	if target >= 33 {
		nsKinds += ",endpoints"
	}
	fields := `{range .items[*]}{.kind}{"\t"}{.metadata.namespace}{"/"}{.metadata.name}{"\t"}{range .metadata.managedFields[*]}{.manager}{"="}{.apiVersion}{","}{end}{"\n"}{end}`
	return []probe{
		versionProbe,
		clusterProbe("nodes", `{range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kubeletVersion}{"\t"}{.status.nodeInfo.osImage}{"\t"}{.status.nodeInfo.kernelVersion}{"\t"}{.status.nodeInfo.containerRuntimeVersion}{"\t"}{.metadata.labels.eks\.amazonaws\.com/nodegroup}{"\t"}{.metadata.labels.karpenter\.sh/nodepool}{"\t"}{.metadata.labels.eks\.amazonaws\.com/compute-type}{"\t"}{.metadata.labels.node\.kubernetes\.io/instance-type}{"\n"}{end}`),
		listProbe("deployments,statefulsets,daemonsets", "", `{range .items[*]}W{"\t"}{.kind}{"\t"}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.replicas}{"\t"}{.spec.strategy.type}{.spec.updateStrategy.type}{"\t"}{.spec.template.metadata.labels}{"\t"}{.spec.template.metadata.annotations}{"\t"}{.spec.template.spec.volumes[*].gitRepo.repository}{"\t"}{.spec.template.spec.securityContext.appArmorProfile.type}{"\n"}`+
			`{range .spec.template.spec.containers[*]}C{"\t"}{.name}{"\t"}{.image}{"\t"}{.readinessProbe.periodSeconds}{"\t"}{.resources.requests.cpu}{"\t"}{.resources.requests.memory}{"\t"}{.lifecycle.preStop}{"\t"}{.securityContext.appArmorProfile.type}{"\n"}{end}{end}`),
		listProbe("poddisruptionbudgets", "", `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.selector}{"\t"}{.spec.minAvailable}{"\t"}{.spec.maxUnavailable}{"\t"}{.status.expectedPods}{"\t"}{.status.currentHealthy}{"\t"}{.status.desiredHealthy}{"\t"}{.status.disruptionsAllowed}{"\t"}{.status.observedGeneration}{"\t"}{.metadata.generation}{"\t"}{.spec.unhealthyPodEvictionPolicy}{"\n"}{end}`),
		listProbe("pods", "", `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.metadata.labels}{"\t"}{.spec.nodeName}{"\t"}{.status.phase}{"\t"}{.metadata.deletionTimestamp}{"\n"}{end}`),
		listProbe(nsKinds, "", fields),
		clusterProbe("customresourcedefinitions,validatingwebhookconfigurations,mutatingwebhookconfigurations,flowschemas,prioritylevelconfigurations,priorityclasses", fields),
		listProbe("services", "", `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.type}{"\t"}{.spec.selector}{"\t"}{.spec.externalIPs[*]}{"\t"}{.spec.loadBalancerSourceRanges[*]}{"\n"}{end}`),
		listProbe("networkpolicies", "", `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.ingress[*].from[*].ipBlock.cidr} {.spec.egress[*].to[*].ipBlock.cidr} {.spec.ingress[*].from[*].ipBlock.except[*]} {.spec.egress[*].to[*].ipBlock.except[*]}{"\n"}{end}`),
		clusterProbe("clusterrolebindings", `{range .items[*]}{.metadata.name}{"\t"}{.roleRef.name}{"\t"}{.subjects[*].name}{"\n"}{end}`),
		{"get", "configmap", "kube-proxy-config", "-n", "kube-system", "-o", `jsonpath={.data.config}`},
		clusterProbe("validatingwebhookconfigurations,mutatingwebhookconfigurations", `{range .items[*]}H{"\t"}{.kind}{"\t"}{.metadata.name}{"\n"}{range .webhooks[*]}B{"\t"}{.name}{"\t"}{.failurePolicy}{"\t"}{.timeoutSeconds}{"\t"}{.namespaceSelector}{"\t"}{.rules[*].resources}{"\t"}{.clientConfig.service.namespace}{"/"}{.clientConfig.service.name}{"\n"}{end}{end}`),
		clusterProbe("customresourcedefinitions", `{range .items[*]}{.metadata.name}{"\t"}{.status.storedVersions[*]}{"\t"}{range .spec.versions[*]}{.name}{"="}{.served}{","}{end}{"\n"}{end}`),
	}
}

const (
	upNodes = iota + 1
	upWorkloads
	upPDBs
	upPods
	upFieldsNS
	upFieldsCluster
	upServices
	upNetpol
	upCRB
	upKubeProxy
	upWebhooks
	upCRDs
)

// upgradeReport is one cluster's assessment.
type upgradeReport struct {
	clusterFindings
	Region      string      `json:"region,omitempty"`
	Current     string      `json:"currentVersion"`
	Target      string      `json:"targetVersion"`
	Path        []string    `json:"path,omitempty"` // when the target is more than one minor away
	Score       *int        `json:"score,omitempty"`
	Tier        string      `json:"tier"`
	Provisional bool        `json:"provisional"`
	Blockers    []string    `json:"blockers"`
	Breakdown   []scoreLine `json:"breakdown,omitempty"`
	Verify      []verify    `json:"verify,omitempty"`
	Plan        []planStep  `json:"plan,omitempty"`
	Facts       *eksFacts   `json:"facts,omitempty"`
}

type scoreLine struct {
	Area     string `json:"area"`
	Deducted int    `json:"deducted"`
	Max      int    `json:"max"`
}

// verify is something nedctl cannot judge offline: an add-on whose
// project publishes its supported Kubernetes versions.
type verify struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Where    string `json:"where"`
	URL      string `json:"url"`
	Critical bool   `json:"critical,omitempty"`
}

type planStep struct {
	Title    string   `json:"title"`
	Commands []string `json:"commands,omitempty"`
	Notes    []string `json:"notes,omitempty"`
}

// areaCaps are the most points each area can cost.
var areaCaps = []scoreLine{
	{"breaking-changes", 0, 25}, {"removed-apis", 0, 20}, {"nodes", 0, 20}, {"support", 0, 15}, {"addons", 0, 15},
	{"karpenter", 0, 10}, {"workloads", 0, 10}, {"insights", 0, 10}, {"al2", 0, 10},
}

// labelSelector is a Kubernetes label selector.
type labelSelector struct {
	MatchLabels      map[string]string `json:"matchLabels"`
	MatchExpressions []struct {
		Key, Operator string
		Values        []string
	} `json:"matchExpressions"`
}

func (s labelSelector) matches(l map[string]string) bool {
	for k, v := range s.MatchLabels {
		if l[k] != v {
			return false
		}
	}
	for _, e := range s.MatchExpressions {
		v, has := l[e.Key]
		in := false
		for _, x := range e.Values {
			in = in || x == v
		}
		switch e.Operator {
		case "In":
			if !has || !in {
				return false
			}
		case "NotIn":
			if has && in {
				return false
			}
		case "Exists":
			if !has {
				return false
			}
		case "DoesNotExist":
			if has {
				return false
			}
		}
	}
	return true
}

func jsonLabels(s string) map[string]string {
	m := map[string]string{}
	_ = json.Unmarshal([]byte(strings.TrimSpace(s)), &m)
	return m
}

type upNode struct {
	name, kubelet, os, kernel, runtime, nodegroup, nodepool, compute, instance string
}

func (n upNode) kind() string {
	switch {
	case n.compute == "fargate":
		return "fargate"
	case n.compute == "auto" || n.compute == "hybrid":
		return "eks-managed"
	case n.nodegroup != "":
		return "managed"
	case n.nodepool != "":
		return "karpenter"
	}
	return "self-managed"
}

func (n upNode) al2() bool {
	return strings.Contains(n.os, "Amazon Linux 2") && !strings.Contains(n.os, "2023")
}

type upContainer struct {
	name, image, readiness, cpu, memory, preStop, appArmor string
}

type upWorkload struct {
	kind, ns, name, strategy, gitRepo, appArmor string
	replicas                                    int
	labels, annotations                         map[string]string
	containers                                  []upContainer
}

func (w upWorkload) ref() string { return strings.ToLower(w.kind) + "/" + w.ns + "/" + w.name }

type upPDB struct {
	ns, name, minAvailable, maxUnavailable, policy string
	selector                                       *labelSelector // nil: selects nothing
	expected, healthy, desired, allowed            int
	fresh                                          bool
}

type upPod struct {
	ns, name, node string
	labels         map[string]string
	live           bool // scheduled, running, not terminating
}

func atoi(s string) int { n, _ := strconv.Atoi(strings.TrimSpace(s)); return n }

// assessUpgrade judges one cluster. co is nil when the cluster could not be
// read with kubectl (the EKS findings still count).
func assessUpgrade(cfg config.Config, f eksFacts, co clusterOut, target string, today time.Time) upgradeReport {
	rep := upgradeReport{clusterFindings: newClusterFindings(co), Region: f.Region, Current: f.Version, Target: target, Blockers: []string{}}
	rep.Cluster, rep.Cloud = f.Cluster, "aws"
	rep.Status = "ok"
	rep.Facts = &f
	cur, tgt := minorOf(f.Version), minorOf(target)
	add := func(area, check, sev, title, object, detail, fix string, points int, blocker bool) {
		rep.add(checkFinding{Check: check, Area: area, Severity: sev, Title: title, Object: object, Detail: detail, Fix: fix, Points: points, Blocker: blocker, Source: sourceOf(area)})
		if blocker {
			rep.Blockers = append(rep.Blockers, title+ifNonBlank(": ", object))
		}
	}
	for what, err := range f.Errors {
		rep.unassessed("EKS %s: %s", what, err)
	}

	// 1. Version, path and support.
	if tgt > cur+1 {
		for m := cur + 1; m <= tgt; m++ {
			rep.Path = append(rep.Path, "1."+strconv.Itoa(m))
		}
		add("version", "multi-hop", "info", "EKS upgrades one minor version at a time", "", "path "+f.Version+" → "+strings.Join(rep.Path, " → ")+"; this assessment is for the whole path's removals, run it again before each hop", "", 0, false)
	}
	available := false
	var curInfo eksVersionInfo
	for _, v := range f.Versions {
		if minorOf(v.Version) == tgt {
			available = true
		}
		if minorOf(v.Version) == cur {
			curInfo = v
		}
	}
	if len(f.Versions) > 0 && !available {
		add("version", "target-unavailable", "critical", "the target version is not available on EKS", "Kubernetes "+target,
			"EKS offers "+versionList(f.Versions), "assess the newest version EKS offers instead", 0, true)
	}
	if f.Status != "" && f.Status != "ACTIVE" {
		add("version", "cluster-not-active", "critical", "the cluster is not ACTIVE", f.Cluster, "status "+f.Status, "wait for the cluster's current operation to finish", 0, true)
	}
	for _, i := range f.HealthIssues {
		add("version", "cluster-health", "high", "the cluster reports a health issue", f.Cluster, i, "resolve it before upgrading (aws eks describe-cluster shows it)", 0, false)
	}
	switch {
	case curInfo.Status == "UNSUPPORTED" || (curInfo.ExtendedEnd != "" && today.Format("2006-01-02") >= curInfo.ExtendedEnd):
		add("support", "unsupported-version", "critical", "the current version is out of support", "Kubernetes "+f.Version,
			"no security fixes; AWS upgrades it automatically at the end of extended support", "upgrade now", 15, false)
	case curInfo.Status == "EXTENDED_SUPPORT" || (curInfo.StandardEnd != "" && today.Format("2006-01-02") >= curInfo.StandardEnd):
		detail := "until " + curInfo.ExtendedEnd
		if r := cfg.CostRates.AWS; r.ExtendedHourly > r.StandardHourly {
			detail += fmt.Sprintf("; about %s %.0f a month more per cluster ((%.2f − %.2f) × 730 h)", cfg.CostRates.Currency, (r.ExtendedHourly-r.StandardHourly)*730, r.ExtendedHourly, r.StandardHourly)
		}
		add("support", "extended-support", "info", "the current version is in extended support (costs more)", "Kubernetes "+f.Version, detail, "", 0, false)
	case curInfo.StandardEnd != "":
		add("support", "standard-support", "info", "the current version is in standard support", "Kubernetes "+f.Version, "until "+curInfo.StandardEnd, "", 0, false)
	}
	if f.AuthMode == "CONFIG_MAP" {
		add("version", "aws-auth-configmap", "low", "cluster access still only through the aws-auth ConfigMap", f.Cluster, "", "move to access entries (API_AND_CONFIG_MAP, then API): nedctl eks auth", 0, false)
	}

	// 2. EKS Upgrade Insights (scored after the removed-API check, below).
	kube := co.reachErr() == nil
	if !kube {
		rep.unassessed("everything read from the cluster itself (nodes, workloads, APIs in use): %v", co.reachErr())
	}
	lines := func(i int, what string, optional bool) ([]string, bool) {
		if !kube || i >= len(co.Outs) {
			return nil, false
		}
		if err := co.Outs[i].Err; err != nil {
			if !(optional && notInstalled(err)) {
				rep.unassessed("%s: %v", what, err)
			}
			return nil, false
		}
		return nonEmptyLines(string(co.Outs[i].Out)), true
	}

	// The cluster's inventory.
	var nodes []upNode
	nl, nodesOK := lines(upNodes, "nodes", false)
	for _, l := range nl {
		x := strings.Split(l, "\t")
		if len(x) < 9 {
			continue
		}
		nodes = append(nodes, upNode{x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8]})
	}
	var workloads []upWorkload
	wl, workloadsOK := lines(upWorkloads, "workloads", false)
	for _, l := range wl {
		x := strings.Split(l, "\t")
		switch {
		case len(x) >= 10 && x[0] == "W":
			w := upWorkload{kind: x[1], ns: x[2], name: x[3], replicas: -1, strategy: x[5], labels: jsonLabels(x[6]), annotations: jsonLabels(x[7]), gitRepo: strings.TrimSpace(x[8]), appArmor: x[9]}
			if x[4] != "" {
				w.replicas = atoi(x[4])
			}
			workloads = append(workloads, w)
		case len(x) >= 8 && x[0] == "C" && len(workloads) > 0:
			w := &workloads[len(workloads)-1]
			w.containers = append(w.containers, upContainer{x[1], x[2], x[3], x[4], x[5], x[6], x[7]})
		}
	}
	var pdbs []upPDB
	pl, pdbsOK := lines(upPDBs, "pod disruption budgets", false)
	for _, l := range pl {
		x := strings.Split(l, "\t")
		if len(x) < 12 {
			continue
		}
		p := upPDB{ns: x[0], name: x[1], minAvailable: x[3], maxUnavailable: x[4], expected: atoi(x[5]), healthy: atoi(x[6]), desired: atoi(x[7]), allowed: atoi(x[8]),
			fresh: x[9] != "" && x[9] == x[10], policy: firstNonBlank(x[11], "IfHealthyBudget")}
		if s := strings.TrimSpace(x[2]); s != "" {
			var sel labelSelector
			if json.Unmarshal([]byte(s), &sel) == nil {
				p.selector = &sel
			}
		}
		pdbs = append(pdbs, p)
	}
	var pods []upPod
	pol, podsOK := lines(upPods, "pods", false)
	for _, l := range pol {
		x := strings.Split(l, "\t")
		if len(x) < 6 {
			continue
		}
		pods = append(pods, upPod{ns: x[0], name: x[1], labels: jsonLabels(x[2]), node: x[3], live: x[3] != "" && x[4] == "Running" && x[5] == ""})
	}
	userNS := func(ns string) bool { return !upgradeSystemNamespaces[ns] && !cfg.Security.Ignored(ns) }

	// 3. Breaking changes for this hop.
	crossing := func(m int) bool { return cur < m && tgt >= m }
	if tgt > rulesCoverTo {
		rep.unassessed("breaking changes and API removals in Kubernetes %s: nedctl's tables cover up to 1.%d — read the Kubernetes and EKS release notes (EKS Upgrade Insights still apply)", target, rulesCoverTo)
	}
	breaking := func(sev, check, title, object, detail, fix string) {
		pts := map[string]int{"high": 10, "medium": 4, "low": 2}[sev]
		add("breaking-changes", check, sev, title, object, detail, fix, pts, false)
	}
	if workloadsOK {
		for _, w := range workloads {
			armor := w.appArmor != ""
			for k := range w.annotations {
				armor = armor || strings.HasPrefix(k, "container.apparmor.security.beta.kubernetes.io/")
			}
			for _, c := range w.containers {
				armor = armor || c.appArmor != ""
			}
			switch {
			case armor && tgt >= 34:
				breaking("medium", "apparmor", "uses AppArmor, which AWS deprecates from 1.34", w.ref(), "", "plan a move to seccomp profiles or Pod Security Standards")
			case tgt >= 30 && hasPrefixKey(w.annotations, "container.apparmor.security.beta.kubernetes.io/"):
				breaking("medium", "apparmor-annotation", "sets AppArmor with the deprecated annotation", w.ref(), "", "use securityContext.appArmorProfile instead")
			}
			if w.gitRepo != "" && tgt >= 36 {
				breaking("high", "gitrepo-volume", "uses a gitRepo volume, which 1.36 kubelets refuse to run", w.ref(), w.gitRepo, "clone in an init container or a git-sync sidecar instead")
			}
		}
	}
	if crossing(32) {
		if cl, ok := lines(upCRB, "cluster role bindings", false); ok {
			for _, l := range cl {
				x := strings.Split(l, "\t")
				if len(x) >= 3 && (strings.Contains(x[2], "system:unauthenticated") || strings.Contains(x[2], "system:anonymous")) && x[1] != "system:public-info-viewer" {
					breaking("medium", "anonymous-access", "grants anonymous requests more than the health endpoints, which 1.32 refuses", "clusterrolebinding/"+x[0], "role "+x[1], "authenticate the client (monitoring, load balancer health checks) or point it at /healthz, /livez or /readyz")
				}
			}
		}
	}
	if tgt >= 35 {
		if kl, ok := lines(upKubeProxy, "kube-proxy configuration", true); ok {
			conf := strings.ReplaceAll(strings.Join(kl, "\n"), `"`, "")
			if strings.Contains(conf, "mode: ipvs") {
				breaking("medium", "ipvs", "kube-proxy runs in IPVS mode, deprecated from 1.35", "kube-proxy", "", "plan a move to iptables or nftables mode")
			}
		}
	}
	if tgt >= 36 {
		if sl, ok := lines(upServices, "services", false); ok {
			for _, l := range sl {
				x := strings.Split(l, "\t")
				if len(x) < 6 {
					continue
				}
				if strings.TrimSpace(x[4]) != "" {
					breaking("low", "external-ips", "uses spec.externalIPs, deprecated in 1.36", "service/"+x[0]+"/"+x[1], x[4], "use a LoadBalancer Service, NodePort or the Gateway API")
				}
				for _, c := range strings.Fields(x[5]) {
					if bad := nonCanonicalCIDR(c); bad != "" {
						breaking("medium", "non-canonical-cidr", "a non-canonical IP or CIDR, refused on update from 1.36", "service/"+x[0]+"/"+x[1], c+" ("+bad+")", "write it canonically in the manifest")
					}
				}
			}
		}
		if nl, ok := lines(upNetpol, "network policies", false); ok {
			for _, l := range nl {
				x := strings.Split(l, "\t")
				if len(x) < 3 {
					continue
				}
				for _, c := range strings.Fields(x[2]) {
					if bad := nonCanonicalCIDR(c); bad != "" {
						breaking("medium", "non-canonical-cidr", "a non-canonical IP or CIDR, refused on update from 1.36", "networkpolicy/"+x[0]+"/"+x[1], c+" ("+bad+")", "write it canonically in the manifest")
					}
				}
			}
		}
	}

	// 4. Removed APIs still written by someone's tooling (managedFields
	// keeps the apiVersion each writer used, even after conversion).
	scoredPaths := map[string]bool{}
	removedPts := 0
	for _, i := range []int{upFieldsNS, upFieldsCluster} {
		fl, _ := lines(i, "API versions in use (managedFields)", false)
		for _, l := range fl {
			x := strings.SplitN(l, "\t", 3)
			if len(x) < 3 {
				continue
			}
			kind, obj := x[0], x[1]
			ns, _, _ := strings.Cut(obj, "/")
			for _, e := range strings.Split(x[2], ",") {
				manager, gv, ok := strings.Cut(e, "=")
				if !ok || systemWriter(manager) {
					continue
				}
				if kind == "Endpoints" && tgt >= 33 && userNS(ns) && manager != "endpoint-controller" && !strings.Contains(manager, "controller-manager") {
					breaking("medium", "endpoints-api", "writes the Endpoints API, deprecated from 1.33", "endpoints/"+obj, "written by "+manager, "move that tooling to EndpointSlices (discovery.k8s.io/v1)")
					continue
				}
				r, ok := removedFor(gv, kind)
				if !ok {
					continue
				}
				path := gv + " " + kind
				object := strings.ToLower(kind) + "/" + strings.TrimPrefix(obj, "/")
				switch {
				case r.RemovedIn > cur && r.RemovedIn <= tgt:
					pts := 0
					if !scoredPaths[path] {
						scoredPaths[path] = true
						pts = min(5, 20-removedPts)
						removedPts += pts
					}
					add("removed-apis", "removed-api", "high", fmt.Sprintf("%s %s is removed in 1.%d", kind, gv, r.RemovedIn), object, "written by "+manager, "update the manifest (Helm chart, GitOps repo) to "+r.Replacement+" and apply it before the upgrade", pts, false)
				case r.RemovedIn > tgt:
					add("removed-apis", "removed-later", "info", fmt.Sprintf("%s %s is removed in 1.%d (a later upgrade)", kind, gv, r.RemovedIn), object, "written by "+manager, "plan the move to "+r.Replacement, 0, false)
				default:
					add("removed-apis", "stale-manifest", "medium", fmt.Sprintf("its manifest still uses %s, removed in 1.%d", gv, r.RemovedIn), object, "written by "+manager+"; the next apply of that manifest will fail", "update the manifest to "+r.Replacement, 0, false)
				}
			}
		}
	}

	// 5. EKS Upgrade Insights, not counting what the API check already
	// scored.
	insightPts := 0
	for _, in := range f.Insights {
		if in.Status == "PASSING" {
			continue
		}
		detail := firstNonBlank(in.Reason, in.Status)
		var clients []string
		confirms := false
		for _, d := range in.Deprecation {
			clients = append(clients, d.Clients...)
			for p := range scoredPaths {
				gv, _, _ := strings.Cut(p, " ")
				if strings.Contains(d.Usage, "/"+gv+"/") {
					confirms = true
				}
			}
		}
		if len(clients) > 0 {
			detail += "; still called by " + strings.Join(clients, ", ")
		}
		if len(in.Resources) > 0 {
			detail += fmt.Sprintf("; %d resource(s): %s", len(in.Resources), strings.Join(in.Resources[:min(3, len(in.Resources))], ", "))
		}
		if in.Category == "MISCONFIGURATION" {
			add("misconfiguration", "eks-insight", insightSeverity(in.Status), in.Name, "insight "+in.ID, detail, in.Recommend, 0, false)
			continue
		}
		sev, pts := insightSeverity(in.Status), map[string]int{"ERROR": 5, "WARNING": 2}[in.Status]
		switch {
		case in.Version != "" && minorOf(in.Version) > tgt:
			sev, pts = "info", 0
			detail = "flagged for " + in.Version + ", a later upgrade; " + detail
		case confirms:
			pts = 0
			detail = "confirms the removed-API finding above; " + detail
		}
		pts = min(pts, 10-insightPts)
		insightPts += pts
		add("insights", "eks-insight", sev, in.Name, "insight "+in.ID, detail, in.Recommend, pts, false)
	}

	// 6. Add-ons managed by EKS.
	curSets, tgtSets := f.AddonVersions[f.Version], f.AddonVersions[target]
	managedNames := map[string]bool{}
	for _, a := range f.Addons {
		managedNames[a.Name] = true
		critical := criticalAddons[a.Name]
		obj := "addon/" + a.Name + " " + a.Version
		if a.Status == "DEGRADED" || strings.HasSuffix(a.Status, "FAILED") {
			pts := 3
			if critical {
				pts = 5
			}
			add("addons", "addon-unhealthy", map[bool]string{true: "critical", false: "high"}[critical], "the add-on is "+a.Status, obj, strings.Join(a.HealthIssues, "; "), "fix its health first: aws eks describe-addon shows the issue", pts, critical)
			continue
		}
		b, known := tgtSets[a.Name]
		if tgtSets == nil || !known {
			rep.unassessed("add-on %s: the builds compatible with %s could not be read", a.Name, target)
			continue
		}
		if !contains(b.Versions, a.Version) {
			pts, sev := 3, "high"
			if critical {
				pts, sev = 5, "critical"
			}
			fix := "update it to " + firstNonBlank(b.Default, newest(b.Versions)) + " after the control plane"
			if both := newest(intersect(curSets[a.Name].Versions, b.Versions)); both != "" {
				fix = "update it to " + both + " (supports " + f.Version + " and " + target + ") before the control plane"
			}
			add("addons", "addon-incompatible", sev, "the installed build does not support "+target, obj, "", fix, pts, critical)
			continue
		}
		if a.Name == "kube-proxy" && tgt-minorOf(a.Version) > 3 {
			add("addons", "kube-proxy-skew", "medium", "kube-proxy is more than three minors behind the target", obj, "", "update kube-proxy to "+b.Default, 2, false)
			continue
		}
		if dv, ok1 := parseBuildVersion(b.Default); ok1 {
			if iv, ok2 := parseBuildVersion(a.Version); ok2 && iv.less(dv) {
				add("addons", "addon-update", "low", "older than "+target+"'s default build", obj, "default "+b.Default, "update it after the control plane", 1, false)
			}
		}
	}
	// Core add-ons running self-managed (not EKS add-ons) and other
	// add-ons people installed.
	if workloadsOK {
		self := map[string]string{"coredns": "deployment/kube-system/coredns", "kube-proxy": "daemonset/kube-system/kube-proxy", "vpc-cni": "daemonset/kube-system/aws-node"}
		for name, ref := range self {
			for _, w := range workloads {
				if w.ref() == ref && !managedNames[name] {
					add("addons", "self-managed-addon", "medium", name+" is self-managed: EKS will not update it", ref, "", "update it by hand with the control plane, or adopt the EKS add-on (aws eks create-addon --resolve-conflicts OVERWRITE)", 0, false)
				}
			}
		}
		seen := map[string]bool{}
		for _, w := range workloads {
			for _, c := range w.containers {
				a, ok := ossAddonFor(c.image)
				if !ok || seen[a.Name] {
					continue
				}
				seen[a.Name] = true
				version := imageTag(c.image)
				switch a.Name {
				case "karpenter":
					karpenterCheck(&rep, add, version, tgt, w.ref())
				case "cluster-autoscaler":
					if m := minorOf(version); m > 0 && m != tgt {
						add("addons", "cluster-autoscaler-version", "low", "cluster-autoscaler must match the Kubernetes minor", w.ref(), "runs "+version+", the target is "+target, "update it to a 1."+strconv.Itoa(tgt)+".x release with the control plane", 1, false)
					}
				case "ingress-nginx":
					breaking("high", "ingress-nginx-retired", "ingress-nginx is retired", w.ref(), a.Note, "migrate to the AWS Load Balancer Controller or a Gateway API implementation")
				}
				if a.Name != "karpenter" && a.Name != "ingress-nginx" {
					rep.Verify = append(rep.Verify, verify{Name: a.Name, Version: version, Where: w.ref(), URL: a.URL, Critical: a.Critical})
				}
			}
		}
	}

	// 7. Nodes.
	for _, ng := range f.Nodegroups {
		if ng.Status == "UPDATING" {
			add("nodes", "nodegroup-updating", "medium", "a node group is mid-update: the node picture may be mixed", "nodegroup/"+ng.Name, "", "run upgrade-check again when it is ACTIVE", 0, false)
		}
		for _, i := range ng.HealthIssues {
			add("nodes", "nodegroup-health", "high", "the node group reports a health issue", "nodegroup/"+ng.Name, i, "resolve it first: node updates stall on unhealthy groups", 0, false)
		}
		if ng.AMIType == "CUSTOM" {
			add("nodes", "custom-ami", "info", "a custom AMI: build one for "+target+" first", "nodegroup/"+ng.Name, "launch template "+ng.LaunchTemplate, "bake the AMI for "+target+" and update the launch template version", 0, false)
		}
	}
	if nodesOK {
		minors := map[int][]string{}
		al2, selfManaged, containerd1 := 0, 0, []string{}
		for _, n := range nodes {
			m := minorOf(n.kubelet)
			minors[m] = append(minors[m], n.name)
			if n.al2() {
				al2++
			}
			if n.kind() == "self-managed" {
				selfManaged++
			}
			if strings.HasPrefix(n.runtime, "containerd://1.") {
				containerd1 = append(containerd1, n.name)
			}
		}
		keys := make([]int, 0, len(minors))
		for m := range minors {
			keys = append(keys, m)
		}
		sort.Ints(keys)
		for _, m := range keys {
			skew := tgt - m
			names := strings.Join(minors[m][:min(3, len(minors[m]))], ", ")
			switch {
			case skew > 3:
				add("nodes", "kubelet-skew", "critical", fmt.Sprintf("kubelets on 1.%d are more than three minors behind %s", m, target), fmt.Sprintf("%d node(s)", len(minors[m])), names, "upgrade these nodes before the control plane", 20, true)
			case skew == 3:
				add("nodes", "kubelet-skew", "medium", fmt.Sprintf("kubelets on 1.%d will be at the largest skew allowed", m), fmt.Sprintf("%d node(s)", len(minors[m])), names, "upgrade these nodes right after the control plane", 5, false)
			}
		}
		if al2 > 0 {
			if tgt >= 33 {
				breaking("high", "al2-nodes", "Amazon Linux 2 nodes: no AL2 AMIs for 1.33 and later", fmt.Sprintf("%d node(s)", al2), "AL2 also uses cgroup v1, which 1.35 kubelets refuse by default", "move the node groups to AL2023 or Bottlerocket before upgrading")
			}
			add("al2", "al2-nodes", map[bool]string{true: "high", false: "low"}[tgt >= 33], "Amazon Linux 2 nodes (AL2 support ended 2026-06-30)", fmt.Sprintf("%d node(s)", al2), "", "plan the move to AL2023", min(5, 2+al2/10), false)
		}
		if selfManaged > 0 {
			add("nodes", "self-managed-nodes", "medium", "self-managed nodes: no automated upgrade", fmt.Sprintf("%d node(s)", selfManaged), "", "build an AMI for "+target+" and replace them", 3, false)
		}
		if len(containerd1) > 0 {
			sev, pts := "medium", 2
			if tgt >= 36 && selfManaged > 0 {
				sev, pts = "high", 5
			}
			add("nodes", "containerd-1", sev, "nodes on containerd 1.x (1.36 kubelets are tested with containerd 2)", fmt.Sprintf("%d node(s)", len(containerd1)), strings.Join(containerd1[:min(3, len(containerd1))], ", "),
				"managed node groups move to containerd 2 when updated; rebuild self-managed and custom AMIs", pts, false)
		}
	}
	if len(f.Subnets) > 0 {
		total := 0
		for _, s := range f.Subnets {
			total += s.Available
			if s.Available <= 15 {
				add("nodes", "subnet-ips", "medium", "few free IP addresses in a cluster subnet", "subnet/"+s.ID, fmt.Sprintf("%d free in %s (%s)", s.Available, s.Zone, s.CIDR), "review capacity for the control plane's new ENIs and the node update's surge", 2, false)
			}
		}
		if total < 5 {
			add("nodes", "subnet-capacity", "critical", "fewer than 5 free IPs across the cluster subnets", f.Cluster, fmt.Sprintf("%d free in all", total), "add subnets with free addresses to the cluster before upgrading", 5, true)
		}
	}
	if f.AutoMode {
		add("nodes", "auto-mode", "info", "EKS Auto Mode: AWS upgrades the nodes after the control plane", "", "", "", 0, false)
	}
	if len(f.Fargate) > 0 {
		add("nodes", "fargate", "info", "Fargate: pods run on the new version only once redeployed", strings.Join(f.Fargate, ", "), "", "after the control plane: kubectl rollout restart the Fargate workloads", 0, false)
	}

	// 8. Workloads: will node rotation take them down?
	if workloadsOK {
		hiPts, medPts := 0, 0
		score := func(high bool, pts int) int {
			if high {
				pts = min(pts, 8-hiPts)
				hiPts += pts
				return pts
			}
			pts = min(pts, 4-medPts)
			medPts += pts
			return pts
		}
		exposed := map[string]bool{}
		if sl, ok := lines(upServices, "services", false); ok {
			for _, l := range sl {
				x := strings.Split(l, "\t")
				if len(x) >= 4 && x[2] == "LoadBalancer" {
					sel := jsonLabels(x[3])
					for _, w := range workloads {
						if w.ns == x[0] && len(sel) > 0 && (labelSelector{MatchLabels: sel}).matches(w.labels) {
							exposed[w.ref()] = true
						}
					}
				}
			}
		}
		for _, w := range workloads {
			if !userNS(w.ns) {
				continue
			}
			if (w.kind == "Deployment" || w.kind == "StatefulSet") && w.replicas == 1 {
				add("workloads", "single-replica", "high", "one replica: unavailable while its node is replaced", w.ref(), "", "run 2 or more replicas (and a PodDisruptionBudget)", score(true, 3), false)
			}
			if w.kind == "Deployment" && w.strategy == "Recreate" {
				add("workloads", "recreate-strategy", "high", "Recreate strategy: every pod stops before new ones start on a rollout", w.ref(), "", "use RollingUpdate unless the application cannot run two versions at once", score(true, 3), false)
			}
			var noReady, noReq, noStop []string
			for _, c := range w.containers {
				if c.readiness == "" {
					noReady = append(noReady, c.name)
				}
				if c.cpu == "" || c.memory == "" {
					noReq = append(noReq, c.name)
				}
				if c.preStop == "" {
					noStop = append(noStop, c.name)
				}
			}
			if len(noReady) > 0 {
				add("workloads", "no-readiness-probe", "medium", "no readiness probe: traffic reaches pods before they are ready", w.ref(), "containers "+strings.Join(noReady, ", "), "add a readinessProbe", score(false, 1), false)
			}
			if len(noReq) > 0 {
				add("workloads", "no-requests", "medium", "no CPU or memory request: rescheduling cannot place it reliably", w.ref(), "containers "+strings.Join(noReq, ", "), "set resources.requests", score(false, 1), false)
			}
			if exposed[w.ref()] && len(noStop) == len(w.containers) {
				add("workloads", "no-prestop", "medium", "behind a load balancer without a preStop hook: requests fail as pods stop", w.ref(), "", "add a short preStop sleep so the load balancer drains first", score(false, 1), false)
			}
			if w.kind == "Deployment" && w.replicas > 1 && pdbsOK {
				covered := false
				for _, p := range pdbs {
					covered = covered || (p.ns == w.ns && p.selector != nil && p.selector.matches(w.labels))
				}
				if !covered {
					add("workloads", "no-pdb", "medium", "no PodDisruptionBudget: a node drain may evict every replica at once", w.ref(), fmt.Sprintf("%d replicas", w.replicas), "add a PodDisruptionBudget (maxUnavailable: 1)", score(false, 1), false)
				}
			}
		}
		// PDBs that will stall node rotation.
		drainPts := 0
		if pdbsOK && podsOK {
			cover := map[string][]string{} // pod → PDBs selecting it
			for _, p := range pods {
				if !p.live || !userNS(p.ns) {
					continue
				}
				for _, b := range pdbs {
					if b.ns == p.ns && b.selector != nil && b.selector.matches(p.labels) {
						cover[p.ns+"/"+p.name] = append(cover[p.ns+"/"+p.name], b.name)
					}
				}
			}
			overlap := map[string][]string{}
			for pod, list := range cover {
				if len(list) > 1 {
					for _, b := range list {
						overlap[b] = append(overlap[b], pod)
					}
				}
			}
			for _, b := range pdbs {
				if !userNS(b.ns) {
					continue
				}
				var reasons []string
				if b.fresh && b.expected > 0 && b.allowed == 0 {
					switch {
					case b.maxUnavailable == "0" || b.maxUnavailable == "0%" || b.minAvailable == "100%" || (b.minAvailable != "" && !strings.HasSuffix(b.minAvailable, "%") && atoi(b.minAvailable) >= b.expected):
						reasons = append(reasons, "it allows no disruption even at full health (configuration)")
					case b.healthy < b.desired:
						reasons = append(reasons, fmt.Sprintf("only %d of %d pods healthy, %d needed", b.healthy, b.expected, b.desired))
					default:
						reasons = append(reasons, "no disruption allowed right now")
					}
					if b.policy == "AlwaysAllow" && b.healthy < b.expected {
						reasons[len(reasons)-1] += " (unhealthy pods may still be evicted: AlwaysAllow)"
					}
				}
				if pods := overlap[b.name]; len(pods) > 0 {
					sort.Strings(pods)
					reasons = append(reasons, fmt.Sprintf("selects pods another PDB also selects (%s) — eviction refuses those pods", pods[0]))
				}
				if len(reasons) == 0 {
					continue
				}
				pts := min(2, 4-drainPts)
				drainPts += pts
				add("workloads", "pdb-blocks-drain", "medium", "may stall node maintenance", "pdb/"+b.ns+"/"+b.name, strings.Join(reasons, "; "), "review the budget with the owner before the node update (never force the update past it)", pts, false)
			}
		}
	}

	// 9. Webhooks that can stop the cluster recovering, and CRDs.
	if wl, ok := lines(upWebhooks, "webhook configurations", false); ok {
		cfgName := ""
		for _, l := range wl {
			x := strings.Split(l, "\t")
			switch {
			case len(x) >= 3 && x[0] == "H":
				cfgName = x[2]
			case len(x) >= 7 && x[0] == "B":
				broad := strings.Contains(x[5], `"pods"`) || strings.Contains(x[5], `"*"`) || strings.Contains(x[5], `"nodes"`)
				if x[2] == "Fail" && broad && !strings.Contains(x[4], "kube-system") {
					add("webhooks", "fail-closed-webhook", "medium", "a fail-closed webhook on pods or nodes, kube-system included", "webhook/"+cfgName+" ("+x[1]+")",
						"served by "+x[6]+"; if its pods are down during node rotation, those creates fail cluster-wide", "run it with 2+ replicas and a PDB, and exclude kube-system with a namespaceSelector", 0, false)
				}
			}
		}
	}
	if cl, ok := lines(upCRDs, "custom resource definitions", false); ok {
		for _, l := range cl {
			x := strings.Split(l, "\t")
			if len(x) < 3 {
				continue
			}
			served := map[string]bool{}
			for _, v := range strings.Split(x[2], ",") {
				if n, s, ok := strings.Cut(v, "="); ok {
					served[n] = s == "true"
				}
			}
			for _, v := range strings.Fields(x[1]) {
				if !served[v] {
					add("crds", "crd-stored-version", "medium", "objects stored in a version no longer served", "crd/"+x[0], "storedVersions has "+v, "migrate stored objects (re-write them) before the add-on removes "+v, 0, false)
				}
			}
		}
	}

	rep.finishUpgrade()
	rep.Plan = upgradePlan(f, rep, target)
	return rep
}

func hasPrefixKey(m map[string]string, prefix string) bool {
	for k := range m {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

func karpenterCheck(rep *upgradeReport, add func(area, check, sev, title, object, detail, fix string, points int, blocker bool), version string, tgt int, where string) {
	want, known := karpenterMinimum[tgt]
	have, ok := parseBuildVersion(version)
	switch {
	case !known:
		rep.unassessed("Karpenter %s against 1.%d: not in nedctl's matrix — check https://karpenter.sh/docs/upgrading/compatibility/", version, tgt)
	case !ok:
		rep.unassessed("Karpenter's version (image %q): not readable — check https://karpenter.sh/docs/upgrading/compatibility/", version)
	default:
		w, _ := parseBuildVersion(want)
		if have.less(w) {
			add("karpenter", "karpenter-incompatible", "critical", fmt.Sprintf("Karpenter %s does not support 1.%d (needs %s or later)", version, tgt, want), where, "", "upgrade Karpenter BEFORE the control plane, to a release supporting both versions (crossing 1.0 also migrates its APIs)", 10, true)
		}
	}
}

func insightSeverity(status string) string {
	switch status {
	case "ERROR":
		return "high"
	case "WARNING":
		return "medium"
	}
	return "low"
}

func sourceOf(area string) string {
	switch area {
	case "insights", "misconfiguration":
		return "eks-insights"
	case "version", "support", "addons":
		return "eks-api"
	}
	return "kubernetes"
}

func versionList(vs []eksVersionInfo) string {
	var s []string
	for _, v := range vs {
		s = append(s, v.Version)
	}
	return strings.Join(s, ", ")
}

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		if contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func newest(vs []string) string {
	best, bestV := "", buildVersion{}
	for _, v := range vs {
		if s, ok := parseBuildVersion(v); ok && (best == "" || bestV.less(s)) {
			best, bestV = v, s
		}
	}
	return best
}

// nonCanonicalCIDR says what is wrong with an IP or CIDR ("" when fine):
// leading zeros, or host bits set in a CIDR.
func nonCanonicalCIDR(s string) string {
	addr, bits, isCIDR := strings.Cut(s, "/")
	for _, o := range strings.Split(addr, ".") {
		if len(o) > 1 && o[0] == '0' {
			return "leading zeros"
		}
	}
	if !isCIDR || strings.Contains(addr, ":") {
		return ""
	}
	n := atoi(bits)
	parts := strings.Split(addr, ".")
	if len(parts) != 4 || n < 0 || n > 32 {
		return ""
	}
	var ip uint32
	for _, p := range parts {
		ip = ip<<8 | uint32(atoi(p))
	}
	if n < 32 && ip&(1<<(32-n)-1) != 0 {
		return "host bits set"
	}
	return ""
}

// finishUpgrade sorts the findings and works out the score.
func (r *upgradeReport) finishUpgrade() {
	r.finish()
	if r.Status == "unreachable" && r.Current == "" {
		r.Tier = "NOT ASSESSED"
		return
	}
	for _, f := range r.Findings {
		if f.Check == "target-unavailable" {
			r.Tier = "NOT ASSESSED"
			return
		}
	}
	deducted := map[string]int{}
	for _, f := range r.Findings {
		deducted[f.Area] += f.Points
	}
	total := 0
	for _, c := range areaCaps {
		d := min(deducted[c.Area], c.Max)
		total += d
		r.Breakdown = append(r.Breakdown, scoreLine{c.Area, d, c.Max})
	}
	score := 100 - total
	if len(r.Blockers) > 0 {
		score = min(score, 59)
	}
	r.Score = &score
	switch {
	case score >= 90:
		r.Tier = "READY"
	case score >= 80:
		r.Tier = "GOOD"
	case score >= 70:
		r.Tier = "FAIR"
	case score >= 60:
		r.Tier = "RISKY"
	default:
		r.Tier = "NOT READY"
	}
	r.Provisional = len(r.Unassessed) > 0 || len(r.Verify) > 0
}

// upgradePlan is the order to do it in, with the commands filled in. They
// are printed for the engineer to run under their change record; nedctl
// never runs them.
func upgradePlan(f eksFacts, r upgradeReport, target string) []planStep {
	aws := func(args string) string {
		return "aws " + args + " --region " + f.Region + " --profile " + f.Profile
	}
	var plan []planStep
	if len(r.Blockers) > 0 {
		plan = append(plan, planStep{Title: "Resolve the blockers", Notes: r.Blockers})
	}
	var before []string
	for _, x := range r.Findings {
		if (x.Check == "addon-incompatible" && strings.Contains(x.Fix, "before the control plane")) || x.Check == "karpenter-incompatible" || x.Check == "removed-api" {
			before = append(before, x.Object+": "+x.Fix)
		}
	}
	for _, v := range r.Verify {
		before = append(before, fmt.Sprintf("verify %s %s supports %s: %s", v.Name, v.Version, target, v.URL))
	}
	if len(before) > 0 {
		plan = append(plan, planStep{Title: "Before the control plane", Notes: dedupe(before)})
	}
	plan = append(plan, planStep{Title: "Upgrade the control plane to " + target,
		Commands: []string{
			aws("eks update-cluster-version --name " + f.Cluster + " --kubernetes-version " + target),
			aws("eks wait cluster-active --name " + f.Cluster),
		},
		Notes: []string{"production: under an approved change record", "the API stays available; it takes 10–30 minutes"}})
	var addons []string
	order := map[string]int{"vpc-cni": 0, "kube-proxy": 1, "coredns": 2}
	sorted := append([]eksAddon(nil), f.Addons...)
	sort.SliceStable(sorted, func(i, j int) bool {
		oi, ok := order[sorted[i].Name]
		if !ok {
			oi = 3
		}
		oj, ok := order[sorted[j].Name]
		if !ok {
			oj = 3
		}
		return oi < oj
	})
	for _, a := range sorted {
		b := f.AddonVersions[target][a.Name]
		want := firstNonBlank(b.Default, newest(b.Versions))
		if want == "" || want == a.Version {
			continue
		}
		if iv, ok := parseBuildVersion(a.Version); ok {
			if wv, ok := parseBuildVersion(want); ok && !iv.less(wv) {
				continue
			}
		}
		addons = append(addons, aws("eks update-addon --cluster-name "+f.Cluster+" --addon-name "+a.Name+" --addon-version "+want+" --resolve-conflicts PRESERVE"))
	}
	if len(addons) > 0 {
		plan = append(plan, planStep{Title: "Update the EKS add-ons (EKS does not do it for you)", Commands: addons, Notes: []string{"one at a time; vpc-cni first, then kube-proxy and coredns"}})
	}
	var nodes []string
	var notes []string
	for _, ng := range f.Nodegroups {
		cmd := aws("eks update-nodegroup-version --cluster-name " + f.Cluster + " --nodegroup-name " + ng.Name + " --kubernetes-version " + target)
		if ng.AMIType == "CUSTOM" {
			cmd = aws("eks update-nodegroup-version --cluster-name " + f.Cluster + " --nodegroup-name " + ng.Name + " --launch-template name=" + strings.Split(ng.LaunchTemplate, ":")[0] + ",version=<new version with the " + target + " AMI>")
		}
		nodes = append(nodes, cmd)
	}
	for _, x := range r.Findings {
		if x.Check == "self-managed-nodes" {
			notes = append(notes, "self-managed nodes: replace them with an AMI for "+target)
		}
		if x.Check == "fargate" {
			notes = append(notes, "Fargate: kubectl rollout restart the workloads on Fargate profiles "+x.Object)
		}
		if x.Check == "pdb-blocks-drain" {
			notes = append(notes, "a disruption budget may stall the node update ("+x.Object+"): agree it with the owner first")
		}
	}
	if len(nodes) > 0 || len(notes) > 0 {
		plan = append(plan, planStep{Title: "Update the nodes", Commands: nodes, Notes: append(notes, "Karpenter replaces its nodes through drift once the control plane is upgraded")})
	}
	plan = append(plan, planStep{Title: "Check afterwards", Commands: []string{
		"nedctl health --cluster " + f.Cluster,
		"nedctl changes --cluster " + f.Cluster + " --since 3h",
		"nedctl upgrade-check --cluster " + f.Cluster + "   # the next hop, and anything left",
	}})
	return plan
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
