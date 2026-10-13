package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"

	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// `nedctl why SOURCE TARGET` answers "why can A not reach B?" by reading
// the objects on the path and evaluating them the way Kubernetes and Istio
// do — no traffic is sent:
//
//	the target Service exists, its port maps to a container port, it has
//	ready endpoints; NetworkPolicy lets the source send (egress, DNS
//	included) and the target receive (ingress), with pod and namespace
//	selectors, ipBlocks and named or ranged ports; Istio's mTLS mode and
//	authorization policies (DENY, then ALLOW) let this caller in.
//
// It ends with one verdict naming the object that blocks, and the live
// check to run (nedctl debug net). Read-only; a handful of namespaced reads.

type whyStep struct {
	Check  string `json:"check"`
	Result string `json:"result"` // ok | blocked | warn | unknown
	Detail string `json:"detail"`
	Object string `json:"object,omitempty"`
}

type whyPod struct {
	ns, name, ip, sa, phase string
	labels                  map[string]string
	sidecar                 bool
	ports                   map[string]int // container port name → number
}

const whyPodPath = `{range .items[*]}{.metadata.name}{"\t"}{.metadata.labels}{"\t"}{.status.podIP}{"\t"}{.spec.serviceAccountName}{"\t"}{.spec.containers[*].name} {.spec.initContainers[*].name}{"\t"}{.status.phase}{"\t"}{range .spec.containers[*].ports[*]}{.name}{"="}{.containerPort}{","}{end}{"\n"}{end}`

func parseWhyPods(ns string, out []byte) []whyPod {
	var pods []whyPod
	for _, l := range nonEmptyLines(string(out)) {
		f := strings.Split(l, "\t")
		if len(f) < 7 {
			continue
		}
		p := whyPod{ns: ns, name: f[0], labels: jsonLabels(f[1]), ip: f[2], sa: firstNonBlank(f[3], "default"), phase: f[5], ports: map[string]int{},
			sidecar: strings.Contains(" "+f[4]+" ", " istio-proxy ")}
		for _, e := range strings.Split(f[6], ",") {
			if n, v, ok := strings.Cut(e, "="); ok {
				p.ports[n] = atoi(v)
			}
		}
		pods = append(pods, p)
	}
	return pods
}

// NetworkPolicy, as much as evaluation needs.
type npPolicy struct {
	Metadata struct{ Name, Namespace string }
	Spec     struct {
		PodSelector labelSelector `json:"podSelector"`
		PolicyTypes []string      `json:"policyTypes"`
		Ingress     []npRule      `json:"ingress"`
		Egress      []npRule      `json:"egress"`
	}
}

type npRule struct {
	From  []npPeer `json:"from"`
	To    []npPeer `json:"to"`
	Ports []npPort `json:"ports"`
}

type npPeer struct {
	PodSelector       *labelSelector `json:"podSelector"`
	NamespaceSelector *labelSelector `json:"namespaceSelector"`
	IPBlock           *struct {
		CIDR   string   `json:"cidr"`
		Except []string `json:"except"`
	} `json:"ipBlock"`
}

type npPort struct {
	Protocol string          `json:"protocol"`
	Port     json.RawMessage `json:"port"`
	EndPort  int             `json:"endPort"`
}

func (p npPolicy) types() (ingress, egress bool) {
	if len(p.Spec.PolicyTypes) == 0 {
		return true, len(p.Spec.Egress) > 0
	}
	for _, t := range p.Spec.PolicyTypes {
		ingress = ingress || t == "Ingress"
		egress = egress || t == "Egress"
	}
	return ingress, egress
}

// endpoint is one side of a connection, for matching peers.
type endpoint struct {
	ns     string
	labels map[string]string
	ip     string
	inside bool // a pod in the cluster (else an outside address)
}

func ipIn(ip, cidr string) bool {
	_, n, err := net.ParseCIDR(cidr)
	addr := net.ParseIP(ip)
	return err == nil && addr != nil && n.Contains(addr)
}

func (peer npPeer) matches(policyNS string, e endpoint, nsLabels map[string]map[string]string) bool {
	if peer.IPBlock != nil {
		if e.ip == "" || !ipIn(e.ip, peer.IPBlock.CIDR) {
			return false
		}
		for _, x := range peer.IPBlock.Except {
			if ipIn(e.ip, x) {
				return false
			}
		}
		return true
	}
	if !e.inside {
		return false
	}
	switch {
	case peer.NamespaceSelector != nil && !peer.NamespaceSelector.matches(nsLabels[e.ns]):
		return false
	case peer.NamespaceSelector == nil && e.ns != policyNS:
		return false
	}
	return peer.PodSelector == nil || peer.PodSelector.matches(e.labels)
}

func portAllowed(ports []npPort, port int, name, proto string) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		if firstNonBlank(p.Protocol, "TCP") != proto {
			continue
		}
		if len(p.Port) == 0 || string(p.Port) == "null" {
			return true
		}
		var n int
		var s string
		switch {
		case json.Unmarshal(p.Port, &n) == nil:
			if port == n || (p.EndPort >= n && port >= n && port <= p.EndPort) {
				return true
			}
		case json.Unmarshal(p.Port, &s) == nil:
			if s == name && name != "" {
				return true
			}
		}
	}
	return false
}

// npVerdict evaluates one direction: is subject (isolated by the policies
// selecting it) allowed to talk to peer on port?
func npVerdict(policies []npPolicy, subject endpoint, peer endpoint, egress bool, port int, portName, proto string, nsLabels map[string]map[string]string) (allowed bool, isolating []string, allowedBy string) {
	for _, p := range policies {
		if p.Metadata.Namespace != subject.ns || !p.Spec.PodSelector.matches(subject.labels) {
			continue
		}
		in, out := p.types()
		rules := p.Spec.Ingress
		if egress {
			rules = p.Spec.Egress
		}
		if (egress && !out) || (!egress && !in) {
			continue
		}
		isolating = append(isolating, p.Metadata.Namespace+"/"+p.Metadata.Name)
		for _, r := range rules {
			peers := r.From
			if egress {
				peers = r.To
			}
			hit := len(peers) == 0
			for _, x := range peers {
				hit = hit || x.matches(p.Metadata.Namespace, peer, nsLabels)
			}
			if hit && portAllowed(r.Ports, port, portName, proto) {
				return true, isolating, p.Metadata.Namespace + "/" + p.Metadata.Name
			}
		}
	}
	return len(isolating) == 0, isolating, ""
}

// Istio, as much as evaluation needs.
type istioPolicy struct {
	Metadata struct{ Name, Namespace string }
	Spec     struct {
		Selector *struct {
			MatchLabels map[string]string `json:"matchLabels"`
		} `json:"selector"`
		Action string `json:"action"`
		Rules  []struct {
			From []struct {
				Source map[string][]string `json:"source"`
			} `json:"from"`
			To []struct {
				Operation map[string][]string `json:"operation"`
			} `json:"to"`
			When []json.RawMessage `json:"when"`
		} `json:"rules"`
		Mtls *struct {
			Mode string `json:"mode"`
		} `json:"mtls"`
	}
}

func (p istioPolicy) selects(ns string, labels map[string]string) bool {
	if p.Metadata.Namespace != ns && p.Metadata.Namespace != meshRoot {
		return false
	}
	if p.Spec.Selector == nil || len(p.Spec.Selector.MatchLabels) == 0 {
		return p.Metadata.Namespace == ns || p.Metadata.Namespace == meshRoot
	}
	return (labelSelector{MatchLabels: p.Spec.Selector.MatchLabels}).matches(labels)
}

func wildcard(pattern, s string) bool {
	switch {
	case pattern == "*":
		return true
	case strings.HasPrefix(pattern, "*"):
		return strings.HasSuffix(s, pattern[1:])
	case strings.HasSuffix(pattern, "*"):
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	}
	return pattern == s
}

func anyWild(list []string, s string) bool {
	for _, p := range list {
		if wildcard(p, s) {
			return true
		}
	}
	return false
}

// istioRuleMatches: does a rule match this caller on this port? sure is
// false when the rule uses conditions nedctl cannot see (paths, methods,
// JWTs, when).
func istioRuleMatches(rule struct {
	From []struct {
		Source map[string][]string `json:"source"`
	} `json:"from"`
	To []struct {
		Operation map[string][]string `json:"operation"`
	} `json:"to"`
	When []json.RawMessage `json:"when"`
}, src whyPod, port int) (match, sure bool) {
	sure = len(rule.When) == 0
	principal := "cluster.local/ns/" + src.ns + "/sa/" + src.sa
	fromOK := len(rule.From) == 0
	for _, f := range rule.From {
		ok := true
		for k, v := range f.Source {
			switch k {
			case "principals":
				ok = ok && src.sidecar && anyWild(v, principal)
			case "notPrincipals":
				ok = ok && !(src.sidecar && anyWild(v, principal))
			case "namespaces":
				ok = ok && src.sidecar && anyWild(v, src.ns)
			case "notNamespaces":
				ok = ok && !(src.sidecar && anyWild(v, src.ns))
			case "ipBlocks":
				any := false
				for _, c := range v {
					any = any || ipIn(src.ip, c) || src.ip == c
				}
				ok = ok && any
			default: // requestPrincipals, remoteIpBlocks…
				sure = false
			}
		}
		fromOK = fromOK || ok
	}
	toOK := len(rule.To) == 0
	for _, t := range rule.To {
		ok := true
		for k, v := range t.Operation {
			switch k {
			case "ports":
				ok = ok && contains(v, strconv.Itoa(port))
			case "notPorts":
				ok = ok && !contains(v, strconv.Itoa(port))
			default: // hosts, paths, methods
				sure = false
			}
		}
		toOK = toOK || ok
	}
	return fromOK && toOK, sure
}

func cmdWhy(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("why", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ns := fs.String("n", "default", "the source's namespace (and the target's, unless it names one: svc/NAME.NS)")
	cluster := fs.String("cluster", "", "the cluster (default: pick one)")
	env := fs.String("env", "", "AKS: the environment whose bastion to use")
	profile := fs.String("aws-profile", "", "EKS: the AWS profile to act with")
	protocol := fs.String("protocol", "TCP", "TCP, UDP or SCTP")
	output := addOutputFlag(fs)
	pos, err := parseInterspersed(fs, args)
	usage := "usage: nedctl why <pod/NAME|deploy/NAME> <svc/NAME[.NS][:PORT]|pod/NAME[.NS]:PORT|IP:PORT> [-n NS] [--cluster C]"
	if err != nil || len(pos) != 2 || !config.ValidNamespace(*ns) || (*protocol != "TCP" && *protocol != "UDP" && *protocol != "SCTP") {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	srcKind, srcName, ok := parseTarget(pos[0])
	if !ok {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	tgt, err := parseWhyTarget(pos[1], *ns)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	s, code := openKubeSession(ctx, cfg, sessionFlags{cluster: *cluster, env: *env, awsProfile: *profile}, stderr)
	if code != ExitOK {
		return code
	}
	defer s.close()
	sp := spinning(stderr, "Reading the path on "+s.label()+"…")
	res := tracePath(ctx, s, *ns, srcKind, srcName, tgt, *protocol)
	sp.Stop()
	if *output == "json" {
		if code := writeJSON(stdout, stderr, res); code != ExitOK {
			return code
		}
	} else {
		printWhy(stdout, res, s)
	}
	if res.Verdict == "blocked" {
		return ExitFailure
	}
	return ExitOK
}

type whyTarget struct {
	kind, name, ns, host string // kind: service | pod | address
	port                 int
}

func parseWhyTarget(s, defaultNS string) (whyTarget, error) {
	t := whyTarget{ns: defaultNS}
	rest := s
	if h, p, err := net.SplitHostPort(s); err == nil {
		rest = h
		if t.port, err = strconv.Atoi(p); err != nil || t.port < 1 || t.port > 65535 {
			return t, fmt.Errorf("%q: the port must be a number", s)
		}
	}
	kind, name, typed := strings.Cut(rest, "/")
	if !typed {
		kind, name = "", rest
	}
	switch strings.ToLower(kind) {
	case "svc", "service":
		t.kind = "service"
	case "pod", "po":
		t.kind = "pod"
		if t.port == 0 {
			return t, fmt.Errorf("%q: a pod target needs a port (pod/NAME:PORT)", s)
		}
	case "":
		if ip := net.ParseIP(name); ip != nil {
			t.kind, t.host = "address", name
			if t.port == 0 {
				return t, fmt.Errorf("%q: an address needs a port", s)
			}
			return t, nil
		}
		t.kind = "service"
	default:
		return t, fmt.Errorf("%q: the target is svc/NAME, pod/NAME or IP:PORT", s)
	}
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".cluster.local"), ".svc")
	if n, nsPart, ok := strings.Cut(name, "."); ok {
		name, t.ns = n, nsPart
	}
	if !podNameRe.MatchString(name) || !config.ValidNamespace(t.ns) {
		return t, fmt.Errorf("%q is not a name in the cluster", s)
	}
	t.name = name
	return t, nil
}

type whyResult struct {
	Cluster string    `json:"cluster"`
	Source  string    `json:"source"`
	Target  string    `json:"target"`
	Steps   []whyStep `json:"steps"`
	Verdict string    `json:"verdict"` // reachable | blocked | unknown
	Reason  string    `json:"reason"`
	LiveTry string    `json:"liveCheck"`
}

func tracePath(ctx context.Context, s *kubeSession, ns, srcKind, srcName string, t whyTarget, proto string) whyResult {
	res := whyResult{Cluster: s.cluster}
	step := func(check, result, detail, object string) {
		res.Steps = append(res.Steps, whyStep{check, result, detail, object})
	}
	get := func(args ...string) ([]byte, error) {
		return s.output(ctx, "", append([]string{"--request-timeout=20s"}, args...)...)
	}

	// The source pod.
	var src whyPod
	switch srcKind {
	case "pod", "":
		out, err := get("get", "pods", "-n", ns, "--field-selector", "metadata.name="+srcName, "-o", "jsonpath="+whyPodPath)
		if pods := parseWhyPods(ns, out); err == nil && len(pods) == 1 {
			src = pods[0]
		}
	default:
		out, err := get("get", srcKind, srcName, "-n", ns, "-o", "jsonpath={.spec.selector.matchLabels}")
		if sel := jsonLabels(string(out)); err == nil && len(sel) > 0 {
			out, err = get("get", "pods", "-n", ns, "-l", labelString(sel), "-o", "jsonpath="+whyPodPath)
			for _, p := range parseWhyPods(ns, out) {
				if err == nil && (src.name == "" || p.phase == "Running" && src.phase != "Running") {
					src = p
				}
			}
		}
	}
	res.Source = ns + "/" + firstNonBlank(src.name, srcName)
	if src.name == "" {
		step("source", "unknown", "no such pod or workload in "+ns, srcKind+"/"+srcName)
		res.Verdict, res.Reason = "unknown", "the source was not found"
		return res
	}
	mesh := "outside the mesh"
	if src.sidecar {
		mesh = "Istio sidecar"
	}
	step("source", "ok", fmt.Sprintf("pod %s (%s), service account %s, %s", src.name, firstNonBlank(src.ip, "no IP"), src.sa, mesh), "pod/"+ns+"/"+src.name)

	// The target: a Service and its pods, a pod, or an address.
	dst := endpoint{ns: t.ns, ip: t.host}
	var dstPods []whyPod
	port, portName := t.port, ""
	res.Target = t.ns + "/" + t.name
	switch t.kind {
	case "service":
		res.Target = "svc/" + t.name + "." + t.ns
		out, err := get("get", "service", t.name, "-n", t.ns, "-o", `jsonpath={.spec.type}{"\t"}{.spec.clusterIP}{"\t"}{.spec.selector}{"\t"}{.spec.externalName}{"\t"}{range .spec.ports[*]}{.name}{"="}{.port}{":"}{.targetPort}{"/"}{.protocol}{","}{end}`)
		f := strings.Split(string(out), "\t")
		if err != nil || len(f) < 5 {
			step("service", "blocked", "no Service "+t.name+" in "+t.ns+" — DNS has no answer for it", "svc/"+t.ns+"/"+t.name)
			res.Verdict, res.Reason = "blocked", "the Service does not exist"
			return res
		}
		if f[0] == "ExternalName" {
			step("service", "warn", "an ExternalName Service: it points DNS at "+f[3]+", outside the cluster", "svc/"+t.ns+"/"+t.name)
		}
		var target string
		var choices []string
		svcPorts := strings.Split(strings.Trim(f[4], ","), ",")
		for _, p := range svcPorts {
			if p == "" {
				continue
			}
			_, rest, _ := strings.Cut(p, "=")
			sp, rest2, _ := strings.Cut(rest, ":")
			tp, pr, _ := strings.Cut(rest2, "/")
			choices = append(choices, sp)
			if (t.port == 0 && len(svcPorts) == 1) || atoi(sp) == t.port {
				port, target, proto = atoi(sp), tp, firstNonBlank(pr, proto)
			}
		}
		if target == "" {
			step("service", "blocked", fmt.Sprintf("Service %s has no port %d (it has %s)", t.name, t.port, strings.Join(choices, ", ")), "svc/"+t.ns+"/"+t.name)
			res.Verdict, res.Reason = "blocked", "the Service has no such port"
			return res
		}
		sel := jsonLabels(f[2])
		if len(sel) == 0 && f[0] != "ExternalName" {
			step("service", "warn", "the Service has no selector: its endpoints are managed by hand", "svc/"+t.ns+"/"+t.name)
		}
		if len(sel) > 0 {
			out, _ := get("get", "pods", "-n", t.ns, "-l", labelString(sel), "-o", "jsonpath="+whyPodPath)
			dstPods = parseWhyPods(t.ns, out)
		}
		// targetPort: a number, or a container port's name.
		tpNum := atoi(target)
		if tpNum == 0 {
			portName = target
			for _, p := range dstPods {
				if n, ok := p.ports[target]; ok {
					tpNum = n
				}
			}
			if tpNum == 0 && len(dstPods) > 0 {
				step("port", "blocked", fmt.Sprintf("targetPort %q is not a port name on the pods", target), "svc/"+t.ns+"/"+t.name)
				res.Verdict, res.Reason = "blocked", "the Service's targetPort names no container port"
				return res
			}
		}
		step("service", "ok", fmt.Sprintf("%s %s, port %d → targetPort %s", f[0], f[1], port, target), "svc/"+t.ns+"/"+t.name)
		port = firstPositive(tpNum, port)
		eps, _ := get("get", "endpointslices", "-n", t.ns, "-l", "kubernetes.io/service-name="+t.name, "-o", `jsonpath={range .items[*]}{range .endpoints[*]}{.conditions.ready}{" "}{end}{end}`)
		ready, notReady := 0, 0
		for _, r := range strings.Fields(string(eps)) {
			if r == "true" {
				ready++
			} else {
				notReady++
			}
		}
		switch {
		case ready > 0:
			step("endpoints", "ok", fmt.Sprintf("%d ready endpoint(s)", ready)+ifNonBlank(", ", plural(notReady, "not ready")), "")
		case notReady > 0:
			step("endpoints", "blocked", fmt.Sprintf("no ready endpoints (%d not ready): the pods fail their readiness probe", notReady), "")
			res.Verdict, res.Reason = "blocked", "no ready endpoints"
		case f[0] != "ExternalName":
			step("endpoints", "blocked", "no endpoints: the selector matches no running pod", "")
			res.Verdict, res.Reason = "blocked", "the Service selects no pods"
		}
	case "pod":
		res.Target = "pod/" + t.ns + "/" + t.name
		out, _ := get("get", "pods", "-n", t.ns, "--field-selector", "metadata.name="+t.name, "-o", "jsonpath="+whyPodPath)
		dstPods = parseWhyPods(t.ns, out)
		if len(dstPods) == 0 {
			step("target", "blocked", "no pod "+t.name+" in "+t.ns, "")
			res.Verdict, res.Reason = "blocked", "the target pod does not exist"
			return res
		}
	case "address":
		res.Target = t.host
		dst.inside = false
	}
	var dp whyPod
	if len(dstPods) > 0 {
		dp = dstPods[0]
		dst = endpoint{ns: dp.ns, labels: dp.labels, ip: dp.ip, inside: true}
		for name, n := range dp.ports {
			if n == port && portName == "" {
				portName = name
			}
		}
	}

	// Namespaces' labels, for namespace selectors.
	nsLabels := map[string]map[string]string{}
	nsList := []string{ns}
	if t.ns != ns {
		nsList = append(nsList, t.ns)
	}
	out, _ := get(append(append([]string{"get", "namespaces"}, nsList...), "kube-system", "-o", `jsonpath={range .items[*]}{.metadata.name}{"\t"}{.metadata.labels}{"\n"}{end}`)...)
	for _, l := range nonEmptyLines(string(out)) {
		if n, lab, ok := strings.Cut(l, "\t"); ok {
			nsLabels[n] = jsonLabels(lab)
		}
	}
	for _, n := range append(nsList, "kube-system") {
		if nsLabels[n] == nil {
			nsLabels[n] = map[string]string{}
		}
		nsLabels[n]["kubernetes.io/metadata.name"] = n
	}
	var policies []npPolicy
	npRead := true
	for _, n := range nsList {
		out, err := get("get", "networkpolicies", "-n", n, "-o", "json")
		var list struct{ Items []npPolicy }
		if err != nil || json.Unmarshal(out, &list) != nil {
			npRead = false
			continue
		}
		policies = append(policies, list.Items...)
	}
	srcEnd := endpoint{ns: src.ns, labels: src.labels, ip: src.ip, inside: true}

	// NetworkPolicy: the source sending, DNS first for a name.
	if !npRead {
		step("network policy", "unknown", "network policies could not be read", "")
	} else {
		if t.kind == "service" {
			dns := endpoint{ns: "kube-system", labels: map[string]string{"k8s-app": "kube-dns"}, inside: true}
			okUDP, iso, _ := npVerdict(policies, srcEnd, dns, true, 53, "dns", "UDP", nsLabels)
			okTCP, _, _ := npVerdict(policies, srcEnd, dns, true, 53, "dns-tcp", "TCP", nsLabels)
			if !okUDP && !okTCP {
				step("egress: DNS", "blocked", "the source may not reach kube-dns on port 53: names do not resolve", strings.Join(iso, ", "))
				res.Verdict, res.Reason = "blocked", "egress policy blocks DNS ("+strings.Join(iso, ", ")+")"
			}
		}
		allowed, iso, by := npVerdict(policies, srcEnd, dst, true, port, portName, proto, nsLabels)
		switch {
		case len(iso) == 0:
			step("egress", "ok", "no network policy restricts the source's outgoing traffic", "")
		case allowed:
			step("egress", "ok", fmt.Sprintf("allowed to port %d by %s", port, by), by)
		case !dst.inside && dst.ip == "":
			step("egress", "unknown", "the source's egress is restricted and nedctl cannot see which address the name resolves to", strings.Join(iso, ", "))
		default:
			step("egress", "blocked", fmt.Sprintf("%s restrict(s) the source's egress and no rule allows %s port %d/%s", strings.Join(iso, ", "), res.Target, port, proto), strings.Join(iso, ", "))
			if res.Verdict == "" {
				res.Verdict, res.Reason = "blocked", "egress network policy "+strings.Join(iso, ", ")
			}
		}
		if dst.inside {
			allowed, iso, by := npVerdict(policies, dst, srcEnd, false, port, portName, proto, nsLabels)
			switch {
			case len(iso) == 0:
				step("ingress", "ok", "no network policy restricts the target's incoming traffic", "")
			case allowed:
				step("ingress", "ok", fmt.Sprintf("allowed from %s by %s", res.Source, by), by)
			default:
				step("ingress", "blocked", fmt.Sprintf("%s restrict(s) the target's ingress and no rule allows %s on port %d/%s", strings.Join(iso, ", "), res.Source, port, proto), strings.Join(iso, ", "))
				if res.Verdict == "" {
					res.Verdict, res.Reason = "blocked", "ingress network policy "+strings.Join(iso, ", ")
				}
			}
		}
	}

	// Istio: mTLS mode and authorization at the target.
	if dst.inside {
		var pa, ap []istioPolicy
		istio := false
		for _, n := range dedupe([]string{t.ns, meshRoot}) {
			for kind, into := range map[string]*[]istioPolicy{"peerauthentications.security.istio.io": &pa, "authorizationpolicies.security.istio.io": &ap} {
				out, err := get("get", kind, "-n", n, "-o", "json")
				var list struct{ Items []istioPolicy }
				if err == nil && json.Unmarshal(out, &list) == nil {
					istio = true
					*into = append(*into, list.Items...)
				}
			}
		}
		if istio || dp.sidecar || src.sidecar {
			mode := "PERMISSIVE"
			rank := -1 // workload > namespace > mesh-wide
			for _, p := range pa {
				if p.Spec.Mtls == nil || !p.selects(dp.ns, dp.labels) {
					continue
				}
				r := 0
				if p.Metadata.Namespace == dp.ns {
					r = 1
				}
				if p.Spec.Selector != nil && len(p.Spec.Selector.MatchLabels) > 0 {
					r = 2
				}
				if r > rank && p.Spec.Mtls.Mode != "" && p.Spec.Mtls.Mode != "UNSET" {
					mode, rank = p.Spec.Mtls.Mode, r
				}
			}
			switch {
			case dp.sidecar && mode == "STRICT" && !src.sidecar:
				step("istio mTLS", "blocked", "the target requires mTLS (STRICT) and the source has no sidecar: its plain-text connection is refused", "")
				if res.Verdict == "" {
					res.Verdict, res.Reason = "blocked", "STRICT mTLS at the target, source outside the mesh"
				}
			default:
				step("istio mTLS", "ok", fmt.Sprintf("target %s, mode %s, source %s", map[bool]string{true: "in the mesh", false: "outside the mesh"}[dp.sidecar], mode, mesh), "")
			}
			if dp.sidecar {
				istioAuthz(ap, src, dp, port, step, &res)
			}
		}
	}
	if res.Verdict == "" {
		res.Verdict, res.Reason = "reachable", "nothing on the path blocks it"
		for _, x := range res.Steps {
			if x.Result == "unknown" {
				res.Verdict, res.Reason = "unknown", "part of the path could not be judged: "+x.Check
			}
		}
	}
	host := t.host
	if t.kind == "service" {
		host = t.name + "." + t.ns
	}
	if host != "" {
		res.LiveTry = fmt.Sprintf("nedctl debug net %s:%d -n %s --cluster %s", host, firstPositive(t.port, port), ns, s.cluster)
	}
	return res
}

func istioAuthz(ap []istioPolicy, src, dp whyPod, port int, step func(check, result, detail, object string), res *whyResult) {
	var allows []istioPolicy
	for _, p := range ap {
		if !p.selects(dp.ns, dp.labels) {
			continue
		}
		obj := "authorizationpolicy/" + p.Metadata.Namespace + "/" + p.Metadata.Name
		switch firstNonBlank(p.Spec.Action, "ALLOW") {
		case "DENY":
			for _, r := range p.Spec.Rules {
				if m, sure := istioRuleMatches(r, src, port); m {
					if sure {
						step("istio authorization", "blocked", "a DENY policy matches this caller", obj)
						if res.Verdict == "" {
							res.Verdict, res.Reason = "blocked", "Istio DENY policy "+p.Metadata.Namespace+"/"+p.Metadata.Name
						}
						return
					}
					step("istio authorization", "warn", "a DENY policy may match (it also checks paths, methods or conditions)", obj)
				}
			}
		case "ALLOW":
			allows = append(allows, p)
		case "CUSTOM":
			step("istio authorization", "unknown", "a CUSTOM (external) authorizer decides; nedctl cannot see its answer", obj)
		}
	}
	if len(allows) == 0 {
		step("istio authorization", "ok", "no ALLOW policy applies, so callers are not restricted", "")
		return
	}
	var names []string
	for _, p := range allows {
		names = append(names, p.Metadata.Namespace+"/"+p.Metadata.Name)
		for _, r := range p.Spec.Rules {
			if m, sure := istioRuleMatches(r, src, port); m {
				if sure {
					step("istio authorization", "ok", "allowed by "+p.Metadata.Namespace+"/"+p.Metadata.Name, "")
				} else {
					step("istio authorization", "warn", "allowed by "+p.Metadata.Namespace+"/"+p.Metadata.Name+" for some requests (paths, methods or conditions apply)", "")
				}
				return
			}
		}
	}
	sort.Strings(names)
	who := "principal cluster.local/ns/" + src.ns + "/sa/" + src.sa
	if !src.sidecar {
		who = "a caller without a sidecar (no identity)"
	}
	step("istio authorization", "blocked", "ALLOW policies apply and none allows "+who+fmt.Sprintf(" on port %d", port), strings.Join(names, ", "))
	if res.Verdict == "" {
		res.Verdict, res.Reason = "blocked", "Istio authorization ("+strings.Join(names, ", ")+") does not allow this caller"
	}
}

func labelString(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + m[k]
	}
	return strings.Join(parts, ",")
}

func firstPositive(a ...int) int {
	for _, x := range a {
		if x > 0 {
			return x
		}
	}
	return 0
}

func plural(n int, what string) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%d %s", n, what)
}

func printWhy(w io.Writer, res whyResult, s *kubeSession) {
	st := ui.Style{Color: colorOn(w)}
	fmt.Fprintf(w, "%s  →  %s   %s\n\n", st.Bold(res.Source), st.Bold(res.Target), st.Dim(s.label()))
	for _, x := range res.Steps {
		mark := map[string]string{"ok": st.OK("✔"), "blocked": st.Fail("✖"), "warn": st.Fg(ui.Amber, "!"), "unknown": st.Dim("?")}[x.Result]
		fmt.Fprintf(w, " %s %-20s %s\n", mark, x.Check, x.Detail)
		if x.Object != "" && x.Result != "ok" {
			fmt.Fprintf(w, "   %-20s %s\n", "", st.Dim(x.Object))
		}
	}
	verdict := map[string]string{"reachable": st.OK("REACHABLE"), "blocked": st.Fail("BLOCKED"), "unknown": st.Fg(ui.Amber, "NOT SURE")}[res.Verdict]
	fmt.Fprintf(w, "\n%s %s\n", verdict, res.Reason)
	if res.LiveTry != "" {
		fmt.Fprintf(w, "%s %s\n", st.Dim("Live check:"), res.LiveTry)
	}
}
