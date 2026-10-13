package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// `nedctl mesh` checks Istio for what weakens the mesh's security or breaks
// its routing: mTLS that accepts plain text, workloads outside the mesh in
// meshed namespaces, proxies on another version than the control plane,
// policies that allow everything, destination rules that turn TLS off,
// routes to hosts that do not exist, virtual services fighting over a host,
// unrestricted egress and EnvoyFilters. Across environments it compares
// them side by side. Read-only, gentle (see gentle.go).

func meshProbes() []probe {
	return []probe{
		versionProbe,
		clusterProbe("namespaces", `{range .items[*]}{.metadata.name}{"\t"}{.metadata.labels.istio-injection}{"\t"}{.metadata.labels.istio\.io/rev}{"\n"}{end}`),
		listProbe("pods", "", `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.phase}{"\t"}{.metadata.labels.sidecar\.istio\.io/inject}{.metadata.annotations.sidecar\.istio\.io/inject}{"\t"}{.spec.containers[*].name} {.spec.initContainers[*].name}{"\t"}{.spec.containers[?(@.name=="istio-proxy")].image}{.spec.initContainers[?(@.name=="istio-proxy")].image}{"\t"}{.spec.hostNetwork}{"\t"}{.metadata.ownerReferences[0].kind}{"\n"}{end}`),
		listProbe("deployments", "", `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.template.spec.containers[0].image}{"\t"}{.metadata.labels.istio\.io/rev}{"\n"}{end}`, "-l", "app=istiod"),
		listProbe("peerauthentications.security.istio.io", "", `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.selector.matchLabels}{"\t"}{.spec.mtls.mode}{"\t"}{.spec.portLevelMtls}{"\n"}{end}`),
		listProbe("authorizationpolicies.security.istio.io", "", `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.action}{"\t"}{.spec.selector.matchLabels}{"\t"}{.spec.rules}{"\n"}{end}`),
		listProbe("destinationrules.networking.istio.io", "", `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.host}{"\t"}{.spec.trafficPolicy.tls.mode}{"\t"}{.spec.trafficPolicy.portLevelSettings[*].tls.mode}{"\n"}{end}`),
		listProbe("virtualservices.networking.istio.io", "", `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.hosts[*]}{"\t"}{.spec.gateways[*]}{"\t"}{.spec.http[*].route[*].destination.host} {.spec.tcp[*].route[*].destination.host} {.spec.tls[*].route[*].destination.host}{"\n"}{end}`),
		listProbe("services", "", `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}`),
		listProbe("serviceentries.networking.istio.io", "", `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.hosts[*]}{"\n"}{end}`),
		listProbe("gateways.networking.istio.io", "", `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{range .spec.servers[*]}S{"\t"}{.port.number}{"\t"}{.port.protocol}{"\t"}{.tls.mode}{"\t"}{.tls.httpsRedirect}{"\t"}{.hosts[*]}{"\n"}{end}{end}`),
		listProbe("envoyfilters.networking.istio.io", "", `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}`),
		{"get", "configmap", "istio", "-n", "istio-system", "-o", `jsonpath={.data.mesh}`},
	}
}

const (
	meNamespaces = iota + 1
	mePods
	meIstiod
	mePeerAuth
	meAuthz
	meDestRules
	meVirtualSvcs
	meServices
	meSvcEntries
	meGateways
	meEnvoyFilters
	meMeshConfig
)

// meshRoot is Istio's root namespace: mesh-wide policies live there.
const meshRoot = "istio-system"

func assessMesh(cfg config.Config, r clusterOut, includeSystem bool) clusterFindings {
	cf := newClusterFindings(r)
	if err := r.reachErr(); err != nil {
		cf.Status, cf.Error = "unreachable", err.Error()
		return cf
	}
	installed := true
	lines := func(i int, what string) []string {
		if i >= len(r.Outs) {
			return nil
		}
		if err := r.Outs[i].Err; err != nil {
			if notInstalled(err) {
				if i == mePeerAuth {
					installed = false
				}
				return nil
			}
			cf.unassessed("%s: %v", what, err)
			return nil
		}
		return nonEmptyLines(string(r.Outs[i].Out))
	}
	add := func(sev, check, title, object, detail, fix string) {
		cf.add(checkFinding{Check: check, Area: "mesh", Severity: sev, Title: title, Object: object, Detail: detail, Fix: fix, Source: "kubernetes"})
	}
	user := func(ns string) bool {
		return includeSystem || !cfg.Security.Ignored(ns) && ns != meshRoot && ns != "istio-ingress"
	}

	// The control plane.
	istiodVersions := map[string]bool{}
	for _, l := range lines(meIstiod, "istiod") {
		f := strings.Split(l, "\t")
		if len(f) >= 3 {
			istiodVersions[imageTag(f[2])] = true
		}
	}
	peer := lines(mePeerAuth, "peer authentications")
	if !installed && len(istiodVersions) == 0 {
		cf.Summary = map[string]any{"istio": "not installed"}
		cf.finish()
		return cf
	}

	// Which namespaces are in the mesh.
	meshed := map[string]bool{}
	for _, l := range lines(meNamespaces, "namespaces") {
		f := strings.Split(l, "\t")
		if len(f) >= 3 && (f[1] == "enabled" || f[2] != "") {
			meshed[f[0]] = true
		}
	}

	// mTLS: the mesh-wide policy, then namespace overrides.
	meshMode := ""
	nsMode := map[string]string{}
	for _, l := range peer {
		f := strings.Split(l, "\t")
		if len(f) < 4 {
			continue
		}
		mode := firstNonBlank(f[3], "UNSET")
		obj := "peerauthentication/" + f[0] + "/" + f[1]
		noSelector := strings.TrimSpace(f[2]) == "" || f[2] == "{}"
		switch {
		case f[0] == meshRoot && noSelector:
			meshMode = mode
		case noSelector:
			nsMode[f[0]] = mode
		}
		switch mode {
		case "DISABLE":
			add("high", "mtls-disabled", "mTLS turned off: traffic travels in plain text", obj, "", "set mtls.mode STRICT (or remove the override)")
		case "PERMISSIVE":
			if !(f[0] == meshRoot && noSelector) {
				add("medium", "mtls-permissive", "PERMISSIVE: plain-text traffic is accepted", obj, "", "move to STRICT once every client is in the mesh")
			}
		}
		if strings.Contains(f[4], "DISABLE") || strings.Contains(f[4], "PERMISSIVE") {
			add("medium", "mtls-port-override", "a port accepts plain text", obj, f[4], "remove the port-level exception, or document why it is needed")
		}
	}
	switch meshMode {
	case "STRICT":
	case "":
		add("high", "mesh-mtls", "no mesh-wide mTLS policy: Istio's default PERMISSIVE accepts plain text", meshRoot, "", "add a PeerAuthentication named default in "+meshRoot+" with mtls.mode STRICT")
	default:
		add("high", "mesh-mtls", "mesh-wide mTLS is "+meshMode+", not STRICT", "peerauthentication/"+meshRoot, "", "set the mesh-wide PeerAuthentication to STRICT")
	}

	// Sidecars: who is in the mesh, on which version.
	proxyVersions := map[string]int{}
	podsMeshed, podsInMeshedNS := 0, 0
	for _, l := range lines(mePods, "pods") {
		f := strings.Split(l, "\t")
		if len(f) < 8 || f[2] != "Running" || !meshed[f[0]] {
			continue
		}
		if f[6] == "true" || f[7] == "Job" { // host network, or a run-to-completion job
			continue
		}
		podsInMeshedNS++
		has := strings.Contains(" "+f[4]+" ", " istio-proxy ")
		if has {
			podsMeshed++
			proxyVersions[imageTag(f[5])]++
			continue
		}
		if !user(f[0]) {
			continue
		}
		if f[3] == "false" {
			add("medium", "sidecar-opt-out", "opted out of the mesh in a meshed namespace", "pod/"+f[0]+"/"+f[1], "sidecar.istio.io/inject: false", "confirm the exception; its traffic bypasses mTLS and authorization policy")
		} else {
			add("high", "no-sidecar", "no sidecar in a meshed namespace: its traffic bypasses mTLS and policy", "pod/"+f[0]+"/"+f[1], "", "restart it (kubectl rollout restart) so the sidecar is injected")
		}
	}
	for v, n := range proxyVersions {
		if len(istiodVersions) > 0 && !istiodVersions[v] {
			add("medium", "proxy-version", "sidecars on a version the control plane does not run", fmt.Sprintf("%d pod(s)", n), "proxy "+v+", istiod "+strings.Join(keysOf(istiodVersions), ", "), "restart those workloads after an Istio upgrade so they take the new proxy")
		}
	}
	if len(istiodVersions) > 1 {
		add("info", "istiod-revisions", "more than one istiod revision", "", strings.Join(keysOf(istiodVersions), ", "), "finish the canary upgrade and remove the old revision")
	}

	// Authorization.
	withPolicy := map[string]bool{}
	for _, l := range lines(meAuthz, "authorization policies") {
		f := strings.Split(l, "\t")
		if len(f) < 5 {
			continue
		}
		withPolicy[f[0]] = true
		action := firstNonBlank(f[2], "ALLOW")
		var rules []map[string]any
		_ = json.Unmarshal([]byte(strings.TrimSpace(f[4])), &rules)
		allowAll := false
		for _, rule := range rules {
			allowAll = allowAll || len(rule) == 0
		}
		if action == "ALLOW" && allowAll {
			scope := "the workloads it selects"
			if strings.TrimSpace(f[3]) == "" {
				scope = "every workload in " + f[0]
				if f[0] == meshRoot {
					scope = "every workload in the mesh"
				}
			}
			add("high", "allow-all-policy", "an authorization policy that allows every request", "authorizationpolicy/"+f[0]+"/"+f[1], "covers "+scope, "name the callers (from.source.principals) and the operations allowed")
		}
	}
	if !withPolicy[meshRoot] {
		for ns := range meshed {
			if user(ns) && !withPolicy[ns] {
				add("low", "no-authorization-policy", "no authorization policy: any workload in the mesh may call these", "namespace/"+ns, "", "add a deny-by-default policy and allow named callers")
			}
		}
	}

	// Destination rules that turn TLS off.
	for _, l := range lines(meDestRules, "destination rules") {
		f := strings.Split(l, "\t")
		if len(f) >= 5 && (f[3] == "DISABLE" || strings.Contains(f[4], "DISABLE")) {
			add("high", "tls-disabled-destination", "a destination rule sends plain text", "destinationrule/"+f[0]+"/"+f[1], "host "+f[2], "use ISTIO_MUTUAL (or SIMPLE to an external TLS service)")
		}
	}

	// Routes.
	services := map[string]bool{}
	for _, l := range lines(meServices, "services") {
		if f := strings.Split(l, "\t"); len(f) >= 2 {
			services[f[1]+"."+f[0]] = true
		}
	}
	external := map[string]bool{}
	for _, l := range lines(meSvcEntries, "service entries") {
		f := strings.Split(l, "\t")
		if len(f) >= 3 {
			for _, h := range strings.Fields(f[2]) {
				external[h] = true
			}
		}
	}
	exists := func(host, ns string) bool {
		if external[host] || strings.HasPrefix(host, "*") {
			return true
		}
		h := strings.TrimSuffix(host, ".svc.cluster.local")
		parts := strings.Split(h, ".")
		switch {
		case len(parts) == 1:
			return services[parts[0]+"."+ns]
		case len(parts) == 2 || (len(parts) == 3 && parts[2] == "svc"):
			return services[parts[0]+"."+parts[1]]
		}
		return true // an outside name: not ours to judge
	}
	claims := map[string][]string{} // gateway|host → virtual services
	for _, l := range lines(meVirtualSvcs, "virtual services") {
		f := strings.Split(l, "\t")
		if len(f) < 5 {
			continue
		}
		obj := "virtualservice/" + f[0] + "/" + f[1]
		for _, d := range strings.Fields(f[4]) {
			if !exists(d, f[0]) {
				add("medium", "route-to-nowhere", "routes to a service that does not exist", obj, "destination "+d, "correct the destination host, or create the service")
			}
		}
		gws := strings.Fields(f[3])
		if len(gws) == 0 {
			gws = []string{"mesh"}
		}
		for _, g := range gws {
			for _, h := range strings.Fields(f[2]) {
				k := g + "|" + h
				claims[k] = append(claims[k], f[0]+"/"+f[1])
			}
		}
	}
	for k, vs := range claims {
		if len(vs) > 1 {
			g, h, _ := strings.Cut(k, "|")
			sort.Strings(vs)
			add("medium", "virtualservice-conflict", "several virtual services claim the same host", h+" on "+g, strings.Join(vs, ", "), "merge them into one; Istio's choice between them is not defined")
		}
	}

	// Gateways serving plain HTTP.
	gw := ""
	for _, l := range lines(meGateways, "gateways") {
		f := strings.Split(l, "\t")
		switch {
		case len(f) >= 2 && f[0] != "S":
			gw = "gateway/" + f[0] + "/" + f[1]
		case len(f) >= 6 && f[0] == "S" && strings.EqualFold(f[2], "HTTP") && f[4] != "true":
			add("medium", "plain-http-gateway", "a gateway serves plain HTTP without redirecting to HTTPS", gw, "port "+f[1]+" for "+f[5], "set tls.httpsRedirect: true on the HTTP server")
		}
	}
	for _, l := range lines(meEnvoyFilters, "envoy filters") {
		if f := strings.Split(l, "\t"); len(f) >= 2 {
			add("low", "envoyfilter", "an EnvoyFilter: patches Envoy directly, often breaks on Istio upgrades", "envoyfilter/"+f[0]+"/"+f[1], "", "replace it with a supported API (Telemetry, WasmPlugin, AuthorizationPolicy) where one exists")
		}
	}
	egress := "unknown"
	if len(r.Outs) > meMeshConfig && r.Outs[meMeshConfig].Err == nil {
		mc := string(r.Outs[meMeshConfig].Out)
		egress = "ALLOW_ANY"
		if strings.Contains(mc, "REGISTRY_ONLY") {
			egress = "REGISTRY_ONLY"
		} else {
			add("medium", "open-egress", "workloads may call any outside host (outboundTrafficPolicy ALLOW_ANY)", "mesh config", "", "set outboundTrafficPolicy.mode REGISTRY_ONLY and declare outside services as ServiceEntries")
		}
	}
	coverage := "-"
	if podsInMeshedNS > 0 {
		coverage = fmt.Sprintf("%d%%", podsMeshed*100/podsInMeshedNS)
	}
	cf.Summary = map[string]any{"istio": strings.Join(keysOf(istiodVersions), ", "), "meshMtls": firstNonBlank(meshMode, "unset (PERMISSIVE)"), "meshedNamespaces": len(meshed),
		"sidecarCoverage": coverage, "egress": egress, "namespacesWithPolicy": len(withPolicy)}
	cf.finish()
	return cf
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func cmdMesh(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mesh", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, true)
	includeSystem := fs.Bool("include-system", false, "also check the platform namespaces")
	minSev := fs.String("min", "low", "show findings at least this severe")
	failOn := failOnFlag(fs, "high")
	output := addOutputFlag(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) > 0 || severityRank(*minSev) < 0 || !validFailOn(*failOn) {
		fmt.Fprintln(stderr, "usage: nedctl mesh [--cluster C | --env qa,prod | --aws | --aws-env ete,qa] [--match WORD] [--fail-on high] [-o json]")
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
	results, code := runProbes(ctx, cfg, sel, meshProbes(), stderr)
	if code != ExitOK {
		return code
	}
	report := make([]clusterFindings, 0, len(results))
	for _, r := range results {
		report = append(report, assessMesh(cfg, r, *includeSystem))
	}
	if *output == "json" {
		if code := writeJSON(stdout, stderr, findingsDoc("mesh", report, nil)); code != ExitOK {
			return code
		}
	} else {
		st := ui.Style{Color: colorOn(stdout)}
		if len(report) > 1 {
			tw := newTable(stdout)
			fmt.Fprintln(tw, "CLUSTER\tISTIO\tMESH MTLS\tSIDECARS\tEGRESS\tSTATUS")
			for _, c := range report {
				s := c.Summary
				get := func(k string) string {
					if v, ok := s[k]; ok {
						return fmt.Sprint(v)
					}
					return "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", strings.TrimSpace(strings.ToUpper(c.Environment)+" "+c.Cluster), get("istio"), get("meshMtls"), get("sidecarCoverage"), get("egress"), c.Status)
			}
			tw.Flush()
			fmt.Fprintln(stdout)
		}
		printReport(stdout, cfg, report, *minSev)
		printFixes(stdout, report, *minSev)
		fmt.Fprintf(stdout, "\n%s\n", st.Dim("read-only · -o json is the evidence"))
	}
	if failed(report, *failOn) {
		return ExitFailure
	}
	return ExitOK
}
