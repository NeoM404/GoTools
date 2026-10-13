package app

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestWhyFindsWhatBlocksThePath(t *testing.T) {
	c := "pay-k8s-qa-cluster"
	f := newClusterFixture(t, "", c)
	f.answer(t, c, "get pods -n payments --field-selector metadata.name=api-1 -o jsonpath="+whyPodPath,
		"api-1\t{\"app\":\"api\"}\t10.0.1.5\tpayments-api\tapi \tRunning\t\n")
	f.answer(t, c, "get service ledger -n core -o jsonpath="+`{.spec.type}{"\t"}{.spec.clusterIP}{"\t"}{.spec.selector}{"\t"}{.spec.externalName}{"\t"}{range .spec.ports[*]}{.name}{"="}{.port}{":"}{.targetPort}{"/"}{.protocol}{","}{end}`,
		"ClusterIP\t172.20.1.9\t{\"app\":\"ledger\"}\t\thttp=8080:https/TCP,")
	f.answer(t, c, "get pods -n core -l app=ledger -o jsonpath="+whyPodPath,
		"ledger-1\t{\"app\":\"ledger\"}\t10.0.2.7\tledger\tledger istio-proxy \tRunning\thttps=8443,\n")
	f.answer(t, c, `get endpointslices -n core -l kubernetes.io/service-name=ledger -o jsonpath={range .items[*]}{range .endpoints[*]}{.conditions.ready}{" "}{end}{end}`, "true true false ")
	f.answer(t, c, `get namespaces payments core kube-system -o jsonpath={range .items[*]}{.metadata.name}{"\t"}{.metadata.labels}{"\n"}{end}`,
		"payments\t{\"team\":\"payments\"}\ncore\t{\"team\":\"core\"}\nkube-system\t{}\n")
	denyEgress := `{"metadata":{"name":"default-deny","namespace":"payments"},"spec":{"podSelector":{},"policyTypes":["Egress"],"egress":[{"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"kube-system"}},"podSelector":{"matchLabels":{"k8s-app":"kube-dns"}}}],"ports":[{"protocol":"UDP","port":53}]}]}}`
	allowCore := `{"metadata":{"name":"to-core","namespace":"payments"},"spec":{"podSelector":{"matchLabels":{"app":"api"}},"policyTypes":["Egress"],"egress":[{"to":[{"namespaceSelector":{"matchLabels":{"team":"core"}}}],"ports":[{"port":8000,"endPort":9000}]}]}}`
	ingressFromWeb := `{"metadata":{"name":"ledger-in","namespace":"core"},"spec":{"podSelector":{"matchLabels":{"app":"ledger"}},"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"team":"web"}}}],"ports":[{"port":"https"}]}]}}`
	ingressFromPayments := `{"metadata":{"name":"ledger-in","namespace":"core"},"spec":{"podSelector":{"matchLabels":{"app":"ledger"}},"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"team":"payments"}},"podSelector":{"matchLabels":{"app":"api"}}}],"ports":[{"port":"https"}]}]}}`
	np := func(ns string, items ...string) {
		f.answer(t, c, "get networkpolicies -n "+ns+" -o json", `{"items":[`+strings.Join(items, ",")+`]}`)
	}
	istio := func(kind, ns, items string) {
		f.answer(t, c, "get "+kind+" -n "+ns+" -o json", `{"items":[`+items+`]}`)
	}
	istio("peerauthentications.security.istio.io", "istio-system", `{"metadata":{"name":"default","namespace":"istio-system"},"spec":{"mtls":{"mode":"STRICT"}}}`)
	istio("peerauthentications.security.istio.io", "core", "")
	istio("authorizationpolicies.security.istio.io", "istio-system", "")
	istio("authorizationpolicies.security.istio.io", "core", "")
	why := func() (int, whyResult, string) {
		code, out, errb := run("--config", f.cfg, "why", "pod/api-1", "svc/ledger.core:8080", "-n", "payments", "--cluster", c)
		_, jout, _ := run("--config", f.cfg, "why", "pod/api-1", "svc/ledger.core:8080", "-n", "payments", "--cluster", c, "-o", "json")
		var r whyResult
		if err := json.Unmarshal([]byte(jout), &r); err != nil {
			t.Fatalf("json: %v %s %s", err, jout, errb)
		}
		return code, r, out
	}

	// 1. Egress: default deny (DNS allowed), nothing to core.
	np("payments", denyEgress)
	np("core")
	code, r, out := why()
	if code != ExitFailure || r.Verdict != "blocked" || !strings.Contains(r.Reason, "egress network policy payments/default-deny") {
		t.Fatalf("egress: %d %+v\n%s", code, r, out)
	}
	for _, want := range []string{"port 8080 → targetPort https", "2 ready endpoint(s), 1 not ready", "BLOCKED", "Live check: nedctl debug net ledger.core:8080 -n payments --cluster " + c} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "DNS") {
		t.Fatalf("DNS is allowed:\n%s", out)
	}
	// 2. Egress to core's 8000-9000 allowed; ingress only from web.
	np("payments", denyEgress, allowCore)
	np("core", ingressFromWeb)
	if _, r, out = why(); r.Verdict != "blocked" || !strings.Contains(r.Reason, "ingress network policy core/ledger-in") || !strings.Contains(out, "allowed to port 8443 by payments/to-core") {
		t.Fatalf("ingress: %+v\n%s", r, out)
	}
	// 3. Ingress from payments' api allowed (named port): now Istio STRICT
	// refuses a source without a sidecar.
	np("core", ingressFromPayments)
	if _, r, _ = why(); r.Verdict != "blocked" || !strings.Contains(r.Reason, "STRICT mTLS") {
		t.Fatalf("istio: %+v", r)
	}
	// 4. Source in the mesh, an ALLOW policy for another caller only.
	f.answer(t, c, "get pods -n payments --field-selector metadata.name=api-1 -o jsonpath="+whyPodPath,
		"api-1\t{\"app\":\"api\"}\t10.0.1.5\tpayments-api\tapi istio-proxy \tRunning\t\n")
	istio("authorizationpolicies.security.istio.io", "core", `{"metadata":{"name":"ledger-callers","namespace":"core"},"spec":{"selector":{"matchLabels":{"app":"ledger"}},"rules":[{"from":[{"source":{"principals":["cluster.local/ns/web/sa/web"]}}]}]}}`)
	if _, r, _ = why(); r.Verdict != "blocked" || !strings.Contains(r.Reason, "Istio authorization (core/ledger-callers)") {
		t.Fatalf("authz: %+v", r)
	}
	// 5. Allowed for payments-api: reachable.
	istio("authorizationpolicies.security.istio.io", "core", `{"metadata":{"name":"ledger-callers","namespace":"core"},"spec":{"selector":{"matchLabels":{"app":"ledger"}},"rules":[{"from":[{"source":{"principals":["*/ns/payments/sa/payments-api"]}}],"to":[{"operation":{"ports":["8443"]}}]}]}}`)
	if code, r, out := why(); code != ExitOK || r.Verdict != "reachable" || !strings.Contains(out, "REACHABLE") {
		t.Fatalf("reachable: %d %+v\n%s", code, r, out)
	}
	// A Service that does not exist.
	if code, out, _ := run("--config", f.cfg, "why", "pod/api-1", "svc/nope.core:80", "-n", "payments", "--cluster", c); code != ExitFailure || !strings.Contains(out, "no Service nope in core") {
		t.Fatalf("missing service: %d %s", code, out)
	}
}

func TestNetworkPolicyPortsAndBlocks(t *testing.T) {
	ports := []npPort{{Port: json.RawMessage(`8000`), EndPort: 8100}, {Protocol: "UDP", Port: json.RawMessage(`"dns"`)}}
	if !portAllowed(ports, 8050, "", "TCP") || portAllowed(ports, 8200, "", "TCP") || !portAllowed(ports, 53, "dns", "UDP") || portAllowed(ports, 53, "dns", "TCP") {
		t.Fatal("ports")
	}
	peer := npPeer{IPBlock: &struct {
		CIDR   string   `json:"cidr"`
		Except []string `json:"except"`
	}{CIDR: "10.0.0.0/16", Except: []string{"10.0.9.0/24"}}}
	if !peer.matches("x", endpoint{ip: "10.0.1.1"}, nil) || peer.matches("x", endpoint{ip: "10.0.9.9"}, nil) {
		t.Fatal("ipBlock")
	}
	for in, want := range map[string]string{"svc/ledger.core:8080": "service ledger core 8080", "ledger:80": "service ledger payments 80", "pod/api-1.web:9000": "pod api-1 web 9000", "10.1.2.3:443": "address  payments 443"} {
		tg, err := parseWhyTarget(in, "payments")
		if got := tg.kind + " " + tg.name + " " + tg.ns + " " + itoa(tg.port); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"pod/x", "svc/../x:80", "ftp/x:21", "10.1.2.3"} {
		if _, err := parseWhyTarget(bad, "payments"); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
