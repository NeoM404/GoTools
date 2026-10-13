package app

import (
	"strings"
	"testing"
)

func TestMeshFindsWhatWeakensIt(t *testing.T) {
	f := newClusterFixture(t, "", "pay-k8s-qa-cluster", "pay-k8s-prod-cluster")
	probes := meshProbes()
	answerProbes(t, f, "pay-k8s-qa-cluster", probes, map[int]string{
		0:            `{"gitVersion":"v1.31.2"}`,
		meNamespaces: "payments\tenabled\t\nledger\t\tdefault\nweb\t\t\nistio-system\t\t\n",
		mePods: "payments\tapi-1\tRunning\t\tapi istio-proxy \tdocker.io/istio/proxyv2:1.22.3\t\tReplicaSet\n" +
			"payments\tapi-2\tRunning\t\tapi istio-proxy \tdocker.io/istio/proxyv2:1.21.0\t\tReplicaSet\n" +
			"payments\tbatch-1\tRunning\t\tbatch \t\t\tReplicaSet\n" +
			"payments\tlegacy-1\tRunning\tfalse\tlegacy \t\t\tReplicaSet\n" +
			"payments\tmigrate-1\tRunning\t\tmigrate \t\t\tJob\n" +
			"web\tweb-1\tRunning\t\tweb \t\t\tReplicaSet\n",
		meIstiod:   "istio-system\tistiod\tdocker.io/istio/pilot:1.22.3\t\n",
		mePeerAuth: "istio-system\tdefault\t\tPERMISSIVE\t\nledger\tledger-plain\t\tDISABLE\t\npayments\tapi-port\t{\"app\":\"api\"}\tSTRICT\t{\"8081\":{\"mode\":\"PERMISSIVE\"}}\n",
		meAuthz:    "payments\topen\tALLOW\t\t[{}]\nledger\tdeny\t\t\t\n",
		meDestRules: "payments\tlegacy-plain\tlegacy.payments.svc.cluster.local\tDISABLE\t\n" +
			"payments\tapi\tapi\tISTIO_MUTUAL\t\n",
		meVirtualSvcs: "payments\tapi\tapi.bank.example\tistio-system/public\tapi gone \n" +
			"payments\tapi-2\tapi.bank.example\tistio-system/public\tapi.payments.svc.cluster.local  \n",
		meServices:     "payments\tapi\npayments\tlegacy\n",
		meSvcEntries:   "",
		meGateways:     "istio-system\tpublic\nS\t80\tHTTP\t\t\tapi.bank.example\nS\t443\tHTTPS\tSIMPLE\t\tapi.bank.example\n",
		meEnvoyFilters: "payments\tlua-hack\n",
		meMeshConfig:   "accessLogFile: /dev/stdout\noutboundTrafficPolicy:\n  mode: ALLOW_ANY\n",
	})
	answerProbes(t, f, "pay-k8s-prod-cluster", probes, map[int]string{0: `{"gitVersion":"v1.31.2"}`, meNamespaces: "payments\t\t\n"})
	for _, i := range []int{mePeerAuth, meAuthz, meDestRules, meVirtualSvcs, meSvcEntries, meGateways, meEnvoyFilters} {
		f.fail(t, "pay-k8s-prod-cluster", strings.Join(probes[i], " "), `error: the server doesn't have a resource type "x"`)
	}
	f.answer(t, "pay-k8s-prod-cluster", strings.Join(probes[mePods], " "), "")
	f.answer(t, "pay-k8s-prod-cluster", strings.Join(probes[meIstiod], " "), "")
	f.answer(t, "pay-k8s-prod-cluster", strings.Join(probes[meServices], " "), "")
	f.fail(t, "pay-k8s-prod-cluster", strings.Join(probes[meMeshConfig], " "), `configmaps "istio" not found`)

	code, out, errb := run("--config", f.cfg, "mesh", "--env", "qa")
	if code != ExitFailure {
		t.Fatalf("high findings fail: code=%d err=%q", code, errb)
	}
	for _, want := range []string{
		"CLUSTER", "MESH MTLS", "PERMISSIVE", "not installed",
		"mesh-mtls", "mesh-wide mTLS is PERMISSIVE",
		"mtls-disabled", "peerauthentication/ledger/ledger-plain",
		"mtls-port-override",
		"no-sidecar", "pod/payments/batch-1",
		"sidecar-opt-out", "pod/payments/legacy-1",
		"proxy-version", "proxy 1.21.0, istiod 1.22.3",
		"allow-all-policy", "every workload in payments",
		"tls-disabled-destination",
		"route-to-nowhere", "destination gone",
		"virtualservice-conflict", "api.bank.example on istio-system/public",
		"plain-http-gateway",
		"envoyfilter", "open-egress",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	for _, not := range []string{"migrate-1", "web-1", "destination api "} {
		if strings.Contains(out, not) {
			t.Fatalf("%q should not be a finding (job, unmeshed namespace, existing service):\n%s", not, out)
		}
	}
}
