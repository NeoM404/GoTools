package app

import (
	"strings"
	"testing"
)

func TestQuantity(t *testing.T) {
	for in, want := range map[string]float64{"100m": 0.1, "2": 2, "1.5": 1.5, "128Mi": 128 << 20, "1Gi": 1 << 30, "1G": 1e9, "500k": 5e5, "250000n": 0.00025, "": 0} {
		if got := quantity(in); got != want {
			t.Errorf("%q: %v want %v", in, got, want)
		}
	}
}

func TestCapacityFindsHeadroomProblems(t *testing.T) {
	f := newClusterFixture(t, "", "pay-k8s-qa-cluster")
	probes := capacityProbes(true)
	answerProbes(t, f, "pay-k8s-qa-cluster", probes, map[int]string{
		0: `{"gitVersion":"v1.31.2"}`,
		caNodes: "n1\t2\t8Gi\t30\tapp\tReady,\t\n" +
			"n2\t2\t8Gi\t30\tapp\tReady,MemoryPressure,\t\n" +
			"n3\t4\t16Gi\t30\tbatch\tReady,\t\n" +
			"n4\t4\t16Gi\t30\tbatch\tReady,\ttrue\n",
		caPods: "payments\tapi-1\tn1\tRunning\t1500m 300m\t3Gi\t\t\n" +
			"payments\tapi-2\tn2\tRunning\t1800m\t4Gi\t\t\n" +
			"batch\tjob-1\tn3\tRunning\t1\t2Gi\t\t\n" +
			"payments\tapi-3\t\tPending\t500m\t1Gi\tUnschedulable\t0/4 nodes are available: 2 Insufficient cpu, 1 node(s) were unschedulable.\n" +
			"payments\tapi-4\t\tPending\t500m\t1Gi\tUnschedulable\t0/4 nodes are available: 2 Insufficient cpu.\n" +
			"web\tweb-1\t\tPending\t100m\t64Mi\tUnschedulable\t0/4 nodes are available: 4 node(s) had untolerated taint {dedicated: gpu}.\n",
		caHPA:         "payments\tapi\t2\t4\t4\t6\tTrue\tTooManyReplicas\nweb\tweb\t1\t5\t2\t2\tFalse\t\n",
		caQuotas:      "payments\tq\t{\"requests.cpu\":\"4\",\"pods\":\"10\"}\t{\"requests.cpu\":\"3800m\",\"pods\":\"10\"}\n",
		caNodeMetrics: `{"items":[{"metadata":{"name":"n1"},"usage":{"cpu":"1","memory":"7Gi"}},{"metadata":{"name":"n2"},"usage":{"cpu":"1500m","memory":"7.8Gi"}},{"metadata":{"name":"n3"},"usage":{"cpu":"100m","memory":"1Gi"}}]}`,
		caPodMetrics:  `{"items":[{"metadata":{"namespace":"batch"},"containers":[{"usage":{"cpu":"50m","memory":"100Mi"}}]}]}`,
	})
	code, out, errb := run("--config", f.cfg, "capacity", "--env", "qa", "--namespaces")
	if code != ExitFailure {
		t.Fatalf("pressure and full pools fail: code=%d err=%q", code, errb)
	}
	for _, want := range []string{
		"POOL", "CPU REQ", "app", "batch",
		"node-pressure", "node/n2", "Memory pressure",
		"pool-headroom", "90% of the pool's CPU is requested",
		"memory-used",
		"pending-pods", "2 pod(s) cannot be placed: Insufficient cpu", "taints the pods do not tolerate",
		"hpa-at-max", "hpa/payments/api", "running 4, desired 6",
		"quota-full", "no more pods can be created", "quota-nearly-full", "95% used",
		"over-requested", "namespace/batch", "requests 20× the CPU it uses",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "hpa/web/web") {
		t.Fatalf("an autoscaler below its maximum is fine:\n%s", out)
	}
	// The batch pool: n4 is cordoned, so one node of 4 cores, 1 requested.
	if !strings.Contains(out, " 25% ") {
		t.Fatalf("cordoned nodes are not capacity:\n%s", out)
	}
}
