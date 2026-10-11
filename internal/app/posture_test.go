package app

import (
	"strings"
	"testing"
)

// These lines are what kubectl prints for postureProbes (checked against
// kubectl's own jsonpath with `kubectl label --local -o jsonpath=…`).
const posturePods = "P\tpay\tbad\ttrue\t\t\t\t\t/var/run/docker.sock\n" +
	"C\ta\tdocker.io/x/a:latest\ttrue\t\t\t\tSYS_ADMIN NET_RAW\t\tDB_PASSWORD LOG_LEVEL \n" +
	"P\tpay\tgood\t\t\t\ttrue\t1000\t\n" +
	"C\tb\treg.example/b:1.2\t\t\t\tfalse\t\t256Mi\t\n" +
	"P\tkube-system\tkube-proxy\ttrue\t\t\t\t\t/lib/modules\n" +
	"C\tkube-proxy\tmcr.microsoft.com/kube-proxy:v1.30\ttrue\t\t\t\t\t\t\n"

const postureSvcs = "pay\tpublic-api\tLoadBalancer\t{\"x\":\"y\"}\n" +
	"pay\tinternal-api\tLoadBalancer\t{\"service.beta.kubernetes.io/azure-load-balancer-internal\":\"true\"}\n" +
	"pay\tweb\tClusterIP\t\n"

func TestPostureFindsRiskySettings(t *testing.T) {
	f := newClusterFixture(t, `,"security":{"approvedRegistries":["reg.example","mcr.microsoft.com"]}`, "pay-k8s-qa-cluster")
	c := "pay-k8s-qa-cluster"
	f.answer(t, c, strings.Join(postureProbes[0], " "), posturePods)
	f.answer(t, c, strings.Join(postureProbes[1], " "), postureSvcs)
	code, out, errb := run("--config", f.cfg, "posture", "--env", "qa")
	if code != ExitFailure {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, want := range []string{
		"QA pay-k8s-qa-cluster  2 pods checked",
		"privileged              fail    1      pay/bad/a",
		"host-namespaces         fail    1      pay/bad (hostNetwork)",
		"secret-in-env           fail    1      pay/bad/a (DB_PASSWORD)",
		"public-load-balancer    fail    1      pay/public-api",
		"unapproved-registry     fail    1      pay/bad/a (docker.io/x/a:latest)",
		"dangerous-capabilities  fail    1      pay/bad/a (SYS_ADMIN)",
		"host-path               warn    1      pay/bad (/var/run/docker.sock)",
		"root                    warn    1      pay/bad/a",
		"no-memory-limit         warn    1      pay/bad/a",
		"mutable-image-tag       warn    1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, "kube-proxy") || strings.Contains(out, "internal-api") || strings.Contains(out, "LOG_LEVEL") || strings.Contains(out, "hunter") {
		t.Error("ignored namespace, internal LB, harmless variable or a value shown")
	}
	if t.Failed() {
		t.Log(out)
	}
	_, out, _ = run("--config", f.cfg, "posture", "--env", "qa", "--include-system", "-o", "json")
	if !strings.Contains(out, `"object": "kube-system/kube-proxy/kube-proxy"`) || !strings.Contains(out, `"podsChecked": 3`) {
		t.Fatalf("json:\n%s", out)
	}
}

func TestPosturePassesAClean(t *testing.T) {
	f := newClusterFixture(t, "", "pay-k8s-qa-cluster")
	c := "pay-k8s-qa-cluster"
	f.answer(t, c, strings.Join(postureProbes[0], " "), "P\tpay\tgood\t\t\t\ttrue\t1000\t\nC\tb\treg.example/b:1.2\t\t\t\tfalse\t\t256Mi\t\n")
	f.answer(t, c, strings.Join(postureProbes[1], " "), "")
	code, out, errb := run("--config", f.cfg, "posture", "--cluster", c)
	if code != ExitOK || strings.Contains(out, "fail ") || strings.Contains(out, "warn ") {
		t.Fatalf("code=%d out=%s err=%s", code, out, errb)
	}
}

func TestRegistryOf(t *testing.T) {
	for in, want := range map[string]string{"nginx": "docker.io", "library/nginx:1": "docker.io", "myacr.azurecr.io/a/b:1": "myacr.azurecr.io",
		"localhost/x": "localhost", "reg:5000/x": "reg:5000", "123.dkr.ecr.af-south-1.amazonaws.com/a": "123.dkr.ecr.af-south-1.amazonaws.com"} {
		if got := registryOf(in); got != want {
			t.Errorf("%s: %s want %s", in, got, want)
		}
	}
}
