package app

import (
	"strings"
	"testing"
)

func TestImagesInventoryAcrossClusters(t *testing.T) {
	f := newClusterFixture(t, `,"security":{"approvedRegistries":["reg.example"]}`, "a-k8s-qa-cluster", "b-k8s-qa-cluster")
	key := strings.Join(imagesProbe, " ")
	f.answer(t, "a-k8s-qa-cluster", key, "P\tpay\tapi-1\nC\tapi\treg.example/pay/api:1.4.2\treg.example/pay/api@sha256:aaaaaaaaaaaaaaaa\n"+
		"P\tpay\tcache-1\nC\tredis\tdocker.io/library/redis:latest\tdocker.io/library/redis@sha256:1111111111111111\n")
	f.answer(t, "b-k8s-qa-cluster", key, "P\tpay\tapi-2\nC\tapi\treg.example/pay/api:1.4.2\treg.example/pay/api@sha256:bbbbbbbbbbbbbbbb\n"+
		"P\tops\tagent\nC\tagent\treg.example/ops/agent:2.0\treg.example/ops/agent@sha256:cccccccccccccccc\n")
	code, out, errb := run("--config", f.cfg, "images", "--env", "qa")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, want := range [][]string{{"docker.io/library/redis:latest", "111111111111", "1", "1", "unapproved-registry, mutable-tag"},
		{"reg.example/pay/api:1.4.2", "aaaaaaaaaaaa +1", "2", "2", "several-digests"}} {
		if !regexpLine(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "3 image(s) shown of 3 running") {
		t.Fatal(out)
	}
	_, out, _ = run("--config", f.cfg, "images", "--env", "qa", "--flagged", "-o", "csv")
	if !strings.HasPrefix(out, "image,registry,tag,digests,clusters,namespaces,containers,flags\n") || strings.Contains(out, "ops/agent") ||
		!strings.Contains(out, "reg.example/pay/api:1.4.2,reg.example,1.4.2,sha256:aaaaaaaaaaaaaaaa sha256:bbbbbbbbbbbbbbbb,a-k8s-qa-cluster b-k8s-qa-cluster,pay,2,several-digests") {
		t.Fatalf("csv:\n%s", out)
	}
	if code, _, _ := run("--config", f.cfg, "images", "--env", "qa", "--fail-on-unapproved"); code != ExitFailure {
		t.Fatal("unapproved registry did not fail")
	}
	_, out, _ = run("--config", f.cfg, "images", "--env", "qa", "--registry", "docker.io", "-o", "json")
	if strings.Count(out, `"image":`) != 1 {
		t.Fatalf("registry filter: %s", out)
	}
}

// regexpLine reports a line holding the cells in order, separated by
// table spacing.
func regexpLine(out string, cells []string) bool {
	for _, l := range strings.Split(out, "\n") {
		rest, ok := l, true
		for _, c := range cells {
			i := strings.Index(rest, c)
			if i < 0 {
				ok = false
				break
			}
			rest = rest[i+len(c):]
		}
		if ok {
			return true
		}
	}
	return false
}
