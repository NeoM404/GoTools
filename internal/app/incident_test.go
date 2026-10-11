package app

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIncidentCollectsCleanEvidence(t *testing.T) {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster")
	c := "acm-k8s-qa-cluster"
	wl := `{"kind":"Deployment","metadata":{"name":"payments-api","namespace":"payments","annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"DB_PASSWORD\":\"hunter22\"}","team":"pay"},"managedFields":[{"manager":"kubectl"}]},
 "spec":{"replicas":1,"selector":{"matchLabels":{"app":"payments-api"}},"template":{"spec":{"containers":[{"name":"api","env":[{"name":"DB_PASSWORD","value":"hunter22"},{"name":"DB_HOST","valueFrom":{"configMapKeyRef":{"name":"cfg","key":"h"}}}]}]}}},"status":{"readyReplicas":0}}`
	f.answer(t, c, "get deployment payments-api -n payments -o json", wl)
	f.answer(t, c, "get pods -n payments -l app=payments-api -o json", `{"items":[`+pullPod+`]}`)
	f.answer(t, c, "get events -n payments -o json", `{"items":[{"type":"Warning","reason":"Failed","message":"pull failed","involvedObject":{"kind":"Pod","name":"api-2"}},{"type":"Normal","reason":"Other","message":"unrelated","involvedObject":{"kind":"Pod","name":"billing-1"}}]}`)
	f.answer(t, c, "get pod api-2 -n payments -o jsonpath={.spec.containers[*].name}", "api")
	f.answer(t, c, "logs api-2 -n payments -c api --since=1h --tail=500 --timestamps", "2026-10-12T08:00:00Z login password=hunter22\n2026-10-12T08:00:01Z charged 4111 1111 1111 1111\n")
	dir := t.TempDir()
	out := filepath.Join(dir, "evidence.zip")

	code, stdout, errb := run("--config", f.cfg, "incident", "deploy/payments-api", "-n", "payments", "--cluster", c, "--out", out)
	if code != ExitOK || !strings.Contains(stdout, "evidence collected:") || !strings.Contains(stdout, "sha256") {
		t.Fatalf("code=%d out=%q err=%q", code, stdout, errb)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
		t.Fatalf("evidence must be owner-only, got %v", fi.Mode().Perm())
	}
	sum := sha256.Sum256(data)
	if !strings.Contains(stdout, hex.EncodeToString(sum[:])) {
		t.Fatal("the printed SHA-256 must be the file's")
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	contents := map[string]string{}
	for _, zf := range zr.File {
		rc, _ := zf.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		contents[zf.Name] = string(b)
	}
	all := strings.Join(func() []string {
		var v []string
		for _, s := range contents {
			v = append(v, s)
		}
		return v
	}(), "\n")
	if strings.Contains(all, "hunter22") || strings.Contains(all, "4111 1111") || strings.Contains(all, "\"managedFields\"") || strings.Contains(all, "kubectl.kubernetes.io/last-applied-configuration") {
		t.Fatalf("evidence leaks something it must not:\n%s", all)
	}
	for _, name := range []string{"summary.md", "findings.json", "workload.json", "pods.json", "events.json", "logs/api-2_api.log", "manifest.json"} {
		if _, ok := contents[name]; !ok {
			t.Fatalf("missing %s; have %v", name, func() []string {
				var k []string
				for n := range contents {
					k = append(k, n)
				}
				return k
			}())
		}
	}
	if !strings.Contains(contents["workload.json"], `"DB_PASSWORD"`) || !strings.Contains(contents["workload.json"], notCollected) || !strings.Contains(contents["workload.json"], `"team": "pay"`) {
		t.Fatalf("names stay, values go:\n%s", contents["workload.json"])
	}
	if strings.Contains(contents["events.json"], "billing-1") || !strings.Contains(contents["events.json"], "pull failed") {
		t.Fatalf("only the workload's events:\n%s", contents["events.json"])
	}
	if !strings.Contains(contents["logs/api-2_api.log"], "password=‹redacted›") {
		t.Fatalf("logs redacted:\n%s", contents["logs/api-2_api.log"])
	}
	var m struct {
		Files       map[string]string `json:"files"`
		CollectedBy string            `json:"collectedBy"`
		Cluster     string            `json:"cluster"`
	}
	if err := json.Unmarshal([]byte(contents["manifest.json"]), &m); err != nil || m.Cluster != c || m.CollectedBy == "" {
		t.Fatalf("manifest: %+v %v", m, err)
	}
	for name, want := range m.Files {
		h := sha256.Sum256([]byte(contents[name]))
		if hex.EncodeToString(h[:]) != want {
			t.Fatalf("manifest checksum for %s does not match", name)
		}
	}
	ev := readAudit(t, f.logPath)
	if last := ev[len(ev)-1]; last.Action != "incident-collect" || !strings.Contains(last.Detail, hex.EncodeToString(sum[:])) {
		t.Fatalf("audit: %+v", last)
	}
	// Never overwrites.
	if code, _, _ := run("--config", f.cfg, "incident", "deploy/payments-api", "-n", "payments", "--cluster", c, "--out", out); code != ExitFailure {
		t.Fatal("an existing evidence file must not be replaced")
	}
}
