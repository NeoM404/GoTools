package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImagesScanJoinsTheBanksScanners(t *testing.T) {
	prisma := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer prisma-token" || r.URL.Path != "/api/v1/images" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("search") == "quay.io/team/web" {
			w.Write([]byte(`[{"repoDigests":["quay.io/team/web@sha256:web1"],"vulnerabilityDistribution":{"critical":1,"high":4},"vulnerabilities":[{"cve":"CVE-2026-0002","severity":"critical","status":"fixed in 2.1"}],"scanTime":"2026-10-12T00:00:00Z"}]`))
			return
		}
		w.Write([]byte(`[]`))
	}))
	defer prisma.Close()
	old := prismaClient
	prismaClient = prisma.Client
	t.Cleanup(func() { prismaClient = old })

	f := newClusterFixture(t, `, "security": {"prismaApi": "`+prisma.URL+`/api/v1"}`, "pay-k8s-qa-cluster")
	t.Setenv("NEDCTL_PRISMA_TOKEN", "prisma-token")
	f.answer(t, "pay-k8s-qa-cluster", "get --raw /version", `{"gitVersion":"v1.31.2"}`)
	f.answer(t, "pay-k8s-qa-cluster", strings.Join(imagesProbe, " "),
		"P\tpayments\tapi-1\nC\tapi\t111111111111.dkr.ecr.af-south-1.amazonaws.com/payments/api:1.4\t111111111111.dkr.ecr.af-south-1.amazonaws.com/payments/api@sha256:api1\n"+
			"P\tweb\tweb-1\nC\tweb\tquay.io/team/web:2.0\tquay.io/team/web@sha256:web1\n"+
			"P\tops\ttool-1\nC\ttool\tregistry.internal/ops/tool:9\tregistry.internal/ops/tool@sha256:tool1\n"+
			"P\tops\tlog-1\nC\tlog\tdocker.io/fluent/fluent-bit:3.0\tdocker.io/fluent/fluent-bit@sha256:fb1\n")
	f.answer(t, "pay-k8s-qa-cluster", strings.Join(trivyReportsProbe, " "),
		"index.docker.io\tfluent/fluent-bit\t3.0\tsha256:fb1\t0\t2\t5\t1\t2026-10-12T08:00:00Z\t\n")
	calls := filepath.Join(t.TempDir(), "aws-calls")
	fakeCLI(t, "aws", `echo "$*" >> `+sq(calls)+`
case "$*" in
"ecr describe-image-scan-findings --registry-id 111111111111 --repository-name payments/api --image-id imageDigest=sha256:api1"*)
  echo '{"imageScanStatus":{"status":"ACTIVE"},"imageScanFindings":{"findingSeverityCounts":{"CRITICAL":2,"HIGH":3},"imageScanCompletedAt":"2026-10-11T10:00:00Z","enhancedFindings":[{"severity":"CRITICAL","fixAvailable":"YES","packageVulnerabilityDetails":{"vulnerabilityId":"CVE-2026-0001"}},{"severity":"HIGH","fixAvailable":"NO","packageVulnerabilityDetails":{"vulnerabilityId":"CVE-2026-0003"}}]}}';;
*) echo "unexpected: $*" >&2; exit 254;;
esac`)

	code, out, errb := run("--config", f.cfg, "images", "scan", "--env", "qa", "--source", "ecr,trivy-operator,prisma")
	if code != ExitFailure {
		t.Fatalf("a critical with a fix fails the run: code=%d err=%q", code, errb)
	}
	for _, want := range []string{
		"IMAGE", "SCANNED BY", "payments/api:1.4", "ecr",
		"vulnerable-image", "2 critical, 3 high vulnerabilities (1 with a fix)", "CVE-2026-0001",
		"quay.io/team/web:2.0", "prisma", "CVE-2026-0002",
		"fluent-bit", "trivy-operator", "2 high vulnerabilities",
		"not-scanned", "registry.internal/ops/tool:9", "nobody",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	data, _ := os.ReadFile(calls)
	if !strings.Contains(string(data), "--region af-south-1") || strings.Count(string(data), "\n") != 1 {
		t.Fatalf("one ECR read, in the registry's region:\n%s", data)
	}

	_, out, _ = run("--config", f.cfg, "images", "scan", "--env", "qa", "--source", "ecr,trivy-operator,prisma", "-o", "json")
	var doc struct {
		Images []scannedImage `json:"images"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Images) != 4 {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if strings.Contains(out, "prisma-token") {
		t.Fatal("the token never appears")
	}
	t.Setenv("NEDCTL_PRISMA_TOKEN", "")
	if code, _, errb := run("--config", f.cfg, "images", "scan", "--env", "qa", "--source", "prisma"); code != ExitUsage || !strings.Contains(errb, "NEDCTL_PRISMA_TOKEN") {
		t.Fatalf("no token: %d %q", code, errb)
	}
}
