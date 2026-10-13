package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCert is a self-signed certificate for cn expiring at notAfter, PEM.
func testCert(t *testing.T, cn string, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: notAfter.Add(-365 * 24 * time.Hour), NotAfter: notAfter, DNSNames: []string{cn}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestExpiryFindsWhatStopsOnADate(t *testing.T) {
	today := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	pinNow(t, today)
	f := newClusterFixture(t, `, "supportCalendar": {"azure": {"1.29": {"standardEnd": "2026-10-01"}, "1.31": {"standardEnd": "2026-11-01"}}}`, "pay-k8s-qa-cluster")
	day := func(d int) time.Time { return today.Add(time.Duration(d) * 24 * time.Hour) }
	probes := expiryProbes("")
	answerProbes(t, f, "pay-k8s-qa-cluster", probes, map[int]string{
		0: `{"gitVersion":"v1.31.2"}`,
		exSecrets: "payments\tapi-tls\t\t" + b64(testCert(t, "api.bank.example", day(-2))) + "\n" +
			"payments\tweb-tls\t\t" + b64(testCert(t, "web.bank.example", day(5))) + "\n" +
			"payments\tauto-tls\tauto\t" + b64(testCert(t, "auto.bank.example", day(5))) + "\n" +
			"payments\tlater-tls\t\t" + b64(testCert(t, "later.bank.example", day(200))) + "\n",
		exCertificates: "payments\tauto\tauto-tls\t2026-10-18T12:00:00Z\t2026-10-16T12:00:00Z\tTrue\tCertificate is up to date\n" +
			"payments\tbroken\tbroken-tls\t\t\tFalse\tIssuing certificate as Secret does not exist: ACME challenge failed\n",
		exIngresses:   "payments\tweb\tweb-tls gone-tls\n",
		exWebhooks:    "H\tValidatingWebhookConfiguration\tpolicy-webhook\nB\tvalidate.policy.io\t" + b64(testCert(t, "policy-webhook.svc", day(20))) + "\n",
		exAPIServices: "v1.\t\tTrue\nv1beta1.metrics.k8s.io\t" + b64(testCert(t, "metrics-server", day(60))) + "\tTrue\n",
		exRootCA:      string(testCert(t, "kubernetes", day(3000))),
	})
	f.fail(t, "pay-k8s-qa-cluster", strings.Join(probes[exGateways], " "), `error: the server doesn't have a resource type "gateways"`)

	code, out, errb := run("--config", f.cfg, "expiry", "--env", "qa")
	if code != ExitFailure {
		t.Fatalf("an expired certificate fails the run: code=%d err=%q", code, errb)
	}
	for _, want := range []string{
		"CRITICAL", "secret/payments/api-tls", "expired 2 day(s) ago", "api.bank.example",
		"secret/payments/web-tls", "expires in 5 day(s)",
		"cert-manager-renewal", "ACME challenge failed",
		"missing-certificate", "ingress/payments/web", "secret gone-tls is missing",
		"validatingwebhook/policy-webhook (validate.policy.io)", "expires in 20 day(s)",
		"apiservice/v1beta1.metrics.k8s.io",
		"kubernetes-support", "standard support ends soon",
		"certificate has expired", "CHECK", "FIX",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	// cert-manager renews auto-tls: one level lower than web-tls (high → medium).
	if !strings.Contains(out, "MEDIUM  tls-secret") && !strings.Contains(out, "renewed by cert-manager from 2026-10-16") {
		t.Fatalf("cert-manager renewal not shown:\n%s", out)
	}
	if strings.Contains(out, "later.bank.example") || strings.Contains(out, "cluster CA") {
		t.Fatalf("far-off expiries are only shown with --all:\n%s", out)
	}
	if strings.Contains(out, "gateways") || strings.Contains(out, "not assessed") {
		t.Fatalf("Istio not installed is not an unassessed check:\n%s", out)
	}

	_, out, _ = run("--config", f.cfg, "expiry", "--env", "qa", "--all", "-o", "json")
	var doc struct {
		Schema   string            `json:"schema"`
		Clusters []clusterFindings `json:"clusters"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Schema != findingsSchema || len(doc.Clusters) != 1 {
		t.Fatalf("json: %v %s", err, out)
	}
	c := doc.Clusters[0]
	if c.Status != "critical" || c.Findings[0].Severity != "critical" || !strings.Contains(out, "later.bank.example") || !strings.Contains(out, "cluster CA") {
		t.Fatalf("json report: %+v", c)
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatal("never a key")
	}
	if code, _, _ := run("--config", f.cfg, "expiry", "--env", "qa", "--fail-on", "nope"); code != ExitUsage {
		t.Fatal("bad --fail-on")
	}
}

func TestExpirySeverity(t *testing.T) {
	for days, want := range map[int]string{-1: "critical", 0: "high", 7: "high", 8: "medium", 30: "medium", 31: "low", 90: "low", 91: ""} {
		if got := expirySeverity(days, 30); got != want {
			t.Errorf("%d days: %q want %q", days, got, want)
		}
	}
	if lower("high") != "medium" || lower("critical") != "critical" || lower("low") != "low" {
		t.Fatal("lower")
	}
}
