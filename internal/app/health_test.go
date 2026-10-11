package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func certB64(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestHealthOfAnEnvironment(t *testing.T) {
	today := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	old := now
	now = func() time.Time { return today }
	t.Cleanup(func() { now = old })
	f := newClusterFixture(t, `,"supportCalendar":{"azure":{"1.29":{"standardEnd":"2026-04-01","extendedEnd":"2027-04-01"},"1.30":{"standardEnd":"2027-07-01"}}}`,
		"good-k8s-qa-cluster", "bad-k8s-qa-cluster", "gone-k8s-qa-cluster")
	key := func(i int) string { return strings.Join(healthProbes[i], " ") }
	g, b := "good-k8s-qa-cluster", "bad-k8s-qa-cluster"
	f.answer(t, g, key(0), `{"gitVersion":"v1.30.4"}`)
	f.answer(t, g, key(1), "n1\tReady=True,MemoryPressure=False,\t\nn2\tReady=True,\t\n")
	f.answer(t, g, key(2), "app\tapi-1\tRunning\t\t0\t2026-10-10T08:00:00Z\t\n")
	f.answer(t, g, key(3), "Deployment\tapp\tapi\t2\t2\n")
	f.answer(t, g, key(4), "app\tdata\tBound\n")
	f.answer(t, g, key(5), "app\tweb-tls\t"+certB64(t, today.Add(200*24*time.Hour))+"\n")
	f.answer(t, b, key(0), `{"gitVersion":"v1.29.9"}`)
	f.answer(t, b, key(1), "n1\tReady=False,\t\nn2\tReady=True,DiskPressure=True,\ttrue\n")
	f.answer(t, b, key(2), "app\tapi-1\tRunning\tCrashLoopBackOff\t12\t2026-10-10T08:00:00Z\t\n"+
		"app\tbatch-1\tPending\t\t0\t2026-10-11T08:00:00Z\t\napp\tnew-1\tPending\t\t0\t2026-10-11T08:58:00Z\t\n")
	f.answer(t, b, key(3), "Deployment\tapp\tapi\t3\t\nStatefulSet\tapp\tdb\t3\t2\n")
	f.answer(t, b, key(4), "app\tdata\tPending\n")
	f.answer(t, b, key(5), "app\told-tls\t"+certB64(t, today.Add(-24*time.Hour))+"\napp\tsoon-tls\t"+certB64(t, today.Add(10*24*time.Hour))+"\n")
	f.fail(t, "gone-k8s-qa-cluster", key(0), "Unable to connect to the server: dial tcp 10.0.0.9:443: i/o timeout")

	code, out, errb := run("--config", f.cfg, "health", "--env", "qa")
	if code != ExitFailure {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, want := range []string{
		"qa   good-k8s-qa-cluster  ok           2/2 ready              1, 0 failing  1, 0 short  1.30.4 ok",
		"qa   bad-k8s-qa-cluster   fail         1/2 ready, 1 cordoned  3, 2 failing  2, 2 short  1.29.9 extended",
		"gone-k8s-qa-cluster  unreachable",
		"✖ TLS certificate app/old-tls expired on 2026-10-10", "✖ deployment app/api has no ready replicas (0/3)", "✖ node n1 is not Ready",
		"✖ pod app/api-1: CrashLoopBackOff", "⚠ TLS certificate app/soon-tls expires in 10 days", "⚠ Kubernetes 1.29.9 is in extended (paid) support until 2027-04-01",
		"⚠ node n2: DiskPressure", "⚠ pod app/batch-1 pending for 1h", "⚠ statefulset app/db: 2/3 ready", "⚠ volume claim app/data is Pending", "i/o timeout",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, "new-1") {
		t.Error("a pod pending for 2 minutes is not a problem yet")
	}
	if t.Failed() {
		t.Log(out)
	}
	code, out, _ = run("--config", f.cfg, "health", "--env", "qa", "--match", "good", "-o", "json")
	if code != ExitOK || !strings.Contains(out, `"status": "ok"`) {
		t.Fatalf("code=%d out=%s", code, out)
	}
}
