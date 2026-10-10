package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nedctl/internal/audit"
)

const eksHost = "abc123def456.gr7.af-south-1.eks.amazonaws.com"

// fakeEKSAPI serves /version over TLS on 127.0.0.1:port with a certificate
// valid ONLY for the EKS hostname, and requires the bearer token the fake
// `aws eks get-token` hands out — standing in for the cluster at the far
// end of the Session Manager tunnel.
func fakeEKSAPI(t *testing.T, port int) (caData string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: eksHost}, DNSNames: []string{eksHost},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k8s-aws-v1.fake" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"major":"1","minor":"30","gitVersion":"v1.30.4-eks"}`))
	}), TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}
	go srv.ServeTLS(l, "", "")
	t.Cleanup(func() { srv.Close() })
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func installConnectFake(t *testing.T, w *ec2World, caData string) {
	t.Helper()
	desc := `{"cluster":{"name":"payments-eks-prod","arn":"arn:aws:eks:af-south-1:111111111111:cluster/payments-eks-prod","endpoint":"https://` + eksHost + `","version":"1.30","certificateAuthority":{"data":"` + caData + `"}}}`
	fakeCLI(t, "aws", `echo "$*" >> `+sq(w.calls)+`
case "$*" in
"eks describe-cluster"*"--region af-south-1"*) printf '%s' `+sq(desc)+`;;
"eks list-clusters"*"--region af-south-1"*) echo '{"clusters":["payments-eks-prod"]}';;
"eks list-clusters"*) echo '{"clusters":[]}';;
"ec2 describe-regions"*) echo '["af-south-1","eu-west-1"]';;
"ec2 describe-instances"*"--region af-south-1"*) printf '%s' `+sq(instancesJSON)+`;;
"ec2 describe-instances"*) echo '{"Reservations":[]}';;
"ssm start-session"*) echo "Waiting for connections...";;
"eks get-token"*) echo '{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","status":{"token":"k8s-aws-v1.fake","expirationTimestamp":"2099-01-01T00:00:00Z"}}';;
*) echo "fake aws: unexpected: $*" >&2; exit 254;;
esac`)
}

func TestConnectTunnelsThroughDevopsBoxAndKubectlWorks(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not installed")
	}
	w := newEC2World(t, "prod", "")
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	ca := fakeEKSAPI(t, port)
	installConnectFake(t, w, ca)

	code, _, errb := run("--config", w.cfg, "connect", "payments-eks-prod", "--port", strconv.Itoa(port))
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	calls := w.awsCalls(t)
	want := "ssm start-session --target i-0aaaaaaaaaaaaaaa1 --document-name AWS-StartPortForwardingSessionToRemoteHost --parameters host=" + eksHost + ",portNumber=443,localPortNumber=" + strconv.Itoa(port) + " --region af-south-1"
	if !strings.Contains(calls, want) {
		t.Fatalf("tunnel must go through the devops instance to the private endpoint:\n%s", calls)
	}
	kc := filepath.Join(w.home, ".kube", "nedctl", "payments-eks-prod.json")
	if fi, err := os.Stat(kc); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("kubeconfig: %v %v", fi, err)
	}

	// The real kubectl, through the kubeconfig: TLS must verify against the
	// cluster CA under the EKS hostname, and auth must come from get-token.
	out, err := exec.Command("kubectl", "--kubeconfig", kc, "get", "--raw", "/version").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "v1.30.4-eks") {
		t.Fatalf("kubectl through the tunnel kubeconfig: %v\n%s", err, out)
	}
	if !strings.Contains(w.awsCalls(t), "eks get-token --cluster-name payments-eks-prod --region af-south-1 --profile nedctl.payments-prod.Platform-Admin") {
		t.Fatalf("token must come from the engineer's own profile:\n%s", w.awsCalls(t))
	}

	ev := readAudit(t, w.logPath)
	if len(ev) != 2 || ev[1].Action != "eks-connect" || ev[1].Cluster != "payments-eks-prod" || !ev[1].Production || ev[1].Outcome != audit.OutcomeSuccess {
		t.Fatalf("audit: %+v", ev)
	}

	// guard sees production through this kubeconfig.
	t.Setenv("KUBECONFIG", kc)
	cfgGuard := filepath.Join(w.home, "g.json")
	os.WriteFile(cfgGuard, []byte(`{"prodPatterns": ["(?i)(^|[-_.])(prod|prd|qa)([-_.]|$)"]}`), 0o600)
	if code, _, _ := run("--config", cfgGuard, "guard", "--block"); code != ExitProdContext {
		t.Fatalf("guard: code=%d", code)
	}
}

func TestConnectKubeconfigRejectsWrongHostname(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not installed")
	}
	w := newEC2World(t, "dev", "")
	port, _ := freePort()
	ca := fakeEKSAPI(t, port)
	installConnectFake(t, w, ca)
	if code, _, errb := run("--config", w.cfg, "connect", "payments-eks-prod", "--port", strconv.Itoa(port)); code != ExitOK {
		t.Fatalf("err=%q", errb)
	}
	kc := filepath.Join(w.home, ".kube", "nedctl", "payments-eks-prod.json")
	data, _ := os.ReadFile(kc)
	var doc map[string]any
	json.Unmarshal(data, &doc)
	// Tamper: point TLS at another name — kubectl must now refuse.
	os.WriteFile(kc, []byte(strings.Replace(string(data), eksHost, "evil.example.com", 1)), 0o600)
	if out, err := exec.Command("kubectl", "--kubeconfig", kc, "get", "--raw", "/version").CombinedOutput(); err == nil {
		t.Fatalf("TLS must verify the cluster's hostname; kubectl accepted it:\n%s", out)
	}
}

func TestConnectRefusesBadInput(t *testing.T) {
	w := newEC2World(t, "dev", "")
	for _, args := range [][]string{{"connect", "a", "b"}, {"connect", "bad name"}, {"connect", "x", "--port", "70000"}} {
		if code, _, _ := run(append([]string{"--config", w.cfg}, args...)...); code != ExitUsage {
			t.Fatalf("%v: code=%d", args, code)
		}
	}
	// An endpoint that is not EKS is refused before anything is written.
	fakeCLI(t, "aws", `case "$*" in
"ec2 describe-regions"*) echo '["af-south-1"]';;
"eks list-clusters"*) echo '{"clusters":["x"]}';;
"eks describe-cluster"*) echo '{"cluster":{"arn":"arn:aws:eks:af-south-1:1:cluster/x","endpoint":"https://evil.example.com","certificateAuthority":{"data":"eA=="}}}';;
esac`)
	code, _, errb := run("--config", w.cfg, "connect", "x")
	if code != ExitFailure || !strings.Contains(errb, "unexpected endpoint") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

// EKS returned an endpoint with an upper-case prefix on the bank's first
// real connect; it was refused as "unexpected". It must be accepted,
// lower-cased, and still verified by kubectl against the cluster CA.
func TestConnectAcceptsUpperCaseEndpoint(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not installed")
	}
	w := newEC2World(t, "dev", "")
	port, _ := freePort()
	ca := fakeEKSAPI(t, port)
	installConnectFake(t, w, ca)
	upper := strings.ToUpper(strings.TrimSuffix(eksHost, ".gr7.af-south-1.eks.amazonaws.com")) + ".gr7.af-south-1.eks.amazonaws.com"
	desc := `{"cluster":{"name":"payments-eks-prod","arn":"arn:aws:eks:af-south-1:111111111111:cluster/payments-eks-prod","endpoint":"https://` + upper +
		`","version":"1.30","certificateAuthority":{"data":"` + ca + `"}}}`
	fakeCLI(t, "aws", `echo "$*" >> `+sq(w.calls)+`
case "$*" in
"ec2 describe-regions"*) echo '["af-south-1"]';;
"eks list-clusters"*) echo '{"clusters":["payments-eks-prod"]}';;
"eks describe-cluster"*) printf '%s' `+sq(desc)+`;;
"ec2 describe-instances"*) printf '%s' `+sq(instancesJSON)+`;;
"ssm start-session"*) echo "Waiting for connections...";;
"eks get-token"*) echo '{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","status":{"token":"k8s-aws-v1.fake","expirationTimestamp":"2099-01-01T00:00:00Z"}}';;
esac`)
	if code, _, errb := run("--config", w.cfg, "connect", "payments-eks-prod", "--port", strconv.Itoa(port)); code != ExitOK {
		t.Fatalf("err=%q", errb)
	}
	if !strings.Contains(w.awsCalls(t), "host="+eksHost+",") {
		t.Fatalf("the tunnel host must be lower-cased:\n%s", w.awsCalls(t))
	}
	kc := filepath.Join(w.home, ".kube", "nedctl", "payments-eks-prod.json")
	if out, err := exec.Command("kubectl", "--kubeconfig", kc, "get", "--raw", "/version").CombinedOutput(); err != nil {
		t.Fatalf("kubectl: %v\n%s", err, out)
	}
}
