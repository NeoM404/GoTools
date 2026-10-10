package app

import (
	"encoding/json"
	"strings"
	"testing"
)

func installEKSFake(t *testing.T, w *ec2World) {
	t.Helper()
	fakeCLI(t, "aws", `echo "$*" >> `+sq(w.calls)+`
case "$*" in
"ec2 describe-regions"*) echo '["af-south-1","eu-west-1"]';;
"eks list-clusters"*"--region af-south-1"*) echo '{"clusters":["payments-eks-prod","payments-eks-tools"]}';;
"eks list-clusters"*) echo '{"clusters":[]}';;
"eks describe-cluster --name payments-eks-prod"*) echo '{"cluster":{"arn":"arn:aws:eks:af-south-1:111111111111:cluster/payments-eks-prod","version":"1.30","accessConfig":{"authenticationMode":"CONFIG_MAP"},"resourcesVpcConfig":{"endpointPublicAccess":false,"endpointPrivateAccess":true}}}';;
"eks describe-cluster --name payments-eks-tools"*) echo '{"cluster":{"arn":"arn:aws:eks:af-south-1:111111111111:cluster/payments-eks-tools","version":"1.31","accessConfig":{"authenticationMode":"API_AND_CONFIG_MAP"},"resourcesVpcConfig":{"endpointPublicAccess":true,"endpointPrivateAccess":true}}}';;
"eks list-access-entries"*) echo '{"accessEntries":["arn:aws:iam::111111111111:role/AWSReservedSSO_Platform-Admin_abc","arn:aws:iam::111111111111:role/devops-pipeline"]}';;
"eks describe-access-entry"*) echo '{"accessEntry":{"type":"STANDARD","username":"x","kubernetesGroups":[]}}';;
"eks list-associated-access-policies --cluster-name payments-eks-tools --principal-arn arn:aws:iam::111111111111:role/AWSReservedSSO"*) echo '{"associatedAccessPolicies":[{"policyArn":"arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy","accessScope":{"type":"cluster"}}]}';;
"eks list-associated-access-policies"*) echo '{"associatedAccessPolicies":[{"policyArn":"arn:aws:eks::aws:cluster-access-policy/AmazonEKSEditPolicy","accessScope":{"type":"namespace","namespaces":["payments"]}}]}';;
*) echo "fake aws: unexpected: $*" >&2; exit 254;;
esac`)
}

func TestEKSAuthReportsConfigMapClustersFirst(t *testing.T) {
	w := newEC2World(t, "prod", "")
	installEKSFake(t, w)
	code, out, errb := run("--config", w.cfg, "eks", "auth", "-o", "json", "--fail-on-configmap")
	if code != ExitFailure {
		t.Fatalf("--fail-on-configmap with a CONFIG_MAP cluster: code=%d err=%q", code, errb)
	}
	var rep eksAuthReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.ConfigMapOnly != 1 || len(rep.Clusters) != 2 || rep.Clusters[0].Cluster != "payments-eks-prod" ||
		rep.Clusters[0].Endpoint != "private" || rep.Clusters[0].Environment != "prod" || rep.Clusters[0].Account != "111111111111" ||
		!strings.Contains(rep.Clusters[0].Action, "API_AND_CONFIG_MAP") || rep.Clusters[1].Endpoint != "public+private" {
		t.Fatalf("report: %+v", rep)
	}
	code, out, _ = run("--config", w.cfg, "eks", "auth")
	if code != ExitOK || !strings.Contains(out, "2 cluster(s) · 1 on CONFIG_MAP only") || !strings.Contains(out, "searched af-south-1") || !strings.Contains(out, "REGION") {
		t.Fatalf("table: code=%d\n%s", code, out)
	}
}

func TestEKSAccessListsPrincipalsAndScopes(t *testing.T) {
	w := newEC2World(t, "prod", "")
	installEKSFake(t, w)
	code, out, errb := run("--config", w.cfg, "eks", "access", "payments-eks-tools")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, want := range []string{"AWSReservedSSO_Platform-Admin_abc", "AmazonEKSClusterAdminPolicy (cluster)", "devops-pipeline", "AmazonEKSEditPolicy (namespace:payments)", "2 principal(s)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("lacks %q:\n%s", want, out)
		}
	}
}

// With no fleet inventory configured, clusters list answers from the AWS
// account signed in to, instead of failing.
func TestClustersListLiveWithoutInventory(t *testing.T) {
	w := newEC2World(t, "prod", "")
	installEKSFake(t, w)
	code, out, errb := run("--config", w.cfg, "clusters", "list")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, want := range []string{"payments-eks-prod", "payments-eks-tools", "af-south-1", "2 cluster(s) in payments · PROD, live from AWS", "nedctl kube <name>"} {
		if !strings.Contains(out, want) {
			t.Fatalf("lacks %q:\n%s", want, out)
		}
	}
	code, out, _ = run("--config", w.cfg, "clusters", "list", "-o", "json")
	if code != ExitOK || !strings.Contains(out, `"cluster": "payments-eks-tools"`) {
		t.Fatalf("json: %s", out)
	}
	code, out, _ = run("--config", w.cfg, "clusters", "list", "--env", "dev", "-o", "json")
	if code != ExitOK || strings.TrimSpace(out) != "[]" {
		t.Fatalf("env filter: %s", out)
	}
}
