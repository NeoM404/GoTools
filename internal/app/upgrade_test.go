package app

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/support"
)

// fakeUpgradeAWS is an aws CLI answering the EKS and EC2 reads upgrade-check
// makes, for payments-eks-qa on 1.31; every call is logged.
func fakeUpgradeAWS(t *testing.T) string {
	t.Helper()
	calls := filepath.Join(t.TempDir(), "aws-calls")
	fakeCLI(t, "aws", `echo "$*" >> `+sq(calls)+`
case "$*" in
"eks describe-cluster --name payments-eks-qa"*) echo '{"cluster":{"version":"1.31","platformVersion":"eks.20","status":"ACTIVE","upgradePolicy":{"supportType":"EXTENDED"},"accessConfig":{"authenticationMode":"API_AND_CONFIG_MAP"},"resourcesVpcConfig":{"subnetIds":["subnet-a","subnet-b"]},"health":{"issues":[]}}}';;
"eks describe-cluster-versions"*) echo '{"clusterVersions":[{"clusterVersion":"1.31","versionStatus":"EXTENDED_SUPPORT","endOfStandardSupportDate":"2025-11-26T00:00:00Z","endOfExtendedSupportDate":"2026-11-26T00:00:00Z"},{"clusterVersion":"1.32","versionStatus":"STANDARD_SUPPORT","endOfStandardSupportDate":"2026-03-23T00:00:00Z","endOfExtendedSupportDate":"2027-03-23T00:00:00Z"},{"clusterVersion":"1.33","versionStatus":"STANDARD_SUPPORT","endOfStandardSupportDate":"2026-07-29T00:00:00Z","endOfExtendedSupportDate":"2027-07-29T00:00:00Z"}]}';;
"eks list-insights"*) echo '{"insights":[{"id":"i-1","name":"Deprecated APIs removed in Kubernetes v1.32","category":"UPGRADE_READINESS","kubernetesVersion":"1.32","insightStatus":{"status":"ERROR","reason":"Deprecated API usage detected"}},{"id":"i-2","name":"Kubelet version skew","category":"UPGRADE_READINESS","kubernetesVersion":"1.32","insightStatus":{"status":"PASSING"}},{"id":"i-3","name":"Deprecated APIs removed in Kubernetes v1.35","category":"UPGRADE_READINESS","kubernetesVersion":"1.35","insightStatus":{"status":"WARNING","reason":"usage in the last 30 days"}},{"id":"i-4","name":"Amazon EKS add-on misconfiguration","category":"MISCONFIGURATION","insightStatus":{"status":"WARNING","reason":"pod identity association missing"}}]}';;
"eks describe-insight --cluster-name payments-eks-qa --id i-1"*) echo '{"insight":{"recommendation":"Update manifests and clients to flowcontrol.apiserver.k8s.io/v1","resources":[{"kubernetesResourceUri":"/apis/flowcontrol.apiserver.k8s.io/v1beta3/flowschemas/team-fs"}],"categorySpecificSummary":{"deprecationDetails":[{"usage":"/apis/flowcontrol.apiserver.k8s.io/v1beta3/flowschemas","replacedWith":"/apis/flowcontrol.apiserver.k8s.io/v1/flowschemas","stopServingVersion":"1.32","clientStats":[{"userAgent":"argocd-application-controller","numberOfRequestsLast30Days":120}]}]}}}';;
"eks describe-insight"*) echo '{"insight":{"recommendation":"see the insight"}}';;
"eks list-nodegroups"*) echo '{"nodegroups":["app","legacy"]}';;
"eks describe-nodegroup --cluster-name payments-eks-qa --nodegroup-name app"*) echo '{"nodegroup":{"nodegroupName":"app","version":"1.31","amiType":"AL2023_x86_64_STANDARD","status":"ACTIVE","scalingConfig":{"desiredSize":3},"updateConfig":{"maxUnavailable":1}}}';;
"eks describe-nodegroup --cluster-name payments-eks-qa --nodegroup-name legacy"*) echo '{"nodegroup":{"nodegroupName":"legacy","version":"1.29","amiType":"AL2_x86_64","status":"ACTIVE","scalingConfig":{"desiredSize":2},"updateConfig":{"maxUnavailablePercentage":33}}}';;
"eks list-addons"*) echo '{"addons":["vpc-cni","coredns","kube-proxy","aws-efs-csi-driver"]}';;
"eks describe-addon --cluster-name payments-eks-qa --addon-name vpc-cni"*) echo '{"addon":{"addonName":"vpc-cni","addonVersion":"v1.18.1-eksbuild.1","status":"ACTIVE"}}';;
"eks describe-addon --cluster-name payments-eks-qa --addon-name coredns"*) echo '{"addon":{"addonName":"coredns","addonVersion":"v1.11.1-eksbuild.9","status":"ACTIVE"}}';;
"eks describe-addon --cluster-name payments-eks-qa --addon-name kube-proxy"*) echo '{"addon":{"addonName":"kube-proxy","addonVersion":"v1.31.2-eksbuild.3","status":"ACTIVE"}}';;
"eks describe-addon --cluster-name payments-eks-qa --addon-name aws-efs-csi-driver"*) echo '{"addon":{"addonName":"aws-efs-csi-driver","addonVersion":"v2.0.7-eksbuild.1","status":"DEGRADED","health":{"issues":[{"code":"InsufficientNumberOfReplicas","message":"the controller has 0 of 2 replicas"}]}}}';;
"eks describe-addon-versions --kubernetes-version 1.31"*) echo '{"addons":[{"addonName":"vpc-cni","addonVersions":[{"addonVersion":"v1.18.1-eksbuild.1","compatibilities":[{"clusterVersion":"1.31","defaultVersion":false}]},{"addonVersion":"v1.19.0-eksbuild.1","compatibilities":[{"clusterVersion":"1.31","defaultVersion":true}]}]},{"addonName":"coredns","addonVersions":[{"addonVersion":"v1.11.1-eksbuild.9","compatibilities":[{"clusterVersion":"1.31","defaultVersion":true}]},{"addonVersion":"v1.11.3-eksbuild.1","compatibilities":[{"clusterVersion":"1.31","defaultVersion":false}]}]},{"addonName":"kube-proxy","addonVersions":[{"addonVersion":"v1.31.2-eksbuild.3","compatibilities":[{"clusterVersion":"1.31","defaultVersion":true}]}]},{"addonName":"aws-efs-csi-driver","addonVersions":[{"addonVersion":"v2.0.7-eksbuild.1","compatibilities":[{"clusterVersion":"1.31","defaultVersion":true}]}]}]}';;
"eks describe-addon-versions --kubernetes-version 1.32"*) echo '{"addons":[{"addonName":"vpc-cni","addonVersions":[{"addonVersion":"v1.19.0-eksbuild.1","compatibilities":[{"clusterVersion":"1.32","defaultVersion":true}]},{"addonVersion":"v1.19.2-eksbuild.1","compatibilities":[{"clusterVersion":"1.32","defaultVersion":false}]}]},{"addonName":"coredns","addonVersions":[{"addonVersion":"v1.11.3-eksbuild.1","compatibilities":[{"clusterVersion":"1.32","defaultVersion":false}]},{"addonVersion":"v1.11.4-eksbuild.2","compatibilities":[{"clusterVersion":"1.32","defaultVersion":true}]}]},{"addonName":"kube-proxy","addonVersions":[{"addonVersion":"v1.32.0-eksbuild.2","compatibilities":[{"clusterVersion":"1.32","defaultVersion":true}]},{"addonVersion":"v1.31.2-eksbuild.3","compatibilities":[{"clusterVersion":"1.32","defaultVersion":false}]}]},{"addonName":"aws-efs-csi-driver","addonVersions":[{"addonVersion":"v2.0.7-eksbuild.1","compatibilities":[{"clusterVersion":"1.32","defaultVersion":true}]}]}]}';;
"ec2 describe-subnets"*) echo '{"Subnets":[{"SubnetId":"subnet-a","AvailabilityZone":"af-south-1a","CidrBlock":"10.0.0.0/24","AvailableIpAddressCount":2},{"SubnetId":"subnet-b","AvailabilityZone":"af-south-1b","CidrBlock":"10.0.1.0/24","AvailableIpAddressCount":1}]}';;
"eks list-fargate-profiles"*) echo '{"fargateProfileNames":[]}';;
"ec2 describe-regions"*) echo '["af-south-1"]';;
"eks list-clusters"*) echo '{"clusters":["payments-eks-qa"]}';;
*) echo "fake aws: unexpected: $*" >&2; exit 254;;
esac`)
	return calls
}

// upgradeCluster is the cluster side: what the kubectl lists return.
func upgradeCluster() clusterOut {
	outs := map[int]string{
		0: `{"gitVersion":"v1.31.4-eks-1234"}`,
		upNodes: "n1\tv1.31.4-eks-1\tAmazon Linux 2023.6\t6.1\tcontainerd://2.0.1\tapp\t\t\tm6i.large\n" +
			"n2\tv1.29.10-eks-1\tAmazon Linux 2\t5.10.0-1.amzn2\tcontainerd://1.7.11\tlegacy\t\t\tm5.large\n" +
			"n3\tv1.31.4-eks-1\tBottlerocket OS 1.20\t6.1\tcontainerd://2.0.1\t\tdefault\t\tm6i.large\n" +
			"n4\tv1.31.4-eks-1\tAmazon Linux 2023.6\t6.1\tcontainerd://1.7.20\t\t\t\tm6i.large\n",
		upWorkloads: "W\tDeployment\tpayments\tapi\t1\tRollingUpdate\t{\"app\":\"api\"}\t{}\t\t\n" +
			"C\tapi\treg/api:1\t10\t100m\t128Mi\t\t\n" +
			"W\tDeployment\tpayments\tweb\t3\tRecreate\t{\"app\":\"web\"}\t{\"container.apparmor.security.beta.kubernetes.io/web\":\"runtime/default\"}\t\t\n" +
			"C\tweb\treg/web:2\t\t\t\t\t\n" +
			"W\tDeployment\tpayments\tledger\t3\tRollingUpdate\t{\"app\":\"ledger\",\"tier\":\"core\"}\t{}\t\t\n" +
			"C\tledger\treg/ledger:3\t10\t100m\t1Gi\t{\"exec\":{\"command\":[\"sleep\",\"5\"]}}\t\n" +
			"W\tDeployment\tkarpenter\tkarpenter\t2\tRollingUpdate\t{\"app\":\"karpenter\"}\t{}\t\t\n" +
			"C\tcontroller\tpublic.ecr.aws/karpenter/controller:1.0.8\t10\t1\t1Gi\t\t\n" +
			"W\tDeployment\tingress-nginx\tingress-nginx-controller\t2\tRollingUpdate\t{\"app\":\"ingress-nginx\"}\t{}\t\t\n" +
			"C\tcontroller\tregistry.k8s.io/ingress-nginx/controller:v1.11.2\t10\t100m\t90Mi\t\t\n" +
			"W\tDeployment\tcert-manager\tcert-manager\t2\tRollingUpdate\t{\"app\":\"cert-manager\"}\t{}\t\t\n" +
			"C\tcontroller\tquay.io/jetstack/cert-manager-controller:v1.15.0\t10\t10m\t32Mi\t\t\n" +
			"W\tDeployment\tkube-system\tcoredns\t2\tRollingUpdate\t{\"k8s-app\":\"kube-dns\"}\t{}\t\t\n" +
			"C\tcoredns\tcoredns:1.11\t10\t100m\t70Mi\t\t\n",
		upPDBs: "payments\tledger-pdb\t{\"matchLabels\":{\"app\":\"ledger\"}}\t\t0\t3\t3\t3\t0\t2\t2\t\n" +
			"payments\tcore-pdb\t{\"matchLabels\":{\"tier\":\"core\"}}\t1\t\t3\t3\t1\t2\t1\t1\t\n" +
			"cert-manager\tcm-pdb\t{\"matchLabels\":{\"app\":\"cert-manager\"}}\t1\t\t2\t2\t1\t1\t1\t1\t\n" +
			"ingress-nginx\tin-pdb\t{\"matchLabels\":{\"app\":\"ingress-nginx\"}}\t1\t\t2\t2\t1\t1\t1\t1\t\n",
		upPods: "payments\tledger-1\t{\"app\":\"ledger\",\"tier\":\"core\"}\tn1\tRunning\t\n" +
			"payments\tledger-2\t{\"app\":\"ledger\",\"tier\":\"core\"}\tn3\tRunning\t\n" +
			"payments\told-1\t{\"app\":\"ledger\",\"tier\":\"core\"}\tn3\tRunning\t2026-10-13T10:00:00Z\n",
		upFieldsNS: "Deployment\tpayments/api\tkubectl-client-side-apply=apps/v1,\n" +
			"HorizontalPodAutoscaler\tpayments/api\thelm=autoscaling/v2beta2,kube-controller-manager=autoscaling/v2,\n",
		upFieldsCluster: "FlowSchema\t/team-fs\targocd-application-controller=flowcontrol.apiserver.k8s.io/v1beta3,api-priority-and-fairness-config-consumer-v1=flowcontrol.apiserver.k8s.io/v1,\n" +
			"FlowSchema\t/exempt\tapi-priority-and-fairness-config-producer-v1=flowcontrol.apiserver.k8s.io/v1beta3,\n" +
			"PriorityLevelConfiguration\t/team-pl\tkubectl-client-side-apply=flowcontrol.apiserver.k8s.io/v1beta3,\n",
		upServices:  "payments\tweb\tLoadBalancer\t{\"app\":\"web\"}\t\t\n",
		upNetpol:    "",
		upCRB:       "anon-metrics\tsystem:monitoring\tsystem:unauthenticated\nsystem:public-info-viewer\tsystem:public-info-viewer\tsystem:authenticated system:unauthenticated\n",
		upKubeProxy: "mode: iptables\n",
		upWebhooks:  "H\tValidatingWebhookConfiguration\tpolicy\nB\tpods.policy.io\tFail\t10\t{}\t[\"pods\"]\tpolicy/policy-svc\n",
		upCRDs:      "widgets.example.io\tv1alpha1 v1\tv1alpha1=false,v1=true,\n",
	}
	co := clusterOut{Cloud: "aws", Env: "qa", Cluster: "payments-eks-qa", Outs: make([]probeOut, len(upgradeProbes(32)))}
	for i := range co.Outs {
		co.Outs[i] = probeOut{Out: []byte(outs[i])}
	}
	return co
}

func eksTestFacts(t *testing.T) (eksFacts, string) {
	t.Helper()
	calls := fakeUpgradeAWS(t)
	cfg := config.Config{}
	f := gatherEKSFacts(context.Background(), cfg, "nedctl.payments-qa.Platform-ReadOnly", "af-south-1", "payments-eks-qa", "")
	return f, calls
}

func TestUpgradeFactsReadOnlyEKSAndEC2(t *testing.T) {
	f, calls := eksTestFacts(t)
	if len(f.Errors) != 0 {
		t.Fatalf("errors: %v", f.Errors)
	}
	if f.Version != "1.31" || len(f.Versions) != 3 || len(f.Nodegroups) != 2 || len(f.Addons) != 4 || len(f.Subnets) != 2 || len(f.Insights) != 4 {
		t.Fatalf("facts: %+v", f)
	}
	if f.AddonVersions["1.32"]["vpc-cni"].Default != "v1.19.0-eksbuild.1" || f.Versions[0].ExtendedEnd != "2026-11-26" {
		t.Fatalf("versions: %+v %+v", f.AddonVersions, f.Versions)
	}
	in := f.Insights[0]
	if len(in.Deprecation) != 1 || in.Deprecation[0].Clients[0] != "argocd-application-controller (120)" || in.Recommend == "" {
		t.Fatalf("insight details: %+v", in)
	}
	if f.Insights[1].Recommend != "" {
		t.Fatal("passing insights are not described (one call fewer each)")
	}
	data, _ := os.ReadFile(calls)
	for _, l := range nonEmptyLines(string(data)) {
		verb := strings.Fields(l)[1]
		if !(strings.HasPrefix(verb, "describe-") || strings.HasPrefix(verb, "list-")) {
			t.Fatalf("not a read: %s", l)
		}
		if !strings.Contains(l, "--profile nedctl.payments-qa.Platform-ReadOnly --region af-south-1 --output json") {
			t.Fatalf("every call names the profile and region: %s", l)
		}
	}
}

func findCheck(r upgradeReport, check string) []checkFinding {
	var out []checkFinding
	for _, f := range r.Findings {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return out
}

func TestUpgradeAssessment(t *testing.T) {
	f, _ := eksTestFacts(t)
	f.Profile = "nedctl.payments-qa.Platform-ReadOnly"
	cfg := config.Config{CostRates: supportRates()}
	r := assessUpgrade(cfg, f, upgradeCluster(), "1.32", time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC))

	want := map[string]string{ // check → severity of its first finding
		"addon-incompatible":     "critical", // vpc-cni / coredns: critical add-ons
		"addon-unhealthy":        "high",     // efs: optional
		"karpenter-incompatible": "critical",
		"subnet-capacity":        "critical",
		"subnet-ips":             "medium",
		"kubelet-skew":           "medium", // 1.29 → 1.32 is the largest skew allowed
		"al2-nodes":              "low",    // before 1.33
		"self-managed-nodes":     "medium",
		"containerd-1":           "medium",
		"removed-api":            "high",
		"stale-manifest":         "medium",
		"anonymous-access":       "medium",
		"apparmor-annotation":    "medium",
		"ingress-nginx-retired":  "high",
		"single-replica":         "high",
		"recreate-strategy":      "high",
		"no-readiness-probe":     "medium",
		"no-requests":            "medium",
		"no-pdb":                 "medium",
		"no-prestop":             "medium",
		"pdb-blocks-drain":       "medium",
		"fail-closed-webhook":    "medium",
		"crd-stored-version":     "medium",
		"addon-update":           "low",
		"extended-support":       "info",
	}
	for check, sev := range want {
		got := findCheck(r, check)
		if len(got) == 0 || got[0].Severity != sev {
			t.Errorf("%s: %+v, want severity %s", check, got, sev)
		}
	}
	// Removed APIs: only the user-written ones, once per API path for points.
	removed := findCheck(r, "removed-api")
	if len(removed) != 2 || !strings.Contains(removed[0].Detail+removed[1].Detail, "argocd-application-controller") {
		t.Fatalf("removed APIs: %+v", removed)
	}
	for _, x := range r.Findings {
		if strings.Contains(x.Object, "exempt") {
			t.Fatalf("the API server's own APF writer is not a finding: %+v", x)
		}
	}
	// Insights: i-1 confirms the removed-API finding (no extra points),
	// i-3 is for 1.35 (info), i-4 is a misconfiguration (no points).
	var i1, i3, i4 checkFinding
	for _, x := range findCheck(r, "eks-insight") {
		switch x.Object {
		case "insight i-1":
			i1 = x
		case "insight i-3":
			i3 = x
		case "insight i-4":
			i4 = x
		}
	}
	if i1.Points != 0 || !strings.Contains(i1.Detail, "confirms") || !strings.Contains(i1.Detail, "argocd-application-controller (120)") {
		t.Fatalf("i-1: %+v", i1)
	}
	if i3.Severity != "info" || i3.Points != 0 || i4.Area != "misconfiguration" || i4.Points != 0 {
		t.Fatalf("i-3: %+v i-4: %+v", i3, i4)
	}
	// Add-ons: a build supporting both versions goes in before the control
	// plane.
	inc := findCheck(r, "addon-incompatible")
	if !strings.Contains(inc[0].Fix+inc[1].Fix, "v1.19.0-eksbuild.1 (supports 1.31 and 1.32) before the control plane") ||
		!strings.Contains(inc[0].Fix+inc[1].Fix, "v1.11.3-eksbuild.1") {
		t.Fatalf("add-on sequencing: %+v", inc)
	}
	// PDBs: ledger-pdb allows nothing by configuration and overlaps core-pdb
	// on live pods (a terminating one does not count).
	drain := findCheck(r, "pdb-blocks-drain")
	if len(drain) != 2 || !strings.Contains(drain[0].Detail+drain[1].Detail, "configuration") || !strings.Contains(drain[0].Detail+drain[1].Detail, "another PDB also selects (payments/ledger-1)") {
		t.Fatalf("drain: %+v", drain)
	}
	// Workload checks leave the platform namespaces out.
	for _, x := range findCheck(r, "single-replica") {
		if strings.Contains(x.Object, "kube-system") {
			t.Fatalf("system workloads are add-ons, not workloads: %+v", x)
		}
	}
	// Score: blockers cap it, and the add-on to verify makes it provisional.
	if r.Score == nil || *r.Score > 59 || r.Tier != "NOT READY" || len(r.Blockers) < 4 || !r.Provisional || len(r.Verify) != 1 || r.Verify[0].Name != "cert-manager" {
		t.Fatalf("score=%v tier=%s blockers=%v verify=%+v", r.Score, r.Tier, r.Blockers, r.Verify)
	}
	for _, b := range r.Breakdown {
		if b.Deducted > b.Max {
			t.Fatalf("area over its cap: %+v", b)
		}
	}
	// The plan: commands filled in, in order.
	var all []string
	for _, p := range r.Plan {
		all = append(all, p.Title)
		all = append(all, p.Commands...)
		all = append(all, p.Notes...)
	}
	plan := strings.Join(all, "\n")
	for _, want := range []string{
		"Resolve the blockers",
		"aws eks update-cluster-version --name payments-eks-qa --kubernetes-version 1.32 --region af-south-1 --profile nedctl.payments-qa.Platform-ReadOnly",
		"aws eks update-addon --cluster-name payments-eks-qa --addon-name vpc-cni --addon-version v1.19.0-eksbuild.1 --resolve-conflicts PRESERVE",
		"--addon-name kube-proxy --addon-version v1.32.0-eksbuild.2",
		"aws eks update-nodegroup-version --cluster-name payments-eks-qa --nodegroup-name legacy --kubernetes-version 1.32",
		"verify cert-manager v1.15.0 supports 1.32",
		"nedctl health --cluster payments-eks-qa",
	} {
		if !strings.Contains(plan, want) {
			t.Fatalf("plan lacks %q:\n%s", want, plan)
		}
	}
	if strings.Index(plan, "update-cluster-version") > strings.Index(plan, "update-addon") || strings.Index(plan, "update-addon") > strings.Index(plan, "update-nodegroup-version") {
		t.Fatalf("order: control plane, add-ons, nodes:\n%s", plan)
	}
}

func supportRates() support.Rates {
	return support.Rates{Currency: "USD", AWS: support.CloudRates{StandardHourly: 0.10, ExtendedHourly: 0.60}}
}

func TestUpgradeAssessmentLaterTargetsAndReadiness(t *testing.T) {
	f, _ := eksTestFacts(t)
	// 1.33: AL2 nodes become a breaking change; 1.29 kubelets a blocker.
	r := assessUpgrade(config.Config{}, f, upgradeCluster(), "1.33", time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC))
	if got := findCheck(r, "kubelet-skew"); got[0].Severity != "critical" || !got[0].Blocker {
		t.Fatalf("skew > 3: %+v", got)
	}
	if got := findCheck(r, "al2-nodes"); len(got) != 2 {
		t.Fatalf("AL2 at 1.33 is a breaking change and an AL2 finding: %+v", got)
	}
	if len(r.Path) != 2 || r.Path[1] != "1.33" {
		t.Fatalf("path: %v", r.Path)
	}
	// Beyond the tables: never a silent pass.
	r = assessUpgrade(config.Config{}, eksFacts{Cluster: "c", Version: "1.36", Region: "x", Profile: "p"}, upgradeCluster(), "1.37", time.Now())
	found := false
	for _, u := range r.Unassessed {
		found = found || strings.Contains(u, "1.37")
	}
	if !found {
		t.Fatalf("1.37 must be listed as not assessed: %v", r.Unassessed)
	}
	// A target EKS does not offer: no score.
	f.Versions = f.Versions[:1]
	r = assessUpgrade(config.Config{}, f, upgradeCluster(), "1.32", time.Now())
	if r.Score != nil || r.Tier != "NOT ASSESSED" {
		t.Fatalf("unavailable target: %v %s", r.Score, r.Tier)
	}
	// A clean cluster scores READY.
	clean := eksFacts{Cluster: "c", Version: "1.31", Status: "ACTIVE", Region: "r", Profile: "p", Versions: []eksVersionInfo{{Version: "1.31", StandardEnd: "2099-01-01"}, {Version: "1.32"}}}
	co := clusterOut{Outs: make([]probeOut, len(upgradeProbes(32)))}
	co.Outs[0].Out = []byte(`{"gitVersion":"v1.31.4"}`)
	r = assessUpgrade(config.Config{}, clean, co, "1.32", time.Now())
	if r.Score == nil || *r.Score != 100 || r.Tier != "READY" || r.Provisional {
		t.Fatalf("clean: %v %s %v %v", r.Score, r.Tier, r.Unassessed, r.Findings)
	}
}

func TestUpgradeCheckCommand(t *testing.T) {
	w := newEC2World(t, "dev", "")
	fakeUpgradeAWS(t)
	oldKube := upgradeKube
	upgradeKube = func(ctx context.Context, cfg config.Config, ref eksRef, probes []probe, stderr io.Writer) clusterOut {
		if ref.name != "payments-eks-qa" || ref.region != "af-south-1" || len(probes) != len(upgradeProbes(32)) {
			t.Errorf("ref %+v", ref)
		}
		return upgradeCluster()
	}
	t.Cleanup(func() { upgradeKube = oldKube })
	report := filepath.Join(t.TempDir(), "upgrade.md")
	code, out, errb := run("--config", w.cfg, "upgrade-check", "payments-eks-qa", "--report", report, "--fail-below", "80")
	if code != ExitFailure {
		t.Fatalf("below 80 with blockers fails: code=%d err=%q", code, errb)
	}
	for _, want := range []string{"payments-eks-qa", "1.31 → 1.32", "NOT READY", "Blockers:", "AREA", "Upgrade plan", "nedctl never runs these", "cert-manager", "SUPPORTED VERSIONS"} {
		if !strings.Contains(strings.ToLower(out), strings.ToLower(want)) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	md, err := os.ReadFile(report)
	if err != nil || !strings.Contains(string(md), "# EKS upgrade readiness: payments-eks-qa") || !strings.Contains(string(md), "## Upgrade plan") {
		t.Fatalf("report: %v\n%s", err, md)
	}
	if fi, _ := os.Stat(report); fi.Mode().Perm() != 0o600 {
		t.Fatalf("report mode %v", fi.Mode().Perm())
	}
	if code, _, _ := run("--config", w.cfg, "upgrade-check", "payments-eks-qa", "--report", report); code != ExitFailure {
		t.Fatal("never overwrites a report")
	}

	code, out, _ = run("--config", w.cfg, "upgrade-check", "payments-eks-qa", "-o", "json")
	var doc struct {
		Schema   string          `json:"schema"`
		Clusters []upgradeReport `json:"clusters"`
	}
	if code != ExitOK || json.Unmarshal([]byte(out), &doc) != nil || doc.Schema != findingsSchema || len(doc.Clusters) != 1 {
		t.Fatalf("json: code=%d %s", code, out)
	}
	c := doc.Clusters[0]
	if c.Facts == nil || c.Facts.Version != "1.31" || c.Target != "1.32" || len(c.Plan) == 0 || len(c.Findings) == 0 {
		t.Fatalf("json report: %+v", c)
	}
	if code, _, errb := run("--config", w.cfg, "upgrade-check", "--env", "qa"); code != ExitUsage || !strings.Contains(errb, "EKS for now") {
		t.Fatalf("AKS: code=%d %q", code, errb)
	}
}
