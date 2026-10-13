package app

import (
	"strconv"
	"strings"
)

// The tables upgrade-check judges by. They hold what Kubernetes and AWS
// have published (as of October 2026) and nothing that goes stale silently:
// a target beyond what they cover is reported as "not assessed — check the
// release notes", never as a pass. EKS Upgrade Insights, read live from
// AWS, cover what the tables cannot.

// rulesCoverTo is the highest Kubernetes minor the tables below know.
const rulesCoverTo = 36

// minorOf is the minor version of "1.31", "v1.31.4-eks-abc" or "1.31.2" (0
// if none).
func minorOf(v string) int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 || parts[0] != "1" {
		return 0
	}
	digits := parts[1]
	for i, c := range digits {
		if c < '0' || c > '9' {
			digits = digits[:i]
			break
		}
	}
	n, _ := strconv.Atoi(digits)
	return n
}

func nextMinor(v string) string {
	if m := minorOf(v); m > 0 {
		return "1." + strconv.Itoa(m+1)
	}
	return ""
}

// buildVersion is major.minor.patch plus an EKS build ("v1.18.3-eksbuild.2").
type buildVersion [4]int

func parseBuildVersion(v string) (buildVersion, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	var s buildVersion
	main, build, _ := strings.Cut(v, "-")
	parts := strings.Split(main, ".")
	if len(parts) < 2 {
		return s, false
	}
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return s, false
		}
		s[i] = n
	}
	if _, b, ok := strings.Cut(build, "eksbuild."); ok {
		s[3], _ = strconv.Atoi(b)
	}
	return s, true
}

func (a buildVersion) less(b buildVersion) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// removedAPI is a group/version a kind stops being served in.
type removedAPI struct {
	GroupVersion, Kind string
	RemovedIn          int // minor
	Replacement        string
}

// removedAPIs: the Kubernetes deprecated API migration guide, through 1.36.
// No API was removed in 1.33–1.36; EKS Upgrade Insights report what is
// removed later from the cluster's own audit log.
var removedAPIs = []removedAPI{
	{"extensions/v1beta1", "Ingress", 22, "networking.k8s.io/v1"},
	{"networking.k8s.io/v1beta1", "Ingress", 22, "networking.k8s.io/v1"},
	{"networking.k8s.io/v1beta1", "IngressClass", 22, "networking.k8s.io/v1"},
	{"rbac.authorization.k8s.io/v1beta1", "*", 22, "rbac.authorization.k8s.io/v1"},
	{"admissionregistration.k8s.io/v1beta1", "*", 22, "admissionregistration.k8s.io/v1"},
	{"apiextensions.k8s.io/v1beta1", "CustomResourceDefinition", 22, "apiextensions.k8s.io/v1"},
	{"apiregistration.k8s.io/v1beta1", "APIService", 22, "apiregistration.k8s.io/v1"},
	{"certificates.k8s.io/v1beta1", "CertificateSigningRequest", 22, "certificates.k8s.io/v1"},
	{"coordination.k8s.io/v1beta1", "Lease", 22, "coordination.k8s.io/v1"},
	{"scheduling.k8s.io/v1beta1", "PriorityClass", 22, "scheduling.k8s.io/v1"},
	{"storage.k8s.io/v1beta1", "CSIDriver", 22, "storage.k8s.io/v1"},
	{"storage.k8s.io/v1beta1", "CSINode", 22, "storage.k8s.io/v1"},
	{"storage.k8s.io/v1beta1", "StorageClass", 22, "storage.k8s.io/v1"},
	{"storage.k8s.io/v1beta1", "VolumeAttachment", 22, "storage.k8s.io/v1"},
	{"batch/v1beta1", "CronJob", 25, "batch/v1"},
	{"discovery.k8s.io/v1beta1", "EndpointSlice", 25, "discovery.k8s.io/v1"},
	{"events.k8s.io/v1beta1", "Event", 25, "events.k8s.io/v1"},
	{"autoscaling/v2beta1", "HorizontalPodAutoscaler", 25, "autoscaling/v2"},
	{"policy/v1beta1", "PodDisruptionBudget", 25, "policy/v1"},
	{"policy/v1beta1", "PodSecurityPolicy", 25, "Pod Security Admission"},
	{"node.k8s.io/v1beta1", "RuntimeClass", 25, "node.k8s.io/v1"},
	{"autoscaling/v2beta2", "HorizontalPodAutoscaler", 26, "autoscaling/v2"},
	{"flowcontrol.apiserver.k8s.io/v1beta1", "*", 26, "flowcontrol.apiserver.k8s.io/v1"},
	{"storage.k8s.io/v1beta1", "CSIStorageCapacity", 27, "storage.k8s.io/v1"},
	{"flowcontrol.apiserver.k8s.io/v1beta2", "*", 29, "flowcontrol.apiserver.k8s.io/v1"},
	{"flowcontrol.apiserver.k8s.io/v1beta3", "*", 32, "flowcontrol.apiserver.k8s.io/v1"},
}

func removedFor(groupVersion, kind string) (removedAPI, bool) {
	for _, r := range removedAPIs {
		if r.GroupVersion == groupVersion && (r.Kind == "*" || r.Kind == kind) {
			return r, true
		}
	}
	return removedAPI{}, false
}

// systemWriter reports managedFields writers that are the control plane's
// own (never a manifest a team must change).
func systemWriter(manager string) bool {
	return strings.HasPrefix(manager, "api-priority-and-fairness-config-") || manager == "eks" || manager == "eks-internal" ||
		manager == "kube-apiserver" || manager == "kube-controller-manager"
}

// karpenterMinimum is the oldest Karpenter supporting each Kubernetes minor
// (karpenter.sh/docs/upgrading/compatibility).
var karpenterMinimum = map[int]string{30: "0.37.0", 31: "1.0.5", 32: "1.2.0", 33: "1.5.0", 34: "1.6.0", 35: "1.9.0", 36: "1.13.0"}

// criticalAddons break the cluster when incompatible: a hard blocker.
var criticalAddons = map[string]bool{"vpc-cni": true, "coredns": true, "kube-proxy": true, "aws-ebs-csi-driver": true}

// ossAddon identifies an add-on someone installed (not an EKS add-on) and
// where its project says which Kubernetes versions it supports. nedctl
// does not judge compatibility from memory: it lists each one with the
// page to verify (an agent can fetch it), and flags the few rules that are
// certain.
type ossAddon struct {
	Name     string
	Images   []string // substrings of the image repository
	URL      string
	Critical bool   // a cluster CNI
	Note     string // a known rule, reported as a finding
}

var ossAddons = []ossAddon{
	{Name: "karpenter", Images: []string{"karpenter/controller"}, URL: "https://karpenter.sh/docs/upgrading/compatibility/"},
	{Name: "ingress-nginx", Images: []string{"ingress-nginx/controller", "nginx-ingress-controller"}, URL: "https://github.com/kubernetes/ingress-nginx#supported-versions-table",
		Note: "retired in March 2026: no more releases or security fixes — migrate to the AWS Load Balancer Controller or a Gateway API implementation"},
	{Name: "cluster-autoscaler", Images: []string{"autoscaling/cluster-autoscaler"}, URL: "https://github.com/kubernetes/autoscaler/tree/master/cluster-autoscaler#releases"},
	{Name: "istio", Images: []string{"istio/pilot", "istio/proxyv2"}, URL: "https://istio.io/latest/docs/releases/supported-releases/"},
	{Name: "kiali", Images: []string{"kiali/kiali"}, URL: "https://kiali.io/docs/installation/installation-guide/prerequisites/"},
	{Name: "cert-manager", Images: []string{"jetstack/cert-manager-controller"}, URL: "https://cert-manager.io/docs/releases/"},
	{Name: "aws-load-balancer-controller", Images: []string{"aws-load-balancer-controller"}, URL: "https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/deploy/installation/"},
	{Name: "external-dns", Images: []string{"external-dns/external-dns", "/external-dns:"}, URL: "https://github.com/kubernetes-sigs/external-dns#kubernetes-version-compatibility"},
	{Name: "metrics-server", Images: []string{"metrics-server/metrics-server"}, URL: "https://github.com/kubernetes-sigs/metrics-server#compatibility-matrix"},
	{Name: "argocd", Images: []string{"argoproj/argocd"}, URL: "https://argo-cd.readthedocs.io/en/stable/operator-manual/tested-kubernetes-versions/"},
	{Name: "flux", Images: []string{"fluxcd/"}, URL: "https://fluxcd.io/flux/installation/#prerequisites"},
	{Name: "kube-prometheus-stack", Images: []string{"prometheus-operator/prometheus-operator"}, URL: "https://github.com/prometheus-operator/kube-prometheus#compatibility"},
	{Name: "kyverno", Images: []string{"kyverno/kyverno"}, URL: "https://kyverno.io/docs/installation/#compatibility-matrix"},
	{Name: "gatekeeper", Images: []string{"openpolicyagent/gatekeeper"}, URL: "https://open-policy-agent.github.io/gatekeeper/website/docs/install/"},
	{Name: "external-secrets", Images: []string{"external-secrets/external-secrets"}, URL: "https://external-secrets.io/latest/introduction/stability-support/"},
	{Name: "keda", Images: []string{"kedacore/keda"}, URL: "https://keda.sh/docs/latest/operate/cluster/#kubernetes-compatibility"},
	{Name: "velero", Images: []string{"velero/velero"}, URL: "https://github.com/vmware-tanzu/velero#velero-compatibility-matrix"},
	{Name: "secrets-store-csi-driver", Images: []string{"csi-secrets-store/driver"}, URL: "https://secrets-store-csi-driver.sigs.k8s.io/"},
	{Name: "trivy-operator", Images: []string{"aquasecurity/trivy-operator"}, URL: "https://aquasecurity.github.io/trivy-operator/latest/"},
	{Name: "prisma-cloud-defender", Images: []string{"twistlock/", "prismacloud"}, URL: "https://docs.prismacloud.io/en/compute-edition/32/admin-guide/install/system-requirements"},
	{Name: "calico", Images: []string{"calico/node"}, URL: "https://docs.tigera.io/calico/latest/getting-started/kubernetes/requirements", Critical: true},
	{Name: "cilium", Images: []string{"cilium/cilium"}, URL: "https://docs.cilium.io/en/stable/network/kubernetes/compatibility/", Critical: true},
}

func ossAddonFor(image string) (ossAddon, bool) {
	for _, a := range ossAddons {
		for _, s := range a.Images {
			if strings.Contains(image, s) {
				return a, true
			}
		}
	}
	return ossAddon{}, false
}

// upgradeSystemNamespaces are left out of the workload checks: platform
// components, judged as add-ons instead.
var upgradeSystemNamespaces = map[string]bool{"kube-system": true, "kube-public": true, "kube-node-lease": true, "karpenter": true,
	"amazon-cloudwatch": true, "amazon-guardduty": true, "aws-observability": true}
