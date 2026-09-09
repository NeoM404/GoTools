# Ecosystem Tools — Install These, Don't Rebuild Them

`bankctl` deliberately only builds the **org-specific glue** (fleet inventory,
prod-context safety, cross-cloud kubeconfig) that no off-the-shelf tool
provides. For everything else, the community already has mature, battle-tested
tools. Install these instead of reinventing them.

`bankctl doctor` checks which of these are present on your machine.

## Must-have daily drivers

| Tool | What it does | Install (macOS) | Docs |
|---|---|---|---|
| **kubectl** | The Kubernetes CLI | `brew install kubectl` | kubernetes.io/docs/reference/kubectl |
| **kubectx / kubens** | Switch context / namespace fast | `brew install kubectx` | github.com/ahmetb/kubectx |
| **kubie** | Isolated per-shell contexts — safer than global switching when you juggle 80+ clusters | `brew install kubie` | github.com/sbstp/kubie |
| **k9s** | Full terminal UI for clusters (logs, exec, scaling, port-forward) | `brew install k9s` | k9scli.io |
| **stern** | Tail logs across many pods with colour | `brew install stern` | github.com/stern/stern |
| **kube-ps1** | Show current context/namespace in your shell prompt (colour prod red) | `brew install kube-ps1` | github.com/jonmosco/kube-ps1 |

## Fleet, GitOps & multi-cluster

| Tool | What it does | Install | Docs |
|---|---|---|---|
| **Argo CD CLI** (`argocd`) | Drive the GitOps fleet control plane | `brew install argocd` | argo-cd.readthedocs.io |
| **Helm** | Package manager / templating | `brew install helm` | helm.sh |
| **Headlamp** | Web UI for clusters (OIDC, extensible) — good self-service face for devs | `brew install --cask headlamp` | headlamp.dev |
| **Cyclonus / kubectl-tree / kubectl-neat** | Policy testing, ownership trees, cleaned manifests | `kubectl krew install neat tree` | krew.sigs.k8s.io |

## Upgrade & hygiene (run before every cluster upgrade)

| Tool | What it does | Install | Docs |
|---|---|---|---|
| **kubent** (kube-no-trouble) | Scans for deprecated/removed API usage before an upgrade | `sh -c "$(curl -sSfL https://git.io/install-kubent)"` | github.com/doitintl/kube-no-trouble |
| **pluto** | Detects deprecated APIs in manifests & Helm releases | `brew install FairwindsOps/tap/pluto` | github.com/FairwindsOps/pluto |
| **popeye** | Cluster resource sanitizer / misconfig scanner | `brew install derailed/popeye/popeye` | github.com/derailed/popeye |

## Security & supply chain

| Tool | What it does | Install | Docs |
|---|---|---|---|
| **Trivy** | Image, IaC, secret & SBOM scanner | `brew install trivy` | trivy.dev |
| **cosign** | Sign & verify container images (Sigstore) | `brew install cosign` | docs.sigstore.dev |
| **kubescape** | CIS / NSA / MITRE posture scanning | `brew install kubescape` | kubescape.io |
| **kube-bench** | CIS Kubernetes benchmark | `brew install kube-bench` | github.com/aquasecurity/kube-bench |

## Access (enterprise — see the platform strategy doc)

| Tool | What it does | Notes |
|---|---|---|
| **Teleport** (`tsh`) | Unified, audited, short-lived access to K8s/SSH/DBs with JIT approvals | Primary recommendation for banking; `tsh kube login` replaces static kubeconfigs |
| **kubelogin** | OIDC/Entra auth plugin for kubectl | Needed for AKS Entra-integrated clusters |
| **aws-cli / az-cli** | Cloud auth + `eks update-kubeconfig` / `aks get-credentials` | `bankctl kubeconfig` orchestrates these |

## Cost

| Tool | What it does | Install |
|---|---|---|
| **kubectl-cost** (OpenCost/Kubecost) | Per-namespace cost from the CLI | `kubectl krew install cost` |

---

### Why bankctl doesn't wrap all of these
Every tool you wrap is a tool you must keep compatible as it evolves. `bankctl`
wraps only `aws`/`az`/`kubectl` because it must (to turn an inventory entry
into working credentials) and does so via their stable, documented
subcommands. Prefer these upstream tools directly for everything else.
