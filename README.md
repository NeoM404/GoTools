# GoTools

Go CLIs for a multi-cloud Kubernetes platform team at a bank. The philosophy:
**build only the org-specific glue; document and install everything else.** The
community already has excellent tools (k9s, kubectx, stern, argocd…) — GoTools
doesn't reinvent them, it fills the gaps they don't cover.

Everything here builds from the **Go standard library with zero third-party
dependencies** — a deliberate supply-chain decision for tooling that
authenticates to production banking clusters.

## Tools

| Tool | Status | What it does |
|---|---|---|
| **[bankctl](docs/bankctl.md)** | built | Fleet CLI: list every EKS/AKS cluster across the group; reconcile the inventory against the clouds (shadow, missing, drifted clusters); pull credentials — identity-verified, change-record-gated, and recorded in a tamper-evident audit trail; report version drift, support lifecycle and extended-support cost; guard against accidental production access; and produce quarterly access evidence for auditors. |
| **AWS access** (`bankctl aws`, `shell`, `connect`, `eks`) | built | Sign in with IAM Identity Center and pick one account and role; Session Manager shells and private-EKS tunnels as your own identity, coloured by environment; break-glass for named admins; works alongside `sm`/SSMshell; access-entries reporting. No pasted keys, every access recorded — [aws.md](docs/aws.md), [security.md](docs/security.md). |
| **kubeconfig sweeper** (`bankctl sweep`) | built | Prune stale EKS/AKS contexts from `~/.kube/config` using the inventory — dry run by default, backup first, removes only what it can prove stale. |
| _namespace-lint_ | 🔜 planned | Check a namespace request against the platform tenancy standard before it becomes a PR. |

New tools are added as separate `cmd/<tool>` binaries in this one module.

## Quick start

```bash
git clone git@github.com:NeoM404/GoTools.git
cd GoTools
make build                     # -> bin/bankctl
./bin/bankctl doctor           # check your ecosystem tools
./bin/bankctl --config configs/bankctl.example.json clusters list
```

### Bastions and Azure DevOps

On jump hosts whose kubeconfig the platform provisions (no `az`/`aws`, no
internet), run bankctl in **bastion mode** (`bankctl init --mode bastion`):
`login` switches to the cluster's existing context with change control and an
audit record, and `guard` classifies contexts by everything the kubeconfig
carries. Cloud discovery moves to a nightly Azure DevOps pipeline that
reconciles the reviewed inventory against Azure — see
**[docs/azure-devops.md](docs/azure-devops.md)**.

## Layout

```
cmd/bankctl/        main entrypoint (thin)
internal/app/       command dispatch + handlers (testable, injected I/O)
internal/execx/     bounded, cancellable subprocess execution (every CLI call)
internal/awssso/    IAM Identity Center assignments + the managed AWS CLI profiles
internal/picker/    type-to-filter terminal picker (no raw mode, no dependencies)
internal/discovery/ enumerates real EKS/AKS clusters in the configured scope
internal/reconcile/ declared-vs-observed diff and the proposed inventory (pure)
internal/support/   support lifecycle + extended-support cost (pure)
internal/audit/     hash-chained, locked audit log + SIEM forwarding
internal/change/    change-record verification (ServiceNow)
internal/evidence/  auditor evidence packs from verified audit logs (pure)
internal/inventory/ fleet model, validation, JSON/HTTPS loading, version-drift logic
internal/cloud/     aws/az CLI orchestration + identity verification
internal/kube/      context resolution, production detection, kubeconfig sweep
internal/config/    config resolution & loading
internal/tools/     `doctor` ecosystem-tool catalog
configs/            example configs + fleet inventories (workstation and bastion)
inventory/          the declared inventory + pipeline config, reconciled nightly
.azure-pipelines/   Azure DevOps CI and inventory-reconciliation pipelines
deploy/terraform/   EKS access entries per Identity Center role
scripts/            e2e-smoke.sh — the built binary's exit-code contract
docs/               bankctl.md (full usage) · ecosystem-tools.md (what to install instead)
```

## Development

```bash
make tools               # install the pinned staticcheck + govulncheck
make ci                  # everything CI gates on: fmt, vet, deps, lint, race tests, e2e, vulns
make e2e                 # end-to-end regression: engineer journey + binary smoke test
make build               # static, reproducible bin/bankctl
make checksums           # cross-compile macOS/Linux arm64+amd64 into dist/ + SHA256SUMS
make repro               # prove the build is byte-for-byte reproducible
```

Requires Go 1.26+. See **[docs/bankctl.md](docs/bankctl.md)** for full command
reference, recipes (shell-prompt prod guard, nightly drift gate), and the
extension guide, and **[docs/ecosystem-tools.md](docs/ecosystem-tools.md)** for
the curated list of upstream tools to install rather than rebuild.
