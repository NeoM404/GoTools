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
| **[bankctl](docs/bankctl.md)** | built | Fleet inventory CLI: list every EKS/AKS cluster across the group, pull credentials for any of them, report version drift, and guard against accidental production access. |
| _kubeconfig-sweeper_ | 🔜 planned | Prune stale contexts from `~/.kube/config` using the live inventory. |
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

## Layout

```
cmd/bankctl/        main entrypoint (thin)
internal/app/       command dispatch + handlers (testable, injected I/O)
internal/inventory/ fleet model, JSON/HTTPS loading, version-drift logic
internal/cloud/     aws/az CLI orchestration for kubeconfig
internal/kube/      current-context + production detection
internal/config/    config resolution & loading
internal/tools/     `doctor` ecosystem-tool catalog
configs/            example config + example fleet inventory
docs/               bankctl.md (full usage) · ecosystem-tools.md (what to install instead)
```

## Development

```bash
make vet test build      # what CI runs
make fmt                 # gofmt
make cross               # build macOS/Linux arm64+amd64 into dist/
```

Requires Go 1.23+. See **[docs/bankctl.md](docs/bankctl.md)** for full command
reference, recipes (shell-prompt prod guard, nightly drift gate), and the
extension guide, and **[docs/ecosystem-tools.md](docs/ecosystem-tools.md)** for
the curated list of upstream tools to install rather than rebuild.
