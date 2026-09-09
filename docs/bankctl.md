# bankctl — Banking Kubernetes Fleet CLI

`bankctl` is the platform team's glue CLI over the **fleet inventory**: one
command to see every EKS/AKS cluster across the group, pull credentials for any
of them, check version drift, and stay out of production by accident. It builds
on the standard cloud CLIs rather than replacing them, and has **zero
third-party dependencies** — a deliberate supply-chain choice for a tool that
authenticates to production banking clusters.

For the tools `bankctl` does **not** replace (k9s, kubectx, stern, argocd, …),
see [ecosystem-tools.md](ecosystem-tools.md).

## Install

```bash
git clone git@github.com:NeoM404/GoTools.git
cd GoTools
make build           # produces bin/bankctl
# or install to $GOBIN / $GOPATH/bin:
make install
# cross-compile for the team (macOS + Linux, arm64 + amd64):
make cross           # outputs to dist/
```

Requires Go 1.23+ to build. The built binary needs `kubectl`, `aws`, and `az`
on PATH for the subcommands that use them — run `bankctl doctor` to check.

## First run

```bash
bankctl init                 # writes ~/.config/bankctl/config.json
# edit it: set "inventoryPath" or "inventoryUrl"
bankctl doctor               # check the CLIs bankctl needs
bankctl clusters list
```

`init` never overwrites an existing config unless you pass `--force`; use
`--path` to write elsewhere.

## Configuration

`bankctl` reads a JSON config, resolved in this order:

1. `--config PATH`
2. `$BANKCTL_CONFIG`
3. `~/.config/bankctl/config.json` (respects `$XDG_CONFIG_HOME`)
4. `./bankctl.json`

If none is found, defaults are used (so `doctor`, `help`, `version` always
work). Example — copy [`configs/bankctl.example.json`](../configs/bankctl.example.json):

```json
{
  "inventoryPath": "fleet.example.json",
  "inventoryUrl": "",
  "prodPatterns": ["(?i)prod", "(?i)-prd-"],
  "kubeconfigDir": "",
  "targetKubeVersion": "1.30"
}
```

| Field | Meaning |
|---|---|
| `inventoryPath` | Local JSON fleet file. Relative paths resolve against the **config file's** directory. |
| `inventoryUrl` | HTTPS endpoint returning the same JSON (preferred in prod so everyone sees the same live fleet). HTTP is refused. |
| `prodPatterns` | Regexes; a context/cluster name matching any is treated as production by `guard`. |
| `kubeconfigDir` | If set, `kubeconfig`/`login` write per-cluster files here instead of the default kubeconfig. |
| `targetKubeVersion` | Fleet's desired minor version; drives `fleet versions`. |
| `minVersions` | Map of tool→minimum version overriding `doctor`'s built-in floors, e.g. `{"kubectl":"1.29","aws":"2.15"}`. |

### The fleet inventory

The inventory is the org-specific asset. Generate it from your IaC — e.g.
`terraform output -json fleet` — and publish it to the `inventoryUrl`. Schema
(see [`configs/fleet.example.json`](../configs/fleet.example.json)):

```json
{
  "clusters": [
    { "name": "eks-payments-prod-euw1", "cloud": "aws", "environment": "prod",
      "region": "eu-west-1", "version": "1.30", "owner": "payments-platform",
      "costCentre": "CC-1001", "account": "111111111111" },
    { "name": "aks-core-prod-weu", "cloud": "azure", "environment": "prod",
      "region": "westeurope", "version": "1.30", "owner": "core-platform",
      "costCentre": "CC-3003", "subscription": "sub-core-prod",
      "resourceGroup": "rg-aks-core-prod" }
  ]
}
```

## Commands

### `bankctl init [--path PATH] [--force]`
Scaffold a starter config so you don't hand-write JSON. See **First run** above.

### `bankctl clusters list [--cloud aws|azure] [--env ENV] [--owner NAME] [-o table|json]`
Tabular (or JSON) view of the fleet with optional filters (`--owner` is a
substring match). `-o json` emits an array — pipe it to `jq`.
```bash
bankctl clusters list --cloud aws --env prod
bankctl clusters list --cloud azure -o json | jq -r '.[].name'
```

### `bankctl clusters get <name> [-o table|json]`
Full detail for one cluster (cloud-specific fields included).
```bash
bankctl clusters get eks-payments-prod-euw1
bankctl clusters get eks-payments-prod-euw1 -o json | jq '{name,account}'
```

### `bankctl kubeconfig <cluster> [--file PATH] [--dry-run]`
Fetches credentials by shelling out to the right cloud CLI
(`aws eks update-kubeconfig` or `az aks get-credentials`). Flags may go before
or after the cluster name.
```bash
bankctl kubeconfig eks-payments-nonprod-euw1
bankctl kubeconfig aks-core-prod-weu --file ~/.kube/aks-core-prod   # isolated
bankctl kubeconfig aks-core-prod-weu --dry-run                      # print, don't run
```
`--file` (or `kubeconfigDir` in config) writes an **isolated** kubeconfig,
which is much safer than merging 80 clusters into one file.

**CLI-drift warning.** After writing credentials, `bankctl` inspects the
kubeconfig's exec auth-plugin `apiVersion`. If an old `aws`/`az` CLI stamped a
removed version (`client.authentication.k8s.io/v1alpha1`, dropped in Kubernetes
1.24), it prints a stderr warning telling you to update that CLI and run
`bankctl doctor`. If the cloud CLI call itself fails, the error is followed by
the same `bankctl doctor` hint. Both go to stderr, so `-o json` and scripts are
unaffected.

### `bankctl login <cluster> [--file PATH] [--dry-run]`
`kubeconfig` plus a loud warning if the target is production.
```bash
bankctl login eks-payments-prod-euw1
# ⚠  "eks-payments-prod-euw1" is a PRODUCTION cluster. Changes require a change record.
```

### `bankctl fleet versions [--fail-on-stale] [-o table|json]`
Version-drift report against `targetKubeVersion`. Status is `current`, `n-1`
(one minor behind — allowed), or `STALE` (two or more behind). `--fail-on-stale`
exits 1 if any cluster is STALE — drop it into a scheduled pipeline as a fleet
hygiene gate. `--fail-on-stale` and `-o json` compose (JSON is still emitted).
```bash
bankctl fleet versions
bankctl fleet versions --fail-on-stale                        # CI gate
bankctl fleet versions -o json | jq -r '.[]|select(.status=="STALE").name'
```

### `bankctl guard [--block]`
Checks the **current** kube-context against `prodPatterns`. Prints `ok <ctx>` or
`PROD <ctx>`. With `--block` it exits **3** on production — ideal for a shell
prompt or a pre-apply hook.
```bash
bankctl guard              # ok    eks-payments-nonprod-euw1
bankctl guard --block || echo "refusing destructive op in prod"
```

### `bankctl current`
Shows the current context and whether it's production.

### `bankctl doctor [--strict]`
Checks required (`kubectl`, `aws`, `az`) and optional ecosystem tools for
**presence and version**. It probes each tool with a floor (`kubectl`, `aws`,
`az`, `helm` by default), parses the version, and flags anything below its
floor as `OUTDATED`. Floors are overridable per tool via `minVersions` in
config.

Exit policy:
- a **missing required** tool → exit 1
- an **outdated required** tool → exit 1 (bankctl's own commands may misbehave)
- `--strict` escalates **any** outdated tool (including optional ones) to exit
  1 — use it as a CI hygiene gate on your build agents so a stale `kubectl`/
  `aws`/`az` fails the pipeline.

```bash
bankctl doctor            # local check with install/upgrade hints
bankctl doctor --strict   # CI: fail if any floored tool is behind
```

This is how the tool answers "are our CLIs current?" — see also the
kubeconfig drift warning under `kubeconfig` above.

### `bankctl version` / `bankctl help`

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | runtime error (inventory/config/cloud CLI failure) or `--fail-on-stale` triggered |
| 2 | usage error (bad flags/args) |
| 3 | `guard --block` found a production context |

## Recipes

**Refuse a destructive kubectl in prod** — add to a wrapper or Makefile:
```bash
bankctl guard --block || { echo "In prod — aborting."; exit 1; }
kubectl delete ...
```

**Shell prompt safety** (zsh) — show a red PROD marker:
```bash
precmd() { bankctl guard 2>/dev/null | grep -q '^PROD' && PROD=' %F{red}[PROD]%f' || PROD=''; }
setopt prompt_subst; PROMPT='%~$PROD %# '
```

**Nightly fleet drift check** (Azure DevOps / cron):
```bash
bankctl --config /etc/bankctl/config.json fleet versions --fail-on-stale
```

**Onboard to a cluster from scratch**:
```bash
bankctl clusters list --owner my-team     # find it
bankctl login eks-myteam-nonprod-euw1     # creds + prod check
kubectl get pods -A                       # you're in
```

## Design notes

- **Zero third-party deps** — stdlib only; smaller attack surface, reproducible
  builds, nothing to `pip`/`npm`/`go get` from the internet at build time.
- **Doesn't reinvent** — orchestrates `aws`/`az`/`kubectl` via their stable
  subcommands; for anything else it points you at the right upstream tool.
- **Fail safe** — HTTPS-only inventory, over-warns rather than under-warns on
  prod detection, invalid prod regexes are skipped (never make prod look safe).
- **Testable** — command dispatch takes injected stdout/stderr; core logic
  (drift classification, filters, prod detection, flag parsing) is unit-tested.

## Extending

Add a subcommand by wiring a `case` in `internal/app/app.go` and a handler in
`internal/app/commands.go`. Keep cloud-specific shelling in `internal/cloud`,
inventory logic in `internal/inventory`, and add a unit test. Run
`make vet test build` before committing.
