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

Requires Go 1.26+ (the oldest supported Go release) to build. The built binary needs `kubectl`, `aws`, and `az`
on PATH for the subcommands that use them — run `bankctl doctor` to check. On a
bastion (`"mode": "bastion"`) it needs only `kubectl`.

## First run

```bash
bankctl init                 # writes ~/.config/bankctl/config.json
# edit it: set "inventoryPath" or "inventoryUrl"
bankctl doctor               # check the CLIs bankctl needs
bankctl clusters list
```

`init` never overwrites an existing config unless you pass `--force`; use
`--path` to write elsewhere, and `--mode bastion` on a jump host (see
[Bastion mode](#bastion-mode)). The starter config uses the `dev`/`ete`/`qa`/`prod`
environments and treats `qa` and `prod` as production.

## Bastion mode

On a bastion the platform has already provisioned the kubeconfig, and there may
be no `az`/`aws` CLI and no internet. With `"mode": "bastion"`:

- `login <cluster>` finds the cluster's existing context (by context name,
  kubeconfig cluster entry, or the `clusterUser_<rg>_<name>` user az writes) and
  switches to it, after change control and with an audit record. If a cluster
  has several contexts (e.g. user and admin), choose with `--context NAME`.
  `--dry-run` prints the `kubectl config use-context` it would run.
- `kubeconfig` is refused (nothing is fetched on a bastion); so are
  `inventory diff`/`sync` — discovery runs in the inventory pipeline instead.
- `doctor` requires only `kubectl`.
- The audit record's principal is the kubeconfig user. When that is a shared
  AKS local account (a static `clusterUser_…` credential, or `clusterAdmin_…`),
  the record says so: the cluster's own audit log cannot tell operators apart.

How the inventory reaches bastions, and the Azure DevOps pipelines that build
and reconcile it, are in [azure-devops.md](azure-devops.md).

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
| `mode` | `"workstation"` (default: credentials fetched through `aws`/`az`) or `"bastion"` (credentials provisioned on the host) — see [Bastion mode](#bastion-mode). |
| `inventoryPath` | Local JSON fleet file. Relative paths resolve against the **config file's** directory. |
| `inventoryUrl` | HTTPS endpoint returning the same JSON (preferred in prod so everyone sees the same live fleet). HTTP is refused. |
| `prodPatterns` | Regexes; a context/cluster name matching any is treated as production by `guard`. |
| `prodEnvironments` | Inventory environments treated as production (default `["prod"]`). A context that resolves to a cluster in one of these is production whatever its name. Must be on the `environments` allow-list when one is set. |
| `inventoryCacheTTL` | How long `guard`/`current` reuse a cached copy of `inventoryUrl` (default `"10m"`), so a shell prompt never waits on the network. |
| `kubeconfigDir` | If set, `kubeconfig`/`login` write per-cluster files here instead of the default kubeconfig. |
| `targetKubeVersion` | Fleet's desired minor version; drives `fleet versions`. |
| `targetKubeVersions` | Per-environment targets, e.g. `{"prod": "1.29", "uat": "1.30"}` — prod deliberately lags. Unlisted environments use `targetKubeVersion`. |
| `supportCalendar` | End of standard/extended support per minor version, per cloud — drives `fleet eol`. See [Support lifecycle](#support-lifecycle). |
| `costRates` | Control-plane hourly prices used to estimate the extended-support premium. Optional. |
| `audit` | Where the credential-access audit trail goes — see [Audit trail](#audit-trail). Always on. |
| `changeControl` | Which environments need a change record for credentials, and how it is verified — see [Change control](#change-control). |
| `minVersions` | Map of tool→minimum version overriding `doctor`'s built-in floors, e.g. `{"kubectl":"1.29","aws":"2.15"}`. |
| `commandTimeout` | Deadline for each cloud CLI call (`aws`/`az`) as a Go duration, e.g. `"90s"`. Default `"2m"`. An invalid value is a config error, not silently ignored. |
| `environments` | Optional allow-list for every cluster's `environment`, e.g. `["dev","ete","qa","prod"]`. A typo such as `prd` then fails at load time instead of quietly dodging production checks. |
| `discovery` | The cloud scope `inventory diff` / `inventory sync` scan — see [Discovery](#discovery). |
| `aws` | IAM Identity Center sign-in and the EC2/EKS access commands (`aws`, `shell`, `connect`, `eks`) — see [aws.md](aws.md). |
| `environmentColors` | `#rrggbb` per environment for pickers, terminal tabs and the prompt. Default: dev green, ete orange, qa blue, prod red. |

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

**Validation.** Every command validates the inventory before acting on it and
reports *every* problem at once. These are hard errors:

| Rule | Why |
|---|---|
| Names are unique (case-insensitive) | Commands address clusters by name; a duplicate could hand you credentials for the wrong cluster — e.g. a prod cluster sharing a dev cluster's name. |
| `cloud` is `aws` or `azure` | An unknown cloud cannot be acted on or verified. |
| AWS clusters have `account` (12 digits) and `region` | Without the full identity the CLI acts in whichever account is active, and discovery cannot prove the cluster exists. |
| Azure clusters have `subscription` and `resourceGroup` | As above, for subscriptions. |
| `version`, when set, parses (`1.30`, `v1.30.4`) | Drift reports would otherwise silently say `unknown`. |
| `environment` is on the `environments` allow-list, when one is configured | Catches `prd`, `Prod ` and friends. |

Inventories are capped at 32 MiB (a fleet of thousands of clusters is well
under 1 MiB), so a wrong URL cannot exhaust memory.

### Change control

Credential fetches, bastion logins, `shell` and `connect` can require a change
record, verified against ServiceNow before anything reaches the cloud.
`"enabled": false` switches change control off without removing its settings:
no record is required, one that is given is still format-checked and recorded,
and the command says change control is off.

```json
"changeControl": {
  "requireFor": ["prod"],
  "pattern": "^CHG\\d{7}$",
  "serviceNow": {
    "instanceUrl": "https://bank.service-now.com",
    "tokenEnv": "BANKCTL_SNOW_TOKEN",
    "allowedStates": ["Scheduled", "Implement"],
    "timeout": "10s"
  }
}
```

```bash
bankctl login eks-payments-prod-euw1 --change-record CHG0012345
# change record CHG0012345 verified: Rotate ingress certificates — Implement, window until 2026-09-29 18:00:00 UTC
```

A change record permits access only if it **exists, is approved, is in an
allowed state, and now is inside its planned window** (start inclusive, end
exclusive). It is looked up through the Table API with
`sysparm_display_value=all`, so dates are read in ServiceNow's fixed UTC
format, independent of the API user's locale.

| Field | Meaning |
|---|---|
| `requireFor` | Environments whose clusters need `--change-record` (or `--break-glass`). Empty = never required; a record given anyway is still verified and recorded. Must be on the `environments` allow-list. |
| `pattern` | Change-number format, checked before any network call (default `^CHG\d{7}$`). |
| `serviceNow.instanceUrl` | HTTPS base URL of the instance. Without it, records are format-checked only — and the output says so. |
| `serviceNow.tokenEnv` | Environment variable holding the API token — never stored in config. |
| `serviceNow.allowedStates` | States (label or numeric value) in which work may proceed. Default `Scheduled`, `Implement`. |

**Fail closed.** If a required record cannot be verified — ServiceNow
unreachable, token missing — access is refused.

**Break-glass.** For incidents that cannot wait for a change system,
`--break-glass "<reason>"` grants access without a record. The reason must be
at least 20 characters; a banner is printed; and the access is flagged
(`breakGlass`, with the reason) in the audit trail from its first event, for
review. Refused attempts are recorded too.

### Audit trail

Every credential fetch (`kubeconfig`, `login`) and every `sweep --apply` is
recorded — who (OS user, host, and the **cloud principal** that acted), which
cluster, account/subscription and environment, whether it is production, and
the outcome (`success`, `failure`, or `refused`, e.g. wrong account).

- **Recorded before it happens.** A `start` event is written *before* the
  cloud CLI runs; if it cannot be written, the fetch does not happen. The `end`
  event carries the outcome (and is written even if you press Ctrl-C). A
  `start` with no `end` means the process was killed mid-access.
- **Tamper-evident.** The log is JSON Lines, one event per line, each carrying
  the previous event's hash. Editing, removing or reordering past events breaks
  the chain. Appends take an exclusive file lock, so concurrent runs cannot
  fork it; writes are fsynced; the file is 0600.
- **Forwarded to your SIEM**, optionally, as each event is written, so the
  record does not depend on the laptop. Delivery is best-effort: the local log
  is authoritative and a SIEM outage never blocks access (it is reported).

```json
"audit": {
  "logPath": "",
  "forward": {
    "url": "https://splunk.bank.example:8088/services/collector/event",
    "tokenEnv": "BANKCTL_AUDIT_TOKEN",
    "scheme": "Splunk",
    "format": "splunk-hec",
    "timeout": "5s"
  }
}
```

| Field | Meaning |
|---|---|
| `logPath` | Local log. Default `$XDG_STATE_HOME/bankctl/audit.jsonl` (`~/.local/state/bankctl/audit.jsonl`). |
| `forward.url` | HTTPS collector (HTTP refused, and redirects to HTTP refused). |
| `forward.tokenEnv` | Name of the environment variable holding the collector token — **the token is never stored in config**. |
| `forward.scheme` | `Authorization` scheme: `Bearer` (default) or `Splunk` for HEC. |
| `forward.format` | `json` (the event as-is) or `splunk-hec` (HEC envelope, `sourcetype` `bankctl:audit`). |

Limits, stated plainly: someone who controls the file can rewrite the whole
chain, and deleting the most recent events leaves a valid shorter chain. The
chain proves internal consistency; forwarding is what makes the record
independent. And like `guard`, this runs on the operator's machine — it records
intent and attribution for accesses made **through bankctl**; the cloud's own
audit logs (CloudTrail, Azure Activity Log) and the API server audit log remain
the authoritative record of what reached the cluster.

### Support lifecycle

`fleet eol` reads the lifecycle and (optionally) prices from config:

```json
"supportCalendar": {
  "aws":   { "1.30": { "standardEnd": "2026-07-23", "extendedEnd": "2027-07-23" } },
  "azure": { "1.30": { "standardEnd": "2026-07-31" } }
},
"costRates": {
  "currency": "USD",
  "aws":   { "standardHourly": 0.10, "extendedHourly": 0.60 },
  "azure": { "standardHourly": 0.10, "extendedHourly": 0.60 }
}
```
*(Illustrative values — generate AWS dates with `fleet calendar aws`, take
Azure dates from the AKS release calendar, and set prices from your own
agreement: list prices change and negotiated discounts differ.)* Dates are
calendar days in UTC; each end date is the **first day of the next phase**. An
empty `extendedEnd` means no extended support is offered. The premium is
`(extendedHourly − standardHourly) × 730` per cluster per month. Calendars are
validated: versions must be minors, dates `YYYY-MM-DD`, and each `extendedEnd`
after its `standardEnd`.

### Discovery

`inventory diff` and `inventory sync` scan an **explicit** scope. bankctl never
guesses which accounts or subscriptions exist, so the scope is reviewable and
every completeness claim is made only for it:

```json
"discovery": {
  "aws": [
    { "profile": "payments-prod", "account": "111111111111", "regions": ["eu-west-1", "eu-central-1"] },
    { "profile": "payments-uat",  "account": "222222222222", "regions": ["eu-west-1"] }
  ],
  "azure": [
    { "subscription": "sub-core-prod" },
    { "subscription": "0b7c…-subscription-guid" }
  ],
  "concurrency": 8,
  "tagKeys": { "environment": "environment", "owner": "owner", "costCentre": "cost-centre" }
}
```

| Field | Meaning |
|---|---|
| `aws[].profile` | AWS CLI profile (e.g. an SSO profile). Empty = default credential chain. |
| `aws[].account` | The account the profile **must** resolve to. Verified with `sts get-caller-identity` before anything is scanned; a mismatch is refused, not silently scanned. |
| `aws[].regions` | Regions to scan in that account. |
| `azure[].subscription` | Subscription name or ID. The inventory may use either form. |
| `concurrency` | Maximum cloud CLI processes at once across the whole scan (default 8, max 64). |
| `tagKeys` | Which cloud tags carry `environment`, `owner`, `costCentre` (matched case-insensitively). |
| `nameEnvironmentPattern` | Fallback for clusters without an environment tag: a regex with a named group `env` applied to the cluster name, e.g. `(?i)^.+-k8s-(?P<env>[a-z]+)-cluster$`. The tag always wins. |

The credentials need only read access: `sts:GetCallerIdentity`,
`eks:ListClusters` and `eks:DescribeCluster` on AWS; `Reader` (or
`Microsoft.ContainerService/managedClusters/read`) on each subscription.

## AWS access

`aws login`, `aws whoami`, `aws env`, `shell`, `ec2`, `connect`, `eks auth`,
`eks access` and `prompt` cover the IAM Identity Center and EC2/EKS access
flow. They are documented in **[aws.md](aws.md)**, with the security model for
reviewers in **[security.md](security.md)**.

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

### `bankctl kubeconfig <cluster> [--file PATH] [--dry-run] [--change-record CHG… | --break-glass REASON]`
Fetches credentials by shelling out to the right cloud CLI
(`aws eks update-kubeconfig` or `az aks get-credentials`). Flags may go before
or after the cluster name.
```bash
bankctl kubeconfig eks-payments-sit-euw1
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
the same `bankctl doctor` hint, and quotes the CLI's own error message rather
than a bare exit status. Both go to stderr, so `-o json` and scripts are
unaffected.

**Identity verified first.** `aws eks update-kubeconfig` uses whatever account
your active credentials belong to — if that account has a cluster with the same
name, you would get credentials for the wrong cluster, labelled as the right
one. So before fetching, bankctl checks `aws sts get-caller-identity` against
the cluster's `account` and refuses on a mismatch:
```text
kubeconfig refused: active AWS credentials are for account 999999999999 (arn:aws:sts::999999999999:assumed-role/dev/neo),
but eks-payments-prod-euw1 is in account 111111111111 — select the right profile (e.g. AWS_PROFILE=...) and retry
```
On Azure every call passes `--subscription`; bankctl confirms the subscription
is reachable and records who is acting. Every real fetch is recorded in the
[audit trail](#audit-trail) — `--dry-run` fetches nothing and records nothing.

**Bounded and cancellable.** Every cloud CLI call has a deadline
(`commandTimeout`, default 2 minutes). A hung CLI fails with
`aws did not finish within 2m0s` instead of hanging your shell or CI job, and
Ctrl-C stops it cleanly (exit 130). Either way the CLI **and every process it
spawned** are killed — a timed-out `az` does not leave python running in the
background.

### `bankctl login <cluster> [--file PATH] [--dry-run] [--change-record CHG… | --break-glass REASON] [--context NAME]`
`kubeconfig` plus a loud warning if the target is production (a
`prodEnvironments` environment, or a name matching `prodPatterns`). Takes the
same flags as `kubeconfig`, including change control.
```bash
bankctl login eks-payments-prod-euw1
# ⚠  "eks-payments-prod-euw1" is a PRODUCTION cluster. Changes require a change record.
```
In [bastion mode](#bastion-mode) it switches to the cluster's provisioned
context instead of fetching credentials; `--context` picks one when the cluster
has several, and `--file` does not apply.

### `bankctl fleet versions [--fail-on-stale] [-o table|json]`
Version-drift report against each cluster's target — `targetKubeVersions` for
its environment, else `targetKubeVersion`. Status is `current`, `n-1`
(one minor behind — allowed), or `STALE` (two or more behind). `--fail-on-stale`
exits 1 if any cluster is STALE — drop it into a scheduled pipeline as a fleet
hygiene gate. `--fail-on-stale` and `-o json` compose (JSON is still emitted).
```bash
bankctl fleet versions
bankctl fleet versions --fail-on-stale                        # CI gate
bankctl fleet versions -o json | jq -r '.[]|select(.status=="STALE").name'
```

### `bankctl fleet eol [--warn-days N] [--by-cost-centre] [--fail-on-risk] [-o table|json]`
Where each cluster sits in its cloud's support lifecycle, most at-risk first,
and what extended support costs. "Two versions behind" is an engineering
concern; "USD 730/month from 1 December" gets upgrade windows approved.

| Status | Meaning |
|---|---|
| `unsupported` | Past the end of all support. |
| `extended` | In paid extended support; `PREMIUM/MO` is the extra it costs now. |
| `ending` | Standard support ends within `--warn-days` (default 90); the premium it will start costing is shown with its start date. |
| `unknown` | No `supportCalendar` entry for its version — an assurance gap, so it counts as at-risk. |
| `ok` | In standard support beyond the warning window. |

```text
NAME                    CLOUD  ENV   VERSION  STATUS       PHASE ENDS  DAYS  PREMIUM/MO (USD)
eks-payments-dev-euw1   aws    dev   1.27     unsupported  -           -     -
eks-payments-sit-euw1   aws    sit   1.29     extended     2027-03-01  153   365.00
eks-payments-prod-euw1  aws    prod  1.30     ending       2026-12-01  63    365.00 from 2026-12-01
aks-core-prod-weu       azure  prod  1.30     ok           2027-06-01  245   -

extended-support premium: USD 365.00/month now; +USD 730.00/month if the 2 ending cluster(s) are not upgraded in time
```
*(Illustrative dates and prices.)* `--by-cost-centre` adds a roll-up per
`costCentre`; `--fail-on-risk` exits 1 if any cluster is anything but `ok` — a
scheduled gate. Money is computed in integer micro-units (exact, no float
drift) and appears in JSON as decimal strings, e.g. `"365.00"`.

### `bankctl fleet calendar aws [--profile P] [--region R]`
Generates `supportCalendar.aws` from `aws eks describe-cluster-versions`, so
AWS dates come from AWS rather than being typed by hand. Profile and region
default to the first `discovery.aws` target. Paste the output under
`supportCalendar`. **Azure publishes no API for AKS support dates** — maintain
`supportCalendar.azure` from the
[AKS release calendar](https://learn.microsoft.com/azure/aks/supported-kubernetes-versions).

### `bankctl inventory validate [--file PATH]`
Loads the config and the inventory and applies every validation rule, reporting
all problems at once (exit 1). `--file` checks a candidate — e.g. the inventory
in a pull request — against the config. CI runs this on every change to the
inventory.

### `bankctl inventory diff [-o table|json] [--report FILE]`
Reconciles the inventory against what the clouds actually run. Exits **0 only
when the scan was complete and there are no findings**; otherwise 1.

| Finding | Meaning |
|---|---|
| `shadow` | Exists in the cloud, absent from the inventory — **ungoverned infrastructure**. |
| `missing` | Declared, but not found in a scope that was **fully** scanned — decommissioned, renamed, or wrong identity in the inventory. |
| `drift` | Found, but a field disagrees: running version (compared by minor), Azure location, or a tagged environment/owner/cost centre. An absent tag is unknown, never drift. |
| `unscanned` | Declared in a scope outside `discovery` (or that failed), so it was **not verified**. |

```text
KIND       CLUSTER                SCOPE                                   DETAIL
shadow     eks-trading-uat-euw1   aws 222222222222/eu-west-1              exists in the cloud but not in the inventory — ungoverned infrastructure
missing    aks-core-uat-weu       azure sub-core-nonprod/rg-aks-core-uat  declared in the inventory but not found in a fully scanned scope — …
drift      eks-payments-sit-euw1  aws 333333333333/eu-west-1              version: inventory "1.29", cloud "1.30"
unscanned  eks-payments-dev-euw1  aws 444444444444/eu-west-1              its scope is not in the discovery configuration (or failed to scan), …

scan INCOMPLETE — 1 scope(s) failed; results cannot prove the inventory is complete:
  aws 444444444444/eu-west-1 (profile acct-444444444444): verifying identity: credentials resolve to account 999999999999, expected 444444444444 — refusing to scan
```

A scope is scanned all-or-nothing: if one cluster in a region cannot be
described, the whole region is reported as failed, never as partially clean. A
failed scope never produces `missing` findings — only `unscanned`. `-o json`
emits the full report, including the exact scopes scanned, for audit evidence.

`--report FILE` also writes the JSON report to a file, so a pipeline gets a
readable log and a machine-readable artifact from one scan.

```bash
bankctl inventory diff                                   # human review
bankctl inventory diff -o json > evidence/inventory-$(date +%F).json
bankctl inventory diff -o json | jq -r '.findings[]|select(.kind=="shadow").cluster'
```

### `bankctl inventory sync [--out FILE] [--force]`
Writes the inventory the clouds imply: every observed cluster with its real
identity and running version, `environment`/`owner`/`costCentre` from tags
(falling back to the declared values), declared clusters in unscanned scopes
kept unchanged, and clusters proven missing removed. Prints to stdout, or to
`--out` atomically (never a half-written file); `--force` to overwrite.

It **refuses to write** when:
- the scan was incomplete — clusters in the failed scopes would be silently dropped;
- the result would not pass validation — e.g. two real clusters share a name, or
  an untagged cluster has no environment on the allow-list (and
  `nameEnvironmentPattern` does not supply one). Fix at the source (tag or
  rename), then sync again.

```bash
bankctl inventory sync --out fleet.proposed.json
git diff --no-index fleet.json fleet.proposed.json      # review before publishing
```

### `bankctl sweep [--apply] [--include-current] [--kubeconfig PATH] [-o table|json]`
Removes kube-contexts the inventory proves stale — after 80 clusters come and
go, `~/.kube/config` fills with dead entries that are easy to switch to by
mistake. It **only removes what it can prove**:

| Verdict | Meaning | Action |
|---|---|---|
| `stale` | An EKS/AKS context matching nothing in the inventory | removed with `--apply` |
| `stale-current` | Stale, but it is the current context | kept unless `--include-current` |
| `unverifiable` | EKS/AKS, but the inventory lists no clusters for that cloud, or does not cover that AWS account — absence proves nothing | kept |
| `keep` | Resolves to an inventory cluster | kept |
| `unmanaged` | Not EKS/AKS (kind, minikube, on-prem, …) | never touched |

A context is recognised as EKS/AKS by its API host (`*.eks.amazonaws.com`,
`*.azmk8s.io`), exec plugin (`aws eks get-token`, `kubelogin`) or the names the
CLIs write, and matched to the inventory through its context name, its ARN,
its `aws eks get-token --cluster-name/--region` arguments or az's
`clusterUser_<rg>_<name>` user — so renamed contexts still resolve.

Safety:
- **dry run by default** — nothing changes without `--apply`;
- a **byte-identical backup** (`<file>.bankctl-<UTC time>.bak`, 0600) is written first;
- edits go through `kubectl config delete-*`, so the file's format is preserved;
  cluster and user entries are removed only when no remaining context uses them;
- afterwards the file is **re-read and verified**: every planned context gone,
  every other context still present — on any failure it prints the `cp`
  command that restores the backup;
- a `KUBECONFIG` listing several files is refused (pass `--kubeconfig`), and it
  refuses to run at all without a valid inventory.

Run `bankctl inventory diff` first: the sweep is only as good as the inventory.
```bash
bankctl sweep                 # review what would go
bankctl sweep --apply         # remove it (backup first)
```

### `bankctl audit verify [--log PATH]... [-o table|json]`
Checks the hash chain of the audit log (default: the configured one; repeat
`--log` for several). Exits 1 if any chain is broken or unreadable, naming the
first bad line and whether an event was modified or removed.

### `bankctl evidence (--period 2026-Q3 | --from DATE --to DATE) [--log PATH]... [--production] [--out FILE] [-o table|json]`
Builds the auditor-facing evidence pack for a period (a quarter, a month, or
inclusive dates, all UTC): every access — start and end events joined — with
who, which cloud principal, which cluster and environment, the change record
and whether it was verified, and the outcome.

```text
evidence 2026-07-01 → 2026-09-30 · 1 source(s) · chains intact
accesses 4 · production 3 (1 verified change, 0 unverified, 2 without) · break-glass 1 · refused 1 · failed 0 · incomplete 0

NEEDS REVIEW (1)
STARTED (UTC)     USER  CLUSTER                 ENV   CHANGE  REASON
2026-09-29 10:00  neo   eks-payments-prod-euw1  prod  -       break-glass access: P1 INC0099887: payments ingress down
```

**Needs review** lists what a reviewer must look at: successful break-glass
access, production access without a change record or with an unverified one,
and accesses that started but never finished. Refused attempts are counted
(the control worked) but are not exceptions.

- The chain of every log is **verified while the pack is built**. A broken
  chain marks the pack `"complete": false` and exits 1 — a tampered log cannot
  yield clean-looking evidence.
- Pass `--log` several times to combine logs collected from the team (or a SIEM
  export); an event present in two copies is counted once.
- `--out` writes the JSON pack atomically (0600 — it names people and
  principals) and prints its SHA-256, for the auditor's chain of custody.

### `bankctl guard [--block] [-o table|json]`
Classifies the **current** kube-context. It is production if **either**:

- the context resolves to an inventory cluster in a `prodEnvironments`
  environment — recognising the names the tools write:
  `arn:aws:eks:<region>:<account>:cluster/<name>` (aws default),
  `<account>.<name>` (bankctl's alias), `<name>` and `<name>-admin` (az); the
  ARN and alias forms must match the account too, so a same-named cluster in
  another account never resolves to this one; **or**
- its name matches a `prodPatterns` regex.

Using both means the inventory can only make detection stricter: a prod
cluster named `eks-core-live-euw1` is caught, and the patterns still over-warn
as before. If the inventory is unreachable or invalid, `guard` says so on
stderr and falls back to the patterns — it never stops working. A URL inventory
is cached locally for `inventoryCacheTTL` (0600, atomic writes; a failed
refresh falls back to the last good copy with a warning), so `guard` costs
about 10 ms over the `kubectl` call it wraps.

With `--block` it exits **3** on production — for a shell prompt or a
pre-apply hook. `-o json` never weakens `--block`.
```bash
bankctl guard --block || echo "refusing destructive op in prod"
# PROD  arn:aws:eks:eu-west-1:555555555555:cluster/eks-core-live-euw1  (inventory: eks-core-live-euw1 is in environment prod)
bankctl guard -o json
# {"context": "...", "production": true, "cluster": "eks-core-live-euw1", "environment": "prod", "reasons": ["inventory: ..."]}
```

`guard` runs on the operator's machine, so it is a fast **safety net, not an
access control** — an engineer can simply not run it. Enforcement belongs at
credential issuance (short-lived, JIT-approved credentials) and admission
policy; do not present `guard` as the control in audit evidence.

### `bankctl current [-o table|json]`
Shows the current context, whether it's production, the inventory cluster it
resolves to, and why. `-o json` emits the same schema as `guard -o json`.

### `bankctl doctor [--strict] [-o table|json]`
Checks required (`kubectl`, `aws`, `az`; on a bastion only `kubectl`) and optional ecosystem tools for
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
bankctl doctor -o json | jq -r '.tools[]|select(.status!="ok").name'
```
In `-o json`, `healthy` always agrees with the exit code under the same flags.
Version probes run concurrently, each with its own deadline.

This is how the tool answers "are our CLIs current?" — see also the
kubeconfig drift warning under `kubeconfig` above.

### `bankctl version` / `bankctl help`

## Exit codes

Exit codes are a **stable contract**: prompts, CI gates and wrappers branch on
them. New codes may be added; existing ones are never renumbered or
repurposed. They are defined once, in `internal/app/exitcodes.go`.

| Code | Name | Meaning |
|---|---|---|
| 0 | `ExitOK` | success, or the check passed |
| 1 | `ExitFailure` | the command ran and failed (inventory/config/cloud CLI failure, timeout), or a check found a problem (`--fail-on-stale`, missing required tool, `inventory diff` not in sync) |
| 2 | `ExitUsage` | invalid invocation — unknown command, bad flag, bad `-o` value; nothing was attempted |
| 3 | `ExitProdContext` | `guard --block` found a production context |
| 130 | `ExitInterrupted` | cancelled by Ctrl-C / SIGTERM; child processes were stopped |

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

**Scheduled hygiene gates** (nightly pipeline; each exits 1 on a finding):
```bash
bankctl inventory diff -o json > inventory-diff.json   # shadow / missing / drift
bankctl fleet eol --fail-on-risk                      # lifecycle and cost risk
bankctl doctor --strict                               # build-agent CLIs current
```

**Quarterly access evidence** — collect each engineer's log (or a SIEM export),
then:
```bash
bankctl evidence --period 2026-Q3 --log alice.jsonl --log bob.jsonl --production \
  --out evidence/2026-Q3-prod-access.json
# evidence written to evidence/2026-Q3-prod-access.json (sha256 …)
```

**Emergency access** when the change system is down:
```bash
bankctl login eks-payments-prod-euw1 --break-glass "P1 INC0099887: payments ingress down, SNOW unavailable"
```

**Onboard to a cluster from scratch**:
```bash
bankctl clusters list --owner my-team     # find it
bankctl login eks-myteam-sit-euw1         # creds + prod check
kubectl get pods -A                       # you're in
```

## Design notes

- **Zero third-party deps** — stdlib only; smaller attack surface, reproducible
  builds, nothing to `pip`/`npm`/`go get` from the internet at build time.
- **Doesn't reinvent** — orchestrates `aws`/`az`/`kubectl` via their stable
  subcommands; for anything else it points you at the right upstream tool.
- **Fail safe** — HTTPS-only inventory, over-warns rather than under-warns on
  prod detection, invalid prod regexes are skipped (never make prod look safe).
  An ambiguous inventory is refused before any command acts on it.
- **Says less, never more** — discovery scans scopes all-or-nothing, verifies
  account identity first, and a partial scan is reported as incomplete; `sync`
  will not write from one. Output is deterministically ordered, so two scans of
  the same estate are byte-identical and diffable.
- **Bounded at scale** — one semaphore caps live cloud CLI processes across the
  whole scan; tested at 1,500 clusters / 1,700 calls with concurrency held.
- **Recorded, or it doesn't happen** — credential fetches are audited before
  they run, verified against the cluster's real account first, and refused if
  the record cannot be written. Evidence is built only from verified chains.
- **Bounded** — every subprocess goes through `internal/execx`: a deadline,
  cancellation on SIGINT/SIGTERM, the whole process group killed on either, and
  the CLI's stderr carried in the error.
- **Testable** — command dispatch takes injected stdout/stderr; core logic
  (drift classification, filters, prod detection, flag parsing) is unit-tested,
  and CLI-facing behaviour is tested end to end against fake `aws`/`kubectl`
  binaries on `PATH`.
- **Verifiable builds** — static (`CGO_ENABLED=0`), path-free (`-trimpath`),
  reproducible (`make repro` builds twice and compares), with SHA-256
  checksums. CI gates on formatting, vet, the stdlib-only policy, staticcheck,
  race-detected tests on Linux and macOS, and `govulncheck` (also nightly).

## Extending

Add a subcommand by wiring a `case` in `internal/app/app.go` and a handler in
`internal/app/commands.go`. Keep cloud-specific shelling in `internal/cloud`,
inventory logic in `internal/inventory`, and add a unit test. Run external
CLIs only through `internal/execx`, return the named exit codes, and offer
`-o json` on anything a script might read. Run `make ci` before committing.
