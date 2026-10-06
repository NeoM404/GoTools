# Fleet inventory in Azure DevOps

A proposal for the platform team: keep the list of AKS clusters as a
reviewed file in Azure Repos, and have a nightly pipeline check it against
what Azure is actually running.

## The problem it solves

Today nothing lists every cluster in one place except Azure itself. Terraform
in Azure DevOps creates clusters, but a cluster created outside Terraform, or
one Terraform has lost track of, is not visible to anyone until it causes a
problem. An auditor asking "is this every cluster you run?" cannot be
answered with evidence.

## How it works

```
 Terraform (ADO) ──creates──▶ AKS clusters ◀──reads (Reader)── nightly pipeline
                                                                 │
              inventory/fleet.json ◀──PR, reviewed by a person───┘ proposed-fleet.json
                     │                                              + diff.json
                     ▼
        CI validates on every PR ──▶ published "fleet" artifact ──▶ bastions
                                                                 (bankctl guard / login)
```

1. **`inventory/fleet.json` is the record.** One entry per cluster: name,
   environment, subscription, resource group, version, owner. It changes only by
   pull request, so every change has an author, a reviewer and a date.
2. **The nightly pipeline** (`.azure-pipelines/inventory.yml`) lists every AKS
   cluster in the in-scope subscriptions and compares that with the file.
   - Everything matches: the run is green.
   - Something differs: the run goes red and publishes `diff.json` (what is
     wrong) and `proposed-fleet.json` (the corrected file).
3. **A person reviews and merges** the proposal. The pipeline only reads from
   Azure and never writes to the repo, so the identity that scans the clouds
   cannot change the record it is checked against. This is separation of
   duties by design.
4. **CI** (`.azure-pipelines/ci.yml`) validates `fleet.json` on every pull
   request. A duplicate name, an unknown environment or a missing resource group
   fails the build. On `main` it publishes the validated file as the `fleet`
   artifact.

### What it reports

| Finding | Meaning | Typical cause |
|---|---|---|
| `shadow` | Running in Azure, not in the inventory | Created by hand or outside Terraform; forgotten test cluster |
| `missing` | In the inventory, not in Azure | Decommissioned without updating the record; renamed |
| `drift` | In both, but a field differs | Upgraded (`version`); environment tag disagrees with the record |
| `unscanned` | In the inventory, in a subscription the scan doesn't cover | Scope gap: add the subscription |

A scan that cannot finish, for example because access to one subscription was
denied, is reported as **incomplete** and never as in sync. No proposal is
written from a partial scan, so a permissions problem can never silently drop
clusters from the record.

### Environments

Each cluster's environment comes from its `environment` tag. If the tag is
missing, it comes from the naming convention `<app>-k8s-<env>-cluster`, using
`discovery.nameEnvironmentPattern`. Allowed values are `dev`, `ete`, `qa` and
`prod`. **QA is treated as production** (`prodEnvironments: ["qa", "prod"]`)
because it is an exact copy of production.

## What the team needs to provide

| # | Item | Who | Notes |
|---|---|---|---|
| 1 | **Service connection** `sc-bankctl-inventory-reader` | ADO / cloud admins | Workload identity federation (no secret). Role: **Reader** on each in-scope subscription, or narrower: `Microsoft.ContainerService/managedClusters/read`. |
| 2 | **Subscription IDs** | Platform team | Replace the `REPLACE-…` entries in `inventory/bankctl.json`. |
| 3 | **Agent pool** | ADO admins | `ubuntu-latest` works. For a self-hosted pool, set `pool: name:`. Agents need Go (installed by the `GoTool` task) and `az`. Without internet, also set `GOPROXY` to the internal Go proxy. |
| 4 | **Branch policy** on `main` | Repo admins | Make `ci.yml` a required build validation and require at least one reviewer. Azure Repos ignores YAML `pr:` triggers. |
| 5 | **Delivery to bastions** | Platform team | See below. |
| 6 | **Alerting** (optional) | Platform team | Notify the team channel when the inventory pipeline fails. |

## First run (bootstrap)

`inventory/fleet.json` starts empty. The first nightly run, or a manual run,
reports every cluster as `shadow` and proposes the full inventory. Review the
proposal, fill in `owner` and `costCentre`, merge it, and the next run is green.
From then on the pipeline only goes red when reality changes.

To try it before any pipeline exists, run it as yourself. This needs only
Reader access and a machine with `az`:

```bash
make build
az login
BANKCTL_CONFIG=inventory/bankctl.json OUT_DIR=out inventory/reconcile.sh
```

## Getting the inventory onto the bastions

The bastions have no internet. The team needs to pick one of these:

| Option | How | Trade-off |
|---|---|---|
| **A. Existing deploy path** | Whatever already puts files on the bastions (Ansible, Satellite, an ADO deployment group) copies the `fleet` artifact to a fixed path, e.g. `/etc/bankctl/fleet.json`. | Simplest when such a path exists. Updates follow that tool's cadence. |
| **B. Internal HTTPS endpoint** | Pipeline uploads `fleet.json` to an internal web or artifact server (Artifactory/Nexus) that the bastions can reach. Bastions set `"inventoryUrl"`. | Always current. `guard` caches it, so a network blip falls back to the last good copy. The endpoint must serve without per-user auth. |
| **C. Azure Storage, private endpoint** | Static website on a storage account reachable only through a private endpoint in the bastions' VNet. | Fully Azure-native. Needs network/DNS work, and the bank's storage policy may forbid anonymous read. |

Each bastion then uses a config like
[`configs/bankctl.bastion.example.json`](../configs/bankctl.bastion.example.json)
(`"mode": "bastion"`), created with `bankctl init --mode bastion`.

## What bankctl does on a bastion

| Command | Bastion behaviour |
|---|---|
| `guard`, `current` | Classify the current context as production or not, using the inventory **and** everything the kubeconfig carries: context name, cluster entry, `clusterUser_<rg>_<name>` user. A renamed context is still recognised. |
| `login <cluster>` | Find the context the platform provisioned for that cluster and switch to it. Before that, apply change control (`--change-record` / `--break-glass`, when `changeControl.requireFor` is set) and write the audit record. Fetches no credentials and needs no `az`. |
| `kubeconfig` | Refused: bastion credentials are provisioned, not fetched. |
| `inventory diff/sync` | Refused, with a pointer to this pipeline. |
| `doctor` | Needs only `kubectl`. `aws` and `az` are not required. |
| `clusters`, `fleet versions/eol` | Unchanged: they read the inventory. |

### A note on identity

On AKS clusters reached through a `clusterUser_<rg>_<name>` user with a static
certificate or token, every engineer is the **same identity** to the API server.
These are AKS local accounts on a cluster without Entra ID integration. The
cluster's own audit log cannot tell people apart, and removing one person's
access means rotating the credential for everyone.

The bastion login records the individual Linux user, and flags each such
access as using a shared local account. That is attribution of intent, not a
control. The durable fix is Entra ID integration with `kubelogin` and
`--disable-local-accounts`. bankctl handles that case already: a kubelogin user
is recognised as personal.

## Change control (optional for now)

ServiceNow verification is configured but switched off. When an API account
and network path from the bastions exist:

```json
"changeControl": {
  "requireFor": ["qa", "prod"],
  "serviceNow": { "instanceUrl": "https://<instance-host>", "tokenEnv": "SNOW_TOKEN" }
}
```

`instanceUrl` is the instance's **base URL**, without the `/sp` Service Portal
path. bankctl calls the Table API at `/api/now/table/change_request` under it.
Until then, `--change-record CHG…` is format-checked and recorded, but not
verified.
