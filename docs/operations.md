# For DevOps: running the fleet

Commands for the platform team, on EKS and AKS. Most work on one cluster or
on many at once:

| Clusters | Flag |
|---|---|
| One cluster (AKS by name, or EKS in your signed-in account) | `--cluster NAME` |
| Every AKS cluster on an environment's bastion (one SSH connection each) | `--env qa`, `--env dev,qa` |
| Only the clusters whose name contains a word | `--match payments` |
| Every EKS cluster in your signed-in account | `--aws` |
| Every EKS cluster in your squad's accounts for these environments | `--aws-env ete,qa` |

`--env` always means the AKS bastions in `azure.bastions` (`--env dev` is
`aks-dev`), because AWS environments are accounts you sign in to, not hosts.
For EKS use `--aws` (with `--aws-profile`), or both: `--env qa --aws`.

On AWS each environment is a separate account, so `--aws` alone sees only
the account you are signed in to. **`--aws-env ete,qa`** reads your squad's
ETE and QA accounts too. It uses the same role you hold now, or else your
first non-elevated role; it never picks an elevated role silently. The first
time, it signs in to each account, which is recorded as an `aws-login`.
Your current profile doesn't change. When your only role in an account is
elevated, nedctl asks before using it for the read (`[y/N]`). Without a
terminal it skips that account and says why. For example:

```bash
nedctl diff kiali --aws-env ete,qa --match lms
nedctl health --aws-env dev,ete,qa --board
```

On a bastion, eight clusters are read at a time, each request with a 20s limit.
Progress shows as clusters finish (`12/23 clusters read`). A cluster that is
down costs up to 20s per check, so a large environment can take a minute or
two. `--match` narrows it.

## The morning check: `nedctl health`

```bash
nedctl health --env qa
```

```
ENV  CLUSTER              STATUS  NODES                  PODS           WORKLOADS   VERSION
qa   acm-k8s-qa-cluster   ok      3/3 ready              84, 0 failing  21, 0 short  1.30.4 ok
qa   pay-k8s-qa-cluster   fail    2/3 ready, 1 cordoned  61, 2 failing  14, 2 short  1.29.9 extended

QA pay-k8s-qa-cluster
  ✖ TLS certificate payments/api-tls expired on 2026-10-10
  ✖ node aks-pool1-000002 is not Ready
  ✖ pod payments/api-7f9c-x2x4z: CrashLoopBackOff
  ⚠ Kubernetes 1.29.9 is in extended (paid) support until 2027-04-01
  ⚠ statefulset payments/redis: 2/3 ready
```

For each cluster, `health` reports:

- **Nodes:** not Ready (a failure), under memory, disk or PID pressure, or
  cordoned.
- **Pods:** crash-looping, unable to pull their image, missing a Secret or
  ConfigMap (failures), pending for more than 10 minutes, or evicted.
- **Workloads:** deployments and statefulsets below their replicas. None
  ready is a failure.
- **Volume claims** that aren't Bound.
- **TLS certificates** in `kubernetes.io/tls` secrets: expired (a failure),
  or expiring within `--cert-days 30`. Only the certificate is read; the
  private key stays inside kubectl.
- **The Kubernetes version** against the support calendar
  (`supportCalendar`): out of support is a failure, extended or ending
  standard support is a warning.

`health` exits with code 1 when any cluster fails or can't be reached, so it
works as a scheduled check. `-o json` gives the full list.

### The fleet board: `nedctl health --board`

```bash
nedctl health --env prod --board              # every prod cluster on one screen
nedctl health --env dev,qa,prod --watch 1m    # a wall screen: read again every minute
```

The board draws every cluster straight away and fills each one in as its
result arrives over the bastion connection. The status flips into place
like a departures board, and the counters at the top climb (ok, warn,
fail, unreachable, still reading).

With `--watch`, it reads everything again on that interval (30s or more).
A cluster whose status changed since the last round flips again and is
marked `▲` (better) or `▼` (worse). Ctrl-C stops it, and the problems of
the last round are listed underneath.

**Clusters that are slow or don't answer:**

- each check waits at most 20s;
- a cluster that doesn't answer its first check isn't asked the rest, so
  it shows as `UNREACHABLE` after about 20s instead of two minutes;
- no cluster is read for more than 90s;
- while you wait, the board shows how long each cluster has taken
  (`····· 12s`), and amber `slow 42s` after 30s.

The rest of the board fills in as other clusters finish, unaffected.

The board only draws in a terminal. Scripts keep using plain `health`, or
`-o json`. `NEDCTL_REDUCED_MOTION=1` keeps the live updates but drops the
flipping. Columns that don't fit a narrow window are left out rather than
wrapped.

## One command on many clusters: `nedctl fleet run`

```bash
nedctl fleet run --env qa -- kubectl get nodes
nedctl fleet run --env dev,qa,prod --prefix -- kubectl get deploy -A | grep payments-api
nedctl fleet run --env prod -- kubectl auth can-i list secrets
```

This runs one **read-only** kubectl command on every selected cluster and
shows the answers under a heading per cluster. With `--prefix`, every line
starts with the cluster's name instead, ready for `grep`. All of a bastion's
clusters run over one SSH connection, eight at a time, with a 20-second
limit each. A cluster that doesn't answer is shown as failed, and the
command exits 1.

Allowed: `get`, `describe`, `logs`, `top`, `events`, `version`,
`api-resources`, `api-versions`, `explain`, `cluster-info`, `auth can-i`
and `auth whoami`. Refused:

- every command that changes something (use a [runbook](#runbooks-nedctl-run));
- `--context`, `--kubeconfig`, `--server`, `--token` and `--as`, because
  nedctl chooses the clusters;
- `-f` and `--watch`, because the command has to finish on every cluster.

## Runbooks: `nedctl run`

```bash
nedctl run ls                                   # built-in and team runbooks
nedctl run show restart-deployment              # its parameters and steps
nedctl run restart-deployment deployment=payments-api namespace=payments --cluster acm-k8s-qa-cluster
nedctl run scale-deployment deployment=api replicas=3 --dry-run
```

A runbook is a team procedure written down as data: named steps, each one a
kubectl command with `{parameters}`. With it, second-line support can follow
a procedure safely without knowing every command, and every run looks the
same in the audit trail.

When you run one, nedctl:

1. **shows the whole runbook** filled in with your values, marking the
   steps that change something with ✎;
2. **runs reading steps** straight away and shows their output;
3. for each **changing step**, runs a **server-side dry run** (when the
   step allows it) and shows what the cluster says, then **asks** before
   running it. `--dry-run` runs the dry runs but changes nothing, and skips
   the reading steps that follow a change, since they would watch for
   something that didn't happen. `--yes` runs without asking, which scripts
   need;
4. **stops at the first failure**, and **records** the run with its
   parameters and how far it got (`runbook` in the audit trail).

A `rollout status` step shows the rollout live instead of a silent wait:
`rollout ██████████░░░░ 2/3 new replicas ready · 1 old terminating`.

### Built in

| Runbook | Does |
|---|---|
| `restart-deployment` | Rolling restart, then waits until healthy |
| `scale-deployment` | Sets the replicas, then waits until ready |
| `rollback-deployment` | Shows the history, returns to the previous version, waits |

### Writing one

Team runbooks live in `runbooks/` in the nedctl repository (or the
`runbooksDir` setting). A runbook with the same name as a built-in one
replaces it. Changes go through a pull request like any other code.

```json
{
  "name": "ingress-overview",
  "description": "Ingresses, services and endpoints of a namespace",
  "params": [
    {"name": "namespace", "description": "the namespace"},
    {"name": "replicas", "description": "how many", "pattern": "^[0-9]{1,3}$", "default": "2"}
  ],
  "steps": [
    {"name": "Ingresses", "kubectl": ["get", "ingress", "-n", "{namespace}"]},
    {"name": "Scale", "kubectl": ["scale", "deployment/web", "-n", "{namespace}", "--replicas={replicas}"], "change": true, "dryRun": true}
  ]
}
```

Rules, checked when runbooks load (a runbook that breaks one is skipped,
with a warning that says why):

- Each step is one kubectl command, written without the word `kubectl`. A
  runbook can't run a shell.
- `--context`, `--kubeconfig`, `--server`, `--token` and `--as` aren't
  allowed, because nedctl chooses the cluster.
- Every `{name}` must be a declared parameter.
- Parameter values must match their `pattern`. Without one, they may hold
  only letters, digits and `. _ : / = -`, and may not start with `-`.
- Mark every step that changes the cluster with `"change": true`. Add
  `"dryRun": true` when kubectl supports `--dry-run=server` for it (`apply`,
  `scale`, `rollout restart` and `rollout undo`, `patch`, `delete`, `label`,
  `annotate`).

## Draining a node safely: `nedctl node`

```bash
nedctl node drain aks-pool1-000001 --cluster acm-k8s-qa-cluster --dry-run
nedctl node drain aks-pool1-000001 --cluster acm-k8s-qa-cluster
nedctl node uncordon aks-pool1-000001 --cluster acm-k8s-qa-cluster
```

Before draining, nedctl shows the checks people skip under pressure:

- **the pods that will move**, and how many DaemonSet pods stay;
- **pods that belong to no controller.** Nothing would recreate them, so
  the drain stops on them. nedctl never uses `--force`; move or delete them
  first;
- **disruption budgets that allow no disruption** in the affected
  namespaces. The drain waits on them, up to `--timeout 5m`;
- **the cluster's own server-side dry run** of the drain.

Then it asks. `--dry-run` stops before asking, and `--yes` skips the
question. The drain runs with `--ignore-daemonsets --delete-emptydir-data`.

While it runs, you see it live:

- a bar of the pods moved off the node (`7/12 pods moved`);
- each pod being evicted, with how long it has taken;
- in amber, the pods a disruption budget is holding back.

In logs and pipes you get kubectl's own lines instead. If it doesn't finish, the node stays cordoned and nedctl says how to give
it back. `cordon` and `uncordon` follow the same steps. Every one is
recorded (`node-drain`, `node-cordon`, `node-uncordon`), and change control
applies.
