# For DevSecOps: checks and evidence

These are read-only checks on EKS and AKS, with reports you can file as
evidence. They take the same cluster flags as `health`: `--cluster NAME`,
`--env prod` (every cluster on that bastion, over one SSH connection),
`--match WORD` and `--aws`.

## What runs, and how risky: `nedctl posture`

```bash
nedctl posture --env prod
nedctl posture --env qa,prod -o json > posture-2026-10.json
```

```
PROD pay-k8s-prod-cluster  61 pods checked
CHECK                   RESULT  COUNT  EXAMPLES
privileged              fail    1      payments/agent-x2/agent
host-namespaces         ok      0
secret-in-env           fail    2      payments/api-7f9c/api (DB_PASSWORD); payments/worker-1/worker (API_KEY)
public-load-balancer    ok      0
unapproved-registry     ok      0
dangerous-capabilities  ok      0
host-path               warn    1      payments/agent-x2 (/var/run)
root                    warn    6      …
no-memory-limit         warn    3      …
mutable-image-tag       ok      0
privilege-escalation    info    14     …
```

| Check | Severity | What it finds | Fix |
|---|---|---|---|
| `privileged` | fail | `privileged: true` containers | Grant only the capability needed |
| `host-namespaces` | fail | Pods sharing the node's network, PIDs or IPC | Remove `hostNetwork`, `hostPID` and `hostIPC` |
| `secret-in-env` | fail | Variables named like a secret (`PASSWORD`, `TOKEN`, `API_KEY`…) with a **literal** value | `valueFrom.secretKeyRef` or a mounted Secret |
| `public-load-balancer` | fail | `LoadBalancer` services without the internal annotation (Azure or AWS) | Annotate as internal, or use the ingress |
| `unapproved-registry` | fail | Images from registries not in `security.approvedRegistries` (only when that's set) | Mirror into an approved registry |
| `dangerous-capabilities` | fail | `SYS_ADMIN`, `NET_ADMIN`, `ALL`, `SYS_PTRACE`, `SYS_MODULE`… | Remove, or record an exception |
| `host-path` | warn | Volumes from the node's filesystem | Another volume type |
| `root` | warn | Containers that may run as root | `runAsNonRoot: true` and a non-zero `runAsUser` |
| `no-memory-limit` | warn | No `resources.limits.memory` | Set one |
| `mutable-image-tag` | warn | `latest` or untagged images | A fixed tag or a digest |
| `privilege-escalation` | info | `allowPrivilegeEscalation` not set to `false` | Set it |

**What it reads.** It fetches only the fields it judges, so a whole
environment fits in a small transfer. For environment variables it reads
**names only**, never values: a variable counts when it has a literal value
and its name looks like a secret. Platform namespaces are skipped (`kube-system`,
`kube-public`, `kube-node-lease`, `gatekeeper-system`, `calico-system`,
`tigera-operator`; change the list with `security.ignoreNamespaces`).
`--include-system` checks them too.

**Exit code.** 1 when a cluster fails or can't be reached; with
`--fail-on warn`, warnings fail too. That makes it usable as a pipeline gate.
`-o json` adds a timestamp and the check catalogue with fixes, as an
evidence pack.

## Every image running: `nedctl images`

```bash
nedctl images --env prod
nedctl images --env qa,prod --flagged
nedctl images --env prod -o csv > images-prod.csv     # for trivy, Defender or Inspector
nedctl images --env prod --fail-on-unapproved         # a pipeline gate
```

```
IMAGE                           DIGEST           CLUSTERS  CONTAINERS  FLAGS
docker.io/library/redis:latest  1f2e3d4c5b6a     1         3           unapproved-registry, mutable-tag
reg.example/pay/api:1.4.2       9a8b7c6d5e4f +1  2         6           several-digests
```

This is the inventory of what actually runs, not what manifests say. For
each image reference it shows:

- the **digests** it runs as (from the container status);
- its registry;
- the clusters and namespaces it runs in, and how many containers.

| Flag | Means |
|---|---|
| `unapproved-registry` | The registry isn't in `security.approvedRegistries` (only flagged when that's set) |
| `mutable-tag` | `latest` or no tag: what runs can change without a deployment |
| `several-digests` | The same tag runs as different images: it was re-pushed, so the tag doesn't identify the code |

`-o csv` gives `image, registry, tag, digests, clusters, namespaces,
containers, flags`, one image per row, ready for a scanner. Scanning by
digest checks exactly what runs. `--registry` and `--flagged` narrow the
list.

## Who can do what: `nedctl access review`

```bash
nedctl access review --env prod
nedctl access review --env qa,prod -o json > access-review-2026-Q4.json
nedctl access review --cluster acm-k8s-qa-cluster --roles '*'
```

```
CLUSTER               SUBJECT                  ROLE           SCOPE          STATUS
pay-k8s-prod-cluster  Group:platform-admins    cluster-admin  cluster-wide   approved
pay-k8s-prod-cluster  User:alice@bank.example  cluster-admin  cluster-wide   unapproved
pay-k8s-prod-cluster  ServiceAccount:pay/ci    edit           namespace:pay  unapproved

✖ 2 grant(s) not on the approved list (access/approved.json)
• approval no longer used: Group:old-team → admin on .* — remove it?
```

This lists every subject bound to a **reviewed role** (default
`cluster-admin`, `admin` and `edit`; `--roles '*'` for all), through
ClusterRoleBindings and RoleBindings. Each grant is checked against the
**approved list**, `access/approved.json` in the repository (or
`security.approvedAccess`). Changing that list goes through a pull
request, so every approval has a reviewer and a date.

```json
{
  "rules": [
    {"subject": "Group:platform-admins", "roles": ["cluster-admin"]},
    {"subject": "ServiceAccount:argocd/argocd-application-controller", "roles": ["cluster-admin"]},
    {"subject": "Group:.*-developers", "roles": ["edit"], "clusters": ".*-(dev|ete)-.*",
     "note": "Squads may edit in dev and ete only"}
  ]
}
```

- `subject` is a regular expression over `Group:name`, `User:name` or
  `ServiceAccount:namespace/name`, matched in full.
- `clusters` is a regular expression over cluster names. Without one, it
  matches every cluster.
- `roles` lists role names. `*` means any role.
- An **approval no longer used** (it matches no grant on any reachable
  cluster) is listed so it can be removed.

Kubernetes' own subjects (`system:*`, `kube-system` service accounts) are
left out unless you pass `--include-system`. `system:masters` is always
listed. The command exits 1 on an unapproved grant or an unreachable
cluster, and `-o json` is the dated evidence.

**What it doesn't cover:**

- **EKS access entries.** They aren't RBAC bindings; review them with
  `nedctl eks access <cluster>`.
- **The AKS shared local account (`clusterUser`).** It's admitted through
  `system:masters` by certificate, not by a binding; see
  [`nedctl azure auth`](#aks-local-accounts-versus-entra-id-nedctl-azure-auth).

## Your own machine: `nedctl doctor --hygiene`

```bash
nedctl doctor --hygiene
```

```
CHECK                     STATUS  DETAIL
aws keys on disk          FAIL    long-term access keys in ~/.aws/credentials (profiles: default) — delete them, use `nedctl aws login`, …
file permissions          WARN    ~/.aws/credentials is readable by others (-rw-r--r--) — chmod 600 ~/.aws/credentials
kubeconfig credentials    WARN    ~/.kube/config holds 3 static credential(s) (client keys, tokens or passwords) — …
ssh key passphrase        WARN    ~/.ssh/id_rsa has no passphrase — add one: ssh-keygen -p -f ~/.ssh/id_rsa
secrets in shell history  WARN    ~/.bash_history has 2 line(s) that look like secrets — remove those lines and rotate what they hold
```

This finds what turns a lost laptop or a shared screen into an incident:

| Check | Finds |
|---|---|
| AWS keys on disk | Long-term `AKIA…` keys in `~/.aws/credentials` (a failure), or leftover short-term `ASIA…` keys |
| AWS keys in environment | `AWS_ACCESS_KEY_ID` exported in this shell, which reaches every program you start |
| Kubeconfig credentials | Kubeconfigs (in `~/.kube` and `$KUBECONFIG`) holding client keys, tokens or passwords. Exec-based ones (`aws eks get-token`, kubelogin) are fine |
| SSH keys | Private keys without a passphrase (OpenSSH and PEM formats), or readable by others |
| Plain-text credentials | `~/.git-credentials`, `~/.netrc` |
| Secrets in shell history | bash, zsh and fish history, and PowerShell's history on Windows: secret keys, GitHub and Slack tokens, `password=…`, pasted private keys |
| File permissions | Credential files others can read (not on Windows) |

It runs locally and sends nothing anywhere. **It never prints a secret**:
only where it is and how to fix it (tests enforce this). It exits 1 when
long-term AWS keys are found. Run it once after `setup`, and whenever a
laptop changes hands.

## AKS local accounts versus Entra ID: `nedctl azure auth`

```bash
nedctl azure auth
nedctl azure auth --env prod -o json
nedctl azure auth --fail-on-local          # a gate, once the migration is under way
```

```
ENV  CLUSTER             AUTH           KUBECONFIG USER
qa   acm-k8s-qa-cluster  local-account  clusterUser_rg_acm
qa   pay-k8s-qa-cluster  entra-id       entra

⚠ 1 of 2 cluster(s) are reached with a shared local account: their audit logs cannot name the engineer
```

Today the AKS bastions reach clusters with the clusters' **local
accounts** (`clusterUser_…`). That's a certificate in `system:masters`, the
same for everyone, so the cluster's own audit log can't tell engineers
apart. Until that changes, nedctl's audit trail is the only record of who
used which cluster.

`azure auth` reads each bastion's kubeconfig with `kubectl config view`,
which hides every key, certificate and token. For each cluster it shows:

| AUTH | Means |
|---|---|
| `local-account` | Shared client certificate or token: no per-person identity |
| `entra-id` | `kubelogin`, so each engineer signs in as themselves |
| `entra-id (legacy auth-provider)` | The old in-tree Azure plugin, which needs moving to kubelogin |
| `exec: …` | Another credential plugin |

**Moving a cluster to per-person access** (platform team, per cluster,
through the usual Terraform change):

1. Enable AKS-managed Entra ID integration with Kubernetes RBAC (or Azure
   RBAC).
2. Bind the squads' and platform team's Entra groups to roles. Write the
   same grants into `access/approved.json` so `access review` checks them.
3. Give the bastions `kubelogin` and Entra contexts. Engineers sign in once
   a day, and `nedctl azure kube` works the same.
4. Disable local accounts: `az aks update --disable-local-accounts`.
5. Run `nedctl azure auth` again. The cluster now shows `entra-id`.

nedctl doesn't need to change for this. `azure kube`, `debug`, `logs` and
the rest work the same way, and the clusters' audit logs then name the
engineer as well.
