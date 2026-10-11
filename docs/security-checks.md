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
