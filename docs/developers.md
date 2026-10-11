# For developers: is my app OK, and why not?

These commands answer the questions developers ask the platform team most,
on EKS or AKS. You don't need a shell on a cluster or any kubectl
experience. They pick the cluster the way `kube` and `azure kube` do:

- `--cluster acm-k8s-qa-cluster` is an AKS cluster, reached on its bastion.
- `--cluster payments-eks-dev` is an EKS cluster in the account you're
  signed in to.
- With neither, nedctl asks which cluster.

Every command here only reads, except `forward` and `cp`, and those are
recorded. The namespace is `default` unless you give `-n`.

## Why is it not working? `nedctl explain`

```bash
nedctl explain deploy/payments-api -n payments --cluster acm-k8s-qa-cluster
```

```
deployment/payments-api in payments on QA · acm-k8s-qa-cluster

✖ payments-api-7f9c-x2x4z (container api): keeps being killed for using more memory than its limit (256Mi), 4 restarts
  → raise resources.limits.memory, or find what uses the memory
  last log lines:
    | java.lang.OutOfMemoryError: Java heap space
```

nedctl reads the workload, its pods, their events and, for a container that
keeps crashing, its last log lines. It then says what's wrong and what to do:

| It finds | It suggests |
|---|---|
| The image can't be pulled | Check the name and tag, and that the cluster may pull from that registry |
| A crash loop | The reason: killed for memory (with the limit), exit 137 or 143, a command missing from the image, the app failing at start-up (with its last log lines) |
| The pod can't be scheduled | Not enough CPU or memory on any node, taints, or a volume claim that isn't bound |
| A Secret or ConfigMap is missing | Which one |
| The readiness probe fails | The probe's message; the pod gets no traffic |
| The liveness probe fails | How often; it restarts the container |
| The rollout is stuck, or no pods exist | Rollback, or the quota or policy message that stopped the pods |
| The pod was evicted or is stuck terminating | Why |

Targets are `deploy/NAME`, `sts/NAME`, `ds/NAME`, a pod name, or a bare
name. A bare name tries a pod first, then the deployment of that name.

The same problem on every replica is reported once. `explain` exits with
code 1 when something is failing. Use `-o json` to feed it to other tools.

## What runs where? `nedctl app`

```bash
nedctl app payments-api
```

```
ENV   CLUSTER                   NAMESPACE  NAME          READY  VERSION  UPDATED
dev   payments-k8s-dev-cluster  payments   payments-api  1/1    1.5.0    2026-10-11T08:12:40
qa    payments-k8s-qa-cluster   payments   payments-api  2/3    1.4.2    2026-10-10T09:00:00
prod  payments-k8s-prod-cluster payments   payments-api  3/3    1.3.9    2026-10-02T18:30:11

versions: dev 1.5.0 · qa 1.4.2 · prod 1.3.9
```

nedctl searches every AKS cluster on the bastions for deployments and
statefulsets whose name contains `payments-api`. It shows each one's version
(the image tag), ready replicas and last update. Each bastion answers over
one SSH connection.

| Narrow it | Flag |
|---|---|
| Some environments | `--env qa,prod` |
| Clusters whose name contains a word | `--match payments` |
| One cluster | `--cluster payments-k8s-qa-cluster` |
| EKS clusters in your signed-in account | `--aws` |
| A namespace, or the exact name | `-n payments`, `--exact` |

Clusters that can't be reached are listed as warnings, so a missing row is
never silent. Use `-o json` for release tooling.

## Every pod's logs at once: `nedctl logs`

```bash
nedctl logs payments-api -n payments                 # every pod and container of the deployment
nedctl logs payments-api -n payments -f --grep error # follow, only lines with "error"
nedctl logs payments-api-7f9c-x2x4z -n payments -c api --since 10m
```

Each line starts with its pod and container, coloured per pod, so you can
follow several replicas in one stream (like `stern`). It reads from
`--since 1h` by default, with at most `--tail 200` lines per container to
start. `-f` keeps following until you press Ctrl-C.

On AKS this runs on the bastion, so you don't need a shell there. Reading
logs is recorded in the audit trail (`logs-read`), because production logs
can hold customer data.

## Reach a service from your laptop: `nedctl forward`

```bash
nedctl forward svc/payments-api 8080 -n payments            # → http://127.0.0.1:8080
nedctl forward svc/payments-db 15432:5432 -n payments       # DBeaver on 127.0.0.1:15432
nedctl forward svc/web 443 -n web                           # privileged port → 127.0.0.1:8443
```

This makes a service, pod or deployment reachable on **127.0.0.1** on your
machine, for a browser, Postman or a database tool. It works the same on
Windows, WSL and Mac. Ctrl-C stops it.

- **EKS:** kubectl port-forwards through the tunnel.
- **AKS:** kubectl port-forwards on the bastion, to its own loopback, and
  your SSH connection carries that port to you. It's a single connection,
  so when you stop, both ends stop. If the local port is in use, nedctl says
  so before connecting.

Each forward is recorded (`port-forward`). On the bastion, the forwarded
port is on the bastion's loopback for as long as you forward, so other users
logged in to that bastion could reach it too. They have the same cluster
access already, so this gives them nothing new, but don't forward to a
production database longer than you need.
