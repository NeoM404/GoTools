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
