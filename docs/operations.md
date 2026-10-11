# For DevOps: running the fleet

Commands for the platform team, on EKS and AKS. Most work on one cluster or
on many at once:

| Clusters | Flag |
|---|---|
| One cluster (AKS by name, or EKS in your signed-in account) | `--cluster NAME` |
| Every AKS cluster on an environment's bastion (one SSH connection each) | `--env qa`, `--env dev,qa` |
| Only the clusters whose name contains a word | `--match payments` |
| Every EKS cluster in your signed-in account | `--aws` |

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
