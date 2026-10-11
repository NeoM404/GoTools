# Debugging on a cluster: `nedctl debug`

nedctl can put a debugging container where you need one, on EKS or AKS, in
four ways:

- a pod with a shell and network tools;
- a pod on a specific node, with the node's processes, network and files;
- a container beside a running pod;
- a quick "can the pods reach X?" test.

```bash
nedctl debug pod                         # netshoot pod in "default", shell in it
nedctl debug node                        # pick a node, shell with the node's files at /host
nedctl debug attach payments-api-7f9c -n payments
nedctl debug net payments-db.internal:5432
```

## Nothing is deployed without your approval

Every command that creates something follows the same steps:

1. **It shows you exactly what it will deploy.** For a pod that's the full
   manifest. For `attach` it's the exact `kubectl` command.
2. **It asks the cluster to check it** with a server-side dry run, so
   admission policies (Pod Security, Gatekeeper, Azure Policy) answer before
   anything exists. A refusal is shown and nothing is created.
3. **It asks: `Deploy it? [y/N]`.** Production environments also ask you to
   type the environment's name, when your organisation turns that on.

`--dry-run` stops after step 2. `--yes` skips the question (it still shows
and checks), which scripts need because they have no terminal.

```
To deploy a debug pod on QA · acm-k8s-qa-cluster (on bastion aks-qa):

    apiVersion: v1
    kind: Pod
    metadata:
      name: "nedctl-debug-nb000001-3fa9c1"
      namespace: "default"
      labels:
        app.kubernetes.io/managed-by: nedctl
        nedctl.io/debug: "true"
        nedctl.io/kind: "pod"
        nedctl.io/owner: "nb000001"
    spec:
      restartPolicy: Never
      activeDeadlineSeconds: 7200   # removed after 2h at the latest
      terminationGracePeriodSeconds: 0
      automountServiceAccountToken: false
      containers:
      - name: debugger
        image: "docker.io/nicolaka/netshoot:v0.13"
        command: ["sleep", "7200"]

✔ The cluster accepts it (server-side dry run).
Deploy it? [y/N]
```

## Debug pods are cleaned up

- **Removed when you exit.** If the connection drops, the pod still ends at
  its time limit (`activeDeadlineSeconds`, 2 hours by default).
- **In `default`** unless you give `-n`.
- **No service-account token.** The pod can't act as anyone in the cluster.
- **Labelled with your name.** `nedctl debug ls` shows every debug pod, and
  `nedctl debug clean` removes your leftovers after showing them.
- **Recorded.** Each session goes in the audit trail: `debug-pod`,
  `debug-node`, `debug-attach`, `debug-net` or `debug-clean`, with the
  cluster, namespace, image, profile and node.

## Choosing the cluster

Each command picks a cluster the way `kube` and `azure kube` do:

- `--cluster acm-k8s-qa-cluster` names an AKS cluster. Its bastion comes from
  the name, or from `--env qa`.
- `--cluster payments-eks-dev` names an EKS cluster in the account you're
  signed in to (`--aws-profile` picks another).
- With no `--cluster`, nedctl asks: AWS or Azure, then the cluster.

On **EKS**, kubectl runs on your machine. nedctl holds one tunnel through
the devops instance open for the whole debug session, or goes directly when
the endpoint answers.

On **AKS**, kubectl runs on the bastion with the cluster selected for that
session only, as with `azure kube`. Nothing is copied to your machine.

## Images

`--image` takes a short name or any image reference:

| Short name | Image | Good for |
|---|---|---|
| `netshoot` (default) | `docker.io/nicolaka/netshoot:v0.13` | dig, curl, tcpdump, mtr, nc, openssl, iperf |
| `busybox` | `docker.io/library/busybox:1.36` | a small shell |
| `alpine` | `docker.io/library/alpine:3.20` | `apk add` what you need |
| `ubuntu` | `docker.io/library/ubuntu:24.04` | `apt install` what you need |
| `curl` | `docker.io/curlimages/curl:8.10.1` | HTTP only |

A custom image needs `sh` and `sleep`.

**Clusters that can't pull from Docker Hub.** If the pod doesn't start,
nedctl says why (for example `ErrImagePull`). Map the short names to your
internal registry in the config, or better, in the release's built-in
defaults:

```json
{
  "debug": {
    "images": {
      "netshoot": "myregistry.azurecr.io/tools/netshoot:v0.13",
      "busybox": "myregistry.azurecr.io/tools/busybox:1.36"
    }
  }
}
```

## Profiles

`--profile` chooses the debug pod's privileges. These are the profiles
`kubectl debug` uses:

| Profile | Pod (`debug pod`, `attach`) | Node (`debug node`) |
|---|---|---|
| `general` (default) | no extra privileges | the node's processes, network and IPC, its files at `/host` |
| `netadmin` | adds `NET_ADMIN`, `NET_RAW`, for tcpdump | the same, plus `NET_ADMIN`, `NET_RAW` |
| `sysadmin` | privileged | privileged: full access to the node |
| `restricted` | non-root, no capabilities, seccomp | not for nodes |

Use the smallest profile that does the job. Pod Security or Gatekeeper may
refuse `sysadmin` in some namespaces. You'll see that in the dry run, before
anything is deployed.

## The commands

### `nedctl debug pod`
A pod with a shell (bash if the image has it, else sh). `--on-node NODE`
places it on a node without the node's privileges.

```bash
nedctl debug pod
nedctl debug pod --image busybox -n payments
nedctl debug pod --profile netadmin --cluster acm-k8s-qa-cluster    # tcpdump in the pod's network
```

### `nedctl debug node [NODE]`
Without a name you pick from the nodes, which show their status, pool, zone
and version. A word such as `pool1` narrows the list. The node's files are
at `/host`, and `chroot /host` runs the node's own tools: `journalctl -u
kubelet`, `crictl ps`, `df -h`.

```bash
nedctl debug node
nedctl debug node aks-pool1-000001 --profile sysadmin
nedctl debug node --profile netadmin      # tcpdump on the node's interfaces
```

### `nedctl debug attach POD`
This is for an image with no shell (distroless) or a container that keeps
crashing. It adds an ephemeral container that shares the processes of one of
the pod's containers (`-c`, default: the first). The pod isn't restarted.
Ephemeral containers can't be removed: it stops when you exit and stays
listed until the pod is replaced. This needs kubectl 1.27 or newer where it
runs. kubectl has no dry run for ephemeral containers, so nedctl shows the
exact command and asks.

### `nedctl debug net HOST[:PORT]`
Runs the checks from a short-lived pod and removes it afterwards:

- DNS;
- TCP connect;
- for 443, 8443 and 6443, the certificate's subject, issuer and expiry;
- the HTTP status.

It exits non-zero when DNS or TCP fails, so you can use it in scripts with
`--yes`.

### `nedctl debug ls` and `nedctl debug clean`
`ls` shows the debug pods on a cluster: namespace, owner, kind, node, state
and age. `clean` removes yours after showing them. `clean --all` removes
everyone's, and the removal is recorded.

## Settings

| Setting | Meaning |
|---|---|
| `debug.namespace` | Namespace for debug pods without `-n`. Default `default`. |
| `debug.image` | Image without `--image`: a short name or a reference. Default `netshoot`. |
| `debug.images` | Short names to image references, added to and overriding the table above. |
| `debug.ttl` | Longest a debug pod lives. Default `"2h"`. |
