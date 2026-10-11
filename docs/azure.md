# Azure access with nedctl

AKS clusters are used from each environment's **AKS bastion**, and the
bastions have no `az` CLI or internet. nedctl doesn't change that. It takes
you to the right bastion over SSH, with the cluster you picked selected
**for that session only**. Your prompt and Windows Terminal tab show the
environment's colour, and every session is recorded.

```bash
nedctl azure kube                    # pick an environment, then a cluster
nedctl azure kube qa payments        # narrow it: QA, clusters with "payments"
nedctl azure kube acm-k8s-qa-cluster -- kubectl get pods -A   # one command, no shell
nedctl azure shell qa                # a plain shell on the QA bastion
```

It works the same from **WSL, macOS and Windows PowerShell**. OpenSSH comes
with all three.

## What happens when you run `nedctl azure kube`

1. nedctl gets the environment from a word you typed (`qa`), from the cluster
   name (`acm-k8s-qa-cluster` → QA), or from a picker.
2. It asks that environment's bastion for its kube-contexts, the same list
   `kubectx` shows there, and offers them in a picker. It remembers the list,
   so next time a full cluster name goes straight in and **Tab** completes
   cluster names.
3. It records the session in the audit trail. In production it asks you to
   confirm first, if your organisation turns that on.
4. It opens SSH to the bastion and starts bash there with your own `~/.bashrc`. The prompt
   starts with `[QA acm-k8s-qa-cluster]` in the environment's colour, and
   `kubectl`, `helm`, `k9s` and `kubectx` work on that cluster.
5. Type `exit` to leave.

### Each session is separate

Today, `kubectx` on a bastion changes `current-context` in your
`~/.kube/config`. That changes **every** session you have open on that
bastion. With two terminals open, one on a QA cluster and one on another,
switching in one silently switches the other.

nedctl's sessions don't do that. Each session gets a small file on the
bastion (`/tmp/nedctl-ctx.XXXXXX`, readable only by you) that holds only
`current-context`. That file goes first in `KUBECONFIG`, in front of your
own kubeconfig. Your `~/.kube` is never written to, so this works when it is
read-only. As a result:

- each session stays on the cluster it was opened for;
- `kubectx` inside a session switches only that session;
- your `~/.kube/config` isn't changed;
- **no credentials are copied**. They stay in the bastion kubeconfig the
  platform gave you, and nothing reaches your laptop.

The session file is deleted when you leave. Leftovers from dropped
connections are cleared after a day.

## One-time setup

### 1. Your SSH key

Use the key you use for the bastions today (`~/.ssh/id_rsa` or similar). On
Windows without WSL it lives in `C:\Users\<you>\.ssh\`.

### 2. The bastions

Release builds already contain each environment's bastion, so you usually
don't need to do anything. Check with:

```bash
nedctl azure hosts
```

If it says Azure access isn't set up, add your bastions to
`~/.config/nedctl/config.json`. Use the names from your `~/.ssh/config`
(for example `aks-qa`), or the addresses:

```json
{
  "azure": {
    "bastions": { "dev": "aks-dev", "ete": "aks-ete", "qa": "aks-qa", "prod": "aks-prod" }
  }
}
```

nedctl passes these to `ssh`, so everything in `~/.ssh/config` still
applies: `User`, `HostName`, `Port`, `IdentityFile` and `ProxyJump`. If your
bastion login name differs from your local user name, set
`"user": "<login>"` under `azure`, or `User` in `~/.ssh/config`.

### 3. The SSH agent: type your passphrase once

**WSL and Linux.** Run `nedctl setup` once, or run it again. Its shell block
then starts **one SSH agent for all your terminals**. Your key's passphrase
is asked once, the first time an `azure` command connects, and kept for 12
hours. You no longer need `eval "$(ssh-agent -s)"` and `ssh-add` in every
terminal. If you already have an agent (`SSH_AUTH_SOCK` is set), nedctl uses
yours.

**macOS.** The system agent already does this.

**Windows (PowerShell).** Start the built-in agent service once, in
PowerShell **as administrator**:

```powershell
Get-Service ssh-agent | Set-Service -StartupType Automatic
Start-Service ssh-agent
```

Then run `ssh-add` once in a normal PowerShell. Windows keeps the key from
then on.

### 4. Check

```bash
nedctl doctor
```

doctor shows the SSH agent and whether each bastion answers from where you
are, without logging in. For example: `bastion qa  OK  aks-qa (10.x.x.x:22)
reachable`.

## Daily use

| Do this | Command |
|---|---|
| kubectl on an AKS cluster (pick one) | `nedctl azure kube` |
| Narrow the list | `nedctl azure kube qa payments` |
| Straight to a cluster | `nedctl azure kube acm-k8s-qa-cluster` |
| One command, no shell (scripts get its exit code) | `nedctl azure kube acm-k8s-qa-cluster -- kubectl get pods -A` |
| The same in a new coloured Windows Terminal tab | `nedctl azure kube acm-k8s-qa-cluster --tab` |
| The clusters on each bastion | `nedctl azure clusters` (`--refresh` asks again) |
| A shell on a bastion or another Azure machine | `nedctl azure shell qa` |
| What `azure shell` can reach | `nedctl azure hosts` |

A new cluster isn't in the remembered list yet. Run `nedctl azure clusters
qa --refresh`, or just use `nedctl azure kube qa`, which always asks the
bastion.

### Other Azure machines

To make machines other than the bastions available in `nedctl azure shell`,
list them under `hosts`. `"jump": "bastion"` goes through that environment's
bastion (`ssh -J`):

```json
{
  "azure": {
    "bastions": { "dev": "aks-dev", "qa": "aks-qa" },
    "hosts": [
      { "name": "jenkins-dev", "environment": "dev", "jump": "bastion" },
      { "name": "tools-qa", "host": "10.1.2.3", "environment": "qa" }
    ]
  }
}
```

nedctl's `azure shell` sets the prompt and title on the remote machine using
bash. For a machine without bash, use `nedctl azure shell <name> --plain`.

## What gets recorded

Every `azure kube` and `azure shell` writes a start record and an end record
to the audit trail, like the AWS commands do. The records hold:

- the bastion, the cluster and the environment;
- whether the environment is production;
- any change record or break-glass reason;
- your local user name.

AKS on the bastions authenticates as a **shared AKS local account**
(`clusterUser`), so the cluster's own audit log can't tell engineers apart.
nedctl's record is the one that names who used which cluster and when. It
says so in its detail.

## Shared local account or per-person sign-in?

`nedctl azure auth` shows, per cluster, whether the bastion reaches it with
the shared local account or with Entra ID. It also lists the steps to move
a cluster to per-person sign-in; see
[For DevSecOps](security-checks.md#aks-local-accounts-versus-entra-id-nedctl-azure-auth).

## Settings

| Setting | Meaning |
|---|---|
| `azure.bastions` | Each environment's AKS bastion: an `~/.ssh/config` alias, a host name or an address, optionally `user@host`. |
| `azure.user` | SSH login name for destinations that don't name one. Default: what `~/.ssh/config` says, else your local user name. |
| `azure.hosts` | Further machines for `azure shell`. Each has `name`, `host` (default: name), `environment`, and `jump` (`"bastion"` or an SSH destination). |

Environment colours, production environments and `confirmProduction` are
the same settings the AWS commands use. See [Reference](nedctl.md).
