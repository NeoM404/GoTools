# Getting started

From nothing to `kubectl` on a cluster in about ten minutes. You need the
bank network or VPN, and for AWS an IAM Identity Center login (the AWS
access portal you use today); for Azure, the SSH key you use for the AKS
bastions.

## 1. Install the prerequisites

nedctl drives three tools you may already have. Check first:

```bash
aws --version; session-manager-plugin --version; kubectl version --client
```

Install whatever is missing.

**WSL (Ubuntu) or Linux:**

```bash
# AWS CLI v2
curl -sSo awscliv2.zip https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip
unzip -q awscliv2.zip && sudo ./aws/install --update

# Session Manager plugin
curl -sSo session-manager-plugin.deb https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb
sudo dpkg -i session-manager-plugin.deb

# kubectl
curl -sSLo kubectl "https://dl.k8s.io/release/$(curl -sSL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -m 0755 kubectl /usr/local/bin/kubectl
```

**Windows (PowerShell, no WSL):**

```powershell
winget install Amazon.AWSCLI
winget install Amazon.SessionManagerPlugin
winget install Kubernetes.kubectl
```

**macOS:**

```bash
brew install awscli kubectl && brew install --cask session-manager-plugin
```

**Behind the bank proxy:** if the AWS CLI needs a proxy on your machine, set
it where your shell starts (for example in `~/.bashrc`), so the AWS CLI and
nedctl both use it:

```bash
export HTTPS_PROXY=http://<proxy>:<port>
export NO_PROXY=localhost,127.0.0.1,169.254.169.254
```

## 2. Download nedctl

In Azure DevOps: **Pipelines → nedctl Release → the newest run (named after
its version, e.g. `v1.0.0`) → Artifacts → `nedctl-v1.0.0`**, and download the
file for your machine:

| Your machine | File |
|---|---|
| WSL or Linux (Intel/AMD) | `nedctl-linux-amd64` |
| Windows without WSL | `nedctl-windows-amd64.exe` |
| Mac with Apple silicon (M1–M4) | `nedctl-darwin-arm64` |
| Mac with Intel | `nedctl-darwin-amd64` |

Optional: download `SHA256SUMS` too and check the file is intact:
`sha256sum -c SHA256SUMS --ignore-missing` (on a Mac: `shasum -a 256 -c …`).

## 3. Run setup

**WSL, Linux or Mac:**

```bash
chmod +x nedctl-linux-amd64          # the file you downloaded
./nedctl-linux-amd64 setup
```

**Windows (PowerShell):**

```powershell
.\nedctl-windows-amd64.exe setup
```

`setup` asks before each step, never overwrites anything, and is safe to run
again:

- **config** — release builds already contain the bank's sign-in settings, so
  there is nothing to fill in.
- **install** — copies nedctl to `~/.local/bin` (Windows:
  `%LOCALAPPDATA%\Programs\nedctl`, added to your PATH).
- **shell** — adds a marked block to `~/.bashrc` / `~/.zshrc` / your
  PowerShell profile: the coloured prompt and tab, tab completion, and
  `nedctl aws login` switching the terminal you run it in. If it finds an
  older `prompt init` line you added by hand, it offers to comment it out.
- **doctor** — checks tools, proxy, CA bundle and that the AWS portal is
  reachable, and says what to fix.

Then **open a new terminal** (or run `exec bash`).

## 4. Sign in

```bash
nedctl aws login
```

A browser opens (in WSL: your Windows browser) — confirm the sign-in. Then
pick an account and role from the list; type words to narrow it, e.g.
`nedctl aws login lms dev`. Your prompt now starts with the account and
environment, and the Windows Terminal tab turns that environment's colour:
**dev green, ete orange, qa blue, prod red**. A `▲` marks a role that can
change and delete resources.

You sign in once a day; when it expires, the next command renews it.

## 4b. Azure: AKS through the bastions

Nothing to sign in to — nedctl uses your SSH key. Check that it can reach
the bastions, then go:

```bash
nedctl doctor            # "ssh agent" and one "bastion <env>" line each
nedctl azure kube qa     # pick a QA cluster; exit to leave
```

Your key's passphrase is asked once and kept for 12 hours (WSL/Linux, after
`setup`; on Windows see [Azure access](azure.md#3-the-ssh-agent-type-your-passphrase-once)).
If `nedctl azure hosts` says Azure access is not set up, add your bastions
as shown in [Azure access](azure.md#2-the-bastions).

## 5. Daily use

| Do this | Command |
|---|---|
| See who you are signed in as, and for how long | `nedctl` |
| Switch account or role | `nedctl aws login <words>` |
| kubectl on a cluster (pick one; `exit` closes the tunnel) | `nedctl kube` |
| One kubectl command, no shell | `nedctl kube <cluster> -- kubectl get pods -A` |
| A shell on an instance (the one you used last is listed first) | `nedctl shell` |
| The same, in a new coloured Windows Terminal tab | `nedctl shell devops --tab` |
| Your `sm` / SSMshell, already signed in | `nedctl shell --via legacy` |
| The AWS console as the same account and role | `nedctl console` or `nedctl console eks` |
| Keys for a tool that needs them | `eval "$(nedctl aws env)"` |
| kubectl on an AKS cluster (on its bastion) | `nedctl azure kube` or `nedctl azure kube qa payments` |
| A shell on an Azure bastion or machine | `nedctl azure shell qa` |
| Check your machine | `nedctl doctor` |

Press **Tab** to complete commands, cluster names, instance names and the
words `aws login` accepts. `nedctl help <command>` shows examples and flags.

Everything that reaches an account — sign-in, shells, tunnels, the console —
is recorded in an audit trail, and production sessions say so.

## 6. Updating

When a new version is announced (or `nedctl version --check` says so),
download the new file as in step 2 and run its `setup` again — it replaces
the installed copy and refreshes the shell block. `nedctl version` shows what
you have.

## 7. Uninstalling

Delete `~/.local/bin/nedctl` (Windows: `%LOCALAPPDATA%\Programs\nedctl`) and
the block between `# >>> nedctl >>>` and `# <<< nedctl <<<` in your shell's
startup file. nedctl's AWS profiles live in a marked section of
`~/.aws/config`; remove that section too if you like.

---

**Next:** [Troubleshooting](troubleshooting.md) if anything above went wrong ·
[AWS access](aws.md) and [Azure access](azure.md) for every option · [Security](security.md) for how it
keeps you safe.
