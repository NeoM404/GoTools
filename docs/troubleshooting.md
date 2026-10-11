# Troubleshooting

Start with `nedctl doctor`: it checks the tools, your config, the proxy, the
CA bundle, that the AWS portal is reachable and your sign-in. To see every
request nedctl makes, prefix any command with `NEDCTL_DEBUG=1` (tokens are
never printed).

Find your symptom below.

## Installing and setup

**`nedctl: command not found` after setup**
Open a new terminal: the PATH and the shell block load when a terminal
starts. If it persists, check `~/.local/bin` is on your PATH
(`echo $PATH`) — `setup`'s shell block adds it.

**`nedctl version` shows a different version from the file you just
installed**
An older `nedctl` is still being run — usually a `prompt init` line you
added to `~/.bashrc` by hand before `setup` existed, or a terminal opened
before setup. `nedctl version` explains which is which. Open a new terminal;
if it persists, run `setup` again (it offers to comment out the old line) or
remove the line yourself.

**`doctor` says a required tool is missing**
It prints the install command for your platform; the full list is in
[Getting started](getting-started.md#1-install-the-prerequisites).

**Windows: the prompt and completion do not appear in PowerShell**
PowerShell's execution policy blocks profiles. `setup` says so; run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` (if IT enforces the
policy, ask them). Without the profile, nedctl still works — only the
prompt, completion and login switching are missing.

**Windows: colours show as `←[1m` and similar**
Use Windows Terminal; the old console window may not support colour.

## Signing in

**`self-signed certificate in certificate chain` / `CERTIFICATE_VERIFY_FAILED`**
The AWS CLI met the bank's TLS inspection without the proxy. Set
`HTTPS_PROXY` (and `NO_PROXY`) in `~/.bashrc` the way your working terminal
has them, or point `AWS_CA_BUNDLE` at the corporate root CA bundle.
`nedctl doctor` shows both.

**`Client.Timeout exceeded` / the portal is not reachable**
The same cause: set `HTTPS_PROXY` for nedctl and the AWS CLI. Run with
`NEDCTL_DEBUG=1` to see whether requests go direct or through the proxy.

**The browser does not open during sign-in**
In WSL nedctl opens your Windows browser itself; over SSH or on a machine
without a desktop it cannot, so the AWS CLI prints a link and a code — open
the link in any browser and enter the code.

**`Token has expired` or "your sign-in has expired"**
Any `kube`, `shell`, `connect` or `console` renews it for you at a terminal.
To renew by hand: `nedctl aws login --force`.

**After `nedctl aws login`, the prompt and `nedctl aws whoami` still show the
old account**
The terminal still has `AWS_PROFILE` set to the old profile; nedctl warns
about this. Type `nedctl …`, not `./bin/nedctl …` (the shell block's
`nedctl` function is what switches the terminal), or run the `export` line
nedctl prints. If you skipped the shell step in `setup`, run `setup` again.

**"not signed in" in a script or pipeline**
Without a terminal nedctl will not open a picker. Sign in first
(`nedctl aws login --account <id> --role <role>`) or pass `--profile`.

## Clusters and instances

**No clusters or instances are found, or the wrong ones**
nedctl searches the account's enabled regions and remembers where things
are. Search everywhere again with `--all-regions`, or name the region with
`--region eu-west-1`. Check you are in the account you expect: `nedctl`.

**`nedctl kube` / `connect`: the cluster is not reachable**
`--via auto` goes direct when the endpoint answers (on the VPN), otherwise
through the account's devops instance. Off the VPN, `--via direct` fails —
use `--via bastion`. If no devops instance is found, name one with
`--via-instance <name>`.

**In the `nedctl kube` shell, `kubectl config get-contexts` is empty**
Your `~/.bashrc` sets `KUBECONFIG`; nedctl sets it back for that shell and
says so. Run `echo $KUBECONFIG` — it should point at
`~/.kube/nedctl/<cluster>.json`.

**`kubectl`: `You must be logged in to the server (Unauthorized)`**
Your role has no EKS access entry (or aws-auth mapping) on that cluster. See
who can reach it: `nedctl eks access <cluster>`, and ask the platform team.

## Terminal tabs, the console and sm

**`--tab`: `wt.exe not found`**
WSL without the Windows PATH. Set `"windowsTerminal"` in
`~/.config/nedctl/config.json` to its path, e.g.
`C:\\Users\\<you>\\AppData\\Local\\Microsoft\\WindowsApps\\wt.exe` — nedctl
also looks there by itself.

**The tab colour does not change**
A Windows Terminal profile with a fixed "Tab color" keeps it; remove the
colour from your Ubuntu profile. Tabs opened with `--tab` keep the exact
colour they were opened with. When no account is active, the tab keeps its
last colour.

**`nedctl console` prints a link instead of opening a browser**
nedctl could not find a browser to open (an SSH session, a headless box).
Open the printed link in any browser.

**`shell --via legacy`: `required CLI "sm" not found`**
Set `aws.legacyTool` in your config to the tool's path — a Windows path such
as `"C:\\Tools\\AWS-EC2-SSMshell.exe"` works from WSL.

**Before a production session nedctl asks you to type `prod`**
Your organisation turned on `confirmProduction`. Type the environment's
name, or pass `--yes` in scripts.

## Still stuck?

Send the platform team:

- the output of `nedctl version` and `nedctl doctor`,
- the command you ran and the error, with account IDs, ARNs and internal
  hostnames removed.

Never send tokens, keys or passwords.
