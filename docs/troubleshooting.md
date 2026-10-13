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
The terminal was opened without nedctl's shell code, so nothing can switch
its `AWS_PROFILE`; nedctl warns about this. Run `nedctl setup` (or redo its
shell step) and open a new terminal: from then on every sign-in in a
terminal switches that terminal by itself. `echo $NEDCTL_SHELL_ID` prints a
number when the shell code is loaded. Meanwhile, run the `export` line
nedctl prints.

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

## Azure (AKS through the bastions)

**`Azure access is not set up`**
Your build has no bastions in it. Add them under `azure.bastions` in
`~/.config/nedctl/config.json` — see [Azure access](azure.md#2-the-bastions).

**`could not reach aks-qa over SSH`**
Run `ssh aks-qa` yourself: the message it gives is the real one. Usually
the VPN, a key that is not loaded (`ssh-add -l`), or a name your
`~/.ssh/config` does not know. `nedctl doctor` checks each bastion's port
without logging in.

**`no such host` for a bastion in doctor**
The bastion is given as an alias (`aks-qa`) your `~/.ssh/config` does not
define. Add `Host aks-qa` with `HostName <address>`, or put the address in
`azure.bastions`.

**The passphrase is asked every time**
No SSH agent in this terminal. WSL/Linux: run `nedctl setup` again and open
a new terminal. Windows: start the `ssh-agent` service (see
[Azure access](azure.md#3-the-ssh-agent-type-your-passphrase-once)).

**`there is no kube-context "…" on <bastion>`, or a new cluster is missing**
nedctl's remembered list is out of date: `nedctl azure clusters qa
--refresh`. If the bastion itself lacks the context, ask the platform team.

**Strange prompt or no colour on the bastion**
nedctl starts bash with your own `~/.bashrc`, then adds the label. For a
machine without bash, or to keep the prompt untouched, use
`nedctl azure shell <name> --plain`.

## Debugging (`nedctl debug`)

**`The cluster refuses it (server-side dry run)`**
An admission policy (Pod Security, Gatekeeper, Azure Policy) does not allow
that pod there. Try a smaller `--profile`, or another namespace with `-n`;
nothing was created.

**`the debug pod did not start: … ErrImagePull`**
The cluster cannot pull the image, usually because it may only use an
internal registry. Map the short names to it under `debug.images` — see
[Debugging](debug.md#images).

**`kubectl debug: … it needs kubectl 1.27 or newer`**
`debug attach` uses `kubectl debug --profile`. Update kubectl on your
machine (EKS) or ask for it on the bastion (AKS).

**A debug pod was left behind**
It ends by itself at its time limit (2h). `nedctl debug ls` shows it;
`nedctl debug clean` removes it now.

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
