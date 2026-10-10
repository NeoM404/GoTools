# AWS access with nedctl

nedctl replaces copying keys from the AWS access portal with
your own short-lived identity. Every step is recorded. `sm` and SSMshell keep
working, and nedctl can launch them for you already signed in.

| Today | With nedctl |
|---|---|
| Copy access key, secret and session token from the portal | `nedctl aws login`: one browser approval, then pick an account and role |
| Paste them into SSMshell / `sm` | `nedctl shell`, or `nedctl shell --via legacy` to launch `sm` signed in |
| The session starts as `root`; switch to `ec2-user` and paste the keys again | The session runs as your SSO role; cluster access needs no keys on the box |
| `kubectl` on the devops box | `nedctl connect <cluster>`: `kubectl` on your laptop, through the box |

For the reasoning behind each choice, and what Information Security is asked
to configure, see [security.md](security.md).

## Setup

Add an `aws` block to your config (`nedctl init` writes the rest). A complete
example is [`configs/nedctl.aws.example.json`](../configs/nedctl.aws.example.json).

```json
"aws": {
  "startUrl": "https://d-xxxxxxxxxx.awsapps.com/start",
  "ssoRegion": "af-south-1",
  "accountNamePattern": "^(?P<squad>[a-z0-9]+)-(?P<env>dev|ete|qa|prod)$",
  "breakGlassRoles": ["BreakGlass-Admin"]
}
```

| Field | Meaning |
|---|---|
| `startUrl`, `ssoRegion` | The Identity Center access portal and its region. Required. |
| `ssoSession` | Name of the `[sso-session]` nedctl writes (default `nedctl`). |
| `region` | Default region of generated profiles (default `ssoRegion`). Rarely needed: commands find regions themselves (below). |
| `regions` | The exact regions to search, overriding automatic discovery. |
| `profilePrefix` | Generated profiles are named `<prefix>.<account>.<role>` (default `nedctl`). |
| `accountNamePattern` | Optional. By default nedctl reads the account name itself: a leading `[TAG]` is dropped, and the environment is the last part of the name that is one of your `environments` (dev, ete, qa, prod). The squad is what comes before it, less `aws-`, so `[NONPROD] aws-mov-lms-dev` → squad `mov-lms`, env `dev`. Set a regex with named groups `env` and optionally `squad` only for names that don't follow that shape. |
| `accounts` | Explicit `{id, squad, environment}` per account. Overrides the pattern. |
| `breakGlassRoles` | The only roles `aws login --all` may use. |
| `elevatedRolePattern` | Which roles count as elevated (able to change resources). Default: names containing devops, admin, poweruser, breakglass, fullaccess, owner or deploy. |
| `accessLevelTag` | EC2 tag shown as the instance's access level (default `AccessLevel`). |
| `devopsInstance` | Name match for the devops instance `connect` tunnels through (default `devops`). |
| `legacyTool` | What `shell --via legacy` launches (default `sm`; e.g. `AWS-EC2-SSMshell.exe`). |
| `sessionTimeout` | Longest an interactive session may run (default `12h`). |

`environmentColors` (top level) sets tab, picker and prompt colours. The
defaults match the existing tools: dev `#22c55e`, ete `#f97316`, qa `#3b82f6`,
prod `#ef4444`.

You need: AWS CLI v2, the Session Manager plugin, and `kubectl` for `connect`.
Run `nedctl doctor` to check.

## Behind a corporate proxy

nedctl's own HTTPS calls (the Identity Center portal, plus ServiceNow, the
SIEM and an inventory URL when configured) use the same proxy settings as the
AWS CLI: `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`. If the proxy re-signs
TLS with a corporate CA, trust that CA with `SSL_CERT_FILE=<bundle>`, the same
file `AWS_CA_BUNDLE` points at, or add it to the system store.

To see every request nedctl makes, set `NEDCTL_DEBUG=1`. It logs the method,
URL (without its query), the route taken (proxy or direct), the status and the
time taken. Headers are never logged, so tokens stay out of the output:

```bash
NEDCTL_DEBUG=1 nedctl aws login --device-code
# nedctl debug: GET https://portal.sso.eu-west-1.amazonaws.com/assignment/accounts via proxy http://proxy:8080
# nedctl debug: GET https://portal.sso.eu-west-1.amazonaws.com/assignment/accounts -> 200 OK in 412ms
```

## Regions are found for you

Accounts keep clusters and instances in whatever region the squad chose, not
the Identity Center region. So `shell`, `ec2`, `connect` and `eks` don't rely
on the profile's region. They search:

1. **First run in an account:** every region enabled for it (`ec2 describe-regions`).
   Regions an SCP denies are skipped.
2. **After that:** only the regions where something was found, so it's fast. If
   those turn up nothing, every region is searched again.
3. **Overrides:** `--region R` searches one region, and `--all-regions` forces a
   full search. `aws.regions` in config fixes the list.

Results always say which regions were searched, so an empty answer is never
silent. What was found where is remembered per account for 24 hours.

## Sign in: `nedctl aws login`

```bash
eval "$(nedctl aws login)"                       # bash/zsh: sign in if needed, picker, then sets AWS_PROFILE
nedctl aws login --format powershell | iex       # PowerShell
nedctl aws login --account payments-prod --role Platform-ReadOnly   # no picker
nedctl aws login --browser                       # force browser sign-in (default where a browser can open)
```

1. If no valid sign-in is cached, nedctl runs `aws sso login`, the AWS CLI's
   own flow. Where no browser can open here (WSL, SSH, Linux without a
   desktop, such as a devops box), it uses a device code automatically. Open
   the link in any browser, for example on Windows, and confirm the code.
2. It lists **only the accounts and roles Identity Center assigns you**, in a
   picker coloured by environment. Type to filter, enter a number to choose.
   `--account`/`--role` choose without the picker. With no terminal and more
   than one match, it refuses rather than guessing.
3. It writes **one** AWS CLI profile for that account and role, in a marked
   section of `~/.aws/config`. Everything outside that section, including
   profiles `sm` or you wrote, is left byte for byte.
4. It checks that the profile really acts in the chosen account
   (`sts get-caller-identity`), and records the sign-in.

The account list is fetched once per sign-in and reused until you sign in
again, so later logins open the picker straight away. Use `--refresh` after
you've been given a new account. The saved list holds names and IDs only,
never the token.

No AWS keys pass through nedctl. The AWS CLI fetches short-term credentials
for that one account and role when the profile is used. The picker and
messages go to stderr, so stdout carries only `export AWS_PROFILE=…`.

### Elevated roles are marked

A role whose name matches `elevatedRolePattern` can change and delete
resources. Today that includes every `<account>-devops` role. nedctl shows
this wherever it matters:

- **Picker:** the role has an orange ▲, explained in the legend.
- **Sign-in:** a warning, naming a read-only role in the same account if you
  have one, and flagging production accounts.
- **Other places:** `aws whoami` (`"elevated": true` in JSON), the shell banner,
  the prompt (`aws:mov-lms▲[dev]`) and the audit record.

### Break-glass: every account at once

```bash
nedctl aws login --all --break-glass "P1 INC0012345: payments API down in prod"
```

Only for the named admins who hold a break-glass role in Identity Center:

- It needs a reason of at least 20 characters.
- It uses only `breakGlassRoles`.
- Every sign-in is flagged for review in the evidence pack, and a refused
  attempt is recorded too.

Who may use it is decided by Identity Center. nedctl just never signs in to
every account with an ordinary role.

### Who am I: `nedctl aws whoami`

Shows the profile, account, squad, environment, role and ARN, plus how long the
sign-in has left. `-o json` for scripts.

### Credentials for older tools: `nedctl aws env`

```bash
eval "$(nedctl aws env)"; sm        # sm gets the keys without a paste
```

Prints the profile's short-term credentials as environment variables:

- It refuses to print them onto a terminal screen unless you add `--show`.
- It validates the AWS CLI's output before passing it on.
- It records the export. The keys themselves are never recorded.

## A shell on an instance: `nedctl shell`

```bash
nedctl shell                     # picker: NAME, INSTANCE, PRIVATE IP, STATE, TYPE, ZONE, LEVEL
nedctl shell devops              # filter; one match goes straight in
nedctl shell --instance i-0abc…  # by ID or Name tag
nedctl shell devops --tab        # in a new Windows Terminal tab coloured by environment
nedctl shell --via legacy        # launch sm / SSMshell already signed in
nedctl ec2 start payments-batch  # start/stop, confirmed by instance ID in prod
```

The session is `aws ssm start-session` under your own profile. Before it
starts, nedctl sets the terminal title and prints a banner in the
environment's colour. In production it adds a warning that the session is
recorded. `--tab` works from Windows and from WSL: the tab re-enters the same
distribution.

## Straight to a cluster: `nedctl connect`

```bash
nedctl connect payments-eks-prod            # holds the tunnel; Ctrl-C closes it
export KUBECONFIG=~/.kube/nedctl/payments-eks-prod.json
kubectl get nodes
```

1. Looks the cluster up under your profile: endpoint, CA and region.
2. Opens a Session Manager port-forward through the account's devops instance
   to the private endpoint (`AWS-StartPortForwardingSessionToRemoteHost`).
3. Writes an isolated kubeconfig, readable only by you (`0600`):
   - The server is the local tunnel.
   - TLS is still verified against the cluster's CA under its EKS hostname
     (`tls-server-name`).
   - The token comes from `aws eks get-token` as your SSO role.
   - Nothing long-lived is stored.

`--tab` holds the tunnel in its own coloured tab. `--via-instance` and
`--port` override the defaults. `guard` and `prompt` treat the context like
any other, so production still shows red.

## Listing clusters

```bash
nedctl clusters list          # the signed-in account's EKS clusters, every region
```

With no fleet inventory configured, which is the usual case for AWS users,
this asks AWS directly. The output shows each cluster's environment, region,
version, endpoint exposure and authentication mode.

## One command to a cluster: `nedctl kube`

`kube` is `connect` without the second terminal:

```bash
nedctl kube                                        # no name: pick from the account's clusters (last used first)
nedctl kube lms-eks-cluster-ete                    # a shell with kubectl ready; exit closes the tunnel
nedctl kube lms-eks-cluster-ete -- kubectl get ns  # one command; its exit code is kube's exit code
```

It works the same way as `connect`: it finds the region and the devops
instance, and applies the same audit and change control. The tunnel runs in
the background, so Ctrl-C in your shell interrupts your command, not the
tunnel. Its output goes to `~/.local/state/nedctl/tunnels/<cluster>.log`.
Nothing starts until the tunnel actually accepts connections. If it fails,
you see why, and no shell opens.

**How it reaches the cluster:** `--via auto` (the default) connects
**directly** when the endpoint answers from your machine, for example on the
VPN, or for a public endpoint open to your address. Otherwise it tunnels
through the devops instance.

- `--via direct` insists on a direct connection.
- `--via bastion` always goes through the devops instance.
- `--via-instance NAME` tunnels through a named instance.

Direct connections verify TLS against the cluster's CA and use the same
`aws eks get-token` as your SSO role. They are recorded as `direct to <endpoint>`.
If neither route works, nedctl says why for both: the endpoint's exposure,
and the missing instance.

In bash and zsh, your own startup files load first (`~/.bashrc`, or
`~/.zshenv` and `~/.zshrc`). Then nedctl sets `KUBECONFIG` back to the
cluster's kubeconfig, and says so if a startup file had changed it. It also
prefixes the prompt with `⎈ <cluster> <ENV>` in the environment's colour.
Other shells start unchanged, with `KUBECONFIG` and `NEDCTL_KUBE` set. The
ready message prints the `export KUBECONFIG=…` line for other terminals.

## Moving clusters to access entries: `nedctl eks`

```bash
nedctl eks auth --all-profiles             # mode, endpoint exposure, next step per cluster
nedctl eks auth --fail-on-configmap        # exit 1 while any cluster is CONFIG_MAP only
nedctl eks access payments-eks-prod        # who can reach it, with which policy and scope
```

[`deploy/terraform/eks-access-entries`](../deploy/terraform/eks-access-entries)
has the Terraform. It switches a cluster to `API_AND_CONFIG_MAP` (`aws-auth`
keeps working, and the switch is one-way) and gives each Identity Center role
and the pipeline their own entry.

## Your prompt

```bash
PS1='$(nedctl prompt --shell bash) \w\$ '        # bash
PROMPT='$(nedctl prompt --shell zsh) %~ %# '     # zsh (setopt prompt_subst)
```

Shows `k8s:<context>[env]` and `aws:<squad>[env]` in the environment's colour,
with production in bold capitals. It reads only local files and never fails.

## Change records

Change control is switched off for now (`"changeControl": {"enabled": false}`).
No record is required. One you pass is still format-checked and recorded, and
the command says change control is off. Set `"enabled": true` to require
`--change-record` for the environments in `requireFor`. `shell`, `connect`,
`kubeconfig` and `login` all honour it. `--break-glass "<reason>"` is the
emergency path.

## What gets recorded

Every action below is written to the hash-chained audit log, and forwarded to
the SIEM when `audit.forward` is set. Each is included in
`nedctl evidence --period 2026-Q4`.

| Action | When |
|---|---|
| `aws-login` | Each account sign-in (break-glass flagged) |
| `aws-export-credentials` | `aws env` |
| `ssm-session` | `shell` |
| `legacy-ssm-tool` | `shell --via legacy` |
| `eks-connect` | `connect` |
| `ec2-start`, `ec2-stop` | `ec2` |
