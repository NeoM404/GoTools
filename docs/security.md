# nedctl security model

This page is written for Information Security reviewers. It says what nedctl
touches, what it never does, and what it relies on AWS to enforce.

**nedctl is not an access control.** Every control that matters lives in IAM
Identity Center, IAM, Session Manager and EKS, and nedctl cannot bypass any
of them. Its job is to make the secure path the easiest one: no pasted keys,
your own identity everywhere, and a record of every access.

## Secrets: what nedctl touches

| Secret | Does nedctl handle it? | How |
|---|---|---|
| Identity Center access token | Reads it, for one purpose | Read from the AWS CLI's own cache (`~/.aws/sso/cache`) only to list the caller's account assignments. It is sent only to the Identity Center portal endpoint, in a request header, over TLS 1.2+, and redirects are refused. It is never written, logged, or put on a command line where other users could see it in the process list. |
| AWS role credentials (access key, secret, session token) | **No**, by default | Generated profiles make the AWS CLI fetch and cache short-term credentials itself, for one account and role, when used. |
| The same, for tools that need keys (`aws env`, `shell --via legacy`) | Passes them on, on request | Obtained from `aws configure export-credentials` and validated. They are either handed to one child process's environment, or printed to stdout for `eval`. nedctl refuses to print them onto a terminal screen without `--show`. The export is recorded; the values never are. |
| EKS tokens | **No** | Kubeconfigs use `aws eks get-token` as an exec plugin. No token is stored. |
| ServiceNow / SIEM tokens | Reads them from the environment | Only the name of the environment variable is in config. Sent over HTTPS only. |

A test checks that no Identity Center token, access key, secret or EKS token
ever reaches the audit log (`TestE2EEngineerJourney`).

## Identity

- **Sign-in:** the AWS CLI's own Identity Center flow (`aws sso login`,
  browser or device code). nedctl never sees a password.
- **Least privilege by default:** a sign-in produces a profile for **one**
  account and role. Signing in to every account at once is break-glass only:
  it needs a recorded reason, uses only the configured break-glass roles, and
  every resulting sign-in is flagged for review. Identity Center decides who
  holds those roles.
- **Verified:** every new profile is checked to act in the chosen account
  before use. A mismatch is refused and recorded.
- **Your identity end to end:** `shell` runs Session Manager, and `connect`
  runs `kubectl`, as the engineer's own SSO role. CloudTrail, Session Manager
  and EKS therefore record the person, not a shared box or pipeline role.

## Audit trail

- Every access (`aws-login`, `ssm-session`, `eks-connect`,
  `legacy-ssm-tool`, `aws-export-credentials`, `ec2-start`/`ec2-stop`, and
  the cluster credential commands) writes a start event **before** acting.
  If the event cannot be written, the action does not happen.
- The log is hash-chained and file-locked. `nedctl audit verify` detects any
  edit, insertion or deletion (tested).
- Events are forwarded to the SIEM (Splunk HEC or JSON) when configured. The
  local log stays authoritative even if the SIEM is down.
- `nedctl evidence` builds an auditor pack for a quarter or month, with a
  SHA-256 for chain of custody. It lists for review: break-glass use,
  production access without a change record, unverified records, and
  incomplete sessions.
- **Limitation:** the log is written by a client the engineer runs. It is
  evidence of intent and attribution, not proof of everything that happened.
  The authoritative records are CloudTrail, Session Manager session logs and
  EKS control-plane audit logs. nedctl's job is to make sure those name a
  person.

## Network and processes

- nedctl itself connects only to: the Identity Center portal, plus ServiceNow,
  the SIEM collector and an inventory URL when configured. All are HTTPS,
  TLS 1.2+, and redirects to plain HTTP are refused. Everything else goes
  through the AWS CLI, `kubectl` and the Session Manager plugin.
- Subprocesses are started directly with argument lists, never through a
  shell. Each has a deadline, and on Unix is killed with its whole process
  group. Interactive sessions are bounded by `aws.sessionTimeout`.
- Values from AWS are validated before they reach a command line or file:
  account IDs, role names, instance IDs, cluster names, EKS endpoints and
  certificate data. Writes to the shared `~/.aws/config` touch only nedctl's
  marked section, and refuse to overwrite a section someone else owns.
- `connect` keeps TLS verification. kubectl checks the cluster's own
  certificate under its EKS hostname through the tunnel; a tampered hostname
  fails (tested with the real `kubectl`).

## Supply chain

| Control | Status |
|---|---|
| Zero third-party Go dependencies | Enforced in CI (`make deps-check`) |
| `govulncheck` on our code and the standard library | Every build and nightly |
| Static, reproducible builds (`CGO_ENABLED=0`, `-trimpath`) | `make repro` proves byte-identical output |
| SHA-256 checksums for release binaries | `make checksums` |
| Pinned analysis tools | `staticcheck` and `govulncheck` versions pinned |
| Unit, race and end-to-end tests | Every build (`make ci`) |
| Binary signing (cosign) and SBOM | Recommended next step, not yet in place |

## What we ask Information Security to configure

nedctl works without these. They are what turn the secure path into an
enforced one.

| # | Control | Why |
|---|---|---|
| 1 | Session Manager **Run As** a named user per person (`SSMSessionRunAs`), never `root` | Per-person shells and history, and no reading other people's files |
| 2 | Session Manager **session logging** to S3/CloudWatch, KMS-encrypted | A record of what was run, not only who connected |
| 3 | `ssm:StartSession` conditioned on the instance **access-level tag** | The 0–4 levels become a control |
| 4 | **Permission sets per environment**, with shorter sessions for prod | Least privilege by default |
| 5 | A separate **break-glass permission set** for two named admins | Wide access only through a named, audited path |
| 6 | **Devops role trust** limited to the Azure DevOps pipeline | People and pipelines stop sharing an identity |

## Known limitations and open items

- `shell --via legacy` assumes `sm`/SSMshell read the standard AWS credential
  environment variables. This is to be confirmed with their maintainers.
- The Terraform under `deploy/terraform/eks-access-entries` has not been run
  through `terraform validate` in CI.
- Whether EKS access entries need SSO role ARNs with or without the
  `/aws-reserved/sso.amazonaws.com/` path is to be tested in dev.
- Release binaries are checksummed but not yet signed.
