# AI agents: Kiro, GitHub Copilot, Claude Code, AWS DevOps Agent

The bank's clusters are private, and every access goes through a person's
sign-in and an audited path. An AI agent can't reach them directly, and
shouldn't hold credentials to try. nedctl gives agents the evidence instead:
read-only checks run with your access, returned as JSON, and recorded in your
audit trail.

```
agent (Kiro / Copilot / Claude Code)
   │  MCP over stdio — read-only tools only
   ▼
nedctl mcp ──► one nedctl command per call (its own process, no stdin)
   │            -o json, recorded as agent-tool in your audit trail
   ▼
EKS/EC2 APIs (your profile) · kubectl through the SSM tunnel or the AKS bastion
```

## Set it up (when your tool is enabled)

```bash
nedctl agents setup kiro                         # ~/.kiro: MCP server, steering, skill, eks-upgrade agent
nedctl agents setup copilot --dir ~/src/platform # .vscode/mcp.json, .github/agents, .github/skills
nedctl agents setup claude --dir ~/src/platform  # .mcp.json, .claude/skills
nedctl agents setup devops-agent                 # ./nedctl-devops-agent: SKILL.md + how to give it evidence
nedctl agents setup copilot --dry-run            # what it would write
```

`agents setup` only writes new files. If a file already exists, it's left as
it is. If an existing MCP config doesn't list nedctl yet, setup shows the
entry to add rather than editing the file.

| Agent | How it reaches nedctl | Where things go |
|---|---|---|
| **Kiro** (IDE and CLI) | MCP server in `~/.kiro/settings/mcp.json`; the `eks-upgrade` agent for `kiro-cli chat --agent eks-upgrade` | `~/.kiro/steering/nedctl.md`, `~/.kiro/skills/eks-upgrade-readiness/`, `~/.kiro/agents/eks-upgrade.json` |
| **GitHub Copilot** (VS Code agent mode) | `.vscode/mcp.json` in the repository; the `eks-upgrade` custom agent | `.github/agents/eks-upgrade.agent.md`, `.github/skills/eks-upgrade-readiness/` |
| **Claude Code** | `.mcp.json` in the repository | `.claude/skills/eks-upgrade-readiness/` |
| **AWS DevOps Agent** | Runs in AWS, so it can't start `nedctl mcp`. Upload the skill, and give it nedctl's JSON from a pipeline (see its README) | `./nedctl-devops-agent/` |

Tools change their file layouts. If one doesn't pick its file up, check
that tool's documentation for its MCP, skill and agent locations. The
content stays the same.

## The tools

`nedctl mcp tools` lists them. Each is one nedctl command with `-o json`:

| Tool | Runs | For |
|---|---|---|
| `whoami` | `aws whoami` | Which account, role and environment the evidence comes from |
| `list_eks_clusters` | `eks auth` | The account's clusters, versions, auth mode, endpoint exposure |
| `upgrade_check` | `upgrade-check` | EKS upgrade readiness: score, blockers, findings, Insights, add-on compatibility, plan |
| `expiry` | `expiry` | Certificates, CA bundles and version support running out |
| `changes` | `changes` | What changed recently (Secrets never read) |
| `health` | `health` | Cluster health |
| `mesh` | `mesh` | Istio mTLS, sidecar coverage, policies and routing |
| `posture` | `posture` | Risky settings in what runs |
| `explain` | `explain --no-logs` | Why a workload is failing, without its logs |
| `app` / `diff` | `app` / `diff` | One application across environments, side by side |

**What agents never get:**
- logs (they carry personal data);
- `exec`, `cp`, `debug` or port-forwards;
- Secrets;
- anything that changes a cluster or an account;
- your credentials or a kubeconfig.

The bank can narrow or disable agent access in the built-in defaults:

```json
"agents": { "tools": ["upgrade_check", "expiry", "changes", "health"] }
"agents": { "disabled": true }
```

**Every call is recorded** in your audit trail as `agent-tool`, with the
agent's name and the exact nedctl command it became. `nedctl evidence`
includes these records.

**Arguments are names, never flags.** Each tool takes named fields (cluster,
env, namespace, target…). Values must look like names, so an agent can't
slip in `--kubeconfig`, a shell character or anything else. Calls run with no
stdin, so no picker or prompt waits. Where a read would need an elevated-only
role, it's refused rather than asked about.

## The EKS upgrade readiness skill

The skill (`eks-upgrade-readiness/SKILL.md`, the same file for every tool)
tells the agent how to work with the bank's estate:

1. Get the evidence from `upgrade_check`, and never try to reach the cluster
   another way.
2. **Verify what nedctl can't judge offline:**
   - each `verify[]` add-on (cert-manager, Istio, Argo CD, Prisma Cloud
     Defender, Calico…) against its project's supported-versions page;
   - release notes for any version beyond nedctl's tables.
3. Treat anything *not assessed* as open, never passed.
4. Write the readiness report for the change request, with nedctl's plan
   unchanged. **Never run it.**

It complements AWS's sample skill
([aws-samples/sample-eks-upgrade-skill](https://github.com/aws-samples/sample-eks-upgrade-skill)),
which assumes the agent can run `kubectl` and the EKS MCP server against the
cluster itself. Here nedctl does that part, through the bank's access path,
and covers the same eight areas:
- version validation;
- breaking changes;
- deprecated and removed APIs (from `managedFields`, not `-o yaml`);
- add-on compatibility from `describe-addon-versions`;
- node readiness;
- workload risks, including PDB drain blocks and overlaps;
- EKS Upgrade Insights;
- the upgrade plan.

It uses the same READY / GOOD / FAIR / RISKY / NOT READY tiers and a
blocker cap. The agent adds the live web lookups.

## What a session looks like

> **Engineer:** Is payments-eks-qa ready for 1.33?
>
> **Agent:**
> 1. Calls `whoami`, then `upgrade_check {cluster: "payments-eks-qa", target: "1.33"}`.
> 2. Reads the result: 72% FAIR, provisional; no blockers; Karpenter OK;
>    vpc-cni needs v1.19.x before the control plane; a FlowSchema still
>    written by argocd as v1beta3.
> 3. Checks cert-manager v1.15 against cert-manager.io: supported.
> 4. Writes the report and lists what is still open.

Each step leaves an `agent-tool` record in the engineer's audit trail.

## Roadmap

- **A remote MCP endpoint** for AWS DevOps Agent and shared agents: HTTP
  inside the bank's network, behind single sign-on, with the same tools and
  records. Built once the team has DevOps Agent enabled to test against.
- **AKS** in `upgrade_check`, once the AKS upgrade check exists.
