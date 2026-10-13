# EKS upgrade readiness for AWS DevOps Agent

AWS DevOps Agent runs in AWS, not on your machine, so it can't start
`nedctl mcp` locally. Give it nedctl's evidence instead:

1. **The skill.** Upload `SKILL.md` (in this folder) as a skill in your
   DevOps Agent space. It's the same skill Copilot, Kiro and Claude Code use.
2. **The evidence.** A pipeline you already trust runs the read-only check on
   a schedule, or before a change, and keeps the JSON as an artifact:

   ```bash
   nedctl upgrade-check --aws-env dev,ete,qa --match <squad> -o json > readiness.json
   nedctl upgrade-check <cluster> --report upgrade-<cluster>.md
   ```

   Point the agent at that artifact, for example in S3 where the agent space
   can read it, or paste it into the conversation.
3. **Where the agent can read EKS itself** (its own IAM role in the account),
   it can also call the EKS APIs the skill names (`ListInsights`,
   `DescribeInsight`, `DescribeAddonVersions`). nedctl's JSON already has
   them under `facts`.

A remote MCP endpoint for nedctl (HTTP, inside the bank's network, behind
single sign-on) is the next step once DevOps Agent is enabled for the team.
The tools and their JSON stay the same.
