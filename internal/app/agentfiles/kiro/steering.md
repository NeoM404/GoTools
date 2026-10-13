---
inclusion: always
---

# nedctl: reading the bank's clusters

The bank's EKS and AKS clusters are private. Reach them only through the
`nedctl` MCP server's read-only tools, and never ask for kubeconfigs, tokens
or keys.

- Upgrade readiness: `upgrade_check`. Follow the eks-upgrade-readiness
  skill: verify each `verify[]` add-on at its URL, and treat `unassessed[]` as
  open, never as passed.
- What changed recently: `changes`. Certificates and support windows:
  `expiry`. Cluster health: `health`. A failing workload: `explain`.
- Never run commands that change a cluster or an AWS account. Plans are for
  an engineer under an approved change record.
