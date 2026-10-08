# Architecture diagrams

Editable draw.io sources (`*.drawio`) with their PNG exports. Icons are the
official AWS Architecture Icons and Azure icons bundled with draw.io
(`mxgraph.aws4.*`, `img/lib/azure2/*`).

| Diagram | Shows |
|---|---|
| [01-system-context](01-system-context.png) | nedctl on the workstation and AKS bastion, AWS, Azure and enterprise services |
| [02-aws-sign-in](02-aws-sign-in.png) | `aws login`: Identity Center sign-in, assignments, one profile, verification, break-glass |
| [03-shell-session](03-shell-session.png) | `shell`: instance picker, Session Manager, legacy `sm` path, coloured tabs |
| [04-connect-tunnel](04-connect-tunnel.png) | `connect`: port-forward through the devops instance to private EKS, TLS and token |
| [05-eks-access-entries](05-eks-access-entries.png) | CONFIG_MAP → API_AND_CONFIG_MAP → API; access entries per role |
| [06-audit-evidence](06-audit-evidence.png) | Audit trail, SIEM forwarding, evidence packs, authoritative cloud logs |
| [07-aks-bastion-inventory](07-aks-bastion-inventory.png) | Azure DevOps inventory pipeline and bastion mode on AKS |
| [08-code-architecture](08-code-architecture.png) | Go package layers and the execx boundary |

Edit a `.drawio` file directly in draw.io (desktop or app.diagrams.net). To
regenerate all of them from code, with draw.io desktop installed:

```bash
cd docs/architecture/generate
python3 d01.py .. && python3 d02_08.py ..
```
