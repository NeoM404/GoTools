# nedctl

**One command to a cluster, an instance or the AWS console — AWS or Azure,
with nothing pasted and every access recorded.**

nedctl is the platform team's command-line tool for reaching AWS accounts,
EC2 instances and private EKS clusters, and AKS clusters through the Azure
bastions. It signs you in to AWS with IAM Identity Center, takes you to the
right AKS bastion with your cluster selected, colours your prompt and
terminal tab by environment so production is always obvious, and works
beside `sm`, SSMshell and your SSH setup.

## Start here

| I want to… | Read |
|---|---|
| Install nedctl and use it today | **[Getting started](getting-started.md)** |
| Learn every AWS command and option | [AWS access](aws.md) |
| Use AKS clusters and Azure machines | [Azure access](azure.md) |
| See why my app is failing, read its logs, reach it from my laptop | [For developers](developers.md) |
| Check the fleet's health, run commands across clusters, runbooks, drain nodes | [For DevOps](operations.md) |
| Check posture, images and access; evidence for reviews | [For DevSecOps](security-checks.md) |
| Debug pods, nodes and network on a cluster | [Debugging](debug.md) |
| Fix something that is not working | [Troubleshooting](troubleshooting.md) |
| Understand the security model | [Security](security.md) |
| Look up any command, flag or setting | [Reference](nedctl.md) |
| See which other CLIs we standardise on | [Ecosystem tools](ecosystem-tools.md) |
| Build, release or change nedctl | [For maintainers](maintainers.md) |

## The commands you will use

```bash
nedctl aws login lms dev    # AWS: sign in, pick an account and role
nedctl kube                 # AWS: kubectl on an EKS cluster (tunnel handled)
nedctl shell                # AWS: a shell on an instance (Session Manager)
nedctl console eks          # AWS: the console, same account and role
nedctl azure kube qa        # Azure: kubectl on an AKS cluster, on the QA bastion
nedctl azure shell qa       # Azure: a shell on the QA bastion
nedctl debug pod            # a netshoot pod to debug from (shown and approved first)
nedctl                      # where am I signed in, and the commands above
```

Stuck? `nedctl help <command>` shows examples, and `nedctl doctor` checks
your machine.
