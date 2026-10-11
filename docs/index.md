# nedctl

**One sign-in a day, then one command to a cluster, an instance or the AWS
console — as your own identity, with nothing pasted and every access
recorded.**

nedctl is the platform team's command-line tool for reaching AWS accounts,
EC2 instances and private EKS clusters. It signs you in with IAM Identity
Center, colours your prompt and terminal tab by environment so production is
always obvious, and works beside `sm` and SSMshell.

## Start here

| I want to… | Read |
|---|---|
| Install nedctl and use it today | **[Getting started](getting-started.md)** |
| Learn every AWS command and option | [AWS access](aws.md) |
| Fix something that is not working | [Troubleshooting](troubleshooting.md) |
| Understand the security model | [Security](security.md) |
| Look up any command, flag or setting | [Reference](nedctl.md) |
| See which other CLIs we standardise on | [Ecosystem tools](ecosystem-tools.md) |
| Build, release or change nedctl | [For maintainers](maintainers.md) |

## The five commands you will use

```bash
nedctl aws login lms dev    # sign in, pick an account and role
nedctl kube                 # kubectl on a cluster (pick one; tunnel handled)
nedctl shell                # a shell on an instance (Session Manager)
nedctl console eks          # the AWS console, same account and role
nedctl                      # who am I signed in as, and for how long
```

Stuck? `nedctl help <command>` shows examples, and `nedctl doctor` checks
your machine.
