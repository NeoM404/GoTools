# Bridge: Mac ⇄ GitHub ⇄ WSL workstation ⇄ Azure DevOps

This file lives on the **`bridge`** branch of the GitHub repo only. It never
goes to `main` and never goes to Azure DevOps. It carries two things:

1. **Steps** for the workstation (written on the Mac).
2. **Logs** from the workstation when something fails (pasted on the workstation).

**Azure DevOps `main` is the source of truth.** GitHub `main` is a mirror of it,
refreshed after every merge, so the Mac and the workstation always start from
the same code.

---

## ⚠ Rules before you paste anything here

The GitHub repo is **public**. Everything in this file can be read by anyone.

- **Never** paste tokens, PATs, passwords, access keys, session tokens, cookies.
- **Redact** before pasting: AWS account IDs (12 digits → `1111…`), ARNs,
  internal hostnames and URLs (`*.nedbank.*`, `*.nedcloud.*`, proxy
  addresses), IP addresses, usernames/emails, cluster and instance names if
  they reveal anything sensitive.
- Paste **only the failing step's lines** — about 20 lines above the error is
  enough.
- When in doubt, describe the error in words instead of pasting it.

---

## One-time setup on the workstation

```bash
cd <repo>
git remote -v                     # expect: ado (Azure DevOps) and github
git fetch github
git switch bridge                 # this file
git switch main                   # back to code
```

Pushing to GitHub needs your GitHub token at the password prompt. Keep it out
of files and commands:

```bash
git config --global credential.helper 'cache --timeout=3600'
```

---

## The loop

### A. A change arrives from the Mac

The Mac pushes each change as a branch named `claude/<topic>` to GitHub, and
the status table below says which one.

```bash
git fetch github
git fetch ado
# The change must sit on top of what ADO has:
git merge-base --is-ancestor ado/main github/claude/<topic> && echo OK
# Send it to Azure DevOps as a branch:
git push ado github/claude/<topic>:refs/heads/claude/<topic>
```

Then in Azure DevOps: **Repos → Pull requests → New**, `claude/<topic>` →
`main`. CI runs on the pull request.

### B. CI (or anything else) fails

```bash
git switch bridge && git pull github bridge
# edit github.md: add an entry under "Log" (newest first) — see the template
git commit -am "log: <topic> — <step that failed>"
git push github bridge
git switch main
```

Then tell Claude on the Mac: "log pushed". The fix comes back as a new commit
on the same `claude/<topic>` branch; repeat A (push the branch to ADO again —
the pull request updates itself).

### C. After the pull request is merged in Azure DevOps

Mirror ADO `main` to GitHub so the next change starts from it:

```bash
git fetch ado
git push github ado/main:main
git switch main && git pull ado main
```

Then tell Claude: "merged".

### D. Releasing

Only from ADO, after the merge (C):

```bash
git fetch ado && git switch main && git pull ado main
git tag -a vX.Y.Z -m "nedctl X.Y.Z" && git push ado vX.Y.Z
```

---

## Status

| Branch | What | State |
|---|---|---|
| `claude/ci-tool-path` | Makefile finds staticcheck and govulncheck in `$(GOBIN)` (fixes the CI static-analysis failure); test uses a placeholder Identity Center instance ID | Ready: do **A**. If you already applied the python fix on `fix/ci-tool-path`, use this branch instead and delete that one |

---

## Log

<!-- Newest first. Template:

### YYYY-MM-DD — <branch> — <pipeline/step or command>
**What I ran:** `...`
**Where:** CI pipeline / release pipeline / WSL / Windows
**Result:**
```
<redacted lines>
```
-->
