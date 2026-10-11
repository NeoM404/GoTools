# Bridge: Mac ⇄ GitHub ⇄ WSL workstation ⇄ Azure DevOps

This file lives on the **`bridge`** branch of the GitHub repo only. It never
goes to `main` and never goes to Azure DevOps. It holds the **steps** for the
workstation and the **status** of each change. Errors go to Claude in the chat.

**Azure DevOps `main` is the source of truth.** GitHub `main` holds the same
files (Claude keeps it in step after every merge), so changes made on the Mac
always start from what ADO has.

---

## ⚠ Rules before you paste an error anywhere

The GitHub repo is **public**, and chat logs travel too. Redact first.

- **Never** paste tokens, PATs, passwords, access keys, session tokens, cookies.
- **Redact** before pasting: AWS account IDs (12 digits → `1111…`), ARNs,
  internal hostnames and URLs (`*.nedbank.*`, `*.nedcloud.*`, proxy
  addresses), IP addresses, usernames/emails, cluster and instance names if
  they reveal anything sensitive.
- Paste **only the failing step's lines** — about 20 lines above the error is
  enough.
- When in doubt, describe the error in words instead of pasting it.

---

## How changes move (one way — no GitHub token on the workstation)

The workstation only **fetches** from GitHub (the repo is public, so no
login is needed) and pushes to **Azure DevOps**. Commit IDs differ between
GitHub and ADO (the ADO history was rewritten); that does not matter,
because changes move as **files**.

### A. A change arrives from the Mac

The Mac pushes it as branch `claude/<topic>`; the Status table says which.

```bash
cd <repo>
git fetch github && git fetch ado
git diff --stat refs/remotes/ado/main refs/remotes/github/claude/<topic>   # only the files the change touches
git switch -C claude/<topic> refs/remotes/ado/main
git restore --source=refs/remotes/github/claude/<topic> --staged --worktree :/
git status --short                                                         # same files as the diff above
git commit -m "<message from the Status table>"
git push ado claude/<topic> --force
```

Then in Azure DevOps: **Repos → Pull requests → New**, `claude/<topic>` →
`main`; complete it once CI is green. Tell Claude "merged".

Always use the full names `refs/remotes/ado/…` and `refs/remotes/github/…`:
short names can be ambiguous.

### B. Something fails

Paste the redacted error lines into the chat with Claude (rules above). The
fix arrives as a new commit on the same `claude/<topic>` branch: repeat A.

### C. After a merge

Nothing to do on the workstation. Claude moves GitHub `main` to the merged
files. To check the two are in step (should print nothing):

```bash
git fetch github && git fetch ado
git diff --stat refs/remotes/ado/main refs/remotes/github/main
```

### D. Releasing

From Azure DevOps only:

```bash
git fetch ado && git switch main && git pull
git tag -a vX.Y.Z -m "nedctl X.Y.Z" && git push ado vX.Y.Z
```

---

## Status

| Branch | What | State |
|---|---|---|
| `claude/ci-tool-path` | Makefile finds staticcheck and govulncheck in `$(GOBIN)` (fixes the CI static-analysis failure); test uses a placeholder Identity Center instance ID | Sent to ADO as a PR. Waiting for "merged" + CI result |

---
