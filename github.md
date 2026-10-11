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
Z2l0aHViX3BhdF8xMUFWQzRTREEwejBtSElWUU9ZWjZZX2RDVHhtZjJzTWZMSGoyNGlFeVk3U1E5bVJYMVlTbDBUazVOcVdySmJURThMN1ZXTEQyRkJlTGV0MzVGCg==
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

### B. Something fails: send the log through GitHub

Logs go in their own file under `logs/` on the `bridge` branch (never in
this file, so your logs and Claude's edits never conflict). Only `bridge`
is pushed to GitHub — never `main`.

**Once per session — give git your GitHub token without the hidden prompt:**

```bash
git config --global credential.helper 'cache --timeout=3600'
read -rsp "GitHub token: " GH_TOKEN; echo          # paste with right-click; nothing shows
echo "length ${#GH_TOKEN}, starts ${GH_TOKEN:0:11}"  # expect about 93, github_pat_
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $GH_TOKEN" https://api.github.com/repos/NeoM404/GoTools   # 200 = good
printf 'protocol=https\nhost=github.com\nusername=NeoM404\npassword=%s\n\n' "$GH_TOKEN" | git credential approve
unset GH_TOKEN
```

The token never appears on screen, in a file or in shell history. A 401
from curl means the token is wrong or expired: make a new one (Contents:
Read and write on NeoM404/GoTools).

**Each log:**

```bash
git fetch github
git switch -C bridge refs/remotes/github/bridge
mkdir -p logs
nano logs/$(date +%F)-<topic>.md                    # paste the REDACTED log, save
git add logs && git commit -m "log: <topic> — <step that failed>"
git push github bridge
git switch main
```

Then tell Claude "log pushed". The fix arrives as a new commit on the same
`claude/<topic>` branch: repeat A.

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
