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

Paste the **redacted** error lines into the chat with Claude (rules above) —
the first error and about 20 lines above it is enough. The bank network does
not allow logging in to GitHub from the workstation, so nothing is pushed to
GitHub from there; never put a token in this repo, encoded or not.

The fix arrives as a new commit on the same `claude/<topic>` branch: repeat A.

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
| `claude/docs-squads` | Docs for squads: Home, Getting started, Troubleshooting, wiki page order, maintainer docs moved to `docs/maintainers/`; `doctor` install hints per platform; `setup` offers to disable older `prompt init` lines; `version` warns when another nedctl shadows it. Commit message: `Docs for squads; doctor hints per platform; setup and version catch an old nedctl` | **Ready: do A.** Then tag **v1.0.1** (D) |
| `claude/ci-tool-path` | CI tool path, test isolation, doctor network checks | Merged (CI green); GitHub `main` updated |
