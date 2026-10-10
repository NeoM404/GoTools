# bankctl Fleet Tooling Roadmap

Expanding GoTools for a multi-cloud AKS + EKS fleet under banking regulatory constraints.

Sep 29, 2026 · @Neo Mthimkhulu

## Why now

Every bankctl feature is a pure function of the fleet inventory, and that inventory is hand-maintained JSON.

`guard`, `fleet versions`, `kubeconfig` and prod detection all read the same `Fleet` struct, loaded by `LoadFile` or `LoadURL` from a static document. At 80+ clusters that file goes stale within a week. Every downstream feature silently inherits the staleness.

The regulatory consequence outweighs the operational one: completeness cannot be proven. When an auditor asks whether the inventory lists every cluster, a hand-maintained file can only assert an answer, never evidence one.

This roadmap treats that as the root constraint. Most items below either fix it or become possible once it is fixed.

## Horizon 1 — derive the inventory, then find what is missing from it

Reconcile the declared inventory against what the clouds actually report, and treat the gap as a finding.

```
bankctl inventory sync      # enumerate reality from cloud APIs
bankctl inventory diff      # declared vs actual
```

The payoff is **shadow-cluster detection**: any cluster present in AWS or Azure but absent from the inventory is ungoverned infrastructure. Nothing off-the-shelf reports this, because it depends on your inventory being the control record. That places it squarely inside the build-the-glue line the README already draws.

This stays zero-dependency. `aws eks list-clusters --output json` and `az aks list -o json` fan out through the existing `internal/cloud` pattern, parse with `encoding/json`, and parallelise with goroutines. It preserves the property `cloud.go` was deliberately built around: bankctl never handles long-lived secrets, it rides the operator's existing SSO session.

It also maps onto DORA's register-of-information duty, in force since January 2025. A continuously reconciled inventory is that register for the Kubernetes estate, rather than a spreadsheet maintained alongside one.

**Open question:** how many AWS accounts and Azure subscriptions are in scope? Subprocess fan-out across roughly 40 accounts may take minutes, which is tolerable nightly but not interactively.

## Guard is an affordance, not a control

`bankctl guard` runs on the engineer's laptop, so the engineer can skip it. Auditors draw a hard line between a usability affordance and a control, and a client-side check will not survive that scrutiny.

This is worth stating plainly in the roadmap because the fix is not more CLI work. Real enforcement sits in two places, neither of them a binary the operator chooses to run:

| Layer | Mechanism | Status |
| --- | --- | --- |
| Credential issuance | Short-lived, JIT-approved credentials (Teleport `tsh kube login`) | Already recommended in `docs/ecosystem-tools.md` |
| Admission | Kyverno or Gatekeeper policy at the API server | Not yet in scope |
| Client feedback | `bankctl guard --block` | Built — keep as the fast feedback loop |

Keep `guard`. It catches mistakes seconds before they happen, which matters. Just do not enter it into audit evidence as the control that prevents production access.

There is also a concrete fragility underneath it. `kube.IsProd` regex-matches the kube-context *name*, so a single badly named cluster is invisible to the guard. Derive `environment` from cloud resource tags instead, set by the landing zone and far harder to get wrong than a naming convention, keeping the regex as fallback. That is a contained change to `internal/kube` plus one inventory field, and it becomes straightforward once Horizon 1 lands.

## Horizon 2 — evidence generation

This is the highest-value thing to build, because it is the least substitutable: it has to match your control framework, so no vendor can sell it to you.

`cmdLogin` already prints "Changes require a change record." Close that loop and make it structured:

```
bankctl login eks-payments-prod-euw1 --change-record CHG0012345
```

Three pieces follow from it:

1. **Validate** the change-record reference against ServiceNow before granting access, rejecting an access attempt with no open CR.
2. **Emit** a structured audit event per prod-touching invocation — who, which cluster, which command, when, under which CR — to the SIEM.
3. **Assemble** the auditor pack: `bankctl evidence --period Q3` renders the quarter's prod access, each entry tied to its change record.

The value is in linking access to change management, which is exactly what SOX and DORA reviewers probe and what most platform teams reconstruct by hand every quarter. Once the events are structured, the quarterly fire-drill becomes a command.

One caution: an audit event emitted by the same CLI the engineer chooses to run has the weakness described above. Treat these events as evidence of *intent and attribution*, and pair them with API-server audit logs as the authoritative record of what actually reached the cluster.

## Upgrades — add end-of-support and cost, not just drift

`Classify` measures distance from a single fleet-wide `targetKubeVersion`. That is one dimension short of how upgrades actually get prioritised.

**Per-environment targets.** Prod deliberately lags nonprod. One global target cannot express that, so prod either looks permanently stale or the target is set so loosely that nonprod drift hides.

**End-of-support awareness.** A cluster two minors behind is an engineering concern; a cluster approaching end of standard support is a budget and resilience one. `bankctl fleet eol` should report days remaining and projected extended-support cost. EKS extended support bills the control plane at several times the standard rate, and AKS LTS behaves similarly — worth confirming current pricing rather than hard-coding it.

That reframing is the point. Converting "two versions behind" into a monthly figure moves the conversation from the platform backlog to the cost centre, which is what actually gets upgrade windows approved.

**Unused data already modelled.** `Cluster.CostCentre` is carried through the inventory and used by nothing. Per-cost-centre reporting is close to free given the field exists, and it is the natural join key for the cost figures above.

Fleet-wide pre-upgrade scanning belongs here too: `kubent` and `pluto` are already in `docs/ecosystem-tools.md`, and aggregating their per-cluster output across the fleet is glue worth owning.

## Supply chain — the philosophy is stated but not enforced

The repo states zero dependencies as a security decision, but there is no CI at all: no `.github/`, no `LICENSE`, `CODEOWNERS` or `SECURITY.md`. The property holds by convention, and convention is not evidence.

| Add | Why it matters here |
| --- | --- |
| `govulncheck ./...` | Zero third-party dependencies is not zero CVEs. It catches **standard-library** vulnerabilities, which you are fully exposed to. Highest value of anything in this table. |
| Dependency-count gate | Fail CI if `go.mod` ever gains a require. Turns the zero-dep claim from a norm into a build-breaking invariant. |
| `-trimpath` | Binaries currently embed local build paths. Removes them and enables reproducible builds. |
| `CGO_ENABLED=0` on cross-compiles | Guarantees static Linux binaries; the `net` resolver can otherwise pull cgo in. |
| cosign signing + SBOM | Already recommended in your own ecosystem docs. A binary that authenticates to production banking clusters should be verifiable before it runs. |

`-trimpath` and `CGO_ENABLED=0` are two-line Makefile changes and can land immediately. `govulncheck` in CI is the first thing to add once a workflow file exists, and it needs re-running on Go toolchain releases, not just on code changes — stdlib CVEs arrive independently of this repo's commits.

## Where the zero-dependency rule holds, and where it will strain

Hold it for `bankctl`. It is a binary distributed to engineer laptops that shells out to already-audited cloud CLIs. The rule is buying something real there, and the cost is low.

It will strain when the roadmap reaches a reconciliation service — call it `fleetd` — doing continuous inventory sync and exporting metrics. The recommendation is still to hold: the Prometheus text exposition format is trivial to emit from the standard library, so fleet-hygiene metrics, alerting and SLOs cost no dependencies.

Break it only for in-cluster controllers that genuinely need `client-go`. If that happens, split the module so the zero-dependency guarantee on the distributed CLI stays separately provable rather than quietly diluted.

A middle path exists if CLI fan-out across many accounts becomes too slow to be useful. AWS SigV4 signing is roughly 200 lines of standard-library HMAC-SHA256, and Azure ARM needs only an OAuth bearer token — direct API calls without leaving the stdlib. Worth knowing it is available; not worth taking on until subprocess latency actually hurts.

## Near-term fixes — small, and worth doing before the big items

- [ ] **`exec.Command` has no timeout** in `cloud.run`. A hung `az` call hangs bankctl indefinitely, with no way out but Ctrl-C. Switch to `exec.CommandContext` with a deadline.
- [ ] **`-o json` is not universal.** `guard`, `current` and `doctor` lack it. CI needs `doctor -o json` to gate on structured output rather than parsing a table.
- [ ] **Document the exit-code contract** (0 / 1 / 2 / 3) as a stable scripting API. It is already well designed — `guard --block` returning 3 is exactly right — so make it a published promise rather than an implementation detail.
- [ ] **`-trimpath` and `CGO_ENABLED=0`** in the Makefile, per the supply-chain section.

The two tools already on the README roadmap both get stronger after Horizon 1, which is an argument for sequencing them after it rather than before:

- **`kubeconfig-sweeper`** can prune contexts against reality instead of against a possibly-stale file, which is the difference between a useful tool and a dangerous one.
- **`namespace-lint`** is the natural front-end to tenancy policy, and pairs with the admission-control work in the guard section.

## Sequencing

Build the derived inventory first: four of the remaining items wait on it, and the quick wins beside it block nothing.

&#91;embedded content: sequencing · 3 phases, 4 dependencies\]

The left column can start today, in any order. The evidence track is genuinely independent of the inventory work, so it can run in parallel given a second person.

**If only one thing gets built this quarter:** `bankctl inventory diff` with shadow-cluster detection. It is the shortest path from the code as it stands to something an auditor and a CTO both care about, and it is the prerequisite for most of what follows.
