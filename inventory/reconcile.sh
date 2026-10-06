#!/usr/bin/env bash
# Reconcile the declared inventory (inventory/fleet.json) against what Azure
# actually runs, and propose the corrected inventory when they differ.
#
# Runs inside the AzureCLI@2 step of .azure-pipelines/inventory.yml, where az
# is already signed in as the read-only service connection. It can also be
# run by hand by anyone with Reader on the subscriptions:
#
#   BANKCTL_CONFIG=inventory/bankctl.json OUT_DIR=out inventory/reconcile.sh
#
# Writes to $OUT_DIR:
#   diff.json             declared vs actual: shadow, missing, drifted clusters
#   proposed-fleet.json   only when out of sync — the inventory the clouds
#                         imply. A person reviews it and merges it by pull
#                         request; the pipeline never edits the inventory.
#
# Exit: 0 in sync · 1 out of sync, or the scan could not complete.
set -uo pipefail

bankctl="${BANKCTL:-./bin/bankctl}"
out="${OUT_DIR:?set OUT_DIR to the directory for diff.json and proposed-fleet.json}"
mkdir -p "$out"

# Azure DevOps log commands; plain echo when run by hand.
error() {
	if [ -n "${TF_BUILD:-}" ]; then echo "##vso[task.logissue type=error]$*"; else echo "error: $*" >&2; fi
}

"$bankctl" inventory validate || { error "inventory/fleet.json is invalid — fix it before reconciling"; exit 1; }

"$bankctl" inventory diff --report "$out/diff.json"
diff_rc=$?
if [ "$diff_rc" -eq 0 ]; then
	exit 0
fi
if [ ! -s "$out/diff.json" ]; then
	error "inventory diff failed before it could scan (exit $diff_rc) — see the log above"
	exit 1
fi

# Out of sync, or a scope could not be scanned. sync refuses a partial scan,
# so a proposal is only ever written from a complete one.
if "$bankctl" inventory sync --out "$out/proposed-fleet.json" --force; then
	error "inventory NOT in sync with Azure — review diff.json, then merge proposed-fleet.json as inventory/fleet.json by pull request"
else
	error "inventory NOT in sync with Azure, and no proposal could be written (incomplete scan or untagged clusters) — see the log above"
fi
exit 1
