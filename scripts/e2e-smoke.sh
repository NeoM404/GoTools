#!/usr/bin/env bash
# Smoke test of the built nedctl binary, the way engineers run it: the
# documented exit codes and refusals hold on a machine with no cloud access.
# The full behavioural journey is TestE2EEngineerJourney (go test -run E2E).
#
# Usage: scripts/e2e-smoke.sh [path/to/nedctl]   (default: builds one)
set -uo pipefail

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
bin="${1:-}"
if [ -z "$bin" ]; then
	bin="$work/nedctl"
	CGO_ENABLED=0 go build -trimpath -o "$bin" ./cmd/nedctl || exit 1
fi
export HOME="$work/home" XDG_STATE_HOME="$work/state" XDG_CONFIG_HOME="$work/config" AWS_CONFIG_FILE="$work/home/.aws/config"
export KUBECONFIG="$work/none" AWS_PROFILE="" NO_COLOR=1
mkdir -p "$HOME"
root="$(cd "$(dirname "$0")/.." && pwd)"

pass=0 fail=0
check() { # check <name> <want-exit> <grep-pattern|-> -- <args...>
	local name="$1" want="$2" pattern="$3"
	shift 4
	local out code
	out="$("$bin" "$@" 2>&1 </dev/null)"
	code=$?
	if [ "$code" -ne "$want" ] || { [ "$pattern" != "-" ] && ! grep -qE -- "$pattern" <<<"$out"; }; then
		echo "FAIL  $name: exit $code (want $want)"
		echo "$out" | sed 's/^/      /' | head -5
		fail=$((fail + 1))
	else
		echo "ok    $name"
		pass=$((pass + 1))
	fi
}

check "version" 0 '^nedctl ' -- version
check "help lists the AWS commands" 0 'aws login.*' -- help
check "help lists shell and connect" 0 'connect <eks-cluster>' -- help
check "unknown command is a usage error" 2 'unknown command' -- frobnicate
check "init --mode bastion" 0 'wrote starter config' -- init --path "$work/b.json" --mode bastion
check "init refuses to overwrite" 1 'already exists' -- init --path "$work/b.json" --mode bastion
check "bastion example inventory is valid" 0 'inventory valid: 4' -- --config "$root/configs/nedctl.bastion.example.json" inventory validate
check "aws example config loads" 1 'no profile selected' -- --config "$root/configs/nedctl.aws.example.json" aws whoami
check "aws login needs Identity Center config" 1 'not configured' -- --config "$work/b.json" aws login
check "aws env refuses without a profile" 1 'no profile selected' -- --config "$root/configs/nedctl.aws.example.json" aws env
check "break-glass needs a reason" 2 'go together' -- --config "$root/configs/nedctl.aws.example.json" aws login --all
check "kubeconfig is refused on a bastion" 2 'does not fetch any' -- --config "$root/configs/nedctl.bastion.example.json" kubeconfig payments-k8s-prod-cluster
check "connect validates its argument" 2 'usage: nedctl connect' -- --config "$root/configs/nedctl.aws.example.json" connect 'bad name'
check "prompt never fails" 0 - -- prompt --shell bash
check "guard without a kubeconfig fails clearly" 1 'current kube-context' -- guard
check "doctor -o json is machine readable" 0 '"healthy"' -- --config "$root/configs/nedctl.bastion.example.json" doctor -o json

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
