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
check "help lists shell and connect" 0 'connect \[eks-cluster\]' -- help
check "help lists kube" 0 'kube \[eks-cluster\]' -- help
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
check "kube validates its argument" 2 'usage: nedctl kube' -- --config "$root/configs/nedctl.aws.example.json" kube 'bad name'
check "help lists azure kube" 0 'azure kube \[cluster' -- help
check "azure example lists the bastions" 0 'qa +aks-qa +aks bastion' -- --config "$root/configs/nedctl.aws.example.json" azure hosts
check "azure needs bastions" 1 'Azure access is not set up' -- --config "$work/b.json" azure kube
check "help lists debug" 0 'debug node \[NODE\]' -- help
check "debug validates the image" 2 'not an image reference' -- --config "$root/configs/nedctl.aws.example.json" debug pod --image 'x; rm'
check "explain validates its target" 2 'usage: nedctl explain' -- explain 'svc/x'
check "app needs a name" 2 'usage: nedctl app' -- app
check "logs validates --since" 2 'usage: nedctl logs' -- logs x --since 1d
check "forward validates the port" 2 'ports are 1-65535' -- forward svc/x 70000
check "health validates its flags" 2 'usage: nedctl health' -- health --cert-days 0
check "fleet run is read-only" 2 'read-only' -- fleet run --env qa -- kubectl delete ns x
check "built-in runbooks load" 0 'restart-deployment' -- run ls
check "runbook parameters are checked" 2 'is not allowed' -- --config "$root/configs/nedctl.aws.example.json" run restart-deployment 'deployment=x;rm'
check "node needs an action" 2 'usage: nedctl node' -- node reboot n1
check "cp needs an absolute pod path" 2 'remote path as an absolute path' -- cp api-1:relative .
check "posture validates --fail-on" 2 'usage: nedctl posture' -- posture --fail-on never
check "images validates the format" 2 'table|json|csv' -- images -o xml
check "access needs review" 2 'nedctl access <review>' -- access
check "doctor --hygiene on a clean home" 0 'nothing found' -- doctor --hygiene
check "azure auth needs bastions" 1 'Azure access is not set up' -- --config "$work/b.json" azure auth
check "prompt never fails" 0 - -- prompt --shell bash
check "guard without a kubeconfig fails clearly" 1 'current kube-context' -- guard
check "doctor -o json is machine readable" 0 '"healthy"' -- --config "$root/configs/nedctl.bastion.example.json" doctor -o json

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
