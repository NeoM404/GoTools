package app

import (
	"os"
	"path/filepath"
	"testing"
)

// clusterFixture is a bastion (the azureWorld fake ssh) with clusters
// whose kubectl answers come from files: fixtures/<context>/<key>, the key
// being the kubectl arguments with every other character turned into "_".
// It serves both the per-cluster bastion script (--context) and sessions
// (current-context from the session file in KUBECONFIG).
type clusterFixture struct {
	*azureWorld
	dir, calls string
}

func newClusterFixture(t *testing.T, extra string, clusters ...string) *clusterFixture {
	t.Helper()
	f := &clusterFixture{azureWorld: newAzureWorld(t, extra)}
	f.dir = filepath.Join(t.TempDir(), "fixtures")
	f.calls = filepath.Join(f.dir, ".calls")
	for _, c := range clusters {
		if err := os.MkdirAll(filepath.Join(f.dir, c), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fakeCLI(t, "kubectl", `F=`+sq(f.dir)+`
ctx=""
while [ $# -gt 0 ]; do
  case "$1" in --context) ctx=$2; shift 2;; --request-timeout=*) shift;; *) break;; esac
done
if [ -z "$ctx" ] && [ -n "$KUBECONFIG" ]; then
  ctx=$(sed -n 's/^current-context: "\(.*\)"$/\1/p' "${KUBECONFIG%%:*}" 2>/dev/null)
fi
printf '%s|%s\n' "$ctx" "$*" >> "$F/.calls"
case "$*" in
"config get-contexts -o name") ls "$F"; exit 0;;
"config get-contexts "*) [ -d "$F/$3" ]; exit $?;;
esac
key=$(printf '%s' "$*" | LC_ALL=C tr -c 'A-Za-z0-9' '_')
[ -f "$F/$ctx/$key.stdin" ] && cat > "$F/$ctx/$key.stdin"
if [ -f "$F/$ctx/$key.err" ]; then cat "$F/$ctx/$key.err" >&2; exit 1; fi
if [ -f "$F/$ctx/$key" ]; then cat "$F/$ctx/$key"; exit 0; fi
echo "fixture: no answer for $ctx: $*" >&2
exit 1`)
	return f
}

func fixtureKey(args string) string {
	b := []byte(args)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			b[i] = '_'
		}
	}
	return string(b)
}

// answer makes kubectl on cluster print out for args.
func (f *clusterFixture) answer(t *testing.T, cluster, args, out string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, cluster, fixtureKey(args)), []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fail makes kubectl on cluster fail for args with msg.
func (f *clusterFixture) fail(t *testing.T, cluster, args, msg string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, cluster, fixtureKey(args)+".err"), []byte(msg), 0o600); err != nil {
		t.Fatal(err)
	}
}
