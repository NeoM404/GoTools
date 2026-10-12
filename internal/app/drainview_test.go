package app

import (
	"bytes"
	"strings"
	"testing"
)

func TestDrainViewFollowsEvictions(t *testing.T) {
	var b bytes.Buffer
	v := newDrainView(&b, "aks-pool1-000001", 3)
	for _, l := range []string{
		"node/aks-pool1-000001 cordoned",
		"evicting pod payments/api-1",
		"evicting pod payments/api-2",
		"evicting pod web/front-1",
		`error when evicting pods/"api-2" -n "payments" (will retry after 5s): Cannot evict pod as it would violate the pod's disruption budget.`,
		"pod/api-1 evicted",
		"WARNING: ignoring DaemonSet-managed Pods: kube-system/kube-proxy-x",
	} {
		v.Write([]byte(l + "\n"))
	}
	v.mu.Lock()
	f := plain(strings.Join(v.render(), "\n"))
	v.mu.Unlock()
	for _, want := range []string{"draining aks-pool1-000001", "1/3 pods moved", "payments/api-2 waiting for its disruption budget", "web/front-1 moving"} {
		if !strings.Contains(f, want) {
			t.Fatalf("frame lacks %q:\n%s", want, f)
		}
	}
	if strings.Contains(f, "api-1 moving") {
		t.Fatalf("an evicted pod is no longer moving:\n%s", f)
	}
	v.Write([]byte("pod/api-2 evicted\npod/front-1 evicted\nnode/aks-pool1-000001 drained\n"))
	v.stop()
	out := plain(b.String())
	if !strings.Contains(out, "3/3 pods moved") || !strings.Contains(out, "WARNING: ignoring DaemonSet-managed Pods") {
		t.Fatalf("end:\n%s", out)
	}
}
