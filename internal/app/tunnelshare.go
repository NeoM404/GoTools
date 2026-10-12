package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"nedctl/internal/config"
)

// An EKS tunnel already open on this machine is used again instead of
// opening another: `nedctl kube` and `nedctl connect` publish the tunnel
// they hold (cluster, local port, hop, their own process ID) next to the
// kubeconfigs, and anything else that needs the same cluster — another
// kube, health, explain, logs — checks the holder is alive and the port
// answers, then uses that port. Users take a lease (a file named after
// their process ID) so a kube holder waits for them before closing; a
// connect holder ends on Ctrl-C, and its users see the tunnel go.

// tunnelRecord is a published tunnel.
type tunnelRecord struct {
	Cluster string       `json:"cluster"`
	Host    string       `json:"host"` // the API endpoint: the same name in another account is another cluster
	Profile string       `json:"profile"`
	Port    int          `json:"port"`
	PID     int          `json:"pid"`
	Hop     string       `json:"hop"`
	HopName string       `json:"hopName,omitempty"`
	Started time.Time    `json:"started"`
	Holder  string       `json:"holder,omitempty"` // kube | connect
	State   *tunnelState `json:"state,omitempty"`
}

// tunnelDir is where kubeconfigs and tunnel records live.
func tunnelDir(cfg config.Config) (string, error) {
	if cfg.KubeconfigDir != "" {
		return cfg.KubeconfigDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".kube", "nedctl"), nil
}

func tunnelRecordPath(cfg config.Config, cluster string) (string, error) {
	dir, err := tunnelDir(cfg)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, cluster+".tunnel.json"), nil
}

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// processAlive is a seam for tests.
var processAlive = pidAlive

// portAnswers reports whether something accepts connections on the port.
var portAnswers = func(port int) bool {
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// openTunnel returns the live tunnel to the cluster, if one is published;
// a record whose holder is gone, or whose port no longer answers, is
// removed.
func openTunnel(cfg config.Config, c eksTarget) (tunnelRecord, bool) {
	p, err := tunnelRecordPath(cfg, c.Name)
	if err != nil {
		return tunnelRecord{}, false
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return tunnelRecord{}, false
	}
	var r tunnelRecord
	if json.Unmarshal(data, &r) != nil || r.Cluster != c.Name || r.Port <= 0 || r.Port > 65535 || r.PID <= 0 {
		_ = os.Remove(p)
		return tunnelRecord{}, false
	}
	if r.Host != c.Host {
		return tunnelRecord{}, false // another account's cluster of that name; leave its record alone
	}
	if !processAlive(r.PID) {
		_ = os.Remove(p)
		_ = os.RemoveAll(leaseDir(p))
		return tunnelRecord{}, false
	}
	if !portAnswers(r.Port) {
		return tunnelRecord{}, false // the holder is still opening it, or it dropped; not ours to remove
	}
	return r, true
}

// publishTunnel records the tunnel this process holds; the returned
// function removes the record (only if it is still ours). A managed tunnel
// keeps its state in the record up to date.
func publishTunnel(cfg config.Config, plan tunnelPlan, profile string, holder string, mt ...*managedTunnel) func() {
	p, err := tunnelRecordPath(cfg, plan.cluster.Name)
	if err != nil {
		return func() {}
	}
	r := tunnelRecord{Cluster: plan.cluster.Name, Host: plan.cluster.Host, Profile: profile, Port: plan.port, PID: os.Getpid(),
		Hop: plan.hop.ID, HopName: plan.hop.Name, Started: now().UTC(), Holder: holder}
	var mu sync.Mutex
	write := func() error {
		data, _ := json.Marshal(r)
		return writeFileAtomic(p, data, 0o600)
	}
	if os.MkdirAll(filepath.Dir(p), 0o700) != nil || write() != nil {
		return func() {}
	}
	_ = os.Remove(p + ".close") // a stale request must not close this new tunnel
	if len(mt) == 1 && mt[0] != nil {
		mt[0].onState(func(s tunnelState) {
			mu.Lock()
			defer mu.Unlock()
			r.State = &s
			if cur, err := os.ReadFile(p); err == nil {
				var c tunnelRecord
				if json.Unmarshal(cur, &c) == nil && c.PID == r.PID {
					_ = write()
				}
			}
		})
		mt[0].publish()
	}
	return func() {
		if cur, err := os.ReadFile(p); err == nil {
			var c tunnelRecord
			if json.Unmarshal(cur, &c) == nil && c.PID == r.PID && c.Port == r.Port {
				_ = os.Remove(p)
			}
		}
	}
}

func leaseDir(recordPath string) string { return recordPath + ".users" }

// leaseTunnel marks this process as using the published tunnel; the
// returned function releases it.
func leaseTunnel(cfg config.Config, cluster string) func() {
	p, err := tunnelRecordPath(cfg, cluster)
	if err != nil {
		return func() {}
	}
	dir := leaseDir(p)
	lease := filepath.Join(dir, strconv.Itoa(os.Getpid()))
	if os.MkdirAll(dir, 0o700) != nil || os.WriteFile(lease, nil, 0o600) != nil {
		return func() {}
	}
	return func() { _ = os.Remove(lease) }
}

// tunnelUsers counts the live processes leasing the tunnel (stale leases
// are removed).
func tunnelUsers(cfg config.Config, cluster string) int {
	p, err := tunnelRecordPath(cfg, cluster)
	if err != nil {
		return 0
	}
	entries, err := os.ReadDir(leaseDir(p))
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		switch {
		case err != nil || pid <= 0:
		case pid != os.Getpid() && processAlive(pid):
			n++
			continue
		case pid == os.Getpid():
			continue
		}
		_ = os.Remove(filepath.Join(leaseDir(p), e.Name()))
	}
	return n
}

// leaseWait is how often a closing holder looks again; a var for tests.
var leaseWait = time.Second

// waitForTunnelUsers keeps the tunnel open while other sessions use it,
// saying so; Ctrl-C closes it anyway.
func waitForTunnelUsers(ctx context.Context, cfg config.Config, cluster string, stderr io.Writer) {
	n := tunnelUsers(cfg, cluster)
	if n == 0 {
		return
	}
	sp := working(stderr, fmt.Sprintf("%d other session(s) still use this tunnel — keeping it open until they finish (Ctrl-C closes it now)…", n))
	defer sp.Stop()
	for n > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(leaseWait):
		}
		n = tunnelUsers(cfg, cluster)
	}
}

// sharedPlan is the plan for using a published tunnel: its port and hop,
// and a kubeconfig of this profile's own (a different profile gets its own
// file, so the holder's kubeconfig keeps its identity).
func sharedPlan(cfg config.Config, c eksTarget, r tunnelRecord, profile string) (tunnelPlan, error) {
	data, err := tunnelKubeconfig(c, profile, r.Port)
	if err != nil {
		return tunnelPlan{}, err
	}
	name := c.Name
	if r.Profile != profile {
		name = c.Name + "." + unsafeFileChars.ReplaceAllString(profile, "_")
	}
	kc, err := writeKubeconfigFile(cfg, name, data)
	if err != nil {
		return tunnelPlan{}, err
	}
	return tunnelPlan{cluster: c, hop: ec2Instance{ID: r.Hop, Name: r.HopName}, port: r.Port, kubeconfig: kc, shared: true}, nil
}
