package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/execx"
)

// sshAgentState reports the SSH agent as `ssh-add -l` does: 0 with keys
// loaded (and how many), 1 running without keys, 2 no agent, -1 when
// ssh-add is not installed. A seam for tests.
var sshAgentState = func(ctx context.Context) (state, keys int) {
	out, err := execx.Output(ctx, 5*time.Second, "ssh-add", "-l")
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, len(strings.Split(strings.TrimSpace(string(out)), "\n"))
	case errors.As(err, &exit):
		return exit.ExitCode(), 0
	case errors.As(err, new(*execx.NotFoundError)):
		return -1, 0
	}
	return 2, 0
}

// bastionDialTimeout bounds doctor's reachability probe of each bastion.
var bastionDialTimeout = 4 * time.Second

// azureChecks: the SSH agent, and whether each bastion's SSH port answers
// from here (resolved through ~/.ssh/config with `ssh -G`, no login).
func azureChecks(ctx context.Context, cfg config.Config, offline bool) []doctorCheck {
	var cs []doctorCheck
	switch state, keys := sshAgentState(ctx); state {
	case 0:
		cs = append(cs, doctorCheck{"ssh agent", "ok", fmt.Sprintf("%d key(s) loaded", keys)})
	case 1:
		cs = append(cs, doctorCheck{"ssh agent", "info", "running, no key loaded yet — the first azure command asks for your key's passphrase once and the agent keeps it"})
	case 2:
		if goos == "windows" {
			cs = append(cs, doctorCheck{"ssh agent", "warn", "the ssh-agent service is not running, so you type your key's passphrase on every connection — in PowerShell as administrator: Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent"})
		} else {
			cs = append(cs, doctorCheck{"ssh agent", "info", "none in this terminal, so you type your key's passphrase on every connection — open a new terminal after `nedctl setup` (its shell block starts one agent for all your terminals)"})
		}
	}
	if offline {
		return cs
	}
	targets := azureTargets(cfg)
	results := make([]doctorCheck, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		if !t.Bastion {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = probeBastion(ctx, cfg, t)
		}()
	}
	wg.Wait()
	for _, r := range results {
		if r.Name != "" {
			cs = append(cs, r)
		}
	}
	return cs
}

func probeBastion(ctx context.Context, cfg config.Config, t sshTarget) doctorCheck {
	name := "bastion " + t.Env
	args := append([]string{"-G"}, sshArgs(cfg, t, false, "")...)
	out, err := execx.Output(ctx, 5*time.Second, "ssh", args...)
	if err != nil {
		return doctorCheck{name, "warn", fmt.Sprintf("%s: %v", t.Dest, err)}
	}
	conf := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), " "); ok {
			conf[strings.ToLower(k)] = v
		}
	}
	if j := conf["proxyjump"]; j != "" && j != "none" {
		return doctorCheck{name, "info", fmt.Sprintf("%s goes through %s (not probed)", t.Dest, j)}
	}
	if c := conf["proxycommand"]; c != "" && c != "none" {
		return doctorCheck{name, "info", t.Dest + " uses a ProxyCommand (not probed)"}
	}
	addr := net.JoinHostPort(conf["hostname"], firstNonBlank(conf["port"], "22"))
	conn, err := (&net.Dialer{Timeout: bastionDialTimeout}).DialContext(ctx, "tcp", addr)
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return doctorCheck{name, "warn", fmt.Sprintf("%s: no such host — add it to ~/.ssh/config (Host %s, HostName <address>) or use its address", t.Dest, conf["hostname"])}
	case err != nil:
		return doctorCheck{name, "warn", fmt.Sprintf("%s (%s) does not answer — on the VPN or bank network? %v", t.Dest, addr, err)}
	}
	conn.Close()
	return doctorCheck{name, "ok", fmt.Sprintf("%s (%s) reachable", t.Dest, addr)}
}
