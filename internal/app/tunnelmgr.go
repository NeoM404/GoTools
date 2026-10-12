package app

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/execx"
)

// A tunnel nedctl holds (kube, connect) is managed: nedctl itself listens
// on the local port and passes each connection to the Session Manager
// port-forward behind it. So it knows when the tunnel is in use, and:
//
//   - after tunnelIdleTimeout with no connection and no traffic, it closes
//     the Session Manager session — no open session is left behind a
//     forgotten terminal — and the next kubectl reopens it by itself;
//   - `nedctl tunnels close` asks it to close for good (a request file
//     next to its record, which only you can write);
//   - it publishes its state (open, idle-closed, users) for `nedctl tunnels`.
//
// The local port is bound to 127.0.0.1 only, and the API server's TLS is
// still verified against the cluster's CA end to end.

type managedTunnel struct {
	cfg     config.Config
	plan    tunnelPlan
	profile string
	logFile *os.File
	events  io.Writer
	idle    time.Duration

	ln       net.Listener
	mu       sync.Mutex
	proc     *execx.Process // the Session Manager port-forward; nil while closed
	inner    int            // its local port
	conns    int
	opened   int // times the session was opened
	last     atomic.Int64
	closed   chan struct{}
	stopOnce sync.Once
	state    func(tunnelState)
}

// syncWriter serialises writes from the tunnel's background notices and
// the command's own output; File lets terminal checks see through it.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func newSyncWriter(w io.Writer) io.Writer {
	if s, ok := w.(*syncWriter); ok {
		return s
	}
	return &syncWriter{w: w}
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func (s *syncWriter) File() *os.File {
	f, _ := asFile(s.w)
	return f
}

// tunnelState is what `nedctl tunnels` shows about a held tunnel.
type tunnelState struct {
	Session string    `json:"session"` // open | idle-closed | closed
	Conns   int       `json:"connections"`
	Since   time.Time `json:"since"`
	Opened  int       `json:"opened"`
}

// tunnelWatch is how often the idle and close checks run; a var for tests.
var tunnelWatch = 2 * time.Second

func openManagedTunnel(ctx context.Context, cfg config.Config, plan tunnelPlan, profile string, logFile *os.File, events io.Writer) (*managedTunnel, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(plan.port))
	if err != nil {
		return nil, fmt.Errorf("port %d on 127.0.0.1 is taken: %w", plan.port, err)
	}
	t := &managedTunnel{cfg: cfg, plan: plan, profile: profile, logFile: logFile, events: events, idle: cfg.TunnelIdle(), ln: ln, closed: make(chan struct{})}
	t.touch()
	if err := t.openSession(ctx); err != nil {
		ln.Close()
		return nil, err
	}
	go t.serve(ctx)
	go t.watch(ctx)
	return t, nil
}

func (t *managedTunnel) touch() { t.last.Store(time.Now().UnixNano()) }

// openSession starts the Session Manager port-forward on a port of its own
// and waits until it accepts connections. Callers hold no lock.
func (t *managedTunnel) openSession(ctx context.Context) error {
	inner, err := freePort()
	if err != nil {
		return err
	}
	p := t.plan
	p.port = inner
	proc, err := execx.Start(ctx, execx.Spec{Name: "aws", Args: portForwardArgs(p, t.profile), Stdout: t.logFile, Stderr: t.logFile, Timeout: t.cfg.AWS.Timeout()})
	if err != nil {
		return fmt.Errorf("starting the tunnel: %w", err)
	}
	if err := waitForTunnel(proc, inner, tunnelReadyTimeout); err != nil {
		proc.Stop(3 * time.Second)
		return err
	}
	t.mu.Lock()
	t.proc, t.inner = proc, inner
	t.opened++
	t.mu.Unlock()
	t.publish()
	return nil
}

// session returns the port of a running session, reopening it when it
// was closed for idleness or ended by itself.
func (t *managedTunnel) session(ctx context.Context) (int, error) {
	t.mu.Lock()
	if t.proc != nil {
		if done, _ := t.proc.Exited(); !done {
			port := t.inner
			t.mu.Unlock()
			return port, nil
		}
		t.proc = nil
	}
	reopen := t.opened > 0
	t.mu.Unlock()
	if reopen {
		fmt.Fprintf(t.events, "\r\nnedctl: reopening the tunnel to %s…\r\n", t.plan.cluster.Name)
	}
	if err := t.openSession(ctx); err != nil {
		return 0, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.inner, nil
}

func (t *managedTunnel) serve(ctx context.Context) {
	var opening sync.Mutex // one reopen at a time
	for {
		c, err := t.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			opening.Lock()
			port, err := t.session(ctx)
			opening.Unlock()
			if err != nil {
				fmt.Fprintf(t.events, "\r\nnedctl: the tunnel to %s could not reopen: %v\r\n", t.plan.cluster.Name, err)
				return
			}
			up, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 10*time.Second)
			if err != nil {
				return
			}
			defer up.Close()
			t.mu.Lock()
			t.conns++
			t.mu.Unlock()
			t.touch()
			t.publish()
			// When either side ends, the connection is over: close both
			// (port-forwards do not pass a half-close on, so waiting for the
			// other side would keep a finished connection counted forever).
			done := make(chan struct{}, 2)
			pipe := func(dst, src net.Conn) {
				_, _ = io.Copy(dst, &activityReader{r: src, t: t})
				done <- struct{}{}
			}
			go pipe(up, c)
			go pipe(c, up)
			<-done
			c.Close()
			up.Close()
			<-done
			t.mu.Lock()
			t.conns--
			t.mu.Unlock()
			t.touch()
			t.publish()
		}()
	}
}

// activityReader marks the tunnel in use whenever bytes pass.
type activityReader struct {
	r io.Reader
	t *managedTunnel
}

func (a *activityReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if n > 0 {
		a.t.touch()
	}
	return n, err
}

// watch closes an idle session, and everything on a close request.
func (t *managedTunnel) watch(ctx context.Context) {
	tick := time.NewTicker(tunnelWatch)
	defer tick.Stop()
	for {
		select {
		case <-t.closed:
			return
		case <-ctx.Done():
			t.Stop()
			return
		case <-tick.C:
		}
		if closeRequested(t.cfg, t.plan.cluster.Name) {
			fmt.Fprintf(t.events, "\r\nnedctl: the tunnel to %s was closed (nedctl tunnels close)\r\n", t.plan.cluster.Name)
			t.Stop()
			return
		}
		t.mu.Lock()
		idleFor := time.Since(time.Unix(0, t.last.Load()))
		shut := t.idle > 0 && t.proc != nil && t.conns == 0 && idleFor >= t.idle
		var proc *execx.Process
		if shut {
			proc = t.proc
		}
		t.mu.Unlock()
		if shut {
			// Still unused? (a connection may have arrived meanwhile)
			t.mu.Lock()
			still := t.proc == proc && t.conns == 0 && time.Since(time.Unix(0, t.last.Load())) >= t.idle
			t.mu.Unlock()
			if !still {
				continue
			}
			fmt.Fprintf(t.events, "\r\nnedctl: tunnel to %s idle for %s — Session Manager session closed; the next kubectl reopens it\r\n", t.plan.cluster.Name, shortDuration(idleFor.Round(time.Second)))
			t.mu.Lock()
			if t.proc == proc {
				t.proc = nil
			}
			t.mu.Unlock()
			proc.Stop(3 * time.Second)
			t.publish()
		}
	}
}

func (t *managedTunnel) snapshot() tunnelState {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := tunnelState{Session: "idle-closed", Conns: t.conns, Since: time.Unix(0, t.last.Load()).UTC(), Opened: t.opened}
	select {
	case <-t.closed:
		s.Session = "closed"
	default:
		if t.proc != nil {
			s.Session = "open"
		}
	}
	return s
}

func (t *managedTunnel) publish() {
	t.mu.Lock()
	f := t.state
	t.mu.Unlock()
	if f != nil {
		f(t.snapshot())
	}
}

// onState sets who hears about state changes.
func (t *managedTunnel) onState(f func(tunnelState)) {
	t.mu.Lock()
	t.state = f
	t.mu.Unlock()
}

// setIdle changes the idle limit (tests).
func (t *managedTunnel) setIdle(d time.Duration) {
	t.mu.Lock()
	t.idle = d
	t.mu.Unlock()
}

// Done is closed once the tunnel has stopped for good.
func (t *managedTunnel) Done() <-chan struct{} { return t.closed }

// Ended reports a tunnel stopped by a close request (not by its holder).
func (t *managedTunnel) Ended() bool {
	select {
	case <-t.closed:
		return true
	default:
		return false
	}
}

// Stop closes the listener and the session.
func (t *managedTunnel) Stop() {
	t.stopOnce.Do(func() {
		t.ln.Close()
		t.mu.Lock()
		proc := t.proc
		t.proc = nil
		t.mu.Unlock()
		if proc != nil {
			proc.Stop(3 * time.Second)
		}
		close(t.closed)
		t.publish()
	})
}

// closeRequestPath is where `nedctl tunnels close` asks a holder to stop.
func closeRequestPath(cfg config.Config, cluster string) (string, error) {
	p, err := tunnelRecordPath(cfg, cluster)
	if err != nil {
		return "", err
	}
	return p + ".close", nil
}

func closeRequested(cfg config.Config, cluster string) bool {
	p, err := closeRequestPath(cfg, cluster)
	if err != nil {
		return false
	}
	if _, err := os.Stat(p); err == nil {
		_ = os.Remove(p)
		return true
	}
	return false
}
