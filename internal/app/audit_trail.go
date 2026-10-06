package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"time"

	"github.com/NeoM404/GoTools/internal/audit"
	"github.com/NeoM404/GoTools/internal/config"
	"github.com/NeoM404/GoTools/internal/inventory"
)

// trail records one audited action as a start/end event pair.
type trail struct {
	rec   *audit.Recorder
	base  audit.Event
	ended bool
}

// beginAudit writes the start event. If it cannot be written the caller must
// not proceed: the guarantee is that every access is recorded, or does not
// happen.
// changeInfo is the change-control context recorded with an access.
type changeInfo struct {
	record, breakGlassReason string
}

func beginAudit(ctx context.Context, cfg config.Config, action string, c *inventory.Cluster, production bool, ci changeInfo, stderr io.Writer) (*trail, error) {
	base := audit.Event{
		Action: action, Production: production,
		ChangeRecord: ci.record, BreakGlass: ci.breakGlassReason != "", BreakGlassReason: ci.breakGlassReason,
	}
	if c != nil {
		base.Cluster, base.Cloud, base.Environment = c.Name, string(c.Cloud), c.Environment
		base.Account, base.Subscription = c.Account, c.Subscription
	}
	return beginAuditEvent(ctx, cfg, base, stderr)
}

// beginAuditEvent writes the start event for base, filling in who, where and
// with which tool. Use it for actions that are not about one inventory
// cluster, such as signing in to an AWS account.
func beginAuditEvent(ctx context.Context, cfg config.Config, base audit.Event, stderr io.Writer) (*trail, error) {
	path, err := cfg.AuditLogPath()
	if err != nil {
		return nil, err
	}
	rec := &audit.Recorder{Log: audit.Log{Path: path}, Warn: stderr}
	if f := cfg.Audit.Forward; f.URL != "" {
		token := os.Getenv(f.TokenEnv)
		if token == "" {
			fmt.Fprintf(stderr, "warning: $%s is empty — audit events are kept locally but not forwarded\n", f.TokenEnv)
		} else {
			rec.Forward = &audit.Forwarder{URL: f.URL, Token: token, Scheme: f.Scheme, Format: f.Format, Timeout: f.ForwardTimeout()}
		}
	}
	base.ID, base.Tool, base.Version, base.User, base.Host = audit.NewID(), "bankctl", Version, currentUser(), hostname()
	start := base
	start.Phase, start.Time = audit.PhaseStart, stamp()
	if _, err := rec.Record(ctx, start); err != nil {
		return nil, fmt.Errorf("cannot write the audit log (%s): %w", path, err)
	}
	return &trail{rec: rec, base: base}, nil
}

// end writes the outcome. A failure to record it is reported, not fatal: the
// action has already happened, and its start event is on record.
func (t *trail) end(ctx context.Context, outcome, principal, detail string, stderr io.Writer) {
	if t == nil || t.ended {
		return
	}
	t.ended = true
	e := t.base
	e.Phase, e.Time, e.Outcome, e.Principal, e.Detail = audit.PhaseEnd, stamp(), outcome, principal, detail
	// The end must be written even if the operator pressed Ctrl-C.
	if _, err := t.rec.Record(context.WithoutCancel(ctx), e); err != nil {
		fmt.Fprintf(stderr, "error: action completed but its audit end event could not be written: %v\n", err)
	}
}

func stamp() string { return now().UTC().Format(time.RFC3339Nano) }

func currentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}
