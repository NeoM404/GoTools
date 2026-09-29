package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/NeoM404/GoTools/internal/audit"
	"github.com/NeoM404/GoTools/internal/config"
	"github.com/NeoM404/GoTools/internal/evidence"
)

// stringList is a repeatable string flag (--log a --log b).
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// auditLogs returns the explicit --log paths, or the configured log.
func auditLogs(cfgPath string, explicit stringList, stderr io.Writer) ([]string, bool) {
	if len(explicit) > 0 {
		return explicit, true
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return nil, false
	}
	path, err := cfg.AuditLogPath()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return nil, false
	}
	return []string{path}, true
}

func cmdAudit(cfgPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprintln(stderr, "usage: bankctl audit verify [--log PATH]... [-o table|json]")
		return ExitUsage
	}
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var logs stringList
	fs.Var(&logs, "log", "audit log to verify (repeatable; default: the configured log)")
	output := addOutputFlag(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	paths, ok := auditLogs(cfgPath, logs, stderr)
	if !ok {
		return ExitFailure
	}

	type result struct {
		Path string `json:"path"`
		audit.VerifyResult
		Error string `json:"error,omitempty"`
	}
	results := make([]result, 0, len(paths))
	code := ExitOK
	for _, p := range paths {
		res, err := audit.Verify(p)
		r := result{Path: p, VerifyResult: res}
		if err != nil {
			r.OK, r.Error = false, err.Error()
		}
		if !r.OK {
			code = ExitFailure
		}
		results = append(results, r)
	}
	if *output == "json" {
		if rc := writeJSON(stdout, stderr, results); rc != ExitOK {
			return rc
		}
		return code
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "LOG\tEVENTS\tCHAIN\tDETAIL")
	for _, r := range results {
		status, detail := "intact", "last hash "+short(r.LastHash)
		switch {
		case r.Error != "":
			status, detail = "UNREADABLE", r.Error
		case !r.OK:
			status, detail = "BROKEN", fmt.Sprintf("line %d: %s", r.Line, r.Problem)
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", r.Path, r.Events, status, detail)
	}
	tw.Flush()
	return code
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func cmdEvidence(cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("evidence", flag.ContinueOnError)
	fs.SetOutput(stderr)
	period := fs.String("period", "", "quarter (2026-Q3) or month (2026-09)")
	fromFlag := fs.String("from", "", "first day, YYYY-MM-DD (with --to)")
	toFlag := fs.String("to", "", "last day, YYYY-MM-DD, inclusive (with --from)")
	prodOnly := fs.Bool("production", false, "only production accesses")
	out := fs.String("out", "", "write the JSON evidence pack to this file")
	force := fs.Bool("force", false, "overwrite --out if it exists")
	var logs stringList
	fs.Var(&logs, "log", "audit log to include (repeatable; default: the configured log)")
	output := addOutputFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}

	var from, to time.Time
	var err error
	switch {
	case *period != "" && (*fromFlag != "" || *toFlag != ""):
		fmt.Fprintln(stderr, "use --period, or --from and --to — not both")
		return ExitUsage
	case *period != "":
		from, to, err = evidence.ParsePeriod(*period)
	case *fromFlag != "" && *toFlag != "":
		if from, err = evidence.ParseDate(*fromFlag); err == nil {
			to, err = evidence.ParseDate(*toFlag)
		}
		if err == nil && to.Before(from) {
			err = fmt.Errorf("--to %s is before --from %s", *toFlag, *fromFlag)
		}
	default:
		fmt.Fprintln(stderr, "an explicit period is required: --period 2026-Q3, or --from YYYY-MM-DD --to YYYY-MM-DD")
		return ExitUsage
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	if *out != "" && !*force {
		if _, err := os.Stat(*out); err == nil {
			fmt.Fprintf(stderr, "%s already exists — use --force to overwrite\n", *out)
			return ExitFailure
		}
	}

	paths, ok := auditLogs(cfgPath, logs, stderr)
	if !ok {
		return ExitFailure
	}
	sources := make([]evidence.Source, 0, len(paths))
	for _, p := range paths {
		events, res, err := audit.Read(p)
		if err != nil {
			fmt.Fprintf(stderr, "reading audit log %s: %v\n", p, err)
			return ExitFailure
		}
		sources = append(sources, evidence.Source{Path: p, Events: events, Chain: res})
	}
	rep := evidence.Build(sources, from, to, *prodOnly, now(), Version)

	code := ExitOK
	if !rep.Complete {
		code = ExitFailure
		for _, s := range rep.Sources {
			if !s.Chain.OK {
				fmt.Fprintf(stderr, "chain BROKEN in %s at line %d: %s — this evidence is incomplete\n", s.Path, s.Chain.Line, s.Chain.Problem)
			}
		}
	}

	if *out != "" || *output == "json" {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "encoding evidence: %v\n", err)
			return ExitFailure
		}
		data = append(data, '\n')
		if *out != "" {
			if err := writeFileAtomic(*out, data, 0o600); err != nil {
				fmt.Fprintf(stderr, "writing %s: %v\n", *out, err)
				return ExitFailure
			}
			sum := sha256.Sum256(data)
			fmt.Fprintf(stderr, "evidence written to %s (sha256 %s)\n", *out, hex.EncodeToString(sum[:]))
		}
		if *output == "json" {
			if _, err := stdout.Write(data); err != nil {
				return ExitFailure
			}
			return code
		}
	}

	chains := "chains intact"
	if !rep.Complete {
		chains = "CHAIN BROKEN — incomplete"
	}
	s := rep.Summary
	fmt.Fprintf(stdout, "evidence %s → %s · %d source(s) · %s\n", rep.From, rep.To, len(rep.Sources), chains)
	fmt.Fprintf(stdout, "accesses %d · production %d (%d verified change, %d unverified, %d without) · break-glass %d · refused %d · failed %d · incomplete %d\n",
		s.Accesses, s.Production, s.ProdVerifiedChange, s.ProdUnverifiedChange, s.ProdWithoutChange, s.BreakGlass, s.Refused, s.Failed, s.Incomplete)
	if len(rep.Exceptions) == 0 {
		fmt.Fprintln(stdout, "\nno exceptions to review")
		return code
	}
	fmt.Fprintf(stdout, "\nNEEDS REVIEW (%d)\n", len(rep.Exceptions))
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "STARTED (UTC)\tUSER\tCLUSTER\tENV\tCHANGE\tREASON")
	for _, e := range rep.Exceptions {
		started := e.Started
		if t, err := time.Parse(time.RFC3339Nano, e.Started); err == nil {
			started = t.UTC().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", started, e.User, e.Cluster, e.Environment, dash(e.ChangeRecord), e.Reason)
	}
	tw.Flush()
	return code
}
