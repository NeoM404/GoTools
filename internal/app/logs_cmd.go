package app

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"regexp"
	"strconv"
	"strings"

	"nedctl/internal/audit"
	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// `nedctl logs` shows the logs of every pod of an application at once,
// each line prefixed with its pod and container in a colour of its own,
// like stern. On AKS it runs on the bastion; developers need no shell.

var sinceRe = regexp.MustCompile(`^[0-9]+(s|m|h)$`)

func cmdLogs(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, false)
	ns := addNamespaceFlag(fs)
	since := fs.String("since", "1h", "how far back, e.g. 10m, 2h")
	tail := fs.Int("tail", 200, "at most this many lines per container to start with")
	follow := fs.Bool("f", false, "keep following new lines (Ctrl-C stops)")
	container := fs.String("c", "", "only this container (default: all)")
	grep := fs.String("grep", "", "only lines containing this text (case-insensitive)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	kind, name, ok := "", "", len(pos) == 1
	if ok {
		kind, name, ok = parseTarget(pos[0])
	}
	if !ok || !config.ValidNamespace(*ns) || !sinceRe.MatchString(*since) || *tail < 1 || (*container != "" && !podNameRe.MatchString(*container)) {
		fmt.Fprintln(stderr, "usage: nedctl logs <deploy/NAME|sts/NAME|ds/NAME|POD|NAME> [-n NS] [--since 1h] [--tail 200] [-f] [-c CONTAINER] [--grep TEXT]")
		return ExitUsage
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	s, code := openKubeSession(ctx, cfg, sessionFlags{cluster: sel.cluster, env: sel.env, awsProfile: sel.awsProfile}, stderr)
	if code != ExitOK {
		return code
	}
	defer s.close()

	// What to read: one pod, or every pod of the workload.
	target, subject := []string{}, ""
	if kind == "" || kind == "pod" {
		if _, err := s.output(ctx, "", "get", "pod", name, "-n", *ns, "-o", "name"); err == nil {
			target, subject = []string{name}, "pod/"+name
		} else if kind == "pod" {
			fmt.Fprintf(stderr, "pod %s in %s: %v\n", name, *ns, err)
			return ExitFailure
		} else {
			kind = "deployment"
		}
	}
	if subject == "" {
		out, err := s.output(ctx, "", "get", kind, name, "-n", *ns, "-o", "json")
		if err != nil {
			fmt.Fprintf(stderr, "%s %s in %s: %v\n", kind, name, *ns, err)
			return ExitFailure
		}
		var wl kubeWorkload
		if err := json.Unmarshal(out, &wl); err != nil || wl.selector() == "" {
			fmt.Fprintf(stderr, "%s %s has no label selector to find its pods\n", kind, name)
			return ExitFailure
		}
		target, subject = []string{"-l", wl.selector(), "--max-log-requests=20"}, kind+"/"+name
	}
	kargs := append([]string{"logs", "-n", *ns}, target...)
	kargs = append(kargs, "--prefix", "--since="+*since, "--tail="+strconv.Itoa(*tail))
	if *container != "" {
		kargs = append(kargs, "-c", *container)
	} else {
		kargs = append(kargs, "--all-containers")
	}
	if *follow {
		kargs = append(kargs, "-f")
	}

	base := audit.Event{Action: "logs-read", Cloud: s.cloud, Cluster: s.cluster, Account: s.pc.AccountID, Environment: s.env, Production: s.pc.Production,
		Detail: fmt.Sprintf("logs of %s in %s (since %s), %s", subject, *ns, *since, s.where)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing: every access must be recorded\n", err)
		return ExitFailure
	}
	st := ui.Style{Color: colorOn(stderr)}
	fmt.Fprintf(stderr, "%s %s in %s on %s%s\n", st.Dim("logs of"), subject, *ns, s.label(), st.Dim(map[bool]string{true: " — Ctrl-C stops", false: ""}[*follow]))
	lw := &logWriter{out: stdout, color: colorOn(stdout), grep: strings.ToLower(*grep)}
	err = s.kubectl(ctx, kargs, strings.NewReader(""), lw, stderr, false)
	lw.flush()
	if err != nil && !*follow {
		tr.end(ctx, audit.OutcomeFailure, s.pc.Role, err.Error(), stderr)
		fmt.Fprintf(stderr, "reading logs: %v\n", err)
		return ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, s.pc.Role, base.Detail, stderr)
	return ExitOK
}

// logWriter colours kubectl's "[pod/NAME/CONTAINER] line" prefix, one
// colour per pod and container, and filters lines.
type logWriter struct {
	out   io.Writer
	color bool
	grep  string
	buf   bytes.Buffer
}

var logPalette = []string{ui.Blue, ui.Green, ui.Amber, "#c084fc", "#22d3ee", "#f472b6", "#a3e635", "#fb923c"}

func (w *logWriter) Write(p []byte) (int, error) {
	w.buf.Write(p)
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			w.buf.WriteString(line) // keep a partial line for the next write
			return len(p), nil
		}
		w.line(strings.TrimSuffix(line, "\n"))
	}
}

func (w *logWriter) flush() {
	if w.buf.Len() > 0 {
		w.line(w.buf.String())
		w.buf.Reset()
	}
}

func (w *logWriter) line(l string) {
	if w.grep != "" && !strings.Contains(strings.ToLower(l), w.grep) {
		return
	}
	if w.color && strings.HasPrefix(l, "[") {
		if end := strings.Index(l, "] "); end > 0 {
			prefix := strings.TrimPrefix(l[1:end], "pod/")
			h := fnv.New32a()
			h.Write([]byte(prefix))
			col := logPalette[int(h.Sum32()%uint32(len(logPalette)))]
			l = ui.Style{Color: true}.Fg(col, prefix) + " " + l[end+2:]
		}
	}
	fmt.Fprintln(w.out, l)
}
