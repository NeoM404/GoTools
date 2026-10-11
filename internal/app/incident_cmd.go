package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"nedctl/internal/audit"
	"nedctl/internal/config"
	"nedctl/internal/redact"
	"nedctl/internal/ui"
)

// `nedctl incident deploy/NAME` gathers what an incident ticket needs in
// one dated file: the explain findings, the workload and its pods, their
// events and recent logs. Before anything is written, environment
// variable values, last-applied annotations and managed fields are
// removed, and every log line is redacted (secrets, card and ID numbers).
// A manifest lists each file's SHA-256 with who collected it, when and
// from where, and the zip's own SHA-256 goes into the audit trail, so the
// evidence can be shown to be unchanged. Read-only.

const notCollected = "‹not collected›"

func cmdIncident(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("incident", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, false)
	ns := addNamespaceFlag(fs)
	since := fs.String("since", "1h", "how far back to read logs, e.g. 30m, 2h")
	tail := fs.Int("tail", 500, "at most this many log lines per container")
	out := fs.String("out", "", "the file to write (default: incident-NAME-CLUSTER-TIME.zip here)")
	save := fs.Bool("save", false, "write it to your Downloads folder (on WSL: Windows' Downloads)")
	pos, err := parseInterspersed(fs, args)
	kind, name, ok := "", "", err == nil && len(pos) == 1
	if ok {
		kind, name, ok = parseTarget(pos[0])
	}
	if !ok || !config.ValidNamespace(*ns) || !sinceRe.MatchString(*since) || *tail < 1 || *tail > 5000 || (*save && *out != "") {
		fmt.Fprintln(stderr, "usage: nedctl incident <deploy/NAME|sts/NAME|POD> [-n NS] [--cluster C] [--since 1h] [--tail 500] [--out FILE | --save]")
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

	stamp := now().UTC().Format("20060102-150405")
	fileName := fmt.Sprintf("incident-%s-%s-%s.zip", name, s.cluster, stamp)
	dest := *out
	switch {
	case *save:
		if dest, err = saveTarget(ctx, fileName); err != nil {
			fmt.Fprintf(stderr, "finding your Downloads folder: %v — use --out instead\n", err)
			return ExitFailure
		}
	case dest == "":
		dest = fileName
	}

	ev := audit.Event{Action: "incident-collect", Cloud: s.cloud, Cluster: s.cluster, Account: s.pc.AccountID, Environment: s.env, Production: s.pc.Production,
		Detail: fmt.Sprintf("%s in %s (logs since %s), %s", pos[0], *ns, *since, s.where)}
	tr, err := beginAuditEvent(ctx, cfg, ev, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing: every access must be recorded\n", err)
		return ExitFailure
	}
	sp := working(stderr, "Collecting "+pos[0]+" from "+s.label()+"…")
	files, subject, findings, err := collectIncident(ctx, s, *ns, kind, name, *since, *tail)
	sp.Stop()
	if err != nil {
		tr.end(ctx, audit.OutcomeFailure, s.pc.Role, err.Error(), stderr)
		fmt.Fprintln(stderr, err)
		return ExitFailure
	}
	meta := map[string]any{
		"collectedBy": debugOwner(), "collectedAt": now().UTC().Format(time.RFC3339), "nedctl": Version,
		"cloud": s.cloud, "environment": s.env, "cluster": s.cluster, "account": s.pc.AccountID, "namespace": *ns, "target": subject,
		"logsSince": *since, "redaction": "environment variable values, last-applied annotations and managed fields removed; log lines redacted (secrets, tokens, keys, card and ID numbers)",
	}
	files["summary.md"] = []byte(incidentSummary(meta, findings))
	data, sum, err := buildIncidentZip(files, meta)
	if err == nil {
		err = writeNewFile(dest, data)
	}
	if err != nil {
		tr.end(ctx, audit.OutcomeFailure, s.pc.Role, err.Error(), stderr)
		fmt.Fprintf(stderr, "writing %s: %v\n", dest, err)
		return ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, s.pc.Role, fmt.Sprintf("%s; %s sha256:%s", ev.Detail, filepath.Base(dest), sum), stderr)

	st := ui.Style{Color: colorOn(stdout)}
	fails := 0
	for _, f := range findings {
		if f.Severity == "fail" {
			fails++
		}
	}
	fmt.Fprintf(stdout, "%s %s (%d files, %s)\n", st.OK("evidence collected:"), dest, len(files)+1, byteSize(int64(len(data))))
	fmt.Fprintf(stdout, "  sha256  %s\n", sum)
	fmt.Fprintf(stdout, "  %d finding(s), %d failing — summary.md inside says what is wrong\n", len(findings), fails)
	fmt.Fprintln(stdout, st.Hint("attach it to the incident; the SHA-256 is in your audit trail, so it can be shown unchanged"))
	savedHint(dest, stdout)
	return ExitOK
}

// collectIncident reads the target, its pods, events and logs, cleaned.
func collectIncident(ctx context.Context, s *kubeSession, ns, kind, name, since string, tail int) (map[string][]byte, string, []finding, error) {
	subject, findings, err := explainTarget(ctx, s, ns, kind, name, true)
	if err != nil {
		return nil, "", nil, err
	}
	files := map[string][]byte{}
	fj, _ := json.MarshalIndent(findings, "", "  ")
	files["findings.json"] = fj
	podsSel := []string{}
	if k, n, _ := strings.Cut(subject, "/"); k == "pod" {
		out, err := s.output(ctx, "", "get", "pod", n, "-n", ns, "-o", "json")
		if err != nil {
			return nil, "", nil, err
		}
		files["pod.json"] = scrubJSON(out)
		podsSel = []string{n}
	} else {
		out, err := s.output(ctx, "", "get", k, n, "-n", ns, "-o", "json")
		if err != nil {
			return nil, "", nil, err
		}
		files["workload.json"] = scrubJSON(out)
		var wl kubeWorkload
		if json.Unmarshal(out, &wl) == nil && wl.selector() != "" {
			if out, err := s.output(ctx, "", "get", "pods", "-n", ns, "-l", wl.selector(), "-o", "json"); err == nil {
				files["pods.json"] = scrubJSON(out)
				var list struct{ Items []kubePod }
				if json.Unmarshal(out, &list) == nil {
					for _, p := range list.Items {
						podsSel = append(podsSel, p.Metadata.Name)
					}
				}
			}
		}
	}
	// Events about the workload, its ReplicaSets and pods only.
	if out, err := s.output(ctx, "", "get", "events", "-n", ns, "-o", "json"); err == nil {
		var list struct {
			Items []map[string]any `json:"items"`
		}
		if json.Unmarshal(out, &list) == nil {
			var keep []map[string]any
			for _, e := range list.Items {
				obj, _ := e["involvedObject"].(map[string]any)
				n, _ := obj["name"].(string)
				if n == name || strings.HasPrefix(n, name+"-") || contains(podsSel, n) {
					keep = append(keep, e)
				}
			}
			ej, _ := json.MarshalIndent(map[string]any{"items": keep}, "", "  ")
			files["events.json"] = ej
		}
	}
	sort.Strings(podsSel)
	if len(podsSel) > 20 {
		podsSel = podsSel[:20] // enough to see the pattern; bounded on big workloads
	}
	for _, p := range podsSel {
		out, err := s.output(ctx, "", "get", "pod", p, "-n", ns, "-o", "jsonpath={.spec.containers[*].name}")
		if err != nil {
			continue
		}
		for _, c := range strings.Fields(string(out)) {
			for _, prev := range []bool{false, true} {
				args := []string{"logs", p, "-n", ns, "-c", c, "--since=" + since, "--tail=" + strconv.Itoa(tail), "--timestamps"}
				suffix := ""
				if prev {
					args = append(args[:len(args)-3], "--previous", "--tail="+strconv.Itoa(tail), "--timestamps")
					suffix = ".previous"
				}
				out, err := s.output(ctx, "", args...)
				if err != nil || len(out) == 0 {
					continue
				}
				files["logs/"+p+"_"+c+suffix+".log"] = redactLines(out)
			}
		}
	}
	return files, subject, findings, nil
}

func redactLines(b []byte) []byte {
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		lines[i], _ = redact.Line(l)
	}
	return []byte(strings.Join(lines, "\n"))
}

// scrubJSON removes what must not leave the cluster in evidence: the
// values of environment variables (names stay), the last-applied
// annotation (a full copy of the spec, values included) and managedFields.
func scrubJSON(b []byte) []byte {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return []byte(`{"error":"not JSON; not collected"}`)
	}
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			if md, ok := t["metadata"].(map[string]any); ok {
				delete(md, "managedFields")
				if ann, ok := md["annotations"].(map[string]any); ok {
					delete(ann, "kubectl.kubernetes.io/last-applied-configuration")
				}
			}
			if env, ok := t["env"].([]any); ok {
				for _, e := range env {
					if m, ok := e.(map[string]any); ok {
						if _, has := m["value"]; has {
							m["value"] = notCollected
						}
					}
				}
			}
			for _, c := range t {
				walk(c)
			}
		case []any:
			for _, c := range t {
				walk(c)
			}
		}
	}
	walk(v)
	out, _ := json.MarshalIndent(v, "", "  ")
	return out
}

var unsafeZipName = regexp.MustCompile(`[^A-Za-z0-9._/-]`)

// buildIncidentZip writes the files and a manifest of their SHA-256s,
// returning the zip and its own SHA-256.
func buildIncidentZip(files map[string][]byte, meta map[string]any) ([]byte, string, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	sums := map[string]string{}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	stamp := now()
	add := func(name string, data []byte) error {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: unsafeZipName.ReplaceAllString(name, "_"), Method: zip.Deflate, Modified: stamp})
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	for _, n := range names {
		h := sha256.Sum256(files[n])
		sums[n] = hex.EncodeToString(h[:])
		if err := add(n, files[n]); err != nil {
			return nil, "", err
		}
	}
	m := map[string]any{}
	for k, v := range meta {
		m[k] = v
	}
	m["files"] = sums
	mj, _ := json.MarshalIndent(m, "", "  ")
	if err := add("manifest.json", mj); err != nil {
		return nil, "", err
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	h := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(h[:]), nil
}

func incidentSummary(meta map[string]any, findings []finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Incident evidence: %v\n\n", meta["target"])
	for _, k := range []string{"environment", "cluster", "account", "namespace", "collectedBy", "collectedAt", "nedctl", "logsSince"} {
		if v := fmt.Sprint(meta[k]); v != "" {
			fmt.Fprintf(&b, "- **%s:** %s\n", k, v)
		}
	}
	fmt.Fprintf(&b, "\n## Findings\n\n")
	if len(findings) == 0 {
		b.WriteString("Nothing wrong found in the workload, its pods or their events.\n")
	}
	for _, f := range findings {
		fmt.Fprintf(&b, "- **%s** %s%s\n", strings.ToUpper(f.Severity), f.What, ifNonBlank(" — ", f.Fix))
	}
	fmt.Fprintf(&b, "\n## What was removed\n\n%v.\n\nFile checksums are in manifest.json; the zip's own SHA-256 is in the collector's nedctl audit trail.\n", meta["redaction"])
	return b.String()
}

// writeNewFile writes data to a new file only readable by its owner,
// never replacing one that exists.
func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
