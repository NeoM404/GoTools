package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// `nedctl explain` answers "why is my app not working?" in plain words:
// it reads the workload, its pods and their events (and, for a container
// that keeps crashing, its last log lines) and turns them into findings
// with what to do. It only reads.

// finding is one thing explain found.
type finding struct {
	Severity  string   `json:"severity"` // fail | warn | ok
	Pod       string   `json:"pod,omitempty"`
	Container string   `json:"container,omitempty"`
	What      string   `json:"what"`
	Fix       string   `json:"fix,omitempty"`
	Logs      []string `json:"logs,omitempty"`
}

// kubePod is the part of a pod explain reads.
type kubePod struct {
	Metadata struct {
		Name              string            `json:"name"`
		Namespace         string            `json:"namespace"`
		Labels            map[string]string `json:"labels"`
		CreationTimestamp time.Time         `json:"creationTimestamp"`
		DeletionTimestamp *time.Time        `json:"deletionTimestamp"`
		OwnerReferences   []struct {
			Kind, Name string
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		NodeName   string `json:"nodeName"`
		Containers []struct {
			Name      string `json:"name"`
			Image     string `json:"image"`
			Resources struct {
				Limits   map[string]string `json:"limits"`
				Requests map[string]string `json:"requests"`
			} `json:"resources"`
		} `json:"containers"`
	} `json:"spec"`
	Status struct {
		Phase      string `json:"phase"`
		Reason     string `json:"reason"`
		Message    string `json:"message"`
		Conditions []struct {
			Type, Status, Reason, Message string
		} `json:"conditions"`
		ContainerStatuses     []kubeContainerStatus `json:"containerStatuses"`
		InitContainerStatuses []kubeContainerStatus `json:"initContainerStatuses"`
	} `json:"status"`
}

type kubeContainerStatus struct {
	Name         string `json:"name"`
	Ready        bool   `json:"ready"`
	RestartCount int    `json:"restartCount"`
	Image        string `json:"image"`
	State        kubeContainerState
	LastState    kubeContainerState `json:"lastState"`
}

type kubeContainerState struct {
	Waiting *struct {
		Reason, Message string
	} `json:"waiting"`
	Running *struct {
		StartedAt time.Time `json:"startedAt"`
	} `json:"running"`
	Terminated *struct {
		Reason, Message string
		ExitCode        int       `json:"exitCode"`
		FinishedAt      time.Time `json:"finishedAt"`
	} `json:"terminated"`
}

type kubeEvent struct {
	Type, Reason, Message string
	Count                 int
	InvolvedObject        struct {
		Kind, Name string
	} `json:"involvedObject"`
	LastTimestamp time.Time `json:"lastTimestamp"`
}

// kubeWorkload is the part of a deployment/statefulset/daemonset read.
type kubeWorkload struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Replicas *int `json:"replicas"`
		Selector struct {
			MatchLabels map[string]string `json:"matchLabels"`
		} `json:"selector"`
	} `json:"spec"`
	Status struct {
		Replicas               int `json:"replicas"`
		ReadyReplicas          int `json:"readyReplicas"`
		UpdatedReplicas        int `json:"updatedReplicas"`
		DesiredNumberScheduled int `json:"desiredNumberScheduled"`
		NumberReady            int `json:"numberReady"`
		Conditions             []struct {
			Type, Status, Reason, Message string
		} `json:"conditions"`
	} `json:"status"`
}

func (w kubeWorkload) desired() int {
	if w.Kind == "DaemonSet" {
		return w.Status.DesiredNumberScheduled
	}
	if w.Spec.Replicas != nil {
		return *w.Spec.Replicas
	}
	return 1
}

func (w kubeWorkload) ready() int {
	if w.Kind == "DaemonSet" {
		return w.Status.NumberReady
	}
	return w.Status.ReadyReplicas
}

// selector is the workload's label selector for kubectl -l.
func (w kubeWorkload) selector() string {
	keys := make([]string, 0, len(w.Spec.Selector.MatchLabels))
	for k := range w.Spec.Selector.MatchLabels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + w.Spec.Selector.MatchLabels[k]
	}
	return strings.Join(parts, ",")
}

var workloadKinds = map[string]string{
	"deploy": "deployment", "deployment": "deployment", "deployments": "deployment",
	"sts": "statefulset", "statefulset": "statefulset", "statefulsets": "statefulset",
	"ds": "daemonset", "daemonset": "daemonset", "daemonsets": "daemonset",
	"po": "pod", "pod": "pod", "pods": "pod",
}

// parseTarget reads pod/x, deploy/x, sts/x, ds/x or a bare name.
func parseTarget(s string) (kind, name string, ok bool) {
	kind, name, typed := strings.Cut(s, "/")
	if !typed {
		kind, name = "", s
	} else if kind = workloadKinds[strings.ToLower(kind)]; kind == "" {
		return "", "", false
	}
	return kind, name, podNameRe.MatchString(name)
}

func cmdExplain(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, false)
	ns := addNamespaceFlag(fs)
	noLogs := fs.Bool("no-logs", false, "do not read the last log lines of crashing containers")
	output := addOutputFlag(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	kind, name, ok := "", "", len(pos) == 1
	if ok {
		kind, name, ok = parseTarget(pos[0])
	}
	if !ok || !config.ValidNamespace(*ns) {
		fmt.Fprintln(stderr, "usage: nedctl explain <pod|deploy/NAME|sts/NAME|ds/NAME> [-n NS] [--cluster C]")
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
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

	subject, findings, err := explainTarget(ctx, s, *ns, kind, name, !*noLogs)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitFailure
	}
	if *output == "json" {
		if code := writeJSON(stdout, stderr, map[string]any{"cluster": s.cluster, "namespace": *ns, "target": subject, "findings": findings}); code != ExitOK {
			return code
		}
	} else {
		printFindings(stdout, cfg, s, *ns, subject, findings)
	}
	for _, f := range findings {
		if f.Severity == "fail" {
			return ExitFailure
		}
	}
	return ExitOK
}

// addNamespaceFlag registers -n/--namespace (default "default").
func addNamespaceFlag(fs *flag.FlagSet) *string {
	ns := new(string)
	fs.StringVar(ns, "n", "default", "namespace")
	fs.StringVar(ns, "namespace", "default", "namespace")
	return ns
}

// explainTarget reads the target, its pods and events and explains them.
func explainTarget(ctx context.Context, s *kubeSession, ns, kind, name string, logs bool) (string, []finding, error) {
	var pods []kubePod
	var wl *kubeWorkload
	subject := name
	if kind == "" || kind == "pod" {
		out, err := s.output(ctx, "", "get", "pod", name, "-n", ns, "-o", "json")
		switch {
		case err == nil:
			var p kubePod
			if err := json.Unmarshal(out, &p); err != nil {
				return "", nil, fmt.Errorf("reading pod %s: %w", name, err)
			}
			pods, subject = []kubePod{p}, "pod/"+name
		case kind == "pod":
			return "", nil, fmt.Errorf("pod %s in %s: %v", name, ns, err)
		default:
			kind = "deployment" // a bare name that is not a pod: the deployment of that name
		}
	}
	if wl == nil && kind != "" && kind != "pod" {
		out, err := s.output(ctx, "", "get", kind, name, "-n", ns, "-o", "json")
		if err != nil {
			return "", nil, fmt.Errorf("%s %s in %s: %v", kind, name, ns, err)
		}
		wl = &kubeWorkload{}
		if err := json.Unmarshal(out, wl); err != nil {
			return "", nil, fmt.Errorf("reading %s %s: %w", kind, name, err)
		}
		subject = kind + "/" + name
		sel := wl.selector()
		if sel == "" {
			return "", nil, fmt.Errorf("%s has no label selector to find its pods", subject)
		}
		out, err = s.output(ctx, "", "get", "pods", "-n", ns, "-l", sel, "-o", "json")
		if err != nil {
			return "", nil, fmt.Errorf("listing the pods of %s: %v", subject, err)
		}
		var list struct{ Items []kubePod }
		if err := json.Unmarshal(out, &list); err != nil {
			return "", nil, fmt.Errorf("reading the pods of %s: %w", subject, err)
		}
		pods = list.Items
	}
	var events []kubeEvent
	if out, err := s.output(ctx, "", "get", "events", "-n", ns, "-o", "json"); err == nil {
		var list struct{ Items []kubeEvent }
		if json.Unmarshal(out, &list) == nil {
			events = list.Items
		}
	}
	findings := analyse(wl, pods, events)
	if logs {
		for i, f := range findings {
			if f.Severity == "fail" && f.Container != "" && strings.Contains(f.What, "restart") {
				findings[i].Logs = lastLogs(ctx, s, ns, f.Pod, f.Container)
			}
		}
	}
	return subject, findings, nil
}

// lastLogs is the crashed run's last lines (else the current run's).
func lastLogs(ctx context.Context, s *kubeSession, ns, pod, container string) []string {
	out, err := s.output(ctx, "", "logs", pod, "-n", ns, "-c", container, "--previous", "--tail=15")
	if err != nil {
		if out, err = s.output(ctx, "", "logs", pod, "-n", ns, "-c", container, "--tail=15"); err != nil {
			return nil
		}
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if l = strings.TrimRight(l, "\r"); l != "" {
			if len(l) > 200 {
				l = l[:200] + "…"
			}
			lines = append(lines, l)
		}
	}
	return lines
}

var restartsRe = regexp.MustCompile(`\d+ restarts`)

var insufficientRe = regexp.MustCompile(`Insufficient (cpu|memory|nvidia\.com/gpu|ephemeral-storage)`)

// analyse turns the state into findings, worst first.
func analyse(wl *kubeWorkload, pods []kubePod, events []kubeEvent) []finding {
	var fs []finding
	add := func(f finding) { fs = append(fs, f) }
	eventsFor := func(name string) []kubeEvent {
		var out []kubeEvent
		for _, e := range events {
			if e.InvolvedObject.Name == name && e.Type == "Warning" {
				out = append(out, e)
			}
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i].LastTimestamp.After(out[j].LastTimestamp) })
		return out
	}
	if wl != nil {
		for _, c := range wl.Status.Conditions {
			if c.Type == "Progressing" && c.Reason == "ProgressDeadlineExceeded" {
				add(finding{Severity: "fail", What: "the rollout is stuck: " + c.Message,
					Fix: "the new pods do not become ready — see the pod findings below; `kubectl rollout undo` returns to the previous version"})
			}
		}
		if wl.desired() == 0 {
			add(finding{Severity: "warn", What: wl.Kind + " is scaled to 0 replicas", Fix: "scale it up if it should be running"})
		} else if len(pods) == 0 {
			add(finding{Severity: "fail", What: "no pods exist for it", Fix: "check the ReplicaSet's events: quota, admission policy or a missing service account can stop pods being created"})
			for _, e := range events {
				if e.Type == "Warning" && (e.Reason == "FailedCreate" || strings.Contains(e.Message, "forbidden")) {
					add(finding{Severity: "fail", What: e.InvolvedObject.Kind + " " + e.InvolvedObject.Name + ": " + e.Message})
				}
			}
		}
	}
	for _, p := range pods {
		pod := p.Metadata.Name
		limits := map[string]map[string]string{}
		for _, c := range p.Spec.Containers {
			limits[c.Name] = c.Resources.Limits
		}
		if p.Status.Reason == "Evicted" {
			add(finding{Severity: "warn", Pod: pod, What: "evicted: " + p.Status.Message, Fix: "the node ran short of memory or disk; set requests that match real use"})
			continue
		}
		if p.Metadata.DeletionTimestamp != nil {
			add(finding{Severity: "warn", Pod: pod, What: "is being deleted (Terminating)", Fix: "if it stays: a finalizer or an unreachable node holds it"})
		}
		if p.Status.Phase == "Pending" {
			for _, c := range p.Status.Conditions {
				if c.Type == "PodScheduled" && c.Status == "False" {
					fix := "check the pod's node selector, affinity and tolerations"
					switch {
					case insufficientRe.MatchString(c.Message):
						fix = "no node has room for its requests: lower resources.requests, or the platform team adds capacity"
					case strings.Contains(c.Message, "taint"):
						fix = "the free nodes have taints the pod does not tolerate: add a toleration or target the right node pool"
					case strings.Contains(c.Message, "persistentvolumeclaim") || strings.Contains(c.Message, "PersistentVolumeClaim"):
						fix = "its volume claim is not bound: check the PVC and its storage class"
					}
					add(finding{Severity: "fail", Pod: pod, What: "cannot be scheduled: " + c.Message, Fix: fix})
				}
			}
		}
		statuses := append(append([]kubeContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...)
		failing := false
		for _, cs := range statuses {
			failing = addContainer(add, pod, cs, limits[cs.Name]) || failing
		}
		if p.Status.Phase == "Running" && !failing { // a crashing container explains not being ready
			for _, c := range p.Status.Conditions {
				if c.Type == "Ready" && c.Status == "False" {
					why := "not ready"
					for _, e := range eventsFor(pod) {
						if e.Reason == "Unhealthy" {
							why = "not ready: " + e.Message
							break
						}
					}
					add(finding{Severity: "warn", Pod: pod, What: why, Fix: "the readiness probe fails, so it gets no traffic: check the probe's path, port and timing against the app"})
				}
			}
		}
		for _, e := range eventsFor(pod) {
			switch e.Reason {
			case "FailedMount", "FailedAttachVolume":
				add(finding{Severity: "fail", Pod: pod, What: "volume: " + e.Message, Fix: "a missing Secret/ConfigMap, or a disk still attached to another node"})
			case "Unhealthy":
				if strings.HasPrefix(e.Message, "Liveness") {
					add(finding{Severity: "warn", Pod: pod, What: fmt.Sprintf("%s (%d×)", e.Message, max(e.Count, 1)),
						Fix: "a failing liveness probe restarts the container: give it a longer initialDelaySeconds or timeoutSeconds, or fix the endpoint"})
				}
			}
		}
	}
	if wl != nil && len(fs) == 0 && wl.ready() < wl.desired() {
		add(finding{Severity: "warn", What: fmt.Sprintf("only %d of %d replicas ready", wl.ready(), wl.desired()),
			Fix: "pods may still be starting; run explain again in a minute"})
	}
	if len(fs) == 0 {
		ready := 0
		for _, p := range pods {
			for _, c := range p.Status.Conditions {
				if c.Type == "Ready" && c.Status == "True" {
					ready++
				}
			}
		}
		add(finding{Severity: "ok", What: fmt.Sprintf("nothing wrong found: %d of %d pod(s) ready", ready, len(pods))})
	}
	sort.SliceStable(fs, func(i, j int) bool { return sevRank(fs[i].Severity) < sevRank(fs[j].Severity) })
	return dedupeFindings(fs)
}

// addContainer adds what is wrong with one container; it reports whether
// that is a failure.
func addContainer(add func(finding), pod string, cs kubeContainerStatus, limits map[string]string) bool {
	f := finding{Pod: pod, Container: cs.Name}
	restarts := ""
	if cs.RestartCount > 0 {
		restarts = fmt.Sprintf(", %d restarts", cs.RestartCount)
	}
	last := cs.LastState.Terminated
	if w := cs.State.Waiting; w != nil {
		switch w.Reason {
		case "ImagePullBackOff", "ErrImagePull", "InvalidImageName":
			f.Severity, f.What = "fail", "cannot pull its image "+cs.Image+": "+firstNonBlank(w.Message, w.Reason)
			f.Fix = "check the image name and tag exist, and that the cluster may pull from that registry (imagePullSecrets; some clusters only reach an internal registry)"
		case "CrashLoopBackOff":
			f.Severity = "fail"
			f.What, f.Fix = crashReason(last, limits, restarts)
		case "CreateContainerConfigError", "CreateContainerError", "RunContainerError":
			f.Severity, f.What = "fail", "cannot start: "+firstNonBlank(w.Message, w.Reason)
			f.Fix = "usually a Secret or ConfigMap (or a key in it) that does not exist in this namespace"
		case "ContainerCreating", "PodInitializing":
		default:
			f.Severity, f.What = "warn", "waiting: "+firstNonBlank(w.Message, w.Reason)
		}
	}
	if f.Severity == "" && last != nil && last.Reason == "OOMKilled" {
		f.Severity, f.What, f.Fix = "warn", "was killed for using more memory than its limit"+limitText(limits, "memory")+restarts,
			"raise resources.limits.memory, or find what uses the memory"
	}
	if f.Severity == "" && cs.RestartCount >= 3 && last != nil {
		f.Severity = "warn"
		f.What, f.Fix = crashReason(last, limits, restarts)
	}
	if f.Severity != "" {
		add(f)
	}
	return f.Severity == "fail"
}

// crashReason explains why a container exited.
func crashReason(t *struct {
	Reason, Message string
	ExitCode        int       `json:"exitCode"`
	FinishedAt      time.Time `json:"finishedAt"`
}, limits map[string]string, restarts string) (string, string) {
	if t == nil {
		return "keeps crashing and restarting" + restarts, "read its logs: nedctl logs"
	}
	switch {
	case t.Reason == "OOMKilled":
		return "keeps being killed for using more memory than its limit" + limitText(limits, "memory") + restarts,
			"raise resources.limits.memory, or find what uses the memory"
	case t.ExitCode == 137:
		return "keeps being killed (exit 137)" + restarts, "killed from outside: often a failing liveness probe or memory pressure on the node"
	case t.ExitCode == 143:
		return "keeps stopping on SIGTERM (exit 143)" + restarts, "something stops it: a failing liveness probe, or the app exits on SIGTERM too early"
	case t.Reason == "Completed" || t.ExitCode == 0:
		return "keeps exiting normally (exit 0) and restarting" + restarts, "a long-running container's main process must not end: check its command"
	case t.ExitCode == 126 || t.ExitCode == 127:
		return fmt.Sprintf("keeps failing to start its command (exit %d)", t.ExitCode) + restarts, "the command or entrypoint is not in the image, or is not executable"
	}
	return fmt.Sprintf("keeps crashing with exit code %d", t.ExitCode) + restarts, "the application fails at start-up: the last log lines below usually say why"
}

func limitText(limits map[string]string, res string) string {
	if v := limits[res]; v != "" {
		return " (" + v + ")"
	}
	return " (no limit set: the node ran short)"
}

func sevRank(s string) int {
	switch s {
	case "fail":
		return 0
	case "warn":
		return 1
	}
	return 2
}

// dedupeFindings drops findings repeated for every replica, counting them.
func dedupeFindings(fs []finding) []finding {
	var out []finding
	seen := map[string]int{}
	for _, f := range fs {
		key := f.Severity + "|" + f.Container + "|" + restartsRe.ReplaceAllString(f.What, "")
		if i, ok := seen[key]; ok && f.Pod != "" {
			if !strings.Contains(out[i].Pod, " and ") {
				out[i].Pod += " and others"
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, f)
	}
	return out
}

func printFindings(w io.Writer, cfg config.Config, s *kubeSession, ns, subject string, fs []finding) {
	st := ui.Style{Color: colorOn(w)}
	fmt.Fprintf(w, "%s in %s on %s\n\n", st.Bold(subject), ns, st.Fg(cfg.ColorFor(s.env), s.label()))
	for _, f := range fs {
		where := f.Pod
		if f.Container != "" {
			where += " (container " + f.Container + ")"
		}
		if where != "" {
			where += ": "
		}
		switch f.Severity {
		case "fail":
			fmt.Fprintf(w, "%s\n", st.Fail(where+f.What))
		case "warn":
			fmt.Fprintf(w, "%s\n", st.Warn(where+f.What))
		default:
			fmt.Fprintf(w, "%s\n", st.OK(where+f.What))
		}
		if f.Fix != "" {
			fmt.Fprintf(w, "  %s\n", st.Hint(f.Fix))
		}
		if len(f.Logs) > 0 {
			fmt.Fprintf(w, "  %s\n", st.Dim("last log lines:"))
			for _, l := range f.Logs {
				fmt.Fprintf(w, "    %s %s\n", st.Dim("|"), l)
			}
		}
	}
}
