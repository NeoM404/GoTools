package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// `nedctl changes` answers the first question of an incident — what
// changed? — as one timeline per cluster or environment: rollouts (with the
// image before and after), DaemonSet and StatefulSet revisions, ConfigMap
// edits, RBAC, network policy, ingress and Istio edits (who wrote them, from
// managedFields), nodes joining or turning NotReady, autoscaler scaling,
// container restarts with their reason, and warning events. Secrets are not
// read: listing them returns their values. Read-only, and gentle (see
// gentle.go).

// clusterChange is one thing that changed.
type clusterChange struct {
	Time        time.Time `json:"time"`
	Environment string    `json:"environment,omitempty"`
	Cluster     string    `json:"cluster"`
	Kind        string    `json:"kind"` // rollout, revision, config, rbac, network, mesh, node, scale, restart, warning
	Object      string    `json:"object"`
	What        string    `json:"what"`
	By          string    `json:"by,omitempty"`
}

// changesProbes lists what changes leave behind; ns narrows the namespaced
// ones.
func changesProbes(ns string) []probe {
	return []probe{
		versionProbe,
		listProbe("replicasets", ns, `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.ownerReferences[0].name}{"\t"}{.metadata.annotations.deployment\.kubernetes\.io/revision}{"\t"}{.metadata.annotations.deployment\.kubernetes\.io/revision-history}{"\t"}{.metadata.creationTimestamp}{"\t"}{.spec.template.spec.containers[*].image}{"\t"}`+managedFieldsPath+`{"\n"}{end}`),
		listProbe("controllerrevisions", ns, `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.ownerReferences[0].kind}{"/"}{.metadata.ownerReferences[0].name}{"\t"}{.revision}{"\t"}{.metadata.creationTimestamp}{"\t"}{.data.spec.template.spec.containers[*].image}{"\n"}{end}`),
		listProbe("configmaps", ns, `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.metadata.creationTimestamp}{"\t"}`+managedFieldsPath+`{"\n"}{end}`),
		listProbe("networkpolicies,ingresses,roles,rolebindings,poddisruptionbudgets", ns, `{range .items[*]}{.kind}{"\t"}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.metadata.creationTimestamp}{"\t"}`+managedFieldsPath+`{"\n"}{end}`),
		clusterProbe("clusterrolebindings", `{range .items[*]}{.kind}{"\t"}{""}{"\t"}{.metadata.name}{"\t"}{.metadata.creationTimestamp}{"\t"}`+managedFieldsPath+`{"\n"}{end}`),
		clusterProbe("nodes", `{range .items[*]}{.metadata.name}{"\t"}{.metadata.creationTimestamp}{"\t"}{range .status.conditions[?(@.type=="Ready")]}{.status}{"\t"}{.lastTransitionTime}{end}{"\t"}{.spec.unschedulable}{"\n"}{end}`),
		listProbe("horizontalpodautoscalers", ns, `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.lastScaleTime}{"\t"}{.status.currentReplicas}{"\t"}{.status.desiredReplicas}{"\n"}{end}`),
		listProbe("pods", ns, `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{range .status.containerStatuses[*]}C{"\t"}{.name}{"\t"}{.restartCount}{"\t"}{.lastState.terminated.finishedAt}{"\t"}{.lastState.terminated.reason}{"\t"}{.lastState.terminated.exitCode}{"\n"}{end}{end}`),
		listProbe("events", ns, `{range .items[*]}{.metadata.namespace}{"\t"}{.involvedObject.kind}{"/"}{.involvedObject.name}{"\t"}{.reason}{"\t"}{.lastTimestamp}{"\t"}{.eventTime}{"\t"}{.count}{"\t"}{.message}{"\n"}{end}`, "--field-selector", "type=Warning"),
		listProbe("virtualservices.networking.istio.io,destinationrules.networking.istio.io,gateways.networking.istio.io,authorizationpolicies.security.istio.io,peerauthentications.security.istio.io", ns,
			`{range .items[*]}{.kind}{"\t"}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.metadata.creationTimestamp}{"\t"}`+managedFieldsPath+`{"\n"}{end}`),
	}
}

// Probe indexes in changesProbes.
const (
	chRS = iota + 1
	chRevisions
	chConfigMaps
	chObjects
	chClusterObjects
	chNodes
	chHPA
	chPods
	chEvents
	chIstio
)

func cmdChanges(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("changes", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, true)
	since := fs.Duration("since", 2*time.Hour, "how far back, e.g. 30m, 2h, 24h (at most 720h)")
	ns := fs.String("n", "", "only this namespace (and the cluster's own objects: nodes, cluster role bindings)")
	kinds := fs.String("kind", "", "only these kinds, e.g. rollout,config,rbac (rollout, revision, config, rbac, network, mesh, node, scale, restart, warning)")
	includeSystem := fs.Bool("include-system", false, "also the platform namespaces (security.ignoreNamespaces), noisy with controllers' own writes")
	output := addOutputFlag(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) > 0 || *since <= 0 || *since > 720*time.Hour || (*ns != "" && !config.ValidNamespace(*ns)) {
		fmt.Fprintln(stderr, "usage: nedctl changes [--cluster C | --env qa | --aws | --aws-env ete,qa] [--match WORD] [--since 2h] [-n NS] [--kind rollout,config,…] [-o json]")
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	want := map[string]bool{}
	for _, k := range strings.Split(*kinds, ",") {
		if k = strings.TrimSpace(k); k != "" {
			want[k] = true
		}
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	results, code := runProbes(ctx, cfg, sel, changesProbes(*ns), stderr)
	if code != ExitOK {
		return code
	}
	from := now().Add(-*since)
	var all []clusterChange
	var notes []string
	for _, r := range results {
		cs, n := clusterChanges(cfg, r, from, *includeSystem)
		notes = append(notes, n...)
		for _, c := range cs {
			if len(want) == 0 || want[c.Kind] {
				all = append(all, c)
			}
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.After(all[j].Time) })
	if *output == "json" {
		if all == nil {
			all = []clusterChange{}
		}
		return writeJSON(stdout, stderr, map[string]any{"since": from.UTC().Format(time.RFC3339), "changes": all, "notes": notes})
	}
	printChanges(stdout, all, len(results) > 1, *since)
	for _, n := range notes {
		fmt.Fprintln(stderr, "note: "+n)
	}
	return ExitOK
}

// clusterChanges reads one cluster's results into changes since from.
func clusterChanges(cfg config.Config, r clusterOut, from time.Time, includeSystem bool) ([]clusterChange, []string) {
	name := firstNonBlank(r.Cluster, r.Where)
	if err := r.reachErr(); err != nil {
		return nil, []string{fmt.Sprintf("%s: not read: %v", name, err)}
	}
	var out []clusterChange
	var notes []string
	add := func(t time.Time, kind, object, what, by string) {
		if t.IsZero() || t.Before(from) {
			return
		}
		out = append(out, clusterChange{Time: t.UTC(), Environment: r.Env, Cluster: name, Kind: kind, Object: object, What: what, By: by})
	}
	skip := func(ns string) bool { return ns != "" && !includeSystem && cfg.Security.Ignored(ns) }
	lines := func(i int, what string) []string {
		if i >= len(r.Outs) {
			return nil
		}
		if err := r.Outs[i].Err; err != nil {
			if !notInstalled(err) {
				notes = append(notes, fmt.Sprintf("%s: %s not read: %v", name, what, err))
			}
			return nil
		}
		return nonEmptyLines(string(r.Outs[i].Out))
	}

	// Rollouts: a Deployment's ReplicaSets by revision; a new one is a
	// rollout, with the images before and after.
	type rs struct {
		rev            int
		history, image string
		created, wrote time.Time
	}
	byOwner := map[string][]rs{}
	for _, l := range lines(chRS, "replica sets") {
		f := strings.Split(l, "\t")
		if len(f) < 7 || skip(f[0]) || f[1] == "" {
			continue
		}
		rev, _ := strconv.Atoi(f[2])
		wrote, _ := lastWrite(f[6])
		key := f[0] + "/" + f[1]
		byOwner[key] = append(byOwner[key], rs{rev: rev, history: f[3], created: parseTime(f[4]), image: strings.Join(strings.Fields(f[5]), " "), wrote: wrote})
	}
	for owner, list := range byOwner {
		sort.Slice(list, func(i, j int) bool { return list[i].rev < list[j].rev })
		for i, x := range list {
			obj := "deploy/" + owner
			switch {
			case x.history != "" && i == len(list)-1:
				add(x.wrote, "rollout", obj, fmt.Sprintf("back on revision %d (%s) — a rollback, or the same template applied again", x.rev, x.image), "")
			case i == 0 && x.rev <= 1:
				add(x.created, "rollout", obj, "created ("+x.image+")", "")
			case i == 0:
				add(x.created, "rollout", obj, fmt.Sprintf("revision %d: %s (the revision before is no longer kept)", x.rev, x.image), "")
			case i > 0 && list[i-1].image != x.image:
				add(x.created, "rollout", obj, fmt.Sprintf("revision %d: %s → %s", x.rev, list[i-1].image, x.image), "")
			default:
				add(x.created, "rollout", obj, fmt.Sprintf("revision %d: same image, the pod template changed (environment, config, resources or annotations)", x.rev), "")
			}
		}
	}
	// DaemonSet and StatefulSet revisions.
	for _, l := range lines(chRevisions, "controller revisions") {
		f := strings.Split(l, "\t")
		if len(f) < 5 || skip(f[0]) {
			continue
		}
		what := "revision " + f[2]
		if img := strings.Join(strings.Fields(f[4]), " "); img != "" {
			what += ": " + img
		}
		kind, owner, _ := strings.Cut(f[1], "/")
		add(parseTime(f[3]), "revision", strings.ToLower(kind)+"/"+f[0]+"/"+owner, what, "")
	}
	// ConfigMaps.
	for _, l := range lines(chConfigMaps, "config maps") {
		f := strings.Split(l, "\t")
		if len(f) < 4 || skip(f[0]) {
			continue
		}
		created := parseTime(f[2])
		at, by := lastWrite(f[3])
		obj := "configmap/" + f[0] + "/" + f[1]
		if at.Sub(created) > time.Second {
			add(at, "config", obj, "edited", by)
		} else {
			add(created, "config", obj, "created", by)
		}
	}
	// Policies, ingresses, RBAC; the same for Istio's objects when installed.
	objects := func(i int, what string) {
		for _, l := range lines(i, what) {
			f := strings.Split(l, "\t")
			if len(f) < 5 || skip(f[1]) {
				continue
			}
			kind := map[string]string{"NetworkPolicy": "network", "Ingress": "network", "Role": "rbac", "RoleBinding": "rbac", "ClusterRoleBinding": "rbac", "PodDisruptionBudget": "config"}[f[0]]
			if i == chIstio {
				kind = "mesh"
			}
			obj := strings.ToLower(f[0]) + "/" + strings.TrimPrefix(f[1]+"/"+f[2], "/")
			created := parseTime(f[3])
			at, by := lastWrite(f[4])
			if at.Sub(created) > time.Second {
				add(at, kind, obj, "edited", by)
			} else {
				add(created, kind, obj, "created", by)
			}
		}
	}
	objects(chObjects, "policies, ingresses and RBAC")
	objects(chClusterObjects, "cluster role bindings")
	objects(chIstio, "Istio objects")
	// Nodes.
	for _, l := range lines(chNodes, "nodes") {
		f := strings.Split(l, "\t")
		if len(f) < 4 {
			continue
		}
		created := parseTime(f[1])
		add(created, "node", "node/"+f[0], "joined", "")
		if t := parseTime(f[3]); t.Sub(created) > time.Minute {
			state := "became Ready"
			if f[2] != "True" {
				state = "turned NotReady (" + firstNonBlank(f[2], "Unknown") + ")"
			}
			if len(f) > 4 && f[4] == "true" {
				state += "; cordoned"
			}
			add(t, "node", "node/"+f[0], state, "")
		}
	}
	// Autoscaling.
	for _, l := range lines(chHPA, "autoscalers") {
		f := strings.Split(l, "\t")
		if len(f) < 5 || skip(f[0]) {
			continue
		}
		add(parseTime(f[2]), "scale", "hpa/"+f[0]+"/"+f[1], fmt.Sprintf("scaled to %s (now %s running)", firstNonBlank(f[4], "?"), firstNonBlank(f[3], "?")), "")
	}
	// Restarts: each container's last termination.
	pod := ""
	for _, l := range lines(chPods, "pods") {
		f := strings.Split(l, "\t")
		switch {
		case len(f) >= 2 && f[0] != "C":
			pod = ""
			if !skip(f[0]) {
				pod = f[0] + "/" + f[1]
			}
		case len(f) >= 6 && f[0] == "C" && pod != "":
			what := fmt.Sprintf("container %s restarted (%s, exit %s) — %s restart(s) in all", f[1], firstNonBlank(f[4], "?"), firstNonBlank(f[5], "?"), firstNonBlank(f[2], "?"))
			add(parseTime(f[3]), "restart", "pod/"+pod, what, "")
		}
	}
	// Warning events (the API server keeps them about an hour).
	for _, l := range lines(chEvents, "events") {
		f := strings.SplitN(l, "\t", 7)
		if len(f) < 7 || skip(f[0]) {
			continue
		}
		at := parseTime(f[3])
		if at.IsZero() {
			at = parseTime(f[4])
		}
		msg := strings.TrimSpace(f[6])
		if len(msg) > 160 {
			msg = msg[:157] + "…"
		}
		what := f[2] + ": " + msg
		if n, _ := strconv.Atoi(f[5]); n > 1 {
			what += fmt.Sprintf(" (×%d)", n)
		}
		add(at, "warning", strings.ToLower(f[1])+" in "+f[0], what, "")
	}
	return out, notes
}

func printChanges(w io.Writer, all []clusterChange, multi bool, since time.Duration) {
	st := ui.Style{Color: colorOn(w)}
	if len(all) == 0 {
		fmt.Fprintf(w, "nothing changed in the last %s\n", shortDuration(since))
		return
	}
	tw := newTable(w)
	head := "WHEN\tKIND\tOBJECT\tWHAT"
	if multi {
		head = "WHEN\tCLUSTER\tKIND\tOBJECT\tWHAT"
	}
	fmt.Fprintln(tw, head)
	for _, c := range all {
		when := c.Time.Local().Format("15:04") + " (" + shortDuration(now().Sub(c.Time).Round(time.Minute)) + " ago)"
		if now().Sub(c.Time) > 24*time.Hour {
			when = c.Time.Local().Format("Jan 02 15:04")
		}
		what := c.What
		if c.By != "" {
			what += " by " + c.By
		}
		if multi {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", when, strings.TrimSpace(strings.ToUpper(c.Environment)+" "+c.Cluster), c.Kind, c.Object, what)
		} else {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", when, c.Kind, c.Object, what)
		}
	}
	tw.Flush()
	counts := map[string]int{}
	for _, c := range all {
		counts[c.Kind]++
	}
	var parts []string
	for _, k := range []string{"rollout", "revision", "config", "rbac", "network", "mesh", "node", "scale", "restart", "warning"} {
		if counts[k] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[k], k))
		}
	}
	fmt.Fprintf(w, "\n%d change(s) in the last %s: %s\n", len(all), shortDuration(since), strings.Join(parts, " · "))
	fmt.Fprintln(w, st.Dim("Secrets are not read (listing them returns their values) · warning events are kept about an hour · \"by\" is the writer recorded in managedFields"))
}
