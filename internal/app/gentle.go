package app

import (
	"strings"
	"time"
)

// Reading clusters gently. The checking commands (changes, expiry,
// upgrade-check, mesh, why, capacity, images scan) follow the same rules, so
// running them against a busy production cluster costs it little:
//
//   - each resource type is listed once per run, whatever number of checks
//     use it, and only on the namespace asked for when one is (-n);
//   - lists are paged (--chunk-size): the API server answers in pages of
//     listChunk objects, so no single response — or etcd read — is large;
//   - only the fields a check judges are printed (jsonpath), so little
//     crosses SSH or Session Manager and nothing more is kept;
//   - every request has a timeout; a cluster that does not answer its first
//     request is not asked the rest, and none is read for more than 90s;
//   - reads only: no watches, no exec into workloads, no proxying to pods,
//     and Secrets are never listed (a list returns their values) — except
//     TLS certificates, whose key never leaves kubectl;
//   - clusters are read eight at a time per bastion, EKS one after another.

// listChunk is the page size for every list.
const listChunk = "--chunk-size=250"

// versionProbe is first in every checking command: cheap, and it tells a
// cluster that answers from one that does not before anything else is asked.
var versionProbe = probe{"get", "--raw", "/version"}

// listProbe lists resource across all namespaces (or ns), paged, printing
// jsonpath.
func listProbe(resource, ns, jsonpath string, extra ...string) probe {
	scope := []string{"-A"}
	if ns != "" {
		scope = []string{"-n", ns}
	}
	p := probe{"get", resource}
	p = append(p, scope...)
	p = append(p, listChunk)
	p = append(p, extra...)
	return append(p, "-o", "jsonpath="+jsonpath)
}

// clusterProbe lists a cluster-scoped resource, paged.
func clusterProbe(resource, jsonpath string) probe {
	return probe{"get", resource, listChunk, "-o", "jsonpath=" + jsonpath}
}

// notInstalled reports a probe that failed because the cluster does not
// have the resource type (an add-on's CRD is not installed).
func notInstalled(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "doesn't have a resource type") || strings.Contains(s, "the server could not find the requested resource") ||
		strings.Contains(s, "no matches for kind")
}

// parseTime reads a Kubernetes timestamp ("" or bad: zero).
func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}
	}
	return t
}

// lastWrite is the latest of "time=manager=operation," managedFields
// entries: when the object was last written, by which tool.
func lastWrite(fields string) (time.Time, string) {
	var at time.Time
	by := ""
	for _, e := range strings.Split(fields, ",") {
		ts, manager, _ := strings.Cut(e, "=")
		manager, _, _ = strings.Cut(manager, "=")
		if t := parseTime(ts); t.After(at) {
			at, by = t, manager
		}
	}
	return at, by
}

// managedFieldsPath prints an object's managedFields as time=manager=operation,…
const managedFieldsPath = `{range .metadata.managedFields[*]}{.time}{"="}{.manager}{"="}{.operation}{","}{end}`
