package app

import (
	"encoding/json"
	"strings"
	"testing"
)

func pods(t *testing.T, js string) []kubePod {
	t.Helper()
	var list struct{ Items []kubePod }
	if err := json.Unmarshal([]byte(`{"items":[`+js+`]}`), &list); err != nil {
		t.Fatal(err)
	}
	return list.Items
}

const (
	oomPod = `{"metadata":{"name":"api-1","namespace":"payments"},
 "spec":{"containers":[{"name":"api","image":"reg/api:1.4","resources":{"limits":{"memory":"256Mi"}}}]},
 "status":{"phase":"Running","conditions":[{"type":"Ready","status":"False"}],
  "containerStatuses":[{"name":"api","restartCount":4,"image":"reg/api:1.4",
   "state":{"waiting":{"reason":"CrashLoopBackOff","message":"back-off 5m0s restarting failed container"}},
   "lastState":{"terminated":{"reason":"OOMKilled","exitCode":137}}}]}}`
	pullPod = `{"metadata":{"name":"api-2"},"spec":{"containers":[{"name":"api","image":"docker.io/x/api:9"}]},
 "status":{"phase":"Pending","containerStatuses":[{"name":"api","image":"docker.io/x/api:9","state":{"waiting":{"reason":"ImagePullBackOff","message":"Back-off pulling image \"docker.io/x/api:9\""}}}]}}`
	pendingPod = `{"metadata":{"name":"api-3"},"spec":{"containers":[{"name":"api"}]},
 "status":{"phase":"Pending","conditions":[{"type":"PodScheduled","status":"False","reason":"Unschedulable","message":"0/3 nodes are available: 3 Insufficient memory."}]}}`
	configPod = `{"metadata":{"name":"api-4"},"spec":{"containers":[{"name":"api"}]},
 "status":{"phase":"Pending","containerStatuses":[{"name":"api","state":{"waiting":{"reason":"CreateContainerConfigError","message":"secret \"db-creds\" not found"}}}]}}`
	notReadyPod = `{"metadata":{"name":"api-5"},"spec":{"containers":[{"name":"api"}]},
 "status":{"phase":"Running","conditions":[{"type":"Ready","status":"False"}],"containerStatuses":[{"name":"api","ready":false,"state":{"running":{}}}]}}`
	healthyPod = `{"metadata":{"name":"api-6"},"spec":{"containers":[{"name":"api"}]},
 "status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}],"containerStatuses":[{"name":"api","ready":true,"state":{"running":{}}}]}}`
)

func TestAnalyseExplainsCommonFailures(t *testing.T) {
	events := []kubeEvent{{Type: "Warning", Reason: "Unhealthy", Message: "Readiness probe failed: HTTP probe failed with statuscode: 503", InvolvedObject: struct{ Kind, Name string }{"Pod", "api-5"}}}
	cases := []struct {
		pod, sev, what, fix string
	}{
		{oomPod, "fail", "keeps being killed for using more memory than its limit (256Mi), 4 restarts", "raise resources.limits.memory"},
		{pullPod, "fail", "cannot pull its image docker.io/x/api:9", "internal registry"},
		{pendingPod, "fail", "cannot be scheduled: 0/3 nodes are available: 3 Insufficient memory.", "lower resources.requests"},
		{configPod, "fail", `cannot start: secret "db-creds" not found`, "Secret or ConfigMap"},
		{notReadyPod, "warn", "not ready: Readiness probe failed: HTTP probe failed with statuscode: 503", "readiness probe"},
		{healthyPod, "ok", "nothing wrong found: 1 of 1 pod(s) ready", ""},
	}
	for _, c := range cases {
		fs := analyse(nil, pods(t, c.pod), events)
		if len(fs) == 0 || fs[0].Severity != c.sev || !strings.Contains(fs[0].What, c.what) || !strings.Contains(fs[0].Fix, c.fix) {
			t.Errorf("got %+v\nwant %s %q / %q", fs, c.sev, c.what, c.fix)
		}
	}
}

func TestAnalyseWorkloadAndReplicas(t *testing.T) {
	var wl kubeWorkload
	json.Unmarshal([]byte(`{"kind":"Deployment","spec":{"replicas":3,"selector":{"matchLabels":{"app":"api"}}},
 "status":{"conditions":[{"type":"Progressing","status":"False","reason":"ProgressDeadlineExceeded","message":"ReplicaSet \"api-7f9c\" has timed out progressing."}]}}`), &wl)
	fs := analyse(&wl, pods(t, oomPod+","+strings.Replace(oomPod, "api-1", "api-2", 1)), nil)
	if fs[0].What != `the rollout is stuck: ReplicaSet "api-7f9c" has timed out progressing.` {
		t.Fatalf("first: %+v", fs[0])
	}
	// The same failure on every replica is reported once.
	if len(fs) != 2 || fs[1].Pod != "api-1 and others" {
		t.Fatalf("findings: %+v", fs)
	}
	var none kubeWorkload
	json.Unmarshal([]byte(`{"kind":"Deployment","spec":{"replicas":2,"selector":{"matchLabels":{"app":"api"}}}}`), &none)
	fs = analyse(&none, nil, []kubeEvent{{Type: "Warning", Reason: "FailedCreate", Message: `pods "api-" is forbidden: exceeded quota`, InvolvedObject: struct{ Kind, Name string }{"ReplicaSet", "api-7f9c"}}})
	if len(fs) != 2 || fs[0].What != "no pods exist for it" || !strings.Contains(fs[1].What, "exceeded quota") {
		t.Fatalf("findings: %+v", fs)
	}
	if wl.selector() != "app=api" {
		t.Fatal(wl.selector())
	}
}

func TestExplainDeploymentOnACluster(t *testing.T) {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster")
	c := "acm-k8s-qa-cluster"
	f.answer(t, c, "get deployment payments-api -n payments -o json", `{"kind":"Deployment","metadata":{"name":"payments-api"},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"payments-api","tier":"web"}}},"status":{"readyReplicas":0}}`)
	f.answer(t, c, "get pods -n payments -l app=payments-api,tier=web -o json", `{"items":[`+oomPod+`]}`)
	f.answer(t, c, "get events -n payments -o json", `{"items":[]}`)
	f.answer(t, c, "logs api-1 -n payments -c api --previous --tail=15", "starting\njava.lang.OutOfMemoryError: Java heap space\n")
	code, out, errb := run("--config", f.cfg, "explain", "deploy/payments-api", "-n", "payments", "--cluster", c)
	if code != ExitFailure {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, want := range []string{"deployment/payments-api in payments on QA · acm-k8s-qa-cluster", "✖ api-1 (container api): keeps being killed for using more memory than its limit (256Mi), 4 restarts",
		"→ raise resources.limits.memory", "| java.lang.OutOfMemoryError: Java heap space"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	// A bare name that is not a pod is the deployment of that name.
	f.fail(t, c, "get pod payments-api -n payments -o json", `Error from server (NotFound): pods "payments-api" not found`)
	code, out, _ = run("--config", f.cfg, "explain", "payments-api", "-n", "payments", "--cluster", c, "--no-logs", "-o", "json")
	if code != ExitFailure || !strings.Contains(out, `"target": "deployment/payments-api"`) || strings.Contains(out, "OutOfMemoryError") {
		t.Fatalf("code=%d out=%s", code, out)
	}
	if code, _, _ := run("--config", f.cfg, "explain", "svc/x"); code != ExitUsage {
		t.Fatalf("svc accepted: %d", code)
	}
}
