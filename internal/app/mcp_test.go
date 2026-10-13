package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mcpSession sends requests to nedctl mcp and returns its replies by id.
func mcpSession(t *testing.T, cfg string, requests ...string) map[float64]map[string]any {
	t.Helper()
	old := stdin
	stdin = strings.NewReader(strings.Join(requests, "\n") + "\n")
	t.Cleanup(func() { stdin = old })
	code, out, errb := run("--config", cfg, "mcp")
	if code != ExitOK {
		t.Fatalf("mcp: code=%d err=%q", code, errb)
	}
	replies := map[float64]map[string]any{}
	for _, l := range nonEmptyLines(out) {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON-RPC on stdout: %q", l)
		}
		id, _ := m["id"].(float64)
		replies[id] = m
	}
	return replies
}

func toolText(t *testing.T, reply map[string]any) (string, bool) {
	t.Helper()
	res, ok := reply["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", reply)
	}
	content := res["content"].([]any)[0].(map[string]any)
	return content["text"].(string), res["isError"].(bool)
}

func TestMCPServesReadOnlyToolsAndRecordsEachCall(t *testing.T) {
	today := time.Now()
	f := newClusterFixture(t, "", "pay-k8s-qa-cluster")
	probes := expiryProbes("")
	answerProbes(t, f, "pay-k8s-qa-cluster", probes, map[int]string{
		0:         `{"gitVersion":"v1.31.2"}`,
		exSecrets: "payments\tapi-tls\t\t" + b64(testCert(t, "api.bank.example", today.Add(3*24*time.Hour))) + "\n",
	})
	t.Setenv("NEDCTL_TEST_AS_NEDCTL", "1") // tools run as their own nedctl process: this binary

	replies := mcpSession(t, f.cfg,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"kiro","version":"1.2"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"expiry","arguments":{"env":"qa"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"expiry","arguments":{"env":"--kubeconfig=/etc/x"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"expiry","arguments":{"env":"qa;rm -rf /"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"expiry","arguments":{"kubeconfig":"/etc/x"}}}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"logs","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"explain","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":9,"method":"nope"}`,
		`{"jsonrpc":"2.0","id":10,"method":"ping"}`,
	)
	init := replies[1]["result"].(map[string]any)
	if init["protocolVersion"] != "2025-06-18" || init["serverInfo"].(map[string]any)["name"] != "nedctl" {
		t.Fatalf("initialize: %v", init)
	}
	var names []string
	for _, x := range replies[2]["result"].(map[string]any)["tools"].([]any) {
		tool := x.(map[string]any)
		names = append(names, tool["name"].(string))
		if tool["annotations"].(map[string]any)["readOnlyHint"] != true {
			t.Fatalf("every tool is read-only: %v", tool)
		}
	}
	for _, n := range names {
		if n == "logs" || n == "debug" || n == "run" || n == "cp" {
			t.Fatalf("%s must never be offered to an agent", n)
		}
	}
	if !contains(names, "upgrade_check") || !contains(names, "expiry") || !contains(names, "changes") {
		t.Fatalf("tools: %v", names)
	}

	text, isErr := toolText(t, replies[3])
	var doc struct {
		Schema   string            `json:"schema"`
		Clusters []clusterFindings `json:"clusters"`
	}
	if isErr || json.Unmarshal([]byte(strings.SplitN(text, "\n\nnedctl notes:", 2)[0]), &doc) != nil || doc.Schema != findingsSchema || doc.Clusters[0].Findings[0].Object != "secret/payments/api-tls" {
		t.Fatalf("expiry through MCP: err=%v %s", isErr, text)
	}
	if strings.Contains(text, "PRIVATE KEY") {
		t.Fatal("never a key")
	}
	for id, want := range map[float64]string{4: "not a name nedctl accepts", 5: "not a name nedctl accepts", 6: "unknown argument", 7: "no such tool", 8: "target is required"} {
		text, isErr := toolText(t, replies[id])
		if !isErr || !strings.Contains(text, want) {
			t.Fatalf("call %v: %q (error %v), want %q", id, text, isErr, want)
		}
	}
	if replies[9]["error"].(map[string]any)["code"].(float64) != -32601 || replies[10]["result"] == nil {
		t.Fatalf("errors: %v %v", replies[9], replies[10])
	}
	// One recorded call (refused arguments never ran), with the agent named.
	var calls int
	for _, e := range readAudit(t, f.logPath) {
		if e.Action == "agent-tool" && e.Phase == "end" {
			calls++
			if !strings.Contains(e.Detail, "for kiro 1.2") || !strings.Contains(e.Detail, "nedctl expiry --env qa -o json") {
				t.Fatalf("audit: %+v", e)
			}
		}
	}
	if calls != 1 {
		t.Fatalf("%d agent-tool records, want 1", calls)
	}
}

func TestMCPToolArgsAreNamesNotFlags(t *testing.T) {
	var up mcpTool
	for _, x := range mcpTools {
		if x.Name == "upgrade_check" {
			up = x
		}
	}
	args, err := up.toolArgs(map[string]any{"cluster": "payments-eks-qa", "target": "1.33", "aws": false})
	if err != nil || strings.Join(args, " ") != "upgrade-check --cluster payments-eks-qa --target 1.33 -o json" {
		t.Fatalf("%v %v", args, err)
	}
	for _, bad := range []any{"-x", "a b", "$(id)", "../..", strings.Repeat("a", 300), true} {
		if _, err := up.toolArgs(map[string]any{"cluster": bad}); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if _, err := up.toolArgs(map[string]any{"aws": "yes"}); err == nil {
		t.Error("a bool must be a bool")
	}
}

func TestMCPCanBeTurnedOffOrNarrowed(t *testing.T) {
	cfg := writeConfig(t, `, "agents":{"disabled":true}`)
	if code, _, errb := run("--config", cfg, "mcp"); code != ExitFailure || !strings.Contains(errb, "agents.disabled") {
		t.Fatalf("disabled: %d %q", code, errb)
	}
	cfg = writeConfig(t, `, "agents":{"tools":["expiry"]}`)
	_, out, _ := run("--config", cfg, "mcp", "tools")
	if !strings.Contains(out, "expiry") || strings.Contains(out, "upgrade_check") {
		t.Fatalf("narrowed: %s", out)
	}
}

func TestAgentsSetupWritesOnlyNewFiles(t *testing.T) {
	home, _ := os.UserHomeDir()
	repo := t.TempDir()
	code, _, errb := run("agents", "setup", "copilot", "--dir", repo)
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, p := range []string{".vscode/mcp.json", ".github/agents/eks-upgrade.agent.md", ".github/skills/eks-upgrade-readiness/SKILL.md"} {
		data, err := os.ReadFile(filepath.Join(repo, p))
		if err != nil || len(data) == 0 {
			t.Fatalf("%s: %v", p, err)
		}
	}
	mcp, _ := os.ReadFile(filepath.Join(repo, ".vscode/mcp.json"))
	var conf map[string]map[string]map[string]any
	if json.Unmarshal(mcp, &conf) != nil || conf["servers"]["nedctl"]["command"] != "nedctl" {
		t.Fatalf("mcp.json: %s", mcp)
	}
	skill, _ := os.ReadFile(filepath.Join(repo, ".github/skills/eks-upgrade-readiness/SKILL.md"))
	if !bytes.HasPrefix(skill, []byte("---\nname: eks-upgrade-readiness\ndescription: ")) {
		t.Fatalf("skill frontmatter:\n%s", skill[:80])
	}
	// Again: nothing is overwritten.
	_, out, _ := run("agents", "setup", "copilot", "--dir", repo)
	if !strings.Contains(out, "already has nedctl") || !strings.Contains(out, "left as it is") {
		t.Fatalf("second run: %s", out)
	}
	// An MCP config someone else wrote: shown what to add, not edited.
	os.WriteFile(filepath.Join(repo, ".mcp.json"), []byte(`{"mcpServers":{"other":{}}}`), 0o600)
	_, out, _ = run("agents", "setup", "claude", "--dir", repo)
	if data, _ := os.ReadFile(filepath.Join(repo, ".mcp.json")); string(data) != `{"mcpServers":{"other":{}}}` || !strings.Contains(out, "add this server") {
		t.Fatalf("someone's .mcp.json was changed: %s\n%s", data, out)
	}
	// Kiro goes in ~/.kiro, with this nedctl's full path.
	if code, _, errb := run("agents", "setup", "kiro"); code != ExitOK {
		t.Fatalf("kiro: %q", errb)
	}
	self, _ := os.Executable()
	agent, err := os.ReadFile(filepath.Join(home, ".kiro", "agents", "eks-upgrade.json"))
	var a map[string]any
	if err != nil || json.Unmarshal(agent, &a) != nil || !strings.Contains(string(agent), filepath.Base(self)) {
		t.Fatalf("kiro agent: %v %s", err, agent)
	}
	if code, _, _ := run("agents", "setup", "nope"); code != ExitUsage {
		t.Fatal("unknown agent")
	}
}
