package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"nedctl/internal/audit"
	"nedctl/internal/config"
	"nedctl/internal/safetext"
)

// `nedctl mcp` serves nedctl's read-only checks to AI agents — Kiro, GitHub
// Copilot, Claude Code — over the Model Context Protocol (JSON-RPC on
// stdio). The agent gets evidence through the bank's own access path
// (your sign-in, the audited tunnel), never credentials or a kubeconfig:
//
//   - only the tools below, each one nedctl command with -o json; nothing
//     that changes anything, no logs (personal data), no exec, no Secrets;
//   - arguments are checked (names, not flags) before anything runs;
//   - each call runs as its own nedctl process with no stdin, so no picker
//     or prompt can wait and nothing it prints can reach the protocol;
//   - every call is recorded in your audit trail (action "agent-tool"),
//     with the agent's name;
//   - agents.disabled turns it off; agents.tools narrows the list.

const mcpProtocol = "2025-06-18"

var mcpProtocols = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// mcpArg is one tool argument and the flag it becomes.
type mcpArg struct {
	Name, Desc string
	Flag       string // "" for a positional argument
	Bool       bool
	Required   bool
}

type mcpTool struct {
	Name, Desc string
	Command    []string // the nedctl command
	Args       []mcpArg
	Fixed      []string // always added (e.g. -o json)
}

// Selection arguments shared by the fleet-wide tools.
var (
	argCluster = mcpArg{Name: "cluster", Desc: "one cluster by name (EKS in the signed-in account, or AKS by name)", Flag: "--cluster"}
	argEnv     = mcpArg{Name: "env", Desc: "AKS: every cluster on these environments' bastions, e.g. qa or dev,qa", Flag: "--env"}
	argAWS     = mcpArg{Name: "aws", Desc: "every EKS cluster in the signed-in account", Flag: "--aws", Bool: true}
	argAWSEnv  = mcpArg{Name: "aws_env", Desc: "EKS: every cluster in your squad's accounts for these environments, e.g. ete,qa", Flag: "--aws-env"}
	argMatch   = mcpArg{Name: "match", Desc: "only clusters whose name contains this", Flag: "--match"}
	argProfile = mcpArg{Name: "aws_profile", Desc: "EKS: the AWS profile to read with (default: the current one)", Flag: "--aws-profile"}
	argNS      = mcpArg{Name: "namespace", Desc: "only this namespace", Flag: "-n"}
	fleetArgs  = []mcpArg{argCluster, argEnv, argAWS, argAWSEnv, argMatch, argProfile}
)

var mcpTools = []mcpTool{
	{Name: "whoami", Desc: "The AWS identity nedctl acts with: account, squad, environment, role, whether it is elevated, and when the sign-in expires.",
		Command: []string{"aws", "whoami"}, Fixed: []string{"-o", "json"}},
	{Name: "list_eks_clusters", Desc: "The EKS clusters in the signed-in account: version, region, authentication mode and endpoint exposure.",
		Command: []string{"eks", "auth"}, Fixed: []string{"-o", "json"}},
	{Name: "upgrade_check", Desc: "EKS upgrade readiness for the next Kubernetes version (or target): score, blockers, findings with fixes, add-ons to verify upstream (verify[] with URLs), the upgrade plan, and the facts read from AWS (EKS Upgrade Insights, add-on compatible builds, node groups, subnets). Read-only evidence in the nedctl.findings/v1 layout.",
		Command: []string{"upgrade-check"}, Fixed: []string{"-o", "json"},
		Args: []mcpArg{argCluster, argAWS, argAWSEnv, argMatch, argProfile, {Name: "target", Desc: "the Kubernetes version to assess, e.g. 1.33 (default: the next minor)", Flag: "--target"}}},
	{Name: "expiry", Desc: "What stops working on a date: TLS certificates (and cert-manager renewal), missing Ingress/Gateway certificates, webhook and API service CA bundles, the cluster CA, and the Kubernetes version's support window.",
		Command: []string{"expiry"}, Fixed: []string{"-o", "json", "--fail-on", "none"},
		Args: append(append([]mcpArg{}, fleetArgs...), argNS, mcpArg{Name: "days", Desc: "medium severity within this many days (default 30)", Flag: "--days"})},
	{Name: "changes", Desc: "What changed recently: rollouts with images before/after, config, RBAC, network and Istio edits with their writer, nodes, scaling, restarts, warning events. Secrets are never read.",
		Command: []string{"changes"}, Fixed: []string{"-o", "json"},
		Args: append(append([]mcpArg{}, fleetArgs...), argNS, mcpArg{Name: "since", Desc: "how far back, e.g. 2h (default) or 24h", Flag: "--since"}, mcpArg{Name: "kind", Desc: "only these kinds, e.g. rollout,config,rbac", Flag: "--kind"})},
	{Name: "health", Desc: "Each cluster's health: nodes, crash-looping or pending pods, workloads below their replicas, unbound volumes, expiring certificates, version support.",
		Command: []string{"health"}, Fixed: []string{"-o", "json"}, Args: fleetArgs},
	{Name: "posture", Desc: "Risky settings in what runs: privileged containers, host access, root, dangerous capabilities, secrets in environment variables (names only), public load balancers, unapproved registries.",
		Command: []string{"posture"}, Fixed: []string{"-o", "json"}, Args: fleetArgs},
	{Name: "explain", Desc: "Why a workload or pod is not working, in plain findings with what to do (logs are not read through an agent).",
		Command: []string{"explain"}, Fixed: []string{"-o", "json", "--no-logs"},
		Args: []mcpArg{{Name: "target", Desc: "deploy/NAME, sts/NAME, ds/NAME or a pod name", Required: true}, argNS, argCluster, {Name: "env", Desc: "AKS: the environment whose bastion to use", Flag: "--env"}}},
	{Name: "app", Desc: "One application in every environment: version, ready replicas and last change per cluster.",
		Command: []string{"app"}, Fixed: []string{"-o", "json"},
		Args: append([]mcpArg{{Name: "name", Desc: "part of the deployment or statefulset name", Required: true}}, fleetArgs...)},
	{Name: "diff", Desc: "The same deployment or statefulset side by side wherever it runs: images, replicas, resources, probes, environment variable NAMES and the ConfigMaps/Secrets it loads (names only).",
		Command: []string{"diff"}, Fixed: []string{"-o", "json"},
		Args: append([]mcpArg{{Name: "name", Desc: "the exact workload name", Required: true}}, append(append([]mcpArg{}, fleetArgs...), argNS)...)},
}

// mcpValue is what an argument may hold: names and short lists, never a
// flag.
var mcpValue = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/,=@-]{0,252}$`)

// toolArgs turns a call's arguments into the nedctl command line.
func (t mcpTool) toolArgs(in map[string]any) ([]string, error) {
	known := map[string]mcpArg{}
	for _, a := range t.Args {
		known[a.Name] = a
	}
	for k := range in {
		if _, ok := known[k]; !ok {
			return nil, fmt.Errorf("unknown argument %q", k)
		}
	}
	args := append([]string{}, t.Command...)
	var pos []string
	for _, a := range t.Args {
		v, ok := in[a.Name]
		if !ok || v == nil {
			if a.Required {
				return nil, fmt.Errorf("%s is required", a.Name)
			}
			continue
		}
		if a.Bool {
			b, isBool := v.(bool)
			if !isBool {
				return nil, fmt.Errorf("%s must be true or false", a.Name)
			}
			if b {
				args = append(args, a.Flag)
			}
			continue
		}
		var s string
		switch x := v.(type) {
		case string:
			s = x
		case float64:
			s = fmt.Sprint(int(x))
		default:
			return nil, fmt.Errorf("%s must be a string", a.Name)
		}
		if !mcpValue.MatchString(s) {
			return nil, fmt.Errorf("%s: %q is not a name nedctl accepts", a.Name, s)
		}
		if a.Flag == "" {
			pos = append(pos, s)
		} else {
			args = append(args, a.Flag, s)
		}
	}
	args = append(args, pos...)
	return append(args, t.Fixed...), nil
}

func (t mcpTool) schema() map[string]any {
	props := map[string]any{}
	var req []string
	for _, a := range t.Args {
		typ := "string"
		if a.Bool {
			typ = "boolean"
		}
		props[a.Name] = map[string]any{"type": typ, "description": a.Desc}
		if a.Required {
			req = append(req, a.Name)
		}
	}
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(req) > 0 {
		s["required"] = req
	}
	return s
}

// mcpRun runs one nedctl command for a tool: its own process, no stdin.
var mcpRun = func(ctx context.Context, cfgPath string, args []string) (stdout, stderr []byte, code int) {
	self, err := os.Executable()
	if err != nil {
		return nil, []byte(err.Error()), ExitFailure
	}
	if cfgPath != "" {
		args = append([]string{"--config", cfgPath}, args...)
	}
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, self, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, &out, &errb
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "NEDCTL_AGENT=1")
	err = cmd.Run()
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		return out.Bytes(), errb.Bytes(), ee.ExitCode()
	case err != nil:
		return out.Bytes(), []byte(err.Error()), ExitFailure
	}
	return out.Bytes(), errb.Bytes(), ExitOK
}

// mcpMaxOutput bounds what one call returns to the agent.
const mcpMaxOutput = 512 << 10

// mcpToolTimeout bounds one call (a fleet-wide upgrade check takes a while).
var mcpToolTimeout = 15 * time.Minute

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func cmdMCP(ctx context.Context, cfgPath string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "tools" {
		cfg, _, err := config.Load(cfgPath)
		if err != nil {
			fmt.Fprintf(stderr, "config error: %v\n", err)
			return ExitFailure
		}
		tw := newTable(stdout)
		fmt.Fprintln(tw, "TOOL\tRUNS")
		for _, t := range offeredTools(cfg) {
			fmt.Fprintf(tw, "%s\tnedctl %s %s\n", t.Name, strings.Join(t.Command, " "), strings.Join(t.Fixed, " "))
		}
		tw.Flush()
		return ExitOK
	}
	if len(args) > 0 {
		fmt.Fprintln(stderr, "usage: nedctl mcp          (an MCP server on stdio, started by the agent)\n       nedctl mcp tools    (the tools it offers)")
		return ExitUsage
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	if cfg.Agents.Disabled {
		fmt.Fprintln(stderr, "nedctl mcp is turned off here (agents.disabled)")
		return ExitFailure
	}
	s := &mcpServer{cfg: cfg, cfgPath: cfgPath, out: stdout, log: stderr, tools: offeredTools(cfg)}
	return s.serve(ctx, stdin)
}

func offeredTools(cfg config.Config) []mcpTool {
	if len(cfg.Agents.Tools) == 0 {
		return mcpTools
	}
	var out []mcpTool
	for _, t := range mcpTools {
		if contains(cfg.Agents.Tools, t.Name) {
			out = append(out, t)
		}
	}
	return out
}

type mcpServer struct {
	cfg     config.Config
	cfgPath string
	out     io.Writer
	log     io.Writer
	tools   []mcpTool
	client  string
	mu      sync.Mutex // one message at a time on stdout
	wg      sync.WaitGroup
}

func (s *mcpServer) send(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out.Write(append(b, '\n'))
}

func (s *mcpServer) reply(id json.RawMessage, result any) {
	s.send(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func (s *mcpServer) fail(id json.RawMessage, code int, msg string) {
	s.send(map[string]any{"jsonrpc": "2.0", "id": id, "error": rpcErr{code, msg}})
}

func (s *mcpServer) serve(ctx context.Context, in io.Reader) int {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m rpcMsg
		if err := json.Unmarshal(line, &m); err != nil || m.JSONRPC != "2.0" {
			s.fail(nil, -32700, "parse error")
			continue
		}
		if m.Method == "" { // a response to us: nedctl asks nothing
			continue
		}
		notification := len(m.ID) == 0
		switch m.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string
				ClientInfo      struct{ Name, Version string }
			}
			_ = json.Unmarshal(m.Params, &p)
			s.client = strings.TrimSpace(safetext.Text(p.ClientInfo.Name + " " + p.ClientInfo.Version))
			version := mcpProtocol
			if contains(mcpProtocols, p.ProtocolVersion) {
				version = p.ProtocolVersion
			}
			s.reply(m.ID, map[string]any{
				"protocolVersion": version,
				"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
				"serverInfo":      map[string]any{"name": "nedctl", "version": Version},
				"instructions": "nedctl reads EKS and AKS clusters through the bank's audited access path. Every tool is read-only and returns JSON evidence. " +
					"Use upgrade_check for EKS upgrade readiness; then verify each verify[] add-on at its URL and read release notes for anything listed as not assessed. " +
					"Never run the commands in a plan: they are for an engineer under an approved change record.",
			})
		case "notifications/initialized", "notifications/cancelled":
		case "ping":
			s.reply(m.ID, map[string]any{})
		case "tools/list":
			var list []map[string]any
			for _, t := range s.tools {
				list = append(list, map[string]any{"name": t.Name, "description": t.Desc, "inputSchema": t.schema(),
					"annotations": map[string]any{"readOnlyHint": true, "destructiveHint": false, "openWorldHint": true}})
			}
			s.reply(m.ID, map[string]any{"tools": list})
		case "tools/call":
			var p struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			if err := json.Unmarshal(m.Params, &p); err != nil {
				s.fail(m.ID, -32602, "invalid params")
				continue
			}
			s.wg.Add(1)
			go func(id json.RawMessage) {
				defer s.wg.Done()
				s.reply(id, s.call(ctx, p.Name, p.Arguments))
			}(m.ID)
		default:
			if !notification {
				s.fail(m.ID, -32601, "method not found: "+m.Method)
			}
		}
	}
	s.wg.Wait()
	return ExitOK
}

func toolResult(text string, isError bool) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isError}
}

// call runs one tool, recorded.
func (s *mcpServer) call(ctx context.Context, name string, in map[string]any) map[string]any {
	var tool *mcpTool
	for i := range s.tools {
		if s.tools[i].Name == name {
			tool = &s.tools[i]
		}
	}
	if tool == nil {
		return toolResult("no such tool: "+name, true)
	}
	args, err := tool.toolArgs(in)
	if err != nil {
		return toolResult(err.Error(), true)
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, fmt.Sprintf("%s=%v", k, in[k]))
	}
	sort.Strings(keys)
	ev := audit.Event{Action: "agent-tool", Detail: fmt.Sprintf("%s (%s) for %s: nedctl %s", name, strings.Join(keys, " "), firstNonBlank(s.client, "an agent"), strings.Join(args, " "))}
	tr, err := beginAuditEvent(ctx, s.cfg, ev, s.log)
	if err != nil {
		return toolResult(err.Error()+" — refusing: every agent call must be recorded", true)
	}
	cctx, cancel := context.WithTimeout(ctx, mcpToolTimeout)
	defer cancel()
	out, errb, code := mcpRun(cctx, s.cfgPath, args)
	text := strings.TrimSpace(string(safetext.Bytes(out)))
	note := strings.TrimSpace(safetext.Text(string(errb)))
	if len(text) > mcpMaxOutput {
		text = text[:mcpMaxOutput] + "\n… (truncated: narrow the request with cluster, match or namespace)"
	}
	// Checks exit 1 when they find something: that is a result, not an
	// error. No JSON at all is an error.
	if text == "" || !json.Valid([]byte(text)) && !strings.HasSuffix(text, "narrow the request with cluster, match or namespace)") {
		tr.end(ctx, audit.OutcomeFailure, "", firstNonBlank(note, fmt.Sprintf("exit %d", code)), s.log)
		return toolResult(firstNonBlank(note, text, fmt.Sprintf("nedctl exited %d", code)), true)
	}
	tr.end(ctx, audit.OutcomeSuccess, "", ev.Detail, s.log)
	if note != "" && len(note) < 4096 {
		text += "\n\nnedctl notes:\n" + note
	}
	return toolResult(text, false)
}
