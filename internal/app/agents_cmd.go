package app

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"nedctl/internal/ui"
)

// `nedctl agents setup <kiro|copilot|claude|devops-agent>` wires an AI
// agent to `nedctl mcp`: the MCP server entry, the eks-upgrade-readiness
// skill, and the agent's own definition where it has one. It writes only
// new files; one that exists is left as it is, with what to add shown.

//go:embed agentfiles
var agentFiles embed.FS

type agentFile struct {
	path    string // relative to the base directory
	content []byte
	mcp     bool // an MCP config: if it exists, show the entry to add
}

func embedded(name string) []byte {
	b, _ := agentFiles.ReadFile("agentfiles/" + name)
	return b
}

func mcpEntry(key, bin string, extra map[string]any) []byte {
	server := map[string]any{"command": bin, "args": []string{"mcp"}}
	for k, v := range extra {
		server[k] = v
	}
	b, _ := json.MarshalIndent(map[string]any{key: map[string]any{"nedctl": server}}, "", "  ")
	return append(b, '\n')
}

// agentPlan is what setup writes for a target, and where.
func agentPlan(target, dir, home, self string) (string, []agentFile, error) {
	skill := embedded("skill/SKILL.md")
	switch target {
	case "kiro":
		base := filepath.Join(home, ".kiro")
		return base, []agentFile{
			{path: "settings/mcp.json", mcp: true, content: mcpEntry("mcpServers", self, map[string]any{"disabled": false, "autoApprove": []string{"whoami", "upgrade_check", "expiry", "changes", "health"}})},
			{path: "steering/nedctl.md", content: embedded("kiro/steering.md")},
			{path: "skills/eks-upgrade-readiness/SKILL.md", content: skill},
			{path: "agents/eks-upgrade.json", content: []byte(strings.ReplaceAll(string(embedded("kiro/agent.json")), "@NEDCTL@", strings.ReplaceAll(self, `\`, `\\`)))},
		}, nil
	case "copilot":
		return dir, []agentFile{
			{path: ".vscode/mcp.json", mcp: true, content: mcpEntry("servers", "nedctl", map[string]any{"type": "stdio"})},
			{path: ".github/agents/eks-upgrade.agent.md", content: embedded("copilot/eks-upgrade.agent.md")},
			{path: ".github/skills/eks-upgrade-readiness/SKILL.md", content: skill},
		}, nil
	case "claude":
		return dir, []agentFile{
			{path: ".mcp.json", mcp: true, content: mcpEntry("mcpServers", "nedctl", nil)},
			{path: ".claude/skills/eks-upgrade-readiness/SKILL.md", content: skill},
		}, nil
	case "devops-agent":
		return filepath.Join(dir, "nedctl-devops-agent"), []agentFile{
			{path: "SKILL.md", content: skill},
			{path: "README.md", content: embedded("devops-agent/README.md")},
		}, nil
	}
	return "", nil, fmt.Errorf("unknown agent %q", target)
}

func cmdAgents(cfgPath string, args []string, stdout, stderr io.Writer) int {
	usage := "usage: nedctl agents setup <kiro|copilot|claude|devops-agent> [--dir DIR] [--dry-run]\n       nedctl agents tools"
	if len(args) > 0 && args[0] == "tools" {
		return cmdMCP(context.Background(), cfgPath, []string{"tools"}, nil, stdout, stderr)
	}
	if len(args) < 2 || args[0] != "setup" {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	fs := flag.NewFlagSet("agents setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", ".", "copilot, claude: the repository to add it to; devops-agent: where to put the bundle")
	dry := fs.Bool("dry-run", false, "show what would be written")
	pos, err := parseInterspersed(fs, args[1:])
	if err != nil || len(pos) != 1 {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(stderr, "locating nedctl: %v\n", err)
		return ExitFailure
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(stderr, "locating your home: %v\n", err)
		return ExitFailure
	}
	base, files, err := agentPlan(pos[0], *dir, home, self)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	st := ui.Style{Color: colorOn(stdout)}
	failed := false
	for _, f := range files {
		p := filepath.Join(base, filepath.FromSlash(f.path))
		if _, err := os.Stat(p); err == nil {
			if f.mcp {
				if data, _ := os.ReadFile(p); strings.Contains(string(data), `"nedctl"`) {
					fmt.Fprintf(stdout, "%s %s (already has nedctl)\n", st.OK("✔"), p)
					continue
				}
				fmt.Fprintf(stdout, "%s %s exists — add this server to it:\n%s\n", st.Fg(ui.Amber, "!"), p, f.content)
				continue
			}
			fmt.Fprintf(stdout, "%s %s exists — left as it is\n", st.Dim("·"), p)
			continue
		}
		if *dry {
			fmt.Fprintf(stdout, "would write %s\n", p)
			continue
		}
		err := os.MkdirAll(filepath.Dir(p), 0o755)
		if err == nil {
			err = writeNewFile(p, f.content)
		}
		if err != nil {
			failed = true
			fmt.Fprintf(stdout, "%s %s: %v\n", st.Fail("✖"), p, err)
			continue
		}
		fmt.Fprintf(stdout, "%s %s\n", st.OK("✔"), p)
	}
	next := map[string]string{
		"kiro":         "restart Kiro; the nedctl tools appear in the MCP panel, and `kiro-cli chat --agent eks-upgrade` uses the agent",
		"copilot":      "in VS Code: open the repository, start the nedctl server from .vscode/mcp.json, and pick the eks-upgrade agent in Copilot Chat",
		"claude":       "in the repository: claude, then approve the nedctl server and ask about an EKS upgrade",
		"devops-agent": "upload SKILL.md to your DevOps Agent space and give it nedctl's JSON (see README.md)",
	}[pos[0]]
	fmt.Fprintf(stdout, "\n%s %s\n%s\n", st.Bold("Next:"), next, st.Dim("every tool is read-only and every call is recorded in your audit trail (agent-tool); agents.disabled turns it off"))
	if failed {
		return ExitFailure
	}
	return ExitOK
}
