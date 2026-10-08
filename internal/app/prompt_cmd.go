package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"nedctl/internal/awssso"
	"nedctl/internal/config"
	"nedctl/internal/kube"
	"nedctl/internal/picker"
)

// cmdPrompt prints a short, coloured segment for a shell prompt: the current
// kube-context and AWS profile, each with its environment in that
// environment's colour, production in bold capitals. It reads only local
// state (kubeconfig, AWS config, the cached inventory) and always exits 0 —
// a prompt must never fail or stall.
func cmdPrompt(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("prompt", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	shell := fs.String("shell", "plain", "escape colour codes for: bash, zsh, powershell or plain (no colour)")
	noKube := fs.Bool("no-kube", false, "skip the kube-context segment")
	noAWS := fs.Bool("no-aws", false, "skip the AWS profile segment")
	if err := fs.Parse(args); err != nil {
		return ExitOK
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		return ExitOK
	}
	var parts []string
	if !*noKube {
		if k, err := kube.ViewCurrent(ctx); err == nil {
			cl := kube.ClassifyCurrent(k, guardFleet(cfg, io.Discard), cfg.ProdEnvs(), cfg.ProdPatterns)
			env := cl.Environment
			if env == "" && cl.Production {
				env = "prod"
			}
			parts = append(parts, segment(cfg, *shell, "k8s:"+k.CurrentContext, env, cl.Production))
		}
	}
	if !*noAWS {
		if name := resolveProfile(cfg, ""); name != "" {
			label, env := "aws:"+name, ""
			if path, err := awssso.ConfigPath(); err == nil {
				if m, err := awssso.LoadManaged(path); err == nil {
					if p, ok := m.Profiles[name]; ok {
						label, env = "aws:"+firstNonBlank(p.Squad, p.AccountID), p.Environment
					}
				}
			}
			parts = append(parts, segment(cfg, *shell, label, env, cfg.IsProdEnvironment(env)))
		}
	}
	if len(parts) > 0 {
		fmt.Fprint(stdout, strings.Join(parts, " "))
	}
	return ExitOK
}

func segment(cfg config.Config, shell, label, env string, prod bool) string {
	text := label
	if env != "" {
		e := strings.ToLower(env)
		if prod {
			e = strings.ToUpper(env)
		}
		text += "[" + e + "]"
	}
	r, g, b, ok := picker.RGB(cfg.ColorFor(env))
	if shell == "plain" || !ok {
		return text
	}
	weight := "22"
	if prod {
		weight = "1"
	}
	start, end := fmt.Sprintf("\x1b[%s;38;2;%d;%d;%dm", weight, r, g, b), "\x1b[0m"
	switch shell {
	case "bash":
		// \[ \] mark non-printing bytes so readline measures the line right.
		start, end = `\[`+start+`\]`, `\[`+end+`\]`
	case "zsh":
		start, end = "%{"+start+"%}", "%{"+end+"%}"
	}
	return start + text + end
}
