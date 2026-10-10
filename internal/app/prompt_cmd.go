package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

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
	if len(args) > 0 && args[0] == "init" {
		return promptInit(args[1:], stdout, stderr)
	}
	fs := flag.NewFlagSet("prompt", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	shell := fs.String("shell", "plain", "escape colour codes for: bash, zsh, powershell or plain (no colour)")
	noKube := fs.Bool("no-kube", false, "skip the kube-context segment")
	noAWS := fs.Bool("no-aws", false, "skip the AWS profile segment")
	tab := fs.Bool("tab", false, "also colour the Windows Terminal tab by environment (the AWS profile's, else the kube-context's)")
	if err := fs.Parse(args); err != nil {
		return ExitOK
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		return ExitOK
	}
	var parts []string
	tabEnv := ""
	if !*noKube {
		if k, err := kube.ViewCurrent(ctx); err == nil {
			cl := kube.ClassifyCurrent(k, guardFleet(cfg, io.Discard), cfg.ProdEnvs(), cfg.ProdPatterns)
			env := cl.Environment
			if env == "" && cl.Production {
				env = "prod"
			}
			parts = append(parts, segment(cfg, *shell, "k8s:"+k.CurrentContext, env, cl.Production))
			tabEnv = env
		}
	}
	if !*noAWS {
		if name := resolveProfile(cfg, ""); name != "" {
			label, env, suffix := "aws:"+name, "", ""
			if path, err := awssso.ConfigPath(); err == nil {
				if m, err := awssso.LoadManaged(path); err == nil {
					if p, ok := m.Profiles[name]; ok {
						label, env = "aws:"+firstNonBlank(p.Squad, p.AccountID), p.Environment
						if cfg.AWS.Elevated(p.Role) {
							label += "▲"
						}
						if left, ok := signInLeft(m.Session.Name); ok {
							switch {
							case left <= 0:
								suffix = " (expired)"
							case left < time.Hour:
								suffix = fmt.Sprintf(" (%dm)", int(left.Minutes()))
							}
						}
					}
				}
			}
			parts = append(parts, segment(cfg, *shell, label, env, cfg.IsProdEnvironment(env))+suffix)
			if env != "" {
				tabEnv = env
			}
		}
	}
	out := strings.Join(parts, " ")
	if *tab && *shell != "plain" {
		if seq := tabColorSeq(cfg.ColorFor(tabEnv)); seq != "" {
			out += nonPrinting(*shell, seq)
		}
	}
	fmt.Fprint(stdout, out)
	return ExitOK
}

// nonPrinting marks s as taking no columns, so the shell measures the
// prompt correctly.
func nonPrinting(shell, s string) string {
	switch shell {
	case "bash":
		return `\[` + s + `\]`
	case "zsh":
		return "%{" + s + "%}"
	}
	return s
}

// promptInit prints shell code that puts the nedctl segment in front of
// the user's own prompt and keeps the tab coloured, for
// `eval "$(nedctl prompt init bash)"` in ~/.bashrc. It refers to this
// nedctl by full path, so it works when nedctl is not on PATH. Inside
// `nedctl kube`, the cluster prefix that shell sets is kept in front.
func promptInit(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || (args[0] != "bash" && args[0] != "zsh") {
		fmt.Fprintln(stderr, "usage: nedctl prompt init <bash|zsh>   (add  eval \"$(nedctl prompt init bash)\"  to ~/.bashrc)")
		return ExitUsage
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(stderr, "locating nedctl: %v\n", err)
		return ExitFailure
	}
	bin := shellQuote(self)
	switch args[0] {
	case "bash":
		fmt.Fprintf(stdout, `__nedctl_base_ps1="${__nedctl_base_ps1-$PS1}"
__nedctl_prompt() {
  local s
  s="$(%s prompt --shell bash --tab 2>/dev/null)"
  PS1="${__nedctl_kube_prefix:+$__nedctl_kube_prefix }${s:+$s }${__nedctl_base_ps1}"
}
case ";${PROMPT_COMMAND-};" in
  *";__nedctl_prompt;"*) ;;
  *) PROMPT_COMMAND="__nedctl_prompt${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
esac
`, bin)
	case "zsh":
		fmt.Fprintf(stdout, `__nedctl_base_prompt="${__nedctl_base_prompt-$PROMPT}"
__nedctl_prompt() {
  local s
  s="$(%s prompt --shell zsh --tab 2>/dev/null)"
  PROMPT="${__nedctl_kube_prefix:+$__nedctl_kube_prefix }${s:+$s }${__nedctl_base_prompt}"
}
autoload -Uz add-zsh-hook
add-zsh-hook precmd __nedctl_prompt
`, bin)
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
