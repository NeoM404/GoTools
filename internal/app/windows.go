package app

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"nedctl/internal/config"
)

// Windows programs started from WSL: Windows Terminal for --tab, and the
// existing SSM tool for `shell --via legacy`. WSL often runs without the
// Windows PATH (appendWindowsPath=false), so both can be named by path in
// config, as a Linux path or as the C:\ path Windows shows.

var windowsPathRe = regexp.MustCompile(`^([A-Za-z]):[\\/](.*)$`)

// inWSL reports whether nedctl runs inside WSL.
func inWSL() bool { return lookupEnv("WSL_DISTRO_NAME") != "" || lookupEnv("WSL_INTEROP") != "" }

// wslPath turns C:\Program Files\x.exe into /mnt/c/Program Files/x.exe
// inside WSL; anything else is returned unchanged.
func wslPath(p string) string {
	p = strings.TrimSpace(p)
	m := windowsPathRe.FindStringSubmatch(p)
	if m == nil || !inWSL() {
		return p
	}
	return "/mnt/" + strings.ToLower(m[1]) + "/" + strings.ReplaceAll(m[2], `\`, "/")
}

// windowsAppsGlob is where the Store install of Windows Terminal puts
// wt.exe; a var so tests can point it elsewhere.
var windowsAppsGlob = "/mnt/c/Users/*/AppData/Local/Microsoft/WindowsApps/wt.exe"

// findWindowsTerminal locates wt.exe: the windowsTerminal setting, then
// PATH, then the per-user WindowsApps folder (prefer the folder named after
// the Linux user, when there is one).
func findWindowsTerminal(cfg config.Config) (string, error) {
	if cfg.WindowsTerminal != "" {
		p := wslPath(cfg.WindowsTerminal)
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("windowsTerminal %q: %w", cfg.WindowsTerminal, err)
		}
		return p, nil
	}
	if p, err := exec.LookPath("wt.exe"); err == nil {
		return p, nil
	}
	if inWSL() {
		found, _ := filepath.Glob(windowsAppsGlob)
		sort.SliceStable(found, func(i, j int) bool {
			return strings.Contains(found[i], "/Users/"+lookupEnv("USER")+"/") && !strings.Contains(found[j], "/Users/"+lookupEnv("USER")+"/")
		})
		if len(found) > 0 {
			return found[0], nil
		}
	}
	return "", fmt.Errorf(`wt.exe not found in PATH — set "windowsTerminal" in config to its path, e.g. C:\Users\<you>\AppData\Local\Microsoft\WindowsApps\wt.exe`)
}

// openWTTab runs nedctl with args in a new Windows Terminal tab, titled and
// coloured by environment. From WSL the tab re-enters the same distribution.
// The tab's nedctl records its own session.
func openWTTab(cfg config.Config, env, title, hint string, args []string, stderr io.Writer) int {
	if os.Getenv("WT_SESSION") == "" {
		fmt.Fprintf(stderr, "--tab needs Windows Terminal (WT_SESSION is not set) — %s\n", hint)
		return ExitUsage
	}
	wt, err := findWindowsTerminal(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "--tab: %v\n", err)
		return ExitFailure
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(stderr, "--tab: locating nedctl: %v\n", err)
		return ExitFailure
	}
	wtArgs := []string{"-w", "0", "nt", "--title", title}
	if c := cfg.ColorFor(env); c != "" {
		wtArgs = append(wtArgs, "--tabColor", c)
	}
	if distro := os.Getenv("WSL_DISTRO_NAME"); distro != "" {
		shell, script, err := tabScript(self, args)
		if err != nil {
			fmt.Fprintf(stderr, "--tab: %v\n", err)
			return ExitFailure
		}
		wtArgs = append(wtArgs, "wsl.exe", "-d", distro, "--", shell, "-i", script)
	} else {
		wtArgs = append(append(wtArgs, self), args...)
	}
	cmd := exec.Command(wt, wtArgs...) //nolint:gosec // configured or fixed binary, validated arguments
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(stderr, "--tab: %v\n", err)
		return ExitFailure
	}
	_ = cmd.Process.Release()
	return ExitOK
}

// tabScript writes a one-shot script that runs nedctl with args, for an
// interactive shell to run in the new tab. `wsl.exe -- cmd` alone starts cmd
// without the user's ~/.bashrc or ~/.zshrc, so the tab would lack what they
// set there — the corporate CA bundle (AWS_CA_BUNDLE), the proxy, PATH —
// and the AWS CLI fails TLS behind the bank's inspecting proxy. Running it
// as `<shell> -i script` loads them exactly as a new terminal does. The
// script deletes itself first.
func tabScript(self string, args []string) (shell, path string, err error) {
	shell = os.Getenv("SHELL")
	if b := filepath.Base(shell); !filepath.IsAbs(shell) || (b != "bash" && b != "zsh") {
		shell = "/bin/bash"
	}
	f, err := os.CreateTemp("", "nedctl-tab-*.sh")
	if err != nil {
		return "", "", fmt.Errorf("writing the tab's start script: %w", err)
	}
	defer f.Close()
	line := []string{"exec", shellQuote(self)}
	for _, a := range args {
		line = append(line, shellQuote(a))
	}
	if _, err := fmt.Fprintf(f, "rm -f -- \"$0\"\n%s\n", strings.Join(line, " ")); err != nil {
		os.Remove(f.Name())
		return "", "", fmt.Errorf("writing the tab's start script: %w", err)
	}
	return shell, f.Name(), nil
}

// shareWithWindows adds the variables in env to WSLENV, so a Windows
// program started from WSL receives them; WSL passes nothing else across.
func shareWithWindows(env []string) []string {
	shared := strings.Split(os.Getenv("WSLENV"), ":")
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		shared = append(shared, k)
	}
	var keep []string
	for _, s := range shared {
		if s != "" {
			keep = append(keep, s)
		}
	}
	return append(env, "WSLENV="+strings.Join(keep, ":"))
}
