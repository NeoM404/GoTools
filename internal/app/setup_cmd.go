package app

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/execx"
	"nedctl/internal/picker"
)

// cmdSetup takes a new engineer from a downloaded binary to a working tool
// in one command: sign-in settings, nedctl on PATH, the shell integration
// (prompt, tab colour, `aws login` switching the shell), then a health
// check. Every step is idempotent and asks first; nothing is overwritten.
func cmdSetup(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	yes := fs.Bool("yes", false, "accept every step without asking")
	startURL := fs.String("start-url", "", "IAM Identity Center start URL (when not built in)")
	ssoRegion := fs.String("sso-region", "", "IAM Identity Center region (when not built in)")
	noInstall := fs.Bool("no-install", false, "do not copy nedctl to ~/.local/bin")
	noShell := fs.Bool("no-shell", false, "do not add the shell integration to ~/.bashrc / ~/.zshrc")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if !*yes && !stdinIsTerminal() {
		fmt.Fprintln(stderr, "setup asks before each step; without a terminal pass --yes")
		return ExitUsage
	}
	in := bufio.NewReader(stdin)
	ask := func(q string) bool {
		if *yes {
			return true
		}
		fmt.Fprintf(stderr, "%s [Y/n] ", q)
		line, _ := in.ReadString('\n')
		a := strings.ToLower(strings.TrimSpace(line))
		return a == "" || a == "y" || a == "yes"
	}
	prompt := func(q string) string {
		fmt.Fprintf(stderr, "%s: ", q)
		line, _ := in.ReadString('\n')
		return strings.TrimSpace(line)
	}
	done := func(step, detail string) { fmt.Fprintf(stderr, "%s %-8s %s\n", tick(stderr, true), step, detail) }
	skip := func(step, detail string) { fmt.Fprintf(stderr, "%s %-8s %s\n", tick(stderr, false), step, detail) }

	fmt.Fprintln(stderr, "Setting up nedctl "+Version)
	fmt.Fprintln(stderr)

	// 1. Sign-in settings.
	cfg, path, err := config.Load(cfgPath)
	switch {
	case err != nil:
		fmt.Fprintf(stderr, "config error: %v\n→ fix the file, then run setup again\n", err)
		return ExitFailure
	case cfg.AWS.Configured() && path != "":
		done("config", path)
	case cfg.AWS.Configured():
		done("config", "built-in settings for your organisation ("+cfg.AWS.StartURL+", "+cfg.AWS.SSORegion+") — no file needed")
	default:
		url, region := *startURL, *ssoRegion
		if url == "" && !*yes {
			fmt.Fprintln(stderr, "  Your AWS access portal URL and region are on the portal's \"Access keys\" page.")
			url = prompt("  IAM Identity Center start URL")
		}
		if url != "" && region == "" && !*yes {
			region = prompt("  IAM Identity Center region (e.g. eu-west-1)")
		}
		if url == "" || region == "" {
			skip("config", "no sign-in settings yet — run setup again with --start-url and --sso-region")
			break
		}
		written, err := writeSetupConfig(cfgPath, path, url, region)
		if err != nil {
			fmt.Fprintf(stderr, "writing config: %v\n", err)
			return ExitFailure
		}
		done("config", written)
	}

	// 2. nedctl on PATH.
	installed, _ := os.Executable()
	if !*noInstall {
		dest, onPath, err := installSelf(ask)
		if dest != "" {
			installed = dest
		}
		switch {
		case err != nil:
			fmt.Fprintf(stderr, "installing: %v\n", err)
			return ExitFailure
		case dest == "":
			skip("install", "left where it is")
		case onPath:
			done("install", dest)
		default:
			done("install", dest+" (its folder joins PATH through the shell step)")
		}
		if goos == "windows" && dest != "" && !pathHas(filepath.Dir(dest)) {
			fmt.Fprintln(stderr, "         added to your PATH for new terminals")
		}
	}

	// 3. Shell integration.
	if !*noShell {
		switch rc, note, err := addShellIntegration(ask, installed); {
		case err != nil:
			fmt.Fprintf(stderr, "shell integration: %v\n", err)
			return ExitFailure
		case rc == "":
			skip("shell", note)
		default:
			done("shell", rc+": prompt shows account + env, tab coloured, tab completion, `nedctl aws login` switches the shell")
			if note != "" {
				fmt.Fprintln(stderr, "         "+note)
			}
		}
	}

	// 4. Health check.
	fmt.Fprintln(stderr)
	code := cmdDoctor(ctx, cfgPath, nil, stdout, stderr)
	fmt.Fprintln(stderr)
	if goos == "windows" {
		fmt.Fprintln(stderr, "Next: open a new PowerShell window, then")
	} else {
		fmt.Fprintln(stderr, "Next: open a new terminal (or run  exec $SHELL), then")
	}
	fmt.Fprintln(stderr, "  nedctl aws login          pick an account and role")
	fmt.Fprintln(stderr, "  nedctl shell              a shell on an instance")
	fmt.Fprintln(stderr, "  nedctl kube               kubectl on a cluster")
	return code
}

func tick(w io.Writer, ok bool) string {
	mark, col := "✔", "#22c55e"
	if !ok {
		mark, col = "–", "#9ca3af"
	}
	if colorOn(w) {
		return picker.Paint(col, mark)
	}
	return mark
}

// writeSetupConfig writes a starter config with the sign-in settings, at
// the path config.Load would read (or --config).
func writeSetupConfig(explicit, found, url, region string) (string, error) {
	path := firstNonBlank(explicit, found)
	if path == "" {
		base := os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, ".config")
		}
		path = filepath.Join(base, "nedctl", "config.json")
	}
	var starter map[string]any
	if err := json.Unmarshal([]byte(fmt.Sprintf(starterConfig, config.ModeWorkstation)), &starter); err != nil {
		return "", err
	}
	starter["aws"] = map[string]string{"startUrl": url, "ssoRegion": region}
	data, err := json.MarshalIndent(starter, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := writeFileAtomic(path, append(data, '\n'), 0o644); err != nil {
		return "", err
	}
	if _, _, err := config.Load(path); err != nil {
		return "", err
	}
	return path, nil
}

// goos is runtime.GOOS; a var so tests can take the Windows paths.
var goos = runtime.GOOS

// userBinDir is where setup installs nedctl: ~/.local/bin, or on Windows
// %LOCALAPPDATA%\Programs\nedctl. A var so tests can move it.
var userBinDir = defaultUserBinDir

func defaultUserBinDir() (string, error) {
	if goos == "windows" {
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			return filepath.Join(base, "Programs", "nedctl"), nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "bin"), nil
}

// psRun runs a PowerShell command (Windows setup only); a var for tests.
var psRun = func(script string) (string, error) {
	out, err := execx.Output(context.Background(), 20*time.Second, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	return strings.TrimSpace(string(out)), err
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// installSelf copies this binary into userBinDir, unless the nedctl on PATH
// already is this binary. On Windows it also puts that folder on the user's
// PATH for new terminals. Re-running setup from a newer download is also how
// nedctl is updated.
func installSelf(ask func(string) bool) (dest string, onPath bool, err error) {
	self, err := os.Executable()
	if err != nil {
		return "", false, err
	}
	self, _ = filepath.EvalSymlinks(self)
	dir, err := userBinDir()
	if err != nil {
		return "", false, err
	}
	name := "nedctl"
	if goos == "windows" {
		name = "nedctl.exe"
	}
	dest = filepath.Join(dir, name)
	onPath = pathHas(dir)
	if p, err := exec.LookPath("nedctl"); err == nil {
		if real, _ := filepath.EvalSymlinks(p); real == self {
			return real, true, nil
		}
	}
	if self != dest {
		if !ask(fmt.Sprintf("Install nedctl to %s so it runs from anywhere?", dest)) {
			return "", false, nil
		}
		data, err := os.ReadFile(self)
		if err != nil {
			return "", false, err
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", false, err
		}
		if err := writeFileAtomic(dest, data, 0o755); err != nil {
			if goos == "windows" {
				err = fmt.Errorf("%w (close any nedctl running from %s and try again)", err, dir)
			}
			return "", false, err
		}
	}
	if goos == "windows" && !onPath {
		// The user's PATH lives in the registry; new terminals pick it up.
		if _, err := psRun(psAddUserPath(dir)); err != nil {
			return dest, false, fmt.Errorf("adding %s to your PATH: %w", dir, err)
		}
		onPath = true
	}
	return dest, onPath, nil
}

func psAddUserPath(dir string) string {
	return "$d = " + psQuote(dir) + "; $p = [Environment]::GetEnvironmentVariable('Path', 'User'); " +
		"if (-not (($p -split ';') -contains $d)) { [Environment]::SetEnvironmentVariable('Path', (@($p.TrimEnd(';'), $d) | Where-Object { $_ }) -join ';', 'User') }"
}

func pathHas(dir string) bool {
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if filepath.Clean(p) == filepath.Clean(dir) {
			return true
		}
	}
	return false
}

const (
	rcBegin = "# >>> nedctl >>>"
	rcEnd   = "# <<< nedctl <<<"
)

const rcComment = "# Added by `nedctl setup`: prompt with account and environment, coloured tab,\n# tab completion, and `nedctl aws login` switching this shell. Re-run setup to refresh.\n"

// addShellIntegration adds (or refreshes) a marked block in the shell's
// startup file — ~/.bashrc, ~/.zshrc, or on Windows the PowerShell
// profiles — that runs `nedctl prompt init`. Lines outside the block are
// never changed. bin is the installed nedctl, for PowerShell.
func addShellIntegration(ask func(string) bool, bin string) (rc, note string, err error) {
	if goos == "windows" {
		return addPowerShellIntegration(ask, bin)
	}
	shell := filepath.Base(os.Getenv("SHELL"))
	if shell != "bash" && shell != "zsh" {
		return "", "your shell is " + firstNonBlank(shell, "unknown") + ": add  eval \"$(nedctl prompt init bash)\"  (or zsh) to its startup file yourself", nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	rc = filepath.Join(home, "."+shell+"rc")
	block := rcBegin + "\n" + rcComment
	if dir, err := userBinDir(); err == nil {
		if rel, err := filepath.Rel(home, dir); err == nil && !strings.HasPrefix(rel, "..") {
			dir = "$HOME/" + filepath.ToSlash(rel)
		}
		block += `case ":$PATH:" in *":` + dir + `:"*) ;; *) export PATH="` + dir + `:$PATH" ;; esac` + "\n"
	}
	block += `command -v nedctl >/dev/null 2>&1 && eval "$(nedctl prompt init ` + shell + `)"` + "\n" + rcEnd + "\n"
	old, _ := os.ReadFile(rc)
	written, err := upsertBlock(rc, block, ask)
	if err != nil || !written {
		if err == nil {
			note = "left " + rc + " unchanged"
			rc = ""
		}
		return rc, note, err
	}
	return rc, earlierInitLine(rc, string(old), "command -v nedctl"), nil
}

// addPowerShellIntegration writes the block into the profile of each
// PowerShell installed (Windows PowerShell 5.1 and PowerShell 7 keep
// separate ones; OneDrive may move Documents, so PowerShell is asked where
// they are), and says when the execution policy would stop profiles loading.
func addPowerShellIntegration(ask func(string) bool, bin string) (rc, note string, err error) {
	var profiles []string
	for _, exe := range []string{"powershell.exe", "pwsh.exe"} {
		if _, err := exec.LookPath(exe); err != nil {
			continue
		}
		if p, err := psRunWith(exe, "$PROFILE.CurrentUserCurrentHost"); err == nil && p != "" {
			profiles = append(profiles, p)
		}
	}
	if len(profiles) == 0 {
		return "", "PowerShell not found: add  nedctl prompt init powershell | Out-String | Invoke-Expression  to your profile", nil
	}
	block := rcBegin + "\n" + rcComment + psProfileLine(bin) + "\n" + rcEnd + "\n"
	var done []string
	for _, p := range profiles {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return "", "", err
		}
		written, err := upsertBlock(p, block, ask)
		if err != nil {
			return "", "", err
		}
		if written {
			done = append(done, p)
		}
	}
	if len(done) == 0 {
		return "", "left your PowerShell profile unchanged", nil
	}
	if pol, err := psRun("Get-ExecutionPolicy"); err == nil {
		switch strings.ToLower(pol) {
		case "restricted", "allsigned", "undefined":
			note = "PowerShell's execution policy is " + pol + ", so profiles do not load: run  Set-ExecutionPolicy -Scope CurrentUser RemoteSigned  (or ask IT if it is enforced)"
		}
	}
	return strings.Join(done, ", "), note, nil
}

// psRunWith runs a command in a specific PowerShell.
var psRunWith = func(exe, script string) (string, error) {
	out, err := execx.Output(context.Background(), 20*time.Second, exe, "-NoProfile", "-NonInteractive", "-Command", script)
	return strings.TrimSpace(string(out)), err
}

func psProfileLine(bin string) string {
	return "$__nedctl = " + psQuote(bin) + "; if (Test-Path $__nedctl) { & $__nedctl prompt init powershell | Out-String | Invoke-Expression }"
}

// upsertBlock replaces the marked block in path, or appends it after
// asking; it reports whether the file now holds the block.
func upsertBlock(path, block string, ask func(string) bool) (bool, error) {
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	text := string(old)
	if i, j := strings.Index(text, rcBegin), strings.Index(text, rcEnd); i >= 0 && j > i {
		if text[i:min(len(text), j+len(rcEnd)+1)] == block {
			return true, nil // already current
		}
		text = text[:i] + block + strings.TrimPrefix(text[j+len(rcEnd):], "\n")
	} else {
		if !ask(fmt.Sprintf("Add the nedctl shell integration to %s?", path)) {
			return false, nil
		}
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		text += "\n" + block
	}
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	return true, writeFileAtomic(path, []byte(text), mode)
}

// earlierInitLine points out a hand-added `prompt init` line outside the
// block, which would run as well.
func earlierInitLine(path, old, ours string) string {
	for n, line := range strings.Split(old, "\n") {
		if strings.Contains(line, "prompt init") && !strings.HasPrefix(strings.TrimSpace(line), ours) {
			return fmt.Sprintf("line %d of %s already runs `prompt init` — remove it; the nedctl block replaces it", n+1, path)
		}
	}
	return ""
}
