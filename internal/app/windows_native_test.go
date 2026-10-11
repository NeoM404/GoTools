package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPowerShellInit(t *testing.T) {
	code, out, _ := run("prompt", "init", "powershell")
	if code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	for _, want := range []string{
		"$global:__nedctlBin = '",
		`if ($out -match '^\$env:AWS_PROFILE = ''([A-Za-z0-9._-]+)''$') { $env:AWS_PROFILE = $Matches[1] }`,
		"prompt --shell powershell --tab",
		"Register-ArgumentCompleter -Native -CommandName nedctl, nedctl.exe",
		"$words += '__empty__'",
		"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("lacks %q:\n%s", want, out)
		}
	}
	// The init never runs nedctl's output.
	if strings.Contains(out, "Invoke-Expression") {
		t.Fatal("prompt init powershell must not Invoke-Expression nedctl's output")
	}
	if got := powershellInit(`C:\Users\o'neil\nedctl.exe`); !strings.Contains(got, `'C:\Users\o''neil\nedctl.exe'`) {
		t.Fatalf("path quoting:\n%s", got)
	}
}

func TestCompletionEmptyWordFromPowerShell(t *testing.T) {
	if got := complete(t, "", "aws", "__empty__"); !has(got, "login", "whoami", "env") {
		t.Fatalf("got %v", got)
	}
}

func TestPowerShellKubePrompt(t *testing.T) {
	got := powershellKubePrompt("⎈ payments-eks-prod PROD", true, 239, 68, 68)
	for _, want := range []string{"$env:KUBECONFIG = $env:NEDCTL_KUBECONFIG", "$([char]27)[1;38;2;239;68;68m⎈ payments-eks-prod PROD$([char]27)[0m", "function global:prompt"} {
		if !strings.Contains(got, want) {
			t.Fatalf("lacks %q:\n%s", want, got)
		}
	}
}

func TestSetupOnWindows(t *testing.T) {
	home := setupHome(t)
	local := filepath.Join(home, "AppData", "Local")
	t.Setenv("LOCALAPPDATA", local)
	oldOS, oldBin, oldPS, oldPSW := goos, userBinDir, psRun, psRunWith
	t.Cleanup(func() { goos, userBinDir, psRun, psRunWith = oldOS, oldBin, oldPS, oldPSW })
	goos = "windows"
	userBinDir = defaultUserBinDir // the Windows default: %LOCALAPPDATA%\Programs\nedctl
	var scripts []string
	psRun = func(script string) (string, error) {
		scripts = append(scripts, script)
		if script == "Get-ExecutionPolicy" {
			return "Restricted", nil
		}
		return "", nil
	}
	profiles := map[string]string{
		"powershell.exe": filepath.Join(home, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
		"pwsh.exe":       filepath.Join(home, "OneDrive", "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1"),
	}
	psRunWith = func(exe, script string) (string, error) { return profiles[exe], nil }
	fakeCLI(t, "powershell.exe", "exit 0")
	fakeCLI(t, "pwsh.exe", "exit 0")

	_, _, errb := run("setup", "--yes", "--start-url", "https://d-1234567890.awsapps.com/start", "--sso-region", "eu-west-1")
	dest := filepath.Join(local, "Programs", "nedctl", "nedctl.exe")
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("not installed to %s: %v\n%s", dest, err, errb)
	}
	if len(scripts) == 0 || !strings.Contains(scripts[0], "SetEnvironmentVariable('Path'") || !strings.Contains(scripts[0], filepath.Dir(dest)) {
		t.Fatalf("user PATH not updated: %v", scripts)
	}
	for _, p := range profiles {
		got, err := os.ReadFile(p)
		if err != nil || !strings.Contains(string(got), rcBegin) || !strings.Contains(string(got), "prompt init powershell") || !strings.Contains(string(got), dest) {
			t.Fatalf("profile %s: %v\n%s", p, err, got)
		}
	}
	if !strings.Contains(errb, "Set-ExecutionPolicy -Scope CurrentUser RemoteSigned") || !strings.Contains(errb, "open a new PowerShell window") {
		t.Fatalf("the Restricted policy must be pointed out:\n%s", errb)
	}
}
