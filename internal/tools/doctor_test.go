package tools

import (
	"strings"
	"testing"
)

func TestInstallHintFitsThePlatform(t *testing.T) {
	for _, tool := range Catalog() {
		if tool.Required || tool.Name == "session-manager-plugin" {
			if h := tool.InstallHint("linux"); strings.Contains(h, "brew") || h == "" {
				t.Errorf("%s: Linux/WSL hint must not be Homebrew: %q", tool.Name, h)
			}
			if h := tool.InstallHint("windows"); !strings.HasPrefix(h, "winget install ") {
				t.Errorf("%s: Windows hint should be winget: %q", tool.Name, h)
			}
			if h := tool.InstallHint("darwin"); !strings.HasPrefix(h, "brew install") {
				t.Errorf("%s: macOS hint should be Homebrew: %q", tool.Name, h)
			}
		}
	}
}
