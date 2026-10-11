//go:build windows

package app

import (
	"os"
	"syscall"
)

// The classic Windows console shows colour codes as text unless virtual
// terminal processing is switched on; Windows Terminal has it on already.
// It is enabled once at start; where it cannot be (a very old console),
// nedctl prints without colour.
var vtEnabled = map[uintptr]bool{}

func init() {
	setMode := syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleMode")
	for _, f := range []*os.File{os.Stdout, os.Stderr} {
		var mode uint32
		h := syscall.Handle(f.Fd())
		if syscall.GetConsoleMode(h, &mode) != nil {
			continue
		}
		const enableVirtualTerminalProcessing = 0x0004
		if mode&enableVirtualTerminalProcessing != 0 {
			vtEnabled[f.Fd()] = true
			continue
		}
		if r, _, _ := setMode.Call(uintptr(h), uintptr(mode|enableVirtualTerminalProcessing)); r != 0 {
			vtEnabled[f.Fd()] = true
		}
	}
}

func consoleColor(f *os.File) bool { return vtEnabled[f.Fd()] }
