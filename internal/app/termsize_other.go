//go:build !windows

package app

import (
	"os"
	"syscall"
	"unsafe"
)

// termSize is the terminal's columns and rows, or 0, 0 when f is not one.
func termSize(f *os.File) (int, int) {
	var ws struct{ Row, Col, X, Y uint16 }
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws))); errno != 0 {
		return 0, 0
	}
	return int(ws.Col), int(ws.Row)
}
