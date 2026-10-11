//go:build windows

package app

import (
	"os"
	"syscall"
	"unsafe"
)

// termSize is the console window's columns and rows, or 0, 0 when f is not
// a console.
func termSize(f *os.File) (int, int) {
	var info struct {
		Size, CursorPosition                   struct{ X, Y int16 }
		Attributes                             uint16
		Left, Top, Right, Bottom               int16
		MaximumWindowSizeX, MaximumWindowSizeY int16
	}
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleScreenBufferInfo")
	if r, _, _ := proc.Call(f.Fd(), uintptr(unsafe.Pointer(&info))); r == 0 {
		return 0, 0
	}
	return int(info.Right-info.Left) + 1, int(info.Bottom-info.Top) + 1
}
