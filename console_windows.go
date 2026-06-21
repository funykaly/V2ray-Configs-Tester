//go:build windows

package main

import "golang.org/x/sys/windows"

const (
	enableExtendedFlags        = 0x0080
	enableQuickEditMode        = 0x0040
	enableVirtualTerminalInput = 0x0200
)

func prepareConsolePlatform() bool {
	stdoutOK := enableVirtualTerminal(windows.STD_OUTPUT_HANDLE)
	_ = enableVirtualTerminal(windows.STD_ERROR_HANDLE)
	_ = configureInputConsole(windows.STD_INPUT_HANDLE)
	return stdoutOK
}

func enableVirtualTerminal(stdHandle uint32) bool {
	handle, err := windows.GetStdHandle(stdHandle)
	if err != nil {
		return false
	}
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	return windows.SetConsoleMode(handle, mode) == nil
}

func configureInputConsole(stdHandle uint32) bool {
	handle, err := windows.GetStdHandle(stdHandle)
	if err != nil {
		return false
	}
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	mode |= enableExtendedFlags | enableVirtualTerminalInput
	mode &^= enableQuickEditMode
	return windows.SetConsoleMode(handle, mode) == nil
}
