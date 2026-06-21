//go:build !windows

package main

import (
	"os"
	"strings"
)

func prepareConsolePlatform() bool {
	info, err := os.Stdout.Stat()
	if err == nil && info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	term := strings.TrimSpace(strings.ToLower(os.Getenv("TERM")))
	return term != "" && term != "dumb"
}
