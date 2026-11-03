//go:build !darwin && !linux

package main

import "os"

// isTerminal: on other platforms, a character device counts as a terminal.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
