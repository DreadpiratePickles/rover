//go:build !(darwin && cgo)

// Command spike-auth is the macOS LocalAuthentication spike (M9); it only
// does something on macOS built with cgo.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "spike-auth: macOS only (darwin with cgo); on Linux approvals use polkit (`rover install --polkit`)")
	os.Exit(2)
}
