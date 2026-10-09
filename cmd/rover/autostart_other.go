//go:build !unix

package main

import (
	"errors"
	"os/exec"

	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/paths"
)

// autostart is not supported off Unix (fail closed: the wrapper refuses to
// start the server).
func autostart(paths.Dirs) (*ipc.Client, error) {
	return nil, errors.New("auto-starting roverd is not supported on this OS")
}

func detach(*exec.Cmd) {}
