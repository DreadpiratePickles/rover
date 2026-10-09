//go:build linux

package ipc

import (
	"bytes"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// peerCreds uses SO_PEERCRED, which returns the pid, uid and gid of the
// process that called connect(2).
func peerCreds(fd int) (Creds, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return Creds{}, err
	}
	return Creds{UID: cred.Uid, PID: int(cred.Pid)}, nil
}

// parentPID reads /proc/<pid>/stat. The fourth field is the parent pid; the
// second field (the command name) is in parentheses and may contain spaces
// or parentheses itself, so parse from the last ')' onwards.
func parentPID(pid int) (int, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	i := bytes.LastIndexByte(data, ')')
	if i < 0 {
		return 0, fmt.Errorf("malformed stat for pid %d", pid)
	}
	fields := bytes.Fields(data[i+1:])
	if len(fields) < 2 {
		return 0, fmt.Errorf("malformed stat for pid %d", pid)
	}
	return strconv.Atoi(string(fields[1]))
}
