//go:build darwin

package ipc

import (
	"golang.org/x/sys/unix"
)

// peerCreds uses LOCAL_PEERCRED and LOCAL_PEERPID at level SOL_LOCAL
// (0x0, 0x1 and 0x2 in <sys/un.h>, confirmed in x/sys/unix for M1). The
// first fills an xucred with the effective uid of the connecting process;
// the second returns its pid.
func peerCreds(fd int) (Creds, error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return Creds{}, err
	}
	pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil {
		return Creds{}, err
	}
	return Creds{UID: cred.Uid, PID: pid}, nil
}

// parentPID asks the kernel through sysctl kern.proc.pid.
func parentPID(pid int) (int, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, err
	}
	return int(kp.Eproc.Ppid), nil
}
