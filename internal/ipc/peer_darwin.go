//go:build darwin

package ipc

import "golang.org/x/sys/unix"

// peerUID uses LOCAL_PEERCRED at level SOL_LOCAL (both 0x0 and 0x1 in
// <sys/un.h>, confirmed in x/sys/unix for M1), which fills an xucred with
// the effective uid and groups of the connecting process.
func peerUID(fd int) (uint32, error) {
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return cred.Uid, nil
}
