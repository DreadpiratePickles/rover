package ipc

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// xucredVersion is XUCRED_VERSION from <sys/ucred.h>; x/sys does not export it.
const xucredVersion = 0

// PeerUID asks the kernel which user is on the other end of conn.
//
// macOS: getsockopt(SOL_LOCAL, LOCAL_PEERCRED) returns an xucred with the
// peer's effective uid at connect() time. (x/sys: GetsockoptXucred in
// syscall_darwin.go; SOL_LOCAL=0x0 and LOCAL_PEERCRED=0x1 in zerrors_darwin_*.go.)
func PeerUID(conn *net.UnixConn) (uint32, error) {
	var (
		cred *unix.Xucred
		cerr error
	)
	err := withFD(conn, func(fd int) {
		cred, cerr = unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	})
	if err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	if cred.Version != xucredVersion {
		return 0, errors.New("ipc: unexpected xucred version")
	}
	return cred.Uid, nil
}
