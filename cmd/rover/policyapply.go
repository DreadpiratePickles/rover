package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
	"github.com/DreadpiratePickles/rover/internal/daemon"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/paths"
	"github.com/DreadpiratePickles/rover/internal/state"
)

// approveFirstPolicy records the starter policy's hash with method "init"
// when no policy was ever approved: trust on first use (TOFU, see package
// approve). It only does so with no roverd running (it needs the state
// database); with roverd running, run `rover policy apply`. Every later
// change needs `rover policy apply` and the OS dialog.
func approveFirstPolicy(dirs paths.Dirs) {
	hash, err := loadedHash(dirs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "note: could not hash the new policy files:", err)
		return
	}
	if pingDaemon(dirs) == nil {
		fmt.Println("roverd is running: approve these files with `rover policy apply` (OS authentication)")
		return
	}
	db, err := state.Open(filepath.Join(dirs.State, "state.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "note: could not record the first policy:", err)
		return
	}
	defer func() { _ = db.Close() }()
	if _, found, cerr := approve.CurrentPolicy(db); cerr != nil || found {
		fmt.Println("an approved policy already exists: run `rover policy apply` to approve these files (OS authentication)")
		return
	}
	if err := approve.RecordPolicy(db, hash, approve.MethodInit, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "note: could not record the first policy:", err)
		return
	}
	fmt.Printf("recorded policy %s as approved (method init: the first policy is trusted on first use)\n", short(hash))
}

// policyApply asks for the policy on disk to be approved and loaded (M9).
// It is only a messenger: it checks the files load, then sends roverd a
// policy_apply admin frame with their hash, and roverd shows the OS dialog
// itself. With no roverd running, the same code runs in this process
// (adminCall), and this process shows the dialog. An enforce -> observe
// switch is just another policy_apply.
func policyApply(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: rover policy apply")
		return 2
	}
	dirs, err := paths.Resolve()
	if err == nil {
		err = paths.Ensure(dirs)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	_, cfg, _, hash, err := loadAll(dirs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "not applied:", err)
		return 1
	}
	fmt.Printf("asking for approval of policy %s (mode %s): answer the system authentication dialog\n", short(hash), cfg.Mode)
	raw, err := adminCall(ipc.Frame{Op: ipc.OpPolicyApply, Hash: hash})
	if err != nil {
		fmt.Fprintln(os.Stderr, "not applied:", err)
		return 1
	}
	var res daemon.ApplyResult
	if err := json.Unmarshal(raw, &res); err != nil {
		fmt.Fprintln(os.Stderr, "not applied:", err)
		return 1
	}
	if res.Decision != daemon.ApplyAllowed {
		fmt.Fprintf(os.Stderr, "not applied: %s: %s\n", res.Decision, res.Reason)
		return 1
	}
	fmt.Printf("applied policy %s (mode %s, %s)\n", short(res.Hash), res.Mode, res.Method)
	return 0
}

// pingDaemon connects to roverd's socket and leaves without a hello. It
// half-closes and waits for roverd to hang up, so roverd has read its peer
// credentials before the connection goes away (no log noise).
func pingDaemon(dirs paths.Dirs) error {
	sock, err := paths.SocketPath(dirs)
	if err != nil {
		return err
	}
	c, err := net.DialTimeout("unix", sock, 500*time.Millisecond)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil
	}
	if err := uc.CloseWrite(); err != nil {
		return err
	}
	_ = uc.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = io.Copy(io.Discard, uc)
	return nil
}
