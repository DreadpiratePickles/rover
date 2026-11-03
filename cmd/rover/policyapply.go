package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/DreadpiratePickles/rover/internal/daemon"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/paths"
)

// approveFirstPolicy asks for the policy `rover policy init` just wrote to
// be approved, with the OS dialog, in this process (case (a): the CLI is
// the process that shows it; roverd is not running). There is no trust on
// first use for policies any more (review M9): a state.db deleted by an
// agent followed by `init --force` must not yield an approved policy. With
// no yes, the files are written but nothing is recorded, and roverd runs in
// enforce with no policy until `rover policy apply` succeeds.
func approveFirstPolicy(dirs paths.Dirs) {
	if pingDaemon(dirs) == nil {
		fmt.Println("roverd is running: approve these files with `rover policy apply` (OS authentication)")
		return
	}
	hash, err := loadedHash(dirs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "note: could not hash the new policy files:", err)
		return
	}
	notRecorded := "nothing was recorded: roverd will run enforce with no policy until `rover policy apply` succeeds"
	fmt.Printf("asking for approval of policy %s: answer the system authentication dialog\n", short(hash))
	raw, err := adminCall(ipc.Frame{Op: ipc.OpPolicyApply, Hash: hash})
	var res daemon.ApplyResult
	if err == nil {
		err = json.Unmarshal(raw, &res)
	}
	switch {
	case err != nil:
		fmt.Printf("%s (%v)\n", notRecorded, err)
	case res.Decision != daemon.ApplyAllowed:
		fmt.Printf("%s (%s: %s)\n", notRecorded, res.Decision, res.Reason)
	default:
		fmt.Printf("approved policy %s (mode %s, %s)\n", short(res.Hash), res.Mode, res.Method)
	}
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
