package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
	"github.com/DreadpiratePickles/rover/internal/paths"
	"github.com/DreadpiratePickles/rover/internal/policy"
	"github.com/DreadpiratePickles/rover/internal/state"
)

// approveFirstPolicy records the starter policy's hash with method "init"
// when no policy was ever approved: trust on first use (TOFU, see package
// approve). With roverd running it goes as an init nonce, which roverd
// refuses once any policy is approved. Every later change needs `rover
// policy apply` and the OS dialog.
func approveFirstPolicy(dirs paths.Dirs) {
	hash, err := loadedHash(dirs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "note: could not hash the new policy files:", err)
		return
	}
	if _, derr := runningDaemon(dirs); derr == nil {
		if code := handOver(dirs, hash, approve.MethodInit, ""); code != 0 {
			fmt.Fprintln(os.Stderr, "note: run `rover policy apply` to approve these files")
		}
		return
	}
	db, err := state.Open(filepath.Join(dirs.State, "state.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "note: could not record the first policy:", err)
		return
	}
	defer func() { _ = db.Close() }()
	if _, found, err := approve.CurrentPolicy(db); err != nil || found {
		fmt.Println("an approved policy already exists: run `rover policy apply` to approve these files (OS authentication)")
		return
	}
	if err := approve.RecordPolicy(db, hash, approve.MethodInit, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "note: could not record the first policy:", err)
		return
	}
	fmt.Printf("recorded policy %s as approved (method init: the first policy is trusted on first use)\n", short(hash))
}

// policyApply approves the policy on disk and has roverd load it (M9). The
// OS dialog comes first: without it nothing is approved. With roverd
// running, the approval travels as a one-time nonce in run/ plus SIGHUP
// (roverd holds the state database); without roverd, it is recorded in
// the database directly and loaded when roverd starts.
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
	// Validate before asking the human: never approve a policy that does
	// not load.
	_, cfg, _, hash, err := loadAll(dirs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "not applied:", err)
		return 1
	}
	method, err := authenticateCLI(fmt.Sprintf("Rover: apply policy %s (mode %s)?", short(hash), cfg.Mode))
	if err != nil {
		fmt.Fprintln(os.Stderr, "not applied:", err)
		return 1
	}
	return handOver(dirs, hash, method, cfg.Mode)
}

// handOver gives an approved hash to roverd (nonce + SIGHUP) or, with no
// roverd running, records it in the state database.
func handOver(dirs paths.Dirs, hash, method string, mode policy.Mode) int {
	pid, err := runningDaemon(dirs)
	if err != nil {
		if rerr := recordApproval(dirs, hash, method); rerr != nil {
			fmt.Fprintln(os.Stderr, "not applied:", rerr)
			return 1
		}
		fmt.Printf("approved policy %s (mode %s, %s); roverd is not running and loads it when it starts\n", short(hash), mode, method)
		return 0
	}
	n := approve.Nonce{Nonce: approve.NewToken(), Hash: hash, Method: method, Created: time.Now().UTC()}
	if werr := approve.WriteNonce(dirs.Run, n); werr != nil {
		fmt.Fprintln(os.Stderr, "not applied: writing the apply nonce:", werr)
		return 1
	}
	proc, err := os.FindProcess(pid)
	if err == nil {
		err = proc.Signal(syscall.SIGHUP)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot signal roverd (pid %d): %v\n", pid, err)
		return 1
	}
	fmt.Printf("approved policy %s (mode %s, %s); reload requested (pid %d), roverd.log says whether it loaded\n", short(hash), mode, method, pid)
	return 0
}

// runningDaemon returns roverd's pid if its pid file names it and its
// socket answers. A stale pid file could name an unrelated process, which
// SIGHUP would kill.
func runningDaemon(dirs paths.Dirs) (int, error) {
	b, err := os.ReadFile(filepath.Join(dirs.Run, "roverd.pid"))
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("bad pid file %q", b)
	}
	if err := pingDaemon(dirs); err != nil {
		return 0, fmt.Errorf("roverd is not answering on its socket: %w", err)
	}
	return pid, nil
}

// recordApproval writes the approved hash into the state database, which
// only works while no roverd holds it.
func recordApproval(dirs paths.Dirs, hash, method string) error {
	db, err := state.Open(filepath.Join(dirs.State, "state.db"))
	if errors.Is(err, state.ErrLocked) {
		return errors.New("roverd holds the state database but did not answer on its socket; is it stuck?")
	}
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	return approve.RecordPolicy(db, hash, method, time.Now())
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
