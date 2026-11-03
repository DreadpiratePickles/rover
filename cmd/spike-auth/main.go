//go:build darwin && cgo

// Command spike-auth is the M9 spike (plan §6 M9, §8): does
// LocalAuthentication's LAPolicyDeviceOwnerAuthentication dialog appear for
// a plain, unbundled CLI binary, (a) run from a terminal and (b) run as a
// child of a setsid'd daemon started by a wrapper, exactly as roverd is
// started (cmd/rover/wrap.go spawnDaemon)? It uses the production
// Authenticator (internal/approve.LocalAuth), so the answer is about the
// real code.
//
//	make spike-auth
//	bin/spike-auth direct    # (a)
//	bin/spike-auth daemon    # (b)
//
// It never shows the dialog without asking first: it prints "about to show
// the macOS authentication dialog" and waits for Enter.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
)

const reason = "Rover: allow spike-auth to run spike.test (args: none)?"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: spike-auth direct | daemon")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "direct":
		confirm()
		os.Exit(evaluate("direct"))
	case "daemon":
		confirm()
		os.Exit(viaDaemon())
	case "child": // internal: the setsid'd "daemon"
		os.Exit(evaluate("child of a setsid'd daemon"))
	default:
		fmt.Fprintln(os.Stderr, "usage: spike-auth direct | daemon")
		os.Exit(2)
	}
}

// confirm waits for the human: the dialog only appears when Bobby is there.
func confirm() {
	fmt.Println("about to show the macOS authentication dialog")
	fmt.Print("press Enter to continue (Ctrl-C to stop) ")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

// evaluate shows the dialog once and prints what came back.
func evaluate(how string) int {
	sid, _ := syscall.Getsid(0)
	fmt.Printf("mode=%s pid=%d ppid=%d sid=%d\n", how, os.Getpid(), os.Getppid(), sid)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	start := time.Now()
	ok, method, err := approve.LocalAuth{}.Authenticate(ctx, reason)
	fmt.Printf("ok=%v method=%s elapsed=%s\n", ok, method, time.Since(start).Round(time.Millisecond))
	var la *approve.LAError
	switch {
	case errors.As(err, &la):
		fmt.Printf("error code=%d message=%q\n", la.Code, la.Msg)
	case err != nil:
		fmt.Printf("error=%v\n", err)
	case !ok:
		fmt.Printf("cancelled by the user (LAErrorUserCancel, code %d)\n", approve.LAErrorUserCancel)
	}
	if ok {
		return 0
	}
	return 1
}

// viaDaemon starts this binary the way a wrapper starts roverd: its own
// session (setsid), no stdin, stdout and stderr into a log file; then waits
// and prints the log.
func viaDaemon() int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Println(err)
		return 1
	}
	dir, err := os.MkdirTemp("", "spike-auth-")
	if err != nil {
		fmt.Println(err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()
	logPath := filepath.Join(dir, "daemon.log")
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: our own temp dir
	if err != nil {
		fmt.Println(err)
		return 1
	}
	cmd := exec.Command(exe, "child") //nolint:gosec // G204: re-executing ourselves
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Println(err)
		return 1
	}
	fmt.Printf("started the setsid'd child (pid %d); answer or cancel the dialog if it appears\n", cmd.Process.Pid)
	werr := cmd.Wait()
	_ = logf.Close()
	b, _ := os.ReadFile(logPath) //nolint:gosec // G304: our own temp file
	fmt.Printf("--- child log ---\n%s--- child exit: %v ---\n", b, werr)
	if werr != nil {
		return 1
	}
	return 0
}
