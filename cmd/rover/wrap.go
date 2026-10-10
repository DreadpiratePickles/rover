package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/paths"
	"github.com/DreadpiratePickles/rover/internal/proxy"
)

// autostartWait is how long a wrapper waits for a daemon it just launched.
const autostartWait = 3 * time.Second

func wrap(args []string) int {
	fs := flag.NewFlagSet("wrap", flag.ExitOnError)
	name := fs.String("name", "", "server name for policy and the audit log, [A-Za-z0-9_.-] (default: the command's base name)")
	_ = fs.Parse(args)
	server := fs.Args()
	if len(server) == 0 {
		usage()
	}
	if *name == "" {
		*name = ipc.SanitizeServerName(filepath.Base(server[0]))
	} else if err := ipc.ValidServerName(*name); err != nil {
		// Before roverd or the server: a bad name must not start anything.
		errf("invalid --name: %v", err)
		return 2
	}

	dirs, err := paths.Resolve()
	if err == nil {
		err = paths.Ensure(dirs)
	}
	if err != nil {
		errf("%v", err)
		return 1
	}

	hello := ipc.Hello{
		WrapperPID:   os.Getpid(),
		ClientPID:    os.Getppid(), // the agent app that spawned us
		ServerName:   *name,
		ServerCmdSHA: commandDigest(server),
		Transport:    "stdio",
	}
	// Connect to roverd BEFORE starting the server. If there is no daemon and
	// none can be started, the server never runs: fail closed.
	client, err := connect(dirs, hello)
	if err != nil {
		errf("cannot reach roverd, refusing to start %q: %v", server[0], err)
		return 1
	}
	defer func() { _ = client.Close() }()

	// G204: running a caller-chosen command is the whole point of "wrap". The
	// command comes from the user's own MCP client config, and exec.Command
	// never goes through a shell, so there is no injection surface here.
	cmd := exec.Command(server[0], server[1:]...) //nolint:gosec // G204: wrapping the user-configured server is intended, see above
	cmd.Stderr = os.Stderr
	childIn, err := cmd.StdinPipe()
	if err != nil {
		errf("%v", err)
		return 1
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		errf("%v", err)
		return 1
	}
	if err := cmd.Start(); err != nil {
		errf("cannot start server %q: %v", server[0], err)
		return 1
	}
	// Only the command's base name: MCP configs often carry tokens in the
	// arguments, and stderr ends up in the client's log files.
	errf("session %s: wrapping %s as %q", client.SessionID(), filepath.Base(server[0]), *name)

	// Pass Ctrl-C / termination through to the child so it can shut down cleanly.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()

	w := proxy.New(client)
	w.Errf = errf
	toServer := &proxy.LockedWriter{W: childIn}
	toAgent := &proxy.LockedWriter{W: os.Stdout}

	inDone := make(chan error, 1)
	outDone := make(chan error, 1)
	go func() {
		err := w.Pump(os.Stdin, toServer, toAgent, proxy.ClientToServer)
		w.Wait()
		_ = childIn.Close() // agent hung up -> tell the server (EOF on its stdin)
		inDone <- err
	}()
	go func() { outDone <- w.Pump(childOut, toAgent, toServer, proxy.ServerToClient) }()

	var pumpErr error
	select {
	case pumpErr = <-outDone: // server closed its stdout (exited)
	case pumpErr = <-inDone:
		if pumpErr != nil {
			_ = cmd.Process.Kill()
		}
		if e := <-outDone; pumpErr == nil {
			pumpErr = e
		}
	}
	if pumpErr != nil {
		errf("session ended with error: %v", pumpErr)
		_ = cmd.Process.Kill()
	}

	waitErr := cmd.Wait()
	var exit *exec.ExitError
	if errors.As(waitErr, &exit) {
		return exit.ExitCode()
	}
	if pumpErr != nil {
		return 1
	}
	return 0
}

// commandDigest identifies the server command line in the hello. It lets
// roverd notice when the command behind a server name changes (M4 pins).
func commandDigest(argv []string) string {
	h := sha256.New()
	for _, a := range argv {
		h.Write([]byte(a))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// connect dials roverd, starting it if nothing answers (plan §4.4). An
// exclusive flock on run/autostart.lock means that when ten wrappers start at
// once, one launches the daemon and the rest wait for it.
func connect(dirs paths.Dirs, hello ipc.Hello) (*ipc.Client, error) {
	sock, err := paths.SocketPath(dirs)
	if err != nil {
		return nil, err
	}
	c, err := ipc.Dial(sock, hello)
	if err == nil {
		return c, nil
	}
	if os.Getenv("ROVER_TEST_NO_AUTOSTART") == "1" {
		return nil, fmt.Errorf("%w (auto-start disabled by ROVER_TEST_NO_AUTOSTART)", err)
	}

	lockPath := filepath.Join(dirs.Run, "autostart.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // G304: path is inside Rover's own 0700 run directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("autostart lock: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()

	// Another wrapper may have started roverd while we waited for the lock.
	if c, err := ipc.Dial(sock, hello); err == nil {
		return c, nil
	}
	if err := spawnDaemon(dirs); err != nil {
		return nil, fmt.Errorf("start roverd: %w", err)
	}
	deadline := time.Now().Add(autostartWait)
	var last error
	for time.Now().Before(deadline) {
		c, err := ipc.Dial(sock, hello)
		if err == nil {
			return c, nil
		}
		last = err
		time.Sleep(50 * time.Millisecond)
	}
	return nil, fmt.Errorf("roverd did not come up within %s: %w (see %s)", autostartWait, last, filepath.Join(dirs.State, "roverd.log"))
}

// spawnDaemon runs `rover daemon` detached: its own session (setsid), no
// stdin, stdout and stderr into the daemon log.
func spawnDaemon(dirs paths.Dirs) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logf, err := os.OpenFile(filepath.Join(dirs.State, "roverd.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = logf.Close() }()
	cmd := exec.Command(exe, "daemon") //nolint:gosec // G204: re-executing our own binary
	cmd.Stdin = nil
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
