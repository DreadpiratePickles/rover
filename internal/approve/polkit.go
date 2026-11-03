package approve

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// LESSON (M9): polkit answers "may process P do action A?". A process is
// named by its pid, but pids are reused: if Rover asked about pid 4242 and
// that process exited, another process could be given 4242 and the answer
// (and any "keep" authorisation) would apply to it. pkcheck's
// --process pid,start-time,uid form names one process for its whole life:
// a new process with the same pid has a different start time, and polkit
// refuses the check if the start time no longer matches. Rover asks about
// itself (roverd), so the subject is the process showing the dialog.

// PolkitAction is the action id Rover asks polkit about.
const PolkitAction = "org.rover.approve"

// PolkitActionPath is where `rover install --polkit` puts the action file.
const PolkitActionPath = "/usr/share/polkit-1/actions/org.rover.approve.policy"

// PolkitPolicy is the action file. auth_self: the user proves it is them
// with their own password; never auth_self_keep, which would let one
// approval silently approve the next ones for a few minutes.
const PolkitPolicy = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>Rover</vendor>
  <action id="org.rover.approve">
    <description>Approve an AI agent's tool call or a Rover policy change</description>
    <message>Rover needs you to approve an action requested by an AI agent</message>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>auth_self</allow_active>
    </defaults>
  </action>
</policyconfig>
`

// pkcheck exit codes (pkcheck(1)).
const (
	pkcheckAuthorized   = 0
	pkcheckNoAgent      = 2 // needs interaction and nobody can provide it
	pkcheckDismissed    = 3
	methodPolkit        = "polkit"
	procStatStartField  = 22 // starttime, 1-based, in /proc/<pid>/stat
	procStatFieldsAfter = procStatStartField - 2
)

// pkcheckPaths are where pkcheck is looked for, in order. Never PATH:
// roverd inherits PATH from whatever started it, and a pkcheck planted
// first on PATH that exits 0 would approve everything (review M9).
var pkcheckPaths = []string{"/usr/bin/pkcheck", "/bin/pkcheck"}

// findPkcheck returns the first pkcheck in pkcheckPaths that exists.
func findPkcheck() (string, error) {
	for _, p := range pkcheckPaths {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p, nil
		}
	}
	return "", fmt.Errorf("polkit: pkcheck not found in %s (install polkit)", strings.Join(pkcheckPaths, ", "))
}

// Polkit authenticates through pkcheck. The reason text cannot be passed to
// pkcheck (the action file's message is shown), so roverd's notification
// and details page carry the specifics.
type Polkit struct {
	// Pkcheck is the binary's absolute path; tests point it at a fake
	// script. Empty means the first of pkcheckPaths that exists.
	Pkcheck string
	// PID and UID name the subject; zero means this process.
	PID, UID int
	// StartTime reads a process's start time; nil reads /proc.
	StartTime func(pid int) (uint64, error)
	Logf      func(string, ...any)
}

// Authenticate implements Authenticator: exit 0 allows, exit 2 is
// ErrNoAuthAgent (headless: deny), anything else denies.
func (p Polkit) Authenticate(ctx context.Context, _ string) (bool, string, error) {
	pid, uid := p.PID, p.UID
	if pid == 0 {
		pid = os.Getpid()
	}
	if uid == 0 && p.PID == 0 {
		uid = os.Getuid()
	}
	readStart := p.StartTime
	if readStart == nil {
		readStart = ProcStartTime
	}
	start, err := readStart(pid)
	if err != nil {
		return false, methodPolkit, fmt.Errorf("polkit: start time of pid %d: %w", pid, err)
	}
	bin := p.Pkcheck
	if bin == "" {
		if bin, err = findPkcheck(); err != nil {
			return false, methodPolkit, err
		}
	}
	if !filepath.IsAbs(bin) {
		return false, methodPolkit, fmt.Errorf("polkit: pkcheck path %q is not absolute", bin)
	}
	subject := fmt.Sprintf("%d,%d,%d", pid, start, uid)
	cmd := exec.CommandContext(ctx, bin, "--action-id", PolkitAction, "--process", subject, "--allow-user-interaction") //nolint:gosec // G204: fixed binary and arguments built from integers
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err == nil {
		return true, methodPolkit, nil
	}
	if ctx.Err() != nil {
		return false, methodPolkit, ctx.Err()
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return false, methodPolkit, fmt.Errorf("polkit: %w", err)
	}
	msg := strings.TrimSpace(stderr.String())
	switch exit.ExitCode() {
	case pkcheckNoAgent:
		return false, methodPolkit, fmt.Errorf("%w: %s", ErrNoAuthAgent, msg)
	case pkcheckDismissed:
		return false, methodPolkit, nil
	}
	return false, methodPolkit, fmt.Errorf("polkit: pkcheck exit %d: %s", exit.ExitCode(), msg)
}

// ProcStartTime reads field 22 (starttime) of /proc/<pid>/stat. The comm
// field (2) is in parentheses and may itself contain spaces and ")", so
// the fields are counted after the LAST ")".
func ProcStartTime(pid int) (uint64, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	return parseStartTime(b)
}

func parseStartTime(stat []byte) (uint64, error) {
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, errors.New("malformed /proc stat")
	}
	fields := strings.Fields(string(stat[i+1:]))
	// After ")" the fields start at 3 (state); starttime is field 22.
	if len(fields) < procStatFieldsAfter {
		return 0, errors.New("short /proc stat")
	}
	return strconv.ParseUint(fields[procStatFieldsAfter-1], 10, 64)
}
