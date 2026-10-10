package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	"github.com/DreadpiratePickles/rover/internal/pin"
)

// Pinning (M4) in roverd: tools/list results are checked against the pins
// before the policy sees them, and tools/call of a tool whose pin does not
// match is refused before the policy is asked, in every mode (D6).
const (
	// ReasonPinMismatch blocks a tools/call of a changed or unpinned tool.
	ReasonPinMismatch = pin.ReasonPinMismatch
	// ReasonPinCheckFailed blocks a tools/call when the pins could not be read.
	ReasonPinCheckFailed = "pin_check_failed"
	// MethodToolsListChanged is the server's "my tools changed" notification.
	MethodToolsListChanged = "notifications/tools/list_changed"

	// AuditKindPin is the audit "kind" of pin events (not MCP messages).
	AuditKindPin = "pin"
	// Audit actions of pin events.
	AuditPinned      = "pinned"
	AuditRecheck     = "recheck"
	AuditPinApproved = "pin_approved"
	AuditPinReset    = "pin_reset"
	// adminSession is the audit session of CLI admin operations.
	adminSession = "admin"
)

// kindRecheck is an internal event kind: the server sent list_changed.
const kindRecheck = "recheck"

// pinCall refuses a tools/call the pins do not allow.
func (s *Server) pinCall(server string, m jsonrpc.Message) (judgment, bool) {
	ok, reason, err := s.pins.AllowCall(server, m.ToolName())
	switch {
	case err != nil:
		s.o.Logf("pin check for %s/%s failed, blocking: %v", pin.TerminalSafe(server), pin.TerminalSafe(m.ToolName()), err)
		return blockJ(m, ReasonPinCheckFailed, nil, nil), true
	case !ok:
		return blockJ(m, reason, nil, nil), true
	}
	return judgment{}, false
}

// pinRecheck handles notifications/tools/list_changed. Every tools/list
// result is checked anyway, so this only records that a change was announced.
func (s *Server) pinRecheck(server string) []pin.Event {
	s.pins.MarkRecheck(server)
	s.o.Logf("%s: tools/list_changed; the next tools/list will be checked against the pins", server)
	return []pin.Event{{Server: server, Kind: kindRecheck}}
}

// mismatched lists the tools that events removed from a list.
func mismatched(events []pin.Event) []string {
	var out []string
	for _, e := range events {
		if e.Kind != pin.KindPinned && e.Kind != kindRecheck {
			out = append(out, e.Tool)
		}
	}
	return out
}

// pinEntries turns pin events into audit entries that share msg's time,
// session, server and direction.
func pinEntries(msg audit.Entry, events []pin.Event) []audit.Entry {
	out := make([]audit.Entry, 0, len(events))
	for _, ev := range events {
		e := audit.Entry{Time: msg.Time, Session: msg.Session, Server: ev.Server, Dir: msg.Dir, Kind: AuditKindPin, Tool: ev.Tool}
		switch ev.Kind {
		case pin.KindPinned:
			e.Action, e.Reason, e.Digest = AuditPinned, pin.MethodTOFU, string(ev.New)
		case kindRecheck:
			e.Action, e.Reason = AuditRecheck, MethodToolsListChanged
		default:
			e.Action, e.Reason, e.Findings = ipc.ActionBlock, ReasonPinMismatch+":"+ev.Tool, []string{ev.Kind}
			e.Digest, e.PrevDigest = string(ev.New), string(ev.Old)
		}
		out = append(out, e)
	}
	return out
}

// notifyPins logs the mismatches among events and notifies them, at most
// once per server per pin.NotifyWindow. The log names server, tool and
// digests and gives the diff's length, never its text: descriptions are
// attacker-controlled and roverd's log is not the audit log (review L2).
// `rover pin list` shows the diff.
func (s *Server) notifyPins(events []pin.Event) {
	count := map[string]int{}
	single := map[string]string{}
	var order []string
	for _, ev := range events {
		if ev.Kind == pin.KindPinned || ev.Kind == kindRecheck {
			continue
		}
		s.o.Logf("PIN MISMATCH %s/%s (%s): %s -> %s, diff %d bytes; removed from tools/list and blocked until approved (see `rover pin list %s`)",
			pin.TerminalSafe(ev.Server), pin.TerminalSafe(ev.Tool), ev.Kind, orNone(ev.Old.Short()), orNone(ev.New.Short()), len(ev.Diff), pin.TerminalSafe(ev.Server))
		if count[ev.Server] == 0 {
			order = append(order, ev.Server)
		}
		count[ev.Server]++
		_, single[ev.Server] = pin.Message(ev)
	}
	for _, server := range order {
		s.notes.Add(server, count[server], single[server])
	}
}

func orNone(d string) string {
	if d == "" {
		return "none"
	}
	return d
}

// Admin runs one CLI admin request (ipc.TypeAdmin) and returns the reply.
// The socket path calls it after the peer check; `rover pin` calls it
// directly on a Server it built over the state database when no roverd is
// running, so both paths do exactly the same thing.
// The peer uid check has already passed. Approve and reset are audited
// before the answer goes out; if the audit write fails, roverd turns
// unhealthy like on any other audit failure.
//
// pin_approve and pin_reset first show the OS authentication dialog (M9),
// in this process: roverd, or the CLI itself when no roverd runs. The
// admin frame alone proves nothing, since anything running as the user
// can open the socket and send one; only the dialog proves a human.
func (s *Server) Admin(f ipc.Frame) ipc.Frame {
	fail := func(err error) ipc.Frame { return ipc.Frame{Type: ipc.TypeError, Message: err.Error()} }
	if f.Op == ipc.OpObservationsDump {
		return s.dumpObservations()
	}
	if f.Op == ipc.OpDoctorState {
		return s.doctorState()
	}
	if f.Op == ipc.OpTamperResolve || f.Op == ipc.OpTamperForget {
		return s.tamperAdmin(f)
	}
	if f.Op != ipc.OpPinList {
		s.mu.Lock()
		unhealthy := s.unhealthy
		s.mu.Unlock()
		if unhealthy {
			return fail(errors.New("roverd audit log failed earlier; restart roverd"))
		}
	}
	if f.Op == ipc.OpApprovalsList {
		list := []approve.PendingApproval{}
		if s.o.PendingApprovals != nil {
			list = append(list, s.o.PendingApprovals()...)
		}
		return adminResult(list, "")
	}
	if f.Op == ipc.OpPolicyApply {
		return s.applyPolicy(f)
	}
	var result any
	entry := audit.Entry{Time: s.o.Now().UTC(), Session: adminSession, Server: f.ServerName, Kind: AuditKindPin, Tool: f.Tool}
	switch f.Op {
	case ipc.OpPinList:
		ps, err := s.pins.List(f.ServerName)
		if err != nil {
			return fail(err)
		}
		return adminResult(ps, "")
	case ipc.OpPinApprove:
		if err := s.pins.CheckApprovable(f.ServerName, f.Tool, f.Digest); err != nil {
			return fail(err)
		}
		method, err := s.authenticate(fmt.Sprintf("Rover: approve the changed tool %s.%s (digest %s)?", f.ServerName, approve.Clean(f.Tool), f.Digest))
		if err != nil {
			return fail(err)
		}
		p, prev, err := s.pins.Approve(f.ServerName, f.Tool, f.Digest, method)
		if err != nil {
			return fail(err)
		}
		result, entry.Action, entry.Reason = p, AuditPinApproved, "method:"+method
		entry.Digest, entry.PrevDigest = string(p.Digest), string(prev)
		s.o.Logf("pin approved (%s): %s/%s -> %s", method, f.ServerName, f.Tool, p.Digest.Short())
	case ipc.OpPinReset:
		method, err := s.authenticate(fmt.Sprintf("Rover: forget every tool pin of %s?", f.ServerName))
		if err != nil {
			return fail(err)
		}
		n, err := s.pins.Reset(f.ServerName)
		if err != nil {
			return fail(err)
		}
		result, entry.Action, entry.Reason = map[string]int{"removed": n}, AuditPinReset, "method:"+method
		s.o.Logf("pins reset (%s): %s (%d removed)", method, f.ServerName, n)
	default:
		return fail(errors.New("unknown admin op " + f.Op))
	}
	if err := s.writeAudit(entry); err != nil {
		return fail(err)
	}
	return adminResult(result, "")
}

func adminResult(v any, note string) ipc.Frame {
	b, err := json.Marshal(v)
	if err != nil {
		return ipc.Frame{Type: ipc.TypeError, Message: err.Error()}
	}
	return ipc.Frame{Type: ipc.TypeAdminResult, Result: b, Message: note}
}

// adminAuthTimeout bounds the OS dialog of an admin request; the CLI waits
// ipc.AuthAdminTimeout, a little longer.
const adminAuthTimeout = 150 * time.Second

// ErrNotAuthenticated refuses an admin change the human did not confirm.
var ErrNotAuthenticated = errors.New("refused: OS authentication did not succeed")

// authenticate shows the OS dialog and returns the pin method to record,
// "osauth:<method>". Any failure refuses the change.
func (s *Server) authenticate(reason string) (string, error) {
	if s.o.Authenticator == nil {
		return "", fmt.Errorf("%w: no authenticator in this process", ErrNotAuthenticated)
	}
	ctx, cancel := context.WithTimeout(s.ctx, adminAuthTimeout)
	defer cancel()
	ok, method, err := s.o.Authenticator.Authenticate(ctx, reason)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNotAuthenticated, err)
	}
	if !ok {
		return "", ErrNotAuthenticated
	}
	return pin.MethodOSAuth + ":" + method, nil
}
