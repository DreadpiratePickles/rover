package daemon

import (
	"encoding/json"
	"errors"

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
		s.o.Logf("pin check for %s/%s failed, blocking: %v", server, m.ToolName(), err)
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
			e.Action, e.Reason = AuditPinned, pin.MethodTOFU
		case kindRecheck:
			e.Action, e.Reason = AuditRecheck, MethodToolsListChanged
		default:
			e.Action, e.Reason, e.Findings = ipc.ActionBlock, ReasonPinMismatch+":"+ev.Tool, []string{ev.Kind}
		}
		out = append(out, e)
	}
	return out
}

// notifyPins logs and notifies the mismatches among events.
func (s *Server) notifyPins(events []pin.Event) {
	for _, ev := range events {
		if ev.Kind == pin.KindPinned || ev.Kind == kindRecheck {
			continue
		}
		s.o.Logf("PIN MISMATCH %s/%s (%s): removed from tools/list and blocked until `rover pin approve %s %s`\n%s",
			ev.Server, ev.Tool, ev.Kind, ev.Server, ev.Tool, ev.Diff)
		s.o.Notifier.Notify(pin.Message(ev))
	}
}

// Admin runs one CLI admin request (ipc.TypeAdmin) and returns the reply.
// The socket path calls it after the peer check; `rover pin` calls it
// directly on a Server it built over the state database when no roverd is
// running, so both paths do exactly the same thing.
// The peer uid check has already passed. Approve and reset are audited
// before the answer goes out; if the audit write fails, roverd turns
// unhealthy like on any other audit failure.
// TODO(M9): pin_approve and pin_reset need OS authentication.
func (s *Server) Admin(f ipc.Frame) ipc.Frame {
	fail := func(err error) ipc.Frame { return ipc.Frame{Type: ipc.TypeError, Message: err.Error()} }
	if f.Op != ipc.OpPinList {
		s.mu.Lock()
		unhealthy := s.unhealthy
		s.mu.Unlock()
		if unhealthy {
			return fail(errors.New("roverd audit log failed earlier; restart roverd"))
		}
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
		p, err := s.pins.Approve(f.ServerName, f.Tool, pin.MethodCLI)
		if err != nil {
			return fail(err)
		}
		result, entry.Action, entry.Reason = p, AuditPinApproved, "method:"+pin.MethodCLI
		s.o.Logf("pin approved by CLI: %s/%s -> %s", f.ServerName, f.Tool, p.Digest.Short())
	case ipc.OpPinReset:
		n, err := s.pins.Reset(f.ServerName)
		if err != nil {
			return fail(err)
		}
		result, entry.Action, entry.Reason = map[string]int{"removed": n}, AuditPinReset, "method:"+pin.MethodCLI
		s.o.Logf("pins reset by CLI: %s (%d removed)", f.ServerName, n)
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
