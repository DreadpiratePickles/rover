package daemon

import (
	"encoding/json"
	"fmt"

	"github.com/DreadpiratePickles/rover/internal/detect"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	"github.com/DreadpiratePickles/rover/internal/learn"
	"github.com/DreadpiratePickles/rover/internal/pin"
	"github.com/DreadpiratePickles/rover/internal/policy"
)

// Learn mode (M6, plan D6) in roverd. In observe mode every tools/call,
// tools/list and resources/read the policy forwarded (allowed or
// would_deny) is recorded as a learn.Observation; `rover policy propose`
// turns them into an allow-list. Pinning and detection stay on while
// learning: a call they flag, or whose result they flag, is recorded with
// those flags and never proposed.
//
// decide only appends to the recorder's in-memory queue; one goroutine
// writes to bbolt (learn.Recorder), so learning adds no disk I/O to the
// decision path.

// learnedMethods are the requests learn mode records.
var learnedMethods = map[string]bool{learn.ActionCall: true, learn.ActionList: true, learn.ActionRead: true}

// learnPending is the observation of a request judgePolicy forwarded, or nil
// when it is not recorded (enforce mode, blocked, not a learned method).
// judge sets its flags from the request's own detection findings.
func learnPending(st *loaded, in policy.Input, o policy.Outcome) *learn.Pending {
	m := in.Msg
	if st.cfg.Mode != policy.ModeObserve || o.Action != ipc.ActionForward || in.Dir != policy.DirC2S ||
		m.Kind != jsonrpc.KindRequest || !learnedMethods[m.Method] {
		return nil
	}
	p := &learn.Pending{
		TS: in.Now, Client: in.Client, Server: in.Server, Action: m.Method,
	}
	switch m.Method {
	case learn.ActionCall:
		p.Tool, p.Rules, p.Args, p.Norm = m.ToolName(), in.Normalizers, o.Args, o.Norm
	case learn.ActionRead:
		p.Shape = learn.ResourceShape(resourceURI(m.Params))
	}
	return p
}

// resourceURI is params.uri of a resources/read, read strictly; "" if absent.
func resourceURI(params []byte) string {
	fields, err := jsonrpc.Object(params)
	if err != nil {
		return ""
	}
	v, ok := fields.Get("uri")
	var uri string
	if !ok || json.Unmarshal(v, &uri) != nil {
		return ""
	}
	return uri
}

// flagIDs are the ids of the medium and high findings: those flag an
// observation out of the proposal. Low findings do not: rover eval and
// detection itself treat low as "logged, not acted on", and a benign
// description with a low finding would otherwise keep list_tools out of
// every proposal.
func flagIDs(fs []detect.Finding) []string {
	var ids []string
	for _, f := range fs {
		if f.Severity == detect.Medium || f.Severity == detect.High {
			ids = append(ids, f.ID)
		}
	}
	return sortedUnique(ids)
}

// resultFlags are the flags a response puts on its request's observation:
// medium/high detection findings in the result or tool list, tools removed
// for poisoning (high), and pin mismatches.
func resultFlags(j judgment) []string {
	flags := append([]string(nil), j.learnFlags...)
	for _, p := range j.poisoned {
		flags = append(flags, p.ids...)
	}
	for _, ev := range j.pinEvents {
		if ev.Kind != pin.KindPinned && ev.Kind != kindRecheck {
			flags = append(flags, learn.FlagPinMismatch)
		}
	}
	return sortedUnique(flags)
}

// learnAfter runs once the message's audit entry is written: it queues the
// observation of a forwarded request (remembering its key on the pending
// request) or flags the observation of the request a response answers.
func (s *Server) learnAfter(sess *Session, server, dir string, m jsonrpc.Message, j judgment, obsKey string) {
	if s.rec == nil {
		return
	}
	if j.obs != nil {
		if key := s.rec.Record(*j.obs); key != "" {
			sess.attachObservation(server, dir, m.ID, key)
		}
		return
	}
	if obsKey != "" {
		s.rec.Flag(obsKey, resultFlags(j)...)
	}
}

// dumpObservations answers the observations_dump admin op: it writes the
// queue first, so the CLI sees every call made so far, then returns the
// bucket (oldest first, capped by learn.MaxLoad and learn.MaxDumpBytes).
func (s *Server) dumpObservations() ipc.Frame {
	if s.rec == nil || s.o.State == nil {
		return ipc.Frame{Type: ipc.TypeError, Message: "roverd has no state database"}
	}
	if err := s.rec.Flush(); err != nil {
		return ipc.Frame{Type: ipc.TypeError, Message: "writing queued observations: " + err.Error()}
	}
	obs, err := learn.Load(s.o.State)
	if err != nil {
		return ipc.Frame{Type: ipc.TypeError, Message: err.Error()}
	}
	b, dropped, err := learn.EncodeCapped(obs, learn.MaxDumpBytes)
	if err != nil {
		return ipc.Frame{Type: ipc.TypeError, Message: err.Error()}
	}
	note := ""
	if dropped > 0 {
		note = fmt.Sprintf("%d oldest observations left out (the answer is capped at %d bytes)", dropped, learn.MaxDumpBytes)
	}
	return ipc.Frame{Type: ipc.TypeAdminResult, Result: b, Message: note}
}
