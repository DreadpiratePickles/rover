package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sync"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	"github.com/DreadpiratePickles/rover/internal/policy"
)

// Session is one agent process (Claude Code, Cursor, ...) as seen through
// every wrapper it spawned. Wrappers that share a parent pid share a Session,
// which is what lets M8 reason across servers ("it read a private file on
// server A, now it wants to send email through server B").
type Session struct {
	ID        string
	ClientPID int
	Created   time.Time

	mu         sync.Mutex
	clientName string // from initialize params.clientInfo
	clientVer  string
	// elicitation: the client advertised capabilities.elicitation in
	// initialize, so roverd may ask it about a held call (M9).
	elicitation bool
	servers     map[string]int // server name -> connected wrappers
	pending     map[string]pendingReq
	// flags is context.session for the policy: what this agent has done
	// across every server it uses (plan §5.1).
	flags policy.SessionCtx
	// tools is each server's tool names as this agent saw them listed, for
	// detection's cross_tool_reference (review M4: per session, per server).
	tools map[string]map[string]bool
	// order and nextSeq keep pending's insertion order for the cap
	// (addPending); lingerSince is set while no wrapper is attached
	// (sessionlife.go).
	orders      map[string][]pendingKey // per "<server>:<dir>"
	counts      map[string]int          // live pending entries per "<server>:<dir>"
	nextSeq     uint64
	lingerSince time.Time
}

type pendingReq struct {
	method string
	tool   string
	cursor string // tools/list: params.cursor, for the pins' first-listing window
	start  time.Time
	obsKey string // learn mode: the request's observation, flagged by its result
	// call is a tools/call that was forwarded; labels are its tool's
	// effective labels. Its result sets the session flags (M8).
	call   bool
	labels []string
	seq    uint64 // insertion order, for the pending cap
	bucket string // "<server>:<dir>", the cap it counts against
}

func newSession(id string, clientPID int, now time.Time) *Session {
	return &Session{ID: id, ClientPID: clientPID, Created: now, servers: map[string]int{}, pending: map[string]pendingReq{},
		orders: map[string][]pendingKey{}, counts: map[string]int{}}
}

// noteTools adds names to everything server has ever listed in this
// session (every page of every listing; a name is never forgotten, so a
// server's own tool never becomes "another server's tool" because it sits
// on a later page) and returns a copy of every server's names.
func (s *Session) noteTools(server string, names []string) map[string][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tools == nil {
		s.tools = map[string]map[string]bool{}
	}
	if s.tools[server] == nil {
		s.tools[server] = map[string]bool{}
	}
	for _, n := range names {
		s.tools[server][n] = true
	}
	snap := make(map[string][]string, len(s.tools))
	for srv, set := range s.tools {
		for n := range set {
			snap[srv] = append(snap[srv], n)
		}
	}
	return snap
}

func (s *Session) join(server string) {
	s.mu.Lock()
	s.servers[server]++
	s.mu.Unlock()
}

// leave returns true when no wrapper is attached any more.
func (s *Session) leave(server string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.servers[server]--
	if s.servers[server] <= 0 {
		delete(s.servers, server)
	}
	return len(s.servers) == 0
}

// Client returns the agent's self-reported name and version, if seen.
func (s *Session) Client() (name, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clientName, s.clientVer
}

// observe builds the audit entry for one message and updates the session's
// request/response correlation. It is the logic that lived in the A1 proxy,
// now owned by the daemon so the wrapper stays thin.
// It also returns the pending request a response answers (its tools/list
// cursor, learn-mode observation key and, for a forwarded tools/call, its
// labels); for a request, only the request's own cursor is set.
// evicted are the older pending requests the cap dropped (addPending).
func (s *Session) observe(server, dir string, m jsonrpc.Message, logBodies bool, now time.Time) (e audit.Entry, req pendingReq, evicted []evictedReq) {
	e = audit.Entry{
		Time:    now.UTC(),
		Session: s.ID,
		Server:  server,
		Dir:     dir,
		Kind:    string(m.Kind),
		Method:  m.Method,
		ID:      m.ID,
		Tool:    m.ToolName(),
		Bytes:   len(m.Raw),
	}
	if logBodies && json.Valid(m.Raw) {
		e.Body = m.Raw
	}
	if m.Kind == jsonrpc.KindRequest && m.Method == "tools/list" {
		req.cursor = listCursor(m.Params)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch m.Kind {
	case jsonrpc.KindRequest:
		evicted = s.addPending(server, dir, server+":"+dir+":"+string(m.ID), pendingReq{method: m.Method, tool: e.Tool, cursor: req.cursor, start: now})
		if dir == "c2s" && m.Method == "initialize" {
			// Read strictly (exact keys); Parse already refused an
			// ambiguous clientInfo as invalid.
			s.clientName, s.clientVer = m.ClientInfo()
			s.elicitation = elicitationCapable(m.Params)
		}
	case jsonrpc.KindResult, jsonrpc.KindError:
		// A response travels the opposite way to its request, so look it up
		// under the other direction. IDs are only unique per server and direction.
		key := server + ":" + other(dir) + ":" + string(m.ID)
		if p, ok := s.dropPending(key); ok {
			ms := float64(now.Sub(p.start).Microseconds()) / 1000
			e.LatencyMS, e.ReplyTo, e.Tool, req = &ms, p.method, p.tool, p
		}
		if m.Kind == jsonrpc.KindResult {
			var r struct {
				IsError bool `json:"isError"`
			}
			_ = json.Unmarshal(m.Result, &r)
			e.ToolError = r.IsError
		}
	}
	return e, req, evicted
}

// Elicitation reports whether the agent app said it supports elicitation.
func (s *Session) Elicitation() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.elicitation
}

// elicitationCapable reads params.capabilities.elicitation strictly (exact
// keys, no duplicates): present and an object means yes.
func elicitationCapable(params []byte) bool {
	fields, err := jsonrpc.Object(params)
	if err != nil {
		return false
	}
	caps, ok := fields.Get("capabilities")
	if !ok {
		return false
	}
	cf, err := jsonrpc.Object(caps)
	if err != nil {
		return false
	}
	e, ok := cf.Get("elicitation")
	if !ok {
		return false
	}
	_, err = jsonrpc.Object(e)
	return err == nil
}

// attachObservation remembers the observation key of a pending request, so
// a flag on its result reaches the right observation.
func (s *Session) attachObservation(server, dir string, id []byte, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := server + ":" + dir + ":" + string(id)
	if p, ok := s.pending[k]; ok {
		p.obsKey = key
		s.pending[k] = p
	}
}

// listCursor is the exact params.cursor string of a tools/list request, read
// strictly; "" when absent or not a string (then the page is not a
// follow-up, which only makes pinning stricter).
func listCursor(params []byte) string {
	if len(params) == 0 {
		return ""
	}
	fields, err := jsonrpc.Object(params)
	if err != nil {
		return ""
	}
	v, ok := fields.Get("cursor")
	var c string
	if !ok || json.Unmarshal(v, &c) != nil {
		return ""
	}
	return c
}

func other(dir string) string {
	if dir == "c2s" {
		return "s2c"
	}
	return "c2s"
}

// Flags returns context.session as of now.
func (s *Session) Flags() policy.SessionCtx {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.flags
	f.ServersTouched = slices.Clone(f.ServersTouched)
	return f
}

// noteForwardedCall records that a tools/call reached its server: it counts
// the call, adds the server to servers_touched and remembers the tool's
// labels on the pending request, so its result can set the flags. Only
// forwarded calls count: a blocked read never touched data.
func (s *Session) noteForwardedCall(server, dir string, id []byte, labels []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flags = AfterCall(s.flags, server)
	k := server + ":" + dir + ":" + string(id)
	if p, ok := s.pending[k]; ok {
		p.call, p.labels = true, labels
		s.pending[k] = p
	}
}

// noteResult records that the result of a forwarded tools/call reached the
// agent (see AfterResult).
func (s *Session) noteResult(labels []string, isError bool) {
	s.mu.Lock()
	s.flags = AfterResult(s.flags, labels, isError)
	s.mu.Unlock()
}

// noteUntrusted records that a result with a medium or high detection
// finding reached the agent (plan M8: saw_untrusted is also set by
// detection, whatever the tool's labels say).
func (s *Session) noteUntrusted() {
	s.mu.Lock()
	s.flags.SawUntrusted = true
	s.mu.Unlock()
}

// AfterCall is context.session after one more forwarded tools/call to
// server. The call alone sets no taint flag: those wait for its result.
// `rover policy test` replays sessions with it.
func AfterCall(f policy.SessionCtx, server string) policy.SessionCtx {
	f.Calls++
	if i, found := slices.BinarySearch(f.ServersTouched, server); !found {
		f.ServersTouched = slices.Insert(slices.Clone(f.ServersTouched), i, server)
	}
	return f
}

// AfterResult is context.session after the result of a forwarded call of a
// tool with these labels reached the agent.
//
//   - touched_private: a reads_private call SUCCEEDED. A request alone does
//     not count (the server may refuse it), nor does an isError result (the
//     read failed; what came back is an error message).
//   - saw_untrusted: a reads_untrusted result arrived, isError or not: an
//     error text from a web page or an issue tracker is still a stranger's
//     text.
func AfterResult(f policy.SessionCtx, labels []string, isError bool) policy.SessionCtx {
	for _, l := range labels {
		switch l {
		case "reads_private":
			if !isError {
				f.TouchedPrivate = true
			}
		case "reads_untrusted":
			f.SawUntrusted = true
		}
	}
	return f
}

// noteSession updates the session flags (M8) once the message's audit entry
// is written: a forwarded tools/call is counted and its labels remembered;
// the result (or JSON-RPC error) answering such a call, if it reaches the
// agent (forwarded, or rewritten by detection, not replaced by an error),
// sets touched_private and saw_untrusted from those labels; a medium or high detection finding
// in any result sets saw_untrusted.
func (s *Server) noteSession(sess *Session, server, dir string, m jsonrpc.Message, j judgment, req pendingReq) {
	if j.call {
		sess.noteForwardedCall(server, dir, m.ID, j.callLabels)
	}
	if dir == policy.DirS2C && req.call && j.audit != ipc.ActionBlock {
		switch m.Kind {
		case jsonrpc.KindResult:
			sess.noteResult(req.labels, ResultIsError(m.Result))
		case jsonrpc.KindError:
			// A JSON-RPC error answering the call: its message reached the
			// agent, so reads_untrusted applies; it is not a successful
			// read, so reads_private does not (review HIGH-1).
			sess.noteResult(req.labels, true)
		}
	}
	if j.untrusted {
		sess.noteUntrusted()
	}
}

// ResultIsError reports whether a tools/call result says isError: true,
// reading the exact key strictly. Anything unclear counts as success, so
// a server cannot dodge touched_private with an ambiguous result.
func ResultIsError(result []byte) bool {
	fields, err := jsonrpc.Object(result)
	if err != nil {
		return false
	}
	v, ok := fields.Get("isError")
	return ok && string(v) == "true"
}

// forget drops the pending entry of a request that was blocked: its server
// never saw it, so any "reply" to that id is not a reply to it.
func (s *Session) forget(server, dir string, id []byte) {
	s.mu.Lock()
	s.dropPending(server + ":" + dir + ":" + string(id))
	s.mu.Unlock()
}

// take removes and reports the pending entry of the request sent in dir
// with this id, if there is one.
func (s *Session) take(server, dir string, id []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.dropPending(server + ":" + dir + ":" + string(id))
	return ok
}

// join finds or creates the session for clientPID and attaches a wrapper to
// it, atomically with release, so a wrapper arriving while the last one
// leaves never lands on a session that is about to be deleted.
func (s *Server) join(clientPID int, server string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[clientPID]
	if !ok {
		sess = newSession(newID(), clientPID, s.o.Now())
		s.sessions[clientPID] = sess
	} else if sess.rejoin() {
		s.o.Logf("session %s: a wrapper came back; the session keeps its flags", sess.ID)
	}
	sess.join(server)
	return sess
}

// release detaches a wrapper. When it was the last one the session is not
// deleted: it lingers, flags and all, until the agent process is gone or
// LingerMax passes (sweepSessions), so an agent cannot wash its taint out
// by restarting its servers (review MEDIUM-3).
func (s *Server) release(sess *Session, server string) {
	now := s.o.Now()
	s.mu.Lock()
	last := sess.leave(server)
	if last {
		sess.startLinger(now)
	}
	s.mu.Unlock()
	if last {
		s.o.Logf("session %s: last wrapper left; lingering while client pid %d lives", sess.ID, sess.ClientPID)
		_ = s.writeAudit(sessionEntry(sess, now, AuditSessionLingering, "last wrapper left"))
	}
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
