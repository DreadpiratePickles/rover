package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
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
	servers    map[string]int // server name -> connected wrappers
	pending    map[string]pendingReq
	// flags is context.session for the policy: what this agent has done
	// across every server it uses (plan §5.1).
	flags policy.SessionCtx
	// tools is each server's tool names as this agent saw them listed, for
	// detection's cross_tool_reference (review M4: per session, per server).
	tools map[string]map[string]bool
}

type pendingReq struct {
	method string
	tool   string
	cursor string // tools/list: params.cursor, for the pins' first-listing window
	start  time.Time
	obsKey string // learn mode: the request's observation, flagged by its result
}

func newSession(id string, clientPID int, now time.Time) *Session {
	return &Session{ID: id, ClientPID: clientPID, Created: now, servers: map[string]int{}, pending: map[string]pendingReq{}}
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
// It also returns the cursor of the tools/list request a result answers and
// the learn-mode observation key of the request a response answers.
func (s *Session) observe(server, dir string, m jsonrpc.Message, logBodies bool, now time.Time) (e audit.Entry, cursor, obsKey string) {
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
		cursor = listCursor(m.Params)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch m.Kind {
	case jsonrpc.KindRequest:
		s.pending[server+":"+dir+":"+string(m.ID)] = pendingReq{method: m.Method, tool: e.Tool, cursor: cursor, start: now}
		if dir == "c2s" && m.Method == "initialize" {
			// Read strictly (exact keys); Parse already refused an
			// ambiguous clientInfo as invalid.
			s.clientName, s.clientVer = m.ClientInfo()
		}
	case jsonrpc.KindResult, jsonrpc.KindError:
		// A response travels the opposite way to its request, so look it up
		// under the other direction. IDs are only unique per server and direction.
		key := server + ":" + other(dir) + ":" + string(m.ID)
		if p, ok := s.pending[key]; ok {
			delete(s.pending, key)
			ms := float64(now.Sub(p.start).Microseconds()) / 1000
			e.LatencyMS, e.ReplyTo, e.Tool, cursor, obsKey = &ms, p.method, p.tool, p.cursor, p.obsKey
		}
		if m.Kind == jsonrpc.KindResult {
			var r struct {
				IsError bool `json:"isError"`
			}
			_ = json.Unmarshal(m.Result, &r)
			e.ToolError = r.IsError
		}
	}
	return e, cursor, obsKey
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
	return s.flags
}

// noteForwardedCall records that a tools/call with these labels reached its
// server. Only forwarded calls count: a blocked read never touched data.
func (s *Session) noteForwardedCall(labels []string) {
	s.mu.Lock()
	s.flags = NextFlags(s.flags, labels)
	s.mu.Unlock()
}

// noteUntrusted records that a result with a detection finding reached the
// agent (plan M8: saw_untrusted is also set by any detection finding).
func (s *Session) noteUntrusted() {
	s.mu.Lock()
	s.flags.SawUntrusted = true
	s.mu.Unlock()
}

// NextFlags is context.session after one more forwarded tools/call of a tool
// with these labels. `rover policy test` replays sessions with it.
func NextFlags(f policy.SessionCtx, labels []string) policy.SessionCtx {
	for _, l := range labels {
		switch l {
		case "reads_private":
			f.TouchedPrivate = true
		case "reads_untrusted":
			f.SawUntrusted = true
		}
	}
	f.Calls++
	return f
}

// forget drops the pending entry of a request that was blocked: its server
// never saw it, so any "reply" to that id is not a reply to it.
func (s *Session) forget(server, dir string, id []byte) {
	s.mu.Lock()
	delete(s.pending, server+":"+dir+":"+string(id))
	s.mu.Unlock()
}

// take removes and reports the pending entry of the request sent in dir
// with this id, if there is one.
func (s *Session) take(server, dir string, id []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := server + ":" + dir + ":" + string(id)
	_, ok := s.pending[key]
	delete(s.pending, key)
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
	}
	sess.join(server)
	return sess
}

func (s *Server) release(sess *Session, server string) {
	s.mu.Lock()
	last := sess.leave(server)
	if last {
		if cur, ok := s.sessions[sess.ClientPID]; ok && cur == sess {
			delete(s.sessions, sess.ClientPID)
		}
	}
	s.mu.Unlock()
	if last {
		s.o.Logf("session %s: closed", sess.ID)
	}
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
