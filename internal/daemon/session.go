package daemon

import (
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
}

type pendingReq struct {
	method string
	tool   string
	start  time.Time
}

func newSession(id string, clientPID int, now time.Time) *Session {
	return &Session{ID: id, ClientPID: clientPID, Created: now, servers: map[string]int{}, pending: map[string]pendingReq{}}
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
func (s *Session) observe(server, dir string, m jsonrpc.Message, logBodies bool, now time.Time) audit.Entry {
	e := audit.Entry{
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
	s.mu.Lock()
	defer s.mu.Unlock()
	switch m.Kind {
	case jsonrpc.KindRequest:
		s.pending[server+":"+dir+":"+string(m.ID)] = pendingReq{m.Method, e.Tool, now}
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
			e.LatencyMS, e.ReplyTo, e.Tool = &ms, p.method, p.tool
		}
		if m.Kind == jsonrpc.KindResult {
			var r struct {
				IsError bool `json:"isError"`
			}
			_ = json.Unmarshal(m.Result, &r)
			e.ToolError = r.IsError
		}
	}
	return e
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
