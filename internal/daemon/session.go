package daemon

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
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
			var p struct {
				ClientInfo struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"clientInfo"`
			}
			if json.Unmarshal(m.Params, &p) == nil {
				s.clientName, s.clientVer = p.ClientInfo.Name, p.ClientInfo.Version
			}
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
