// Package daemon is roverd: the one process per user that decides what
// happens to every MCP message, and that alone writes the audit log.
//
// LESSON (M1): why a daemon at all? Each MCP server gets its own wrapper
// process, but the interesting attacks cross servers: read a secret with one
// tool, send it out with another (the "lethal trifecta", M8). Only something
// that sees all of an agent's servers at once can notice that. So wrappers
// are thin and dumb, and roverd is where the decisions, the state and the
// audit log live.
//
// The flow for one message:
//
//	wrapper: read a line from the agent or the server
//	wrapper -> roverd: decide {seq, dir, raw}
//	roverd:  classify it, correlate it, WRITE THE AUDIT ENTRY
//	roverd -> wrapper: verdict {seq, action: forward, rule_ids: []}
//	wrapper: forward the original bytes
//
// M1 always says "forward" (policy arrives in M2), but the order already
// matters: log first, then forward. If the audit log cannot be written,
// roverd says "block" and hangs up - an unrecorded message must not pass.
package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	"github.com/DreadpiratePickles/rover/internal/paths"
	"github.com/DreadpiratePickles/rover/internal/state"
)

// ReasonAuditUnavailable is the verdict reason when the audit log write fails.
const ReasonAuditUnavailable = "audit_unavailable"

// DefaultHelloTimeout is how long a new connection may take to say hello.
const DefaultHelloTimeout = 5 * time.Second

// maxPending bounds the request/response correlation map of one connection,
// so a peer that sends requests and never answers cannot grow it forever.
// Past the cap, new requests are still logged and decided; only their
// responses lose the reply_to/latency annotation.
const maxPending = 4096

// maxClientInfo bounds the clientInfo strings kept per session.
const maxClientInfo = 256

// Options configure a Daemon. Only Audit is required.
type Options struct {
	Dirs      paths.Dirs    // roverd's directories (for later milestones; unused by M1's decision path)
	Audit     *audit.Logger // the audit log roverd owns
	State     *state.DB     // the state database (opened by the caller; unused by M1's decision path)
	LogBodies bool          // write message bodies into the audit log (off by default until M10 adds redaction)

	// Now is the clock for audit times and latencies. Tests inject a fake.
	Now func() time.Time
	// PeerUID reads a connection's peer uid. Tests inject a fake; the
	// default is ipc.PeerUID. The allowed uid is always our own.
	PeerUID func(*net.UnixConn) (uint32, error)
	// Logf receives diagnostics (rejected peers, protocol errors). Default:
	// a logger on stderr. roverd never writes to stdout.
	Logf func(format string, args ...any)
	// HelloTimeout bounds the wait for a new connection's hello (default
	// DefaultHelloTimeout).
	HelloTimeout time.Duration
}

// Daemon is roverd's in-memory state: sessions and live connections.
type Daemon struct {
	opts  Options
	guard *ipc.Guard

	mu       sync.Mutex
	sessions map[int]*session // by client_pid
	conns    map[*ipc.Conn]struct{}
	closing  bool
	serving  bool
	wg       sync.WaitGroup
}

// session is the shared view of one agent app (one client_pid), across all
// of its MCP servers. Fields are guarded by Daemon.mu.
type session struct {
	id            string
	clientPID     int
	conns         int
	clientName    string
	clientVersion string
	elicitation   bool // the client advertised capabilities.elicitation (used in M9)
}

// SessionInfo is a snapshot of one session, for tests and status views.
type SessionInfo struct {
	ID            string
	ClientPID     int
	Conns         int
	ClientName    string
	ClientVersion string
	Elicitation   bool
}

// New checks opts and returns a Daemon ready to Serve.
func New(opts Options) (*Daemon, error) {
	if opts.Audit == nil {
		return nil, errors.New("daemon: an audit log is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.PeerUID == nil {
		opts.PeerUID = ipc.PeerUID
	}
	if opts.Logf == nil {
		opts.Logf = log.New(os.Stderr, "roverd: ", log.LstdFlags).Printf
	}
	if opts.HelloTimeout <= 0 {
		opts.HelloTimeout = DefaultHelloTimeout
	}
	uid, err := ipc.CurrentUID()
	if err != nil {
		return nil, err
	}
	d := &Daemon{
		opts:     opts,
		sessions: map[int]*session{},
		conns:    map[*ipc.Conn]struct{}{},
	}
	d.guard = &ipc.Guard{
		UID:      uid,
		PeerUID:  opts.PeerUID,
		OnReject: func(err error) { opts.Logf("rejected connection: %v", err) },
	}
	return d, nil
}

// Rejected returns how many connections were refused by the peer check.
func (d *Daemon) Rejected() uint64 { return d.guard.Rejected() }

// Serve accepts connections on l until ctx is cancelled, then stops
// accepting, closes every connection, waits for their handlers and returns
// nil. Closing l also removes the socket file. Serve can be called once.
func (d *Daemon) Serve(ctx context.Context, l *net.UnixListener) error {
	d.mu.Lock()
	if d.serving {
		d.mu.Unlock()
		return errors.New("daemon: Serve called twice")
	}
	d.serving = true
	d.mu.Unlock()

	stop := context.AfterFunc(ctx, func() { d.shutdown(l) })
	defer stop()

	var err error
	for {
		uc, aerr := d.guard.Accept(l)
		if aerr != nil {
			if ctx.Err() == nil {
				err = fmt.Errorf("daemon: accept: %w", aerr)
			}
			break
		}
		c := ipc.NewConn(uc)
		if !d.track(c) {
			_ = c.Close()
			break
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.handle(c)
		}()
	}
	d.shutdown(l)
	d.wg.Wait()
	return err
}

// shutdown stops accepting and closes every connection. Safe to call twice.
func (d *Daemon) shutdown(l *net.UnixListener) {
	d.mu.Lock()
	d.closing = true
	conns := make([]*ipc.Conn, 0, len(d.conns))
	for c := range d.conns {
		conns = append(conns, c)
	}
	d.mu.Unlock()
	_ = l.Close()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (d *Daemon) track(c *ipc.Conn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closing {
		return false
	}
	d.conns[c] = struct{}{}
	return true
}

func (d *Daemon) untrack(c *ipc.Conn) {
	d.mu.Lock()
	delete(d.conns, c)
	d.mu.Unlock()
}

// Sessions returns a snapshot of the live sessions.
func (d *Daemon) Sessions() []SessionInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]SessionInfo, 0, len(d.sessions))
	for _, s := range d.sessions {
		out = append(out, SessionInfo{s.id, s.clientPID, s.conns, s.clientName, s.clientVersion, s.elicitation})
	}
	return out
}

// join adds a connection to the session of clientPID, creating it if this is
// the first. Two wrappers started by the same agent app share one session.
func (d *Daemon) join(clientPID int) *session {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.sessions[clientPID]
	if !ok {
		s = &session{id: newSessionID(), clientPID: clientPID}
		d.sessions[clientPID] = s
	}
	s.conns++
	return s
}

// leave removes a connection; the session goes when its last one does.
func (d *Daemon) leave(s *session) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s.conns--
	if s.conns <= 0 && d.sessions[s.clientPID] == s {
		delete(d.sessions, s.clientPID)
	}
}

func newSessionID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error (it crashes the program instead)
	return hex.EncodeToString(b)
}

// errProtocol marks a peer that broke the protocol; its connection is closed.
var errProtocol = errors.New("protocol error")

// handle runs one wrapper connection from hello to close. Any protocol
// error, I/O error or audit failure ends it.
func (d *Daemon) handle(c *ipc.Conn) {
	defer d.untrack(c)
	defer func() { _ = c.Close() }()

	hello, err := d.readHello(c)
	if err != nil {
		d.opts.Logf("closing connection: %v", err)
		return
	}
	sess := d.join(hello.ClientPID)
	defer d.leave(sess)

	if err := c.Write(ipc.Message{Type: ipc.TypeWelcome, Welcome: &ipc.Welcome{SessionID: sess.id}}); err != nil {
		return
	}
	cs := &connState{hello: *hello, sess: sess, pending: map[string]pending{}}
	for {
		m, err := c.Read()
		if err == io.EOF {
			return
		}
		if err != nil {
			d.opts.Logf("closing connection (session %s, server %q): %v", sess.id, hello.ServerName, err)
			return
		}
		switch m.Type {
		case ipc.TypeBye:
			return
		case ipc.TypeDecide:
			v, keep, err := d.onDecide(cs, m.Decide)
			if err != nil {
				d.opts.Logf("closing connection (session %s, server %q): %v", sess.id, hello.ServerName, err)
				return
			}
			if werr := c.Write(ipc.Message{Type: ipc.TypeVerdict, Verdict: &v}); werr != nil || !keep {
				return
			}
		default:
			d.opts.Logf("closing connection (session %s): %v: unexpected %q", sess.id, errProtocol, m.Type)
			return
		}
	}
}

func (d *Daemon) readHello(c *ipc.Conn) (*ipc.Hello, error) {
	if err := c.SetReadDeadline(time.Now().Add(d.opts.HelloTimeout)); err != nil {
		return nil, err
	}
	m, err := c.Read()
	if err != nil {
		return nil, err
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	h := m.Hello
	switch {
	case h == nil:
		return nil, fmt.Errorf("%w: first message is %q, not hello", errProtocol, m.Type)
	case h.Version != ipc.Version:
		return nil, fmt.Errorf("%w: protocol version %d, want %d", errProtocol, h.Version, ipc.Version)
	case h.ClientPID <= 0:
		return nil, fmt.Errorf("%w: client_pid %d", errProtocol, h.ClientPID)
	}
	return h, nil
}

// connState is per-connection state. One goroutine (handle) owns it, so it
// needs no lock: decides on one connection are processed strictly in order.
type connState struct {
	hello   ipc.Hello
	sess    *session
	lastSeq uint64
	pending map[string]pending // key: "<requester dir>:<raw id>"
}

type pending struct {
	method string
	tool   string
	start  time.Time
}

// onDecide checks a decide against the protocol, then runs the decision
// path. keep=false means: send this verdict, then close the connection.
func (d *Daemon) onDecide(cs *connState, m *ipc.Decide) (v ipc.Verdict, keep bool, err error) {
	switch {
	case m.SessionID != cs.sess.id:
		return v, false, fmt.Errorf("%w: decide for session %q on a connection of session %q", errProtocol, m.SessionID, cs.sess.id)
	case m.Seq != cs.lastSeq+1:
		return v, false, fmt.Errorf("%w: seq %d after %d", errProtocol, m.Seq, cs.lastSeq)
	case m.Dir != ipc.DirC2S && m.Dir != ipc.DirS2C:
		return v, false, fmt.Errorf("%w: dir %q", errProtocol, m.Dir)
	case len(m.Raw) == 0:
		return v, false, fmt.Errorf("%w: empty raw", errProtocol)
	}
	cs.lastSeq = m.Seq

	e := d.classify(cs, m.Dir, m.Raw)
	if werr := d.opts.Audit.Write(e); werr != nil {
		// Fail closed: block this message and hang up. The wrapper stops the
		// session; nothing passes without a record.
		d.opts.Logf("audit write failed, blocking and closing (session %s): %v", cs.sess.id, werr)
		return ipc.Verdict{Seq: m.Seq, Action: ipc.ActionBlock, Reason: ReasonAuditUnavailable, RuleIDs: []string{}}, false, nil
	}
	return ipc.Verdict{Seq: m.Seq, Action: ipc.ActionForward, RuleIDs: []string{}}, true, nil
}

// classify builds the audit entry for one message and updates the
// connection's request/response correlation and the session's client info.
// (This is A1's proxy.observe, moved into roverd.)
func (d *Daemon) classify(cs *connState, dir string, raw []byte) audit.Entry {
	now := d.opts.Now()
	m := jsonrpc.Parse(raw)
	e := audit.Entry{
		Time:    now.UTC(),
		Session: cs.sess.id,
		Server:  cs.hello.ServerName,
		Dir:     dir,
		Kind:    string(m.Kind),
		Method:  m.Method,
		ID:      m.ID,
		Tool:    m.ToolName(),
		Bytes:   len(m.Raw),
	}
	if d.opts.LogBodies && json.Valid(m.Raw) {
		e.Body = m.Raw
	}

	switch m.Kind {
	case jsonrpc.KindRequest:
		if len(cs.pending) < maxPending {
			cs.pending[dir+":"+string(m.ID)] = pending{m.Method, e.Tool, now}
		}
		if dir == ipc.DirC2S && m.Method == "initialize" {
			d.noteClient(cs.sess, m.Params)
		}
	case jsonrpc.KindResult, jsonrpc.KindError:
		// A response travels the opposite way to its request, so look it up
		// under the other direction. IDs are only unique per direction.
		key := other(dir) + ":" + string(m.ID)
		if p, ok := cs.pending[key]; ok {
			delete(cs.pending, key)
			ms := float64(now.Sub(p.start).Microseconds()) / 1000
			e.LatencyMS, e.ReplyTo, e.Tool = &ms, p.method, p.tool
		}
		if m.Kind == jsonrpc.KindResult {
			var r struct {
				IsError bool `json:"isError"`
			}
			_ = json.Unmarshal(m.Result, &r) // not a tool result: no isError, and that's fine
			e.ToolError = r.IsError
		}
	}
	return e
}

func other(dir string) string {
	if dir == ipc.DirC2S {
		return ipc.DirS2C
	}
	return ipc.DirC2S
}

// noteClient records clientInfo and the elicitation capability from an
// initialize request's params. M9 uses elicitation to ask the user for
// approval inside the agent app, when the app supports it.
func (d *Daemon) noteClient(s *session, params json.RawMessage) {
	var p struct {
		ClientInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"clientInfo"`
		Capabilities struct {
			Elicitation json.RawMessage `json:"elicitation"`
		} `json:"capabilities"`
	}
	if json.Unmarshal(params, &p) != nil {
		return
	}
	el := len(p.Capabilities.Elicitation) > 0 && string(p.Capabilities.Elicitation) != "null"
	d.mu.Lock()
	defer d.mu.Unlock()
	s.clientName = truncate(p.ClientInfo.Name, maxClientInfo)
	s.clientVersion = truncate(p.ClientInfo.Version, maxClientInfo)
	s.elicitation = el
}

func truncate(s string, n int) string {
	if len(s) > n {
		return strings.ToValidUTF8(s[:n], "") // don't keep half a character
	}
	return s
}
