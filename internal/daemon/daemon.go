// Package daemon is roverd: the long-lived process that owns the audit log
// and makes every decision. Wrappers are thin on purpose; if a decision
// needs state (pins, sessions, approvals), it lives here, in one place, so
// the agent cannot get a different answer by spawning a different wrapper.
//
// M1 decides "forward" for everything and records it. M2 onward replaces the
// body of decide with policy, pinning and detection; the plumbing around it
// stays the same.
package daemon

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/framing"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// Options configures a Server. Audit and SocketPath are required.
type Options struct {
	SocketPath string
	Audit      *audit.Logger
	LogBodies  bool

	// SelfUID is who roverd runs as; peers with any other uid are refused.
	SelfUID uint32
	// PeerCreds reads the connecting process's uid and pid from the kernel.
	// Tests inject it; production uses ipc.PeerCreds.
	PeerCreds func(*net.UnixConn) (ipc.Creds, error)
	// ParentPID returns a process's parent, used to check the client_pid a
	// wrapper claims. Tests inject it; production uses ipc.ParentPID.
	ParentPID func(int) (int, error)
	Now       func() time.Time
	Logf      func(format string, a ...any)
}

// Server accepts wrapper connections and answers decide frames.
type Server struct {
	o  Options
	ln *net.UnixListener

	mu       sync.Mutex
	sessions map[int]*Session // by client pid
	conns    map[net.Conn]struct{}
	closed   bool
	// unhealthy is set when the audit log failed; every later decision is a
	// block until a human restarts roverd and looks at the log.
	unhealthy bool
}

// New prepares a Server; call Listen then Serve.
func New(o Options) *Server {
	if o.PeerCreds == nil {
		o.PeerCreds = ipc.PeerCreds
	}
	if o.ParentPID == nil {
		o.ParentPID = ipc.ParentPID
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return &Server{o: o, sessions: map[int]*Session{}, conns: map[net.Conn]struct{}{}}
}

// Listen binds the socket 0600. A stale socket file from a crashed daemon is
// removed; a live one (something answers) is an error.
func (s *Server) Listen() error {
	if c, err := net.DialTimeout("unix", s.o.SocketPath, 200*time.Millisecond); err == nil {
		_ = c.Close()
		return fmt.Errorf("another roverd is listening on %s", s.o.SocketPath)
	}
	if err := os.Remove(s.o.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.o.SocketPath, Net: "unix"})
	if err != nil {
		return err
	}
	// The socket is created with the process umask; make it owner-only
	// regardless, then check. The peer uid check is the real control, this
	// just keeps other users from even knocking.
	if err := os.Chmod(s.o.SocketPath, 0o600); err != nil {
		_ = ln.Close()
		return err
	}
	s.ln = ln
	return nil
}

// Addr is the bound socket path.
func (s *Server) Addr() string { return s.o.SocketPath }

// Serve accepts connections until ctx is cancelled or Close is called.
func (s *Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		return errors.New("Serve before Listen")
	}
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	for {
		c, err := s.ln.AcceptUnix()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		go s.handle(c)
	}
}

// Close stops accepting and drops every connection.
func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	if s.ln != nil {
		_ = s.ln.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
}

// Sessions returns a snapshot of live sessions (for tests and `rover top`).
func (s *Server) Sessions() []*Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, sess)
	}
	return out
}

type conn struct {
	c  *net.UnixConn
	w  *bufio.Writer
	mu sync.Mutex
}

func (c *conn) send(f ipc.Frame) error {
	line, err := ipc.Encode(f)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.w.Write(line); err != nil {
		return err
	}
	return c.w.Flush()
}

func (s *Server) track(c net.Conn, on bool) {
	s.mu.Lock()
	if on {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
	s.mu.Unlock()
}

func (s *Server) handle(uc *net.UnixConn) {
	defer func() { _ = uc.Close() }()
	s.track(uc, true)
	defer s.track(uc, false)

	// Who is this? Ask the kernel before reading a single byte from them.
	creds, err := s.o.PeerCreds(uc)
	if err != nil {
		s.o.Logf("refusing connection: %v", err)
		return
	}
	if perr := ipc.CheckPeer(creds.UID, s.o.SelfUID); perr != nil {
		s.o.Logf("refusing connection: %v", perr)
		return
	}

	cn := &conn{c: uc, w: bufio.NewWriterSize(uc, 64<<10)}
	r := bufio.NewReaderSize(uc, 64<<10)
	hello, err := s.readFrame(r)
	if err != nil || hello.Type != ipc.TypeHello {
		if err == nil {
			err = fmt.Errorf("%w: first frame must be hello, got %s", ipc.ErrBadFrame, hello.Type)
		}
		_ = cn.send(ipc.Frame{Type: ipc.TypeError, Message: err.Error()})
		s.o.Logf("bad hello: %v", err)
		return
	}
	// The hello names a wrapper pid and a client (agent) pid. Both are checked
	// against the kernel: the connecting pid must be the wrapper, and its
	// parent must be the agent. Otherwise any same-user process could join
	// another agent's session, or dodge its own, just by lying.
	if herr := ipc.CheckHello(creds, hello.WrapperPID, hello.ClientPID, s.o.ParentPID); herr != nil {
		_ = cn.send(ipc.Frame{Type: ipc.TypeError, Message: herr.Error()})
		s.o.Logf("refusing hello from pid %d: %v", creds.PID, herr)
		return
	}
	sess := s.join(hello.ClientPID, hello.ServerName)
	defer s.release(sess, hello.ServerName)
	if err := cn.send(ipc.Frame{Type: ipc.TypeWelcome, SessionID: sess.ID}); err != nil {
		return
	}
	s.o.Logf("session %s: %s attached (client pid %d, wrapper pid %d)", sess.ID, hello.ServerName, hello.ClientPID, hello.WrapperPID)

	for {
		f, err := s.readFrame(r)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				_ = cn.send(ipc.Frame{Type: ipc.TypeError, Message: err.Error()})
				s.o.Logf("session %s: dropping %s: %v", sess.ID, hello.ServerName, err)
			}
			return
		}
		switch f.Type {
		case ipc.TypeDecide:
			if f.SessionID != sess.ID {
				_ = cn.send(ipc.Frame{Type: ipc.TypeError, Message: "decide for a session this connection does not own"})
				return
			}
			v := s.decide(sess, hello.ServerName, f)
			if err := cn.send(v); err != nil {
				return
			}
		case ipc.TypeBye:
			return
		default:
			_ = cn.send(ipc.Frame{Type: ipc.TypeError, Message: "unexpected frame " + f.Type})
			return
		}
	}
}

// readFrame reads one line; io.EOF with no bytes means the peer hung up.
func (s *Server) readFrame(r *bufio.Reader) (ipc.Frame, error) {
	line, err := framing.ReadLine(r, ipc.MaxFrame)
	if len(line) == 0 {
		if err == nil {
			err = io.EOF
		}
		return ipc.Frame{}, err
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return ipc.Frame{}, err
	}
	return ipc.Parse(line)
}

// decide is the whole decision path. M1: observe, log, forward. If the audit
// write fails the answer is block, now and for every later message, because
// a gateway that cannot record what it allowed is not a gateway.
func (s *Server) decide(sess *Session, server string, f ipc.Frame) ipc.Frame {
	m := jsonrpc.Parse(f.Raw)
	e := sess.observe(server, f.Dir, m, s.o.LogBodies, s.o.Now())
	e.Action = ipc.ActionForward

	s.mu.Lock()
	unhealthy := s.unhealthy
	s.mu.Unlock()
	if unhealthy {
		return ipc.Frame{Type: ipc.TypeVerdict, Seq: f.Seq, Action: ipc.ActionBlock, Reason: "roverd audit log failed earlier; restart roverd"}
	}
	if err := s.o.Audit.Write(e); err != nil {
		s.mu.Lock()
		s.unhealthy = true
		s.mu.Unlock()
		s.o.Logf("AUDIT LOG FAILED, blocking everything from now on: %v", err)
		return ipc.Frame{Type: ipc.TypeVerdict, Seq: f.Seq, Action: ipc.ActionBlock, Reason: "audit log unavailable: " + err.Error()}
	}
	return ipc.Frame{Type: ipc.TypeVerdict, Seq: f.Seq, Action: ipc.ActionForward}
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
