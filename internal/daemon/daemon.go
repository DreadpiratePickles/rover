// Package daemon is roverd: the long-lived process that owns the audit log
// and makes every decision. Wrappers are thin on purpose; if a decision
// needs state (pins, sessions, approvals), it lives here, in one place, so
// the agent cannot get a different answer by spawning a different wrapper.
//
// M1 decided "forward" for everything. From M2 every message goes through
// the Cedar policy (policy.go); from M4 tool pins are checked first
// (pins.go); detection joins later, and the plumbing around decide stays
// the same.
package daemon

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
	"github.com/DreadpiratePickles/rover/internal/clients"
	"github.com/DreadpiratePickles/rover/internal/config"
	"github.com/DreadpiratePickles/rover/internal/framing"
	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	"github.com/DreadpiratePickles/rover/internal/learn"
	"github.com/DreadpiratePickles/rover/internal/pin"
	"github.com/DreadpiratePickles/rover/internal/state"
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

	// Policy and Config are the initial decision source (see Reload). A nil
	// Policy means no policy is loaded: every policed message is blocked.
	Policy Policy
	Config config.Config

	// State is roverd's database; pins live in it (M4). Nil keeps pins in
	// memory only (tests): pinning is on either way, in every mode (D6).
	State *state.DB
	// Notifier tells the human about a blocked tool; nil means none.
	Notifier pin.Notifier
	// StateDBCreated (state.db did not exist) and AuditHadHistory (the audit
	// anchor existed) together mean every pin was lost: see reportStateLoss.
	StateDBCreated, AuditHadHistory bool
	// DisableDetection turns detection tier 1 off. Tests only: it exists so
	// a test can measure what detection adds to a decision (plan §6 M5).
	DisableDetection bool

	// Tamper watch (M7, tamper.go): the configs, the rover binary their servers
	// must run, the settle time (500 ms) and the retry tick (every 10 s).
	TamperFiles    []clients.ConfigFile
	RoverPath      string
	TamperDebounce time.Duration
	TamperRetry    <-chan time.Time
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

	pins           *pin.Checker
	notes          *pin.Coalescer // pins and detection: one notification budget per server
	det            detectState    // detection's memory (detect.go)
	pol            atomic.Pointer[loaded]
	noPolicyWarned atomic.Int64 // unix nanos of the last "no policy" warning
	// rec records learn-mode observations (M6); nil without a state DB.
	rec        *learn.Recorder
	taint      toolTaint     // learn mode: tools whose last listing was flagged
	tamper     tamperState   // the client-config watch (tamper.go)
	closedDone chan struct{} // closed when Close has finished (final flush)
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
	if o.Notifier == nil {
		o.Notifier = pin.NopNotifier{}
	}
	var store pin.Store = pin.NewMemStore()
	if o.State != nil {
		store = pin.NewBoltStore(o.State)
	}
	s := &Server{o: o, sessions: map[int]*Session{}, conns: map[net.Conn]struct{}{},
		pins: pin.NewChecker(store, o.Now, o.Logf), notes: pin.NewCoalescerWith(o.Notifier, o.Now, blockedMessage),
		closedDone: make(chan struct{})}
	if o.State != nil {
		s.rec = learn.NewRecorder(o.State, o.Logf)
	}
	s.pol.Store(&loaded{pol: o.Policy, cfg: o.Config}) // startup: any mode (D6)
	return s
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
	if err := s.reportStateLoss(); err != nil {
		_ = ln.Close()
		return err
	}
	// The baseline of wrapped servers is read before Listen returns.
	if err := s.startTamperWatch(); err != nil {
		s.o.Logf("%v; client configs are not watched", err)
	}
	return nil
}

// Addr is the bound socket path.
func (s *Server) Addr() string { return s.o.SocketPath }

// Serve accepts connections until ctx is cancelled or Close is called.
func (s *Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		return errors.New("Serve before Listen")
	}
	if s.rec != nil {
		t := time.NewTicker(learn.FlushEvery)
		defer t.Stop()
		s.rec.Start(t.C)
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
				<-s.closedDone // the final observation flush, before the caller closes the DB
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
	s.stopTamperWatch()
	if s.ln != nil {
		_ = s.ln.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	if s.rec != nil {
		if err := s.rec.Close(); err != nil {
			s.o.Logf("learn: final write of observations failed: %v", err)
		}
	}
	close(s.closedDone)
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
	if errors.Is(err, io.EOF) {
		return // connected and left without a word (`rover policy apply` checks liveness this way)
	}
	if err == nil && hello.Type == ipc.TypeAdmin {
		_ = cn.send(s.Admin(hello))
		return
	}
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
			v := s.decide(sess, hello, f)
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

// decide is the whole decision path: record, judge, log, answer. If the
// audit write fails the answer is block, now and for every later message,
// because a gateway that cannot record what it allowed is not a gateway.
func (s *Server) decide(sess *Session, hello ipc.Frame, f ipc.Frame) ipc.Frame {
	server := hello.ServerName
	m := jsonrpc.Parse(f.Raw)
	now := s.o.Now()
	e, req := sess.observe(server, f.Dir, m, s.o.LogBodies, now)
	j := s.judge(sess, server, hello.Transport, f.Dir, m, e.ReplyTo, req.cursor, now)
	e.Action, e.RuleIDs, e.Findings = j.audit, j.ruleIDs, j.findings
	if j.audit != ipc.ActionForward {
		e.Reason = j.reason
	}
	entries := append(append(pinEntries(e, j.pinEvents), poisonEntries(e, j.poisoned)...), e)
	if j.action == ipc.ActionBlock && m.Kind == jsonrpc.KindRequest {
		sess.forget(server, f.Dir, m.ID)
	}

	s.mu.Lock()
	unhealthy := s.unhealthy
	s.mu.Unlock()
	if unhealthy {
		return ipc.Frame{Type: ipc.TypeVerdict, Seq: f.Seq, Action: ipc.ActionBlock, Reason: "roverd audit log failed earlier; restart roverd"}
	}
	if err := s.writeAudit(entries...); err != nil {
		return ipc.Frame{Type: ipc.TypeVerdict, Seq: f.Seq, Action: ipc.ActionBlock, Reason: "audit log unavailable: " + err.Error()}
	}
	s.notifyPins(j.pinEvents)
	s.notifyPoison(j.poisoned)
	s.noteSession(sess, server, f.Dir, m, j, req)
	s.learnAfter(sess, server, f.Dir, m, j, req.obsKey)
	return ipc.Frame{
		Type: ipc.TypeVerdict, Seq: f.Seq, Action: j.action, Reason: j.reason, RuleIDs: j.ruleIDs,
		ResponseRaw: j.responseRaw, ReplacementRaw: j.replacement,
	}
}
