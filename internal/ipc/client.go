package ipc

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/DreadpiratePickles/rover/internal/proxy"
)

// DefaultDecideTimeout bounds one decide round trip. roverd answers in well
// under a millisecond; if it stops answering, the wrapper stops instead of
// hanging the agent forever.
const DefaultDecideTimeout = 10 * time.Second

// Client is the wrapper's end of the socket. It implements proxy.Decider, so
// a proxy.Pipe can use it directly:
//
//	c, err := ipc.Dial(socketPath, time.Second)
//	w, err := c.Hello(ipc.Hello{...})
//	p := &proxy.Pipe{ToServer: childStdin, ToClient: os.Stdout, Decider: c}
//
// Decide may be called from both pumps at once; calls are serialised, one
// round trip at a time.
type Client struct {
	conn *Conn

	// DecideTimeout bounds one Decide round trip (0 means no limit).
	DecideTimeout time.Duration

	mu        sync.Mutex
	sessionID string
	seq       uint64
	broken    error // set on the first Decide failure; later calls fail too
}

// Dial connects to roverd's socket, giving up after timeout.
//
// It also checks the peer the other way round: the process listening on the
// socket must be our own user. If some other user managed to put a socket
// at our path, we would otherwise hand them every MCP message.
func Dial(path string, timeout time.Duration) (*Client, error) {
	nc, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return nil, err
	}
	uc, ok := nc.(*net.UnixConn)
	if !ok {
		_ = nc.Close()
		return nil, errors.New("ipc: not a unix connection")
	}
	g, err := NewGuard()
	if err == nil {
		err = g.Check(uc)
	}
	if err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("ipc: refusing daemon: %w", err)
	}
	return &Client{conn: NewConn(uc), DecideTimeout: DefaultDecideTimeout}, nil
}

// Send writes one message. Do not mix Send/Recv with concurrent Decide calls.
func (c *Client) Send(m Message) error { return c.conn.Write(m) }

// Recv reads one message. Do not mix Send/Recv with concurrent Decide calls.
func (c *Client) Recv() (Message, error) { return c.conn.Read() }

// Hello sends h (Version defaults to the current one) and waits up to
// timeout for the welcome. Decide only works after a successful Hello.
func (c *Client) Hello(h Hello, timeout time.Duration) (Welcome, error) {
	if h.Version == 0 {
		h.Version = Version
	}
	if timeout > 0 {
		if err := c.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return Welcome{}, err
		}
		defer func() { _ = c.conn.SetDeadline(time.Time{}) }()
	}
	if err := c.Send(Message{Type: TypeHello, Hello: &h}); err != nil {
		return Welcome{}, err
	}
	m, err := c.Recv()
	if err != nil {
		return Welcome{}, err
	}
	if m.Welcome == nil || m.Welcome.SessionID == "" {
		return Welcome{}, fmt.Errorf("%w: expected welcome, got %q", ErrProtocol, m.Type)
	}
	c.mu.Lock()
	c.sessionID = m.Welcome.SessionID
	c.mu.Unlock()
	return *m.Welcome, nil
}

// SessionID returns the id from the welcome, or "" before Hello.
func (c *Client) SessionID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionID
}

// Decide implements proxy.Decider: it sends one decide and waits for the
// verdict with the same seq. Any failure - I/O, timeout, a protocol error, a
// verdict for the wrong seq - is returned as an error (the Pipe then stops
// the session) and poisons the Client, because after a failure we can no
// longer be sure which answer belongs to which question.
func (c *Client) Decide(dir proxy.Direction, raw []byte) (proxy.Verdict, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken != nil {
		return proxy.Verdict{}, c.broken
	}
	v, err := c.decideLocked(dir, raw)
	if err != nil {
		c.broken = fmt.Errorf("ipc: client unusable after earlier failure: %w", err)
		return proxy.Verdict{}, err
	}
	return v, nil
}

func (c *Client) decideLocked(dir proxy.Direction, raw []byte) (proxy.Verdict, error) {
	if c.sessionID == "" {
		return proxy.Verdict{}, errors.New("ipc: decide before hello")
	}
	if c.DecideTimeout > 0 {
		if err := c.conn.SetDeadline(time.Now().Add(c.DecideTimeout)); err != nil {
			return proxy.Verdict{}, err
		}
		defer func() { _ = c.conn.SetDeadline(time.Time{}) }()
	}
	c.seq++
	seq := c.seq
	d := &Decide{SessionID: c.sessionID, Seq: seq, Dir: string(dir), Raw: raw}
	if err := c.conn.Write(Message{Type: TypeDecide, Decide: d}); err != nil {
		return proxy.Verdict{}, err
	}
	for {
		m, err := c.conn.Read()
		if err != nil {
			return proxy.Verdict{}, err
		}
		switch m.Type {
		case TypeRelease:
			// M9 will resolve held messages here. The M1 wrapper never holds
			// (a hold stops the session), so there is nothing to release.
			continue
		case TypeVerdict:
			if m.Verdict.Seq != seq {
				return proxy.Verdict{}, fmt.Errorf("%w: verdict for seq %d, want %d", ErrProtocol, m.Verdict.Seq, seq)
			}
			return proxy.Verdict{
				Action:         m.Verdict.Action,
				ReplacementRaw: m.Verdict.ReplacementRaw,
				Reason:         m.Verdict.Reason,
			}, nil
		default:
			return proxy.Verdict{}, fmt.Errorf("%w: unexpected %q while waiting for a verdict", ErrProtocol, m.Type)
		}
	}
}

// Close says bye (best effort, short deadline) and closes the connection.
func (c *Client) Close() error {
	c.mu.Lock()
	id := c.sessionID
	c.mu.Unlock()
	if id != "" {
		_ = c.conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_ = c.conn.Write(Message{Type: TypeBye, Bye: &Bye{SessionID: id}})
	}
	return c.conn.Close()
}
