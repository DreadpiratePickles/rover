package ipc

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/DreadpiratePickles/rover/internal/framing"
)

// Client is the wrapper's end of a connection to roverd. Decide is safe to
// call from both pump goroutines at once; verdicts are matched to callers by
// seq, and a later release for a held seq is delivered on the channel that
// Decide handed back.
type Client struct {
	conn    net.Conn
	w       *bufio.Writer
	wmu     sync.Mutex
	session string

	mu       sync.Mutex
	seq      uint64
	waiting  map[uint64]chan Frame // verdict waiters
	released map[uint64]chan Frame // release waiters for held seqs
	closed   bool
	err      error
	done     chan struct{}
	// inject receives the message of every inject frame (M9); nil drops
	// them, which only means no elicitation reaches the client.
	inject func(raw []byte)
	// tlsGroup goes on every decide (M11 bridge); "" for wrap.
	tlsGroup string
}

// Hello identifies the wrapper to roverd.
type Hello struct {
	WrapperPID   int
	ClientPID    int
	ServerName   string
	ServerCmdSHA string
	Transport    string
}

// Dial connects to the daemon socket and completes the hello/welcome
// exchange. It returns an error, not a Client, on any problem: the caller is
// expected to fail closed.
func Dial(path string, h Hello) (*Client, error) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	c := &Client{conn: conn, w: bufio.NewWriterSize(conn, 64<<10), waiting: map[uint64]chan Frame{}, released: map[uint64]chan Frame{}, done: make(chan struct{})}
	if err = c.send(Frame{Type: TypeHello, Version: Version, WrapperPID: h.WrapperPID, ClientPID: h.ClientPID, ServerName: h.ServerName, ServerCmdSHA: h.ServerCmdSHA, Transport: h.Transport}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	r := bufio.NewReaderSize(conn, 64<<10)
	line, err := framing.ReadLine(r, MaxFrame)
	if err != nil && (!errors.Is(err, io.EOF) || len(line) == 0) {
		_ = conn.Close()
		return nil, fmt.Errorf("waiting for welcome: %w", err)
	}
	f, err := Parse(line)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	switch f.Type {
	case TypeWelcome:
		c.session = f.SessionID
	case TypeError:
		_ = conn.Close()
		return nil, fmt.Errorf("roverd refused: %s", f.Message)
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("%w: expected welcome, got %s", ErrBadFrame, f.Type)
	}
	go c.readLoop(r)
	return c, nil
}

// SetInjectHandler installs fn for inject frames. It is called on the
// reading goroutine, one frame at a time; it must not block for long.
func (c *Client) SetInjectHandler(fn func(raw []byte)) {
	c.mu.Lock()
	c.inject = fn
	c.mu.Unlock()
}

// SetTLSGroup records the key exchange group of the bridge's newest TLS
// connection; later decides carry it for the audit log.
func (c *Client) SetTLSGroup(g string) {
	if !ValidTLSGroup(g) {
		return
	}
	c.mu.Lock()
	c.tlsGroup = g
	c.mu.Unlock()
}

// SessionID is the id roverd assigned in welcome.
func (c *Client) SessionID() string { return c.session }

// Decide sends one MCP message for a verdict and blocks until it arrives. If
// the verdict is hold, the returned channel delivers the eventual release;
// otherwise it is nil.
func (c *Client) Decide(dir string, raw []byte) (Frame, <-chan Frame, error) {
	c.mu.Lock()
	if c.closed {
		err := c.err
		c.mu.Unlock()
		return Frame{}, nil, fmt.Errorf("roverd connection closed: %w", err)
	}
	c.seq++
	seq := c.seq
	ch := make(chan Frame, 1)
	rel := make(chan Frame, 1)
	// Register the release channel now, not after the verdict: roverd may push
	// the release in the same instant as a hold verdict, and a release with
	// nobody waiting would otherwise be lost and the held message stuck.
	c.waiting[seq] = ch
	c.released[seq] = rel
	group := c.tlsGroup
	c.mu.Unlock()

	if err := c.send(Frame{Type: TypeDecide, SessionID: c.session, Seq: seq, Dir: dir, Raw: raw, TLSGroup: group}); err != nil {
		c.forget(seq)
		return Frame{}, nil, err
	}
	select {
	case v := <-ch:
		if v.Action == ActionHold {
			return v, rel, nil
		}
		c.mu.Lock()
		delete(c.released, seq)
		c.mu.Unlock()
		return v, nil, nil
	case <-c.done:
		c.mu.Lock()
		err := c.err
		c.mu.Unlock()
		return Frame{}, nil, fmt.Errorf("roverd connection closed before verdict %d: %w", seq, err)
	}
}

func (c *Client) forget(seq uint64) {
	c.mu.Lock()
	delete(c.waiting, seq)
	delete(c.released, seq)
	c.mu.Unlock()
}

// Close sends bye and closes the socket.
func (c *Client) Close() error {
	_ = c.send(Frame{Type: TypeBye, SessionID: c.session})
	return c.conn.Close()
}

func (c *Client) send(f Frame) error {
	line, err := Encode(f)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.w.Write(line); err != nil {
		return err
	}
	return c.w.Flush()
}

func (c *Client) readLoop(r *bufio.Reader) {
	var ferr error
	for {
		line, err := framing.ReadLine(r, MaxFrame)
		if len(line) > 0 {
			f, perr := Parse(line)
			if perr != nil {
				ferr = perr
				break
			}
			c.dispatch(f)
			if f.Type == TypeError {
				ferr = errors.New(f.Message)
				break
			}
		}
		if err != nil {
			ferr = err
			break
		}
	}
	c.mu.Lock()
	c.closed = true
	c.err = ferr
	// Wake every held message: a hold whose release will never come is a
	// deny. Seqs still waiting for a verdict are woken through done below.
	for seq, ch := range c.released {
		if _, stillWaiting := c.waiting[seq]; stillWaiting {
			continue
		}
		select {
		case ch <- Frame{Type: TypeRelease, Seq: seq, Action: ActionBlock, Reason: "roverd connection lost"}:
		default:
		}
	}
	c.mu.Unlock()
	close(c.done)
}

func (c *Client) dispatch(f Frame) {
	c.mu.Lock()
	if f.Type == TypeInject {
		fn := c.inject
		c.mu.Unlock()
		if fn != nil {
			fn(f.Raw)
		}
		return
	}
	defer c.mu.Unlock()
	switch f.Type {
	case TypeVerdict:
		if ch, ok := c.waiting[f.Seq]; ok {
			delete(c.waiting, f.Seq)
			ch <- f
		}
	case TypeRelease:
		if ch, ok := c.released[f.Seq]; ok {
			delete(c.released, f.Seq)
			ch <- f
		}
	}
}
