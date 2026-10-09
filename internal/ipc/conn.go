package ipc

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/DreadpiratePickles/rover/internal/proxy"
)

// Conn frames Messages over a stream connection: one line per message.
// Read must be called from one goroutine at a time; Write is safe to call
// from several (each message goes out in a single Write call).
type Conn struct {
	nc  net.Conn
	r   *bufio.Reader
	wmu sync.Mutex
}

// NewConn wraps an established connection.
func NewConn(nc net.Conn) *Conn {
	return &Conn{nc: nc, r: bufio.NewReaderSize(nc, 64<<10)}
}

// Read returns the next message. It returns io.EOF when the peer closed the
// connection cleanly between messages; a line cut off by EOF, an over-long
// line, or a line that does not decode is a protocol error.
func (c *Conn) Read() (Message, error) {
	line, err := proxy.ReadLine(c.r, MaxLine)
	switch {
	case errors.Is(err, proxy.ErrMessageTooLarge):
		return Message{}, ErrLineTooLarge
	case err == io.EOF && len(line) == 0:
		return Message{}, io.EOF
	case err == io.EOF:
		// ReadLine frames an unterminated last line for us, but on this
		// socket every message must end in "\n": a cut-off line is broken.
		return Message{}, fmt.Errorf("%w: connection closed mid-message", ErrProtocol)
	case err != nil:
		return Message{}, err
	}
	return Decode(line)
}

// Write encodes m and sends it as one line.
func (c *Conn) Write(m Message) error {
	b, err := Encode(m)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err = c.nc.Write(b)
	return err
}

// SetDeadline sets the read and write deadline of the underlying connection.
func (c *Conn) SetDeadline(t time.Time) error { return c.nc.SetDeadline(t) }

// SetReadDeadline sets the read deadline of the underlying connection.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.nc.SetReadDeadline(t) }

// Close closes the underlying connection.
func (c *Conn) Close() error { return c.nc.Close() }
