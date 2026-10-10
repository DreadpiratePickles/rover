package daemon

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/DreadpiratePickles/rover/internal/framing"
	"github.com/DreadpiratePickles/rover/internal/ipc"
)

// conn is roverd's end of one wrapper connection. Verdicts (from the
// connection's goroutine), releases and injects (from approvals) all go
// through send, one frame at a time.
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
