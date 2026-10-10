package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// closeTimeout bounds the wait for in-flight requests and the DELETE.
const closeTimeout = 10 * time.Second

// RemoteErrorCode is the JSON-RPC error code of a reply the bridge makes up
// when the remote could not answer (network, TLS, 401, 404, size cap).
const RemoteErrorCode = -32001

// Conn adapts a Transport to the stdio pumps of internal/proxy: Write takes
// the client->server lines roverd allowed (one whole line per call, which
// is how proxy.Wrapper writes), and FromRemote yields the server->client
// lines for the other pump, which sends each one to roverd before the
// client sees it.
type Conn struct {
	t    *Transport
	ctx  context.Context
	stop context.CancelFunc
	pr   *io.PipeReader
	pw   *io.PipeWriter
	logf func(format string, a ...any)

	wg         sync.WaitGroup // in-flight requests
	listenOnce sync.Once
	listening  chan struct{} // closed when the GET stream goroutine ends
	closeOnce  sync.Once
}

// NewConn starts a bridge connection over t.
func NewConn(ctx context.Context, t *Transport, logf func(format string, a ...any)) *Conn {
	ctx, stop := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	return &Conn{t: t, ctx: ctx, stop: stop, pr: pr, pw: pw, logf: logf, listening: make(chan struct{})}
}

// FromRemote is the reader of messages from the remote, one per line.
func (c *Conn) FromRemote() io.Reader { return c.pr }

// Write sends one line to the remote. The initialize request is POSTed
// synchronously, up to the response headers, so the session id it returns
// is in place before the next message; everything else is sent
// concurrently, because a slow tool call must not hold up the client's
// later messages (a cancel, say). JSON-RPC matches replies by id, so order
// across requests does not matter. Replies are always read in the
// background: they go through a pipe the other pump drains.
func (c *Conn) Write(p []byte) (int, error) {
	line := bytes.Clone(bytes.TrimRight(p, "\r\n"))
	if len(bytes.TrimSpace(line)) == 0 {
		return len(p), nil
	}
	m := jsonrpc.Parse(line)
	c.wg.Add(1)
	if m.Kind == jsonrpc.KindRequest && m.Method == "initialize" {
		ch, err := c.t.Send(c.ctx, line)
		go func() {
			defer c.wg.Done()
			c.collect(m, ch, err)
		}()
		return len(p), nil
	}
	go func() {
		defer c.wg.Done()
		ch, err := c.t.Send(c.ctx, line)
		c.collect(m, ch, err)
	}()
	return len(p), nil
}

// collect forwards the replies to one message and makes sure a request
// gets an answer.
func (c *Conn) collect(m jsonrpc.Message, ch <-chan []byte, err error) {
	if err != nil {
		c.fail(m, err)
		return
	}
	answered := false
	for msg := range ch {
		if r := jsonrpc.Parse(msg); m.Kind == jsonrpc.KindRequest && (r.Kind == jsonrpc.KindResult || r.Kind == jsonrpc.KindError) && bytes.Equal(r.ID, m.ID) {
			answered = true
		}
		c.emit(msg)
	}
	if m.Kind == jsonrpc.KindRequest && !answered && c.ctx.Err() == nil {
		c.fail(m, errors.New("the remote closed the stream without answering"))
		return
	}
	if m.Kind == jsonrpc.KindRequest && m.Method == "initialize" && answered {
		// Server-initiated messages (2025-11-25) come on a GET stream,
		// opened once the session exists.
		c.listenOnce.Do(func() {
			go func() {
				defer close(c.listening)
				for msg := range c.t.Listen(c.ctx) {
					c.emit(msg)
				}
			}()
		})
	}
}

// emit hands one remote message to the server->client pump.
func (c *Conn) emit(msg []byte) {
	if _, err := c.pw.Write(append(bytes.Clone(msg), '\n')); err != nil && c.ctx.Err() == nil {
		c.logf("dropping a remote message: %v", err)
	}
}

// fail answers a request the remote could not answer with a JSON-RPC error,
// sent through the server->client pump (so roverd sees it too). A failed
// notification or response is only logged: nobody waits for it.
func (c *Conn) fail(m jsonrpc.Message, err error) {
	c.logf("remote: %s %s: %v", m.Kind, sanitize(m.Method), err)
	if m.Kind != jsonrpc.KindRequest {
		return
	}
	reply, merr := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: m.ID, Error: struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{RemoteErrorCode, "rover bridge: " + err.Error()}})
	if merr != nil {
		c.logf("building an error reply: %v", merr)
		return
	}
	c.emit(reply)
}

// Close waits (bounded) for in-flight requests, ends the remote session
// with DELETE, stops the GET stream and closes FromRemote.
func (c *Conn) Close() {
	c.closeOnce.Do(func() {
		done := make(chan struct{})
		go func() { c.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(closeTimeout):
			c.logf("closing with requests still in flight")
		}
		c.stop()
		started := true
		c.listenOnce.Do(func() { started = false })
		if started {
			select {
			case <-c.listening:
			case <-time.After(closeTimeout):
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
		defer cancel()
		c.t.Close(ctx)
		_ = c.pw.Close()
	})
}
