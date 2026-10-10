package bridge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// Reconnect limits for dropped SSE streams.
const (
	maxResume      = 3                // GETs with Last-Event-ID for one POST stream
	maxListenFails = 5                // consecutive failed GETs before Listen gives up
	defaultRetry   = time.Second      // when the server sent no retry field
	maxRetry       = 30 * time.Second // a hostile retry cannot park the bridge for hours
)

// sleep waits d or until ctx ends; tests replace it.
var sleep = func(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func clampRetry(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultRetry
	}
	return min(d, maxRetry)
}

// openGET opens the GET stream, resuming after lastID if set.
func (t *Transport) openGET(ctx context.Context, lastID string) (*http.Response, error) {
	return t.do(ctx, func() (*http.Request, error) {
		req, err := t.newRequest(ctx, http.MethodGet, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "text/event-stream")
		if _, neg := t.state(); neg != "" {
			req.Header.Set(hdrProtocol, neg)
		}
		if lastID != "" {
			req.Header.Set(hdrLastEventID, lastID)
		}
		return req, nil
	})
}

// readStream forwards one SSE body's messages to out. It returns the last
// event id, the last retry, whether the response to req arrived, and why
// the stream ended (io.EOF for a clean end).
func (t *Transport) readStream(ctx context.Context, body io.Reader, lastID string, req jsonrpc.Message, out chan<- []byte) (string, time.Duration, bool, error) {
	r := NewSSEReader(body, t.MaxMessage)
	r.lastID = lastID
	var retry time.Duration
	answered := false
	for {
		ev, err := r.Next()
		if err != nil {
			return r.LastID(), retry, answered, err
		}
		if ev.Retry > 0 {
			retry = ev.Retry
		}
		if ev.Type != "" && ev.Type != "message" || len(bytes.TrimSpace(ev.Data)) == 0 {
			continue // the priming event, or an event type MCP does not use
		}
		msg, err := oneLine(ev.Data)
		if err != nil {
			t.Logf("dropping an SSE event: %v", err)
			continue
		}
		if req.Kind == jsonrpc.KindRequest {
			if m := jsonrpc.Parse(msg); (m.Kind == jsonrpc.KindResult || m.Kind == jsonrpc.KindError) && bytes.Equal(m.ID, req.ID) {
				answered = true
				t.noteInitialize(req, msg)
			}
		}
		select {
		case out <- msg:
		case <-ctx.Done():
			return r.LastID(), retry, answered, ctx.Err()
		}
	}
}

// pumpPOSTStream reads the SSE answer to one POST. If it drops before the
// response arrives and the server gave event ids, it resumes with GET and
// Last-Event-ID (2025-11-25 resumability), a bounded number of times.
func (t *Transport) pumpPOSTStream(ctx context.Context, resp *http.Response, req jsonrpc.Message, out chan<- []byte) {
	defer close(out)
	lastID, retry, answered, err := t.readStream(ctx, resp.Body, "", req, out)
	_ = resp.Body.Close()
	for attempt := 0; !answered && req.Kind == jsonrpc.KindRequest && lastID != "" && attempt < maxResume; attempt++ {
		if ctx.Err() != nil || errors.Is(err, ErrTooLarge) {
			break
		}
		if !sleep(ctx, clampRetry(retry)) {
			return
		}
		r, gerr := t.openGET(ctx, lastID)
		if gerr != nil {
			err = gerr
			continue
		}
		if r.StatusCode != http.StatusOK || mediaType(r) != "text/event-stream" {
			drain(r)
			t.Logf("resuming the stream after event %q: remote answered HTTP %d", sanitize(lastID), r.StatusCode)
			return
		}
		lastID, retry, answered, err = t.readStream(ctx, r.Body, lastID, req, out)
		_ = r.Body.Close()
	}
	if err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
		t.Logf("remote stream ended: %v", err)
	}
}

// Listen opens the GET stream for server-initiated messages (2025-11-25)
// and keeps it open, reconnecting with Last-Event-ID, until ctx ends. A
// server that answers 405 offers no such stream (every 2026-07-28 server):
// the channel is then simply closed.
func (t *Transport) Listen(ctx context.Context) <-chan []byte {
	out := make(chan []byte, 8)
	go func() {
		defer close(out)
		lastID, retry, fails := "", time.Duration(0), 0
		for ctx.Err() == nil && fails < maxListenFails {
			resp, err := t.openGET(ctx, lastID)
			if err != nil {
				fails++
				t.Logf("GET stream: %v", err)
				if !sleep(ctx, min(clampRetry(retry)<<fails, maxRetry)) {
					return
				}
				continue
			}
			if resp.StatusCode == http.StatusMethodNotAllowed {
				drain(resp)
				t.Logf("remote offers no GET stream (405)")
				return
			}
			if resp.StatusCode != http.StatusOK || mediaType(resp) != "text/event-stream" {
				drain(resp)
				t.Logf("GET stream: remote answered HTTP %d; not listening", resp.StatusCode)
				return
			}
			fails = 0
			var serr error
			lastID, retry, _, serr = t.readStream(ctx, resp.Body, lastID, jsonrpc.Message{}, out)
			_ = resp.Body.Close()
			if errors.Is(serr, ErrTooLarge) {
				t.Logf("GET stream: %v; not listening", serr)
				return
			}
			if !sleep(ctx, clampRetry(retry)) {
				return
			}
		}
	}()
	return out
}
