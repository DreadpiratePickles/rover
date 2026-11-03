package oauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// LESSON (M11): the browser hands the authorization code back to Rover by
// visiting http://127.0.0.1:<random port>/callback. Anything on this
// machine can visit that URL too, so the page takes exactly one code,
// only with the state value Rover generated for this login (a guess or a
// replay gets 400 and is ignored), and then stops accepting. The code alone
// is useless anyway without the PKCE verifier that never left Rover.

// callbackPath is the redirect path on the loopback server.
const callbackPath = "/callback"

// donePage is the one page the loopback server shows, in the cwm style of
// plan §4.7: black on white, bold 14px sans-serif, one 1-pixel box, no
// scripts, nothing to click.
const donePage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>rover</title>` +
	`<style>body{background:#fff;color:#000;font:bold 14px sans-serif;margin:0}` +
	`p{display:inline-block;border:1px solid #000;margin:8px;padding:0 2px}</style></head>` +
	`<body><p>%s</p></body></html>`

// callback is what the browser brought back.
type callback struct {
	code, iss string
	err       error
}

// loopback is the one-shot redirect receiver.
type loopback struct {
	srv      *http.Server
	ln       net.Listener
	state    string
	result   chan callback
	mu       sync.Mutex
	finished bool
}

// startLoopback listens on 127.0.0.1 on a random port.
func startLoopback(state string) (*loopback, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	l := &loopback{ln: ln, state: state, result: make(chan callback, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, l.handle)
	l.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = l.srv.Serve(ln) }()
	return l, nil
}

// RedirectURI is the URI registered with and sent to the authorization server.
func (l *loopback) RedirectURI() string {
	return "http://" + l.ln.Addr().String() + callbackPath
}

func (l *loopback) handle(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	h.Set("Referrer-Policy", "no-referrer") // the URL carries the code
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	if r.Method != http.MethodGet {
		page(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	q := r.URL.Query()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.finished {
		page(w, http.StatusGone, "this login is finished")
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(l.state)) != 1 {
		page(w, http.StatusBadRequest, "state mismatch; ignored")
		return
	}
	l.finished = true
	if e := q.Get("error"); e != "" {
		l.result <- callback{iss: q.Get("iss"), err: fmt.Errorf("the authorization server refused: %s", safeCode(e))}
		page(w, http.StatusOK, "login failed; see the terminal")
		return
	}
	if q.Get("code") == "" {
		l.result <- callback{err: errors.New("the redirect carried no code")}
		page(w, http.StatusBadRequest, "login failed; see the terminal")
		return
	}
	l.result <- callback{code: q.Get("code"), iss: q.Get("iss")}
	page(w, http.StatusOK, "you can close this tab")
}

func page(w http.ResponseWriter, code int, text string) {
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, donePage, text) // text is always one of our constants
}

// wait returns the callback, or an error when ctx ends.
func (l *loopback) wait(ctx context.Context) (callback, error) {
	select {
	case c := <-l.result:
		return c, nil
	case <-ctx.Done():
		return callback{}, fmt.Errorf("no answer from the browser: %w", ctx.Err())
	}
}

func (l *loopback) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = l.srv.Shutdown(ctx)
}
