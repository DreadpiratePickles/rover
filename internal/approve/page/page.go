// Package page is the read-only approval details page (plan M9 Flow 3,
// §4.7): a tiny HTTP server on 127.0.0.1 that shows one approval to whoever
// holds its link, and can do nothing else.
//
// LESSON (M9): everything an agent can reach, it can click. A local web
// page with an "Approve" button is one curl away from the agent's shell
// tool, so this page has no button, no form, no POST handler and no
// JavaScript. It answers exactly one request shape:
//
//	GET /approval/<id>?t=<128-bit token>
//
// Any other method is 405 and any other path is 404. A wrong token is also
// 404, not 403: a 403 would tell a guesser "this id exists, keep trying the
// token". The token is compared in constant time, so response timing does
// not leak how many leading digits were right. Requests whose Host header
// is not the listener's own address are refused too, which stops a web
// page in the user's browser from reading this one through DNS rebinding.
package page

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
)

// Lookup reads approval records (approve.Store implements it).
type Lookup interface {
	Get(id string) (approve.Record, bool, error)
}

// maxTokens bounds how many links the page remembers (oldest dropped).
const maxTokens = 1024

// Server is the details page.
type Server struct {
	records  Lookup
	showArgs atomic.Bool
	now      func() time.Time

	mu    sync.Mutex
	links map[string]link // by approval id
	order []string
	host  string // "127.0.0.1:<port>" once listening
	srv   *http.Server
}

type link struct {
	token string
	shown bool   // approvals.show_args was on when the link was made
	args  []byte // only when shown; kept in memory, never on disk
}

// New returns a page over records. showArgs is approvals.show_args.
func New(records Lookup, showArgs bool) *Server {
	s := &Server{records: records, now: time.Now, links: map[string]link{}}
	s.showArgs.Store(showArgs)
	return s
}

// SetShowArgs changes approvals.show_args for approvals registered from
// now on (roverd calls it on reload).
func (s *Server) SetShowArgs(on bool) { s.showArgs.Store(on) }

// Start listens on 127.0.0.1 with a random port and serves in the
// background.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.host = ln.Addr().String()
	s.srv = &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	srv := s.srv
	s.mu.Unlock()
	go func() { _ = srv.Serve(ln) }()
	return nil
}

// SetHost is the address the page answers for (tests serving with
// httptest call it; Start sets it).
func (s *Server) SetHost(host string) {
	s.mu.Lock()
	s.host = host
	s.mu.Unlock()
}

// Close stops the server.
func (s *Server) Close() error {
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Close()
}

// Register implements approve.Pages: it makes a fresh token for r and
// returns the link.
func (s *Server) Register(r approve.Request) (string, error) {
	if !approve.ValidID(r.ID) {
		return "", errors.New("page: bad approval id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.host == "" {
		return "", errors.New("page: not listening")
	}
	l := link{token: approve.NewToken()}
	if l.shown = s.showArgs.Load(); l.shown {
		l.args = append([]byte(nil), r.Args...)
	}
	if _, exists := s.links[r.ID]; !exists {
		s.order = append(s.order, r.ID)
	}
	s.links[r.ID] = l
	for len(s.order) > maxTokens {
		delete(s.links, s.order[0])
		s.order = s.order[1:]
	}
	return fmt.Sprintf("http://%s/approval/%s?t=%s", s.host, r.ID, l.token), nil
}

// ServeHTTP answers GET /approval/<id>?t=<token> and nothing else.
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	if req.Method != http.MethodGet {
		h.Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, ok := strings.CutPrefix(req.URL.Path, "/approval/")
	if !ok || !approve.ValidID(id) || req.URL.RawPath != "" {
		http.NotFound(w, req)
		return
	}
	s.mu.Lock()
	l, known := s.links[id]
	host := s.host
	s.mu.Unlock()
	q := req.URL.Query()
	tok := q.Get("t")
	// Compare even when the id is unknown, so timing does not say which.
	want := l.token
	if !known {
		want = strings.Repeat("0", 32)
	}
	good := subtle.ConstantTimeCompare([]byte(tok), []byte(want)) == 1
	if !known || !good || len(q) != 1 || len(q["t"]) != 1 || req.Host != host {
		http.NotFound(w, req)
		return
	}
	rec, found, err := s.records.Get(id)
	if err != nil || !found {
		http.NotFound(w, req)
		return
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, s.view(rec, l)); err != nil {
		return // headers are out; nothing more to say
	}
}
