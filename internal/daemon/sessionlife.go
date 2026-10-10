package daemon

import (
	"context"
	"strings"
	"time"

	"github.com/DreadpiratePickles/rover/internal/audit"
)

// Session lifetime (M8, review MEDIUM-3 and LOW-4).
//
// LESSON (M8): taint is only as durable as the session that holds it. If
// a session ended when its last wrapper exited, an agent (or an injection
// steering it) could read your secrets, have its client restart the MCP
// servers, and egress from a clean session. So a session outlives its
// wrappers while the agent process lives, for at most LingerMax, and a
// wrapper that comes back under the same pid inherits its flags.

const (
	// LingerMax bounds how long a session with no wrapper is kept.
	LingerMax = time.Hour
	// LingerPoll is how often lingering sessions are checked.
	LingerPoll = 5 * time.Second

	// AuditKindSession marks session lifecycle entries in the audit log.
	AuditKindSession = "session"
	// AuditSessionLingering is audited when the last wrapper left; the flags are kept.
	AuditSessionLingering = "session_lingering"
	// AuditSessionExpired is audited when a lingering session is dropped.
	AuditSessionExpired = "session_expired"
	// AuditPendingEvicted is audited for each request the pending cap
	// dropped (Reason: a forwarded call's labels); its reply no longer
	// correlates.
	AuditPendingEvicted = "pending_evicted"
)

// Pending-request caps, per server AND direction (re-verification of
// LOW-4): a server flooding server->client requests can only evict its own
// requests, never the agent's forwarded calls, whose results set the
// session flags. Vars so tests can lower them.
var (
	maxPendingS2C = 5_000  // server->client requests per server
	maxPendingC2S = 10_000 // agent->server requests per server
)

type pendingKey struct {
	key string
	seq uint64
}

// evictedReq is a pending request the cap dropped, for the audit log.
type evictedReq struct {
	server, dir string
	p           pendingReq
}

func pendingCap(dir string) int {
	if dir == "s2c" {
		return maxPendingS2C
	}
	return maxPendingC2S
}

// addPending stores p under server/dir/key and evicts the oldest entries of
// that server and direction beyond its cap. An evicted agent->server call
// still counts its reads_untrusted label (its result may yet reach the
// agent, uncorrelated); its reads_private label does not, because no
// success was seen. Callers hold s.mu.
func (s *Session) addPending(server, dir, key string, p pendingReq) (evicted []evictedReq) {
	bucket := server + ":" + dir
	s.nextSeq++
	p.seq, p.bucket = s.nextSeq, bucket
	if _, dup := s.pending[key]; !dup {
		s.counts[bucket]++
	}
	s.pending[key] = p
	s.orders[bucket] = append(s.orders[bucket], pendingKey{key: key, seq: p.seq})
	limit := pendingCap(dir)
	for s.counts[bucket] > limit && len(s.orders[bucket]) > 0 {
		k := s.orders[bucket][0]
		s.orders[bucket] = s.orders[bucket][1:]
		if cur, ok := s.pending[k.key]; ok && cur.seq == k.seq {
			s.dropPending(k.key)
			if cur.call {
				s.flags = AfterResult(s.flags, cur.labels, true)
			}
			evicted = append(evicted, evictedReq{server: server, dir: dir, p: cur})
		}
	}
	// The queue keeps keys of answered requests until they reach the front;
	// compact it so it stays proportional to the live entries.
	if q := s.orders[bucket]; len(q) > 2*limit+64 {
		live := q[:0:0]
		for _, k := range q {
			if cur, ok := s.pending[k.key]; ok && cur.seq == k.seq {
				live = append(live, k)
			}
		}
		s.orders[bucket] = live
	}
	return evicted
}

// dropPending removes one pending entry and returns it. Callers hold s.mu.
func (s *Session) dropPending(key string) (pendingReq, bool) {
	p, ok := s.pending[key]
	if ok {
		delete(s.pending, key)
		s.counts[p.bucket]--
	}
	return p, ok
}

// pendingCount is the number of requests awaiting a reply.
func (s *Session) pendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// Lingering reports whether no wrapper is attached (the session is kept
// for its flags).
func (s *Session) Lingering() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.lingerSince.IsZero()
}

func (s *Session) startLinger(now time.Time) {
	s.mu.Lock()
	s.lingerSince = now
	s.mu.Unlock()
}

// rejoin ends lingering; it reports whether the session was lingering.
func (s *Session) rejoin() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	was := !s.lingerSince.IsZero()
	s.lingerSince = time.Time{}
	return was
}

// expiry says why a lingering session should go, or "".
func (s *Server) expiry(sess *Session, now time.Time) string {
	sess.mu.Lock()
	since := sess.lingerSince
	sess.mu.Unlock()
	switch {
	case since.IsZero():
		return ""
	case !s.o.PIDAlive(sess.ClientPID):
		return "client pid gone"
	case now.Sub(since) >= LingerMax:
		return "linger limit"
	}
	return ""
}

// startSweeper runs sweepSessions every LingerPoll until ctx ends.
func (s *Server) startSweeper(ctx context.Context) {
	t := time.NewTicker(LingerPoll)
	go func() {
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.sweepSessions()
			}
		}
	}()
}

// sweepSessions drops lingering sessions whose agent is gone or whose
// LingerMax passed, and audits each. Serve runs it every LingerPoll; the
// times come from the injected clock.
func (s *Server) sweepSessions() {
	now := s.o.Now()
	var expired []audit.Entry
	s.mu.Lock()
	for pid, sess := range s.sessions {
		if why := s.expiry(sess, now); why != "" {
			delete(s.sessions, pid)
			expired = append(expired, sessionEntry(sess, now, AuditSessionExpired, why))
		}
	}
	s.mu.Unlock()
	for _, e := range expired {
		s.o.Logf("session %s: closed (%s)", e.Session, e.Reason)
		_ = s.writeAudit(e)
	}
}

func sessionEntry(sess *Session, now time.Time, action, reason string) audit.Entry {
	return audit.Entry{Time: now.UTC(), Session: sess.ID, Kind: AuditKindSession, Action: action, Reason: reason}
}

// evictedEntries audits each request the pending cap dropped, with the
// labels of a forwarded call.
func evictedEntries(sess *Session, now time.Time, ev []evictedReq) []audit.Entry {
	out := make([]audit.Entry, 0, len(ev))
	for _, x := range ev {
		e := sessionEntry(sess, now, AuditPendingEvicted, "not a forwarded call ("+x.p.method+")")
		e.Server, e.Dir, e.Tool = x.server, x.dir, x.p.tool
		if x.p.call {
			ls := "none"
			if len(x.p.labels) > 0 {
				ls = strings.Join(x.p.labels, ",")
			}
			e.Reason = "labels: " + ls
		}
		out = append(out, e)
	}
	return out
}
