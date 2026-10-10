package daemon

import (
	"context"
	"strconv"
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
	// AuditPendingEvicted is audited when the pending-request cap dropped
	// the oldest requests (Reason is how many); their replies no longer
	// correlate.
	AuditPendingEvicted = "pending_evicted"
)

// maxPending caps the pending requests of one session, so an agent that
// never lets requests complete cannot grow roverd's memory without bound.
// A var so tests can lower it.
var maxPending = 10_000

type pendingKey struct {
	key string
	seq uint64
}

// addPending stores p under key and evicts the oldest entries beyond
// maxPending, returning how many. Callers hold s.mu.
func (s *Session) addPending(key string, p pendingReq) (evicted int) {
	s.nextSeq++
	p.seq = s.nextSeq
	s.pending[key] = p
	s.order = append(s.order, pendingKey{key: key, seq: p.seq})
	for len(s.pending) > maxPending && len(s.order) > 0 {
		k := s.order[0]
		s.order = s.order[1:]
		if cur, ok := s.pending[k.key]; ok && cur.seq == k.seq {
			delete(s.pending, k.key)
			evicted++
		}
	}
	// order keeps keys of answered requests until they reach the front;
	// compact it so it stays proportional to pending.
	if len(s.order) > 2*maxPending+64 {
		live := s.order[:0:0]
		for _, k := range s.order {
			if cur, ok := s.pending[k.key]; ok && cur.seq == k.seq {
				live = append(live, k)
			}
		}
		s.order = live
	}
	return evicted
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

// evictedEntries is the audit note for requests the pending cap dropped.
func evictedEntries(sess *Session, now time.Time, n int) []audit.Entry {
	if n == 0 {
		return nil
	}
	return []audit.Entry{sessionEntry(sess, now, AuditPendingEvicted, strconv.Itoa(n))}
}
