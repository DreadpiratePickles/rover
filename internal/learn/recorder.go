package learn

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/cedar-policy/cedar-go/types"
	bolt "go.etcd.io/bbolt"

	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
	"github.com/DreadpiratePickles/rover/internal/state"
)

// Batching and size limits of the recorder.
const (
	// FlushEvery is how often queued observations are written.
	FlushEvery = 500 * time.Millisecond
	// BatchSize queued observations trigger a write before the tick.
	BatchSize = 256
	// DefaultCap is the most observations the bucket keeps; above it the
	// oldest are dropped (down to 90% of the cap, so trimming is rare).
	DefaultCap = 50000
	// maxQueue bounds memory if bbolt keeps failing: later records are
	// dropped. Losing learning data only makes a proposal smaller (it can
	// never permit more), so dropping is the safe direction.
	maxQueue = 16 * BatchSize
)

// Pending is one call to record, as roverd's decide knows it. The shape is
// computed later, in the recorder's goroutine, so decide does no more work
// than appending to a slice.
type Pending struct {
	TS                   time.Time
	Client, Server, Tool string
	Action               string
	Rules                normalize.Rules
	Args, Norm           types.Record   // tools/call
	Shape                map[string]Arg // set directly for resources/read
	Flagged              []string
}

type entry struct {
	key     string
	p       Pending
	encoded bool // written in the flush under way: later flags go to late
}

// Recorder queues observations in memory and writes them to the
// observations bucket from one goroutine (Run): every FlushEvery, or as soon
// as BatchSize are queued, in a single bbolt transaction. Record and Flag
// never touch bbolt, so roverd's decide stays within its time budget.
type Recorder struct {
	db   *state.DB
	logf func(string, ...any)
	cap  int

	mu        sync.Mutex
	queue     []*entry
	byKey     map[string]*entry
	late      map[string][]string // flags for observations already written
	seq       uint64
	closed    bool
	started   bool
	dropWarn  bool
	capWarned bool
	count     int // observations in the bucket; -1 until counted
	bytes     int // bytes of keys and values in the bucket
	maxBytes  int

	flushMu    sync.Mutex // one flush at a time (Run and Flush)
	kick       chan struct{}
	stop       chan struct{}
	done       chan struct{}
	afterFlush func() // tests
}

// NewRecorder returns a recorder writing to db. Call Run in a goroutine and
// Close on shutdown.
func NewRecorder(db *state.DB, logf func(string, ...any)) *Recorder {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Recorder{
		db: db, logf: logf, cap: DefaultCap, maxBytes: MaxBucketBytes, byKey: map[string]*entry{}, late: map[string][]string{}, count: -1,
		kick: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
	}
}

// Record queues p and returns its key, for Flag. It returns "" when the
// recorder is closed or its queue is full.
func (r *Recorder) Record(p Pending) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ""
	}
	if len(r.queue) >= maxQueue {
		if !r.dropWarn {
			r.dropWarn = true
			r.logf("learn: observation queue full (%d); dropping new observations until a write succeeds", maxQueue)
		}
		return ""
	}
	r.seq++
	e := &entry{key: string(Key(p.Client, p.Server, p.Tool, p.TS, r.seq)), p: p}
	r.queue = append(r.queue, e)
	r.byKey[e.key] = e
	if len(r.queue) >= BatchSize {
		select {
		case r.kick <- struct{}{}:
		default:
		}
	}
	return e.key
}

// Flag adds flags to the observation with key, queued or already written.
// A flag on a result marks the request's observation this way.
func (r *Recorder) Flag(key string, flags ...string) {
	if key == "" || len(flags) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.byKey[key]; ok && !e.encoded {
		e.p.Flagged = mergeFlags(e.p.Flagged, flags)
		return
	}
	r.late[key] = mergeFlags(r.late[key], flags)
}

// Start runs the writer goroutine: it writes queued observations on every
// tick and every full batch until Close. tick is a time.Ticker's channel in
// roverd and a test's channel in tests (injected clock).
func (r *Recorder) Start(tick <-chan time.Time) {
	r.mu.Lock()
	r.started = true
	r.mu.Unlock()
	go r.run(tick)
}

func (r *Recorder) run(tick <-chan time.Time) {
	defer close(r.done)
	for {
		select {
		case <-r.stop:
			return
		case <-tick:
		case <-r.kick:
		}
		if err := r.Flush(); err != nil {
			r.logf("learn: writing observations failed (kept in memory, retried): %v", err)
		}
	}
}

// Close stops the writer goroutine and writes whatever is queued. Record
// after Close is a no-op.
func (r *Recorder) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	started := r.started
	r.mu.Unlock()
	close(r.stop)
	if started {
		<-r.done
	}
	return r.Flush()
}

// Flush writes the queue and pending late flags in one transaction. On
// failure everything stays queued for the next attempt.
func (r *Recorder) Flush() error {
	r.flushMu.Lock()
	defer r.flushMu.Unlock()
	r.mu.Lock()
	batch, late := r.queue, r.late
	r.queue, r.late = nil, map[string][]string{}
	count, size := r.count, r.bytes
	r.mu.Unlock()
	if len(batch) == 0 && len(late) == 0 {
		return nil
	}
	// Shapes are computed outside the lock: Record keeps going meanwhile.
	// A flag for a batch entry is merged into it until encode reads it;
	// after that it goes to late and is applied by the next flush.
	trimmed := 0
	err := r.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(state.BucketObservations)
		if b == nil {
			return fmt.Errorf("bucket %s missing", state.BucketObservations)
		}
		if count < 0 {
			count, size = 0, 0
			if err := b.ForEach(func(k, v []byte) error { count, size = count+1, size+len(k)+len(v); return nil }); err != nil {
				return err
			}
		}
		for _, e := range batch {
			v, err := r.encode(e)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(e.key), v); err != nil {
				return err
			}
			count, size = count+1, size+len(e.key)+len(v)
		}
		delta, err := applyLate(b, late)
		if err != nil {
			return err
		}
		size += delta
		if count > r.cap || size > r.maxBytes {
			n, freed, err := trimOldest(b, count-r.cap*9/10, size-r.maxBytes*9/10)
			if err != nil {
				return err
			}
			count, size, trimmed = count-n, size-freed, n
		}
		return nil
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		for _, e := range batch {
			e.encoded = false
		}
		r.queue = append(batch, r.queue...)
		for k, f := range late {
			r.late[k] = mergeFlags(r.late[k], f)
		}
		return err
	}
	for _, e := range batch {
		delete(r.byKey, e.key)
	}
	r.count, r.bytes, r.dropWarn = count, size, false
	if trimmed > 0 && !r.capWarned {
		r.capWarned = true
		r.logf("learn: the observations bucket reached its cap (%d entries or %d bytes); dropped the %d oldest (logged once)", r.cap, r.maxBytes, trimmed)
	}
	if r.afterFlush != nil {
		r.afterFlush()
	}
	return nil
}

// encode builds the stored JSON of one queued entry.
func (r *Recorder) encode(e *entry) ([]byte, error) {
	r.mu.Lock()
	e.encoded = true
	p := e.p
	p.Flagged = append([]string(nil), p.Flagged...)
	r.mu.Unlock()
	shape := p.Shape
	if shape == nil && p.Action == ActionCall {
		shape = Shape(p.Rules, p.Args, p.Norm)
	}
	return json.Marshal(capObservation(Observation{
		TS: p.TS.UTC(), Client: p.Client, Server: p.Server, Tool: p.Tool, Action: p.Action,
		Shape: shape, Flagged: p.Flagged,
	}))
}

// applyLate merges flags into observations already in the bucket and
// returns the change in bytes. A key that is gone (trimmed) is skipped.
func applyLate(b *bolt.Bucket, late map[string][]string) (int, error) {
	delta := 0
	for k, flags := range late {
		v := b.Get([]byte(k))
		if v == nil {
			continue
		}
		var o Observation
		if err := json.Unmarshal(v, &o); err != nil {
			return 0, fmt.Errorf("observation %q: %w", k, err)
		}
		o.Flagged = mergeFlags(o.Flagged, flags)
		nv, err := json.Marshal(o)
		if err != nil {
			return 0, err
		}
		delta += len(nv) - len(v)
		if err := b.Put([]byte(k), nv); err != nil {
			return 0, err
		}
	}
	return delta, nil
}

// trimOldest deletes the oldest observations (by the time in their key)
// until at least n are gone and at least minBytes are freed. It returns how
// many it deleted and the bytes freed.
func trimOldest(b *bolt.Bucket, n, minBytes int) (deleted, freed int, err error) {
	type kt struct {
		k    []byte
		t    uint64
		size int
	}
	var all []kt
	if err := b.ForEach(func(k, v []byte) error {
		all = append(all, kt{append([]byte(nil), k...), keyTime(k), len(k) + len(v)})
		return nil
	}); err != nil {
		return 0, 0, err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t < all[j].t })
	for _, e := range all {
		if deleted >= n && freed >= minBytes {
			break
		}
		if err := b.Delete(e.k); err != nil {
			return 0, 0, err
		}
		deleted, freed = deleted+1, freed+e.size
	}
	return deleted, freed, nil
}

// mergeFlags returns the sorted union of a and b.
func mergeFlags(a, b []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string(nil), a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
