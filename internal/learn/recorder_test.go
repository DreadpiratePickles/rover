package learn

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cedar-policy/cedar-go/types"
	bolt "go.etcd.io/bbolt"

	"github.com/DreadpiratePickles/rover/internal/state"
)

// testRecorder is a recorder on a fresh database whose ticks the test
// sends (injected clock) and whose flushes it can wait for.
type testRecorder struct {
	*Recorder
	db      *state.DB
	tick    chan time.Time
	flushed chan struct{}
	logs    *strings.Builder
	mu      *sync.Mutex
}

func newTestRecorder(t *testing.T) testRecorder {
	t.Helper()
	db, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	tr := testRecorder{db: db, tick: make(chan time.Time), flushed: make(chan struct{}, 64), logs: &strings.Builder{}, mu: &sync.Mutex{}}
	tr.Recorder = NewRecorder(db, func(f string, a ...any) {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		fmt.Fprintf(tr.logs, f+"\n", a...)
	})
	tr.afterFlush = func() { tr.flushed <- struct{}{} }
	return tr
}

var t0 = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

func call(i int) Pending {
	return Pending{TS: t0.Add(time.Duration(i) * time.Second), Client: "agent", Server: "files", Tool: "read_file",
		Action: ActionCall, Args: types.NewRecord(types.RecordMap{"mode": types.String("ro")})}
}

func stored(t *testing.T, db *state.DB) []Observation {
	t.Helper()
	obs, err := Load(db)
	if err != nil {
		t.Fatal(err)
	}
	return obs
}

func (tr testRecorder) waitFlush(t *testing.T) {
	t.Helper()
	select {
	case <-tr.flushed:
	case <-time.After(5 * time.Second):
		t.Fatal("no flush")
	}
}

func TestRecorderWritesOnTick(t *testing.T) {
	// Arrange
	tr := newTestRecorder(t)
	tr.Start(tr.tick)
	defer func() { _ = tr.Close() }()

	// Act
	for i := 0; i < 3; i++ {
		tr.Record(call(i))
	}

	// Assert: nothing reaches bbolt before the tick, everything after it.
	if n := len(stored(t, tr.db)); n != 0 {
		t.Fatalf("%d observations written before the tick", n)
	}
	tr.tick <- t0
	tr.waitFlush(t)
	obs := stored(t, tr.db)
	if len(obs) != 3 || obs[0].Shape["mode"].Value != "ro" || !obs[0].TS.Equal(t0) || obs[2].TS.Before(obs[1].TS) {
		t.Fatalf("%+v", obs)
	}
}

func TestRecorderWritesFullBatchWithoutTick(t *testing.T) {
	tr := newTestRecorder(t)
	tr.Start(tr.tick)
	defer func() { _ = tr.Close() }()
	for i := 0; i < BatchSize-1; i++ {
		tr.Record(call(i))
	}
	select {
	case <-tr.flushed:
		t.Fatal("flushed before the batch was full")
	case <-time.After(50 * time.Millisecond):
	}
	tr.Record(call(BatchSize))
	tr.waitFlush(t)
	if n := len(stored(t, tr.db)); n != BatchSize {
		t.Fatalf("%d written, want %d", n, BatchSize)
	}
}

func TestRecorderFlushesOnClose(t *testing.T) {
	tr := newTestRecorder(t)
	tr.Start(tr.tick)
	tr.Record(call(1))
	tr.Record(call(2))
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	if n := len(stored(t, tr.db)); n != 2 {
		t.Fatalf("%d written on close, want 2", n)
	}
	if k := tr.Record(call(3)); k != "" {
		t.Fatal("Record after Close must be a no-op")
	}
}

func TestRecorderCapDropsOldestAndLogsOnce(t *testing.T) {
	// Arrange
	tr := newTestRecorder(t)
	tr.cap = 10

	// Act: 12 observations, then 12 more.
	for round := 0; round < 2; round++ {
		for i := 0; i < 12; i++ {
			tr.Record(call(round*100 + i))
		}
		if err := tr.Flush(); err != nil {
			t.Fatal(err)
		}
	}

	// Assert: never more than the cap; the newest are kept.
	obs := stored(t, tr.db)
	if len(obs) > 10 || len(obs) < 9 {
		t.Fatalf("%d observations kept, cap 10", len(obs))
	}
	if !obs[len(obs)-1].TS.Equal(call(111).TS) || obs[0].TS.Before(call(100).TS) {
		t.Fatalf("oldest not dropped: first %v last %v", obs[0].TS, obs[len(obs)-1].TS)
	}
	if n := strings.Count(tr.logs.String(), "dropped the"); n != 1 {
		t.Fatalf("cap logged %d times:\n%s", n, tr.logs.String())
	}
}

func TestRecorderFlagsQueuedAndWrittenObservations(t *testing.T) {
	// Arrange
	tr := newTestRecorder(t)
	queued := tr.Record(call(1))
	written := tr.Record(call(2))
	tr.Record(call(3))

	// Act: one flag while queued, one after the write (a result that
	// arrives after the flush).
	tr.Flag(queued, "instruction_phrase")
	if err := tr.Flush(); err != nil {
		t.Fatal(err)
	}
	tr.Flag(written, FlagPinMismatch)
	tr.Flag(written, "instruction_phrase", FlagPinMismatch)
	if err := tr.Flush(); err != nil {
		t.Fatal(err)
	}

	// Assert
	obs := stored(t, tr.db)
	got := []string{strings.Join(obs[0].Flagged, ","), strings.Join(obs[1].Flagged, ","), strings.Join(obs[2].Flagged, ",")}
	want := []string{"instruction_phrase", "instruction_phrase,pin_mismatch", ""}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("flags %q, want %q", got, want)
	}
}

// M3 (independent verification): every size is bounded.
func TestObservationSizeCaps(t *testing.T) {
	// Arrange: 100 arguments with 200-byte names, and three 3000-byte paths.
	args := types.RecordMap{}
	for i := 0; i < 100; i++ {
		args[types.String(fmt.Sprintf("%03d%s", i, strings.Repeat("n", 197)))] = types.Long(1)
	}
	shape := Shape(nil, types.NewRecord(args), types.NewRecord(nil))
	for n := range shape {
		if len(n) > MaxArgName {
			t.Fatalf("argument name of %d bytes kept", len(n))
		}
	}
	big := map[string]Arg{}
	for _, n := range []string{"a", "b", "c"} {
		big[n] = Arg{Type: "path", Value: "/" + strings.Repeat(n, 3000)}
	}

	// Act
	short := map[string]Arg{}
	for i := 0; i < 100; i++ {
		short[fmt.Sprintf("a%03d", i)] = Arg{Type: "number"}
	}
	many := capObservation(Observation{Server: "s", Shape: short})
	long := capObservation(Observation{Server: "s", Shape: shape})
	huge := capObservation(Observation{Server: "s", Shape: big, Client: strings.Repeat("c", 10000)})

	// Assert
	if len(many.Shape) != MaxArgs || many.DroppedArgs != 100-MaxArgs {
		t.Fatalf("%d args kept, %d dropped", len(many.Shape), many.DroppedArgs)
	}
	for _, o := range []Observation{many, long, huge} {
		if b, _ := json.Marshal(o); len(b) > MaxObservationBytes {
			t.Fatalf("encoded observation of %d bytes", len(b))
		}
	}
	if huge.DroppedArgs < 2 || len(huge.Client) > maxKeyPart {
		t.Fatalf("huge: %d dropped, client %d bytes", huge.DroppedArgs, len(huge.Client))
	}
}

func TestRecorderBucketByteCap(t *testing.T) {
	tr := newTestRecorder(t)
	tr.maxBytes = 64 << 10
	for i := 0; i < 100; i++ {
		p := call(i)
		p.Shape = map[string]Arg{"path": {Type: "path", Value: "/" + strings.Repeat("x", 3000)}}
		p.Action = ActionRead // Shape is used as given
		tr.Record(p)
	}
	if err := tr.Flush(); err != nil {
		t.Fatal(err)
	}
	var total int
	_ = tr.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(state.BucketObservations).ForEach(func(k, v []byte) error { total += len(k) + len(v); return nil })
	})
	if total > 64<<10 || total == 0 {
		t.Fatalf("bucket holds %d bytes, cap %d", total, 64<<10)
	}
	if obs := stored(t, tr.db); !obs[len(obs)-1].TS.Equal(call(99).TS) {
		t.Fatal("the newest observation must be kept")
	}
}

func TestLoadNewestFirstWithinBudget(t *testing.T) {
	tr := newTestRecorder(t)
	for i := 0; i < 10; i++ {
		tr.Record(call(i))
	}
	if err := tr.Flush(); err != nil {
		t.Fatal(err)
	}
	one, _ := json.Marshal(Observation{TS: call(0).TS, Client: "agent", Server: "files", Tool: "read_file", Action: ActionCall,
		Shape: map[string]Arg{"mode": {Type: "string", Value: "ro"}}})
	obs, err := loadBudget(tr.db, 3*len(one)+1)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 3 || !obs[0].TS.Equal(call(7).TS) || !obs[2].TS.Equal(call(9).TS) {
		t.Fatalf("got %d: %+v", len(obs), obs)
	}
}
