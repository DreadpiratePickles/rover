// Package learn is Rover's learn mode (plan D6, M6): while roverd runs in
// observe mode it records the SHAPE of every call the policy was asked about,
// and `rover policy propose` (internal/policy/propose) generalises those
// shapes into an allow-list.
//
// LESSON (M6): a shape is not a copy of the call. For an argument a
// normaliser understands, the shape keeps only the fact a policy can use: the
// resolved absolute path (never the text the agent typed), the URL's host,
// the e-mail domain, the shell program, the SQL keyword. Every other argument
// keeps its JSON type only, except an argument with an enum-like name
// (mode, state, format, ...; see literalNames) whose value is a short plain
// word that does not look like a secret (literal.go). A file's contents, a
// message body, a token or a password never reaches the observations bucket.
package learn

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cedar-policy/cedar-go/types"
	bolt "go.etcd.io/bbolt"

	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
	"github.com/DreadpiratePickles/rover/internal/state"
)

// Actions recorded, as JSON-RPC methods.
const (
	ActionCall = "tools/call"
	ActionList = "tools/list"
	ActionRead = "resources/read"
)

// FlagPinMismatch flags a call whose tool's pin did not match; the other
// flags are detection finding ids.
const FlagPinMismatch = "pin_mismatch"

// maxKeyPart bounds each name in a bbolt key (bbolt keys are at most 32 KiB)
// and the client, server and tool names stored in an observation.
const maxKeyPart = 256

// Size caps of one observation (found unbounded by independent verification
// of M6: six 8 MB calls grew state.db by 98 MB).
const (
	MaxArgName          = 128      // bytes of an argument name
	MaxArgs             = 64       // arguments per observation
	MaxObservationBytes = 4 << 10  // the encoded observation
	MaxBucketBytes      = 64 << 20 // the observations bucket, keys and values
	LoadBudget          = 16 << 20 // what Load reads, newest first
)

// Arg is the shape of one argument.
type Arg struct {
	// Type is the normaliser kind (path, url, email, shell_command, sql) or,
	// for an argument without one, the JSON type (string, number, boolean,
	// object, array).
	Type string `json:"type"`
	// Value is the normalised fact (resolved path, host, domain, program,
	// keyword) or a short literal string; "" when nothing may be kept.
	Value string `json:"value,omitempty"`
	// Values is a path argument given as a list: each resolved path, sorted.
	Values []string `json:"values,omitempty"`
}

// Observation is one recorded call.
type Observation struct {
	TS     time.Time      `json:"ts"`
	Client string         `json:"client"`
	Server string         `json:"server"`
	Tool   string         `json:"tool,omitempty"` // tools/call only
	Action string         `json:"action"`         // ActionCall, ActionList or ActionRead
	Shape  map[string]Arg `json:"shape,omitempty"`
	// Flagged is non-empty when pinning or detection flagged the call or
	// its result: FlagPinMismatch and/or the ids of medium and high
	// detection findings (low ones do not flag). A flagged observation is
	// never used by propose.
	Flagged []string `json:"flagged,omitempty"`
	// DroppedArgs counts arguments left out to keep the observation within
	// MaxArgs and MaxObservationBytes.
	DroppedArgs int `json:"dropped_args,omitempty"`
}

// Shape returns the shape of a call's arguments. rules are the tool's
// normalisers, args context.args and norm context.norm (both from
// policy.Outcome). An argument with a normaliser whose result is missing
// (wrong type, invalid) keeps only its JSON type.
func Shape(rules normalize.Rules, args, norm types.Record) map[string]Arg {
	if args.Len() == 0 {
		return nil
	}
	out := make(map[string]Arg, args.Len())
	for name, v := range args.All() {
		n := truncate(string(name), MaxArgName)
		if kind, ok := rules[n]; ok {
			if rec, ok := recordAt(norm, n); ok {
				if a, ok := normShape(kind, rec); ok {
					out[n] = a
					continue
				}
			}
			out[n] = Arg{Type: jsonType(v)} // normaliser failed: no value at all
			continue
		}
		out[n] = literalShape(n, v)
	}
	return out
}

// ResourceShape is the shape of a resources/read: the uri's type only (a
// URI can carry a token, and "uri" is not an enum-like name).
func ResourceShape(uri string) map[string]Arg {
	return map[string]Arg{"uri": literalShape("uri", types.String(uri))}
}

func recordAt(r types.Record, name string) (types.Record, bool) {
	v, ok := r.Get(types.String(name))
	if !ok {
		return types.Record{}, false
	}
	rec, ok := v.(types.Record)
	return rec, ok
}

func str(r types.Record, attr string) (string, bool) {
	v, ok := r.Get(types.String(attr))
	if !ok {
		return "", false
	}
	s, ok := v.(types.String)
	return string(s), ok
}

// normShape keeps the one normalised fact of each kind.
func normShape(kind normalize.Kind, rec types.Record) (Arg, bool) {
	attr := map[normalize.Kind]string{
		normalize.KindPath: "path", normalize.KindURL: "host", normalize.KindEmail: "domain",
		normalize.KindShellCommand: "program", normalize.KindSQL: "statement",
	}[kind]
	if attr == "" {
		return Arg{}, false
	}
	if s, ok := str(rec, attr); ok {
		return Arg{Type: string(kind), Value: s}, true
	}
	if kind != normalize.KindPath {
		return Arg{}, false
	}
	v, ok := rec.Get("paths")
	set, isSet := v.(types.Set)
	if !ok || !isSet {
		return Arg{}, false
	}
	vals := make([]string, 0, set.Len())
	for e := range set.All() {
		if s, ok := e.(types.String); ok {
			vals = append(vals, string(s))
		}
	}
	sort.Strings(vals)
	return Arg{Type: string(kind), Values: vals}, true
}

// jsonType names the JSON type a converted value came from. A non-integer
// number arrives as a String (package convert) and is named "string".
func jsonType(v types.Value) string {
	switch v.(type) {
	case types.String:
		return "string"
	case types.Long:
		return "number"
	case types.Boolean:
		return "boolean"
	case types.Record:
		return "object"
	case types.Set:
		return "array"
	}
	return "unknown"
}

// Key is the bbolt key of one observation:
// "<client>\x00<server>\x00<tool>\x00" + unix nanos (8 bytes) + seq (8 bytes),
// big-endian, so one call's observations sort by time.
func Key(client, server, tool string, ts time.Time, seq uint64) []byte {
	var b bytes.Buffer
	for _, p := range []string{client, server, tool} {
		if len(p) > maxKeyPart {
			p = p[:maxKeyPart]
		}
		b.WriteString(p)
		b.WriteByte(0)
	}
	var n [16]byte
	var nanos uint64 // times before 1970 do not occur; they sort first
	if v := ts.UnixNano(); v > 0 {
		nanos = uint64(v)
	}
	binary.BigEndian.PutUint64(n[:8], nanos)
	binary.BigEndian.PutUint64(n[8:], seq)
	b.Write(n[:])
	return b.Bytes()
}

// keyTime returns the unix nanos in a key (its 16-byte suffix).
func keyTime(k []byte) uint64 {
	if len(k) < 16 {
		return 0
	}
	return binary.BigEndian.Uint64(k[len(k)-16:])
}

// MaxLoad caps how many observations Load returns (the bucket cap).
const MaxLoad = DefaultCap

// Load returns the newest observations, oldest first: at most MaxLoad and
// at most LoadBudget bytes of encoded values. It walks the keys with a
// cursor (the time is in each key) and decodes only what fits. A value that
// does not decode is an error: the bucket is roverd's own.
func Load(db *state.DB) ([]Observation, error) { return loadBudget(db, LoadBudget) }

func loadBudget(db *state.DB, budget int) ([]Observation, error) {
	var out []Observation
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(state.BucketObservations)
		if b == nil {
			return fmt.Errorf("bucket %s missing", state.BucketObservations)
		}
		type kt struct {
			k []byte
			t uint64
		}
		var keys []kt
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			keys = append(keys, kt{k, keyTime(k)})
		}
		sort.SliceStable(keys, func(i, j int) bool { return keys[i].t > keys[j].t })
		used := 0
		for _, e := range keys {
			v := b.Get(e.k)
			if len(out) >= MaxLoad || used+len(v) > budget {
				break
			}
			used += len(v)
			var o Observation
			if err := json.Unmarshal(v, &o); err != nil {
				return fmt.Errorf("observation %q: %w", e.k, err)
			}
			out = append(out, o)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// capObservation applies the size caps: names cut to maxKeyPart, at most
// MaxArgs arguments (by name order), then the largest arguments dropped
// until the encoding fits MaxObservationBytes. DroppedArgs counts them.
func capObservation(o Observation) Observation {
	o.Client, o.Server, o.Tool = truncate(o.Client, maxKeyPart), truncate(o.Server, maxKeyPart), truncate(o.Tool, maxKeyPart)
	names := make([]string, 0, len(o.Shape))
	for n := range o.Shape {
		names = append(names, n)
	}
	sort.Strings(names)
	shape := make(map[string]Arg, min(len(names), MaxArgs))
	for i, n := range names {
		if i >= MaxArgs {
			o.DroppedArgs++
			continue
		}
		shape[n] = o.Shape[n]
	}
	o.Shape = shape
	for {
		b, err := json.Marshal(o)
		if err != nil || len(b) <= MaxObservationBytes || len(o.Shape) == 0 {
			return o
		}
		delete(o.Shape, largestArg(o.Shape))
		o.DroppedArgs++
	}
}

func largestArg(shape map[string]Arg) string {
	best, size := "", -1
	for n, a := range shape {
		s := len(n) + len(a.Value)
		for _, v := range a.Values {
			s += len(v)
		}
		if s > size || (s == size && n < best) {
			best, size = n, s
		}
	}
	return best
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// MaxDumpBytes caps the JSON an observations_dump answer carries, well
// inside ipc.MaxFrame.
const MaxDumpBytes = 16 << 20

// EncodeCapped encodes obs as a JSON array, leaving out the oldest entries
// (obs is oldest first) until it fits in maxBytes. dropped says how many.
func EncodeCapped(obs []Observation, maxBytes int) (out []byte, dropped int, err error) {
	enc := make([][]byte, len(obs))
	total := 2
	for i, o := range obs {
		if enc[i], err = json.Marshal(o); err != nil {
			return nil, 0, err
		}
		total += len(enc[i]) + 1
	}
	for dropped < len(enc) && total > maxBytes {
		total -= len(enc[dropped]) + 1
		dropped++
	}
	out = append(make([]byte, 0, total), '[')
	for i, e := range enc[dropped:] {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, e...)
	}
	return append(out, ']'), dropped, nil
}
