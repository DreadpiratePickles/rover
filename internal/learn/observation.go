// Package learn is Rover's learn mode (plan D6, M6): while roverd runs in
// observe mode it records the SHAPE of every call the policy was asked about,
// and `rover policy propose` (internal/policy/propose) generalises those
// shapes into an allow-list.
//
// LESSON (M6): a shape is not a copy of the call. For an argument a
// normaliser understands, the shape keeps only the fact a policy can use: the
// resolved absolute path (never the text the agent typed), the URL's host,
// the e-mail domain, the shell program, the SQL keyword. Every other argument
// keeps its JSON type, plus its value only when that value is a short,
// space-free string (an id, a mode, a branch name): a file's contents or a
// message body never reaches the observations bucket.
package learn

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

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

// MaxLiteral bounds the strings whose value a shape keeps: shorter than
// this many bytes and without white space.
const MaxLiteral = 64

// maxKeyPart bounds each name in a bbolt key (bbolt keys are at most 32 KiB).
const maxKeyPart = 256

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
		n := string(name)
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
		out[n] = literalShape(v)
	}
	return out
}

// ResourceShape is the shape of a resources/read: its uri, as a literal.
func ResourceShape(uri string) map[string]Arg {
	return map[string]Arg{"uri": literalShape(types.String(uri))}
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

// literalShape keeps the JSON type, and the value of a short string with no
// white space.
func literalShape(v types.Value) Arg {
	a := Arg{Type: jsonType(v)}
	if s, ok := v.(types.String); ok && len(s) < MaxLiteral && !strings.ContainsFunc(string(s), unicode.IsSpace) {
		a.Value = string(s)
	}
	return a
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
	binary.BigEndian.PutUint64(n[:8], uint64(ts.UnixNano())) //nolint:gosec // G115: times before 1970 do not occur; order only
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

// Load reads every observation in the bucket, oldest first, at most MaxLoad.
// A value that does not decode is an error: the bucket is roverd's own.
func Load(db *state.DB) ([]Observation, error) {
	type kv struct {
		t   uint64
		obs Observation
	}
	var all []kv
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(state.BucketObservations)
		if b == nil {
			return fmt.Errorf("bucket %s missing", state.BucketObservations)
		}
		return b.ForEach(func(k, v []byte) error {
			var o Observation
			if err := json.Unmarshal(v, &o); err != nil {
				return fmt.Errorf("observation %q: %w", k, err)
			}
			all = append(all, kv{keyTime(k), o})
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].t < all[j].t })
	if len(all) > MaxLoad {
		all = all[len(all)-MaxLoad:]
	}
	out := make([]Observation, len(all))
	for i, e := range all {
		out[i] = e.obs
	}
	return out, nil
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
