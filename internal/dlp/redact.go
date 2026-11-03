package dlp

import (
	"strconv"
	"strings"

	"github.com/DreadpiratePickles/rover/internal/jsonedit"
)

// Marker is what replaces a secret of kind: "[REDACTED:<kind>]".
func Marker(kind string) string { return "[REDACTED:" + kind + "]" }

// Redact returns text with every match replaced by its Marker. Matches may
// come in any order and may overlap: overlapping spans are merged first
// (keeping the most specific kind), and spans outside text are clipped.
// Every byte outside a span is copied unchanged. With no matches it
// returns text itself.
func Redact(text []byte, matches []Match) []byte {
	if len(matches) == 0 {
		return text
	}
	ms := make([]Match, 0, len(matches))
	for _, m := range matches {
		m.Start, m.End = max(0, min(m.Start, len(text))), max(0, min(m.End, len(text)))
		if m.Start < m.End {
			ms = append(ms, m)
		}
	}
	ms = resolve(ms)
	out := make([]byte, 0, len(text))
	at := 0
	for _, m := range ms {
		out = append(out, text[at:m.Start]...)
		out = append(out, Marker(m.Kind)...)
		at = m.End
	}
	return append(out, text[at:]...)
}

// RedactString finds and redacts secrets in s. It returns s itself and no
// matches when there is nothing to redact.
func RedactString(d Detector, s string) (string, []Match) {
	ms := d.Find([]byte(s))
	if len(ms) == 0 {
		return s, nil
	}
	return string(Redact([]byte(s), ms)), ms
}

// FindValue finds secrets in one decoded JSON string value whose member
// name is key. Besides Find, a credential-sounding name ("password",
// "client_secret", "X-Api-Key") makes a plausible value a secret as a
// whole: in JSON the name and the value are separate strings, so the
// "password=..." shape never appears in either alone.
func FindValue(d Detector, key, s string) []Match {
	ms := d.Find([]byte(s))
	if keyedValue(key, s) {
		ms = resolve(append(ms, Match{Kind: KindGeneric, Start: 0, End: len(s)}))
	}
	return ms
}

// RedactJSON redacts secrets inside the strings of raw, one JSON value
// read strictly (jsonedit.Walk: exact keys, no duplicates, depth at most
// jsonedit.MaxDepth): string values AND member names. Each string that
// holds a secret is decoded, redacted and re-encoded, and only its bytes
// are spliced; every other byte of raw is kept, so valid JSON stays valid
// JSON. A redacted member name that would collide with another name of its
// object gets a suffix, "[REDACTED:kind]#2", so names stay unique. It
// returns raw itself when nothing matched, the distinct kinds found and the
// number of matches. An error means raw could not be read strictly:
// callers must not use raw then (fail closed).
func RedactJSON(d Detector, raw []byte) ([]byte, []string, int, error) {
	var edits []jsonedit.Edit
	var all []Match
	objs := map[int]*object{}
	err := jsonedit.Walk(raw, func(s jsonedit.Str) error {
		var ms []Match
		if s.IsKey {
			ms = d.Find([]byte(s.Value))
			o := objs[s.Obj]
			if o == nil {
				o = &object{used: map[string]bool{}}
				objs[s.Obj] = o
			}
			if len(ms) == 0 {
				o.used[fold(s.Value)] = true
				return nil
			}
			o.renames = append(o.renames, rename{s.Start, s.End, string(Redact([]byte(s.Value), ms))})
		} else {
			if ms = FindValue(d, s.Key, s.Value); len(ms) == 0 {
				return nil
			}
			edits = append(edits, jsonedit.Edit{Start: s.Start, End: s.End, With: jsonedit.EncodeString(string(Redact([]byte(s.Value), ms)))})
		}
		all = append(all, ms...)
		return nil
	})
	if err != nil {
		return nil, nil, 0, err
	}
	for _, o := range objs {
		edits = append(edits, o.edits()...)
	}
	if len(edits) == 0 {
		return raw, nil, 0, nil
	}
	out, err := jsonedit.Apply(raw, edits)
	if err != nil {
		return nil, nil, 0, err
	}
	return out, KindsOf(all), len(all), nil
}

// object collects the member names of one object: those kept (used, folded
// as jsonrpc.Object compares them) and those to rename.
type object struct {
	used    map[string]bool
	renames []rename
}

type rename struct {
	start, end int
	name       string
}

func fold(s string) string { return strings.ToLower(s) }

// edits gives each renamed member a name no other member of the object has.
func (o *object) edits() []jsonedit.Edit {
	out := make([]jsonedit.Edit, 0, len(o.renames))
	for _, r := range o.renames {
		name := UniqueName(r.name, o.used)
		o.used[fold(name)] = true
		out = append(out, jsonedit.Edit{Start: r.start, End: r.end, With: jsonedit.EncodeString(name)})
	}
	return out
}

// UniqueName returns name, or name#2, name#3, ... whichever is not in used
// (folded); it does not add it.
func UniqueName(name string, used map[string]bool) string {
	cand := name
	for i := 2; used[fold(cand)]; i++ {
		cand = name + "#" + strconv.Itoa(i)
	}
	return cand
}

// FindJSON returns the distinct kinds of secret in raw's string values and
// member names (read as RedactJSON reads them) without rewriting anything.
func FindJSON(d Detector, raw []byte) ([]string, error) {
	var all []Match
	err := jsonedit.Walk(raw, func(s jsonedit.Str) error {
		if s.IsKey {
			all = append(all, d.Find([]byte(s.Value))...)
		} else {
			all = append(all, FindValue(d, s.Key, s.Value)...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return KindsOf(all), nil
}
