package dlp

import (
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

// RedactJSON redacts secrets inside the string values of raw, one JSON
// value read strictly (jsonedit.Strings: exact keys, no duplicates, depth
// at most jsonedit.MaxDepth). Each string that holds a secret is decoded,
// redacted and re-encoded, and only its bytes are spliced; every other byte
// of raw is kept, so valid JSON stays valid JSON. It returns raw itself
// when nothing matched, and the distinct kinds found. An error means raw
// could not be read strictly: callers must not use raw then (fail closed).
func RedactJSON(d Detector, raw []byte) ([]byte, []string, error) {
	var edits []jsonedit.Edit
	var all []Match
	err := jsonedit.Strings(raw, func(key string, start, end int, s string) error {
		ms := FindValue(d, key, s)
		if len(ms) == 0 {
			return nil
		}
		all = append(all, ms...)
		edits = append(edits, jsonedit.Edit{Start: start, End: end, With: jsonedit.EncodeString(string(Redact([]byte(s), ms)))})
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if len(edits) == 0 {
		return raw, nil, nil
	}
	out, err := jsonedit.Apply(raw, edits)
	if err != nil {
		return nil, nil, err
	}
	return out, KindsOf(all), nil
}

// FindJSON returns the distinct kinds of secret in raw's string values
// (read as RedactJSON reads them) without rewriting anything.
func FindJSON(d Detector, raw []byte) ([]string, error) {
	var all []Match
	err := jsonedit.Strings(raw, func(key string, _, _ int, s string) error {
		all = append(all, FindValue(d, key, s)...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return KindsOf(all), nil
}
