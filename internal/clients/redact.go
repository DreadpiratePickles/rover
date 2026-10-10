package clients

import (
	"errors"
	"sort"
)

// Configs carry secrets: API keys in "env", bearer tokens in "headers".
// Every diff rover prints (install, uninstall, the deny rules) shows these
// values as "[redacted]", context lines included, and on minified files
// too: the redaction works on byte spans found by the strict reader, not
// on lines. The file itself is never changed by it.

// redactedKeys are the members whose object values are secret.
var redactedKeys = map[string]bool{"env": true, "headers": true}

const redactedText = `"[redacted]"`

// maxRedactDepth bounds the walk; a deeper file gets no diff at all.
const maxRedactDepth = 64

var errTooDeep = errors.New("JSON nested too deeply to redact")

// redactions returns the edits that replace every value inside an "env" or
// "headers" object of orig, at any depth.
func redactions(orig []byte) ([]edit, error) {
	src, err := blankJSONC(orig)
	if err != nil {
		return nil, err
	}
	top, err := objectRange(src, 0, len(src))
	if err != nil {
		return nil, err
	}
	var out []edit
	if err := walkRedact(src, top, 0, &out); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	return out, nil
}

func walkRedact(src []byte, obj fields, depth int, out *[]edit) error {
	if depth > maxRedactDepth {
		return errTooDeep
	}
	for _, m := range obj {
		if len(m.Value) == 0 {
			continue
		}
		switch m.Value[0] {
		case '{':
			inner, err := objectAt(src, m)
			if err != nil {
				return err
			}
			if redactedKeys[m.Key] {
				for _, v := range inner {
					*out = append(*out, edit{start: v.Start, end: v.End, text: []byte(redactedText)})
				}
				continue
			}
			if err := walkRedact(src, inner, depth+1, out); err != nil {
				return err
			}
		case '[':
			elems, err := arrayAt(m)
			if err != nil {
				return err
			}
			for _, e := range elems {
				if len(e.Value) > 0 && e.Value[0] == '{' {
					inner, err := objectRange(src, e.Start, e.End)
					if err != nil {
						return err
					}
					if err := walkRedact(src, inner, depth+1, out); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// shift maps an offset in the original to the redacted copy.
func shift(off int, reds []edit) int {
	d := 0
	for _, r := range reds {
		if r.end > off {
			break
		}
		d += len(r.text) - (r.end - r.start)
	}
	return off + d
}

// redactedDiff is unifiedDiff over the redacted copy of orig.
func redactedDiff(path string, orig []byte, edits []edit) string {
	if len(edits) == 0 {
		return ""
	}
	reds, err := redactions(orig)
	if err != nil {
		return "(diff not shown: " + err.Error() + ")\n"
	}
	r, err := applyEdits(orig, reds)
	if err != nil {
		return "(diff not shown: " + err.Error() + ")\n"
	}
	mapped := make([]edit, len(edits))
	for i, e := range edits {
		mapped[i] = edit{start: shift(e.start, reds), end: shift(e.end, reds), text: e.text}
	}
	return unifiedDiff(path, r, mapped)
}

// redactAll returns b with its secret values replaced, or a placeholder.
func redactAll(b []byte) []byte {
	reds, err := redactions(b)
	if err == nil {
		if r, aerr := applyEdits(b, reds); aerr == nil {
			return r
		}
	}
	return []byte("(content not shown: it could not be parsed to hide secrets)\n")
}
