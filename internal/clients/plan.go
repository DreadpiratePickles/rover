package clients

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/DreadpiratePickles/rover/internal/ipc"
)

// Plan is a proposed rewrite of one file: its bytes now, its bytes after,
// a unified diff for the human, and what will (and will not) change.
type Plan struct {
	File ConfigFile
	Orig []byte
	New  []byte
	Diff string

	Changed  []string // servers this plan wraps (or unwraps), as scope/key
	Warnings []string // servers left alone, and why
	// Created means the file does not exist yet (only the settings plan).
	Created bool
}

// HasChanges reports whether applying the plan would change the file.
func (p Plan) HasChanges() bool { return p.Created || !bytes.Equal(p.Orig, p.New) }

// edit replaces orig[start:end] with text (start == end inserts).
type edit struct {
	start, end int
	text       []byte
}

// applyEdits returns orig with edits applied. Edits must not overlap.
func applyEdits(orig []byte, edits []edit) ([]byte, error) {
	es := append([]edit(nil), edits...)
	sort.SliceStable(es, func(i, j int) bool { return es[i].start < es[j].start })
	var out bytes.Buffer
	pos := 0
	for _, e := range es {
		if e.start < pos || e.end < e.start || e.end > len(orig) {
			return nil, fmt.Errorf("internal error: overlapping edit at byte %d", e.start)
		}
		out.Write(orig[pos:e.start])
		out.Write(e.text)
		pos = e.end
	}
	out.Write(orig[pos:])
	return out.Bytes(), nil
}

// jsonString encodes s as a JSON string without HTML escaping.
func jsonString(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a string always encodes
	return bytes.TrimRight(b.Bytes(), "\n")
}

// wrapEdits turns a stdio server into `roverPath wrap --name <key> --
// <command> <args...>`. Only two places change: the command value is
// replaced, and the wrap prefix (ending with the original command's own
// bytes) is inserted at the start of args, or a new args member is added
// right after command. env and every other member are untouched. unwrapEdits
// is the exact inverse.
func wrapEdits(orig []byte, s Server, roverPath string) []edit {
	name := ipc.SanitizeServerName(s.Key)
	prefix := []byte(`"wrap", "--name", ` + string(jsonString(name)) + `, "--", `)
	prefix = append(prefix, orig[s.cmd.Start:s.cmd.End]...)
	es := []edit{{start: s.cmd.Start, end: s.cmd.End, text: jsonString(roverPath)}}
	if s.args == nil {
		text := append([]byte(`, "args": [`), prefix...)
		return append(es, edit{start: s.cmd.End, end: s.cmd.End, text: append(text, ']')})
	}
	if len(s.argElems) > 0 {
		// A multi-line array keeps its line breaks: no trailing space.
		sep := ", "
		if bytes.ContainsRune(orig[s.args.Start+1:s.argElems[0].Start], '\n') {
			sep = ","
		}
		prefix = append(prefix, sep...)
	}
	return append(es, edit{start: s.args.Start + 1, end: s.args.Start + 1, text: prefix})
}

// unwrapEdits undoes wrapEdits on a wrapped server: the command comes back
// from the element after "--" (its original bytes), and the wrap prefix is
// cut out of args, or the whole args member if wrapEdits added it.
func unwrapEdits(orig []byte, s Server) ([]edit, error) {
	i := dashIndex(s.Args)
	if s.Status != StatusWrapped || s.args == nil || i < 0 || i+1 >= len(s.argElems) {
		return nil, fmt.Errorf("%s is not wrapped", s.Label())
	}
	inner := s.argElems[i+1]
	es := []edit{{start: s.cmd.Start, end: s.cmd.End, text: bytes.Clone(orig[inner.Start:inner.End])}}
	rest := s.argElems[i+2:]
	if len(rest) == 0 && string(orig[s.cmd.End:s.args.Start]) == `, "args": ` {
		return append(es, edit{start: s.cmd.End, end: s.args.End}), nil
	}
	end := inner.End
	if len(rest) > 0 {
		if bytes.HasPrefix(orig[end:], []byte(", ")) {
			end += 2
		} else if c := bytes.IndexByte(orig[end:rest[0].Start], ','); c >= 0 {
			end += c + 1
		}
	}
	return append(es, edit{start: s.args.Start + 1, end: end}), nil
}

// planWrap wraps every unwrapped stdio server in doc.
func planWrap(doc Doc, roverPath string) (Plan, error) {
	p := Plan{File: doc.File, Orig: doc.Orig}
	var edits []edit
	for _, s := range doc.Servers {
		switch {
		case s.Status == StatusStdio:
			edits = append(edits, wrapEdits(doc.Orig, s, roverPath)...)
			p.Changed = append(p.Changed, s.Label())
		case s.Status == StatusWrapped && !s.WrappedBy(roverPath):
			p.Warnings = append(p.Warnings, fmt.Sprintf("%s is wrapped by %q, not by this rover (%s); left alone, check it", s.Label(), s.Command, roverPath))
		case s.Status == StatusRemote:
			p.Warnings = append(p.Warnings, s.Label()+" is a remote server; not wrapped until `rover bridge` (M11)")
		case s.Status == StatusUnknown:
			p.Warnings = append(p.Warnings, s.Label()+" was not understood ("+s.Problem+"); left alone")
		}
	}
	return finish(p, edits)
}

// PlanUnwrap undoes the wrapping of every server in doc wrapped by any
// rover. `rover uninstall` uses it when the file changed since install, so
// the newest backup would throw those changes away.
func PlanUnwrap(doc Doc) (Plan, error) {
	p := Plan{File: doc.File, Orig: doc.Orig}
	var edits []edit
	for _, s := range doc.Servers {
		if s.Status != StatusWrapped {
			continue
		}
		es, err := unwrapEdits(doc.Orig, s)
		if err != nil {
			return Plan{}, err
		}
		edits = append(edits, es...)
		p.Changed = append(p.Changed, s.Label())
	}
	return finish(p, edits)
}

func finish(p Plan, edits []edit) (Plan, error) {
	n, err := applyEdits(p.Orig, edits)
	if err != nil {
		return Plan{}, err
	}
	p.New = n
	p.Diff = unifiedDiff(p.File.Path, p.Orig, edits)
	return p, nil
}
