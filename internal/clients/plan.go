package clients

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

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
	// Undo marks an in-place unwrap: its backup is never restored.
	Undo bool
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
// bytes) is inserted at the start of args; a server with no args member
// gets one right after command, marked by writing "--name=<key>" as one
// element (wrapForm). env and every other member are untouched.
// unwrapEdits is the exact inverse.
func wrapEdits(orig []byte, s Server, roverPath string) []edit {
	name := string(jsonString(ipc.SanitizeServerName(s.Key)))
	es := []edit{{start: s.cmd.Start, end: s.cmd.End, text: jsonString(roverPath)}}
	if s.args == nil {
		text := []byte(`, "args": ["wrap", ` + string(jsonString("--name="+ipc.SanitizeServerName(s.Key))) + `, "--", `)
		text = append(append(text, orig[s.cmd.Start:s.cmd.End]...), ']')
		return append(es, edit{start: s.cmd.End, end: s.cmd.End, text: text})
	}
	prefix := []byte(`"wrap", "--name", ` + name + `, "--", `)
	prefix = append(prefix, orig[s.cmd.Start:s.cmd.End]...)
	if len(s.argElems) > 0 {
		prefix = append(prefix, argSep(orig[s.args.Start+1:s.argElems[0].Start])...)
	}
	return append(es, edit{start: s.args.Start + 1, end: s.args.Start + 1, text: prefix})
}

// argSep is the separator wrapEdits puts between the inserted prefix and
// the original first element, whose leading white space is ws: a
// multi-line array keeps its line breaks with no trailing space.
func argSep(ws []byte) string {
	if bytes.ContainsRune(ws, '\n') {
		return ","
	}
	return ", "
}

// unwrapEdits undoes wrapEdits on a wrapped server. The command comes back
// from the element after wrap's "--" (its original bytes); the args are
// everything after it, so the inserted prefix and separator are cut out, or
// the whole args member when install added it.
func unwrapEdits(orig []byte, s Server) ([]edit, error) {
	f, ok := wrapSplit(s.Args)
	if s.Status != StatusWrapped || s.args == nil || !ok {
		return nil, fmt.Errorf("%s is not wrapped", s.Label())
	}
	inner := s.argElems[f.sep+1]
	es := []edit{{start: s.cmd.Start, end: s.cmd.End, text: bytes.Clone(orig[inner.Start:inner.End])}}
	rest := s.argElems[f.sep+2:]
	if f.argsAdded && len(rest) == 0 {
		from, to, err := memberSpan(orig, *s.args, s.cmd.End)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.Label(), err)
		}
		return append(es, edit{start: from, end: to}), nil
	}
	end := inner.End
	if len(rest) > 0 {
		c := bytes.IndexByte(orig[end:rest[0].Start], ',')
		if c < 0 {
			return nil, fmt.Errorf("%s: args are not comma-separated", s.Label())
		}
		end += c + 1
		if argSep(orig[end:rest[0].Start]) == ", " && orig[end] == ' ' {
			end++
		}
	}
	return append(es, edit{start: s.args.Start + 1, end: end}), nil
}

// memberSpan is the byte range to delete to remove the member whose value
// is v: from the comma before its key (or, for a first member, from the
// key through the comma after it). Install puts the member right after
// command as `, "args": [...]`, which is the common case.
func memberSpan(orig []byte, v field, cmdEnd int) (int, int, error) {
	if string(orig[cmdEnd:v.Start]) == `, "args": ` {
		return cmdEnd, v.End, nil
	}
	i := v.Start
	skip := func() {
		for i > 0 && strings.IndexByte(" \t\r\n", orig[i-1]) >= 0 {
			i--
		}
	}
	skip()
	if i == 0 || orig[i-1] != ':' {
		return 0, 0, errors.New("cannot find the args key")
	}
	i--
	skip()
	if i < 6 || string(orig[i-6:i]) != `"args"` {
		return 0, 0, errors.New("cannot find the args key")
	}
	i -= 6
	key := i
	skip()
	if i > 0 && orig[i-1] == ',' {
		return i - 1, v.End, nil
	}
	end := v.End
	for end < len(orig) && strings.IndexByte(" \t\r\n", orig[end]) >= 0 {
		end++
	}
	if end < len(orig) && orig[end] == ',' {
		end++
	}
	return key, end, nil
}

// Errors from planWrap: rover refuses a file it does not fully understand
// (fail closed) rather than wrap part of it.
var (
	ErrNotUnderstood = errors.New("servers rover does not understand")
	ErrNameCollision = errors.New("servers whose names collide after sanitising")
)

// planWrap wraps every unwrapped stdio server in doc. A server that is not
// understood, or two keys that become the same --name, refuse the file.
func planWrap(doc Doc, roverPath string) (Plan, error) {
	if err := checkServers(doc); err != nil {
		return Plan{}, err
	}
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
		}
	}
	return finish(p, edits)
}

// checkServers refuses unknown entries and --name collisions.
func checkServers(doc Doc) error {
	var unknown []string
	keys := map[string]map[string]bool{} // sanitised name -> raw keys
	for _, s := range doc.Servers {
		switch s.Status {
		case StatusUnknown:
			unknown = append(unknown, fmt.Sprintf("%s (%s)", s.Label(), s.Problem))
		case StatusStdio, StatusWrapped:
			n := ipc.SanitizeServerName(s.Key)
			if keys[n] == nil {
				keys[n] = map[string]bool{}
			}
			keys[n][s.Key] = true
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("%w: %s; fix them and run install again (nothing was changed)", ErrNotUnderstood, strings.Join(unknown, ", "))
	}
	var clash []string
	for n, ks := range keys {
		if len(ks) > 1 {
			var l []string
			for k := range ks {
				l = append(l, fmt.Sprintf("%q", k))
			}
			sort.Strings(l)
			clash = append(clash, strings.Join(l, " and ")+" both become --name "+n)
		}
	}
	if len(clash) > 0 {
		sort.Strings(clash)
		return fmt.Errorf("%w: %s; rename one (rover's audit log and policy identify servers by this name)", ErrNameCollision, strings.Join(clash, "; "))
	}
	return nil
}

// PlanUnwrap undoes the wrapping of every server in doc wrapped by any
// rover. `rover uninstall` uses it when the file changed since install, so
// the newest backup would throw those changes away.
func PlanUnwrap(doc Doc) (Plan, error) {
	p := Plan{File: doc.File, Orig: doc.Orig, Undo: true}
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
	p.Diff = redactedDiff(p.File.Path, p.Orig, edits)
	return p, nil
}
