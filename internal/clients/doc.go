package clients

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// MaxConfig bounds a config file. ~/.claude.json grows with history but
// stays far below this; anything bigger is refused, not parsed.
const MaxConfig = 32 << 20

// field is one object member with offsets into the whole file.
type field struct {
	Key        string
	Value      []byte // from the comment-blanked copy
	Start, End int
}

type fields []field

func (fs fields) get(key string) (field, bool) {
	for _, f := range fs {
		if f.Key == key {
			return f, true
		}
	}
	return field{}, false
}

func isNull(f field) bool { return string(f.Value) == "null" }

// objectAt reads f's value as an object, strictly (exact keys, no keys equal
// under case folding), with member offsets into the whole file.
func objectAt(src []byte, f field) (fields, error) {
	return objectRange(src, f.Start, f.End)
}

func objectRange(src []byte, start, end int) (fields, error) {
	fs, err := jsonrpc.Object(src[start:end])
	if err != nil {
		return nil, err
	}
	out := make(fields, len(fs))
	for i, m := range fs {
		out[i] = field{Key: m.Key, Value: m.Value, Start: start + m.Start, End: start + m.End}
	}
	return out, nil
}

// element is one array element with offsets into the whole file.
type element struct {
	Value      []byte
	Start, End int
}

// arrayAt splits f's value, which must be a JSON array, into its elements.
func arrayAt(f field) ([]element, error) {
	dec := json.NewDecoder(bytes.NewReader(f.Value))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return nil, errors.New("not a JSON array")
	}
	var out []element
	for dec.More() {
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		end := int(dec.InputOffset())
		out = append(out, element{Value: v, Start: f.Start + end - len(v), End: f.Start + end})
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim(']') {
		return nil, errors.New("unterminated array")
	}
	return out, nil
}

// Status is what rover install sees in one server definition.
type Status string

// Server statuses.
const (
	StatusStdio   Status = "stdio"   // a local server, not wrapped
	StatusWrapped Status = "wrapped" // command is `rover`, args start with "wrap" (or "bridge", M11)
	StatusRemote  Status = "remote"  // url / type http|sse|ws: converted to `rover bridge` when possible (M11)
	StatusUnknown Status = "unknown" // not an object, or fields of the wrong type
)

// Server is one entry of a server map.
type Server struct {
	Scope   string // "user", "project", "global" or "local:<project dir>"
	Key     string
	Status  Status
	Command string   // for stdio and wrapped
	Args    []string // for stdio and wrapped
	Problem string   // why it is StatusUnknown
	// Bridged: a wrapped entry that is `rover bridge`, not `rover wrap` (M11).
	Bridged bool
	// For StatusRemote: the url, the transport type ("" if none) and
	// whether the entry carries its own headers.
	URL, RemoteType string
	HasHeaders      bool

	cmd, args  *field // offsets into Doc.Orig
	argElems   []element
	urlF, typF *field
}

// Doc is a parsed config file: the original bytes, untouched, and the
// servers found in it with their offsets.
type Doc struct {
	File    ConfigFile
	Orig    []byte
	Servers []Server
}

// remoteTypes are the documented transport types other than stdio.
var remoteTypes = map[string]bool{"http": true, "sse": true, "ws": true, "streamable-http": true}

func readDoc(s spec, cf ConfigFile) (Doc, error) {
	orig, err := readCapped(cf.Path)
	if err != nil {
		return Doc{}, err
	}
	d, err := parseDoc(s, cf, orig)
	if err != nil {
		return Doc{}, fmt.Errorf("%s: %w", cf.Path, err)
	}
	return d, nil
}

// parseDoc finds the servers in orig. Comments and trailing commas (VS
// Code and Cursor accept JSONC) are blanked to spaces in a working copy, so
// every offset still points into orig.
func parseDoc(s spec, cf ConfigFile, orig []byte) (Doc, error) {
	src, err := blankJSONC(orig)
	if err != nil {
		return Doc{}, err
	}
	top, err := objectRange(src, 0, len(src))
	if err != nil {
		return Doc{}, err
	}
	conts, err := s.containers(src, top, cf.Scope)
	if err != nil {
		return Doc{}, err
	}
	d := Doc{File: cf, Orig: orig}
	for _, c := range conts {
		for _, m := range c.members {
			d.Servers = append(d.Servers, classify(src, c.scope, m))
		}
	}
	return d, nil
}

func classify(src []byte, scope string, m field) Server {
	sv := Server{Scope: scope, Key: m.Key, Status: StatusUnknown}
	obj, err := objectAt(src, m)
	if err != nil {
		sv.Problem = "not a JSON object: " + err.Error()
		return sv
	}
	// An explicit type decides (every client documents one); a url with no
	// type is a configuration error in Claude Code's words, so it is not
	// guessed to be remote.
	_, hasURL := obj.get("url")
	if t, ok := obj.get("type"); ok {
		typ, isStr := stringValue(t.Value)
		switch {
		case !isStr:
			sv.Problem = "type is not a string"
			return sv
		case remoteTypes[typ]:
			sv.Status, sv.RemoteType, sv.typF = StatusRemote, typ, &t
			_, sv.HasHeaders = obj.get("headers")
			if f, ok := obj.get("url"); ok {
				sv.URL, _ = stringValue(f.Value)
				sv.urlF = &f
			}
			return sv
		case typ != "stdio":
			sv.Problem = fmt.Sprintf("unknown type %q", typ)
			return sv
		}
	} else if hasURL {
		sv.Problem = `"url" without a "type"`
		return sv
	}
	cmd, ok := obj.get("command")
	command, isStr := stringValue(cmd.Value)
	if !ok || !isStr || command == "" {
		sv.Problem = "no command string"
		return sv
	}
	sv.Command, sv.cmd = command, &cmd
	if a, ok := obj.get("args"); ok {
		elems, err := arrayAt(a)
		if err != nil {
			sv.Problem = "args is not an array"
			return sv
		}
		for _, e := range elems {
			s, ok := stringValue(e.Value)
			if !ok {
				sv.Problem = "args has a non-string element"
				return sv
			}
			sv.Args = append(sv.Args, s)
		}
		sv.args, sv.argElems = &a, elems
	}
	if f, ok := obj.get("type"); ok {
		sv.typF = &f
	}
	sv.Status = StatusStdio
	if IsRoverForm(sv.Command, sv.Args) {
		sv.Status = StatusWrapped
	} else if IsBridgeForm(sv.Command, sv.Args) {
		sv.Status, sv.Bridged = StatusWrapped, true
	}
	return sv
}

// IsRoverForm reports whether command and args look like `rover wrap ...
// -- <server>`: a binary named rover whose arguments parse as wrap's own
// (wrapSplit). Whether it is *this* rover is a separate question
// (Server.WrappedBy).
func IsRoverForm(command string, args []string) bool {
	base := filepath.Base(command)
	if base != "rover" && base != "rover.exe" {
		return false
	}
	_, ok := wrapSplit(args)
	return ok
}

// wrapForm is how a wrapped server's args are laid out.
type wrapForm struct {
	sep int // index of the "--" that ends wrap's flags; the server command follows
	// argsAdded: the server had no args member and install added one. That
	// form writes "--name=<key>" as one element instead of "--name", "<key>",
	// so the unwrap knows to remove the member again; without the marker
	// {"command":"x"} and {"command":"x","args":[]} wrap to the same bytes.
	argsAdded bool
}

// wrapSplit parses args in the forms rover writes or accepts:
// wrap -- cmd..., wrap --name K -- cmd..., wrap --name=K -- cmd... The
// positions are fixed, so a server named "--" is no problem.
func wrapSplit(args []string) (wrapForm, bool) {
	if len(args) < 3 || args[0] != "wrap" {
		return wrapForm{}, false
	}
	f := wrapForm{sep: 1}
	switch {
	case args[1] == "--name":
		f.sep = 3
	case strings.HasPrefix(args[1], "--name="):
		f.sep, f.argsAdded = 2, true
	}
	if f.sep+1 >= len(args) || args[f.sep] != "--" {
		return wrapForm{}, false
	}
	return f, true
}

// WrappedBy says whether a wrapped server runs through roverPath (true) or
// through some other binary called rover (false: a look-alike, or a stale
// install).
func (s Server) WrappedBy(roverPath string) bool {
	return s.Status == StatusWrapped && s.Command == roverPath
}

// Label is "<scope>/<key>" for messages.
func (s Server) Label() string { return s.Scope + "/" + s.Key }

func stringValue(raw []byte) (string, bool) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// readCapped reads a config, refusing anything over MaxConfig.
func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: a client config path chosen by the adapter, read by its owner
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, MaxConfig+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxConfig {
		return nil, fmt.Errorf("%s is larger than %d bytes; refusing to parse it", path, MaxConfig)
	}
	return b, nil
}

// blankJSONC returns a copy of src with // and /* */ comments and trailing
// commas replaced by spaces (newlines kept), so the strict reader accepts it
// and every byte offset is unchanged. Strings are left alone.
func blankJSONC(src []byte) ([]byte, error) {
	out := bytes.Clone(src)
	inStr := false
	for i := 0; i < len(out); i++ {
		c := out[i]
		if inStr {
			switch c {
			case '\\':
				i++
			case '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
		case c == '/' && i+1 < len(out) && out[i+1] == '/':
			for ; i < len(out) && out[i] != '\n'; i++ {
				out[i] = ' '
			}
		case c == '/' && i+1 < len(out) && out[i+1] == '*':
			j := bytes.Index(out[i+2:], []byte("*/"))
			if j < 0 {
				return nil, errors.New("unterminated /* comment")
			}
			end := i + 2 + j + 2
			for k := i; k < end; k++ {
				if out[k] != '\n' && out[k] != '\r' {
					out[k] = ' '
				}
			}
			i = end - 1
		}
	}
	blankTrailingCommas(out)
	return out, nil
}

// blankTrailingCommas blanks a comma whose next non-space byte closes an
// object or array (outside strings; comments are already spaces).
func blankTrailingCommas(out []byte) {
	inStr := false
	for i := 0; i < len(out); i++ {
		c := out[i]
		if inStr {
			switch c {
			case '\\':
				i++
			case '"':
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			continue
		}
		if c != ',' {
			continue
		}
		j := i + 1
		for j < len(out) && strings.IndexByte(" \t\r\n", out[j]) >= 0 {
			j++
		}
		if j < len(out) && (out[j] == '}' || out[j] == ']') {
			out[i] = ' '
		}
	}
}
