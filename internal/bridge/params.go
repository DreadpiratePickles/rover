package bridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// LESSON (M11 fix, MEDIUM-1): the 2026-07-28 Streamable HTTP transport
// ("Request Metadata > Custom Headers from Tool Parameters") lets a server
// mark a tool parameter with "x-mcp-header" in its inputSchema. A client
// MUST then mirror that argument's value into an `Mcp-Param-<Name>` header
// on every tools/call (so a gateway can route on it without parsing the
// body), and MUST drop from tools/list any tool whose annotations break the
// rules, so one bad definition cannot poison the rest. The schema comes from
// the remote, so it is attacker-controlled input: the walk is depth- and
// count-limited, a header name must be an RFC 9110 token, and values go
// through the same base64 sentinel as Mcp-Name, so nothing in an argument
// can become a second header line.

// Limits on the annotations of one tool.
const (
	hdrParamPrefix  = "Mcp-Param-"
	xMCPHeader      = "x-mcp-header"
	maxParamHeaders = 32  // annotations per tool
	maxSchemaDepth  = 32  // nesting of inputSchema
	maxParamName    = 256 // bytes of one x-mcp-header value
	maxSafeInteger  = 1<<53 - 1
)

// paramHeader is one x-mcp-header annotation: the header name after
// "Mcp-Param-" and the chain of properties keys to the argument.
type paramHeader struct {
	Name string
	Path []string
}

// toolHeaders returns the Mcp-Param headers one tool's inputSchema declares.
// An error means the definition is invalid and the tool must be excluded
// from tools/list (spec: "Clients ... MUST reject tool definitions where any
// x-mcp-header value violates these constraints").
func toolHeaders(schema []byte) ([]paramHeader, error) {
	if len(bytes.TrimSpace(schema)) == 0 {
		return nil, nil
	}
	var out []paramHeader
	if err := walkSchema(schema, 0, false, true, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// walkSchema visits every value of a schema. param says this object is a
// property statically reachable from the root (a chain of "properties" keys
// only); props says its own "properties" members are. Anything reached
// through items, oneOf, $ref, if/then or any other keyword is neither, and
// an x-mcp-header there invalidates the tool.
func walkSchema(raw []byte, depth int, param, props bool, path []string, out *[]paramHeader) error {
	if depth > maxSchemaDepth {
		return fmt.Errorf("inputSchema nests deeper than %d", maxSchemaDepth)
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return errors.New("inputSchema holds an empty value")
	}
	switch raw[0] {
	case '[':
		elems, err := arrayElems(raw)
		if err != nil {
			return fmt.Errorf("inputSchema: %w", err)
		}
		for _, e := range elems {
			if err := walkSchema(raw[e[0]:e[1]], depth+1, false, false, nil, out); err != nil {
				return err
			}
		}
	case '{':
		fs, err := jsonrpc.Object(raw)
		if err != nil {
			return fmt.Errorf("inputSchema: %w", err)
		}
		if h, ok := fs.Get(xMCPHeader); ok {
			if !param {
				return errors.New("x-mcp-header on something that is not a statically reachable property")
			}
			name, err := paramName(h, fs, *out)
			if err != nil {
				return err
			}
			if len(*out) >= maxParamHeaders {
				return fmt.Errorf("more than %d x-mcp-header annotations", maxParamHeaders)
			}
			*out = append(*out, paramHeader{Name: name, Path: slices.Clone(path)})
		}
		for _, f := range fs {
			if f.Key == "properties" && props {
				if ps, perr := jsonrpc.Object(f.Value); perr == nil {
					for _, p := range ps {
						if err := walkSchema(p.Value, depth+1, true, true, slices.Concat(path, []string{p.Key}), out); err != nil {
							return err
						}
					}
					continue
				}
			}
			if err := walkSchema(f.Value, depth+1, false, false, nil, out); err != nil {
				return err
			}
		}
	}
	return nil
}

// paramName validates one x-mcp-header value against the spec's constraints:
// a non-empty HTTP token, unique ignoring case, on a parameter whose type is
// integer, string or boolean.
func paramName(raw json.RawMessage, prop jsonrpc.Fields, have []paramHeader) (string, error) {
	var name string
	if json.Unmarshal(raw, &name) != nil {
		return "", errors.New("x-mcp-header is not a string")
	}
	if name == "" {
		return "", errors.New("x-mcp-header is empty")
	}
	if len(name) > maxParamName {
		return "", fmt.Errorf("x-mcp-header is longer than %d bytes", maxParamName)
	}
	for i := 0; i < len(name); i++ {
		if !isTchar(name[i]) {
			return "", fmt.Errorf("x-mcp-header %q is not an HTTP token (RFC 9110 §5.1)", sanitize(name))
		}
	}
	for _, h := range have {
		if strings.EqualFold(h.Name, name) {
			return "", fmt.Errorf("x-mcp-header %q is used twice (names are case-insensitive)", sanitize(name))
		}
	}
	var typ string
	if t, ok := prop.Get("type"); !ok || json.Unmarshal(t, &typ) != nil {
		return "", fmt.Errorf("x-mcp-header %q on a parameter without a single type", sanitize(name))
	}
	switch typ {
	case "integer", "string", "boolean":
		return name, nil
	}
	return "", fmt.Errorf("x-mcp-header %q on a parameter of type %q; only integer, string and boolean are allowed", sanitize(name), sanitize(typ))
}

// isTchar is RFC 9110 §5.6.2 tchar.
func isTchar(c byte) bool {
	switch {
	case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// arrayElems splits one JSON array into the byte spans of its elements
// (raw[s:e] is one element).
func arrayElems(raw []byte) ([][2]int, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return nil, errors.New("not a JSON array")
	}
	var out [][2]int
	for dec.More() {
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		end := int(dec.InputOffset())
		out = append(out, [2]int{end - len(v), end})
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim(']') {
		return nil, errors.New("unterminated array")
	}
	return out, nil
}

// paramValues returns the Mcp-Param headers for one tools/call with these
// annotations: the value at each annotated path, as the spec's string form
// (string as is, integer in decimal, boolean lower-case), sentinel-encoded.
// A missing or null argument, or one that is not a primitive of a mirrored
// kind, gets no header: the server then rejects the call (HeaderMismatch)
// and the client sees why.
func paramValues(hs []paramHeader, params json.RawMessage) [][2]string {
	if len(hs) == 0 || len(params) == 0 {
		return nil
	}
	var p struct {
		Arguments json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal(params, &p) != nil || len(p.Arguments) == 0 {
		return nil
	}
	levels := map[string]map[string]json.RawMessage{} // joined path prefix -> that object's members
	var out [][2]string
	for _, h := range hs {
		v, ok := valueAt(p.Arguments, h.Path, levels)
		if !ok {
			continue
		}
		s, ok := paramString(v)
		if !ok {
			continue
		}
		out = append(out, [2]string{hdrParamPrefix + h.Name, headerValue(s)})
	}
	return out
}

// valueAt follows path through nested objects, parsing each object once.
func valueAt(args json.RawMessage, path []string, levels map[string]map[string]json.RawMessage) (json.RawMessage, bool) {
	cur, prefix := args, ""
	for _, k := range path {
		obj, ok := levels[prefix]
		if !ok {
			if json.Unmarshal(cur, &obj) != nil {
				return nil, false
			}
			levels[prefix] = obj
		}
		next, ok := obj[k]
		if !ok {
			return nil, false
		}
		cur, prefix = next, fmt.Sprintf("%s\x00%d:%s", prefix, len(k), k)
	}
	return cur, true
}

// paramString is the spec's type conversion for a mirrored value.
func paramString(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return "", false
	}
	switch {
	case raw[0] == '"':
		var s string
		return s, json.Unmarshal(raw, &s) == nil
	case bytes.Equal(raw, []byte("true")), bytes.Equal(raw, []byte("false")):
		return string(raw), true
	case raw[0] == '-' || raw[0] >= '0' && raw[0] <= '9':
		return integerString(string(raw))
	}
	return "", false
}

// integerString renders a JSON number that is an integer in JavaScript's
// safe range as its decimal string; anything else is not mirrored.
func integerString(s string) (string, bool) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n < -maxSafeInteger || n > maxSafeInteger {
			return "", false
		}
		return strconv.FormatInt(n, 10), true
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f != math.Trunc(f) || math.Abs(f) > maxSafeInteger {
		return "", false
	}
	return strconv.FormatInt(int64(f), 10), true
}

// toolTable is what a tools/list taught the transport: tool name -> headers.
type toolTable map[string][]paramHeader

// learnToolsList reads one tools/list result and returns the table of its
// valid tools, the invalid ones with the reason, and the result with the
// invalid tools removed (the bytes of every kept tool are the original
// ones). An error means the result could not be read as a tools/list at
// all; the caller then forwards it untouched and mirrors nothing.
func learnToolsList(result []byte) (toolTable, []string, []byte, error) {
	fs, err := jsonrpc.Object(result)
	if err != nil {
		return nil, nil, nil, err
	}
	var tf jsonrpc.Field
	found := false
	for _, f := range fs {
		if f.Key == "tools" {
			tf, found = f, true
		}
	}
	if !found {
		return toolTable{}, nil, result, nil
	}
	elems, err := arrayElems(tf.Value)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("tools: %w", err)
	}
	table := make(toolTable, len(elems))
	var rejected []string
	kept := make([][]byte, 0, len(elems))
	for i, e := range elems {
		el := tf.Value[e[0]:e[1]]
		tfs, err := jsonrpc.Object(el)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("tool %d: %w", i, err)
		}
		var name string
		if n, ok := tfs.Get("name"); !ok || json.Unmarshal(n, &name) != nil {
			return nil, nil, nil, fmt.Errorf("tool %d: name is not a string", i)
		}
		schema, _ := tfs.Get("inputSchema")
		hs, herr := toolHeaders(schema)
		if herr != nil {
			rejected = append(rejected, fmt.Sprintf("%s: %v", sanitize(name), herr))
			continue
		}
		table[name] = hs
		kept = append(kept, el)
	}
	if len(rejected) == 0 {
		return table, nil, result, nil
	}
	var b bytes.Buffer
	b.Write(result[:tf.Start])
	b.WriteByte('[')
	for i, k := range kept {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(k)
	}
	b.WriteByte(']')
	b.Write(result[tf.End:])
	return table, rejected, b.Bytes(), nil
}

// noteToolsList learns the Mcp-Param headers from a tools/list result and
// drops the tools whose annotations are invalid. A first page (no cursor in
// the request) starts a new table; later pages add to it.
func (t *Transport) noteToolsList(req jsonrpc.Message, r jsonrpc.Message) []byte {
	table, rejected, result, err := learnToolsList(r.Result)
	if err != nil {
		t.Logf("tools/list: cannot read the result (%v); mirroring no Mcp-Param headers", err)
		t.mu.Lock()
		t.tools = nil
		t.mu.Unlock()
		return r.Raw
	}
	for _, why := range rejected {
		t.Logf("tools/list: removed tool %s (x-mcp-header rules, MCP 2026-07-28)", why)
	}
	var p struct {
		Cursor string `json:"cursor"`
	}
	_ = json.Unmarshal(req.Params, &p)
	t.mu.Lock()
	if p.Cursor == "" || t.tools == nil {
		t.tools = table
	} else {
		for name, hs := range table {
			t.tools[name] = hs
		}
	}
	t.mu.Unlock()
	if len(rejected) == 0 {
		return r.Raw
	}
	var b bytes.Buffer
	b.Write(r.Raw[:r.ResultAt[0]])
	b.Write(result)
	b.Write(r.Raw[r.ResultAt[1]:])
	return b.Bytes()
}

// paramHeaders returns the Mcp-Param headers for m, a tools/call to a tool
// the last tools/list annotated; nothing for anything else.
func (t *Transport) paramHeaders(m jsonrpc.Message) [][2]string {
	if m.Kind != jsonrpc.KindRequest || m.Method != "tools/call" {
		return nil
	}
	var p struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(m.Params, &p) != nil || p.Name == "" {
		return nil
	}
	t.mu.Lock()
	hs := t.tools[p.Name]
	t.mu.Unlock()
	return paramValues(hs, m.Params)
}
