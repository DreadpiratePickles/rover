// Package yaml2cedar compiles Rover's policy.yaml (plan §5.4) into Cedar
// text that policy.Load accepts.
//
//	version: 1
//	mode: enforce            # observe | enforce (optional)
//	defaults: deny           # the only accepted value
//	servers:
//	  filesystem:
//	    labels: { read_file: [reads_private], write_file: [destructive] }
//	roots: { projects: "~/projects" }
//	rules:
//	  - id: fs-read-projects
//	    allow: filesystem.read_file
//	    when: { path_under: projects }
//
// LESSON (M3): a compiler that sits in front of a security engine is part
// of the security boundary. Whatever it drops, guesses or "fixes" is a rule
// the operator wrote and Rover does not enforce. So this compiler is strict:
// an unknown key, an unknown condition, an undeclared root, an unknown label,
// a name with odd characters or a combination with no exact Cedar meaning is
// an error naming the YAML line and column. It never approximates and never
// escapes its way out of a bad name: ids and names are restricted to
// characters that need no escaping in Cedar, so nothing the YAML says can
// become Cedar syntax.
package yaml2cedar

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"

	"gopkg.in/yaml.v3"
)

// MaxSourceBytes caps the size of a policy.yaml.
const MaxSourceBytes = 1 << 20

// maxNodeDepth bounds the YAML tree we walk. yaml.v3 itself stops at 10000
// levels of flow nesting; a real policy.yaml needs fewer than ten.
const maxNodeDepth = 64

// Compiled is the result of a successful Compile.
type Compiled struct {
	// Cedar is the generated policy text.
	Cedar []byte
	// Mode is "observe", "enforce" or "" when the YAML does not set it.
	Mode string
	// Roots maps root name -> path exactly as written ("~" not expanded).
	Roots map[string]string
	// RootOrder lists the root names in file order. Order matters: a
	// relative path argument is resolved against the first root.
	RootOrder []string
	// Labels maps server -> tool -> labels.
	Labels map[string]map[string][]string
	// Rules describes each compiled policy: the rules in file order, then
	// the implied list_tools permits.
	Rules []RuleInfo
}

// RuleInfo describes one compiled rule.
type RuleInfo struct {
	ID     string
	Line   int    // YAML line of the rule
	Effect string // "permit" or "forbid"
	Server string // "*" for deny: "*"
	Tool   string // "*" for deny: "*"; "" for an implied list_tools permit
	// Implied is set for the list_tools permit the compiler adds for each
	// server with at least one allow rule; Line is that first allow's line.
	Implied bool
}

// CompileError is every error Compile returns. Line and Col are 1-based
// positions in the YAML source; Col is 0 when only the line is known.
type CompileError struct {
	File      string
	Line, Col int
	Msg       string
}

func (e *CompileError) Error() string {
	return fmt.Sprintf("%s:%d:%d: %s", e.File, e.Line, e.Col, e.Msg)
}

// compiler carries the file name for error messages.
type compiler struct{ file string }

func (c compiler) errAt(n *yaml.Node, format string, a ...any) error {
	return &CompileError{File: c.file, Line: n.Line, Col: n.Column, Msg: fmt.Sprintf(format, a...)}
}

func (c compiler) errLine(line int, format string, a ...any) error {
	return &CompileError{File: c.file, Line: line, Msg: fmt.Sprintf(format, a...)}
}

// Compile parses src (named filename in errors and in the generated
// "// from" comments) and returns the Cedar text and the settings the YAML
// carries. Every error is a *CompileError.
func Compile(src []byte, filename string) (Compiled, error) {
	c := compiler{file: filename}
	if len(src) > MaxSourceBytes {
		return Compiled{}, c.errLine(1, "file is %d bytes, limit %d", len(src), MaxSourceBytes)
	}
	doc, err := c.parse(src)
	if err != nil {
		return Compiled{}, err
	}
	p, err := c.document(doc)
	if err != nil {
		return Compiled{}, err
	}
	return Compiled{
		Cedar:     emit(p, filename),
		Mode:      p.mode,
		Roots:     p.roots,
		RootOrder: p.rootOrder,
		Labels:    p.labels,
		Rules:     p.infos(),
	}, nil
}

var yamlLineRE = regexp.MustCompile(`line (\d+)`)

// parse decodes exactly one YAML document into a node tree and refuses
// anchors, aliases and trees deeper than maxNodeDepth.
func (c compiler) parse(src []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, c.errLine(1, "file is empty")
		}
		line := 1
		if m := yamlLineRE.FindStringSubmatch(err.Error()); m != nil {
			if n, convErr := strconv.Atoi(m[1]); convErr == nil {
				line = n
			}
		}
		return nil, c.errLine(line, "%v", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		line := extra.Line
		if line == 0 { // the second document did not parse, so it has no node
			line = separatorLine(src, doc.Line)
		}
		return nil, c.errLine(line, "the file must contain exactly one YAML document")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, c.errLine(1, "file is empty")
	}
	root := doc.Content[0]
	if err := c.plain(root, 0); err != nil {
		return nil, err
	}
	return root, nil
}

// separatorLine returns the line of the first document marker ("---" or
// "...") after line after (where the first document starts), so an error in a
// second document still names a line. Without one it returns the last line.
func separatorLine(src []byte, after int) int {
	lines := bytes.Split(src, []byte("\n"))
	for i := after; i < len(lines); i++ { // lines[i] is line i+1
		l := bytes.TrimRight(lines[i], "\r")
		for _, m := range [][]byte{[]byte("---"), []byte("...")} {
			if bytes.HasPrefix(l, m) && (len(l) == 3 || l[3] == ' ' || l[3] == '\t') {
				return i + 1
			}
		}
	}
	return max(len(lines), 1)
}

// plain refuses anchors, aliases and excessive depth anywhere in the tree.
// Aliases would let one rule silently share another's conditions; nothing
// in policy.yaml needs them.
func (c compiler) plain(n *yaml.Node, depth int) error {
	if depth > maxNodeDepth {
		return c.errAt(n, "nesting is deeper than %d levels", maxNodeDepth)
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return c.errAt(n, "YAML anchors and aliases (&, *) are not allowed in policy.yaml")
	}
	for _, ch := range n.Content {
		if err := c.plain(ch, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// field is one key: value pair of a mapping, in file order.
type field struct {
	key, val *yaml.Node
}

// mapping checks that n is a mapping with string keys from allowed, none
// repeated, and returns its fields in order. what names n in errors.
func (c compiler) mapping(n *yaml.Node, what string, allowed ...string) ([]field, error) {
	if n.Kind != yaml.MappingNode {
		return nil, c.errAt(n, "%s must be a mapping (key: value)", what)
	}
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	seen := map[string]bool{}
	out := make([]field, 0, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
			return nil, c.errAt(k, "%s: keys must be plain strings", what)
		}
		if len(allowed) > 0 && !ok[k.Value] {
			return nil, c.errAt(k, "%s: unknown key %q (allowed: %s)", what, k.Value, joinList(allowed))
		}
		if seen[k.Value] {
			return nil, c.errAt(k, "%s: key %q appears twice", what, k.Value)
		}
		seen[k.Value] = true
		out = append(out, field{k, v})
	}
	return out, nil
}

func (c compiler) str(n *yaml.Node, what string) (string, error) {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return "", c.errAt(n, "%s must be a string", what)
	}
	return n.Value, nil
}

func (c compiler) boolean(n *yaml.Node, what string) (bool, error) {
	var b bool
	if n.Kind != yaml.ScalarNode || n.Tag != "!!bool" || n.Decode(&b) != nil {
		return false, c.errAt(n, "%s must be true or false", what)
	}
	return b, nil
}

func (c compiler) integer(n *yaml.Node, what string) (int, error) {
	var i int
	if n.Kind != yaml.ScalarNode || n.Tag != "!!int" || n.Decode(&i) != nil {
		return 0, c.errAt(n, "%s must be a whole number", what)
	}
	return i, nil
}

func (c compiler) sequence(n *yaml.Node, what string) ([]*yaml.Node, error) {
	if n.Kind != yaml.SequenceNode {
		return nil, c.errAt(n, "%s must be a list", what)
	}
	return n.Content, nil
}

func joinList(ss []string) string {
	var b bytes.Buffer
	for i, s := range ss {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(s)
	}
	return b.String()
}
