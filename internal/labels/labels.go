// Package labels decides which of the four tool labels (reads_private,
// reads_untrusted, egress, destructive) a tool carries, and says where that
// answer came from.
//
// Three sources, in order (plan M8):
//
//  1. built-in labels for well-known servers (known.yaml, embedded),
//  2. the user's labels from config.yaml or policy.yaml: a tool listed there
//     REPLACES its built-in labels (an empty list means "no labels"),
//  3. the conservative default for a tool nobody knows: reads_untrusted and
//     egress.
//
// LESSON (M8): the default is the dangerous-looking answer on purpose. A
// label is what lets the trifecta guard see a risk; a tool with no labels
// is invisible to it. If unknown tools had no labels, a server could hide an
// exfiltration tool from the guard just by giving it a new name. With this
// default, an unknown tool both taints the session (its result counts as
// untrusted) and is treated as a way out (egress).
package labels

import (
	"bytes"
	_ "embed"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// The four labels (plan §5.1).
const (
	ReadsPrivate   = "reads_private"
	ReadsUntrusted = "reads_untrusted"
	Egress         = "egress"
	Destructive    = "destructive"
)

// Where an effective label set came from.
const (
	SourceBuiltIn = "built-in"
	SourceConfig  = "config"
	SourceDefault = "default"
)

// Valid reports whether l is one of the four labels.
func Valid(l string) bool {
	switch l {
	case ReadsPrivate, ReadsUntrusted, Egress, Destructive:
		return true
	}
	return false
}

// Default is the label set of a tool no source knows.
func Default() []string { return []string{Egress, ReadsUntrusted} } // sorted, like every result

//go:embed known.yaml
var knownYAML []byte

type knownServer struct {
	Aliases []string            `yaml:"aliases"`
	Tools   map[string][]string `yaml:"tools"`
}

type knownFile struct {
	Servers map[string]knownServer `yaml:"servers"`
}

// builtIn maps every accepted server name (canonical names and aliases) to
// its canonical name, and canonical names to their tools.
type builtIn struct {
	names map[string]string
	tools map[string]map[string][]string
}

var known = mustParse(knownYAML)

func mustParse(b []byte) builtIn {
	k, err := parse(b)
	if err != nil {
		// known.yaml is compiled in; TestKnownYAMLParses catches this.
		panic(err)
	}
	return k
}

// parse reads known.yaml strictly: an unknown key or label is an error.
func parse(b []byte) (builtIn, error) {
	var f knownFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return builtIn{}, fmt.Errorf("known.yaml: %w", err)
	}
	k := builtIn{names: map[string]string{}, tools: map[string]map[string][]string{}}
	for name, s := range f.Servers {
		for _, n := range append([]string{name}, s.Aliases...) {
			if prev, dup := k.names[n]; dup {
				return builtIn{}, fmt.Errorf("known.yaml: server name %q used by %s and %s", n, prev, name)
			}
			k.names[n] = name
		}
		for tool, ls := range s.Tools {
			for _, l := range ls {
				if !Valid(l) {
					return builtIn{}, fmt.Errorf("known.yaml: %s.%s: unknown label %q", name, tool, l)
				}
			}
		}
		k.tools[name] = s.Tools
	}
	return k, nil
}

// Packaging prefixes and suffixes a configured server name may carry around
// a well-known name: "mcp-server-git", "server-github" or "github-mcp".
var (
	namePrefixes = []string{"mcp-server-", "server-"}
	nameSuffixes = []string{"-mcp-server", "-mcp"}
)

// KnownServer returns the canonical built-in name a configured server name
// matches, or "". The match is exact (case-sensitive) on the name or an
// alias; failing that, one packaging prefix and one suffix are removed and
// the rest must match exactly. Nothing fuzzier: the built-in labels are
// less conservative than the default, so a loose match would weaken it.
func KnownServer(server string) string {
	if c, ok := known.names[server]; ok {
		return c
	}
	trimmed := server
	for _, p := range namePrefixes {
		if t, ok := strings.CutPrefix(trimmed, p); ok {
			trimmed = t
			break
		}
	}
	for _, s := range nameSuffixes {
		if t, ok := strings.CutSuffix(trimmed, s); ok {
			trimmed = t
			break
		}
	}
	return known.names[trimmed]
}

// BuiltIn returns the built-in labels of one tool and whether there are any.
func BuiltIn(server, tool string) ([]string, bool) {
	c := KnownServer(server)
	if c == "" {
		return nil, false
	}
	ls, ok := known.tools[c][tool]
	return ls, ok
}

// Effective returns the labels of server.tool and their source. user is the
// configured labels (server -> tool -> labels), looked up by the exact
// configured server name. The result is a fresh, sorted slice.
func Effective(server, tool string, user map[string]map[string][]string) (labels []string, source string) {
	if ls, ok := user[server][tool]; ok {
		return sorted(ls), SourceConfig
	}
	if ls, ok := BuiltIn(server, tool); ok {
		return sorted(ls), SourceBuiltIn
	}
	return Default(), SourceDefault
}

// Tool is one row of a label listing.
type Tool struct {
	Server, Tool string
	Labels       []string
	Source       string
}

// List returns the effective labels of every tool some source names for
// server: its built-in tools and its configured tools, sorted by tool name.
// Tools no source names get Default; List cannot know them in advance.
func List(server string, user map[string]map[string][]string) []Tool {
	names := map[string]bool{}
	if c := KnownServer(server); c != "" {
		for t := range known.tools[c] {
			names[t] = true
		}
	}
	for t := range user[server] {
		names[t] = true
	}
	out := make([]Tool, 0, len(names))
	for t := range names {
		ls, src := Effective(server, t, user)
		out = append(out, Tool{Server: server, Tool: t, Labels: ls, Source: src})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out
}

// KnownServers returns the canonical built-in server names, sorted.
func KnownServers() []string {
	out := make([]string, 0, len(known.tools))
	for s := range known.tools {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func sorted(ls []string) []string {
	out := append([]string{}, ls...)
	sort.Strings(out)
	return out
}
