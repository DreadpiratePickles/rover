package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/cedar-policy/cedar-go/x/exp/schema"

	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
)

// SchemaExtension is the part of the Cedar schema that depends on
// configuration: which roots exist and which tool arguments policies may
// read. SchemaFor turns it into the Args, Norm, NormPath and NormPaths
// declarations.
//
// LESSON (M3): Cedar has no "any record" type, so the schema has to name
// every attribute a policy may read. If the schema were fixed, a root named
// "lab" in config.yaml could never be used in a policy (strict validation
// would reject `under_lab` as unknown). Generating these four declarations
// from the same config that drives the normalisers keeps the two in step.
type SchemaExtension struct {
	Roots         []string // root names; each gives under_<r> and all_under_<r>
	ArgNames      []string // context.args.<name>, all String
	NormPathArgs  []string // context.norm.<name> is a NormPath
	NormPathsArgs []string // context.norm.<name> is a NormPaths
	NormURLArgs   []string // context.norm.<name> is a NormURL
}

// DefaultArgNames are the raw arguments every schema declares under
// context.args. Policies should prefer context.norm; these exist for
// arguments no normaliser covers (a GitHub owner or repo, for example).
var DefaultArgNames = []string{"branch", "owner", "path", "query", "repo", "url"}

// pluralPathArgs are path arguments that carry a list of paths, so their
// normalised form is a NormPaths (paths, count, all_under_<r>) rather than a
// NormPath. The normaliser decides by the JSON value (string or array); the
// schema has to decide by name, and these are the list-valued names of the
// official servers.
var pluralPathArgs = map[string]bool{"files": true, "paths": true}

// DefaultSchemaExtension is what the shipped schema.cedarschema declares:
// one root named "projects" and the built-in normalisers.
func DefaultSchemaExtension() SchemaExtension {
	return NewSchemaExtension([]string{"projects"}, normalize.BuiltIn())
}

// NewSchemaExtension derives the extension from the configured root names
// and the normaliser config. Argument names are de-duplicated and sorted, so
// the same config always yields byte-identical schema text.
func NewSchemaExtension(roots []string, nc normalize.Config) SchemaExtension {
	ext := SchemaExtension{Roots: append([]string(nil), roots...), ArgNames: append([]string(nil), DefaultArgNames...)}
	for _, tools := range nc.Servers {
		for _, rules := range tools {
			for arg, kind := range rules {
				switch {
				case kind == normalize.KindPath && pluralPathArgs[arg]:
					ext.NormPathsArgs = append(ext.NormPathsArgs, arg)
				case kind == normalize.KindPath:
					ext.NormPathArgs = append(ext.NormPathArgs, arg)
				case kind == normalize.KindURL:
					ext.NormURLArgs = append(ext.NormURLArgs, arg)
				}
			}
		}
	}
	ext.NormPathArgs = uniqueSorted(ext.NormPathArgs)
	ext.NormPathsArgs = uniqueSorted(ext.NormPathsArgs)
	ext.NormURLArgs = uniqueSorted(ext.NormURLArgs)
	ext.ArgNames = uniqueSorted(ext.ArgNames)
	return ext
}

// RootNames returns the names of roots, in order.
func RootNames(roots []normalize.Root) []string {
	out := make([]string, len(roots))
	for i, r := range roots {
		out[i] = r.Name
	}
	return out
}

func uniqueSorted(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	cp := append([]string(nil), ss...)
	sort.Strings(cp)
	out := cp[:1]
	for _, s := range cp[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// identRE is a Cedar identifier. Reserved words are refused separately.
var identRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

var cedarReserved = map[string]bool{
	"true": true, "false": true, "if": true, "then": true, "else": true,
	"in": true, "is": true, "like": true, "has": true, "__cedar": true,
}

// generatedTypes are the declarations SchemaFor replaces, in output order.
var generatedTypes = []string{"Args", "NormPath", "NormPaths", "Norm"}

// typeDeclRE matches one `type <Name> = { ... };` declaration. The bodies
// SchemaFor replaces contain no nested braces (they refer to named types).
var typeDeclRE = regexp.MustCompile(`(?m)^type[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*\{[^{}]*\};`)

// SchemaFor returns base with the Args, Norm, NormPath and NormPaths
// declarations rewritten from ext. Every generated attribute is optional,
// so a missing argument is "has is false" and never an evaluation error.
// The result is parsed and resolved before it is returned.
//
// It is an error (fail closed) if base does not declare each of the four
// types exactly once, if a name is not a Cedar identifier, or if one
// argument name is declared with two different kinds.
func SchemaFor(base []byte, ext SchemaExtension) ([]byte, error) {
	decls, err := extensionDecls(ext)
	if err != nil {
		return nil, fmt.Errorf("%w: schema: %w", ErrLoad, err)
	}
	found := map[string]int{}
	out := typeDeclRE.ReplaceAllFunc(base, func(m []byte) []byte {
		name := string(typeDeclRE.FindSubmatch(m)[1])
		d, ok := decls[name]
		if !ok {
			return m
		}
		found[name]++
		return []byte(d)
	})
	for _, name := range generatedTypes {
		if found[name] != 1 {
			return nil, fmt.Errorf("%w: schema: base must declare `type %s = { ... };` exactly once (found %d)", ErrLoad, name, found[name])
		}
	}
	var s schema.Schema
	s.SetFilename("schema.cedarschema")
	if err := s.UnmarshalCedar(out); err != nil {
		return nil, fmt.Errorf("%w: generated schema: %w", ErrLoad, err)
	}
	if _, err := s.Resolve(); err != nil {
		return nil, fmt.Errorf("%w: generated schema: %w", ErrLoad, err)
	}
	return out, nil
}

// extensionDecls renders the four declarations.
func extensionDecls(ext SchemaExtension) (map[string]string, error) {
	kinds := map[string]string{}
	for _, l := range []struct {
		names []string
		typ   string
	}{{ext.NormPathArgs, "NormPath"}, {ext.NormPathsArgs, "NormPaths"}, {ext.NormURLArgs, "NormURL"}} {
		for _, n := range l.names {
			if prev, dup := kinds[n]; dup && prev != l.typ {
				return nil, fmt.Errorf("argument %q is normalised as both %s and %s", n, prev, l.typ)
			}
			kinds[n] = l.typ
		}
	}
	for _, list := range [][]string{ext.Roots, ext.ArgNames, ext.NormPathArgs, ext.NormPathsArgs, ext.NormURLArgs} {
		for _, n := range list {
			if !identRE.MatchString(n) || cedarReserved[n] {
				return nil, fmt.Errorf("%q is not a Cedar identifier (letters, digits, _; not starting with a digit; not a reserved word)", n)
			}
		}
	}
	roots := uniqueSorted(ext.Roots)
	pathAttrs := []string{"path?: String"}
	pathsAttrs := []string{"paths?: Set<String>", "count?: Long"}
	for _, r := range roots {
		pathAttrs = append(pathAttrs, "under_"+r+"?: Bool")
		pathsAttrs = append(pathsAttrs, "all_under_"+r+"?: Bool")
	}
	normNames := make([]string, 0, len(kinds))
	for n := range kinds {
		normNames = append(normNames, n)
	}
	sort.Strings(normNames)
	normAttrs := make([]string, 0, len(normNames))
	for _, n := range normNames {
		normAttrs = append(normAttrs, n+"?: "+kinds[n])
	}
	argAttrs := make([]string, 0, len(ext.ArgNames))
	for _, n := range uniqueSorted(ext.ArgNames) {
		argAttrs = append(argAttrs, n+"?: String")
	}
	return map[string]string{
		"Args":      record("Args", argAttrs),
		"NormPath":  record("NormPath", pathAttrs),
		"NormPaths": record("NormPaths", pathsAttrs),
		"Norm":      record("Norm", normAttrs),
	}, nil
}

func record(name string, attrs []string) string {
	if len(attrs) == 0 {
		return "type " + name + " = {};"
	}
	return "type " + name + " = {\n  " + strings.Join(attrs, ",\n  ") + "\n};"
}
