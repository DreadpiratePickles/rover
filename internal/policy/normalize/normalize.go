// Package normalize turns raw tool arguments into canonical values that a
// Cedar policy can compare safely. The results land in context.norm.
//
// # Why normalise before the policy runs?
//
// Cedar compares strings literally. A rule such as
//
//	context.args.path like "/home/me/projects/*"
//
// is fooled by "/home/me/projects/../.ssh/id_rsa": the text matches the
// pattern, but the file the server opens is outside projects. Cedar cannot
// see through "..", symlinks, Unicode look-alike characters or URL tricks,
// because it never touches the filesystem or parses URLs. So Rover does that
// work first, in Go, and hands the policy plain facts such as
// norm.path.under_projects == true. The policy then decides on what the
// server will actually do, not on what the text looks like.
//
// When something cannot be normalised safely, Apply either returns an error
// (the caller must deny the call with reason "norm_reject") or leaves the
// argument out of the result with a finding. A rule that needs a missing
// norm.<arg> cannot match, so the default-deny takes over: fail closed.
//
// # Output shape (context.norm.<arg>)
//
//	path (string):  {path: String, under_<root>: Bool for every root}
//	path (array):   {paths: Set<String>, count: Long, all_under_<root>: Bool}
//	                all_under_<root> is true only when the array is non-empty
//	                and every element is under that root. (Cedar sets of
//	                records are awkward to write rules for, hence the summary.)
//	url:            {scheme, host, port: String, has_query: Bool}
//	email:          {local, domain: String}
//	shell_command:  {command, program: String, has_metachar: Bool}
//	sql:            {statement: String (first keyword, upper case),
//	                 is_select: Bool, multi_statement: Bool}
//
// # Findings
//
// Findings are short strings recording something suspicious that was not
// fatal: path_not_nfc, path_relative, path_no_root,
// path_lookalike_separator, url_idn, email_idn and norm_<arg>_wrong_type /
// norm_<arg>_invalid (the argument was skipped).
package normalize

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"

	"github.com/cedar-policy/cedar-go/types"
)

// Kind names a normaliser.
type Kind string

// The normalisers this package provides.
const (
	KindPath         Kind = "path"
	KindURL          Kind = "url"
	KindEmail        Kind = "email"
	KindShellCommand Kind = "shell_command"
	KindSQL          Kind = "sql"
)

func (k Kind) valid() bool {
	switch k {
	case KindPath, KindURL, KindEmail, KindShellCommand, KindSQL:
		return true
	}
	return false
}

// Root is a directory a server is allowed to work in, such as
// {Name: "projects", Path: "/home/me/projects"}. Path must be absolute ("~"
// is expanded by the caller). Name must be a Cedar identifier, because it
// becomes the attribute name under_<Name>.
type Root struct{ Name, Path string }

// Result is what Apply produces. Norm maps an argument name to a Record of
// normalised fields (see the package comment); it becomes context.norm.
type Result struct {
	Norm     types.RecordMap
	Findings []string
}

// ErrReject is wrapped by every hard rejection from Apply. The caller must
// deny the call with reason "norm_reject".
var ErrReject = errors.New("norm_reject")

var rootNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Apply normalises the arguments named in rules. Arguments that are absent
// are skipped. An argument of the wrong JSON type gets the finding
// "norm_<arg>_wrong_type" and is skipped, so a rule that needs norm.<arg>
// denies. A non-nil error (always wrapping ErrReject) means the call must be
// denied: a NUL byte, userinfo in a URL, an unresolvable path, or a bad root.
func Apply(rules Rules, args types.Record, roots []Root) (Result, error) {
	if err := checkRoots(roots); err != nil {
		return Result{}, err
	}
	names := make([]string, 0, len(rules))
	for name := range rules {
		names = append(names, name)
	}
	sort.Strings(names)

	out := Result{Norm: types.RecordMap{}}
	fnd := &findings{}
	for _, name := range names {
		v, ok := args.Get(types.String(name))
		if !ok {
			continue
		}
		rec, err := applyOne(rules[name], name, v, roots, fnd)
		if err != nil {
			return Result{}, fmt.Errorf("%w: argument %q: %w", ErrReject, name, err)
		}
		if rec != nil {
			out.Norm[types.String(name)] = types.NewRecord(rec)
		}
	}
	out.Findings = fnd.list
	return out, nil
}

// errSkip tells applyOne's callers that the argument should be left out of
// the result; the finding has already been recorded.
var errSkip = errors.New("skip")

func applyOne(kind Kind, name string, v types.Value, roots []Root, fnd *findings) (types.RecordMap, error) {
	var rec types.RecordMap
	var err error
	switch kind {
	case KindPath:
		rec, err = pathValue(v, roots, fnd)
	case KindURL:
		rec, err = withString(v, func(s string) (types.RecordMap, error) { return normURL(s, fnd) })
	case KindEmail:
		rec, err = withString(v, func(s string) (types.RecordMap, error) { return normEmail(s, fnd) })
	case KindShellCommand:
		rec, err = withString(v, normShell)
	case KindSQL:
		rec, err = withString(v, normSQL)
	default:
		return nil, fmt.Errorf("unknown normaliser kind %q", kind)
	}
	switch {
	case errors.Is(err, errWrongType):
		fnd.add("norm_" + name + "_wrong_type")
		return nil, nil
	case errors.Is(err, errSkip):
		fnd.add("norm_" + name + "_invalid")
		return nil, nil
	case err != nil:
		return nil, err
	}
	return rec, nil
}

var errWrongType = errors.New("wrong type")

func withString(v types.Value, f func(string) (types.RecordMap, error)) (types.RecordMap, error) {
	s, ok := v.(types.String)
	if !ok {
		return nil, errWrongType
	}
	return f(string(s))
}

func checkRoots(roots []Root) error {
	for _, r := range roots {
		if !rootNameRE.MatchString(r.Name) {
			return fmt.Errorf("%w: root name %q is not a Cedar identifier", ErrReject, r.Name)
		}
		if !isAbs(r.Path) {
			return fmt.Errorf("%w: root %q path %q is not absolute", ErrReject, r.Name, r.Path)
		}
	}
	return nil
}

// findings is an ordered set of finding strings.
type findings struct{ list []string }

func (f *findings) add(s string) {
	if !slices.Contains(f.list, s) {
		f.list = append(f.list, s)
	}
}
