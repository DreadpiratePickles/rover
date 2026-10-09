package normalize

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/cedar-policy/cedar-go/types"
	"golang.org/x/text/unicode/norm"
)

const (
	// maxPathBytes is a generous PATH_MAX; longer input is rejected.
	maxPathBytes = 4096
	// maxSymlinkHops bounds symlink following, so a loop cannot spin forever.
	maxSymlinkHops = 255
	// maxPathItems bounds how many paths one array argument may hold.
	maxPathItems = 1024
)

// lookalikeSeparators are characters that look like "/" or "\" to a human
// (or to a server that applies NFKC folding) but are ordinary characters to
// the filesystem. We keep them literal, so "projects∕..∕.ssh" is one odd
// file name, never a traversal, and record a finding so policy can deny it.
const lookalikeSeparators = "∕／⁄⧸﹨＼"

// percentTraversal lists percent-encodings of '.', '/', '\' and NUL. Paths are
// never URL-decoded here, so "%2e%2e" is a literal name; but a server that
// does decode would see "..", so we reject these outright rather than guess.
var percentTraversal = []string{"%2e", "%2f", "%5c", "%00"}

func pathValue(v types.Value, roots []Root, fnd *findings) (types.RecordMap, error) {
	switch val := v.(type) {
	case types.String:
		return singlePath(string(val), roots, fnd)
	case types.Set:
		return pathSet(val, roots, fnd)
	default:
		return nil, errWrongType
	}
}

func singlePath(s string, roots []Root, fnd *findings) (types.RecordMap, error) {
	p, under, err := normPath(s, roots, fnd)
	if err != nil {
		return nil, err
	}
	rec := types.RecordMap{"path": types.String(p)}
	for i, r := range under {
		rec[types.String("under_"+roots[i].Name)] = types.Boolean(r)
	}
	return rec, nil
}

func pathSet(set types.Set, roots []Root, fnd *findings) (types.RecordMap, error) {
	if set.Len() > maxPathItems {
		return nil, fmt.Errorf("%d paths in one argument, limit %d", set.Len(), maxPathItems)
	}
	items := make([]string, 0, set.Len())
	for v := range set.All() {
		s, ok := v.(types.String)
		if !ok {
			return nil, errWrongType
		}
		items = append(items, string(s))
	}
	allUnder := make([]bool, len(roots))
	for i := range allUnder {
		allUnder[i] = len(items) > 0 // an empty list is never "all under": fail closed
	}
	paths := make([]types.Value, 0, len(items))
	for _, s := range items {
		p, under, err := normPath(s, roots, fnd)
		if err != nil {
			return nil, err
		}
		paths = append(paths, types.String(p))
		for i := range allUnder {
			allUnder[i] = allUnder[i] && i < len(under) && under[i]
		}
	}
	rec := types.RecordMap{
		"paths": types.NewSet(paths...),
		"count": types.Long(len(items)),
	}
	for i, r := range roots {
		rec[types.String("all_under_"+r.Name)] = types.Boolean(allUnder[i])
	}
	return rec, nil
}

// normPath returns the canonical form of s and, for each root, whether it
// lies inside that root. under is nil when there are no roots.
func normPath(s string, roots []Root, fnd *findings) (string, []bool, error) {
	if err := checkPathText(s); err != nil {
		return "", nil, err
	}
	if !norm.NFC.IsNormalString(s) {
		fnd.add("path_not_nfc")
		s = norm.NFC.String(s)
	}
	if strings.ContainsAny(s, lookalikeSeparators) {
		fnd.add("path_lookalike_separator")
	}
	if len(roots) == 0 {
		// Nothing to anchor to (e.g. GitHub repo-relative paths): clean only,
		// and do not touch the local filesystem.
		fnd.add("path_no_root")
		return filepath.Clean(s), nil, nil
	}
	if !isAbs(s) {
		fnd.add("path_relative")
		s = filepath.Join(roots[0].Path, s)
	}
	p, err := resolve(filepath.Clean(s))
	if err != nil {
		return "", nil, err
	}
	under := make([]bool, len(roots))
	for i, r := range roots {
		rp, rerr := resolve(filepath.Clean(r.Path))
		if rerr != nil {
			return "", nil, fmt.Errorf("root %q: %w", r.Name, rerr)
		}
		under[i] = within(rp, p)
	}
	return p, under, nil
}

func checkPathText(s string) error {
	if len(s) > maxPathBytes {
		return fmt.Errorf("path is %d bytes, limit %d", len(s), maxPathBytes)
	}
	if strings.IndexByte(s, 0) >= 0 {
		return errors.New("path contains a NUL byte")
	}
	if !utf8.ValidString(s) {
		return errors.New("path is not valid UTF-8")
	}
	lower := strings.ToLower(s)
	for _, enc := range percentTraversal {
		if strings.Contains(lower, enc) {
			return fmt.Errorf("path contains percent-encoded %q", enc)
		}
	}
	return nil
}

func isAbs(p string) bool { return filepath.IsAbs(p) }

// resolve follows every symlink in the absolute, cleaned path p, one
// component at a time, like filepath.EvalSymlinks. Unlike EvalSymlinks it
// also works when the tail of the path does not exist yet (write_file,
// create_directory): the nearest existing ancestor is resolved and the rest
// is appended. A dangling symlink is followed to its target too, because
// writing through it would create the file wherever it points.
func resolve(p string) (string, error) {
	vol := filepath.VolumeName(p)
	sep := string(filepath.Separator)
	resolved := vol + sep
	todo := splitPath(p[len(vol):])
	missing := false
	hops := 0
	for len(todo) > 0 {
		c := todo[0]
		todo = todo[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, c)
		if missing {
			resolved = next
			continue
		}
		fi, err := os.Lstat(next)
		if err != nil {
			if !isNotExist(err) {
				return "", fmt.Errorf("cannot inspect path: %w", err)
			}
			missing = true
			resolved = next
			continue
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			resolved = next
			continue
		}
		hops++
		if hops > maxSymlinkHops {
			return "", errors.New("too many symlinks (loop?)")
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", fmt.Errorf("cannot read symlink: %w", err)
		}
		if isAbs(target) {
			tv := filepath.VolumeName(target)
			resolved = tv + sep
			target = target[len(tv):]
		}
		todo = append(splitPath(target), todo...)
	}
	return resolved, nil
}

func splitPath(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool { return os.IsPathSeparator(uint8(r)) && r < utf8.RuneSelf })
}

func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

// within reports whether p is root or inside it. filepath.Rel gives a
// component-wise answer, so "/home/x/projects2" is NOT inside
// "/home/x/projects" (a plain string-prefix check would say it is).
func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil || isAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
