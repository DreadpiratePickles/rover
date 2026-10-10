package clients

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for the M7 verification findings (H2, H3, M1, M2, M3, M4, LOW).

func mustParse(t *testing.T, s spec, src string) Doc {
	t.Helper()
	d, err := parseDoc(s, ConfigFile{Path: "x", Scope: "project"}, []byte(src))
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}
	return d
}

// M4: the in-place unwrap is the exact inverse of the wrap, including an
// empty args array right after command, a multi-line empty array, white
// space before a line break, a missing args member and a key of "--".
func TestUnwrapIsExactInverse(t *testing.T) {
	for _, src := range []string{
		`{"mcpServers": {"a": {"command": "x", "args": []}}}`,
		`{"mcpServers": {"a": {"command": "x", "args": [` + "\n" + `]}}}`,
		`{"mcpServers": {"a": {"command": "x", "args": [ ` + "\n" + ` "y"]}}}`,
		`{"mcpServers": {"a": {"command": "x"}}}`,
		`{"mcpServers": {"a": {"command": "x", "env": {}}}}`,
		`{"mcpServers": {"--": {"command": "x", "args": ["--", "y"]}}}`,
		`{"mcpServers": {"--": {"command": "x"}}}`,
		`{"mcpServers": {"a": {"args": ["--name", "z"], "command": "x"}}}`,
	} {
		d := mustParse(t, cursorSpec, src)
		p, err := planWrap(d, testRover)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		w := mustParse(t, cursorSpec, string(p.New))
		if w.Servers[0].Status != StatusWrapped {
			t.Fatalf("%s: not wrapped: %s", src, p.New)
		}
		if again, _ := planWrap(w, testRover); again.HasChanges() {
			t.Errorf("%s: second wrap changes it", src)
		}
		u, err := PlanUnwrap(w)
		if err != nil {
			t.Fatalf("%s: unwrap: %v", src, err)
		}
		if string(u.New) != src {
			t.Errorf("unwrap is not the inverse:\n orig %s\n wrap %s\n back %s", src, p.New, u.New)
		}
	}
}

// H2: a server rover cannot understand makes install refuse the whole file.
// M3: an explicit type decides; url with no type is an error status.
func TestUnknownServerRefusesInstall(t *testing.T) {
	cases := map[string]Status{
		`{"mcpServers": {"a": {"command": "x", "Command": "y"}}}`:              StatusUnknown,
		`{"mcpServers": {"a": {"url": "https://x"}}}`:                          StatusUnknown,
		`{"mcpServers": {"a": {"type": "stdio", "command": "x", "url": "u"}}}`: StatusStdio,
		`{"mcpServers": {"a": {"type": "http", "url": "https://x"}}}`:          StatusRemote,
		`{"mcpServers": {"a": {"type": "stdio", "url": "u"}}}`:                 StatusUnknown,
		`{"mcpServers": {"a": {"type": "carrier-pigeon", "command": "x"}}}`:    StatusUnknown,
	}
	for src, want := range cases {
		d := mustParse(t, cursorSpec, src)
		if got := d.Servers[0].Status; got != want {
			t.Errorf("%s: status %s, want %s (%s)", src, got, want, d.Servers[0].Problem)
		}
		_, err := planWrap(d, testRover)
		if (want == StatusUnknown) != errors.Is(err, ErrNotUnderstood) {
			t.Errorf("%s: plan error %v", src, err)
		}
	}
}

// LOW: two keys that sanitise to the same --name are refused.
func TestNameCollisionRefused(t *testing.T) {
	d := mustParse(t, cursorSpec, `{"mcpServers": {"a b": {"command": "x"}, "a_b": {"command": "y"}}}`)
	if _, err := planWrap(d, testRover); !errors.Is(err, ErrNameCollision) {
		t.Fatalf("got %v", err)
	}
	// The same key in two scopes (Claude Code user and local) is one name.
	d = mustParse(t, claudeCodeSpec, `{"mcpServers": {"fs": {"command": "x"}}, "projects": {"/p": {"mcpServers": {"fs": {"command": "x"}}}}}`)
	if _, err := planWrap(d, testRover); err != nil {
		t.Fatalf("same key in two scopes refused: %v", err)
	}
}

// LOW: servers in a project .mcp.json are labelled "project".
func TestProjectScopeLabel(t *testing.T) {
	d, err := parseDoc(claudeCodeSpec, ConfigFile{Path: "x", Scope: "project"}, []byte(`{"mcpServers": {"a": {"command": "x"}}}`))
	if err != nil || d.Servers[0].Label() != "project/a" {
		t.Fatalf("%v %v", d.Servers, err)
	}
}

// M1: env values (and headers) never appear in a diff, context included,
// in pretty and minified files.
func TestDiffRedactsEnv(t *testing.T) {
	orig, _ := os.ReadFile(filepath.Join("testdata", "claude-desktop.json"))
	d := mustParse(t, claudeDesktopSpec, string(orig))
	p, err := planWrap(d, testRover)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.Diff, `"..."`) || !strings.Contains(p.Diff, `"BRAVE_API_KEY": "[redacted]"`) {
		t.Fatalf("diff leaks or does not show the env key:\n%s", p.Diff)
	}
	minified := `{"mcpServers":{"a":{"command":"x","env":{"TOKEN":"s3cret","N":{"deep":"s3cret"}},"args":["s3cret-arg"]},"r":{"type":"http","url":"u","headers":{"Authorization":"Bearer s3cret"}}}}`
	p, err = planWrap(mustParse(t, cursorSpec, minified), testRover)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ReplaceAll(p.Diff, "s3cret-arg", ""), "s3cret") {
		t.Fatalf("minified diff leaks:\n%s", p.Diff)
	}
	if !bytes.Contains(p.New, []byte(`"TOKEN":"s3cret"`)) {
		t.Fatal("redaction changed the file itself")
	}
}

// H3: install a, add b, install again, uninstall: no rover-wrapped server
// is left, and the file is the original with b added.
func TestStackedInstallsUninstallClean(t *testing.T) {
	env := testEnv(t)
	cfg := filepath.Join(env.Home, ".cursor", "mcp.json")
	_ = os.MkdirAll(filepath.Dir(cfg), 0o700)
	orig := "{\n  \"mcpServers\": {\n    \"a\": {\"command\": \"x\"}\n  }\n}\n"
	withB := "{\n  \"mcpServers\": {\n    \"a\": {\"command\": \"x\"},\n    \"b\": {\"command\": \"y\", \"args\": [\"1\"]}\n  }\n}\n"
	if err := os.WriteFile(cfg, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	cf := ConfigFile{Adapter: NameCursor, Path: cfg, Scope: "global"}
	install(t, env, cf)
	cur, _ := os.ReadFile(cfg) //nolint:gosec // G304: the test's own temp file
	added := strings.Replace(string(cur), "\n  }\n}", ",\n    \"b\": {\"command\": \"y\", \"args\": [\"1\"]}\n  }\n}", 1)
	if err := os.WriteFile(cfg, []byte(added), 0o600); err != nil { //nolint:gosec // G703: a path the test built under its own temp directory
		t.Fatal(err)
	}
	install(t, env, cf)
	steps, err := Uninstall(env, cf)
	if err != nil {
		t.Fatalf("uninstall: %v (%v)", err, steps)
	}
	got, _ := os.ReadFile(cfg) //nolint:gosec // G304: the test's own temp file
	if string(got) != withB {
		t.Fatalf("after uninstall:\n%s\nwant\n%s\nsteps %v", got, withB, steps)
	}
	if len(steps) < 2 {
		t.Errorf("steps %v: want a restore and an in-place unwrap", steps)
	}
}

// M2: one bad manifest is reported and the others are still listed.
func TestInstalledFilesSurvivesBadManifest(t *testing.T) {
	env := testEnv(t)
	cf, _ := place(t, env, fixtures[3])
	install(t, env, cf)
	bad := filepath.Join(env.BackupDir, NameCursor, "deadbeef")
	_ = os.MkdirAll(bad, 0o700)
	if err := os.WriteFile(filepath.Join(bad, "manifest.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, errs := InstalledFiles(env.BackupDir)
	if len(files) != 1 || len(errs) != 1 || !strings.Contains(errs[0].Error(), bad) {
		t.Fatalf("files %v errs %v", files, errs)
	}
}
