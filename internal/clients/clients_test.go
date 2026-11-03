package clients

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the .golden files")

const testRover = "/opt/rover/bin/rover"

// fixture places a testdata config where an adapter looks for it, in a
// throwaway home and project directory.
type fixture struct {
	adapter, testdata string
	rel               func(home, cwd string) string
	wrapped, remote   int
}

var fixtures = []fixture{
	{NameClaudeCode, "claude-code.user.json", func(h, _ string) string { return filepath.Join(h, ".claude.json") }, 6, 1},
	{NameClaudeCode, "claude-code.project.json", func(_, c string) string { return filepath.Join(c, ".mcp.json") }, 1, 1},
	{NameCursor, "cursor.json", func(h, _ string) string { return filepath.Join(h, ".cursor", "mcp.json") }, 2, 1},
	{NameClaudeDesktop, "claude-desktop.json", func(h, _ string) string {
		return filepath.Join(h, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	}, 2, 0},
	{NameVSCode, "vscode.json", func(_, c string) string { return filepath.Join(c, ".vscode", "mcp.json") }, 1, 1},
}

func testEnv(t *testing.T) Env {
	t.Helper()
	root := t.TempDir()
	return Env{Home: filepath.Join(root, "home"), Cwd: filepath.Join(root, "proj"), GOOS: "darwin", BackupDir: filepath.Join(root, "state", "backups")}
}

func place(t *testing.T, env Env, f fixture) (ConfigFile, []byte) {
	t.Helper()
	orig, err := os.ReadFile(filepath.Join("testdata", f.testdata))
	if err != nil {
		t.Fatal(err)
	}
	p := f.rel(env.Home, env.Cwd)
	if err = os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p, orig, 0o644); err != nil { //nolint:gosec // G306: test fixture mimics a normal config's mode
		t.Fatal(err)
	}
	a, _ := Get(f.adapter, env)
	files, err := a.Detect()
	if err != nil {
		t.Fatal(err)
	}
	for _, cf := range files {
		if cf.Path == p {
			return cf, orig
		}
	}
	t.Fatalf("%s: Detect did not find %s (got %v)", f.adapter, p, files)
	return ConfigFile{}, nil
}

func install(t *testing.T, env Env, cf ConfigFile) Plan {
	t.Helper()
	a, _ := Get(cf.Adapter, env)
	doc, err := a.Read(cf)
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.Plan(doc, testRover)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(p); err != nil {
		t.Fatal(err)
	}
	return p
}

// Acceptance (M7): install then uninstall gives back the same bytes;
// install twice equals install once; comments, odd spacing and unknown keys
// survive; remote entries are left alone with a warning. The wrapped output
// is compared with a golden file.
func TestInstallUninstallGolden(t *testing.T) {
	for _, f := range fixtures {
		t.Run(f.testdata, func(t *testing.T) {
			env := testEnv(t)
			cf, orig := place(t, env, f)
			p := install(t, env, cf)
			if len(p.Changed) != f.wrapped {
				t.Errorf("wrapped %d servers %v, want %d", len(p.Changed), p.Changed, f.wrapped)
			}
			remote := 0
			for _, w := range p.Warnings {
				if strings.Contains(w, "remote server") {
					remote++
				}
			}
			if remote != f.remote {
				t.Errorf("remote warnings %d, want %d: %v", remote, f.remote, p.Warnings)
			}
			after, _ := os.ReadFile(cf.Path)
			golden := filepath.Join("testdata", f.testdata+".golden")
			if *update {
				_ = os.WriteFile(golden, after, 0o600) //nolint:gosec // G703: a path the test built under its own temp directory
			}
			want, err := os.ReadFile(golden) //nolint:gosec // G304: a testdata golden file
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, want) {
				t.Errorf("installed output differs from %s:\n%s", golden, after)
			}
			if !strings.Contains(p.Diff, "+++ ") || !strings.Contains(p.Diff, testRover) {
				t.Errorf("diff does not show the change:\n%s", p.Diff)
			}

			// Every server is now wrapped by this rover.
			doc, err := ReadConfig(cf)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range doc.Servers {
				if s.Status == StatusStdio {
					t.Errorf("%s still unwrapped", s.Label())
				}
			}
			// Install twice: nothing to do, nothing written.
			p2 := install(t, env, cf)
			if p2.HasChanges() || len(p2.Changed) != 0 {
				t.Errorf("second install is not a no-op: %v\n%s", p2.Changed, p2.Diff)
			}
			again, _ := os.ReadFile(cf.Path)
			if !bytes.Equal(again, after) {
				t.Error("second install changed the file")
			}
			// The in-place unwrap is the exact inverse too.
			up, err := PlanUnwrap(doc)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(up.New, orig) {
				t.Errorf("unwrap is not the inverse of wrap:\n%s", up.New)
			}
			// Uninstall from the backup.
			a, _ := Get(cf.Adapter, env)
			if err := a.Restore(cf); err != nil {
				t.Fatal(err)
			}
			restored, _ := os.ReadFile(cf.Path)
			if !bytes.Equal(restored, orig) {
				t.Errorf("uninstall is not byte-identical:\n%s", restored)
			}
			if fi, _ := os.Stat(cf.Path); fi.Mode().Perm() != 0o644 {
				t.Errorf("mode %v, want the original 0644", fi.Mode().Perm())
			}
		})
	}
}

func TestRestoreRefusesChangedFileAndCorruptBackup(t *testing.T) {
	env := testEnv(t)
	cf, _ := place(t, env, fixtures[2])
	install(t, env, cf)
	a, _ := Get(cf.Adapter, env)

	// Corrupt the backup: uninstall must refuse and say why.
	backups, _ := filepath.Glob(filepath.Join(backupDir(env, cf), "*[0-9].json"))
	if len(backups) != 1 {
		t.Fatalf("backups: %v", backups)
	}
	if err := os.WriteFile(backups[0], []byte(`{"mcpServers":{"evil":{"command":"sh"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(cf.Path)
	if err := a.Restore(cf); !errors.Is(err, ErrBackupCorrupt) {
		t.Fatalf("restore from a corrupt backup: %v", err)
	}
	if now, _ := os.ReadFile(cf.Path); !bytes.Equal(now, before) {
		t.Fatal("a refused restore changed the file")
	}

	// Change the file after install: restoring would discard the change.
	if err := os.WriteFile(cf.Path, append(before, ' '), 0o600); err != nil { //nolint:gosec // G703: a path the test built under its own temp directory
		t.Fatal(err)
	}
	if err := a.Restore(cf); !errors.Is(err, ErrChangedSinceInstall) {
		t.Fatalf("restore over a changed file: %v", err)
	}
}

func TestApplyRefusesFileChangedSincePlan(t *testing.T) {
	env := testEnv(t)
	cf, _ := place(t, env, fixtures[0])
	a, _ := Get(cf.Adapter, env)
	doc, _ := a.Read(cf)
	p, _ := a.Plan(doc, testRover)
	if err := os.WriteFile(cf.Path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(p); !errors.Is(err, ErrChangedSincePlan) {
		t.Fatalf("got %v", err)
	}
}

func TestBackupsKeepLastFive(t *testing.T) {
	env := testEnv(t)
	cf, _ := place(t, env, fixtures[3])
	for i := 0; i < 7; i++ {
		install(t, env, cf)
		doc, _ := ReadConfig(cf)
		up, err := PlanUnwrap(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := ApplyPlan(env, up); err != nil {
			t.Fatal(err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(backupDir(env, cf), "*[0-9].json"))
	if len(files) != KeepBackups {
		t.Fatalf("%d backups kept, want %d", len(files), KeepBackups)
	}
	for _, f := range files {
		if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, fi.Mode().Perm())
		}
	}
	got, errs := InstalledFiles(env.BackupDir)
	if len(errs) != 0 || len(got) != 1 || got[0].Path != cf.Path {
		t.Fatalf("InstalledFiles = %v, %v", got, errs)
	}
}

func TestForeignRoverIsLeftAloneWithWarning(t *testing.T) {
	env := testEnv(t)
	p := filepath.Join(env.Home, ".cursor", "mcp.json")
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	cfg := `{"mcpServers":{"fs":{"command":"/tmp/x/rover","args":["wrap","--name","fs","--","npx","fs"]}}}`
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := ReadConfig(ConfigFile{Adapter: NameCursor, Path: p})
	if err != nil {
		t.Fatal(err)
	}
	pl, err := planWrap(doc, testRover)
	if err != nil {
		t.Fatal(err)
	}
	if pl.HasChanges() || len(pl.Warnings) != 1 || !strings.Contains(pl.Warnings[0], "/tmp/x/rover") {
		t.Fatalf("plan %+v", pl)
	}
	if doc.Servers[0].WrappedBy(testRover) {
		t.Fatal("a look-alike rover counts as this rover")
	}
}

func TestDuplicateKeysAreRefused(t *testing.T) {
	for _, src := range []string{
		`{"mcpServers":{"a":{"command":"x"}},"mcpservers":{}}`,
		`{"mcpServers":{"a":{"command":"x","Command":"y"}}}`,
	} {
		d, err := parseDoc(cursorSpec, ConfigFile{}, []byte(src))
		if err == nil && (len(d.Servers) == 0 || d.Servers[0].Status != StatusUnknown) {
			t.Errorf("%s: accepted %+v", src, d.Servers)
		}
	}
}

func TestClaudeDesktopSkippedOffMac(t *testing.T) {
	env := testEnv(t)
	env.GOOS = "linux"
	a, _ := Get(NameClaudeDesktop, env)
	if _, err := a.Detect(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v", err)
	}
}

func TestBlankJSONC(t *testing.T) {
	in := "{\"a\": \"// not a comment\", /* x\n y */ \"b\": [1, 2,], // c\n}"
	out, err := blankJSONC([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(in) || !strings.Contains(string(out), `"// not a comment"`) || strings.Contains(string(out), "/*") {
		t.Fatalf("%q", out)
	}
	if _, err := objectRange(out, 0, len(out)); err != nil {
		t.Fatalf("blanked JSONC does not parse: %v", err)
	}
	if _, err := blankJSONC([]byte("{/* open")); err == nil {
		t.Fatal("unterminated comment accepted")
	}
}

func FuzzParseDoc(f *testing.F) {
	for _, fx := range fixtures {
		b, _ := os.ReadFile(filepath.Join("testdata", fx.testdata))
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, s := range specs {
			d, err := parseDoc(s, ConfigFile{Path: "x"}, b)
			if err != nil {
				continue
			}
			p, err := planWrap(d, testRover)
			if err != nil {
				continue
			}
			// Whatever wrap produced must still parse.
			if _, err := parseDoc(s, ConfigFile{Path: "x"}, p.New); err != nil {
				t.Fatalf("wrapped output does not parse: %v\n%q", err, p.New)
			}
		}
	})
}
