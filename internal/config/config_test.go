package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/policy"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMissingFileYieldsObserveDefaults(t *testing.T) {
	// Arrange
	dir := t.TempDir()

	// Act
	cfg, err := Load(dir)

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != policy.ModeObserve || len(cfg.Roots) != 0 {
		t.Fatalf("defaults = %+v", cfg)
	}
	if cfg.ToolNormalizers("filesystem", "read_file")["path"] != "path" {
		t.Fatal("built-in normalisers missing from defaults")
	}
}

func TestFullConfigParses(t *testing.T) {
	// Arrange
	dir := t.TempDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	write(t, dir, "norm.yaml", "servers:\n  echo:\n    read_file:\n      path: path\n")
	write(t, dir, FileName, `mode: enforce
roots:
  zeta: ~/z
  alpha: /tmp/a/../b
labels:
  filesystem:
    read_file: [reads_private]
  fetch:
    fetch: [reads_untrusted, egress]
normalizers: norm.yaml
`)

	// Act
	cfg, err := Load(dir)

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != policy.ModeEnforce {
		t.Fatalf("mode = %q", cfg.Mode)
	}
	if len(cfg.Roots) != 2 || cfg.Roots[0].Name != "zeta" || cfg.Roots[0].Path != filepath.Join(home, "z") || cfg.Roots[1].Path != "/tmp/b" {
		t.Fatalf("roots (file order, ~ expanded, cleaned) = %+v", cfg.Roots)
	}
	if got := cfg.ToolLabels("fetch", "fetch"); len(got) != 2 || got[1] != "egress" {
		t.Fatalf("labels = %v", got)
	}
	if cfg.ToolNormalizers("echo", "read_file")["path"] != "path" || cfg.ToolNormalizers("filesystem", "read_file") != nil {
		t.Fatalf("normalizers file must replace the built-in mapping: %+v", cfg.Normalizers)
	}
}

func TestRelativeRootIsMadeAbsolute(t *testing.T) {
	// Arrange
	cwd, _ := os.Getwd()

	// Act
	cfg, err := Parse([]byte("roots:\n  here: sub\n"), "/ignored")

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Roots[0].Path != filepath.Join(cwd, "sub") {
		t.Fatalf("root = %q", cfg.Roots[0].Path)
	}
}

func TestEmptyFileYieldsDefaults(t *testing.T) {
	cfg, err := Parse(nil, "")
	if err != nil || cfg.Mode != policy.ModeObserve {
		t.Fatalf("cfg %+v err %v", cfg, err)
	}
}

func TestInvalidConfigsAreRefused(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"unknown key":        {"mdoe: enforce\n", "mdoe"},
		"bad mode":           {"mode: block\n", "observe or enforce"},
		"root not ident":     {"roots:\n  my-projects: /tmp\n", "Cedar identifier"},
		"root digit first":   {"roots:\n  1p: /tmp\n", "Cedar identifier"},
		"root twice":         {"roots:\n  a: /x\n  a: /y\n", ""},
		"root empty path":    {"roots:\n  a: \"\"\n", "empty path"},
		"roots not mapping":  {"roots: [a]\n", "mapping"},
		"unknown label":      {"labels:\n  s:\n    t: [reads_secret]\n", "unknown label"},
		"two documents":      {"mode: observe\n---\nmode: enforce\n", "one YAML document"},
		"missing normalizer": {"normalizers: nope.yaml\n", "normalizers"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			_, err := Parse([]byte(tc.body), t.TempDir())

			// Assert
			if err == nil {
				t.Fatalf("%q was accepted", tc.body)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestBadNormalizersFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "n.yaml", "servers:\n  s:\n    t:\n      a: bogus\n")
	if _, err := Parse([]byte("normalizers: n.yaml\n"), dir); err == nil {
		t.Fatal("unknown normaliser kind accepted")
	}
}

func TestOversizedConfigIsRefused(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, FileName, "# "+strings.Repeat("x", maxConfigBytes)+"\n")
	if _, err := Load(dir); err == nil {
		t.Fatal("oversized config accepted")
	}
}

func TestPolicySettingsOverrideConfig(t *testing.T) {
	// Arrange
	base, err := Parse([]byte("mode: observe\nroots:\n  old: /old\nlabels:\n  a:\n    b: [egress]\n"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := PolicySettings{
		Mode:      "enforce",
		RootOrder: []string{"lab", "projects"},
		Roots:     map[string]string{"lab": "/srv/lab", "projects": "/p"},
		Labels:    map[string]map[string][]string{"fs": {"read_file": {"reads_private"}}},
	}

	// Act
	got, err := base.WithPolicySettings(s)

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != policy.ModeEnforce || len(got.Roots) != 2 || got.Roots[0].Name != "lab" || got.Roots[0].Path != "/srv/lab" {
		t.Errorf("got %+v", got)
	}
	if got.ToolLabels("fs", "read_file")[0] != "reads_private" || got.ToolLabels("a", "b") != nil {
		t.Errorf("labels %v", got.Labels)
	}
	if base.Mode != policy.ModeObserve || base.Roots[0].Name != "old" {
		t.Errorf("base was modified: %+v", base)
	}
}

func TestEmptyPolicySettingsKeepConfig(t *testing.T) {
	// Arrange
	base, err := Parse([]byte("mode: enforce\nroots:\n  old: /old\n"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// Act
	got, err := base.WithPolicySettings(PolicySettings{})

	// Assert
	if err != nil || got.Mode != policy.ModeEnforce || got.Roots[0].Name != "old" {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestPolicySettingsRejectBadValues(t *testing.T) {
	for name, s := range map[string]PolicySettings{
		"mode":          {Mode: "audit"},
		"relative root": {RootOrder: []string{"a"}, Roots: map[string]string{"a": ""}},
		"missing path":  {RootOrder: []string{"a"}},
		"bad label":     {Labels: map[string]map[string][]string{"s": {"t": {"nope"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			// Act
			_, err := Default().WithPolicySettings(s)

			// Assert
			if err == nil {
				t.Fatal("want an error")
			}
		})
	}
}
