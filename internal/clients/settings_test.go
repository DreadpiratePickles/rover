package clients

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDenyRules(t *testing.T) {
	rules, err := DenyRules("/Users/a", "/Users/a/Library/Application Support/Rover", "/Users/a/Library/Application Support/Rover/state")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"Edit(~/Library/Application Support/Rover/**)",
		"Edit(~/Library/Application Support/Rover/state/**)",
		"Edit(~/.claude.json)",
		"Edit(~/.cursor/mcp.json)",
	}
	if len(rules) != len(want) {
		t.Fatalf("%v", rules)
	}
	for i := range want {
		if rules[i] != want[i] {
			t.Errorf("rule %d = %q, want %q", i, rules[i], want[i])
		}
	}
	if r, _ := DenyRules("/home/a", "/srv/rover", "/srv/rover"); r[0] != "Edit(//srv/rover/**)" || len(r) != 3 {
		t.Errorf("outside home: %v", r)
	}
	if _, err := DenyRules("/home/a", "/home/a/[x]", "/s"); err == nil {
		t.Error("gitignore metacharacters accepted")
	}
}

func TestPlanDenyMerges(t *testing.T) {
	rules := []string{"Edit(~/a/**)", "Edit(~/.claude.json)"}
	cases := map[string]string{
		"no permissions": "{\n  \"theme\": \"dark\",\n  \"env\": {\"X\": \"1\"}\n}\n",
		"no deny":        "{\n  \"permissions\": {\n    \"allow\": [\"Bash(npm test)\"]\n  }\n}\n",
		"deny lines":     "{\n  \"permissions\": {\n    \"deny\": [\n      \"Read(./.env)\",\n      \"Edit(~/a/**)\"\n    ]\n  },\n  \"model\": \"opus\"\n}\n",
		"deny inline":    `{"permissions":{"deny":[]}}`,
		"empty object":   `{}`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "settings.json")
			if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
			p, err := PlanDeny(path, rules)
			if err != nil {
				t.Fatal(err)
			}
			var v struct {
				Permissions struct{ Deny []string } `json:"permissions"`
			}
			if err := json.Unmarshal(p.New, &v); err != nil {
				t.Fatalf("result is not JSON: %v\n%s", err, p.New)
			}
			have := map[string]bool{}
			for _, r := range v.Permissions.Deny {
				if have[r] {
					t.Errorf("duplicate %q", r)
				}
				have[r] = true
			}
			for _, r := range rules {
				if !have[r] {
					t.Errorf("missing %q in\n%s", r, p.New)
				}
			}
			// Everything that was there is still there, byte for byte.
			if !bytes.Contains(p.New, []byte(src[:len(src)/3])) {
				t.Errorf("prefix not preserved:\n%s", p.New)
			}
			env := Env{BackupDir: filepath.Join(dir, "backups")}
			if err := ApplyPlan(env, p); err != nil {
				t.Fatal(err)
			}
			again, _ := PlanDeny(path, rules)
			if again.HasChanges() {
				t.Errorf("second merge is not a no-op:\n%s", again.Diff)
			}
			if err := Restore(env, p.File); err != nil {
				t.Fatal(err)
			}
			if b, _ := os.ReadFile(path); string(b) != src { //nolint:gosec // G304: the test's own temp file
				t.Errorf("restore is not byte-identical:\n%s", b)
			}
		})
	}
}

func TestPlanDenyCreatesAndRefuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude", "settings.json")
	p, err := PlanDeny(path, []string{"Edit(~/x)"})
	if err != nil || !p.Created {
		t.Fatalf("%+v %v", p, err)
	}
	env := Env{BackupDir: filepath.Join(dir, "backups")}
	if err := ApplyPlan(env, p); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("created %v %v", fi, err)
	}
	if err := Restore(env, p.File); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("restore did not remove the file rover created")
	}
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("{ // comment\n}"), 0o600)
	if _, err := PlanDeny(bad, []string{"Edit(~/x)"}); err == nil {
		t.Fatal("settings with a comment accepted (Claude Code rejects it)")
	}
}
