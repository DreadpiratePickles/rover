package learn

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cedar-policy/cedar-go/types"

	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
)

// shapeOf normalises args with rules (and a root, so paths are resolved)
// and returns the shape, as roverd records it.
func shapeOf(t *testing.T, rules normalize.Rules, args types.RecordMap, roots []normalize.Root) map[string]Arg {
	t.Helper()
	rec := types.NewRecord(args)
	res, err := normalize.Apply(rules, rec, roots)
	if err != nil {
		t.Fatal(err)
	}
	return Shape(rules, rec, types.NewRecord(res.Norm))
}

func TestShapeKeepsOnlyNormalisedFacts(t *testing.T) {
	// Arrange
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "p", "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	rawPath := dir + "/p/sub/../sub/a.txt" // not cleaned: the shape must hold the resolved path
	rules := normalize.Rules{
		"path": normalize.KindPath, "files": normalize.KindPath, "url": normalize.KindURL,
		"to": normalize.KindEmail, "cmd": normalize.KindShellCommand, "q": normalize.KindSQL,
	}
	args := types.RecordMap{
		"path":  types.String(rawPath),
		"files": types.NewSet(types.String(filepath.Join(dir, "p", "b")), types.String(filepath.Join(dir, "p", "a"))),
		"url":   types.String("https://user-data.example.com/secret?token=abc"),
		"to":    types.String("alice@example.org"),
		"cmd":   types.String("rm -rf /tmp/x"),
		"q":     types.String("select * from users where pw = 'hunter2'"),
	}

	// Act
	got := shapeOf(t, rules, args, []normalize.Root{{Name: "p", Path: filepath.Join(dir, "p")}})

	// Assert
	want := map[string]Arg{
		"path":  {Type: "path", Value: resolvedT(t, filepath.Join(dir, "p", "sub", "a.txt"))},
		"files": {Type: "path", Values: []string{resolvedT(t, filepath.Join(dir, "p", "a")), resolvedT(t, filepath.Join(dir, "p", "b"))}},
		"url":   {Type: "url", Value: "user-data.example.com"},
		"to":    {Type: "email", Value: "example.org"},
		"cmd":   {Type: "shell_command", Value: "rm"},
		"q":     {Type: "sql", Value: "SELECT"},
	}
	for k, w := range want {
		if g := got[k]; g.Type != w.Type || g.Value != w.Value || strings.Join(g.Values, ",") != strings.Join(w.Values, ",") {
			t.Errorf("%s: got %+v, want %+v", k, g, w)
		}
	}
	b, _ := json.Marshal(got)
	for _, secret := range []string{rawPath, "..", "token", "alice", "-rf", "hunter2"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("shape %s holds raw input %q", b, secret)
		}
	}
}

func resolvedT(t *testing.T, p string) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(d, filepath.Base(p))
}

func TestShapeOfArgumentsWithoutNormaliser(t *testing.T) {
	// Arrange
	args := types.RecordMap{
		"mode":   types.String("ro"),
		"branch": types.String("feature/x"), // '/' is not in the value pattern
		"state":  types.String("open"),
		"text":   types.String("hello"), // not an enum-like name: type only
		"id":     types.String("abc123"),
		"n":      types.Long(3),
		"ok":     types.True,
		"obj":    types.NewRecord(types.RecordMap{"a": types.String("b")}),
		"list":   types.NewSet(types.String("a")),
		"format": types.String("json"),
		"level":  types.String("a" + strings.Repeat("b", 32)), // 33 bytes: too long
	}

	// Act
	got := shapeOf(t, nil, args, nil)

	// Assert
	want := map[string]Arg{
		"mode": {Type: "string", Value: "ro"}, "branch": {Type: "string"}, "state": {Type: "string"},
		"text": {Type: "string"}, "id": {Type: "string"}, "n": {Type: "number"}, "ok": {Type: "boolean"},
		"obj": {Type: "object"}, "list": {Type: "array"}, "format": {Type: "string", Value: "json"}, "level": {Type: "string"},
	}
	for k, w := range want {
		if g := got[k]; g.Type != w.Type || g.Value != w.Value || g.Values != nil {
			t.Errorf("%s: got %+v, want %+v", k, g, w)
		}
	}
}

// The verifier's secrets: none may reach the bucket, even under an
// enum-like argument name.
func TestShapeNeverKeepsSecretShapedValues(t *testing.T) {
	secrets := []string{
		"sk_live_51HxQabcdEFGH1234", "sk_test_abc", "rk_live_x", "ghp_abcdefghijklmnop", "gho_x", "ghs_x", "ghu_x",
		"github_pat_11ABC", "xoxb-123-456", "xoxp-1", "AKIAIOSFODNN7EXAMPLE", "ASIAXYZ",
		"password=hunter2SuperSecret", "user:pw", "Zq8vR2mX7pL4kT9w", // high entropy, 16 chars
	}
	for _, sec := range secrets {
		for _, name := range []string{"mode", "type", "token", "password", "key"} {
			got := shapeOf(t, nil, types.RecordMap{types.String(name): types.String(sec)}, nil)
			if got[name].Value != "" {
				t.Errorf("%s=%q was kept", name, sec)
			}
			b, _ := json.Marshal(got)
			if strings.Contains(string(b), sec) {
				t.Errorf("%s=%q reached the shape: %s", name, sec, b)
			}
		}
	}
	if got := shapeOf(t, nil, types.RecordMap{"type": types.String("pull_request")}, nil); got["type"].Value != "pull_request" {
		t.Errorf("a plain enum value under an allowed name must be kept: %+v", got)
	}
}

func TestShapeOfFailedNormaliserKeepsOnlyType(t *testing.T) {
	// A path argument of the wrong type is skipped by the normaliser: the
	// shape must not fall back to the raw value.
	got := shapeOf(t, normalize.Rules{"path": normalize.KindPath}, types.RecordMap{"path": types.Long(7)}, nil)
	if g := got["path"]; g.Type != "number" || g.Value != "" || g.Values != nil {
		t.Fatalf("got %+v", got["path"])
	}
	if s := Shape(nil, types.NewRecord(nil), types.NewRecord(nil)); s != nil {
		t.Fatalf("no arguments: %v", s)
	}
}

func TestResourceShapeKeepsNoURI(t *testing.T) {
	// "uri" is not an enum-like name: a URI can carry a token.
	if got := ResourceShape("file:///x?token=abc"); got["uri"].Type != "string" || got["uri"].Value != "" {
		t.Fatalf("%+v", got)
	}
}

func TestKeyOrdersByTimeAndBoundsNames(t *testing.T) {
	ts := time.Unix(100, 5)
	k := Key("c", "s", "t", ts, 1)
	if !strings.HasPrefix(string(k), "c\x00s\x00t\x00") || keyTime(k) != 100_000_000_005 {
		t.Fatalf("key %q", k)
	}
	if string(Key("c", "s", "t", ts, 1)) >= string(Key("c", "s", "t", ts.Add(time.Nanosecond), 0)) {
		t.Fatal("keys of one tool must sort by time")
	}
	if n := len(Key(strings.Repeat("x", 10000), "s", "t", ts, 1)); n > 3*maxKeyPart+19 {
		t.Fatalf("key of %d bytes", n)
	}
}

func TestEncodeCappedDropsOldest(t *testing.T) {
	obs := []Observation{{Server: "old"}, {Server: "mid"}, {Server: "new"}}
	one, _ := json.Marshal(obs[2])
	b, dropped, err := EncodeCapped(obs, 2*len(one)+4)
	if err != nil || dropped != 1 {
		t.Fatalf("dropped %d, %v", dropped, err)
	}
	var back []Observation
	if err := json.Unmarshal(b, &back); err != nil || len(back) != 2 || back[0].Server != "mid" {
		t.Fatalf("%s: %v", b, err)
	}
}

// Re-verification LOW-1: "state" and "scope" are not enum-like enough, and
// a word that mixes digits and letters (8+ characters) looks like a secret.
func TestLiteralRejectsShortSecretsAndKeepsWords(t *testing.T) {
	for name, val := range map[string]string{"state": "open", "scope": "repo", "mode": "hunter2xyz", "kind": "Passw0rdX", "type": "x=y"} {
		if got := shapeOf(t, nil, types.RecordMap{types.String(name): types.String(val)}, nil); got[name].Value != "" {
			t.Errorf("%s=%q kept", name, val)
		}
	}
	got := shapeOf(t, nil, types.RecordMap{"branch": types.String("main"), "mode": types.String("fast"), "sort": types.String("desc"),
		"format": types.String("json"), "lang": types.String("go1"), "order": types.String("ascending")}, nil)
	for n, v := range map[string]string{"branch": "main", "mode": "fast", "sort": "desc", "format": "json", "lang": "go1", "order": "ascending"} {
		if got[n].Value != v {
			t.Errorf("%s=%q not kept: %+v", n, v, got[n])
		}
	}
}
