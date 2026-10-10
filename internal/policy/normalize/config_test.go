package normalize

import (
	"strings"
	"testing"
)

func TestBuiltInParsesAndNamesOfficialTools(t *testing.T) {
	// Act
	cfg := BuiltIn()

	// Assert
	want := map[string]map[string]Rules{
		"filesystem": {
			"read_file": {"path": KindPath}, "read_text_file": {"path": KindPath}, "read_media_file": {"path": KindPath},
			"write_file": {"path": KindPath}, "edit_file": {"path": KindPath}, "create_directory": {"path": KindPath},
			"list_directory": {"path": KindPath}, "list_directory_with_sizes": {"path": KindPath},
			"directory_tree": {"path": KindPath}, "search_files": {"path": KindPath}, "get_file_info": {"path": KindPath},
			"read_multiple_files": {"paths": KindPath},
			"move_file":           {"source": KindPath, "destination": KindPath},
		},
		"fetch": {"fetch": {"url": KindURL}},
		"github": {
			"create_or_update_file": {"path": KindPath}, "delete_file": {"path": KindPath}, "get_file_contents": {"path": KindPath},
		},
		"git": {"git_add": {"repo_path": KindPath, "files": KindPath}},
	}
	for _, tool := range []string{"git_status", "git_diff_unstaged", "git_diff_staged", "git_diff", "git_commit", "git_reset",
		"git_log", "git_create_branch", "git_checkout", "git_show", "git_branch"} {
		want["git"][tool] = Rules{"repo_path": KindPath}
	}
	for server, tools := range want {
		if len(cfg.Servers[server]) != len(tools) {
			t.Errorf("%s: %d tools, want %d", server, len(cfg.Servers[server]), len(tools))
		}
		for tool, rules := range tools {
			got := cfg.Servers[server][tool]
			if len(got) != len(rules) {
				t.Errorf("%s/%s = %v, want %v", server, tool, got, rules)
			}
			for arg, kind := range rules {
				if got[arg] != kind {
					t.Errorf("%s/%s.%s = %q, want %q", server, tool, arg, got[arg], kind)
				}
			}
		}
	}
}

func TestBuiltInReturnsIndependentCopies(t *testing.T) {
	a := BuiltIn()
	a.Servers["fetch"]["fetch"]["url"] = KindSQL
	if BuiltIn().Servers["fetch"]["fetch"]["url"] != KindURL {
		t.Fatal("mutating one BuiltIn result changed another")
	}
}

func TestParseRejectsBadConfig(t *testing.T) {
	cases := map[string]string{
		"unknown top-level key": "servers: {}\nextra: 1\n",
		"typo in servers":       "server:\n  x:\n    t: {a: path}\n",
		"unknown kind":          "servers:\n  x:\n    t: {a: pathh}\n",
		"empty":                 "",
		"two documents":         "servers: {}\n---\nservers: {}\n",
		"too big":               "servers: {}\n#" + strings.Repeat("x", maxConfigBytes),
	}
	for name, in := range cases {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: Parse accepted %q", name, in[:min(len(in), 40)])
		}
	}
}

func TestParseAcceptsValidConfig(t *testing.T) {
	cfg, err := Parse([]byte("servers:\n  db:\n    query: {sql: sql}\n    mail: {to: email}\n    run: {cmd: shell_command}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Servers["db"]["query"]["sql"] != KindSQL || cfg.Servers["db"]["run"]["cmd"] != KindShellCommand {
		t.Fatalf("cfg = %v", cfg)
	}
}
