package labels

import (
	"slices"
	"strings"
	"testing"
)

func TestKnownYAMLParses(t *testing.T) {
	// Act
	k, err := parse(knownYAML)

	// Assert
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"filesystem", "fetch", "git", "github", "memory", "slack", "postgres", "puppeteer", "playwright", "brave-search", "time", "sequentialthinking"} {
		if len(k.tools[s]) == 0 {
			t.Errorf("known.yaml has no tools for %s", s)
		}
	}
}

func TestParseRejectsUnknownLabelsAndKeys(t *testing.T) {
	for name, src := range map[string]string{
		"unknown label":  "servers:\n  x:\n    tools:\n      t: [reads_secret]\n",
		"unknown key":    "servers:\n  x:\n    tool:\n      t: []\n",
		"duplicate name": "servers:\n  x:\n    aliases: [y]\n  y:\n    tools: {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parse([]byte(src)); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestEffectivePrecedence(t *testing.T) {
	user := map[string]map[string][]string{
		"filesystem": {"read_file": {"egress", "reads_private"}, "write_file": {}},
		"mine":       {"lookup": {"reads_private"}},
	}
	for _, tc := range []struct {
		name, server, tool string
		want               []string
		source             string
	}{
		{"built-in", "filesystem", "list_directory", []string{"reads_private"}, SourceBuiltIn},
		{"built-in two labels", "github", "delete_repository", []string{"destructive", "egress"}, SourceBuiltIn},
		{"github issue read is private and untrusted", "github", "get_issue", []string{"reads_private", "reads_untrusted"}, SourceBuiltIn},
		{"github file read is private and untrusted", "github", "get_file_contents", []string{"reads_private", "reads_untrusted"}, SourceBuiltIn},
		{"slack history is private and untrusted", "slack", "slack_get_channel_history", []string{"reads_private", "reads_untrusted"}, SourceBuiltIn},
		{"memory read is private and untrusted", "memory", "read_graph", []string{"reads_private", "reads_untrusted"}, SourceBuiltIn},
		{"postgres rows are private and untrusted", "postgres", "query", []string{"reads_private", "reads_untrusted"}, SourceBuiltIn},
		{"built-in no labels", "time", "get_current_time", []string{}, SourceBuiltIn},
		{"user replaces built-in", "filesystem", "read_file", []string{"egress", "reads_private"}, SourceConfig},
		{"user empty list means none", "filesystem", "write_file", []string{}, SourceConfig},
		{"user labels an unknown server", "mine", "lookup", []string{"reads_private"}, SourceConfig},
		{"unknown tool of a known server", "filesystem", "read_and_upload", []string{"egress", "reads_untrusted"}, SourceDefault},
		{"unknown server", "mail", "send", []string{"egress", "reads_untrusted"}, SourceDefault},
		{"unknown tool of a user server", "mine", "other", []string{"egress", "reads_untrusted"}, SourceDefault},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got, src := Effective(tc.server, tc.tool, user)

			// Assert
			if !slices.Equal(got, tc.want) || src != tc.source {
				t.Fatalf("Effective(%s, %s) = %v %s, want %v %s", tc.server, tc.tool, got, src, tc.want, tc.source)
			}
		})
	}
}

func TestEffectiveDoesNotShareSlices(t *testing.T) {
	// Arrange
	user := map[string]map[string][]string{"x": {"t": {"egress"}}}

	// Act
	a, _ := Effective("x", "t", user)
	a[0] = "reads_private"
	b, _ := Effective("x", "t", user)
	d, _ := Effective("x", "u", nil)
	d[0] = "destructive"

	// Assert
	if b[0] != "egress" || Default()[0] != Egress {
		t.Fatal("callers must not be able to edit the sources")
	}
}

func TestServerNameSuffixTolerance(t *testing.T) {
	for in, want := range map[string]string{
		"git":                     "git",
		"mcp-server-git":          "git",
		"git-mcp":                 "git",
		"server-github":           "github",
		"github-mcp-server":       "github",
		"mcp-server-brave-search": "brave-search",
		"brave":                   "brave-search",
		"sequential-thinking":     "sequentialthinking",
		"fs":                      "filesystem",
		"Git":                     "", // exact case only
		"gitlab":                  "",
		"my-git":                  "",
		"mcp-server-":             "",
		"files":                   "",
	} {
		if got := KnownServer(in); got != want {
			t.Errorf("KnownServer(%q) = %q, want %q", in, got, want)
		}
	}
	if ls, src := Effective("mcp-server-git", "git_commit", nil); src != SourceBuiltIn || !slices.Equal(ls, []string{"destructive"}) {
		t.Fatalf("suffix-tolerant lookup: %v %s", ls, src)
	}
}

func TestUserLabelsUseTheExactConfiguredName(t *testing.T) {
	// A user label for "git" does not apply to a server configured as
	// "git-mcp": config.yaml names servers exactly as `rover wrap --name`.
	user := map[string]map[string][]string{"git": {"git_commit": {}}}
	if _, src := Effective("git-mcp", "git_commit", user); src != SourceBuiltIn {
		t.Fatalf("source = %s", src)
	}
}

func TestListMergesSources(t *testing.T) {
	// Arrange
	user := map[string]map[string][]string{"fetch": {"fetch": {"reads_untrusted"}, "extra": {"egress"}}}

	// Act
	rows := List("fetch", user)

	// Assert
	var got []string
	for _, r := range rows {
		got = append(got, r.Tool+"="+strings.Join(r.Labels, ",")+"/"+r.Source)
	}
	want := []string{"extra=egress/config", "fetch=reads_untrusted/config"}
	if !slices.Equal(got, want) {
		t.Fatalf("List = %v, want %v", got, want)
	}
	if len(List("nobody", nil)) != 0 || len(KnownServers()) != 12 {
		t.Fatalf("unknown server must list nothing; known servers = %v", KnownServers())
	}
}

// HIGH-2 (review): every read of a server that holds both the user's data
// and other people's text must carry both labels, or a chain on that one
// server (read an issue, read a private file, open a PR) never trips the
// guard.
func TestMixedServersReadsCarryBothLabels(t *testing.T) {
	for server, tools := range map[string][]string{
		"github": {"get_file_contents", "get_issue", "get_pull_request", "get_pull_request_comments", "get_pull_request_files",
			"get_pull_request_reviews", "get_pull_request_status", "list_commits", "list_issues", "list_pull_requests",
			"search_code", "search_issues", "search_repositories"},
		"slack":    {"slack_get_channel_history", "slack_get_thread_replies", "slack_list_channels", "slack_get_users", "slack_get_user_profile"},
		"memory":   {"read_graph", "search_nodes", "open_nodes"},
		"postgres": {"query"},
	} {
		for _, tool := range tools {
			ls, _ := BuiltIn(server, tool)
			if !slices.Contains(ls, ReadsPrivate) || !slices.Contains(ls, ReadsUntrusted) {
				t.Errorf("%s.%s = %v, want reads_private and reads_untrusted", server, tool, ls)
			}
		}
	}
}

func TestMatchKind(t *testing.T) {
	for in, want := range map[string]string{
		"git": MatchExact, "brave": MatchAlias, "mcp-server-git": MatchTrimmed, "git-mcp": MatchTrimmed, "nope": "",
	} {
		if _, got := Match(in); got != want {
			t.Errorf("Match(%q) kind = %q, want %q", in, got, want)
		}
	}
}
