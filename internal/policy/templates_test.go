package policy

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

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
	if len(files) != 6 {
		t.Fatalf("want starter + 5 templates, got %d files", len(files))
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
		"unknown context attribute": `permit (principal, action == Action::"call_tool", resource) when { context.args.nope == "x" };`,
		"unknown entity attribute":  `permit (principal, action == Action::"call_tool", resource) when { resource.colour == "red" };`,
		"args on list_tools":        `permit (principal, action == Action::"list_tools", resource) when { context.args.path == "x" };`,
		"unknown action":            `permit (principal, action == Action::"delete_everything", resource);`,
		"unknown entity type":       `permit (principal == User::"bob", action, resource);`,
		"syntax error":              `permit (principal, action, resource`,
		"duplicate id":              `@id("a") permit (principal, action, resource); @id("a") forbid (principal, action, resource);`,
		"misspelt rover annotation": `@rover_hdie("true") forbid (principal, action, resource == Tool::"echo/x");`,
		"approval on a forbid":      `@rover_require("approval") forbid (principal, action, resource);`,
		"approval wrong value":      `@rover_require("yes") permit (principal, action, resource);`,
		"hide with condition":       `@rover_hide("true") forbid (principal, action, resource == Tool::"echo/x") when { context.session.calls > 1 };`,
		"hide a whole server":       `@rover_hide("true") forbid (principal, action, resource in Server::"echo");`,
		"hide on a permit":          `@rover_hide("true") permit (principal, action, resource == Tool::"echo/x");`,
		"hide for one client":       `@rover_hide("true") forbid (principal == Client::"x", action, resource == Tool::"echo/x");`,
		"hide without server/tool":  `@rover_hide("true") forbid (principal, action, resource == Tool::"x");`,
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
