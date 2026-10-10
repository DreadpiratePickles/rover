package policy

import (
	"errors"
	"strings"
	"testing"

	policyfiles "github.com/DreadpiratePickles/rover/policy"
)

// A `has` is checked against the entity types the policy's scope allows,
// not every entity in the schema: Server declares pinned, Tool does not, so
// on call_tool `resource has pinned` is always false (M3 re-verification).
func TestHasCheckResolvesByScope(t *testing.T) {
	cases := []struct {
		name, src, wantErr string // wantErr "" means the policy loads
	}{
		{"pinned on a tool", `forbid (principal, action == Action::"call_tool", resource) when { resource has pinned };`, "has pinned"},
		{"pinned on a server", `forbid (principal, action == Action::"list_tools", resource) when { resource has pinned };`, ""},
		{"pinned for every action", `forbid (principal, action, resource) when { resource has pinned };`, "has pinned"},
		{"name for every action", `forbid (principal, action in [Action::"call_tool", Action::"list_tools"], resource) when { resource has name };`, ""},
		{"labels on a tool", `forbid (principal, action == Action::"call_tool", resource) when { resource has labels };`, ""},
		{"labels on a tool by type", `forbid (principal, action, resource is Tool) when { resource has labels };`, ""},
		{"session calls", `forbid (principal, action == Action::"list_tools", resource) when { context.session has calls };`, ""},
		{"if on the left", `forbid (principal, action == Action::"call_tool", resource) when { context.norm has path && (if true then context.norm.path else context.norm.path) has under_nope };`, "not a plain path"},
		{"action has", `forbid (principal, action, resource) when { action has x };`, "not a plain path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Act
			_, err := Load([]byte(c.src), "p.cedar", policyfiles.Schema)

			// Assert
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("want it to load, got %v", err)
				}
				return
			}
			if !errors.Is(err, ErrLoad) || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("want ErrLoad mentioning %q, got %v", c.wantErr, err)
			}
		})
	}
}
