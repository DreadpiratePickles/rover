package policy

import (
	"fmt"
	"strings"

	"github.com/cedar-policy/cedar-go/types"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"
)

// Rover's own policy annotations. Cedar ignores annotations when it
// evaluates; Rover reads them at Load.
const (
	annID      = "id"
	annRequire = "rover_require" // @rover_require("approval") on a permit
	annHide    = "rover_hide"    // @rover_hide("true") on an unconditional forbid
)

// policyMeta is what the Rover annotations of one policy mean.
type policyMeta struct {
	requireApproval      bool
	hideServer, hideTool string
}

// readAnnotations checks the annotations of one policy. Unknown rover_*
// annotations and unexpected values are errors, because a misspelt
// @rover_hide would otherwise leave a tool visible without anyone noticing.
func readAnnotations(id types.PolicyID, anns types.Annotations, p *xast.Policy) (policyMeta, error) {
	var m policyMeta
	for k, v := range anns {
		key := string(k)
		switch {
		case key == annID:
		case key == annRequire:
			if v != "approval" {
				return m, fmt.Errorf("policy %q: @rover_require must be \"approval\", got %q", id, v)
			}
			if p.Effect != xast.EffectPermit {
				return m, fmt.Errorf("policy %q: @rover_require(\"approval\") only makes sense on a permit", id)
			}
			m.requireApproval = true
		case key == annHide:
			server, tool, err := hiddenTool(id, v, p)
			if err != nil {
				return m, err
			}
			m.hideServer, m.hideTool = server, tool
		case strings.HasPrefix(key, "rover_"):
			return m, fmt.Errorf("policy %q: unknown annotation @%s", id, key)
		}
	}
	return m, nil
}

// hiddenTool checks the shape §5.1 requires for @rover_hide("true") and
// returns the tool it hides. Only an unconditional forbid on one concrete
// Tool, for every principal, can hide: anything conditional must stay listed
// and be judged at call time, since tools/list cannot know the call's context.
func hiddenTool(id types.PolicyID, v types.String, p *xast.Policy) (server, tool string, err error) {
	fail := func(why string) (string, string, error) {
		return "", "", fmt.Errorf("policy %q: @rover_hide needs a concrete tool: %s "+
			"(write: forbid (principal, action, resource == Tool::\"server/tool\");)", id, why)
	}
	if v != "true" {
		return fail(fmt.Sprintf("value must be \"true\", got %q", v))
	}
	if p.Effect != xast.EffectForbid {
		return fail("only a forbid can hide a tool")
	}
	if len(p.Conditions) > 0 {
		return fail("the policy has when/unless conditions")
	}
	if _, ok := p.Principal.(xast.ScopeTypeAll); !ok {
		return fail("the principal must be unconstrained")
	}
	if !actionCoversCallTool(p.Action) {
		return fail("the action must be unconstrained or Action::\"call_tool\"")
	}
	eq, ok := p.Resource.(xast.ScopeTypeEq)
	if !ok || eq.Entity.Type != entityTool {
		return fail("the resource must be `resource == Tool::\"server/tool\"`")
	}
	server, tool, ok = strings.Cut(string(eq.Entity.ID), "/")
	if !ok || server == "" || tool == "" {
		return fail(fmt.Sprintf("tool id %q is not \"server/tool\"", eq.Entity.ID))
	}
	return server, tool, nil
}

func actionCoversCallTool(a xast.IsActionScopeNode) bool {
	switch s := a.(type) {
	case xast.ScopeTypeAll:
		return true
	case xast.ScopeTypeEq:
		return s.Entity == actionUID(actCallTool)
	}
	return false
}
