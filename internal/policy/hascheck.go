package policy

import (
	"fmt"

	"github.com/cedar-policy/cedar-go/types"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema/resolved"
)

// LESSON (M3): Cedar's strict validator types `e has a` as the constant
// false when the record type of e does not declare a, and `false && X` is
// then false without X being checked at all. So
//
//	forbid (...) when { context.norm has path.under_lab && context.norm.path.under_lab };
//
// passes validation when no root named "lab" exists, and the forbid can
// never fire. That is the "silently disabled forbid" strict validation is
// meant to prevent, so Rover adds one check of its own: every attribute a
// `has` test names must be declared by the schema at that place.
//
// Which attributes "resource" has depends on the action: a Tool has labels,
// a Server has pinned. So the check resolves principal and resource by the
// entity types the policy's scope allows. A policy that applies to several
// actions may only test an attribute that every one of those types declares
// (otherwise it is always false for some of them, which is how a forbid
// written for servers silently skips tools). A `has` whose left side is not
// a plain path such as context.norm.path cannot be checked, so it is refused.

// hasChecker checks `has` tests against the resolved schema.
type hasChecker struct {
	s *resolved.Schema
}

func newHasChecker(s *resolved.Schema) *hasChecker {
	return &hasChecker{s: s}
}

// roots are the record types each variable can have under one policy's
// scope. For principal and resource every record must declare an attribute
// (all); for context one is enough, because the validator has already
// refused reading an attribute an applicable context lacks.
type roots map[types.String]recordSet

type recordSet struct {
	recs []resolved.RecordType
	all  bool // the attribute must be declared by every record, not just one
}

// check reports the first `has` in p whose attribute the schema does not
// declare where it is tested, or that Rover cannot check.
func (h *hasChecker) check(p *xast.Policy) error {
	var hasNodes []xast.NodeTypeHas
	for _, c := range p.Conditions {
		xast.Inspect(xast.NewNode(c.Body), func(n xast.IsNode) bool {
			if hn, ok := n.(xast.NodeTypeHas); ok {
				hasNodes = append(hasNodes, hn)
			}
			return true
		})
	}
	if len(hasNodes) == 0 {
		return nil
	}
	r, err := h.roots(p)
	if err != nil {
		return err
	}
	for _, hn := range hasNodes {
		set, ok := r.records(hn.Arg)
		if !ok {
			return fmt.Errorf("`has %s`: the left side is not a plain path (principal, resource or context "+
				"followed by .attribute, ending on a record), so Rover cannot check that the attribute can exist; "+
				"test the path itself, e.g. `context.norm has path && context.norm.path has under_x`", hn.Value)
		}
		if !set.declares(hn.Value) {
			return fmt.Errorf("`has %s` tests an attribute the schema does not declare there, "+
				"so it is always false and the policy can never match "+
				"(is a root or argument missing from the config, or does the action scope include an entity type without it?)", hn.Value)
		}
	}
	return nil
}

// roots works out the record types of principal, resource and context for
// the actions and entity types p's scope allows. It fails (refuse) when the
// scope matches no action or no entity type.
func (h *hasChecker) roots(p *xast.Policy) (roots, error) {
	actions := h.actions(p.Action)
	if len(actions) == 0 {
		return nil, fmt.Errorf("cannot work out which actions the policy applies to, so its `has` tests cannot be checked")
	}
	var principals, resources []types.EntityType
	var contexts []resolved.RecordType
	for _, a := range actions {
		principals = append(principals, a.Principals...)
		resources = append(resources, a.Resources...)
		contexts = append(contexts, a.Context)
	}
	pt := scopeTypes(p.Principal, principals)
	rt := scopeTypes(p.Resource, resources)
	if len(pt) == 0 || len(rt) == 0 {
		return nil, fmt.Errorf("the policy scope matches no principal or resource type, so its `has` tests cannot be checked")
	}
	return roots{
		"principal": {recs: h.shapes(pt), all: true},
		"resource":  {recs: h.shapes(rt), all: true},
		"context":   {recs: contexts},
	}, nil
}

// actions returns the appliesTo of every schema action the scope allows.
func (h *hasChecker) actions(scope xast.IsActionScopeNode) []*resolved.AppliesTo {
	var want func(types.EntityUID) bool
	switch sc := scope.(type) {
	case xast.ScopeTypeAll:
		want = func(types.EntityUID) bool { return true }
	case xast.ScopeTypeEq:
		want = func(u types.EntityUID) bool { return u == sc.Entity }
	case xast.ScopeTypeIn:
		want = func(u types.EntityUID) bool { return h.actionIn(u, sc.Entity, 0) }
	case xast.ScopeTypeInSet:
		want = func(u types.EntityUID) bool {
			for _, g := range sc.Entities {
				if h.actionIn(u, g, 0) {
					return true
				}
			}
			return false
		}
	default:
		return nil
	}
	var out []*resolved.AppliesTo
	for uid, a := range h.s.Actions {
		if a.AppliesTo != nil && want(uid) {
			out = append(out, a.AppliesTo)
		}
	}
	return out
}

// maxActionDepth bounds the walk up the action group hierarchy.
const maxActionDepth = 32

// actionIn reports whether action u is group g or (transitively) in it.
func (h *hasChecker) actionIn(u, g types.EntityUID, depth int) bool {
	if u == g {
		return true
	}
	if depth >= maxActionDepth {
		return false
	}
	a, ok := h.s.Actions[u]
	if !ok {
		return false
	}
	for parent := range a.Entity.Parents.All() {
		if h.actionIn(parent, g, depth+1) {
			return true
		}
	}
	return false
}

// scopeTypes narrows the entity types an action allows by what a principal
// or resource scope says about the type (==, is, is ... in). A plain `in`
// does not fix the type (a Tool and its Server are both "in" the Server).
func scopeTypes(scope any, allowed []types.EntityType) []types.EntityType {
	var only types.EntityType
	switch sc := scope.(type) {
	case xast.ScopeTypeEq:
		only = sc.Entity.Type
	case xast.ScopeTypeIs:
		only = sc.Type
	case xast.ScopeTypeIsIn:
		only = sc.Type
	}
	seen := map[types.EntityType]bool{}
	var out []types.EntityType
	for _, t := range allowed {
		if seen[t] || (only != "" && t != only) {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

func (h *hasChecker) shapes(ts []types.EntityType) []resolved.RecordType {
	out := make([]resolved.RecordType, 0, len(ts))
	for _, t := range ts {
		out = append(out, h.s.Entities[t].Shape) // an enum or unknown type has no attributes
	}
	return out
}

// declares reports whether attr may exist on the records of set.
func (set recordSet) declares(attr types.String) bool {
	if len(set.recs) == 0 {
		return false
	}
	for _, r := range set.recs {
		_, ok := r[attr]
		if ok && !set.all {
			return true
		}
		if !ok && set.all {
			return false
		}
	}
	return set.all
}

// records returns the record types arg can have, or false when arg is not a
// plain path from principal, resource or context that ends on records.
func (r roots) records(arg xast.IsNode) (recordSet, bool) {
	switch n := arg.(type) {
	case xast.NodeTypeVariable:
		set, ok := r[n.Name]
		return set, ok
	case xast.NodeTypeAccess:
		parent, ok := r.records(n.Arg)
		if !ok {
			return recordSet{}, false
		}
		out := recordSet{all: parent.all}
		for _, p := range parent.recs {
			a, found := p[n.Value]
			if !found {
				continue // the validator refuses reading it where it is missing
			}
			rec, isRec := a.Type.(resolved.RecordType)
			if !isRec {
				return recordSet{}, false // an entity or other type: cannot check
			}
			out.recs = append(out.recs, rec)
		}
		return out, true
	}
	return recordSet{}, false
}
