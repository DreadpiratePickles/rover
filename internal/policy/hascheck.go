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

// hasChecker knows the record types a policy can reach from each variable.
type hasChecker struct {
	roots map[types.String][]resolved.RecordType // "context", "principal", ...
}

func newHasChecker(s *resolved.Schema) *hasChecker {
	var contexts, shapes []resolved.RecordType
	for _, a := range s.Actions {
		if a.AppliesTo != nil {
			contexts = append(contexts, a.AppliesTo.Context)
		}
	}
	for _, e := range s.Entities {
		shapes = append(shapes, e.Shape)
	}
	return &hasChecker{roots: map[types.String][]resolved.RecordType{
		"context":   contexts,
		"principal": shapes,
		"resource":  shapes,
	}}
}

// check reports the first `has` in p whose attribute the schema does not
// declare where it is tested.
func (h *hasChecker) check(p *xast.Policy) error {
	var err error
	for _, c := range p.Conditions {
		xast.Inspect(xast.NewNode(c.Body), func(n xast.IsNode) bool {
			if err != nil {
				return false
			}
			if hn, ok := n.(xast.NodeTypeHas); ok && !h.declared(hn.Arg, hn.Value) {
				err = fmt.Errorf("`has %s` tests an attribute the schema does not declare there, "+
					"so it is always false and the policy can never match "+
					"(is a root or argument missing from the config?)", hn.Value)
			}
			return true
		})
	}
	return err
}

// declared reports whether attr may exist on the record arg evaluates to.
// Expressions that are not a plain variable.attr.attr path cannot be
// resolved here and are accepted (the validator has checked their type).
func (h *hasChecker) declared(arg xast.IsNode, attr types.String) bool {
	recs, ok := h.records(arg)
	if !ok {
		return true
	}
	for _, r := range recs {
		if _, ok := r[attr]; ok {
			return true
		}
	}
	return false
}

// records returns the record types arg can have, or false when arg is not a
// path this checker understands.
func (h *hasChecker) records(arg xast.IsNode) ([]resolved.RecordType, bool) {
	switch n := arg.(type) {
	case xast.NodeTypeVariable:
		recs, ok := h.roots[n.Name]
		return recs, ok
	case xast.NodeTypeAccess:
		parents, ok := h.records(n.Arg)
		if !ok {
			return nil, false
		}
		var out []resolved.RecordType
		for _, p := range parents {
			a, found := p[n.Value]
			if !found {
				continue
			}
			rec, isRec := a.Type.(resolved.RecordType)
			if !isRec {
				return nil, false // an entity or other type: give up, accept
			}
			out = append(out, rec)
		}
		return out, true
	}
	return nil, false
}
