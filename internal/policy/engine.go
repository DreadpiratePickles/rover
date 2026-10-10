// Package policy is Rover's policy decision point: it turns one MCP message
// into a Cedar request, asks Cedar for a decision and says what the proxy
// (the enforcement point) must do with the message (plan §5.1).
//
// LESSON (M2): the gateway has two halves. The proxy *enforces*: it forwards,
// blocks or replaces bytes. This package *decides*: it never touches a
// socket. Keeping them apart means the decision can be tested exhaustively
// with plain function calls, and the enforcement code stays small enough to
// read in one sitting.
//
// Rules this package keeps:
//   - Default deny. If no permit matches, the answer is block.
//   - Fail closed. A message we cannot parse, convert or normalise is blocked
//     before Cedar runs, even in observe mode. A forbid that errors during
//     evaluation counts as a forbid that fired.
//   - Validate at load. Every policy is type-checked against the schema in
//     strict mode, and every `has` test must name a declared attribute
//     (hascheck.go); one bad policy fails the whole Load, so a typo can
//     never silently disable a forbid. The schema comes from SchemaFor.
package policy

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"

	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
)

// Mode says what happens to a deny.
type Mode string

// Modes. Anything other than ModeObserve is treated as ModeEnforce (fail
// closed): a typo in config must not switch enforcement off.
const (
	// ModeObserve forwards denied messages and marks them WouldDeny, so a new
	// policy can be tried on real traffic before it blocks anything.
	ModeObserve Mode = "observe"
	// ModeEnforce blocks denied messages.
	ModeEnforce Mode = "enforce"
)

// Directions of a message, as in ipc.Frame.Dir.
const (
	DirC2S = "c2s" // client (agent) -> server
	DirS2C = "s2c" // server -> client
)

// Limits on the policy and schema sources. They are written by the operator,
// not the attacker, but a bound still turns a runaway file into a clear error.
const (
	MaxPolicyBytes = 4 << 20
	MaxSchemaBytes = 1 << 20
)

// ErrLoad wraps every error returned by Load.
var ErrLoad = errors.New("policy load failed")

// SessionCtx is context.session: what this session has done so far.
type SessionCtx struct {
	TouchedPrivate bool
	SawUntrusted   bool
	Calls          int64
}

// DeviceCtx is context.device. All zero until N5 (device posture).
type DeviceCtx struct {
	Managed, Healthy, Quarantined bool
	Tags                          []string
}

// DetectionCtx is context.detection. Zero until M5 (injection detection).
type DetectionCtx struct {
	MaxScore int64
	Findings []string
}

// Input is everything Decide needs about one message.
type Input struct {
	Mode          Mode
	Client        string // clientInfo.name from initialize
	ClientVersion string
	Server        string // the server name from the wrapper's hello
	Transport     string
	Dir           string // DirC2S or DirS2C
	Msg           jsonrpc.Message
	// Labels maps a tool name (without the server prefix) to its labels from
	// config.yaml, e.g. {"read_file": ["reads_private"]}.
	Labels    map[string][]string
	Session   SessionCtx
	Device    DeviceCtx
	Detection DetectionCtx
	// Now is the injected clock. context.time.hour and weekday are taken from
	// it in its own location, so the caller decides the time zone.
	Now         time.Time
	Roots       []normalize.Root
	Normalizers normalize.Rules // the rules for the tool being called
}

// Info describes one loaded policy, for `rover policy validate`.
type Info struct {
	ID     string
	Effect string // "permit" or "forbid"
}

// Engine is a loaded, validated policy set. It is immutable after Load and
// safe for concurrent use by many goroutines.
type Engine struct {
	policies cedar.PolicyMap
	infos    []Info                     // file order
	forbids  map[types.PolicyID]bool    // ids of forbid policies
	approval map[types.PolicyID]bool    // permits with @rover_require("approval")
	hidden   map[string]map[string]bool // server -> tool -> hidden
}

// Load parses policySrc (named policyName in error messages), parses and
// resolves the schema, validates every policy against it in strict mode and
// indexes the Rover annotations. Any problem is an error: the caller must not
// run with a partially loaded policy.
func Load(policySrc []byte, policyName string, schemaSrc []byte) (*Engine, error) {
	if len(policySrc) > MaxPolicyBytes {
		return nil, fmt.Errorf("%w: %s is %d bytes, limit %d", ErrLoad, policyName, len(policySrc), MaxPolicyBytes)
	}
	if len(schemaSrc) > MaxSchemaBytes {
		return nil, fmt.Errorf("%w: schema is %d bytes, limit %d", ErrLoad, len(schemaSrc), MaxSchemaBytes)
	}
	v, hc, err := newValidator(schemaSrc)
	if err != nil {
		return nil, err
	}
	list, err := cedar.NewPolicyListFromBytes(policyName, policySrc)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrLoad, policyName, err)
	}
	e := &Engine{
		policies: make(cedar.PolicyMap, len(list)),
		forbids:  map[types.PolicyID]bool{},
		approval: map[types.PolicyID]bool{},
		hidden:   map[string]map[string]bool{},
	}
	for i, p := range list {
		if err := e.add(i, p, v, hc); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrLoad, policyName, err)
		}
	}
	return e, nil
}

func newValidator(schemaSrc []byte) (*validate.Validator, *hasChecker, error) {
	var s schema.Schema
	s.SetFilename("schema.cedarschema")
	if err := s.UnmarshalCedar(schemaSrc); err != nil {
		return nil, nil, fmt.Errorf("%w: schema: %w", ErrLoad, err)
	}
	r, err := s.Resolve()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: schema: %w", ErrLoad, err)
	}
	return validate.New(r, validate.WithStrict()), newHasChecker(r), nil
}

// add validates policy number i, works out its id and indexes its
// annotations.
func (e *Engine) add(i int, p *cedar.Policy, v *validate.Validator, hc *hasChecker) error {
	id := policyID(i, p)
	if _, dup := e.policies[id]; dup {
		return fmt.Errorf("duplicate policy id %q", id)
	}
	tree := (*xast.Policy)(p.AST())
	if err := v.Policy(string(id), tree); err != nil {
		return fmt.Errorf("policy %q (line %d) does not match the schema: %w", id, p.Position().Line, err)
	}
	if err := hc.check(tree); err != nil {
		return fmt.Errorf("policy %q (line %d): %w", id, p.Position().Line, err)
	}
	meta, err := readAnnotations(id, p.Annotations(), tree)
	if err != nil {
		return err
	}
	e.policies[id] = p
	effect := "permit"
	if p.Effect() == cedar.Forbid {
		effect = "forbid"
		e.forbids[id] = true
	}
	e.infos = append(e.infos, Info{ID: string(id), Effect: effect})
	if meta.requireApproval {
		e.approval[id] = true
	}
	if meta.hideServer != "" {
		if e.hidden[meta.hideServer] == nil {
			e.hidden[meta.hideServer] = map[string]bool{}
		}
		e.hidden[meta.hideServer][meta.hideTool] = true
	}
	return nil
}

// policyID is the @id annotation, else "policy<N>" with N the 0-based
// position in the file (the same naming cedar-go uses).
func policyID(i int, p *cedar.Policy) types.PolicyID {
	if id, ok := p.Annotations()["id"]; ok && id != "" {
		return types.PolicyID(id)
	}
	return types.PolicyID(fmt.Sprintf("policy%d", i))
}

// Policies lists the loaded policies in file order.
func (e *Engine) Policies() []Info {
	return append([]Info(nil), e.infos...)
}

// sortedIDs turns policy ids into a sorted, de-duplicated string slice.
func sortedIDs(ids []types.PolicyID) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[types.PolicyID]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, string(id))
		}
	}
	sort.Strings(out)
	return out
}
