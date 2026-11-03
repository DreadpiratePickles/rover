package policy

import (
	"errors"

	"github.com/cedar-policy/cedar-go/types"

	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
	"github.com/DreadpiratePickles/rover/internal/policy/convert"
	"github.com/DreadpiratePickles/rover/internal/policy/normalize"
)

// Entity types and actions of the schema (plan §5.1, policy/schema.cedarschema).
const (
	entityClient   types.EntityType = "Client"
	entityServer   types.EntityType = "Server"
	entityTool     types.EntityType = "Tool"
	entityResource types.EntityType = "Resource"
	entityAction   types.EntityType = "Action"

	actCallTool          = "call_tool"
	actListTools         = "list_tools"
	actReadResource      = "read_resource"
	actServerSampling    = "server_sampling"
	actServerElicitation = "server_elicitation"
)

// Deny reasons decided before Cedar runs. Conversion failures use the
// sentinel texts of package convert (args_too_complex, ...).
const (
	ReasonNormReject       = "norm_reject"
	ReasonInvalidParams    = "invalid_params"
	ReasonInvalidToolName  = "invalid_tool_name"
	ReasonInvalidURI       = "invalid_resource_uri"
	ReasonInvalidDirection = "invalid_direction"
)

// envelopeLimits are convert.DefaultLimits with two extra levels of depth:
// the whole message is converted, and tool arguments sit at
// message.params.arguments, so 16 levels of arguments stay allowed.
var envelopeLimits = convert.Limits{
	MaxDepth:       convert.DefaultLimits.MaxDepth + 2,
	MaxKeys:        convert.DefaultLimits.MaxKeys,
	MaxStringBytes: convert.DefaultLimits.MaxStringBytes,
}

func actionUID(name string) types.EntityUID {
	return types.NewEntityUID(entityAction, types.String(name))
}

// policedAction maps a message to the Cedar action that judges it, or ""
// when M2 does not police that message.
func policedAction(dir string, m jsonrpc.Message) string {
	if m.Kind != jsonrpc.KindRequest {
		return ""
	}
	switch {
	case dir == DirC2S && m.Method == "tools/call":
		return actCallTool
	case dir == DirC2S && m.Method == "tools/list":
		return actListTools
	case dir == DirC2S && m.Method == "resources/read":
		return actReadResource
	case dir == DirS2C && m.Method == "sampling/createMessage":
		return actServerSampling
	case dir == DirS2C && m.Method == "elicitation/create":
		return actServerElicitation
	}
	return ""
}

// built is a Cedar request plus the entities it refers to.
type built struct {
	req      types.Request
	entities types.EntityMap
	findings []string
	// args and norm are context.args and context.norm of a call_tool, for
	// learn mode (Outcome.Args, Outcome.Norm).
	args types.Record
	norm types.Record
}

// denyError is a pre-evaluation failure: the message is blocked with reason.
type denyError struct{ reason string }

func (d denyError) Error() string { return d.reason }

// buildRequest converts the message and builds the Cedar request for action.
// Every error is a denyError: the caller blocks without asking Cedar.
//
// The whole message is run through convert.Args first. That parse rejects
// duplicate keys at any depth (envelope, params and arguments), so the
// policy cannot be shown one "name" or "path" while the server reads another.
func buildRequest(in Input, action string) (built, error) {
	env, findings, err := convert.Args(in.Msg.Raw, envelopeLimits)
	if err != nil {
		return built{}, denyError{reason: convertReason(err)}
	}
	params := types.Record{}
	if v, ok := env.Get("params"); ok {
		if params, ok = v.(types.Record); !ok {
			return built{}, denyError{reason: ReasonInvalidParams}
		}
	}
	client := clientEntity(in)
	server := serverEntity(in)
	b := built{
		entities: types.EntityMap{client.UID: client, server.UID: server},
		findings: findings,
	}
	b.req = types.Request{Principal: client.UID, Action: actionUID(action), Resource: server.UID}
	var extra types.RecordMap
	switch action {
	case actCallTool:
		tool, args, err := toolCall(in, server.UID, params)
		if err != nil {
			return built{}, err
		}
		b.entities[tool.UID] = tool
		b.req.Resource = tool.UID
		norm, err := normalize.Apply(in.Normalizers, args, in.Roots)
		if err != nil {
			return built{}, denyError{reason: ReasonNormReject}
		}
		b.findings = append(b.findings, norm.Findings...)
		b.args, b.norm = args, types.NewRecord(norm.Norm)
		extra = types.RecordMap{"args": args, "norm": b.norm}
	case actReadResource:
		res, err := resourceEntity(in, server.UID, params)
		if err != nil {
			return built{}, err
		}
		b.entities[res.UID] = res
		b.req.Resource = res.UID
	}
	b.req.Context = buildContext(in, b.findings, extra)
	return b, nil
}

// convertReason maps a convert error to its sentinel text. An error that is
// none of the known sentinels still denies, as args_invalid_json.
func convertReason(err error) string {
	for _, s := range []error{convert.ErrTooComplex, convert.ErrDuplicateKeys, convert.ErrNotObject, convert.ErrInvalidJSON} {
		if errors.Is(err, s) {
			return s.Error()
		}
	}
	return convert.ErrInvalidJSON.Error()
}

func clientEntity(in Input) types.Entity {
	return types.Entity{
		UID: types.NewEntityUID(entityClient, types.String(in.Client)),
		Attributes: types.NewRecord(types.RecordMap{
			"name":    types.String(in.Client),
			"version": types.String(in.ClientVersion),
		}),
	}
}

func serverEntity(in Input) types.Entity {
	return types.Entity{
		UID: types.NewEntityUID(entityServer, types.String(in.Server)),
		Attributes: types.NewRecord(types.RecordMap{
			"name":      types.String(in.Server),
			"transport": types.String(in.Transport),
			"pinned":    types.False, // TODO(M4): server pinning
		}),
	}
}

// toolCall reads params.name and params.arguments of a tools/call.
func toolCall(in Input, server types.EntityUID, params types.Record) (types.Entity, types.Record, error) {
	nv, _ := params.Get("name")
	name, ok := nv.(types.String)
	if !ok || name == "" {
		return types.Entity{}, types.Record{}, denyError{reason: ReasonInvalidToolName}
	}
	args := types.Record{}
	if av, present := params.Get("arguments"); present {
		if args, ok = av.(types.Record); !ok {
			return types.Entity{}, types.Record{}, denyError{reason: convert.ErrNotObject.Error()}
		}
	}
	tool := types.Entity{
		UID:     types.NewEntityUID(entityTool, types.String(in.Server)+"/"+name),
		Parents: types.NewEntityUIDSet(server),
		Attributes: types.NewRecord(types.RecordMap{
			"name":   name,
			"labels": stringSet(in.Labels[string(name)]),
		}),
	}
	return tool, args, nil
}

func resourceEntity(in Input, server types.EntityUID, params types.Record) (types.Entity, error) {
	uv, _ := params.Get("uri")
	uri, ok := uv.(types.String)
	if !ok || uri == "" {
		return types.Entity{}, denyError{reason: ReasonInvalidURI}
	}
	return types.Entity{
		UID:        types.NewEntityUID(entityResource, types.String(in.Server)+"/"+uri),
		Parents:    types.NewEntityUIDSet(server),
		Attributes: types.NewRecord(types.RecordMap{"uri": uri}),
	}, nil
}

// buildContext builds BaseContext, plus args and norm for call_tool. Findings
// from conversion and normalisation join the detector's findings.
func buildContext(in Input, findings []string, extra types.RecordMap) types.Record {
	all := append(append([]string(nil), in.Detection.Findings...), findings...)
	m := types.RecordMap{
		"session": types.NewRecord(types.RecordMap{
			"touched_private": types.Boolean(in.Session.TouchedPrivate),
			"saw_untrusted":   types.Boolean(in.Session.SawUntrusted),
			"calls":           types.Long(in.Session.Calls),
			"servers_touched": stringSet(in.Session.ServersTouched),
		}),
		"device": types.NewRecord(types.RecordMap{
			"managed":     types.Boolean(in.Device.Managed),
			"healthy":     types.Boolean(in.Device.Healthy),
			"quarantined": types.Boolean(in.Device.Quarantined),
			"tags":        stringSet(in.Device.Tags),
		}),
		"time": types.NewRecord(types.RecordMap{
			"hour":    types.Long(in.Now.Hour()),
			"weekday": types.Long(in.Now.Weekday()), // time.Sunday == 0
		}),
		"detection": types.NewRecord(types.RecordMap{
			"max_score": types.Long(in.Detection.MaxScore),
			"findings":  stringSet(all),
		}),
	}
	for k, v := range extra {
		m[k] = v
	}
	return types.NewRecord(m)
}

func stringSet(ss []string) types.Set {
	vs := make([]types.Value, len(ss))
	for i, s := range ss {
		vs[i] = types.String(s)
	}
	return types.NewSet(vs...)
}
