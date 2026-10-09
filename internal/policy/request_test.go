package policy

import (
	"testing"

	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"

	policyfiles "github.com/DreadpiratePickles/rover/policy"
)

// TestBuiltRequestsMatchTheSchema checks the entity model and BaseContext
// that Decide builds against the shipped schema, so the two cannot drift.
func TestBuiltRequestsMatchTheSchema(t *testing.T) {
	// Arrange
	var s schema.Schema
	if err := s.UnmarshalCedar(policyfiles.Schema); err != nil {
		t.Fatal(err)
	}
	r, err := s.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	v := validate.New(r, validate.WithStrict())
	cases := []struct{ action, dir, line string }{
		{actListTools, DirC2S, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`},
		{actReadResource, DirC2S, `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///a"}}`},
		{actServerSampling, DirS2C, `{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{}}`},
		{actServerElicitation, DirS2C, `{"jsonrpc":"2.0","id":1,"method":"elicitation/create","params":{}}`},
	}
	for _, c := range cases {
		in := input(c.dir, c.line)
		in.Device.Tags = []string{"laptop"}

		// Act
		b, berr := buildRequest(in, c.action)

		// Assert
		if berr != nil {
			t.Fatalf("%s: %v", c.action, berr)
		}
		if verr := v.Request(b.req); verr != nil {
			t.Errorf("%s request: %v", c.action, verr)
		}
		if verr := v.Entities(b.entities); verr != nil {
			t.Errorf("%s entities: %v", c.action, verr)
		}
	}

	// The tool entity of a call_tool (its context holds free-form args).
	in := input(DirC2S, toolsCall("1", "echo", `{}`))
	in.Labels = map[string][]string{"echo": {"egress"}}
	b, err := buildRequest(in, actCallTool)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Entities(b.entities); err != nil {
		t.Errorf("call_tool entities: %v", err)
	}
}
