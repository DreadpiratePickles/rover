package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

const hideReadFile = `@id("hide-read-file") @rover_hide("true")
forbid (principal, action, resource == Tool::"echo/read_file");`

func TestFilterToolsListDropsHiddenToolAndKeepsOtherBytes(t *testing.T) {
	// Arrange
	e := mustLoad(t, hideReadFile)
	echoTool := `{ "name" : "echo", "description":"Echo <b>&</b>", "inputSchema":{"type":"object","properties":{"text":{"type":"string"}}} }`
	result := `{"tools":[` + echoTool + `,{"name":"read_file","inputSchema":{}}],"nextCursor":"abc","_meta":{"x":1.50}}`

	// Act
	out, hidden, changed, err := e.FilterToolsList("echo", []byte(result))

	// Assert
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if len(hidden) != 1 || hidden[0] != "read_file" {
		t.Fatalf("hidden %v", hidden)
	}
	want := `{"tools":[` + echoTool + `],"nextCursor":"abc","_meta":{"x":1.50}}`
	if string(out) != want {
		t.Fatalf("\n got %s\nwant %s", out, want)
	}
	if !bytes.Contains(out, []byte(echoTool)) {
		t.Fatal("echo tool bytes changed")
	}
}

func TestFilterToolsListLeavesOriginalWhenNothingHidden(t *testing.T) {
	// Arrange
	e := mustLoad(t, hideReadFile)
	result := []byte(`{"tools":[{"name":"echo"}]}`)

	for _, server := range []string{"echo", "other"} {
		// Act
		out, hidden, changed, err := e.FilterToolsList(server, result)

		// Assert
		if err != nil || changed || hidden != nil || !bytes.Equal(out, result) {
			t.Fatalf("%s: out=%s hidden=%v changed=%v err=%v", server, out, hidden, changed, err)
		}
	}
}

func TestFilterToolsListRejectsAmbiguousResults(t *testing.T) {
	// Arrange
	e := mustLoad(t, hideReadFile)
	cases := map[string]string{
		"duplicate tool name": `{"tools":[{"name":"echo","name":"read_file"}]}`,
		"duplicate tools key": `{"tools":[],"tools":[{"name":"read_file"}]}`,
		"name not a string":   `{"tools":[{"name":1}]}`,
		"no tools":            `{"nextCursor":"x"}`,
		"not an object":       `[1]`,
		"trailing data":       `{"tools":[]} {}`,
	}
	for name, result := range cases {
		// Act
		_, _, _, err := e.FilterToolsList("echo", []byte(result))

		// Assert
		if !errors.Is(err, ErrToolsList) {
			t.Errorf("%s: want ErrToolsList, got %v", name, err)
		}
	}
}

func TestHiddenToolIsAlsoBlockedWhenCalled(t *testing.T) {
	// Arrange
	e := mustLoad(t, permitEcho+"\n"+hideReadFile)

	// Act
	out := e.Decide(input(DirC2S, toolsCall("1", "read_file", `{}`)))

	// Assert
	if got := e.HiddenTools("echo"); len(got) != 1 || got[0] != "read_file" {
		t.Fatalf("HiddenTools %v", got)
	}
	var resp struct{ Result struct{ IsError bool } }
	if err := json.Unmarshal(out.Response, &resp); err != nil || !resp.Result.IsError {
		t.Fatalf("response %s err %v", out.Response, err)
	}
	mustContain(t, out.Response, "rule hide-read-file")
}
