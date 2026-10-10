package ipc

import (
	"errors"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	in := Frame{Type: TypeDecide, SessionID: "s", Seq: 3, Dir: "c2s", Raw: []byte("\xff{not json\n")}
	line, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	if string(out.Raw) != string(in.Raw) || out.Seq != 3 || out.Dir != "c2s" {
		t.Fatalf("round trip changed the frame: %+v", out)
	}
}

func TestValidateRejectsBadFrames(t *testing.T) {
	cases := map[string]Frame{
		"unknown type":      {Type: "nope"},
		"old version":       {Type: TypeHello, Version: 0, WrapperPID: 1, ClientPID: 1, ServerName: "x", Transport: "stdio"},
		"no client pid":     {Type: TypeHello, Version: Version, WrapperPID: 1, ServerName: "x", Transport: "stdio"},
		"bad transport":     {Type: TypeHello, Version: Version, WrapperPID: 1, ClientPID: 1, ServerName: "x", Transport: "carrier pigeon"},
		"decide no raw":     {Type: TypeDecide, SessionID: "s", Seq: 1, Dir: "c2s"},
		"decide bad dir":    {Type: TypeDecide, SessionID: "s", Seq: 1, Dir: "up", Raw: []byte("x")},
		"verdict no action": {Type: TypeVerdict, Seq: 1},
		"replace no body":   {Type: TypeVerdict, Seq: 1, Action: ActionReplace},
		"release hold":      {Type: TypeRelease, Seq: 1, Action: ActionHold},
		"response on fwd":   {Type: TypeVerdict, Seq: 1, Action: ActionForward, ResponseRaw: []byte("{}")},
		"inject no raw":     {Type: TypeInject},
		"inject too big":    {Type: TypeInject, Raw: make([]byte, MaxInject+1)},
		// Tool ids are "<server>/<tool>", split at the first "/" (review L4).
		"slash in server":   {Type: TypeHello, Version: Version, WrapperPID: 1, ClientPID: 1, ServerName: "evil/echo", Transport: "stdio"},
		"space in server":   {Type: TypeHello, Version: Version, WrapperPID: 1, ClientPID: 1, ServerName: "my server", Transport: "stdio"},
		"unicode in server": {Type: TypeHello, Version: Version, WrapperPID: 1, ClientPID: 1, ServerName: "ech\u043e", Transport: "stdio"},
		"quote in server":   {Type: TypeHello, Version: Version, WrapperPID: 1, ClientPID: 1, ServerName: `a"b`, Transport: "stdio"},
	}
	for name, f := range cases {
		if err := f.Validate(); !errors.Is(err, ErrBadFrame) {
			t.Errorf("%s: want ErrBadFrame, got %v", name, err)
		}
	}
}

func TestBlockWithResponseRawRoundTrips(t *testing.T) {
	// Arrange
	in := Frame{Type: TypeVerdict, Seq: 2, Action: ActionBlock, Reason: "r", RuleIDs: []string{"a"}, ResponseRaw: []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)}

	// Act
	line, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Parse(line[:len(line)-1])

	// Assert
	if err != nil || string(out.ResponseRaw) != string(in.ResponseRaw) {
		t.Fatalf("out %+v err %v", out, err)
	}
}

func TestParseRejectsOversize(t *testing.T) {
	big := make([]byte, MaxFrame+1)
	if _, err := Parse(big); !errors.Is(err, ErrBadFrame) {
		t.Fatalf("want ErrBadFrame, got %v", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"type":"hello","version":1,"wrapper_pid":2,"client_pid":1,"server_name":"fs","transport":"stdio"}`))
	f.Add([]byte(`{"type":"decide","session_id":"s","seq":1,"dir":"c2s","raw":"e30="}`))
	f.Add([]byte(`{"type":"verdict","seq":1,"action":"forward"}`))
	f.Add([]byte(`{"type":"admin","op":"pin_approve","server_name":"echo","tool":"echo","digest":"0123456789ab"}`))
	f.Add([]byte(`{"type":"admin_result","result":[{"server":"echo"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, err := Parse(b)
		if err != nil {
			return
		}
		// Anything Parse accepts must re-encode and parse again identically.
		line, err := Encode(fr)
		if err != nil {
			t.Fatalf("encode accepted frame: %v", err)
		}
		if _, err := Parse(line); err != nil {
			t.Fatalf("re-parse: %v", err)
		}
	})
}

func TestServerNames(t *testing.T) {
	for _, ok := range []string{"echo", "echo-server", "fs_2", "server.v1", "A-Z.a_z-0"} {
		if err := ValidServerName(ok); err != nil {
			t.Errorf("ValidServerName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a/b", "a b", "a:b", "a\\b", strings.Repeat("x", 129)} {
		if err := ValidServerName(bad); err == nil {
			t.Errorf("ValidServerName(%q) accepted", bad)
		}
	}
	cases := map[string]string{
		"echo-server":            "echo-server",
		"my server.sh":           "my_server.sh",
		"npx@1":                  "npx_1",
		"caf\u00e9":              "caf__", // two bytes, two underscores
		"":                       "_",
		strings.Repeat("y", 200): strings.Repeat("y", 128),
	}
	for in, want := range cases {
		got := SanitizeServerName(in)
		if got != want || ValidServerName(got) != nil {
			t.Errorf("SanitizeServerName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAdminFrames(t *testing.T) {
	for _, ok := range []string{
		`{"type":"admin","op":"pin_list"}`,
		`{"type":"admin","op":"pin_list","server_name":"echo"}`,
		`{"type":"admin","op":"pin_approve","server_name":"echo","tool":"read file","digest":"0123456789ab"}`,
		`{"type":"admin","op":"pin_reset","server_name":"echo"}`,
		`{"type":"admin_result","result":{"removed":1}}`,
	} {
		if _, err := Parse([]byte(ok)); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		`{"type":"admin","op":"pin_delete"}`,
		`{"type":"admin","op":"pin_approve","server_name":"echo"}`,
		`{"type":"admin","op":"pin_approve","server_name":"echo","tool":"echo"}`,                         // no digest
		`{"type":"admin","op":"pin_approve","server_name":"echo","tool":"echo","digest":"0123456789a"}`,  // too short
		`{"type":"admin","op":"pin_approve","server_name":"echo","tool":"echo","digest":"0123456789AB"}`, // not lowercase
		`{"type":"admin","op":"pin_reset","server_name":"echo","digest":"0123456789ab"}`,
		`{"type":"admin","op":"pin_approve","tool":"echo"}`,
		`{"type":"admin","op":"pin_reset"}`,
		`{"type":"admin","op":"pin_reset","server_name":"a/b"}`,
		`{"type":"admin","op":"pin_reset","server_name":"echo","tool":"x"}`,
		`{"type":"admin","op":"pin_approve","server_name":"echo","tool":"` + strings.Repeat("x", MaxToolName+1) + `"}`,
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%.80s: accepted", bad)
		}
	}
}
