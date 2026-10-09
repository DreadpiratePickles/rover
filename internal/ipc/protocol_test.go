package ipc

import (
	"errors"
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
	}
	for name, f := range cases {
		if err := f.Validate(); !errors.Is(err, ErrBadFrame) {
			t.Errorf("%s: want ErrBadFrame, got %v", name, err)
		}
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
