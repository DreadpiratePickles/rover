package convert

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go/types"
)

func rec(m types.RecordMap) types.Record { return types.NewRecord(m) }

func TestArgsConvertsEachJSONKind(t *testing.T) {
	tests := []struct {
		name         string
		in           string
		want         types.Record
		wantFindings []string
	}{
		{"string", `{"path":"/home/alice/notes.txt"}`, rec(types.RecordMap{"path": types.String("/home/alice/notes.txt")}), nil},
		{"escaped string", `{"s":"aé\n"}`, rec(types.RecordMap{"s": types.String("aé\n")}), nil},
		{"integer", `{"n":42}`, rec(types.RecordMap{"n": types.Long(42)}), nil},
		{"negative integer", `{"n":-7}`, rec(types.RecordMap{"n": types.Long(-7)}), nil},
		{"max int64", `{"n":9223372036854775807}`, rec(types.RecordMap{"n": types.Long(9223372036854775807)}), nil},
		{"min int64", `{"n":-9223372036854775808}`, rec(types.RecordMap{"n": types.Long(-9223372036854775808)}), nil},
		{"int64 overflow", `{"n":9223372036854775808}`, rec(types.RecordMap{"n": types.String("9223372036854775808")}), []string{FindingNonIntegerNumber}},
		{"big number", `{"n":12345678901234567890}`, rec(types.RecordMap{"n": types.String("12345678901234567890")}), []string{FindingNonIntegerNumber}},
		{"fraction", `{"n":1.5}`, rec(types.RecordMap{"n": types.String("1.5")}), []string{FindingNonIntegerNumber}},
		{"integral fraction", `{"n":1.0}`, rec(types.RecordMap{"n": types.String("1.0")}), []string{FindingNonIntegerNumber}},
		{"exponent", `{"n":1e3}`, rec(types.RecordMap{"n": types.String("1e3")}), []string{FindingNonIntegerNumber}},
		{"negative zero", `{"n":-0}`, rec(types.RecordMap{"n": types.String("-0")}), []string{FindingNonIntegerNumber}},
		{"zero", `{"n":0}`, rec(types.RecordMap{"n": types.Long(0)}), nil},
		{"finding reported once", `{"a":1.5,"b":2.5}`, rec(types.RecordMap{"a": types.String("1.5"), "b": types.String("2.5")}), []string{FindingNonIntegerNumber}},
		{"booleans", `{"t":true,"f":false}`, rec(types.RecordMap{"t": types.Boolean(true), "f": types.Boolean(false)}), nil},
		{"nested object", `{"o":{"p":{"q":"x"}}}`, rec(types.RecordMap{"o": rec(types.RecordMap{"p": rec(types.RecordMap{"q": types.String("x")})})}), nil},
		{"array to set", `{"a":["x",1,true]}`, rec(types.RecordMap{"a": types.NewSet(types.String("x"), types.Long(1), types.Boolean(true))}), nil},
		{"array order lost", `{"a":["y","x"]}`, rec(types.RecordMap{"a": types.NewSet(types.String("x"), types.String("y"))}), nil},
		{"array duplicates collapse", `{"a":["x","x","x"]}`, rec(types.RecordMap{"a": types.NewSet(types.String("x"))}), nil},
		{"empty array", `{"a":[]}`, rec(types.RecordMap{"a": types.NewSet()}), nil},
		{"null omitted", `{"a":null,"b":"kept"}`, rec(types.RecordMap{"b": types.String("kept")}), nil},
		{"null array element dropped", `{"a":[null,"x"]}`, rec(types.RecordMap{"a": types.NewSet(types.String("x"))}), nil},
		{"empty object", `{}`, rec(types.RecordMap{}), nil},
		{"surrounding whitespace", " \n{\"a\":1}\t ", rec(types.RecordMap{"a": types.Long(1)}), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			raw := []byte(tt.in)

			// Act
			got, findings, err := Args(raw, DefaultLimits)

			// Assert
			if err != nil {
				t.Fatalf("Args(%s) error = %v", tt.in, err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("Args(%s) = %v, want %v", tt.in, got, tt.want)
			}
			if strings.Join(findings, ",") != strings.Join(tt.wantFindings, ",") {
				t.Errorf("Args(%s) findings = %v, want %v", tt.in, findings, tt.wantFindings)
			}
		})
	}
}

func TestArgsDeniesBadInput(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr error
	}{
		{"duplicate top-level key", `{"path":"/safe","path":"/etc/shadow"}`, ErrDuplicateKeys},
		{"duplicate nested key", `{"o":{"a":1,"b":2,"a":3}}`, ErrDuplicateKeys},
		{"duplicate key inside array", `{"l":[{"k":1,"k":2}]}`, ErrDuplicateKeys},
		{"duplicate key via escape", `{"a":1,"a":2}`, ErrDuplicateKeys},
		{"duplicate with null value", `{"a":null,"a":"x"}`, ErrDuplicateKeys},
		{"case-colliding keys", `{"path":"/safe","Path":"/etc/shadow"}`, ErrDuplicateKeys},
		{"case-colliding nested keys", `{"o":{"Cmd":"ls","CMD":"rm"}}`, ErrDuplicateKeys},
		{"kelvin sign collides with k", "{\"k\":1,\"\u212a\":2}", ErrDuplicateKeys},
		{"top-level array", `["a"]`, ErrNotObject},
		{"top-level string", `"a"`, ErrNotObject},
		{"top-level number", `1`, ErrNotObject},
		{"top-level null", `null`, ErrNotObject},
		{"empty input", ``, ErrInvalidJSON},
		{"truncated", `{"a":`, ErrInvalidJSON},
		{"unterminated object", `{"a":1`, ErrInvalidJSON},
		{"trailing comma", `{"a":1,}`, ErrInvalidJSON},
		{"bare word", `{"a":nope}`, ErrInvalidJSON},
		{"trailing value", `{"a":1}{"a":2}`, ErrInvalidJSON},
		{"trailing garbage", `{"a":1}x`, ErrInvalidJSON},
		{"invalid utf-8", "{\"a\":\"\xff\"}", ErrInvalidJSON},
		{"single quotes", `{'a':1}`, ErrInvalidJSON},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			raw := []byte(tt.in)

			// Act
			_, _, err := Args(raw, DefaultLimits)

			// Assert
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Args(%q) error = %v, want %v", tt.in, err, tt.wantErr)
			}
		})
	}
}

// nestedObjects returns depth nested objects: depth 1 is {"v":1}.
func nestedObjects(depth int) string {
	return strings.Repeat(`{"k":`, depth-1) + `{"v":1}` + strings.Repeat(`}`, depth-1)
}

// nestedArrays returns an object holding arrays so total depth is depth.
func nestedArrays(depth int) string {
	return `{"k":` + strings.Repeat(`[`, depth-1) + `1` + strings.Repeat(`]`, depth-1) + `}`
}

// manyKeys returns an object with n keys spread over a nested object so that
// the count must be global, not per object.
func manyKeys(n int) string {
	var b strings.Builder
	b.WriteString(`{"inner":{`)
	for i := 1; i < n; i++ {
		if i > 1 {
			b.WriteByte(',')
		}
		b.WriteString(`"k`)
		b.WriteString(strconv.Itoa(i))
		b.WriteString(`":1`)
	}
	b.WriteString(`}}`)
	return b.String()
}

func TestArgsLimitBoundaries(t *testing.T) {
	const mib = 1 << 20
	tests := []struct {
		name    string
		in      string
		wantErr error
	}{
		{"depth 16 objects ok", nestedObjects(16), nil},
		{"depth 17 objects denied", nestedObjects(17), ErrTooComplex},
		{"depth 16 arrays ok", nestedArrays(16), nil},
		{"depth 17 arrays denied", nestedArrays(17), ErrTooComplex},
		{"4096 keys ok", manyKeys(4096), nil},
		{"4097 keys denied", manyKeys(4097), ErrTooComplex},
		{"1 MiB string ok", `{"s":"` + strings.Repeat("a", mib) + `"}`, nil},
		{"1 MiB + 1 string denied", `{"s":"` + strings.Repeat("a", mib+1) + `"}`, ErrTooComplex},
		{"1 MiB + 1 key denied", `{"` + strings.Repeat("a", mib+1) + `":1}`, ErrTooComplex},
		{"1 MiB + 1 array string denied", `{"l":["` + strings.Repeat("a", mib+1) + `"]}`, ErrTooComplex},
		{"1 MiB + 1 number literal denied", `{"n":` + strings.Repeat("1", mib+1) + `}`, ErrTooComplex},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			raw := []byte(tt.in)

			// Act
			_, _, err := Args(raw, DefaultLimits)

			// Assert
			if tt.wantErr == nil && err != nil {
				t.Fatalf("Args error = %v, want nil", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("Args error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestArgsKeyLimitCountsWholeDocument(t *testing.T) {
	// Arrange: five keys across three objects, none over 2 per object; limit 4.
	raw := []byte(`{"a":{"b":1,"c":2},"d":{"e":1}}`)
	lim := Limits{MaxDepth: 16, MaxKeys: 4, MaxStringBytes: 64}

	// Act
	_, _, err := Args(raw, lim)

	// Assert
	if !errors.Is(err, ErrTooComplex) {
		t.Fatalf("Args error = %v, want ErrTooComplex", err)
	}
}

func FuzzArgs(f *testing.F) {
	seeds := []string{
		`{}`, `{"a":1}`, `{"a":1,"a":2}`, `{"a":[1,2,{"b":null}]}`, `[1]`, `"x"`, `null`,
		`{"n":1e3}`, `{"n":-0}`, `{"n":12345678901234567890}`, `{"a":`, `{"a":1}x`,
		nestedObjects(17), nestedArrays(17), "{\"a\":\"\xff\"}",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	lim := Limits{MaxDepth: 16, MaxKeys: 64, MaxStringBytes: 256}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, findings, err := Args(raw, lim)
		if err == nil {
			for _, fd := range findings {
				if fd != FindingNonIntegerNumber {
					t.Fatalf("unexpected finding %q", fd)
				}
			}
			return
		}
		for _, want := range []error{ErrTooComplex, ErrDuplicateKeys, ErrNotObject, ErrInvalidJSON} {
			if errors.Is(err, want) {
				return
			}
		}
		t.Fatalf("Args(%q) returned non-sentinel error %v", raw, err)
	})
}
