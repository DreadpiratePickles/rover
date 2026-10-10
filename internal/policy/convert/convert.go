// Package convert turns the JSON arguments of an MCP tools/call into a Cedar
// Record, so that policies can refer to them as context.args (plan §5.2).
//
// Why this package is strict: tool arguments are written by the model, and the
// model can be steered by anything it has read (a web page, a file, an email).
// Treat every byte here as attacker-controlled. The converter therefore fails
// closed: when the input is ambiguous or too large, it returns an error and
// the caller denies the call. It never "does its best" with suspicious input.
//
// Mapping (JSON -> Cedar):
//
//	string                              -> String
//	integer literal that fits in int64  -> Long
//	any other number (1.5, 1e3, -0,
//	  1.0, 9223372036854775808, ...)    -> String holding the original literal,
//	                                       plus the finding FindingNonIntegerNumber
//	true / false                        -> Boolean
//	object                              -> Record
//	array                               -> Set (order is lost and duplicate
//	                                       elements collapse, because a Cedar Set
//	                                       is unordered and has no duplicates)
//	null                                -> the key is omitted (and a null array
//	                                       element is dropped): Cedar has no null
package convert

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"

	"github.com/cedar-policy/cedar-go/types"

	"github.com/DreadpiratePickles/rover/internal/jsonrpc"
)

// Limits bounds how complex an arguments document may be.
//
// Limits are a deny, not a truncation. If we silently cut a deep or huge
// document down to size, the policy would judge a different value from the one
// the server receives (Rover forwards the original bytes). An attacker could
// then hide the dangerous part beyond the cut. Refusing the whole call is the
// only answer that cannot be bypassed this way. Limits also stop a hostile
// document from exhausting memory or the stack while we evaluate it.
type Limits struct {
	// MaxDepth is the deepest allowed nesting of objects and arrays. The
	// top-level object is depth 1.
	MaxDepth int
	// MaxKeys is the total number of object keys allowed in the whole document,
	// counted across every nested object.
	MaxKeys int
	// MaxStringBytes is the longest allowed string in bytes, after JSON escapes
	// are decoded. It applies to keys, string values and number literals.
	MaxStringBytes int
}

// DefaultLimits are the limits from plan §5.2.
var DefaultLimits = Limits{MaxDepth: 16, MaxKeys: 4096, MaxStringBytes: 1 << 20}

// Sentinel errors. Callers use errors.Is and turn each into a deny reason.
var (
	// ErrTooComplex means a limit in Limits was exceeded.
	ErrTooComplex = errors.New("args_too_complex")

	// ErrDuplicateKeys means one object contained the same key twice, at any
	// depth. This is a deny because of "parser differentials": JSON does not
	// say which of two duplicate keys wins. Some parsers keep the first, some
	// the last. If Rover's parser saw {"path":"/safe","path":"/etc/shadow"} as
	// /safe while the MCP server saw /etc/shadow, the policy would approve a
	// call that actually does something else. Rejecting duplicates removes the
	// disagreement entirely. Keys are compared after escapes are decoded, so
	// "a" and "a" count as the same key, and keys equal ignoring case
	// ("path" and "Path", strings.EqualFold) count as duplicates too, because
	// Go's encoding/json matches struct fields case-insensitively.
	ErrDuplicateKeys = errors.New("args_duplicate_keys")

	// ErrNotObject means the top-level JSON value was valid but was not an
	// object (for example an array, a string or null).
	ErrNotObject = errors.New("args_not_object")

	// ErrInvalidJSON means the input was not a single well-formed JSON value
	// in valid UTF-8. The underlying syntax error is wrapped for logs.
	ErrInvalidJSON = errors.New("args_invalid_json")
)

// FindingNonIntegerNumber is reported when a number could not be represented
// as a Cedar Long and was passed to the policy as a String instead.
const FindingNonIntegerNumber = "arg_non_integer_number"

// Args converts a JSON object to a Cedar Record per plan §5.2. It also returns
// the findings raised during conversion (each at most once, nil when none).
//
// It walks the input with json.Decoder tokens, so duplicate keys and limits
// are detected while parsing: no limit is checked "after the fact" on a fully
// decoded structure. Any error means the call must be denied; the returned
// error is always one of ErrTooComplex, ErrDuplicateKeys, ErrNotObject or
// ErrInvalidJSON (possibly wrapped, test with errors.Is).
func Args(raw []byte, lim Limits) (types.Record, []string, error) {
	// encoding/json silently replaces invalid UTF-8 with U+FFFD, which is a
	// parser differential of its own (two different byte strings would look
	// identical to the policy). Reject it up front.
	if !utf8.Valid(raw) {
		return types.Record{}, nil, fmt.Errorf("%w: invalid UTF-8", ErrInvalidJSON)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	c := &converter{dec: dec, lim: lim}

	tok, err := c.token()
	if err != nil {
		return types.Record{}, nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		// Not an object: deny without reading further. Whatever follows is
		// irrelevant, so there is no point spending work on it.
		return types.Record{}, nil, ErrNotObject
	}
	rec, err := c.object(1)
	if err != nil {
		return types.Record{}, nil, err
	}
	if err := c.expectEOF(); err != nil {
		return types.Record{}, nil, err
	}
	return rec, c.findings(), nil
}

// converter holds the state of one Args call.
type converter struct {
	dec        *json.Decoder
	lim        Limits
	keys       int
	nonInteger bool
}

func (c *converter) findings() []string {
	if c.nonInteger {
		return []string{FindingNonIntegerNumber}
	}
	return nil
}

// token reads the next token, mapping every decoder error to ErrInvalidJSON.
func (c *converter) token() (json.Token, error) {
	tok, err := c.dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: unexpected end of input", ErrInvalidJSON)
		}
		return nil, fmt.Errorf("%w: %w", ErrInvalidJSON, err)
	}
	return tok, nil
}

// expectEOF rejects trailing data such as `{} {}` or `{}x`: a second value is
// another chance for two parsers to disagree about what the arguments are.
func (c *converter) expectEOF() error {
	_, err := c.dec.Token()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidJSON, err)
	}
	return fmt.Errorf("%w: trailing data after the top-level value", ErrInvalidJSON)
}

// checkString enforces MaxStringBytes on a key, string value or number literal.
func (c *converter) checkString(s string) error {
	if len(s) > c.lim.MaxStringBytes {
		return fmt.Errorf("%w: string of %d bytes exceeds %d", ErrTooComplex, len(s), c.lim.MaxStringBytes)
	}
	return nil
}

// checkDepth enforces MaxDepth before entering a container at depth.
func (c *converter) checkDepth(depth int) error {
	if depth > c.lim.MaxDepth {
		return fmt.Errorf("%w: nesting depth exceeds %d", ErrTooComplex, c.lim.MaxDepth)
	}
	return nil
}

// object reads the members of an object whose '{' was already consumed.
func (c *converter) object(depth int) (types.Record, error) {
	if err := c.checkDepth(depth); err != nil {
		return types.Record{}, err
	}
	m := types.RecordMap{}
	seen := map[string]string{} // folded key -> first key
	for c.dec.More() {
		key, err := c.key()
		if err != nil {
			return types.Record{}, err
		}
		// Keys equal ignoring case count as duplicates too: a server that
		// decodes with encoding/json reads "Path" into its path field.
		fk := jsonrpc.FoldKey(key)
		if first, dup := seen[fk]; dup {
			return types.Record{}, fmt.Errorf("%w: key %q repeated as %q", ErrDuplicateKeys, first, key)
		}
		seen[fk] = key
		v, present, err := c.value(depth)
		if err != nil {
			return types.Record{}, err
		}
		if present {
			m[types.String(key)] = v
		}
	}
	if _, err := c.token(); err != nil { // the closing '}'
		return types.Record{}, err
	}
	return types.NewRecord(m), nil
}

// key reads one object key and applies the key-count and string limits.
func (c *converter) key() (string, error) {
	tok, err := c.token()
	if err != nil {
		return "", err
	}
	key, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("%w: object key is not a string", ErrInvalidJSON)
	}
	c.keys++
	if c.keys > c.lim.MaxKeys {
		return "", fmt.Errorf("%w: more than %d keys", ErrTooComplex, c.lim.MaxKeys)
	}
	if err := c.checkString(key); err != nil {
		return "", err
	}
	return key, nil
}

// array reads the elements of an array whose '[' was already consumed.
func (c *converter) array(depth int) (types.Set, error) {
	if err := c.checkDepth(depth); err != nil {
		return types.Set{}, err
	}
	var elems []types.Value
	for c.dec.More() {
		v, present, err := c.value(depth)
		if err != nil {
			return types.Set{}, err
		}
		if present {
			elems = append(elems, v)
		}
	}
	if _, err := c.token(); err != nil { // the closing ']'
		return types.Set{}, err
	}
	return types.NewSet(elems...), nil
}

// value reads one value inside a container at parentDepth. present is false
// for null, which has no Cedar equivalent and is omitted.
func (c *converter) value(parentDepth int) (v types.Value, present bool, err error) {
	tok, err := c.token()
	if err != nil {
		return nil, false, err
	}
	switch t := tok.(type) {
	case json.Delim:
		if t == '{' {
			rec, err := c.object(parentDepth + 1)
			return rec, err == nil, err
		}
		if t == '[' {
			set, err := c.array(parentDepth + 1)
			return set, err == nil, err
		}
		return nil, false, fmt.Errorf("%w: unexpected %q", ErrInvalidJSON, t)
	case string:
		if err := c.checkString(t); err != nil {
			return nil, false, err
		}
		return types.String(t), true, nil
	case json.Number:
		n, err := c.number(t)
		return n, err == nil, err
	case bool:
		return types.Boolean(t), true, nil
	case nil:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("%w: unexpected token %T", ErrInvalidJSON, tok)
	}
}

// number maps a JSON number literal to Long when it is a plain integer that
// fits in int64, and otherwise to a String of the original literal plus a
// finding. Policies comparing numbers then fail to match (deny by default)
// instead of comparing against a rounded or overflowed value.
func (c *converter) number(n json.Number) (types.Value, error) {
	lit := n.String()
	if err := c.checkString(lit); err != nil {
		return nil, err
	}
	if isPlainInteger(lit) {
		if i, err := strconv.ParseInt(lit, 10, 64); err == nil {
			return types.Long(i), nil
		}
	}
	c.nonInteger = true
	return types.String(lit), nil
}

// isPlainInteger reports whether lit is an integer literal with no fraction or
// exponent. "-0" is excluded: Long cannot carry the sign of zero, so it is
// passed through as a literal like other numbers that cannot round-trip.
func isPlainInteger(lit string) bool {
	if lit == "-0" {
		return false
	}
	for i := 0; i < len(lit); i++ {
		b := lit[i]
		if (b < '0' || b > '9') && (i != 0 || b != '-') {
			return false
		}
	}
	return lit != "" && lit != "-"
}
