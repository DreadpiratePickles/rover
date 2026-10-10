package normalize

import (
	"errors"
	"net/mail"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/cedar-policy/cedar-go/types"
)

// normURL parses a URL with net/url. Host matching in policy only works on
// a canonical host, so the host is lowercased and a trailing dot (which DNS
// ignores) is dropped. Userinfo ("https://good.com@evil.com/") is a classic
// way to make a URL look like it goes somewhere it does not, so it is a hard
// reject.
//
// IDN: Rover uses only the standard library here, which has no punycode
// encoder. A host with non-ASCII characters is lowercased and recorded with
// the finding "url_idn"; it will never equal an ASCII allowlist entry, so an
// allow rule simply does not match (fail closed).
func normURL(s string, fnd *findings) (types.RecordMap, error) {
	if strings.IndexByte(s, 0) >= 0 {
		return nil, errors.New("url contains a NUL byte")
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, errSkip
	}
	if u.User != nil {
		return nil, errors.New("url contains userinfo")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if !isASCII(host) {
		fnd.add("url_idn")
	}
	return types.RecordMap{
		"scheme":    types.String(strings.ToLower(u.Scheme)),
		"host":      types.String(host),
		"port":      types.String(u.Port()),
		"has_query": types.Boolean(u.RawQuery != "" || u.ForceQuery),
	}, nil
}

// normEmail splits an address into local part and lowercased domain.
// Display names ("Bob <bob@x.com>") are dropped. An address that does not
// parse is skipped with a finding.
func normEmail(s string, fnd *findings) (types.RecordMap, error) {
	if strings.IndexByte(s, 0) >= 0 {
		return nil, errors.New("email contains a NUL byte")
	}
	addr, err := mail.ParseAddress(s)
	if err != nil {
		return nil, errSkip
	}
	at := strings.LastIndexByte(addr.Address, '@')
	if at <= 0 || at == len(addr.Address)-1 {
		return nil, errSkip
	}
	domain := strings.TrimSuffix(strings.ToLower(addr.Address[at+1:]), ".")
	if !isASCII(domain) {
		fnd.add("email_idn")
	}
	return types.RecordMap{
		"local":  types.String(addr.Address[:at]),
		"domain": types.String(domain),
	}, nil
}

// shellMetachars are characters that let one shell string run more than one
// command or splice in another command's output: ; | & $ ` and newlines.
const shellMetachars = ";|&$`\n\r"

// normShell reports the program name (first word) and whether the command
// contains shell metacharacters. A policy should treat has_metachar as
// "this is not a single simple command".
func normShell(s string) (types.RecordMap, error) {
	if strings.IndexByte(s, 0) >= 0 {
		return nil, errors.New("shell command contains a NUL byte")
	}
	cmd := strings.TrimSpace(s)
	program := ""
	if fields := strings.Fields(cmd); len(fields) > 0 {
		program = fields[0]
	}
	return types.RecordMap{
		"command":      types.String(cmd),
		"program":      types.String(program),
		"has_metachar": types.Boolean(strings.ContainsAny(cmd, shellMetachars)),
	}, nil
}

// normSQL extracts the first keyword of a SQL string (after leading
// whitespace and comments) in upper case. is_select is true only for a
// single SELECT statement: "SELECT 1; DROP TABLE t" has multi_statement set
// and is_select false. A ';' inside a string literal also counts as
// multi_statement, which errs on the side of denying.
func normSQL(s string) (types.RecordMap, error) {
	if strings.IndexByte(s, 0) >= 0 {
		return nil, errors.New("sql contains a NUL byte")
	}
	body := skipSQLPrefix(s)
	end := 0
	for end < len(body) && isASCIILetter(body[end]) {
		end++
	}
	keyword := strings.ToUpper(body[:end])
	trimmed := strings.TrimRight(strings.TrimSpace(body), ";")
	multi := strings.Contains(trimmed, ";")
	return types.RecordMap{
		"statement":       types.String(keyword),
		"is_select":       types.Boolean(keyword == "SELECT" && !multi),
		"multi_statement": types.Boolean(multi),
	}, nil
}

// skipSQLPrefix drops leading whitespace, "-- line" and "/* block */"
// comments. An unterminated block comment leaves nothing.
func skipSQLPrefix(s string) string {
	for {
		s = strings.TrimLeft(s, " \t\r\n\f\v")
		switch {
		case strings.HasPrefix(s, "--"):
			i := strings.IndexByte(s, '\n')
			if i < 0 {
				return ""
			}
			s = s[i+1:]
		case strings.HasPrefix(s, "/*"):
			i := strings.Index(s[2:], "*/")
			if i < 0 {
				return ""
			}
			s = s[2+i+2:]
		default:
			return s
		}
	}
}

func isASCIILetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
