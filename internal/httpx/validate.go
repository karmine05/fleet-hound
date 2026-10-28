package httpx

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

// MaxRegexLen is _MAX_REGEX_LEN.
const MaxRegexLen = 100

// Python's \s and \d on str patterns are Unicode-aware; RE2's are ASCII, so
// the classes are spelled out to keep the blocklist at least as strict.
const (
	pySpace = `[\s\v\p{Z}\x{1c}-\x{1f}\x{85}]`
	pyDigit = `\p{Nd}`
)

// redosBlocklist is _REDOS_BLOCKLIST (all four shapes are RE2-compatible).
var redosBlocklist = []*regexp.Regexp{
	regexp.MustCompile(`[+*?]` + pySpace + `*\)` + pySpace + `*[+*?]`),                                     // (a+)+, (a*)*
	regexp.MustCompile(`\(.+\)` + pySpace + `*\{` + pyDigit + `+,?` + pyDigit + `*\}` + pySpace + `*[+*]`), // (x){n,}+
	regexp.MustCompile(`(?:\.\*){2,}`),                                                                     // .*.*
	regexp.MustCompile(`(?:\.\+){2,}`),                                                                     // .+.+
}

// ValidateUserRegex replaces _validate_user_regex. Returns ("", true) when
// the pattern is acceptable, else the python error message:
//
//	"regex pattern must be <= 100 chars"
//	"regex pattern rejected for safety (potential ReDoS)"
//	"invalid regex: <detail>"
//
// Length is counted in code points like python len(). Validity is checked
// with Go RE2; constructs python re accepts but RE2 lacks (lookarounds,
// backreferences, (?P=name), (?#...), \Z, possessive quantifiers) are passed
// through, as python did, because Memgraph evaluates the regex itself. The
// "<detail>" text of a rejection differs from python's.
// The python `pattern is None -> "regex required"` case is the caller's
// missing-parameter check.
func ValidateUserRegex(pattern string) (string, bool) {
	if utf8.RuneCountInString(pattern) > MaxRegexLen {
		return fmt.Sprintf("regex pattern must be <= %d chars", MaxRegexLen), false
	}
	for _, re := range redosBlocklist {
		if re.MatchString(pattern) {
			return "regex pattern rejected for safety (potential ReDoS)", false
		}
	}
	if leadingBracketClass(pattern) {
		// Python reads []a] / [^]a] as one class; Memgraph's ECMAScript engine
		// reads [] as empty and [^] as any-char. Reject so both parsers agree.
		return "regex pattern rejected: '[]' or '[^]' at the start of a class is ambiguous; escape it as '\\]'", false
	}
	if repeatedAmbiguousGroup(pattern) {
		return "regex pattern rejected for safety (potential ReDoS)", false
	}
	if _, err := regexp.Compile(pattern); err != nil && !pythonOnlySyntax(err) {
		return "invalid regex: " + err.Error(), false
	}
	return "", true
}

// repeatedAmbiguousGroup reports a group repeated by *, +, {n,} or {n,m}
// (m >= 2) whose body holds an alternation or a quantifier: (a|aa)+,
// (.|.)+, (.*a){12}, (a?)+. Memgraph's =~ backtracks, so these cost
// exponential time per value; the blocklist above only spots fixed shapes.
// It scans text rather than an RE2 parse tree so that python-only syntax
// (lookarounds, backreferences) cannot hide a group from the check.
func repeatedAmbiguousGroup(p string) bool {
	risky := []bool{false} // per open group: body has | or a quantifier
	for i := 0; i < len(p); i++ {
		top := len(risky) - 1
		switch p[i] {
		case '\\':
			i++
		case '[':
			i = classEnd(p, i)
		case '(':
			risky = append(risky, false)
			if i+1 < len(p) && p[i+1] == '?' {
				i++ // (?: (?= (?<name> ... : group syntax, not a quantifier
			}
		case ')':
			if top == 0 {
				continue // unbalanced; left to the compile check / Memgraph
			}
			body := risky[top]
			risky = risky[:top]
			n, repeats, isQuant := quantifierAt(p, i+1)
			if isQuant && repeats && body {
				return true
			}
			if isQuant || body {
				risky[top-1] = true
			}
			i += n
		case '|', '*', '+', '?':
			risky[top] = true
		case '{':
			if n, _, ok := quantifierAt(p, i); ok {
				risky[top] = true
				i += n - 1
			}
		}
	}
	return false
}

// classEnd returns the index of the ']' closing the class opened at p[i].
// leadingBracketClass reports an unescaped class opening as "[]" or "[^]".
func leadingBracketClass(p string) bool {
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '\\':
			i++
		case '[':
			j := i + 1
			if j < len(p) && p[j] == '^' {
				j++
			}
			if j < len(p) && p[j] == ']' {
				return true
			}
			i = classEnd(p, i)
		}
	}
	return false
}

func classEnd(p string, i int) int {
	j := i + 1
	if j < len(p) && p[j] == '^' {
		j++
	}
	if j < len(p) && p[j] == ']' {
		j++ // leading ] is a literal
	}
	for ; j < len(p); j++ {
		switch p[j] {
		case '\\':
			j++
		case ']':
			return j
		}
	}
	return len(p)
}

// quantifierAt reports whether p[i:] starts with a quantifier, its length
// (including a lazy/possessive suffix) and whether it can repeat more than
// once.
func quantifierAt(p string, i int) (n int, repeats, ok bool) {
	if i >= len(p) {
		return 0, false, false
	}
	switch p[i] {
	case '*', '+':
		n, repeats = 1, true
	case '?':
		n = 1
	case '{':
		m := braceQuant.FindStringSubmatch(p[i:])
		if m == nil {
			return 0, false, false
		}
		n = len(m[0])
		hi := m[1]
		if m[2] != "" {
			hi = m[3]
		}
		repeats = hi == "" || len(hi) > 1 || hi[0] >= '2'
	default:
		return 0, false, false
	}
	if i+n < len(p) && (p[i+n] == '?' || p[i+n] == '+') {
		n++
	}
	return n, repeats, true
}

var braceQuant = regexp.MustCompile(`^\{([0-9]+)(,)?([0-9]*)\}`)

// pythonOnlySyntax reports whether RE2 failed on syntax that python re (the
// validator being ported) accepts. shortcut: only the first RE2 error is
// seen, so a pattern mixing such syntax with a real error is left to
// Memgraph, which then answers 400 "Database error".
func pythonOnlySyntax(err error) bool {
	var se *syntax.Error
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code {
	case syntax.ErrInvalidPerlOp: // (?= (?! (?P=name) (?#...)
		return true
	case syntax.ErrInvalidNamedCapture: // (?<= (?<!
		return strings.HasPrefix(se.Expr, "(?<=") || strings.HasPrefix(se.Expr, "(?<!")
	case syntax.ErrInvalidEscape: // \1-\9 backreference, \Z
		return len(se.Expr) == 2 && (se.Expr[1] >= '1' && se.Expr[1] <= '9' || se.Expr[1] == 'Z')
	case syntax.ErrInvalidRepeatOp: // possessive a++ a*+ a?+ (python 3.11+)
		return len(se.Expr) == 2 && se.Expr[1] == '+'
	}
	return false
}

// NormalizeWhitelist replaces _normalize_whitelist: entries stringified,
// trimmed, lowercased, de-duplicated preserving first-seen order. Falsy
// entries (nil, false, 0, "") are skipped like python `str(raw or "")`.
func NormalizeWhitelist(entries []any) []string {
	seen := make(map[string]struct{}, len(entries))
	out := make([]string, 0, len(entries))
	for _, raw := range entries {
		var s string
		switch t := raw.(type) {
		case nil:
			continue
		case string:
			s = t
		case bool:
			if !t {
				continue
			}
			s = "True"
		case float64:
			if t == 0 {
				continue
			}
			s = fmt.Sprint(t)
		default:
			s = fmt.Sprint(t)
			if s == "0" {
				continue
			}
		}
		item := strings.ToLower(strings.TrimSpace(s))
		if item == "" {
			continue
		}
		if _, dup := seen[item]; dup {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

// WhitelistClause replaces _whitelist_clause(alias): excludes software whose
// name or display_name (lowercased) is in the $whitelist parameter.
func WhitelistClause(alias string) string {
	return fmt.Sprintf("AND NOT (toLower(%s.name) IN $whitelist "+
		"OR toLower(coalesce(%s.display_name, '')) IN $whitelist)", alias, alias)
}

func isASCIIAlnumLower(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// WordMatch replaces _word_match: true when pattern occurs in textLower with
// no [a-z0-9] byte immediately before or after it (python
// `(?<![a-z0-9])re.escape(pattern)(?![a-z0-9])`, implemented without
// lookarounds). Matching is case-sensitive; callers pass lowercased text.
func WordMatch(pattern, textLower string) bool {
	if pattern == "" || textLower == "" {
		return false
	}
	for off := 0; off <= len(textLower)-len(pattern); {
		i := strings.Index(textLower[off:], pattern)
		if i < 0 {
			return false
		}
		start := off + i
		end := start + len(pattern)
		if (start == 0 || !isASCIIAlnumLower(textLower[start-1])) &&
			(end == len(textLower) || !isASCIIAlnumLower(textLower[end])) {
			return true
		}
		off = start + 1
	}
	return false
}

// IsLoopback replaces _is_loopback: addr parses as an IP in 127.0.0.0/8 or
// ::1. Like python ipaddress, an IPv4-mapped IPv6 address (::ffff:127.0.0.1)
// is NOT loopback.
func IsLoopback(addr string) bool {
	if addr == "" {
		return false
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	ip = ip.WithZone("")
	if ip.Is4() {
		return ip.As4()[0] == 127
	}
	return ip == netip.IPv6Loopback()
}

// IsLoopbackHost replaces _is_loopback_host: strips ":port" (except from a
// bare "[::1]"), strips surrounding brackets, lowercases, then accepts
// "localhost" or a loopback IP.
func IsLoopbackHost(host string) bool {
	h := host
	if !strings.HasSuffix(h, "]") {
		if i := strings.LastIndex(h, ":"); i >= 0 {
			h = h[:i]
		}
	}
	h = strings.ToLower(strings.Trim(h, "[]"))
	return h == "localhost" || IsLoopback(h)
}

// ClientIP replaces _client_ip: the direct TCP peer (request.remote_addr).
// X-Forwarded-For is deliberately ignored: python never trusted it either.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return strings.TrimSpace(host)
}
