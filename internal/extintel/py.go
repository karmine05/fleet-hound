package extintel

// Python-semantics helpers: the scorer must produce the same numbers and the
// same strings as src/extension_intel.py for the same inputs, so truthiness,
// int()/float() coercion, str(), round(), str slicing (code points),
// json.dumps (ensure_ascii, compact) and datetime.fromisoformat are mirrored
// here instead of using the nearest Go idiom.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/karmine05/fleet-hound/internal/graphdb"
)

// isPySpace is python str.isspace() for one code point.
func isPySpace(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) }

// pyStrip is python str.strip().
func pyStrip(s string) string { return strings.TrimFunc(s, isPySpace) }

// pySplit is python str.split() (no separator).
func pySplit(s string) []string { return strings.FieldsFunc(s, isPySpace) }

// cleanStr is _clean_str: stripped string, "" for non-strings.
func cleanStr(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return pyStrip(s)
}

// runePrefix is python s[:n] (code points, not bytes).
func runePrefix(s string, n int) string {
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}

// truthy is python bool(v).
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case int:
		return t != 0
	case int64:
		return t != 0
	case int32:
		return t != 0
	case float64:
		return t != 0
	case []any:
		return len(t) > 0
	case []string:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice, reflect.Map, reflect.Array, reflect.String:
		return rv.Len() > 0
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int() != 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint() != 0
	case reflect.Float32, reflect.Float64:
		return rv.Float() != 0
	case reflect.Pointer, reflect.Interface:
		return !rv.IsNil()
	}
	return true
}

// pyOr is python `a or b`.
func pyOr(vals ...any) any {
	for _, v := range vals[:len(vals)-1] {
		if truthy(v) {
			return v
		}
	}
	return vals[len(vals)-1]
}

// intOf is `type(v) is int` (bool excluded) plus the value.
func intOf(v any) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case int:
		return int64(t), true
	case int32:
		return int64(t), true
	case int16:
		return int64(t), true
	case int8:
		return int64(t), true
	case uint32:
		return int64(t), true
	case uint16:
		return int64(t), true
	case uint8:
		return int64(t), true
	case uint:
		if uint64(t) <= math.MaxInt64 {
			return int64(t), true
		}
	case uint64:
		if t <= math.MaxInt64 {
			return int64(t), true
		}
	}
	return 0, false
}

// numOf is `type(v) in (int, float)` plus the value as float64.
func numOf(v any) (float64, bool) {
	if i, ok := intOf(v); ok {
		return float64(i), true
	}
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	}
	return 0, false
}

// pyParseFloat is python float(str).
func pyParseFloat(s string) (float64, bool) {
	s = strings.ToLower(pyStrip(s))
	switch strings.TrimLeft(s, "+-") {
	case "inf", "infinity":
		if strings.HasPrefix(s, "-") {
			return math.Inf(-1), true
		}
		return math.Inf(1), true
	case "nan":
		return math.NaN(), true
	case "":
		return 0, false
	}
	// Go also accepts hex floats and "0x"/underscore forms python float() rejects.
	if strings.ContainsAny(s, "xp_") {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
			return f, true
		}
		return 0, false
	}
	return f, true
}

// asFloat is _as_float: None/"" -> None, float(v) else None.
func asFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case nil:
		return 0, false
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case string:
		if t == "" {
			return 0, false
		}
		return pyParseFloat(t)
	}
	return numOf(v)
}

// asInt is _as_int: int(float(v)), None on failure (and for inf/nan, which
// python raises on).
func asInt(v any) (int64, bool) {
	f, ok := asFloat(v)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	f = math.Trunc(f)
	if f >= 9.223372036854775807e18 || f < -9.223372036854775808e18 {
		return 0, false
	}
	return int64(f), true
}

// asIntOr0 is `_as_int(v) or 0`.
func asIntOr0(v any) int64 {
	i, _ := asInt(v)
	return i
}

// pyIntLoose is `int(v or 0)` for scorer inputs (feed threat, weights):
// ints, floats (truncated), bools and integer strings; 0 otherwise.
func pyIntLoose(v any) int64 {
	if i, ok := intOf(v); ok {
		return i
	}
	switch t := v.(type) {
	case bool:
		if t {
			return 1
		}
	case float64:
		if !math.IsNaN(t) && !math.IsInf(t, 0) {
			return int64(t)
		}
	case string:
		if i, err := strconv.ParseInt(pyStrip(t), 10, 64); err == nil {
			return i
		}
	}
	return 0
}

// toList returns v as []any when it is a slice (python list/tuple).
func toList(v any) ([]any, bool) {
	switch t := v.(type) {
	case []any:
		return t, true
	case []string:
		out := make([]any, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out, true
	case []map[string]any:
		out := make([]any, len(t))
		for i, m := range t {
			out[i] = m
		}
		return out, true
	case nil, string, []byte:
		return nil, false
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil, false
	}
	out := make([]any, rv.Len())
	for i := range out {
		out[i] = rv.Index(i).Interface()
	}
	return out, true
}

// toMap returns v as a map when it is a python dict.
func toMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// asStringList is _as_string_list.
func asStringList(v any) []string {
	if s, ok := v.(string); ok {
		return []string{s}
	}
	list, ok := toList(v)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		switch t := e.(type) {
		case string:
			out = append(out, t)
		case bool:
			out = append(out, pyStr(t))
		default:
			if i, ok := intOf(t); ok {
				out = append(out, strconv.FormatInt(i, 10))
			}
		}
	}
	return out
}

// pyStr is python str(v) for the value kinds records carry.
func pyStr(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case bool:
		if t {
			return "True"
		}
		return "False"
	case string:
		return t
	case float64:
		return pyFloatRepr(t)
	case float32:
		return pyFloatRepr(float64(t))
	}
	if i, ok := intOf(v); ok {
		return strconv.FormatInt(i, 10)
	}
	return fmt.Sprint(v)
}

// pyFloatRepr is python repr(float).
func pyFloatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	s := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expStr, _ := strings.Cut(s, "e")
	exp, _ := strconv.Atoi(expStr)
	if exp < -4 || exp >= 16 {
		return mant + "e" + expStr
	}
	s = strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.ContainsAny(s, ".") {
		s += ".0"
	}
	return s
}

// pyRound1 is python round(f, 1) (correctly rounded, half-even on exact ties).
func pyRound1(f float64) float64 {
	r, _ := strconv.ParseFloat(strconv.FormatFloat(f, 'f', 1, 64), 64)
	return r
}

// pyRound is python round(f) -> int (banker's rounding).
func pyRound(f float64) int64 { return int64(math.RoundToEven(f)) }

var pow10 = func() []float64 {
	out := make([]float64, 23)
	for i := range out {
		out[i] = math.Pow10(i)
	}
	return out
}()

// pyLog10 is C log10, which is exact on powers of ten (Go's math.Log10 is
// not: Log10(1e15) = 14.999999999999998, which would change int(4*log10)).
func pyLog10(x float64) float64 {
	for i, p := range pow10 {
		if x == p {
			return float64(i)
		}
	}
	return math.Log10(x)
}

// commaInt is python f"{n:,}".
func commaInt(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// pyQuote is urllib.parse.quote(s, safe=safe).
func pyQuote(s, safe string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.IndexByte("_.-~", c) >= 0 || strings.IndexByte(safe, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// decodeReplace is bytes.decode("utf-8", "replace").
func decodeReplace(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			sb.WriteRune(utf8.RuneError)
		} else {
			sb.Write(b[:size])
		}
		b = b[size:]
	}
	return sb.String()
}

// decodeSig is bytes.decode("utf-8-sig", "replace").
func decodeSig(b []byte) string {
	return decodeReplace(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")))
}

// pySplitLines is python str.splitlines().
func pySplitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch r {
		case '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			out = append(out, s[start:i])
			i += size
			if r == '\r' && i < len(s) && s[i] == '\n' {
				i++
			}
			start = i
			continue
		}
		i += size
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// pyJSONLoads is json.loads: one value, trailing whitespace only; integers
// int64, others float64 (graphdb.FromJSON).
func pyJSONLoads(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if rest := bytes.TrimLeft(data[dec.InputOffset():], " \t\r\n"); len(rest) > 0 {
		return nil, fmt.Errorf("invalid JSON: extra data at offset %d", dec.InputOffset())
	}
	return graphdb.FromJSON(v), nil
}

// pyISOFromUnix is datetime.fromtimestamp(ts, timezone.utc).isoformat().
func pyISOFromUnix(ts float64) string {
	sec := math.Floor(ts)
	us := math.RoundToEven((ts - sec) * 1e6)
	if us >= 1e6 {
		sec++
		us -= 1e6
	}
	t := time.Unix(int64(sec), int64(us)*1000).UTC()
	if us == 0 {
		return t.Format("2006-01-02T15:04:05") + "+00:00"
	}
	return t.Format("2006-01-02T15:04:05.000000") + "+00:00"
}

// isoRe covers the python 3.11 datetime.fromisoformat forms seen in store
// data and config files: date, optional any-char separator + time with
// optional fraction, optional Z/offset.
var isoRe = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})(?:.(\d{2})(?::(\d{2})(?::(\d{2})(?:[.,](\d+))?)?)?` +
	`(Z|[+-]\d{2}(?::?\d{2}(?::?\d{2}(?:\.\d+)?)?)?)?)?$`)

// pyFromISO is datetime.fromisoformat (naive results are taken as UTC, as
// _parse_iso does).
func pyFromISO(s string) (time.Time, bool) {
	m := isoRe.FindStringSubmatch(s)
	if m == nil {
		return time.Time{}, false
	}
	atoi := func(x string) int { n, _ := strconv.Atoi(x); return n }
	y, mo, d := atoi(m[1]), atoi(m[2]), atoi(m[3])
	h, mi, sec := atoi(m[4]), atoi(m[5]), atoi(m[6])
	if mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || sec > 59 {
		return time.Time{}, false
	}
	ns := 0
	if m[7] != "" {
		frac := (m[7] + "000000")[:6]
		ns = atoi(frac) * 1000
	}
	loc := time.UTC
	if tz := m[8]; tz != "" && tz != "Z" {
		digits := strings.ReplaceAll(tz[1:], ":", "")
		digits, _, _ = strings.Cut(digits, ".")
		oh := atoi(digits[:2])
		om, os := 0, 0
		if len(digits) >= 4 {
			om = atoi(digits[2:4])
		}
		if len(digits) >= 6 {
			os = atoi(digits[4:6])
		}
		if oh > 23 || om > 59 || os > 59 || (len(digits) != 2 && len(digits) != 4 && len(digits) != 6) {
			return time.Time{}, false
		}
		off := oh*3600 + om*60 + os
		if tz[0] == '-' {
			off = -off
		}
		loc = time.FixedZone("", off)
	}
	t := time.Date(y, time.Month(mo), d, h, mi, sec, ns, loc)
	if t.Day() != d || int(t.Month()) != mo {
		return time.Time{}, false
	}
	return t, true
}

// pyKeyOrder fixes the python insertion order of the dict shapes this package
// serialises (signals, vulnerability summaries). Other keys sort after them.
var pyKeyOrder = map[string]int{
	"code": 0, "weight": 1, "detail": 2,
	"cve": 10, "cvss_score": 11, "epss_probability": 12, "details": 13, "created_at": 14,
}

// pyDumps is json.dumps(v, separators=(",", ":"), default=str) with python's
// default ensure_ascii.
func pyDumps(v any) string {
	var b strings.Builder
	pyEncode(&b, v)
	return b.String()
}

func pyEncode(b *strings.Builder, v any) {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
		return
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
		return
	case string:
		pyEncodeString(b, t)
		return
	case float64:
		pyEncodeFloat(b, t)
		return
	case float32:
		pyEncodeFloat(b, float64(t))
		return
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.SliceStable(keys, func(i, j int) bool {
			oi, iok := pyKeyOrder[keys[i]]
			oj, jok := pyKeyOrder[keys[j]]
			switch {
			case iok && jok:
				return oi < oj
			case iok != jok:
				return iok
			}
			return keys[i] < keys[j]
		})
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			pyEncodeString(b, k)
			b.WriteByte(':')
			pyEncode(b, t[k])
		}
		b.WriteByte('}')
		return
	}
	if i, ok := intOf(v); ok {
		b.WriteString(strconv.FormatInt(i, 10))
		return
	}
	if list, ok := toList(v); ok {
		b.WriteByte('[')
		for i, e := range list {
			if i > 0 {
				b.WriteByte(',')
			}
			pyEncode(b, e)
		}
		b.WriteByte(']')
		return
	}
	pyEncodeString(b, pyStr(v)) // default=str
}

func pyEncodeFloat(b *strings.Builder, f float64) {
	switch {
	case math.IsNaN(f):
		b.WriteString("NaN")
	case math.IsInf(f, 1):
		b.WriteString("Infinity")
	case math.IsInf(f, -1):
		b.WriteString("-Infinity")
	default:
		b.WriteString(pyFloatRepr(f))
	}
}

func pyEncodeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s { // invalid UTF-8 decodes as U+FFFD
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r >= 0x20 && r <= 0x7e:
				b.WriteRune(r)
			case r > 0xffff:
				r -= 0x10000
				fmt.Fprintf(b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			default:
				fmt.Fprintf(b, `\u%04x`, r)
			}
		}
	}
	b.WriteByte('"')
}

// isBlank is `value in (None, "", [], {})`.
func isBlank(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case map[string]any:
		return len(t) == 0
	}
	if l, ok := toList(v); ok {
		return len(l) == 0
	}
	return false
}

// optStr is `s or None`.
func optStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func optInt(i int64, ok bool) any {
	if !ok {
		return nil
	}
	return i
}

func optFloat(f float64, ok bool) any {
	if !ok {
		return nil
	}
	return f
}

// optBool is `v if isinstance(v, bool) else None`.
func optBool(v any) any {
	if b, ok := v.(bool); ok {
		return b
	}
	return nil
}

func set[T comparable](items ...T) map[T]struct{} {
	m := make(map[T]struct{}, len(items))
	for _, it := range items {
		m[it] = struct{}{}
	}
	return m
}

func has[T comparable](m map[T]struct{}, k T) bool {
	_, ok := m[k]
	return ok
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+4)
	for k, v := range m {
		out[k] = v
	}
	return out
}
