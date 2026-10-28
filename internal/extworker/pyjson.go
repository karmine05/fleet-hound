package extworker

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// pyDumps reproduces python json.dumps(v, sort_keys=True,
// separators=(",", ":"), default=str) byte for byte for JSON-shaped values
// (ensure_ascii escaping, float repr). Fingerprints persisted on :Software
// nodes by the python worker hash this text, so matching it keeps the
// cutover from re-scoring every extension.
func pyDumps(v any) string {
	var b strings.Builder
	writePy(&b, v)
	return b.String()
}

func writePy(b *strings.Builder, v any) {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writePyString(b, t)
	case int:
		b.WriteString(strconv.Itoa(t))
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case int32:
		b.WriteString(strconv.FormatInt(int64(t), 10))
	case uint64:
		b.WriteString(strconv.FormatUint(t, 10))
	case float64:
		b.WriteString(pyFloat(t))
	case float32:
		b.WriteString(pyFloat(float64(t)))
	case json.Number:
		b.WriteString(t.String())
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			writePy(b, e)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // byte order of UTF-8 == code point order
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writePyString(b, k)
			b.WriteByte(':')
			writePy(b, t[k])
		}
		b.WriteByte('}')
	default:
		writePyReflect(b, v)
	}
}

func writePyReflect(b *strings.Builder, v any) {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			b.WriteString("null")
			return
		}
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = rv.Index(i).Interface()
		}
		writePy(b, out)
	case reflect.Map:
		if rv.IsNil() {
			b.WriteString("null")
			return
		}
		out := make(map[string]any, rv.Len())
		for _, k := range rv.MapKeys() {
			out[fmt.Sprint(k.Interface())] = rv.MapIndex(k).Interface()
		}
		writePy(b, out)
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			b.WriteString("null")
			return
		}
		writePy(b, rv.Elem().Interface())
	case reflect.Int, reflect.Int8, reflect.Int16:
		b.WriteString(strconv.FormatInt(rv.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32:
		b.WriteString(strconv.FormatUint(rv.Uint(), 10))
	default:
		writePyString(b, fmt.Sprint(v)) // default=str
	}
}

const hexDigits = "0123456789abcdef"

func writePyString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
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
			if r >= 0x20 && r <= 0x7e {
				b.WriteRune(r)
			} else if r > 0xffff {
				r -= 0x10000
				writeU(b, 0xd800|((r>>10)&0x3ff))
				writeU(b, 0xdc00|(r&0x3ff))
			} else {
				if r == utf8.RuneError {
					r = 0xfffd
				}
				writeU(b, r)
			}
		}
	}
	b.WriteByte('"')
}

func writeU(b *strings.Builder, r rune) {
	b.WriteString(`\u`)
	for shift := 12; shift >= 0; shift -= 4 {
		b.WriteByte(hexDigits[(r>>uint(shift))&0xf])
	}
}

// pyFloat is python float.__repr__ (json uses it): shortest round-trip
// digits, fixed notation for 1e-4 <= |x| < 1e16, else d.ddde+XX.
func pyFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	s := strconv.FormatFloat(f, 'e', -1, 64)
	sign := ""
	if s[0] == '-' {
		sign, s = "-", s[1:]
	}
	mant, expStr, _ := strings.Cut(s, "e")
	exp, _ := strconv.Atoi(expStr)
	digits := strings.Replace(mant, ".", "", 1)
	if exp >= -4 && exp < 16 {
		var intPart, frac string
		if exp >= 0 {
			if len(digits) <= exp+1 {
				intPart, frac = digits+strings.Repeat("0", exp+1-len(digits)), "0"
			} else {
				intPart, frac = digits[:exp+1], digits[exp+1:]
			}
		} else {
			intPart, frac = "0", strings.Repeat("0", -exp-1)+digits
		}
		return sign + intPart + "." + frac
	}
	m := digits[:1]
	if len(digits) > 1 {
		m += "." + digits[1:]
	}
	return sign + m + fmt.Sprintf("e%+03d", exp)
}
