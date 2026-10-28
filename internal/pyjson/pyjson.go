// Package pyjson encodes values byte-identically to python json.dumps with
// ensure_ascii=True and separators=(",", ":"). Hashes and strings that python
// computed over json.dumps output (snapshot node hashes, label member hashes)
// only stay comparable if Go produces the same bytes. Owner: agent A.
package pyjson

import (
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// KV is one key/value pair of an Ordered object.
type KV struct {
	K string
	V any
}

// Ordered is a JSON object that keeps insertion order (a python dict built
// key by key). Plain map[string]any values are always written with sorted
// keys, since Go maps have no order.
type Ordered []KV

// Marshal is json.dumps(v, separators=(",", ":"), default=str), with
// sort_keys applied to every map[string]any (Ordered keeps its order).
// Values python could not encode fall back to fmt.Sprint (default=str).
func Marshal(v any) []byte {
	var b strings.Builder
	write(&b, v)
	return []byte(b.String())
}

func write(b *strings.Builder, v any) {
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
		Quote(b, t)
	case int:
		b.WriteString(strconv.Itoa(t))
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case int32:
		b.WriteString(strconv.FormatInt(int64(t), 10))
	case uint64:
		b.WriteString(strconv.FormatUint(t, 10))
	case float64:
		b.WriteString(Float(t))
	case float32:
		b.WriteString(Float(float64(t)))
	case Ordered:
		b.WriteByte('{')
		for i, kv := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			Quote(b, kv.K)
			b.WriteByte(':')
			write(b, kv.V)
		}
		b.WriteByte('}')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			Quote(b, k)
			b.WriteByte(':')
			write(b, t[k])
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			write(b, e)
		}
		b.WriteByte(']')
	default:
		rv := reflect.ValueOf(v)
		if rv.Kind() == reflect.Slice && rv.Type().Elem().Kind() != reflect.Uint8 {
			b.WriteByte('[')
			for i := 0; i < rv.Len(); i++ {
				if i > 0 {
					b.WriteByte(',')
				}
				write(b, rv.Index(i).Interface())
			}
			b.WriteByte(']')
			return
		}
		Quote(b, fmt.Sprint(v)) // python default=str
	}
}

// Float is python repr(float) as json.dumps writes it: shortest round-trip
// digits, scientific only when the exponent is < -4 or >= 16, a trailing
// ".0" on integral values, and NaN/Infinity/-Infinity (allow_nan=True).
func Float(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±XX
	mant, expStr, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expStr)
	if exp < -4 || exp >= 16 {
		sign := "+"
		if exp < 0 {
			sign, exp = "-", -exp
		}
		return fmt.Sprintf("%se%s%02d", mant, sign, exp)
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.ContainsAny(s, ".") {
		s += ".0"
	}
	return s
}

// Quote writes s as a python ensure_ascii JSON string: everything outside
// printable ASCII becomes \uXXXX (surrogate pairs above the BMP).
func Quote(b *strings.Builder, s string) {
	const hex = "0123456789abcdef"
	u := func(r rune) {
		b.WriteString(`\u`)
		b.WriteByte(hex[r>>12&0xf])
		b.WriteByte(hex[r>>8&0xf])
		b.WriteByte(hex[r>>4&0xf])
		b.WriteByte(hex[r&0xf])
	}
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r >= 0x20 && r <= 0x7e:
			b.WriteByte(byte(r))
		case r > 0xffff:
			r -= 0x10000
			u(0xd800 | (r>>10)&0x3ff)
			u(0xdc00 | r&0x3ff)
		default:
			u(r)
		}
	}
	b.WriteByte('"')
}

// Str is python str(v) for the scalar shapes graph values take (used for
// f"{kind}_{name}" ids): ints in decimal, floats via repr, bools True/False.
func Str(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case float64:
		switch {
		case math.IsNaN(t):
			return "nan"
		case math.IsInf(t, 1):
			return "inf"
		case math.IsInf(t, -1):
			return "-inf"
		}
		return Float(t)
	}
	return fmt.Sprint(v)
}

// Truthy is python bool(v) for decoded JSON / record values.
func Truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case bool:
		return t
	case int64:
		return t != 0
	case int:
		return t != 0
	case float64:
		return t != 0
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	return true
}

// Or is python `a or b or c`: the first truthy value, else the last one.
func Or(vs ...any) any {
	for _, v := range vs {
		if Truthy(v) {
			return v
		}
	}
	if len(vs) == 0 {
		return nil
	}
	return vs[len(vs)-1]
}
