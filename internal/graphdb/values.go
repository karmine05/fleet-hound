package graphdb

import (
	"bytes"
	"encoding/json"
	"math"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j/dbtype"
)

// Data replaces python Record.data(): a map of key -> Value(v).
func Data(rec *neo4j.Record) map[string]any {
	if rec == nil {
		return nil
	}
	out := make(map[string]any, len(rec.Keys))
	for i, k := range rec.Keys {
		out[k] = Value(rec.Values[i])
	}
	return out
}

// Value converts a driver value into the JSON-friendly shape python's
// Record.data() + Flask jsonify produced:
//
//   - Node            -> map of its properties (dict(node))
//   - Relationship    -> [startProps, type, endProps]; the Go driver does not
//     hydrate endpoint nodes for a bare relationship, so start/end are {}
//     (python returned the endpoint property dicts). Use Run + raw records
//     when endpoints matter.
//   - Path            -> [node, rel, node, ...] each converted as above
//   - temporal types  -> ISO-8601 strings (python jsonify would have 500'd)
//   - NaN / +-Inf     -> nil (python emitted invalid JSON tokens)
//   - lists / maps    -> converted recursively; scalars unchanged (int64,
//     float64, string, bool, nil, []byte)
func Value(v any) any {
	switch t := v.(type) {
	case nil, string, bool, int64, []byte:
		return t
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return nil
		}
		return t
	case dbtype.Node:
		return propsOf(t.Props)
	case *dbtype.Node:
		return propsOf(t.Props)
	case dbtype.Relationship:
		return []any{map[string]any{}, t.Type, map[string]any{}}
	case *dbtype.Relationship:
		return []any{map[string]any{}, t.Type, map[string]any{}}
	case dbtype.Path:
		return pathValue(t)
	case *dbtype.Path:
		return pathValue(*t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = Value(e)
		}
		return out
	case map[string]any:
		return propsOf(t)
	case dbtype.Date:
		return t.Time().Format("2006-01-02")
	case dbtype.LocalTime:
		return t.Time().Format("15:04:05.999999999")
	case dbtype.LocalDateTime:
		return t.Time().Format("2006-01-02T15:04:05.999999999")
	case dbtype.Time:
		return t.Time().Format("15:04:05.999999999Z07:00")
	case time.Time:
		return t.Format(time.RFC3339Nano)
	case dbtype.Duration:
		return t.String()
	default:
		return t
	}
}

func propsOf(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, e := range m {
		out[k] = Value(e)
	}
	return out
}

func pathValue(p dbtype.Path) []any {
	out := make([]any, 0, len(p.Nodes)+len(p.Relationships))
	for i, n := range p.Nodes {
		out = append(out, propsOf(n.Props))
		if i < len(p.Relationships) {
			out = append(out, Value(p.Relationships[i]))
		}
	}
	return out
}

// AsInt64 converts a record value to int64 (python int(x or 0)): int64,
// float64 (truncated) and nil (0) are accepted; anything else returns 0,false.
func AsInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case nil:
		return 0, true
	case int64:
		return t, true
	case int:
		return int64(t), true
	case float64:
		return int64(t), true
	}
	return 0, false
}

// AsString returns v as a string, "" for nil / non-strings (python `x or ""`).
func AsString(v any) string {
	s, _ := v.(string)
	return s
}

// FromJSON normalises a value decoded with json.Decoder.UseNumber() to the
// shape python json.loads produces: integral numbers become int64, others
// float64, recursively through []any and map[string]any. Use it on Fleet API
// payloads and on-disk JSON before passing values as Cypher parameters, so
// ids stay integers in Memgraph (encoding/json's default float64 would not).
func FromJSON(v any) any {
	switch t := v.(type) {
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		f, _ := t.Float64()
		return f
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1<<53 {
			return int64(t)
		}
		return t
	case []any:
		for i, e := range t {
			t[i] = FromJSON(e)
		}
		return t
	case map[string]any:
		for k, e := range t {
			t[k] = FromJSON(e)
		}
		return t
	}
	return v
}

// DecodeJSON decodes data with UseNumber and FromJSON (python json.loads).
func DecodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return FromJSON(v), nil
}
