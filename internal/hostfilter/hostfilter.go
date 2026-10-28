// Package hostfilter ports webviz/host_filters.py and webviz/hostname_utils.py.
// It is shared by internal/api/entities (labels, search), internal/api/graphapi
// (graph, blast_radius) and internal/api/shadowit. Owner: agent F.
//
// Host-filter Cypher composer: ?team=, ?platform= and multi-label
// ?labels=A,B&label_op=AND|OR become one Cypher fragment that always begins
// with " AND " or is empty, meant to be appended to an existing WHERE clause:
//
//	frag, params, err := hostfilter.ApplyHostFilters(r.URL.Query(), "h", false)
//	cypher := "MATCH (h:Host) WHERE 1=1" + frag + " RETURN ..."
//
// Param keys are namespaced with the "_flt_" prefix. Label names, team id and
// platform are always bound as Cypher parameters, never concatenated, so
// Cypher injection on those fields is defended at the parametrization layer.
// label_op is whitelisted to AND/OR. hostVar is always a caller-supplied
// literal alias, never request data.
package hostfilter

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// ValidationError replaces FilterValidationError: a malformed query-string
// filter. Callers respond HTTP 400 with the message (see the python routes for
// the exact body each endpoint used).
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

// IsValidationError reports whether err is (or wraps) a *ValidationError.
func IsValidationError(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve)
}

func verr(format string, a ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, a...)}
}

// splitLabels is _split_labels: comma split, trimmed, empties dropped,
// de-duplicated preserving first-seen order.
func splitLabels(raw string) []string {
	out := []string{}
	if raw == "" {
		return out
	}
	seen := map[string]struct{}{}
	for _, seg := range strings.Split(raw, ",") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if _, dup := seen[seg]; dup {
			continue
		}
		seen[seg] = struct{}{}
		out = append(out, seg)
	}
	return out
}

// ApplyHostFilters replaces apply_host_filters(args, host_var="h",
// label_only=False): composes a Cypher fragment (leading " AND ..." or "")
// plus params from ?team / ?platform / ?labels / ?label_op query args.
// Returns a *ValidationError for malformed values.
func ApplyHostFilters(args url.Values, hostVar string, labelOnly bool) (string, map[string]any, error) {
	var parts []string
	params := map[string]any{}

	if !labelOnly {
		team := strings.TrimSpace(args.Get("team"))
		if team != "" && strings.ToLower(team) != "all" {
			parts = append(parts, fmt.Sprintf("toString(%s.team_id) = $_flt_team", hostVar))
			params["_flt_team"] = team
		}
		// Case-insensitive substring match: a stored "darwin 14.5" still
		// matches ?platform=darwin (pre-refactor regression contract).
		platform := strings.ToLower(strings.TrimSpace(args.Get("platform")))
		if platform != "" && platform != "all" {
			parts = append(parts, fmt.Sprintf("toLower(%s.platform) CONTAINS toLower($_flt_platform)", hostVar))
			params["_flt_platform"] = platform
		}
	}

	labelsRaw := args.Get("labels")
	if labelsRaw != "" && strings.ToLower(strings.TrimSpace(labelsRaw)) != "all" {
		if names := splitLabels(labelsRaw); len(names) > 0 {
			op := args.Get("label_op")
			if op == "" {
				op = "AND"
			}
			op = strings.ToUpper(strings.TrimSpace(op))
			if op != "AND" && op != "OR" {
				return "", nil, verr("label_op must be one of: AND, OR (case-insensitive)")
			}
			// all()/any() over the requested names: a size() comparison broke
			// on duplicate names and duplicate edges.
			quantifier := "all"
			if op == "OR" {
				quantifier = "any"
			}
			parts = append(parts, fmt.Sprintf(
				"%s(_n IN $_flt_labels WHERE _n IN [(%s)-[:HAS_LABEL]->(_l:Label) | _l.name])",
				quantifier, hostVar))
			params["_flt_labels"] = names
		}
	}

	if len(parts) == 0 {
		return "", params, nil
	}
	return " AND " + strings.Join(parts, " AND "), params, nil
}

// ApplyLabelFilter replaces apply_label_filter(args, host_var): label-only.
func ApplyLabelFilter(args url.Values, hostVar string) (string, map[string]any, error) {
	return ApplyHostFilters(args, hostVar, true)
}

// Composite scoping: a JSON boolean expression (not a string DSL) over
// team / platform / label leaves. Every leaf value lands in Cypher params.
//
//	{"op": "AND"|"OR", "children": [<expr>, ...]}
//	{"op": "NOT", "child": <expr>}
//	{"team": "<id>"} | {"platform": "<name>"} | {"label": "<name>"}
const compositeMaxDepth = 6

// compositeMaxLeaves bounds breadth: each leaf adds a Cypher clause and a
// param, so an unbounded OR list builds a multi-MB query for Memgraph.
const compositeMaxLeaves = 64

var (
	compositeOpsList    = "['AND', 'NOT', 'OR']"
	compositeLeavesList = "['label', 'platform', 'team']"
	compositeLeaves     = map[string]struct{}{"team": {}, "platform": {}, "label": {}}
)

// ApplyCompositeFilter replaces apply_composite_filter(expr, host_var): walks
// a decoded JSON boolean tree (AND/OR/NOT over team/platform/label leaves,
// max depth 6) into (" AND <body>", params). nil or an empty map returns
// ("", {}). Non-object expr -> *ValidationError("expr must be a JSON object").
func ApplyCompositeFilter(expr any, hostVar string) (string, map[string]any, error) {
	if expr == nil {
		return "", map[string]any{}, nil
	}
	m, ok := expr.(map[string]any)
	if !ok {
		return "", nil, verr("expr must be a JSON object")
	}
	if len(m) == 0 {
		return "", map[string]any{}, nil
	}
	params := map[string]any{}
	counter := 0
	body, err := compositeNode(m, hostVar, params, &counter, 0)
	if err != nil {
		return "", nil, err
	}
	return " AND " + body, params, nil
}

func compositeNode(node any, hostVar string, params map[string]any, counter *int, depth int) (string, error) {
	if depth > compositeMaxDepth {
		return "", verr("expr exceeds max depth %d", compositeMaxDepth)
	}
	n, ok := node.(map[string]any)
	if !ok {
		return "", verr("expr node must be an object")
	}

	if opRaw, isOp := n["op"]; isOp {
		opStr, ok := opRaw.(string)
		if !ok {
			return "", verr("op must be a string")
		}
		op := strings.ToUpper(opStr)
		if op != "AND" && op != "OR" && op != "NOT" {
			return "", verr("op must be one of %s", compositeOpsList)
		}
		if op == "NOT" {
			child := n["child"]
			if child == nil {
				return "", verr("NOT requires a 'child' field")
			}
			inner, err := compositeNode(child, hostVar, params, counter, depth+1)
			if err != nil {
				return "", err
			}
			return "NOT (" + inner + ")", nil
		}
		children, ok := n["children"].([]any)
		if !ok || len(children) == 0 {
			return "", verr("%s requires a non-empty 'children' list", op)
		}
		rendered := make([]string, 0, len(children))
		for _, c := range children {
			s, err := compositeNode(c, hostVar, params, counter, depth+1)
			if err != nil {
				return "", err
			}
			rendered = append(rendered, s)
		}
		joiner := " AND "
		if op == "OR" {
			joiner = " OR "
		}
		return "(" + strings.Join(rendered, joiner) + ")", nil
	}

	// Leaf: exactly one allowed leaf field.
	var fields []string
	for k := range n {
		if _, ok := compositeLeaves[k]; ok {
			fields = append(fields, k)
		}
	}
	sort.Strings(fields)
	if len(fields) == 0 {
		return "", verr("leaf must contain exactly one of %s", compositeLeavesList)
	}
	if len(fields) > 1 {
		return "", verr("leaf must contain exactly one field; got %s", pyStrList(fields))
	}
	field := fields[0]
	value := n[field]
	if s, isStr := value.(string); value == nil || (isStr && s == "") {
		return "", verr("%s value cannot be empty", field)
	}

	*counter++
	if *counter > compositeMaxLeaves {
		return "", verr("expr exceeds max %d leaves", compositeMaxLeaves)
	}
	key := fmt.Sprintf("_flt_%s_%d", field, *counter)
	switch field {
	case "team":
		params[key] = PyStr(value)
		return fmt.Sprintf("toString(%s.team_id) = $%s", hostVar, key), nil
	case "platform":
		params[key] = strings.ToLower(PyStr(value))
		return fmt.Sprintf("toLower(%s.platform) CONTAINS toLower($%s)", hostVar, key), nil
	}
	params[key] = PyStr(value)
	return fmt.Sprintf("size([(%s)-[:HAS_LABEL]->(_l:Label) WHERE _l.name = $%s | _l]) >= 1", hostVar, key), nil
}

// pyStrList renders a []string like python str(list): ['a', 'b'].
func pyStrList(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = "'" + s + "'"
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// PyStr renders a decoded JSON / Memgraph scalar like python str() / an
// f-string: None, True/False, ints in decimal, floats with a ".0" when
// integral. Added for the composite filter and the entities routes, which
// build ids such as f"host_{fid}".
// shortcut: lists/maps fall back to fmt %v, not python repr; nothing renders them today.
func PyStr(v any) string {
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
	case int64:
		return strconv.FormatInt(t, 10)
	case int:
		return strconv.Itoa(t)
	case float64:
		switch {
		case math.IsNaN(t):
			return "nan"
		case math.IsInf(t, 1):
			return "inf"
		case math.IsInf(t, -1):
			return "-inf"
		case t == math.Trunc(t) && math.Abs(t) < 1e16:
			return strconv.FormatFloat(t, 'f', 1, 64)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	}
	return fmt.Sprintf("%v", v)
}

// HostnameCounts replaces hostname_counts(records): {hostname: count}. A nil
// or missing hostname is counted under the "" key here (python used None);
// DisambiguatedDisplayName never suffixes it, so behaviour is unchanged.
func HostnameCounts(records []map[string]any) map[string]int {
	counts := make(map[string]int, len(records))
	for _, r := range records {
		h, _ := r["hostname"].(string)
		counts[h]++
	}
	return counts
}

// DisambiguatedDisplayName replaces disambiguated_display_name: when
// hostname is a non-empty string seen more than once it returns
// "<hostname> #<fleet_host_id>", else hostname unchanged (nil stays nil).
func DisambiguatedDisplayName(hostname any, fleetHostID any, counts map[string]int) any {
	h, ok := hostname.(string)
	if ok && h != "" && counts[h] > 1 {
		return h + " #" + PyStr(fleetHostID)
	}
	return hostname
}
