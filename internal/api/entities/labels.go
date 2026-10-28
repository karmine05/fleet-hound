package entities

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/karmine05/fleet-hound/internal/app"
	"github.com/karmine05/fleet-hound/internal/graphdb"
	"github.com/karmine05/fleet-hound/internal/hostfilter"
	"github.com/karmine05/fleet-hound/internal/httpx"
)

// labelsQueryHead/Tail wrap the optional `l.query AS query` select: the
// osquery text is only fetched behind ?include_query=true.
const labelsQueryHead = `
                MATCH (l:Label)<-[r:HAS_LABEL]-(:Host)
                WITH l, count(r) AS live_host_count
                RETURN l.fleet_id AS fleet_id,
                       l.name AS name,
                       coalesce(l.description, '') AS description,
                       coalesce(l.label_type, 'regular') AS label_type,
                       coalesce(l.membership_type, '') AS membership_type,
                       live_host_count AS host_count,
                       coalesce(l.last_synced_iso, '') AS last_synced_iso,
                       coalesce(l.last_label_sync_status, 'unknown') AS last_label_sync_status,
                       coalesce(l.consecutive_failures, 0) AS consecutive_failures,
`

const labelsQuerySelect = "                       l.query AS query,\n"

const labelsQueryTail = `                       coalesce(l.orphan_member_count, 0) AS orphan_member_count,
                       coalesce(l.orphan_member_ids, []) AS orphan_member_ids,
                       coalesce(l.orphan_member_truncated, false) AS orphan_member_truncated
                ORDER BY l.name
`

// dbFailure maps a Memgraph error to the labels endpoints' python except
// blocks: Transient/ServiceUnavailable -> 503, anything else -> 500.
func dbFailure(d *app.Deps, w http.ResponseWriter, route string, err error) {
	if graphdb.IsTransient(err) || graphdb.IsServiceUnavailable(err) {
		logger(d).Warn(route+" transient", "err", err)
		httpx.ErrorMsg(w, http.StatusServiceUnavailable, "Database transient error",
			"Memgraph is unreachable. Retry in a moment.")
		return
	}
	logger(d).Error(route+" failed", "err", err)
	httpx.InternalError(w)
}

func intOr0(v any) int64 {
	n, _ := graphdb.AsInt64(v)
	return n
}

// getLabels lists Fleet labels with live HAS_LABEL host counts and sync
// health. ?include_query=true adds the osquery text.
func getLabels(d *app.Deps, w http.ResponseWriter, r *http.Request) {
	if dbDown(d, w, r) {
		return
	}
	includeQuery := strings.ToLower(strings.TrimSpace(httpx.Arg(r, "include_query", ""))) == "true"
	cypher := labelsQueryHead
	if includeQuery {
		cypher += labelsQuerySelect
	}
	cypher += labelsQueryTail

	rows, err := d.DB.Query(r.Context(), cypher, nil)
	if err != nil {
		dbFailure(d, w, "/api/labels", err)
		return
	}
	payload := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		ids, _ := row["orphan_member_ids"].([]any)
		if ids == nil {
			ids = []any{}
		}
		entry := map[string]any{
			"fleet_id":                row["fleet_id"],
			"name":                    row["name"],
			"description":             row["description"],
			"label_type":              row["label_type"],
			"membership_type":         row["membership_type"],
			"host_count":              intOr0(row["host_count"]),
			"last_synced_iso":         row["last_synced_iso"],
			"last_label_sync_status":  row["last_label_sync_status"],
			"consecutive_failures":    intOr0(row["consecutive_failures"]),
			"orphan_member_count":     intOr0(row["orphan_member_count"]),
			"orphan_member_ids":       ids,
			"orphan_member_truncated": truthy(row["orphan_member_truncated"]),
		}
		if includeQuery && truthy(row["query"]) {
			entry["query"] = row["query"]
		}
		payload = append(payload, entry)
	}
	httpx.WriteJSON(w, http.StatusOK, payload)
}

// getLabelScopeCount is the pre-flight host count for a candidate label
// scope (?labels/label_op/team/platform, or ?expr=<json> composite), with an
// optional ?include_alt=true count under the opposite label_op.
func getLabelScopeCount(d *app.Deps, w http.ResponseWriter, r *http.Request) {
	if dbDown(d, w, r) {
		return
	}
	args := r.URL.Query()

	var (
		frag   string
		params map[string]any
		err    error
	)
	if exprRaw := strings.TrimSpace(args.Get("expr")); exprRaw != "" {
		var probe any
		if jerr := json.Unmarshal([]byte(exprRaw), &probe); jerr != nil {
			httpx.ErrorMsg(w, http.StatusBadRequest, "Invalid expr", "expr must be valid JSON: "+jerr.Error())
			return
		}
		expr, _ := graphdb.DecodeJSON([]byte(exprRaw)) // valid per Unmarshal; keeps ints int64
		frag, params, err = hostfilter.ApplyCompositeFilter(expr, "h")
	} else {
		frag, params, err = hostfilter.ApplyHostFilters(args, "h", false)
	}
	if err != nil {
		httpx.ErrorMsg(w, http.StatusBadRequest, "Invalid filter", err.Error())
		return
	}

	includeAlt := strings.ToLower(strings.TrimSpace(args.Get("include_alt"))) == "true"
	// Not de-duplicated, unlike the filter helper: echoed as sent.
	labelNames := []string{}
	for _, s := range strings.Split(strings.TrimSpace(args.Get("labels")), ",") {
		if s = strings.TrimSpace(s); s != "" {
			labelNames = append(labelNames, s)
		}
	}
	labelOp := args.Get("label_op")
	if labelOp == "" {
		labelOp = "AND"
	}
	labelOp = strings.ToUpper(strings.TrimSpace(labelOp))
	if labelOp != "AND" && labelOp != "OR" {
		httpx.Error(w, http.StatusBadRequest, "Invalid label_op")
		return
	}

	count, err := hostCount(d, r, frag, params)
	if err != nil {
		dbFailure(d, w, "/api/labels/scope-count", err)
		return
	}
	payload := map[string]any{
		"count":        count,
		"labels":       labelNames,
		"label_op":     labelOp,
		"alt_count":    nil,
		"alt_label_op": nil,
	}
	// With one label AND and OR are equivalent, so alt needs >= 2.
	if includeAlt && len(labelNames) >= 2 {
		altOp := "AND"
		if labelOp == "AND" {
			altOp = "OR"
		}
		altArgs := url.Values{} // dict(request.args): first value per key
		for k, v := range args {
			altArgs.Set(k, v[0])
		}
		altArgs.Set("label_op", altOp)
		altFrag, altParams, err := hostfilter.ApplyHostFilters(altArgs, "h", false)
		if err == nil {
			payload["alt_count"], err = hostCount(d, r, altFrag, altParams)
		}
		if err != nil {
			dbFailure(d, w, "/api/labels/scope-count", err)
			return
		}
		payload["alt_label_op"] = altOp
	}
	httpx.WriteJSON(w, http.StatusOK, payload)
}

func hostCount(d *app.Deps, r *http.Request, frag string, params map[string]any) (int64, error) {
	rec, err := d.DB.Single(r.Context(), "MATCH (h:Host) WHERE 1=1"+frag+" RETURN count(h) AS c", params)
	if err != nil || rec == nil {
		return 0, err
	}
	return intOr0(rec["c"]), nil
}
