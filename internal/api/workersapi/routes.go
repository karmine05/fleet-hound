// Package workersapi ports webviz/routes/workers.py: enricher / OODA /
// extension-worker status + trigger routes and the /api/extensions inventory.
package workersapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/karmine05/fleet-hound/internal/app"
	"github.com/karmine05/fleet-hound/internal/config"
	"github.com/karmine05/fleet-hound/internal/enrich"
	"github.com/karmine05/fleet-hound/internal/extworker"
	"github.com/karmine05/fleet-hound/internal/graphdb"
	"github.com/karmine05/fleet-hound/internal/httpx"
	"github.com/karmine05/fleet-hound/internal/ooda"
)

// extWhere scopes a query to browser-extension Software nodes.
const extWhere = "(s.kind = 'browser_extension' OR s.extension_key STARTS WITH 'ext:')"

type routes struct{ d *app.Deps }

// Register mounts this package's routes on mux. Every view catches its own
// errors (python try/except), so none need httpx.Handle.
func Register(mux *http.ServeMux, d *app.Deps) {
	rt := &routes{d: d}
	mux.HandleFunc("GET /api/enricher/status", rt.enricherStatus)
	mux.HandleFunc("POST /api/enricher/trigger", rt.enricherTrigger)
	mux.HandleFunc("GET /api/ooda/status", rt.oodaStatus)
	mux.HandleFunc("POST /api/ooda/trigger", rt.oodaTrigger)
	mux.HandleFunc("GET /api/ooda/findings", rt.oodaFindings)
	mux.HandleFunc("GET /api/ooda/cycles", rt.oodaCycles)
	mux.HandleFunc("GET /api/extensions", rt.extensions)
	mux.HandleFunc("GET /api/extensions/status", rt.extensionsStatus)
	mux.HandleFunc("POST /api/extensions/refresh", rt.extensionsRefresh)
	mux.HandleFunc("GET /api/extensions/detail", rt.extensionDetail)
}

func (rt *routes) log() *slog.Logger {
	if rt.d.Log != nil {
		return rt.d.Log
	}
	return slog.Default()
}

func (rt *routes) cfg() *config.Webviz {
	if rt.d.Cfg != nil {
		return rt.d.Cfg
	}
	return &config.Webviz{}
}

func (rt *routes) dbAvailable(ctx context.Context) bool {
	return rt.d.DB != nil && rt.d.DB.Available(ctx)
}

func (rt *routes) enricherStatus(w http.ResponseWriter, r *http.Request) {
	rt.d.EnsureEnricher()
	c := rt.cfg()
	snap := enrich.ReadStatus(c.EnricherStatusPath)
	if snap == nil {
		// python except-branch shape (Go ReadStatus does not fail).
		snap = map[string]any{
			"running": false, "last_tick_iso": nil,
			"items_categorized_total": 0, "last_error": nil,
		}
	}
	// Live config wins over a stale status file.
	snap["enabled"] = c.EnricherEnabled
	queue := 0
	if rt.d.DB != nil {
		queue = enrich.QueueRemaining(r.Context(), rt.d.DB)
	}
	snap["queue_remaining"] = queue
	httpx.WriteJSON(w, http.StatusOK, snap)
}

// fire runs a worker FireTrigger and writes the python 503/429/204 replies.
func (rt *routes) fire(w http.ResponseWriter, enabled bool, disabledMsg string,
	fireFn func(string, float64) (bool, float64), path string, cooldown float64,
	auditAction, auditDetails string) {
	if !enabled {
		httpx.Error(w, http.StatusServiceUnavailable, disabledMsg)
		return
	}
	fired, retryAfter := fireFn(path, cooldown)
	if !fired {
		httpx.WriteJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "Rate limited", "retry_after_sec": int(retryAfter),
		})
		return
	}
	if auditAction != "" {
		rt.d.Audit(auditAction, auditDetails)
	}
	httpx.NoContent(w)
}

func (rt *routes) enricherTrigger(w http.ResponseWriter, r *http.Request) {
	rt.d.EnsureEnricher()
	c := rt.cfg()
	rt.fire(w, c.EnricherEnabled, "Enricher disabled", enrich.FireTrigger,
		c.EnricherTriggerPath, config.EnricherManualTriggerCooldown, "", "")
}

func (rt *routes) oodaStatus(w http.ResponseWriter, r *http.Request) {
	rt.d.EnsureOODA()
	c := rt.cfg()
	snap := ooda.ReadStatus(c.OODAStatusPath)
	if snap == nil {
		snap = map[string]any{
			"running": false, "next_cycle_id": 1, "last_phase": nil,
			"last_error": nil, "cycles_total": 0, "cycles_failed": 0, "last_cycle": nil,
		}
	}
	snap["enabled"] = c.OODAEnabled
	snap["interval_sec"] = c.OODAIntervalSec
	snap["full_scan_every"] = c.OODAFullScanEvery
	httpx.WriteJSON(w, http.StatusOK, snap)
}

func (rt *routes) oodaTrigger(w http.ResponseWriter, r *http.Request) {
	rt.d.EnsureOODA()
	c := rt.cfg()
	rt.fire(w, c.OODAEnabled, "OODA disabled", ooda.FireTrigger,
		c.OODATriggerPath, config.OODAManualTriggerCooldown,
		"ooda_trigger", "manual cycle requested")
}

func (rt *routes) oodaFindings(w http.ResponseWriter, r *http.Request) {
	rt.d.EnsureOODA()
	httpx.WriteJSON(w, http.StatusOK, ooda.ReadFindings(rt.cfg().OODAFindingsPath))
}

func (rt *routes) oodaCycles(w http.ResponseWriter, r *http.Request) {
	rt.d.EnsureOODA()
	limit := httpx.Clamp(httpx.ArgInt(r, "limit", 20), 1, 100)
	cycles := ooda.ReadCycles(rt.cfg().OODACyclesPath, limit)
	if cycles == nil {
		cycles = []map[string]any{}
	}
	httpx.WriteJSON(w, http.StatusOK, cycles)
}

// extensionFilterClause is _extension_filter_clause: the shared WHERE for the
// list + summary queries.
func extensionFilterClause(r *http.Request) (string, map[string]any) {
	q := r.URL.Query()
	clauses := []string{extWhere}
	params := map[string]any{}

	risk := strings.ToLower(strings.TrimSpace(argOr(q.Get("risk"), "all")))
	switch risk {
	case "low", "medium", "high", "critical":
		clauses = append(clauses, "s.risk_band = $risk")
		params["risk"] = risk
	case "unassessed":
		clauses = append(clauses, "s.risk_band IS NULL")
	}

	store := strings.ToLower(strings.TrimSpace(argOr(q.Get("store"), "all")))
	if store != "" && store != "all" {
		clauses = append(clauses, "s.store = $store")
		params["store"] = store
	}

	if httpx.ArgBool(r, "known_bad") {
		clauses = append(clauses, "coalesce(s.known_bad, false) = true")
	}

	if !httpx.ArgBool(r, "include_builtin") {
		// A built-in that a blocklist or threat feed hit is scored above 0:
		// never hide it behind the built-in filter.
		clauses = append(clauses, "(coalesce(s.is_builtin, false) = false OR coalesce(s.risk_score, 0) > 0)")
	}

	if search := strings.TrimSpace(q.Get("search")); search != "" {
		clauses = append(clauses, "("+
			"toLower(coalesce(s.display_name, '')) CONTAINS toLower($q) OR "+
			"toLower(s.name) CONTAINS toLower($q) OR "+
			"toLower(coalesce(s.extension_id, '')) CONTAINS toLower($q) OR "+
			"toLower(coalesce(s.publisher, '')) CONTAINS toLower($q)"+
			")")
		params["q"] = search
	}
	return strings.Join(clauses, " AND "), params
}

// argOr is python `args.get(k) or def` (empty counts as missing).
func argOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// truthy is python bool(v) for record values.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
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

func or(v, def any) any {
	if truthy(v) {
		return v
	}
	return def
}

// num is a numeric record value as float64 (ok=false for non-numbers).
func num(v any) (float64, bool) {
	switch t := v.(type) {
	case int64:
		return float64(t), true
	case int:
		return float64(t), true
	case float64:
		return t, true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// signalsFromProps is _ext_signals_from_props: risk_signals_json decoded when
// it is a JSON list, else [].
func signalsFromProps(props map[string]any) any {
	raw, ok := props["risk_signals_json"].(string)
	if !ok || raw == "" {
		return []any{}
	}
	if l, isList := loadsJSON(raw).([]any); isList {
		return l
	}
	return []any{}
}

// loadsJSON is python json.loads with failures mapped to nil: the whole input
// must be one JSON value (graphdb.DecodeJSON alone ignores trailing data).
// A literal JSON null also yields nil, which callers treat like a failure.
func loadsJSON(s string) any {
	if !json.Valid([]byte(s)) {
		return nil
	}
	v, err := graphdb.DecodeJSON([]byte(s))
	if err != nil {
		return nil
	}
	return v
}

type extGroup struct {
	m         map[string]any
	hostnames map[string]struct{}
	versions  map[string]struct{}
}

// groupRows is _ext_group_rows: collapse per-node rows into one row per
// canonical extension key, sorted scored-first by risk desc then hosts desc
// (stable, so ties keep first-seen order).
func groupRows(rows []map[string]any) []map[string]any {
	var order []*extGroup
	groups := map[string]*extGroup{}
	for _, row := range rows {
		props, _ := row["props"].(map[string]any)
		if props == nil {
			props = map[string]any{}
		}
		key := graphdb.AsString(props["extension_key"])
		if key == "" {
			key = "name:" + pyStr(props["name"])
		}
		g := groups[key]
		if g == nil {
			g = &extGroup{
				m: map[string]any{
					"extension_key":          key,
					"name":                   props["name"],
					"display_name":           or(props["display_name"], props["name"]),
					"store":                  props["store"],
					"extension_id":           props["extension_id"],
					"browser":                props["browser"],
					"vendor":                 props["vendor"],
					"publisher":              props["publisher"],
					"publisher_reputable":    truthy(props["publisher_reputable"]),
					"is_builtin":             truthy(props["is_builtin"]),
					"known_bad":              truthy(props["known_bad"]),
					"store_status":           props["store_status"],
					"store_url":              props["store_url"],
					"latest_version":         props["latest_version"],
					"install_users":          props["install_users"],
					"rating":                 props["rating"],
					"rating_count":           props["rating_count"],
					"category":               props["category"],
					"manifest_version":       props["manifest_version"],
					"permissions":            or(props["permissions"], []any{}),
					"host_permissions":       or(props["host_permissions"], []any{}),
					"content_script_matches": or(props["content_script_matches"], []any{}),
					"risk_score":             props["risk_score"],
					"risk_band":              props["risk_band"],
					"capability_score":       props["capability_score"],
					"trust_score":            props["trust_score"],
					"threat_score":           props["threat_score"],
					"exposure_score":         props["exposure_score"],
					"risk_signals":           signalsFromProps(props),
					"vulnerability_count":    or(props["vulnerability_count"], int64(0)),
					"max_cvss":               props["max_cvss"],
					"intel_refreshed_at":     props["intel_refreshed_at"],
					"intel_error":            props["intel_error"],
				},
				hostnames: map[string]struct{}{},
				versions:  map[string]struct{}{},
			}
			groups[key] = g
			order = append(order, g)
		}
		if hs, ok := row["hosts"].([]any); ok {
			for _, h := range hs {
				if s, ok := h.(string); ok && s != "" {
					g.hostnames[s] = struct{}{}
				}
			}
		}
		if vs, ok := row["versions"].([]any); ok {
			for _, v := range vs {
				if s, ok := v.(string); ok && s != "" {
					g.versions[s] = struct{}{}
				}
			}
		}
		// Several nodes can map to one key; prefer the scored one.
		if props["risk_score"] != nil && g.m["risk_score"] == nil {
			g.m["risk_score"] = props["risk_score"]
			g.m["risk_band"] = props["risk_band"]
			g.m["risk_signals"] = signalsFromProps(props)
		}
	}

	out := make([]map[string]any, 0, len(order))
	for _, g := range order {
		hostnames := sortedKeys(g.hostnames)
		versions := sortedKeys(g.versions)
		g.m["host_count"] = len(hostnames)
		g.m["hostnames"] = hostnames[:min(50, len(hostnames))]
		g.m["versions"] = versions[:min(20, len(versions))]
		out = append(out, g.m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ni, nj := out[i]["risk_score"] == nil, out[j]["risk_score"] == nil
		if ni != nj {
			return !ni // scored (False) before unscored (True)
		}
		si, _ := num(or(out[i]["risk_score"], int64(0)))
		sj, _ := num(or(out[j]["risk_score"], int64(0)))
		if si != sj {
			return si > sj
		}
		return out[i]["host_count"].(int) > out[j]["host_count"].(int)
	})
	return out
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pyStr is python str(v) for the f"name:{...}" fallback key.
func pyStr(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return t
	}
	return fmt.Sprint(v)
}

func (rt *routes) extensions(w http.ResponseWriter, r *http.Request) {
	rt.d.EnsureExtensionWorker()
	ctx := r.Context()
	if !rt.dbAvailable(ctx) {
		httpx.Error(w, http.StatusInternalServerError, "Database connection failed")
		return
	}
	limit := httpx.Clamp(httpx.ArgInt(r, "limit", 1000), 1, 5000)
	where, params := extensionFilterClause(r)

	listQuery := fmt.Sprintf(`
        MATCH (s:Software)
        WHERE %s
        MATCH (s)-[r:INSTALLED_ON]->(h:Host)
        WITH s, count(DISTINCT h) AS host_count,
             collect(DISTINCT r.version) AS versions,
             collect(DISTINCT h.hostname) AS hosts
        RETURN properties(s) AS props, host_count, versions, hosts
        ORDER BY host_count DESC
        LIMIT $limit
    `, where)
	bandQuery := fmt.Sprintf(`
        MATCH (s:Software)
        WHERE %s AND EXISTS((s)-[:INSTALLED_ON]->(:Host))
        RETURN coalesce(s.risk_band, 'unassessed') AS band,
               count(DISTINCT coalesce(s.extension_key, 'name:' + s.name)) AS n
    `, where)
	hostQuery := fmt.Sprintf(`
        MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
        WHERE %s
        RETURN count(DISTINCT h) AS n
    `, where)

	listParams := map[string]any{"limit": int64(limit)}
	for k, v := range params {
		listParams[k] = v
	}
	rows, err := rt.d.DB.Query(ctx, listQuery, listParams)
	var bandRows []map[string]any
	var hostRow map[string]any
	if err == nil {
		bandRows, err = rt.d.DB.Query(ctx, bandQuery, params)
	}
	if err == nil {
		hostRow, err = rt.d.DB.Single(ctx, hostQuery, params)
	}
	if err != nil {
		if graphdb.IsServiceUnavailable(err) || graphdb.IsTransient(err) {
			// Only a dead connection warrants a new driver; resetting on a
			// TransientError would yank the pool from the background workers.
			if graphdb.IsServiceUnavailable(err) {
				rt.d.DB.Reset(ctx)
			}
			rt.log().Error("extensions list unavailable", "err", err)
			httpx.Error(w, http.StatusServiceUnavailable, "Database temporarily unavailable")
			return
		}
		rt.log().Error("extensions list failed", "err", err)
		httpx.ErrorMsg(w, http.StatusInternalServerError, "Extensions query failed", httpx.DebugMsg(rt.d.Debug(), err))
		return
	}

	extensions := groupRows(rows)
	affected := int64(0)
	if hostRow != nil {
		affected, _ = graphdb.AsInt64(hostRow["n"])
	}
	summary := map[string]any{"total": int64(0), "critical": int64(0), "high": int64(0), "medium": int64(0),
		"low": int64(0), "unassessed": int64(0), "affected_hosts": affected}
	for _, b := range bandRows {
		name := graphdb.AsString(b["band"])
		if name == "" {
			name = "unassessed"
		}
		count, _ := graphdb.AsInt64(b["n"])
		if _, ok := summary[name]; ok {
			summary[name] = count
		}
		summary["total"] = summary["total"].(int64) + count
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"extensions": extensions,
		"summary":    summary,
		"total":      summary["total"],
		"worker":     rt.extensionStatusSnapshot(),
	})
}

func (rt *routes) extensionStatusSnapshot() map[string]any {
	c := rt.cfg()
	// queue_remaining comes from the worker's status file: due-ness needs
	// fingerprints and cache ages, so no per-request query can compute it.
	snap := extworker.ReadStatus(c.ExtensionWorkerStatusPath)
	if snap == nil {
		snap = map[string]any{"running": false, "queue_remaining": 0, "last_error": nil}
	}
	snap["enabled"] = c.ExtensionWorkerEnabled
	snap["interval_sec"] = c.ExtensionWorkerIntervalSec
	return snap
}

func (rt *routes) extensionsStatus(w http.ResponseWriter, r *http.Request) {
	rt.d.EnsureExtensionWorker()
	httpx.WriteJSON(w, http.StatusOK, rt.extensionStatusSnapshot())
}

func (rt *routes) extensionsRefresh(w http.ResponseWriter, r *http.Request) {
	rt.d.EnsureExtensionWorker()
	c := rt.cfg()
	rt.fire(w, c.ExtensionWorkerEnabled, "Extension worker disabled", extworker.FireTrigger,
		c.ExtensionWorkerTriggerPath, config.ExtensionManualTriggerCooldown,
		"extensions_refresh", "manual extension intel refresh requested")
}

// detailNullFields: the worker writes NULL (property removed) for fields a
// store doesn't publish; the UI still gets stable keys.
var detailNullFields = []string{
	"risk_band", "risk_score", "capability_score", "trust_score",
	"threat_score", "exposure_score", "install_users",
	"manifest_version", "rating", "rating_count", "publisher",
	"store_status", "store_url", "latest_version", "category",
	"store_updated_at", "store_featured", "established_publisher",
	"developer_verified", "developer_email", "developer_website", "trader",
	"privacy_disclosure", "privacy_policy_url",
}

func (rt *routes) extensionDetail(w http.ResponseWriter, r *http.Request) {
	rt.d.EnsureExtensionWorker()
	ctx := r.Context()
	key := strings.TrimSpace(r.URL.Query().Get("key"))
	if key == "" {
		httpx.Error(w, http.StatusBadRequest, "key parameter required")
		return
	}
	if !rt.dbAvailable(ctx) {
		httpx.Error(w, http.StatusInternalServerError, "Database connection failed")
		return
	}
	nameFallback := strings.TrimPrefix(key, "name:")
	// Extension guard: without it, key=<any software name> returned that
	// node's full property map.
	query := `
        MATCH (s:Software)
        WHERE (s.extension_key = $key OR s.name = $name_fallback) AND ` + extWhere + `
        OPTIONAL MATCH (s)-[r:INSTALLED_ON]->(h:Host)
        RETURN properties(s) AS props,
               collect(DISTINCT {
                   hostname: h.hostname,
                   version: r.version,
                   source: r.source,
                   browser: r.browser,
                   installed_path: r.installed_path,
                   first_seen: r.first_seen,
                   last_seen: r.last_seen
               }) AS hosts
    `
	records, err := rt.d.DB.Query(ctx, query, map[string]any{"key": key, "name_fallback": nameFallback})
	if err != nil {
		rt.log().Error("extension detail failed", "err", err)
		httpx.ErrorMsg(w, http.StatusInternalServerError, "Extension query failed", httpx.DebugMsg(rt.d.Debug(), err))
		return
	}
	if len(records) == 0 {
		httpx.Error(w, http.StatusNotFound, "Extension not found")
		return
	}

	nodes := make([]map[string]any, len(records))
	hosts := map[string]map[string]any{}
	for i, row := range records {
		props, _ := row["props"].(map[string]any)
		if props == nil {
			props = map[string]any{}
		}
		nodes[i] = props
		hs, _ := row["hosts"].([]any)
		for _, x := range hs {
			host, ok := x.(map[string]any)
			if !ok || !truthy(host["hostname"]) {
				continue
			}
			hk := pyStr(host["hostname"])
			existing, seen := hosts[hk]
			if !seen || graphdb.AsString(host["last_seen"]) > graphdb.AsString(existing["last_seen"]) {
				hosts[hk] = host
			}
		}
	}

	// python max(nodes, key=risk_score or -1): first maximal node wins.
	rank := func(p map[string]any) float64 {
		if v, ok := num(p["risk_score"]); ok && truthy(p["risk_score"]) {
			return v
		}
		return -1
	}
	primary := nodes[0]
	for _, n := range nodes[1:] {
		if rank(n) > rank(primary) {
			primary = n
		}
	}
	merged := make(map[string]any, len(primary)+len(detailNullFields)+4)
	for k, v := range primary {
		merged[k] = v
	}
	for _, f := range detailNullFields {
		if _, ok := merged[f]; !ok {
			merged[f] = nil
		}
	}
	merged["extension_key"] = or(primary["extension_key"], key)
	merged["risk_signals"] = signalsFromProps(primary)
	merged["risk_signals_json"] = nil
	merged["vulnerabilities"] = []any{}
	vraw := primary["vulnerabilities_json"]
	if !truthy(vraw) {
		vraw = "[]"
	}
	if s, ok := vraw.(string); ok {
		if v := loadsJSON(s); v != nil {
			merged["vulnerabilities"] = v
		}
	}

	hostList := make([]map[string]any, 0, len(hosts))
	for _, h := range hosts {
		hostList = append(hostList, h)
	}
	sort.SliceStable(hostList, func(i, j int) bool {
		return graphdb.AsString(hostList[i]["hostname"]) < graphdb.AsString(hostList[j]["hostname"])
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"extension":  merged,
		"hosts":      hostList,
		"host_count": len(hostList),
		"node_count": len(nodes),
	})
}
