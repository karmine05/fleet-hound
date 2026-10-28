// Package shadowit ports webviz/routes/shadow_it.py: GET /api/shadow-it
// (outlier / high-risk / version-sprawl detection) with its short
// per-process response cache.
package shadowit

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/karmine05/fleet-hound/internal/app"
	"github.com/karmine05/fleet-hound/internal/catalog"
	"github.com/karmine05/fleet-hound/internal/graphdb"
	"github.com/karmine05/fleet-hound/internal/hostfilter"
	"github.com/karmine05/fleet-hound/internal/httpx"
)

// Response cache. Keyed on the query args plus the whitelist mtime, so
// approving software is visible on the next read; graph changes from an ETL
// cycle show up within the TTL.
const (
	cacheTTL = 30 * time.Second // SHADOW_CACHE_TTL_SEC
	cacheMax = 64               // _SHADOW_CACHE_MAX
)

// extBandToLevel maps extension worker bands to Shadow IT levels (the Shadow
// IT UI has no "critical").
var extBandToLevel = map[string]string{"critical": "high", "high": "high", "medium": "medium", "low": "low"}

var levelRank = map[string]int{"low": 0, "medium": 1, "high": 2}

// highRiskCategory is one HIGH_RISK_PATTERNS entry; a slice keeps python's
// dict insertion order, which decides the first matching category.
type highRiskCategory struct {
	name     string
	patterns []string
}

// highRiskPatterns: curated brand/binary names that are end-user-installable
// and bypass IT review. All matches are word-boundary (httpx.WordMatch).
// Generic terms and sanctioned dual-use dev/security tools are deliberately
// excluded (see python source).
var highRiskPatterns = []highRiskCategory{
	{"Remote Access Tools", []string{
		"teamviewer", "anydesk", "chrome remote desktop", "logmein",
		"gotomypc", "remotepc", "splashtop", "realvnc", "tightvnc",
		"ultravnc", "screenconnect", "connectwise control", "parsec",
	}},
	{"File Sharing", []string{
		"dropbox", "wetransfer", "mega", "sync.com", "tresorit", "pcloud",
		"bittorrent", "utorrent", "qbittorrent", "transmission",
		"deluge", "vuze", "frostwire", "limewire",
	}},
	{"Communication Apps", []string{
		"telegram", "telegram desktop",
		"signal", "signal desktop",
		"whatsapp", "whatsapp desktop",
		"discord", "wechat", "viber", "kik messenger", "qq", "skype",
	}},
	{"Cryptocurrency Mining", []string{
		"nicehash", "cgminer", "ethminer", "xmrig", "phoenixminer",
		"claymore miner", "minergate", "bfgminer", "sgminer", "lolminer",
		"t-rex miner", "gminer", "teamredminer",
	}},
	{"Tor/Privacy Tools", []string{
		"tor browser", "tails", "proxifier", "psiphon", "tunnelbear",
		"nordvpn", "expressvpn", "protonvpn", "mullvad", "surfshark",
		"private internet access", "cyberghost", "ipvanish",
		"hotspot shield",
	}},
}

// recommendations: category-specific advice. Keys match highRiskPatterns.
var recommendations = map[string]string{
	"Remote Access Tools":   "Verify authorization. Remote access tools can be used for data exfiltration. Replace with approved enterprise solution.",
	"File Sharing":          "Verify authorization. File sharing apps may lead to data leakage. Use approved enterprise file sharing.",
	"Communication Apps":    "Verify authorization. Unofficial communication apps may bypass DLP policies. Use approved enterprise messaging.",
	"Cryptocurrency Mining": "CRITICAL: Remove immediately. Cryptocurrency miners consume resources and may indicate compromise.",
	"Tor/Privacy Tools":     "CRITICAL: Investigate immediately. Privacy/anonymity tools may indicate malicious activity or policy violation.",
}

type cacheEntry struct {
	at   time.Time
	body []byte
}

type handler struct {
	d     *app.Deps
	mu    sync.Mutex
	cache map[string]cacheEntry
}

// Register mounts GET /api/shadow-it. DB errors escape to httpx.Handle
// (ClientError -> 400 body, anything else -> 500), like the Flask view.
func Register(mux *http.ServeMux, d *app.Deps) {
	h := &handler{d: d, cache: map[string]cacheEntry{}}
	mux.Handle("GET /api/shadow-it", httpx.Handle(d.Debug(), h.serve))
}

func (h *handler) log() *slog.Logger {
	if h.d.Log != nil {
		return h.d.Log
	}
	return slog.Default()
}

// cacheKey is (tuple(sorted(request.args.items(multi=True))), wl_mtime).
func (h *handler) cacheKey(r *http.Request) string {
	var pairs [][2]string
	for k, vs := range r.URL.Query() {
		for _, v := range vs {
			pairs = append(pairs, [2]string{k, v})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i][0] != pairs[j][0] {
			return pairs[i][0] < pairs[j][0]
		}
		return pairs[i][1] < pairs[j][1]
	})
	var mtime int64
	if h.d.Cfg != nil {
		if st, err := os.Stat(h.d.Cfg.WhitelistFile); err == nil {
			mtime = st.ModTime().UnixNano()
		}
	}
	return fmt.Sprintf("%q|%d", pairs, mtime)
}

func (h *handler) serve(w http.ResponseWriter, r *http.Request) error {
	key := h.cacheKey(r)
	now := time.Now()
	h.mu.Lock()
	hit, ok := h.cache[key]
	h.mu.Unlock()
	if ok && now.Sub(hit.at) < cacheTTL {
		writeBody(w, hit.body)
		return nil
	}
	status, payload, err := h.uncached(r.Context(), r)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		httpx.WriteJSON(w, status, payload)
		return nil
	}
	// Render once through WriteJSON so cached hits replay identical bytes.
	buf := &bufWriter{header: http.Header{}}
	httpx.WriteJSON(buf, status, payload)
	if buf.status == http.StatusOK {
		h.mu.Lock()
		if len(h.cache) >= cacheMax {
			clear(h.cache)
		}
		h.cache[key] = cacheEntry{at: now, body: buf.body.Bytes()}
		h.mu.Unlock()
	}
	for k, v := range buf.header {
		w.Header()[k] = v
	}
	w.WriteHeader(buf.status)
	_, _ = w.Write(buf.body.Bytes())
	return nil
}

func writeBody(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// bufWriter captures a response so it can be cached.
type bufWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufWriter) Header() http.Header { return b.header }
func (b *bufWriter) WriteHeader(code int) {
	if b.status == 0 {
		b.status = code
	}
}
func (b *bufWriter) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}

func errBody(msg string) map[string]any { return map[string]any{"error": msg} }

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

// or returns v when truthy, else def (python `v or def`).
func or(v, def any) any {
	if truthy(v) {
		return v
	}
	return def
}

// pyStr is python str(v) for the scalar values interpolated into messages.
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
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return pyFloat(t)
	}
	return fmt.Sprint(v)
}

// pyFloat is python repr(float): shortest round-trip digits, scientific when
// the exponent is < -4 or >= 16, and always a '.' or exponent.
func pyFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	case math.IsNaN(f):
		return "nan"
	}
	if a := math.Abs(f); a != 0 && (a < 1e-4 || a >= 1e16) {
		return strconv.FormatFloat(f, 'e', -1, 64)
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}

func asInt(v any) int64 {
	n, _ := graphdb.AsInt64(v)
	return n
}

func stringsOf(v any) []string { return catalog.SourcesFrom(v) }

// listOr returns v as a JSON list, [] when absent (python `x or []` for lists).
func listOr(v any) any {
	if l, ok := v.([]any); ok && l != nil {
		return l
	}
	if v == nil {
		return []any{}
	}
	return v
}

func mergeParams(base map[string]any, extra map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// detectSoftwareType: the osquery install source is authoritative (an
// extension named "binhex.ninja" carries no name hint); name heuristics are
// the fallback.
func detectSoftwareType(name string, sources []string) string {
	if t := catalog.ClassifyExtensionType(sources); t != "" {
		return t
	}
	n := strings.ToLower(name)
	containsAny := func(xs ...string) bool {
		for _, x := range xs {
			if strings.Contains(n, x) {
				return true
			}
		}
		return false
	}
	switch {
	case containsAny("-extension", "chrome extension", "firefox addon", "safari extension", "edge extension"):
		return "Browser Extension"
	case containsAny("vscode-", ".vscode", "code-extension"):
		return "VSCode Extension"
	case strings.HasPrefix(n, "npm:") || strings.HasPrefix(n, "@"):
		return "npm Package"
	case strings.HasPrefix(n, "pip:") || strings.HasPrefix(n, "python-"):
		return "Python Package"
	case strings.HasPrefix(n, "gem:"):
		return "Ruby Gem"
	case containsAny("microsoft", "windows", "macos", "darwin", "linux", "ubuntu"):
		return "OS Component"
	case containsAny("git", "node", "python", "java", "docker", "kubernetes"):
		return "Developer Tool"
	}
	return "Application"
}

// countFilterRejects is the python host_count / user_count filter: "1", "2"
// or "3+" against n; any other non-"all" value never rejects.
func countFilterRejects(filter string, n int64) bool {
	switch filter {
	case "1":
		return n != 1
	case "2":
		return n != 2
	case "3+":
		return n < 3
	}
	return false
}

// usersBySoftware is _shadow_it_users_by_software: one batched query mapping
// software name -> sorted usernames on in-scope hosts.
func (h *handler) usersBySoftware(ctx context.Context, names []string, scopeClause string, scopeParams map[string]any) (map[string][]string, error) {
	seen := map[string]struct{}{}
	uniq := make([]any, 0, len(names))
	for _, n := range names {
		if n == "" {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		uniq = append(uniq, n)
	}
	out := map[string][]string{}
	if len(uniq) == 0 {
		return out, nil
	}
	rows, err := h.d.DB.Query(ctx, `
        MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
        WHERE s.name IN $names `+scopeClause+`
        RETURN s.name AS name, COLLECT(DISTINCT u.username) AS users
        `, mergeParams(scopeParams, map[string]any{"names": uniq}))
	if err != nil {
		return nil, fmt.Errorf("shadow-it users lookup: %w", err)
	}
	for _, r := range rows {
		users := stringsOf(r["users"])
		users = append([]string{}, users...)
		sort.Strings(users)
		out[graphdb.AsString(r["name"])] = users
	}
	return out, nil
}

func (h *handler) uncached(ctx context.Context, r *http.Request) (int, any, error) {
	d := h.d
	if d.DB == nil || !d.DB.Available(ctx) {
		return http.StatusInternalServerError, errBody("Database connection failed"), nil
	}

	teamFilter := httpx.Arg(r, "team", "all")
	platformFilter := strings.ToLower(httpx.Arg(r, "platform", "all"))
	riskFilter := strings.ToLower(httpx.Arg(r, "risk", "all"))
	detectionTypeFilter := strings.ToLower(httpx.Arg(r, "detection_type", "all"))
	hostCountFilter := httpx.Arg(r, "host_count", "all")
	userCountFilter := httpx.Arg(r, "user_count", "all")
	softwareTypeFilter := httpx.Arg(r, "software_type", "all")

	labelClause, labelParams, err := hostfilter.ApplyLabelFilter(r.URL.Query(), "h")
	if err != nil {
		if hostfilter.IsValidationError(err) {
			return http.StatusBadRequest, map[string]any{"error": "Invalid filter", "message": err.Error()}, nil
		}
		return 0, nil, fmt.Errorf("label filter: %w", err)
	}

	// Per-platform outlier thresholds (SHADOW_IT_OUTLIER_PCT, default 3%).
	outlierPct := catalog.GetOutlierPct()
	thresholds, err := catalog.ComputePerPlatformThresholds(ctx, d.DB, outlierPct)
	if err != nil {
		return 0, nil, fmt.Errorf("platform thresholds: %w", err)
	}
	// One composite scope per query: use the most restrictive matching
	// threshold (platform substring match, else max over all platforms).
	var outlierThreshold int
	if len(thresholds) > 0 {
		maxAll, maxMatched, matched := 0, 0, false
		for p, t := range thresholds {
			maxAll = max(maxAll, t)
			if platformFilter != "" && platformFilter != "all" && p != "" && strings.Contains(strings.ToLower(p), platformFilter) {
				if !matched || t > maxMatched {
					maxMatched = t
				}
				matched = true
			}
		}
		outlierThreshold = maxAll
		if matched {
			outlierThreshold = maxMatched
		}
	} else {
		row, err := d.DB.Single(ctx, "MATCH (h:Host) RETURN count(h) AS count", nil)
		if err != nil {
			return 0, nil, fmt.Errorf("host count: %w", err)
		}
		total := int64(0)
		if row != nil {
			total = asInt(row["count"])
		}
		if total == 0 {
			total = 1
		}
		outlierThreshold = max(catalog.MinOutlierHosts, int(float64(total)*outlierPct))
	}

	detections := []map[string]any{}
	counter := 1

	whitelist := d.Whitelist.Normalized()
	teamClause, platformClause, whitelistClause := "", "", ""
	filterParams := map[string]any{}
	if teamFilter != "all" {
		teamClause = "AND toString(h.team_id) = $team_id"
		filterParams["team_id"] = teamFilter
	}
	if platformFilter != "all" {
		platformClause = "AND toLower(h.platform) CONTAINS toLower($platform)"
		filterParams["platform"] = platformFilter
	}
	if len(whitelist) > 0 {
		whitelistClause = httpx.WhitelistClause("s")
		filterParams["whitelist"] = whitelist
	}
	for k, v := range labelParams {
		filterParams[k] = v
	}
	// Same host scope for affected_users, so user counts match affected_hosts.
	userScope := teamClause + " " + platformClause + " " + labelClause
	scope := fmt.Sprintf("%s %s %s %s", teamClause, platformClause, whitelistClause, labelClause)

	// ===== DETECTION 1: Outlier Software (installed on very few hosts) =====
	if detectionTypeFilter == "all" || detectionTypeFilter == "outlier" {
		outlierQuery := fmt.Sprintf(`
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE 1=1 %s
                WITH s.name AS software_name,
                     coalesce(s.display_name, s.name) AS display_name,
                     s.last_version AS version,
                     s.category AS db_category, s.wikidata_description AS db_desc,
                     s.sources AS db_sources,
                     s.risk_band AS ext_band, s.risk_score AS ext_score,
                     coalesce(s.is_builtin, false) AS ext_builtin,
                     COUNT(DISTINCT h) AS host_count,
                     COLLECT(DISTINCT h.hostname) AS hosts,
                     COLLECT(DISTINCT h.platform) AS platforms
                WHERE host_count <= $outlier_threshold
                RETURN software_name, display_name, version, host_count, hosts, platforms,
                       db_category, db_desc, db_sources, ext_band, ext_score, ext_builtin
                ORDER BY host_count ASC, display_name ASC
            `, scope)
		filterParams["outlier_threshold"] = outlierThreshold
		rows, err := d.DB.Query(ctx, outlierQuery, filterParams)
		if err != nil {
			return 0, nil, fmt.Errorf("outlier query: %w", err)
		}
		names := make([]string, len(rows))
		for i, rec := range rows {
			names[i] = graphdb.AsString(rec["software_name"])
		}
		usersByName, err := h.usersBySoftware(ctx, names, userScope, filterParams)
		if err != nil {
			return 0, nil, err
		}
		for _, rec := range rows {
			name := graphdb.AsString(rec["software_name"])
			sources := stringsOf(rec["db_sources"])
			if catalog.IsSystemPackage(name, stringsOf(rec["db_category"]), sources) {
				continue
			}
			users := usersOrEmpty(usersByName[name])
			hostCount := asInt(rec["host_count"])

			// Install-count risk unless the extension worker scored this
			// node: its band wins. Built-ins take the higher of the two.
			riskLevel := "medium"
			if hostCount == 1 {
				riskLevel = "high"
			}
			riskReason := fmt.Sprintf("Risk is %s because this software is installed on only %d host(s) (<%d threshold).",
				strings.ToUpper(riskLevel), hostCount, outlierThreshold)
			if band, ok := rec["ext_band"].(string); ok {
				if lvl, ok := extBandToLevel[band]; ok && (!truthy(rec["ext_builtin"]) || levelRank[lvl] > levelRank[riskLevel]) {
					riskLevel = lvl
					riskReason = fmt.Sprintf("Risk is %s from the browser-extension risk score (%s/100, band %s). Installed on %d host(s).",
						strings.ToUpper(riskLevel), pyStr(rec["ext_score"]), band, hostCount)
				}
			}
			if hostCountFilter != "all" && countFilterRejects(hostCountFilter, hostCount) {
				continue
			}
			if userCountFilter != "all" && countFilterRejects(userCountFilter, int64(len(users))) {
				continue
			}
			softwareType := detectSoftwareType(name, sources)
			if softwareTypeFilter != "all" && softwareType != softwareTypeFilter {
				continue
			}
			if riskFilter == "all" || riskFilter == riskLevel {
				detections = append(detections, map[string]any{
					"id":                   fmt.Sprintf("outlier_%d", counter),
					"software_name":        rec["software_name"],
					"display_name":         or(rec["display_name"], rec["software_name"]),
					"software_type":        softwareType,
					"risk_level":           riskLevel,
					"category":             "Outlier Software",
					"db_category":          rec["db_category"],
					"wikidata_description": rec["db_desc"],
					"detection_type":       "outlier",
					"host_count":           rec["host_count"],
					"affected_hosts":       listOr(rec["hosts"]),
					"affected_users":       users,
					"platforms":            listOr(rec["platforms"]),
					"version":              or(rec["version"], "Unknown"),
					"recommendation":       fmt.Sprintf("Verify if this software is authorized. Found on only %d host(s). Consider removing if unauthorized.", hostCount),
					"details":              fmt.Sprintf("Installed on %d host(s) only - unusual for enterprise software", hostCount),
					"risk_reason":          riskReason,
				})
				counter++
			}
		}
	}

	// ===== DETECTION 2: High-Risk Category Software =====
	if detectionTypeFilter == "all" || detectionTypeFilter == "high_risk" {
		allSoftwareQuery := fmt.Sprintf(`
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE 1=1 %s
                WITH s.name AS software_name,
                     coalesce(s.display_name, s.name) AS display_name,
                     s.last_version AS version,
                     s.category AS db_category, s.wikidata_description AS db_desc,
                     s.sources AS db_sources,
                     COUNT(DISTINCT h) AS host_count
                RETURN software_name, display_name, version, host_count,
                       db_category, db_desc, db_sources
            `, scope)
		// Two passes: classify from the light aggregate, then collect
		// hosts/platforms/users only for the matches.
		rows, err := d.DB.Query(ctx, allSoftwareQuery, filterParams)
		if err != nil {
			return 0, nil, fmt.Errorf("high-risk query: %w", err)
		}
		type match struct {
			rec      map[string]any
			category string
		}
		var matches []match
		for _, rec := range rows {
			name := graphdb.AsString(rec["software_name"])
			softwareLower := strings.ToLower(name)
			displayLower := strings.ToLower(graphdb.AsString(or(rec["display_name"], rec["software_name"])))
			dbCategories := stringsOf(rec["db_category"])
			if catalog.IsSystemPackage(name, dbCategories, stringsOf(rec["db_sources"])) {
				continue
			}
			matched := ""
			// 1. Wikidata category match first (highest signal).
		catLoop:
			for _, dbCat := range dbCategories {
				dbCatLower := strings.ToLower(dbCat)
				for _, c := range highRiskPatterns {
					if httpx.WordMatch(strings.ToLower(c.name), dbCatLower) || anyWordMatch(c.patterns, dbCatLower) {
						matched = c.name
						break catLoop
					}
				}
			}
			// 2. Fallback: word-boundary match on name or title.
			if matched == "" {
			nameLoop:
				for _, c := range highRiskPatterns {
					for _, p := range c.patterns {
						if httpx.WordMatch(p, softwareLower) || httpx.WordMatch(p, displayLower) {
							matched = c.name
							break nameLoop
						}
					}
				}
			}
			if matched != "" {
				matches = append(matches, match{rec, matched})
			}
		}

		matchedNames := make([]string, len(matches))
		for i, m := range matches {
			matchedNames[i] = graphdb.AsString(m.rec["software_name"])
		}
		hostDetail := map[string]map[string]any{}
		if len(matchedNames) > 0 {
			detailQuery := fmt.Sprintf(`
                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                    WHERE s.name IN $matched_names %s
                    RETURN s.name AS software_name,
                           COLLECT(DISTINCT h.hostname) AS hosts,
                           COLLECT(DISTINCT h.platform) AS platforms
                `, scope)
			names := make([]any, len(matchedNames))
			for i, n := range matchedNames {
				names[i] = n
			}
			drows, err := d.DB.Query(ctx, detailQuery, mergeParams(filterParams, map[string]any{"matched_names": names}))
			if err != nil {
				return 0, nil, fmt.Errorf("high-risk detail query: %w", err)
			}
			for _, dr := range drows {
				hostDetail[graphdb.AsString(dr["software_name"])] = dr
			}
		}
		usersByName, err := h.usersBySoftware(ctx, matchedNames, userScope, filterParams)
		if err != nil {
			return 0, nil, err
		}
		for _, m := range matches {
			rec := m.rec
			name := graphdb.AsString(rec["software_name"])
			var hosts, platforms any = []any{}, []any{}
			if dt, ok := hostDetail[name]; ok {
				hosts, platforms = listOr(dt["hosts"]), listOr(dt["platforms"])
			}
			users := usersOrEmpty(usersByName[name])
			hostCount := asInt(rec["host_count"])
			riskLevel := "high"
			if hostCountFilter != "all" && countFilterRejects(hostCountFilter, hostCount) {
				continue
			}
			if userCountFilter != "all" && countFilterRejects(userCountFilter, int64(len(users))) {
				continue
			}
			softwareType := detectSoftwareType(name, stringsOf(rec["db_sources"]))
			if softwareTypeFilter != "all" && softwareType != softwareTypeFilter {
				continue
			}
			if riskFilter == "all" || riskFilter == riskLevel {
				det := map[string]any{
					"id":             fmt.Sprintf("highrisk_%d", counter),
					"software_name":  rec["software_name"],
					"display_name":   or(rec["display_name"], rec["software_name"]),
					"software_type":  softwareType,
					"risk_level":     riskLevel,
					"category":       m.category,
					"detection_type": "high_risk",
					"host_count":     rec["host_count"],
					"affected_hosts": hosts,
					"affected_users": users,
					"platforms":      platforms,
					"version":        or(rec["version"], "Unknown"),
					"recommendation": recommendationFor(m.category),
					"details":        "High-risk category: " + m.category,
					"risk_reason":    fmt.Sprintf("Risk is HIGH because '%s' matches the '%s' category, which is flagged for security review.", name, m.category),
				}
				detections = append(detections, det)
				counter++
			}
		}
	}

	// ===== DETECTION 3: Version Sprawl =====
	// Distinct versions across INSTALLED_ON edges (r.version), not the
	// single-valued s.last_version; the 'unknown' sentinel is excluded.
	if detectionTypeFilter == "all" || detectionTypeFilter == "version_sprawl" {
		sprawlQuery := fmt.Sprintf(`
                MATCH (s:Software)-[r:INSTALLED_ON]->(h:Host)
                WHERE r.version IS NOT NULL
                  AND r.version <> ''
                  AND r.version <> 'unknown'
                  %s
                WITH s.name AS software_name,
                     coalesce(s.display_name, s.name) AS display_name,
                     s.category AS db_category,
                     s.sources AS db_sources,
                     COUNT(DISTINCT r.version) AS version_count,
                     COLLECT(DISTINCT r.version) AS versions,
                     COUNT(DISTINCT h) AS host_count,
                     COLLECT(DISTINCT h.hostname) AS hosts
                WHERE version_count > 2
                RETURN software_name, display_name, db_category, db_sources, version_count, versions, host_count, hosts
                ORDER BY version_count DESC
                LIMIT 20
            `, scope)
		rows, err := d.DB.Query(ctx, sprawlQuery, filterParams)
		if err != nil {
			return 0, nil, fmt.Errorf("version sprawl query: %w", err)
		}
		names := make([]string, len(rows))
		for i, rec := range rows {
			names[i] = graphdb.AsString(rec["software_name"])
		}
		usersByName, err := h.usersBySoftware(ctx, names, userScope, filterParams)
		if err != nil {
			return 0, nil, err
		}
		for _, rec := range rows {
			name := graphdb.AsString(rec["software_name"])
			sources := stringsOf(rec["db_sources"])
			if catalog.IsSystemPackage(name, stringsOf(rec["db_category"]), sources) {
				continue
			}
			users := usersOrEmpty(usersByName[name])
			versionCount := asInt(rec["version_count"])
			riskLevel := "low"
			if versionCount > 5 {
				riskLevel = "high"
			} else if versionCount > 3 {
				riskLevel = "medium"
			}
			hostCount := asInt(rec["host_count"])
			if hostCountFilter != "all" && countFilterRejects(hostCountFilter, hostCount) {
				continue
			}
			if userCountFilter != "all" && countFilterRejects(userCountFilter, int64(len(users))) {
				continue
			}
			softwareType := detectSoftwareType(name, sources)
			if softwareTypeFilter != "all" && softwareType != softwareTypeFilter {
				continue
			}
			if riskFilter == "all" || riskFilter == riskLevel {
				versions := stringsOf(rec["versions"])
				shown := versions
				if len(shown) > 3 {
					shown = shown[:3]
				}
				ellipsis := ""
				if len(versions) > 3 {
					ellipsis = "..."
				}
				detections = append(detections, map[string]any{
					"id":             fmt.Sprintf("sprawl_%d", counter),
					"software_name":  rec["software_name"],
					"display_name":   or(rec["display_name"], rec["software_name"]),
					"software_type":  softwareType,
					"risk_level":     riskLevel,
					"category":       "Version Management",
					"detection_type": "version_sprawl",
					"host_count":     rec["host_count"],
					"affected_hosts": listOr(rec["hosts"]),
					"affected_users": users,
					"platforms":      []any{},
					"version":        fmt.Sprintf("%d versions: %s%s", versionCount, strings.Join(shown, ", "), ellipsis),
					"recommendation": fmt.Sprintf("Standardize software versions across fleet. Currently running %d different versions.", versionCount),
					"details":        fmt.Sprintf("Version sprawl detected - %d different versions installed", versionCount),
					"risk_reason":    fmt.Sprintf("Risk is %s because there are %d distinct versions installed, indicating poor patch management.", strings.ToUpper(riskLevel), versionCount),
				})
				counter++
			}
		}
	}

	// ===== Summary =====
	var high, medium, low int
	hostSet, userSet := map[string]struct{}{}, map[string]struct{}{}
	riskDistribution := map[string]any{}
	for _, det := range detections {
		switch det["risk_level"] {
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		}
		if hs, ok := det["affected_hosts"].([]any); ok {
			for _, x := range hs {
				hostSet[pyStr(x)] = struct{}{}
			}
		}
		for _, u := range det["affected_users"].([]string) {
			userSet[u] = struct{}{}
		}
		cat := det["category"].(string)
		n, _ := riskDistribution[cat].(int)
		riskDistribution[cat] = n + 1
	}
	summary := map[string]any{
		"total_detections": len(detections),
		"high_risk":        high,
		"medium_risk":      medium,
		"low_risk":         low,
		"affected_hosts":   len(hostSet),
		"affected_users":   len(userSet),
	}
	h.log().Info(fmt.Sprintf("Shadow IT scan (team: %s, platform: %s): %d detections", teamFilter, platformFilter, len(detections)))

	return http.StatusOK, map[string]any{
		"summary":           summary,
		"detections":        detections,
		"risk_distribution": riskDistribution,
		"filters": map[string]any{
			"team":           teamFilter,
			"platform":       platformFilter,
			"risk":           riskFilter,
			"detection_type": detectionTypeFilter,
		},
	}, nil
}

func usersOrEmpty(u []string) []string {
	if u == nil {
		return []string{}
	}
	return u
}

func anyWordMatch(patterns []string, text string) bool {
	for _, p := range patterns {
		if httpx.WordMatch(p, text) {
			return true
		}
	}
	return false
}

func recommendationFor(category string) string {
	if r, ok := recommendations[category]; ok {
		return r
	}
	return "Review and verify authorization"
}
