package graphapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/karmine05/fleet-hound/internal/graphdb"
	"github.com/karmine05/fleet-hound/internal/hostfilter"
	"github.com/karmine05/fleet-hound/internal/httpx"
)

// graph replaces get_graph_data (/api/graph).
func (h *handlers) graph(w http.ResponseWriter, r *http.Request) error {
	if !h.dbReady(w, r) {
		return nil
	}
	ctx, db := r.Context(), h.d.DB
	nodes := []map[string]any{}

	hostRecs, err := db.Query(ctx, `
            MATCH (h:Host)<-[:USES]-(u:User)
            RETURN DISTINCT h.fleet_host_id AS fleet_host_id,
                            h.hostname AS hostname,
                            h.os_version AS os_version,
                            h.platform AS platform,
                            h.team_id AS team_id,
                            h.team_name AS team_name
        `, nil)
	if err != nil {
		return err
	}
	counts := hostfilter.HostnameCounts(hostRecs)
	for _, rec := range hostRecs {
		fid := rec["fleet_host_id"]
		if fid == nil {
			continue
		}
		hn := rec["hostname"]
		nodes = append(nodes, withTeam(map[string]any{
			"id":            "host_" + pyFmt(fid),
			"name":          hn,
			"display_name":  hostfilter.DisambiguatedDisplayName(hn, fid, counts),
			"fleet_host_id": fid,
			"type":          "host",
			"details":       hostDetails(rec),
		}, rec))
	}

	userRecs, err := db.Query(ctx, `
            MATCH (u:User)-[:USES]->(h:Host)
            RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname
        `, nil)
	if err != nil {
		return err
	}
	for _, rec := range userRecs {
		nodes = append(nodes, userNode(rec))
	}

	links := []map[string]any{}
	relRecs, err := db.Query(ctx, `
            MATCH (u:User)-[r:USES]->(h:Host)
            RETURN DISTINCT 'uses' AS type, u.username AS from_name,
                            h.fleet_host_id AS to_host_id
        `, nil)
	if err != nil {
		return err
	}
	for _, rec := range relRecs {
		links = append(links, map[string]any{
			"source": "user_" + pyFmt(rec["from_name"]),
			"target": "host_" + pyFmt(rec["to_host_id"]),
			"type":   rec["type"],
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "links": links})
	return nil
}

// graphFull replaces get_full_graph_data (/api/graph/full).
func (h *handlers) graphFull(w http.ResponseWriter, r *http.Request) {
	if !h.dbReady(w, r) {
		return
	}
	var (
		frag   string
		params map[string]any
		err    error
	)
	if exprRaw := strings.TrimSpace(r.URL.Query().Get("expr")); exprRaw != "" {
		expr, jerr := jsonLoads(exprRaw)
		if jerr != nil {
			httpx.ErrorMsg(w, http.StatusBadRequest, "Invalid expr", "expr must be valid JSON: "+jerr.Error())
			return
		}
		frag, params, err = hostfilter.ApplyCompositeFilter(expr, "h")
	} else {
		frag, params, err = hostfilter.ApplyHostFilters(r.URL.Query(), "h", false)
	}
	if err != nil {
		if hostfilter.IsValidationError(err) {
			httpx.ErrorMsg(w, http.StatusBadRequest, "Invalid filter", err.Error())
			return
		}
		h.fullGraphError(w, err)
		return
	}
	if err := h.graphFullQuery(w, r, frag, params); err != nil {
		h.fullGraphError(w, err)
	}
}

func (h *handlers) graphFullQuery(w http.ResponseWriter, r *http.Request, frag string, params map[string]any) error {
	ctx, db := r.Context(), h.d.DB
	nodes := []map[string]any{}
	nodeIDs := map[string]struct{}{}
	add := func(n map[string]any) {
		nodes = append(nodes, n)
		nodeIDs[n["id"].(string)] = struct{}{}
	}

	hostRecs, err := db.Query(ctx, "MATCH (h:Host) "+
		"WHERE (EXISTS((h)<-[:USES]-(:User)) OR EXISTS((h)<-[:INSTALLED_ON]-(:Software)))"+
		frag+
		" RETURN h.fleet_host_id AS fleet_host_id, "+
		"        h.hostname AS hostname, h.os_version AS os_version, "+
		"        h.platform AS platform, h.team_id AS team_id, "+
		"        h.team_name AS team_name", params)
	if err != nil {
		return err
	}
	counts := hostfilter.HostnameCounts(hostRecs)
	hostFids := []any{}
	for _, rec := range hostRecs {
		fid, hn := rec["fleet_host_id"], rec["hostname"]
		add(withTeam(map[string]any{
			"id":            "host_" + pyFmt(fid),
			"name":          hn,
			"display_name":  hostfilter.DisambiguatedDisplayName(hn, fid, counts),
			"fleet_host_id": fid,
			"type":          "host",
			"details":       hostDetails(rec),
		}, rec))
		if fid != nil {
			hostFids = append(hostFids, fid)
		}
	}

	userRecs, err := db.Query(ctx, "MATCH (u:User)-[:USES]->(h:Host) "+
		"WHERE 1=1"+frag+
		" RETURN DISTINCT u.username AS username, u.email AS email, "+
		"        u.fullname AS fullname", params)
	if err != nil {
		return err
	}
	for _, rec := range userRecs {
		add(userNode(rec))
	}

	swRecs, err := db.Query(ctx, "MATCH (s:Software)-[:INSTALLED_ON]->(h:Host) "+
		"WHERE 1=1"+frag+
		" WITH s, COUNT(DISTINCT h) AS host_count "+
		"ORDER BY host_count DESC "+
		"LIMIT 50 "+
		"RETURN s.name AS name, coalesce(s.display_name, s.name) AS display_name, s.last_version AS last_version, "+
		"        s.category AS category, "+
		"        s.wikidata_description AS description, "+
		"        host_count", params)
	if err != nil {
		return err
	}
	softwareNames := []any{}
	for _, rec := range swRecs {
		n := map[string]any{
			"id":           "software_" + pyFmt(rec["name"]),
			"name":         rec["name"],
			"display_name": orVal(rec["display_name"], rec["name"]),
			"type":         "software",
			"details":      "Latest: " + orStr(rec["last_version"], "unknown") + " (on " + pyFmt(rec["host_count"]) + " hosts)",
		}
		if truthy(rec["category"]) {
			n["category"] = rec["category"]
		}
		if truthy(rec["description"]) {
			n["description"] = rec["description"]
		}
		add(n)
		softwareNames = append(softwareNames, rec["name"])
	}

	links := []map[string]any{}
	addLink := func(src, tgt string, typ any) bool {
		_, okS := nodeIDs[src]
		_, okT := nodeIDs[tgt]
		if okS && okT {
			links = append(links, map[string]any{"source": src, "target": tgt, "type": typ})
			return true
		}
		return false
	}

	relRecs, err := db.Query(ctx, `
                MATCH (u:User)-[r:USES]->(h:Host)
                WHERE h.fleet_host_id IN $host_fids
                RETURN 'uses' AS type, u.username AS from_name,
                       h.fleet_host_id AS to_host_id
            `, map[string]any{"host_fids": hostFids})
	if err != nil {
		return err
	}
	for _, rec := range relRecs {
		addLink("user_"+pyFmt(rec["from_name"]), "host_"+pyFmt(rec["to_host_id"]), rec["type"])
	}

	if len(softwareNames) > 0 {
		swRel, err := db.Query(ctx, `
                    MATCH (s:Software)-[r:INSTALLED_ON]->(h:Host)
                    WHERE s.name IN $software_names AND h.fleet_host_id IN $host_fids
                    RETURN 'installed' AS type, s.name AS from_name,
                           h.fleet_host_id AS to_host_id
                `, map[string]any{"software_names": softwareNames, "host_fids": hostFids})
		if err != nil {
			return err
		}
		added := 0
		for _, rec := range swRel {
			if addLink("software_"+pyFmt(rec["from_name"]), "host_"+pyFmt(rec["to_host_id"]), rec["type"]) {
				added++
			}
		}
		h.log().Info("Software links added", "count", added)
	}

	h.log().Info("Full graph API", "nodes", len(nodes), "links", len(links))
	resp := map[string]any{}
	if sampleRaw := strings.TrimSpace(r.URL.Query().Get("sample")); sampleRaw != "" {
		n, err := pyInt(sampleRaw)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "sample must be an integer")
			return nil
		}
		if n < 20 || n > 300 {
			httpx.Error(w, http.StatusBadRequest, "sample must be between 20 and 300")
			return nil
		}
		var meta map[string]any
		nodes, links, meta = SampleGraph(nodes, links, n)
		h.log().Info("Full graph sample", "kept_nodes", len(nodes), "total_nodes", meta["total_nodes"],
			"kept_links", len(links), "total_links", meta["total_links"])
		for k, v := range meta {
			resp[k] = v
		}
	}
	resp["nodes"], resp["links"] = nodes, links
	httpx.WriteJSON(w, http.StatusOK, resp)
	return nil
}

// fullGraphError is the except TransientError / except Exception tail of
// get_full_graph_data.
func (h *handlers) fullGraphError(w http.ResponseWriter, err error) {
	msg := err.Error()
	var status int
	var payload map[string]any
	switch {
	case graphdb.IsTransient(err) && strings.Contains(msg, "Memory limit exceeded"):
		h.log().Error("Memory limit exceeded while loading full graph", "err", err)
		status = http.StatusInsufficientStorage
		payload = map[string]any{
			"error":   "Dataset too large for available memory",
			"message": "The dataset is too large to load all at once. Try increasing Memgraph's memory limit in docker-compose.yml or use the filtered view instead.",
		}
	case graphdb.IsTransient(err):
		h.log().Error("Transient error in get_full_graph_data", "err", err)
		status = http.StatusServiceUnavailable
		payload = map[string]any{"error": "Database transient error"}
	default:
		h.log().Error("Unexpected error in get_full_graph_data", "err", err)
		status = http.StatusInternalServerError
		payload = map[string]any{"error": "Internal server error"}
	}
	if h.d.Debug() {
		payload["details"] = msg
	}
	httpx.WriteJSON(w, status, payload)
}

// softwareHosts replaces get_software_hosts (/api/software/<name>/hosts).
func (h *handlers) softwareHosts(w http.ResponseWriter, r *http.Request) error {
	if !h.dbReady(w, r) {
		return nil
	}
	name := strings.ToLower(strings.TrimSpace(r.PathValue("software_name")))
	if name == "" {
		httpx.Error(w, http.StatusBadRequest, "Software name required")
		return nil
	}
	ctx, db := r.Context(), h.d.DB
	p := map[string]any{"name": name}

	sw, err := db.Single(ctx, "MATCH (s:Software {name: $name}) "+
		"RETURN s.name AS name, "+
		"       coalesce(s.display_name, s.name) AS display_name, "+
		"       s.last_version AS last_version", p)
	if err != nil {
		return err
	}
	if sw == nil {
		httpx.Error(w, http.StatusNotFound, "Software not found")
		return nil
	}

	nodes := []map[string]any{}
	nodeIDs := map[string]struct{}{}
	softwareID := "software_" + name
	nodes = append(nodes, map[string]any{
		"id":           softwareID,
		"name":         name,
		"display_name": orVal(sw["display_name"], name),
		"type":         "software",
		"details":      "Latest: " + orStr(sw["last_version"], "unknown"),
	})
	nodeIDs[softwareID] = struct{}{}

	hostRecs, err := db.Query(ctx, `
            MATCH (s:Software {name: $name})-[:INSTALLED_ON]->(h:Host)
            RETURN DISTINCT h.fleet_host_id AS fleet_host_id,
                            h.hostname AS hostname,
                            h.os_version AS os_version,
                            h.platform AS platform,
                            h.team_id AS team_id,
                            h.team_name AS team_name
        `, p)
	if err != nil {
		return err
	}
	counts := hostfilter.HostnameCounts(hostRecs)
	for _, rec := range hostRecs {
		fid, hn := rec["fleet_host_id"], rec["hostname"]
		hostID := "host_" + pyFmt(fid)
		if _, dup := nodeIDs[hostID]; dup {
			continue
		}
		nodes = append(nodes, withTeam(map[string]any{
			"id":            hostID,
			"name":          hn,
			"display_name":  hostfilter.DisambiguatedDisplayName(hn, fid, counts),
			"fleet_host_id": fid,
			"type":          "host",
			"details":       hostDetails(rec),
		}, rec))
		nodeIDs[hostID] = struct{}{}
	}

	userRecs, err := db.Query(ctx, `
            MATCH (s:Software {name: $name})-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
            RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname
        `, p)
	if err != nil {
		return err
	}
	for _, rec := range userRecs {
		n := userNode(rec)
		id := n["id"].(string)
		if _, dup := nodeIDs[id]; dup {
			continue
		}
		nodes = append(nodes, n)
		nodeIDs[id] = struct{}{}
	}

	links := []map[string]any{}
	swLinks, err := db.Query(ctx, `
            MATCH (s:Software {name: $name})-[:INSTALLED_ON]->(h:Host)
            RETURN DISTINCT h.fleet_host_id AS fleet_host_id
        `, p)
	if err != nil {
		return err
	}
	seen := map[[2]string]struct{}{}
	for _, rec := range swLinks {
		target := "host_" + pyFmt(rec["fleet_host_id"])
		key := [2]string{softwareID, target}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		if _, ok := nodeIDs[target]; ok {
			links = append(links, map[string]any{"source": softwareID, "target": target, "type": "installed"})
		}
	}

	uhLinks, err := db.Query(ctx, `
            MATCH (s:Software {name: $name})-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
            RETURN DISTINCT u.username AS username, h.fleet_host_id AS fleet_host_id
        `, p)
	if err != nil {
		return err
	}
	seenUH := map[[2]string]struct{}{}
	for _, rec := range uhLinks {
		src, tgt := "user_"+pyFmt(rec["username"]), "host_"+pyFmt(rec["fleet_host_id"])
		key := [2]string{src, tgt}
		if _, dup := seenUH[key]; dup {
			continue
		}
		seenUH[key] = struct{}{}
		_, okS := nodeIDs[src]
		_, okT := nodeIDs[tgt]
		if okS && okT {
			links = append(links, map[string]any{"source": src, "target": tgt, "type": "uses"})
		}
	}

	h.log().Info("Software graph", "software", name, "nodes", len(nodes), "links", len(links))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "links": links})
	return nil
}

// isASCIIDigits is python str.isdigit restricted to ASCII (int() of the
// non-ASCII digits isdigit also accepts would have raised anyway).
func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// hostSoftware replaces get_host_software (/api/host/<hostname>/software).
func (h *handlers) hostSoftware(w http.ResponseWriter, r *http.Request) error {
	if !h.dbReady(w, r) {
		return nil
	}
	ctx, db := r.Context(), h.d.DB
	var (
		host map[string]any
		err  error
	)
	fidRaw := strings.TrimSpace(r.URL.Query().Get("fleet_host_id"))
	if isASCIIDigits(fidRaw) {
		fid, perr := strconv.ParseInt(fidRaw, 10, 64)
		if perr == nil {
			host, err = db.Single(ctx, "MATCH (h:Host {fleet_host_id: $fid}) "+
				"RETURN h.fleet_host_id AS fleet_host_id, h.hostname AS hostname, "+
				"       h.os_version AS os_version, h.platform AS platform, "+
				"       h.team_id AS team_id, h.team_name AS team_name",
				map[string]any{"fid": fid})
		}
		// shortcut: an id beyond int64 matches no host, so it is a 404 (python raised and 500'd).
	} else {
		host, err = db.Single(ctx, "MATCH (h:Host) "+
			"WHERE toLower(h.hostname) = toLower($hostname) "+
			"RETURN h.fleet_host_id AS fleet_host_id, h.hostname AS hostname, "+
			"       h.os_version AS os_version, h.platform AS platform, "+
			"       h.team_id AS team_id, h.team_name AS team_name "+
			"ORDER BY h.last_seen DESC LIMIT 1",
			map[string]any{"hostname": r.PathValue("hostname")})
	}
	if err != nil {
		return err
	}
	if host == nil {
		httpx.Error(w, http.StatusNotFound, "Host not found")
		return nil
	}

	fid, canonical := host["fleet_host_id"], host["hostname"]
	p := map[string]any{"fleet_host_id": fid}
	nodes := []map[string]any{}
	nodeIDs := map[string]struct{}{}
	hostID := "host_" + pyFmt(fid)
	nodes = append(nodes, withTeam(map[string]any{
		"id":            hostID,
		"name":          canonical,
		"display_name":  canonical,
		"fleet_host_id": fid,
		"type":          "host",
		"details":       hostDetails(host),
	}, host))
	nodeIDs[hostID] = struct{}{}

	userRecs, err := db.Query(ctx, `
            MATCH (u:User)-[:USES]->(h:Host {fleet_host_id: $fleet_host_id})
            RETURN u.username AS username, u.email AS email, u.fullname AS fullname
        `, p)
	if err != nil {
		return err
	}
	for _, rec := range userRecs {
		n := userNode(rec)
		nodes = append(nodes, n)
		nodeIDs[n["id"].(string)] = struct{}{}
	}

	swRecs, err := db.Query(ctx, `
            MATCH (s:Software)-[:INSTALLED_ON]->(h:Host {fleet_host_id: $fleet_host_id})
            RETURN s.name AS name,
                   coalesce(s.display_name, s.name) AS display_name,
                   s.last_version AS last_version
            ORDER BY coalesce(s.display_name, s.name)
        `, p)
	if err != nil {
		return err
	}
	for _, rec := range swRecs {
		id := "software_" + pyFmt(rec["name"])
		nodes = append(nodes, map[string]any{
			"id":           id,
			"name":         rec["name"],
			"display_name": orVal(rec["display_name"], rec["name"]),
			"type":         "software",
			"details":      "Latest: " + orStr(rec["last_version"], "unknown"),
		})
		nodeIDs[id] = struct{}{}
	}

	links := []map[string]any{}
	userLinks, err := db.Query(ctx, `
            MATCH (u:User)-[:USES]->(h:Host {fleet_host_id: $fleet_host_id})
            RETURN u.username AS username
        `, p)
	if err != nil {
		return err
	}
	for _, rec := range userLinks {
		src := "user_" + pyFmt(rec["username"])
		if _, ok := nodeIDs[src]; ok {
			links = append(links, map[string]any{"source": src, "target": hostID, "type": "uses"})
		}
	}
	swLinks, err := db.Query(ctx, `
            MATCH (s:Software)-[:INSTALLED_ON]->(h:Host {fleet_host_id: $fleet_host_id})
            RETURN s.name AS name
        `, p)
	if err != nil {
		return err
	}
	for _, rec := range swLinks {
		src := "software_" + pyFmt(rec["name"])
		if _, ok := nodeIDs[src]; ok {
			links = append(links, map[string]any{"source": src, "target": hostID, "type": "installed"})
		}
	}

	h.log().Info("Host graph", "host", canonical, "id", fid, "nodes", len(nodes), "links", len(links))
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "links": links})
	return nil
}
