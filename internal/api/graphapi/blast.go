package graphapi

import (
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/karmine05/fleet-hound/internal/graphdb"
	"github.com/karmine05/fleet-hound/internal/hostfilter"
	"github.com/karmine05/fleet-hound/internal/httpx"
)

// defaultAccounts is the ignore_defaults=true fallback list from blast_radius.py.
var defaultAccounts = []any{"root", "Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount"}

// blastRadius replaces get_blast_radius (/api/blast-radius).
func (h *handlers) blastRadius(w http.ResponseWriter, r *http.Request) error {
	if !h.dbReady(w, r) {
		return nil
	}
	q := r.URL.Query()
	nodeType, nodeID := q.Get("type"), q.Get("id")
	teamFilter := strings.TrimSpace(q.Get("team"))
	if teamFilter == "" {
		teamFilter = "all"
	}
	ignoreDefaults := strings.ToLower(httpx.Arg(r, "ignore_defaults", "false")) == "true"

	if nodeType == "" || nodeID == "" {
		httpx.Error(w, http.StatusBadRequest, "Missing type or id parameter")
		return nil
	}
	if nodeType != "user" && nodeType != "software" {
		httpx.ErrorMsg(w, http.StatusBadRequest, "Invalid type", "type must be one of ['software', 'user']")
		return nil
	}
	if utf8.RuneCountInString(nodeID) > 300 {
		httpx.ErrorMsg(w, http.StatusBadRequest, "Invalid id", "id must be <= 300 characters")
		return nil
	}
	if nodeType == "software" {
		nodeID = strings.ToLower(strings.TrimSpace(nodeID))
	}

	labelFrag, labelParams, err := hostfilter.ApplyLabelFilter(q, "h")
	if err != nil {
		if hostfilter.IsValidationError(err) {
			httpx.ErrorMsg(w, http.StatusBadRequest, "Invalid filter", err.Error())
			return nil
		}
		return err
	}

	ctx, db := r.Context(), h.d.DB
	metrics := map[string]any{"host_reach": 0, "user_impact": 0, "lateral_movement": 0, "platform_diversity": 0}
	var detailHosts, detailUsers, detailTeams, detailPlatforms []any

	teamClause := ""
	params := map[string]any{"id": nodeID}
	if teamFilter != "all" {
		teamClause = "AND toString(h.team_id) = $team_id"
		params["team_id"] = teamFilter
	}
	for k, v := range labelParams {
		params[k] = v
	}

	userExclusion := ""
	if nodeType == "user" {
		userExclusion = "AND u.username <> $id"
	}
	if raw := q.Get("excluded_users"); raw != "" {
		var excluded []any
		for _, u := range strings.Split(raw, ",") {
			if u = strings.TrimSpace(u); u != "" {
				excluded = append(excluded, u)
			}
		}
		if len(excluded) > 1000 {
			httpx.ErrorMsg(w, http.StatusBadRequest, "excluded_users too large", "excluded_users must contain <= 1000 usernames")
			return nil
		}
		if len(excluded) > 0 {
			userExclusion += " AND NOT u.username IN $defaults"
			params["defaults"] = excluded
		}
	} else if ignoreDefaults {
		userExclusion += " AND NOT u.username IN $defaults"
		params["defaults"] = defaultAccounts
	}

	var hostQuery string
	if nodeType == "user" {
		hostQuery = `
                MATCH (u:User {username: $id})-[:USES]->(h:Host)
                WHERE 1=1 ` + teamClause + ` ` + labelFrag + `
                RETURN collect(DISTINCT h) as hosts
            `
	} else {
		meta, err := db.Single(ctx, "MATCH (s:Software {name: $id}) "+
			"RETURN s.category AS category, "+
			"       s.wikidata_description AS description LIMIT 1",
			map[string]any{"id": nodeID})
		if err != nil {
			return err
		}
		metrics["category"], metrics["description"] = nil, nil
		if meta != nil {
			metrics["category"], metrics["description"] = meta["category"], meta["description"]
		}
		hostQuery = `
                MATCH (s:Software {name: $id})-[:INSTALLED_ON]->(h:Host)
                WHERE 1=1 ` + teamClause + ` ` + labelFrag + `
                RETURN collect(DISTINCT h) AS hosts
            `
	}
	hrec, err := db.Single(ctx, hostQuery, params)
	if err != nil {
		return err
	}
	var hosts []any
	if hrec != nil {
		hosts, _ = hrec["hosts"].([]any)
	}
	metrics["host_reach"] = len(hosts)
	hostFids := []any{}
	seenPlat, seenTeam := map[string]struct{}{}, map[string]struct{}{}
	for _, hv := range hosts {
		hm, _ := hv.(map[string]any)
		detailHosts = append(detailHosts, hm["hostname"])
		hostFids = append(hostFids, hm["fleet_host_id"])
		// python built these from set(); order is first-seen here.
		if p := hm["platform"]; truthy(p) {
			if _, ok := seenPlat[pyFmt(p)]; !ok {
				seenPlat[pyFmt(p)] = struct{}{}
				detailPlatforms = append(detailPlatforms, p)
			}
		}
		if t := hm["team_name"]; truthy(t) {
			if _, ok := seenTeam[pyFmt(t)]; !ok {
				seenTeam[pyFmt(t)] = struct{}{}
				detailTeams = append(detailTeams, t)
			}
		}
	}
	metrics["platform_diversity"] = len(detailPlatforms)

	if len(hosts) > 0 {
		up := make(map[string]any, len(params)+1)
		for k, v := range params {
			up[k] = v
		}
		up["host_fids"] = hostFids
		urec, err := db.Single(ctx, `
                    MATCH (u:User)-[:USES]->(h:Host)
                    WHERE h.fleet_host_id IN $host_fids `+userExclusion+`
                    RETURN collect(DISTINCT u.username) as users
                `, up)
		if err != nil {
			return err
		}
		if urec != nil {
			detailUsers, _ = urec["users"].([]any)
		}
		metrics["user_impact"] = len(detailUsers)
	}

	if len(detailUsers) > 0 {
		lrec, err := db.Single(ctx, `
                MATCH (u:User)-[:USES]->(h:Host)
                WHERE u.username IN $users
                  AND NOT h.fleet_host_id IN $original_fids
                RETURN collect(DISTINCT h.fleet_host_id) as lateral_hosts
            `, map[string]any{"users": detailUsers, "original_fids": hostFids})
		if err != nil {
			return err
		}
		var lateral []any
		if lrec != nil {
			lateral, _ = lrec["lateral_hosts"].([]any)
		}
		metrics["lateral_movement"] = len(lateral)
	}

	global, err := db.Single(ctx, `
            MATCH (h:Host)
            WITH count(h) AS total_hosts, count(DISTINCT h.team_id) AS total_teams
            MATCH (u:User)-[:USES]->(:Host)
            RETURN total_hosts, total_teams, count(DISTINCT u) AS total_users
        `, nil)
	if err != nil {
		return err
	}
	field := func(rec map[string]any, k string) int64 {
		if rec == nil {
			return 1
		}
		v, _ := graphdb.AsInt64(rec[k])
		return v
	}
	globalTeams := field(global, "total_teams")
	scoped := global
	if teamFilter != "all" {
		scoped, err = db.Single(ctx, `
                MATCH (h:Host) WHERE toString(h.team_id) = $team_id
                WITH count(h) as total_hosts
                OPTIONAL MATCH (u:User)-[:USES]->(h:Host) WHERE toString(h.team_id) = $team_id
                RETURN total_hosts, count(DISTINCT u) as total_users
            `, map[string]any{"team_id": teamFilter})
		if err != nil {
			return err
		}
	}
	totalHosts := max(field(scoped, "total_hosts"), 1)
	totalUsers := max(field(scoped, "total_users"), 1)
	globalHosts := max(field(global, "total_hosts"), 1)

	score := func(n int, d int64) int { return min(int(float64(n)/float64(d)*100), 100) }
	scores := map[string]any{
		"Host Reach":         score(metrics["host_reach"].(int), totalHosts),
		"User Impact":        score(metrics["user_impact"].(int), totalUsers),
		"Lateral Movement":   score(metrics["lateral_movement"].(int), globalHosts),
		"Platform Diversity": score(metrics["platform_diversity"].(int), 3),
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"metrics": metrics,
		"scores":  scores,
		"details": map[string]any{
			"hosts":     nonNil(detailHosts),
			"users":     nonNil(detailUsers),
			"teams":     nonNil(detailTeams),
			"platforms": nonNil(detailPlatforms),
		},
		"scope": map[string]any{
			"team_filter": teamFilter,
			"totals":      map[string]any{"hosts": totalHosts, "users": totalUsers, "teams": globalTeams},
		},
	})
	return nil
}

func nonNil(v []any) []any {
	if v == nil {
		return []any{}
	}
	return v
}
