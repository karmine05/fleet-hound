package entities

import (
	"net/http"

	"github.com/karmine05/fleet-hound/internal/app"
	"github.com/karmine05/fleet-hound/internal/hostfilter"
	"github.com/karmine05/fleet-hound/internal/httpx"
)

// softwareVersionsCap bounds `versions` per row in /api/software: the
// largest field in the response; the list view only needs a sample.
const softwareVersionsCap = 25

func getHosts(d *app.Deps, w http.ResponseWriter, r *http.Request) error {
	if dbDown(d, w, r) {
		return nil
	}
	rows, err := d.DB.Query(r.Context(), `
            MATCH (h:Host)
            RETURN h.hostname AS hostname, h.os_version AS os_version,
                   h.platform AS platform, h.ip AS ip, h.last_seen AS last_seen
            LIMIT $limit
            `, map[string]any{"limit": httpx.BoundedLimit(r, 5000, 20000)})
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, rows)
	return nil
}

// getUsers lists users per host - only users connected to hosts.
func getUsers(d *app.Deps, w http.ResponseWriter, r *http.Request) error {
	if dbDown(d, w, r) {
		return nil
	}
	rows, err := d.DB.Query(r.Context(), `
            MATCH (u:User)-[:USES]->(h:Host)
            RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname,
                   h.hostname AS hostname, h.platform AS platform
            ORDER BY h.hostname, u.username
            LIMIT $limit
        `, map[string]any{"limit": httpx.BoundedLimit(r, 5000, 20000)})
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, u := range rows {
		if truthy(u["hostname"]) {
			out = append(out, u)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}

func getSoftware(d *app.Deps, w http.ResponseWriter, r *http.Request) error {
	if dbDown(d, w, r) {
		return nil
	}
	// Sorted by install count so a defaulted limit returns the most
	// widespread software first. Plain MATCH: software on no host is not
	// listed.
	rows, err := d.DB.Query(r.Context(), `
            MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
            WITH s, count(DISTINCT h) AS host_count
            ORDER BY host_count DESC, s.name ASC
            RETURN s.name AS name,
                   coalesce(s.display_name, s.name) AS display_name,
                   s.versions AS versions,
                   s.last_version AS last_version,
                   s.kind AS kind,
                   s.extension_key AS extension_key,
                   host_count
            LIMIT $limit
            `, map[string]any{"limit": httpx.BoundedLimit(r, 5000, 20000)})
	if err != nil {
		return err
	}
	for _, row := range rows {
		switch v := row["versions"].(type) {
		case []any:
			if len(v) > softwareVersionsCap {
				row["versions"] = v[:softwareVersionsCap]
			}
		default:
			if !truthy(v) {
				row["versions"] = []any{}
			}
		}
	}
	httpx.WriteJSON(w, http.StatusOK, rows)
	return nil
}

// getTeams lists all unique teams from hosts.
func getTeams(d *app.Deps, w http.ResponseWriter, r *http.Request) error {
	if dbDown(d, w, r) {
		return nil
	}
	rows, err := d.DB.Query(r.Context(), `
            MATCH (h:Host)
            WHERE h.team_id IS NOT NULL
            RETURN DISTINCT h.team_id AS team_id, h.team_name AS team_name
            ORDER BY h.team_name
        `, nil)
	if err != nil {
		return err
	}
	teams := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		teams = append(teams, map[string]any{"id": hostfilter.PyStr(row["team_id"]), "name": row["team_name"]})
	}
	httpx.WriteJSON(w, http.StatusOK, teams)
	return nil
}

// getPlatforms lists all unique platforms from hosts.
func getPlatforms(d *app.Deps, w http.ResponseWriter, r *http.Request) error {
	if dbDown(d, w, r) {
		return nil
	}
	rows, err := d.DB.Query(r.Context(), `
            MATCH (h:Host)
            WHERE h.platform IS NOT NULL AND h.platform <> ""
            RETURN DISTINCT h.platform AS platform
            ORDER BY h.platform
        `, nil)
	if err != nil {
		return err
	}
	platforms := make([]any, 0, len(rows))
	for _, row := range rows {
		platforms = append(platforms, row["platform"])
	}
	httpx.WriteJSON(w, http.StatusOK, platforms)
	return nil
}

// getRelationships lists USES + INSTALLED_ON edges, bounded so a
// multi-million-edge fleet cannot OOM the response.
func getRelationships(d *app.Deps, w http.ResponseWriter, r *http.Request) error {
	if dbDown(d, w, r) {
		return nil
	}
	limit := httpx.Clamp(httpx.ArgInt(r, "limit", 5000), 1, 10000)
	half := max(1, limit/2)
	rows := make([]map[string]any, 0, limit)
	uses, err := d.DB.Query(r.Context(), `
            MATCH (u:User)-[:USES]->(h:Host)
            RETURN 'USES' AS type, u.username AS from_name, h.hostname AS to_host
            LIMIT $limit
            `, map[string]any{"limit": half})
	if err != nil {
		return err
	}
	rows = append(rows, uses...)
	installed, err := d.DB.Query(r.Context(), `
            MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
            RETURN 'INSTALLED_ON' AS type, s.name AS from_name, h.hostname AS to_host
            LIMIT $limit
            `, map[string]any{"limit": limit - half})
	if err != nil {
		return err
	}
	rows = append(rows, installed...)
	httpx.WriteJSON(w, http.StatusOK, rows)
	return nil
}
