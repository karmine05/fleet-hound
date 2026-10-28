package entities

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/karmine05/fleet-hound/internal/app"
	"github.com/karmine05/fleet-hound/internal/hostfilter"
	"github.com/karmine05/fleet-hound/internal/httpx"
)

// connectedHostCap caps hosts pulled in around matched users/software
// (graph render budget).
const connectedHostCap = 500

const hostReturn = " RETURN DISTINCT h.fleet_host_id AS fleet_host_id, h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform, h.team_name AS team_name, h.team_id AS team_id"

// lowerRegexLiterals is _lower_regex_literals: lowercase a regex for matching
// against toLower(text) with escapes intact (Memgraph has no (?i), and a
// plain lower() turned \D/\S/\W/\B into \d/\s/\w/\b).
func lowerRegexLiterals(pattern string) string {
	rs := []rune(pattern)
	var b strings.Builder
	for i := 0; i < len(rs); i++ {
		if rs[i] == '\\' && i+1 < len(rs) {
			b.WriteRune(rs[i])
			b.WriteRune(rs[i+1])
			i++
			continue
		}
		b.WriteRune(unicode.ToLower(rs[i]))
	}
	return b.String()
}

// searchQuery accumulates one Cypher query + params with the shared
// platform / team / label clauses the python appended inline.
type searchQuery struct {
	sb     strings.Builder
	params map[string]any
}

func (q *searchQuery) scope(platform, team, labelFrag string, labelParams map[string]any) {
	if platform != "all" {
		q.sb.WriteString(" AND toLower(h.platform) CONTAINS toLower($platform)")
		q.params["platform"] = platform
	}
	if team != "all" {
		q.sb.WriteString(" AND toString(h.team_id) = $team_id")
		q.params["team_id"] = team
	}
	q.sb.WriteString(labelFrag)
	for k, v := range labelParams {
		q.params[k] = v
	}
}

func hostRecord(rec map[string]any) map[string]any {
	return map[string]any{
		"fleet_host_id": rec["fleet_host_id"],
		"hostname":      rec["hostname"],
		"os_version":    rec["os_version"],
		"platform":      rec["platform"],
		"team_name":     rec["team_name"],
		"team_id":       rec["team_id"],
	}
}

// searchAll is the universal search over hosts, users and software
// (?q, ?type, ?platform, ?team, ?labels/label_op, ?mode, ?case, ?limit). It
// returns matching nodes plus the links between them.
func searchAll(d *app.Deps, w http.ResponseWriter, r *http.Request) error {
	args := r.URL.Query()
	searchTerm := strings.TrimSpace(httpx.Arg(r, "q", ""))
	nodeType := strings.ToLower(strings.TrimSpace(httpx.Arg(r, "type", "all")))
	platformFilter := strings.ToLower(strings.TrimSpace(httpx.Arg(r, "platform", "all")))
	teamFilter := strings.TrimSpace(httpx.Arg(r, "team", "all"))

	labelFrag, labelParams, err := hostfilter.ApplyLabelFilter(args, "h")
	if err != nil {
		httpx.ErrorMsg(w, http.StatusBadRequest, "Invalid filter", err.Error())
		return nil
	}

	searchMode := strings.ToLower(strings.TrimSpace(httpx.Arg(r, "mode", "wildcard")))
	caseSensitive := strings.ToLower(strings.TrimSpace(httpx.Arg(r, "case", "false"))) == "true"

	// Validate before touching the database: callers get a 400 even when
	// Memgraph is down, and a malicious regex never reaches the DB.
	switch nodeType {
	case "all", "host", "user", "software":
	default:
		httpx.ErrorMsg(w, http.StatusBadRequest, "Invalid node type",
			"type must be one of ['all', 'host', 'software', 'user']")
		return nil
	}
	switch searchMode {
	case "wildcard", "exact", "regex":
	default:
		httpx.ErrorMsg(w, http.StatusBadRequest, "Invalid search mode",
			"mode must be one of ['exact', 'regex', 'wildcard']")
		return nil
	}
	if utf8.RuneCountInString(searchTerm) > 200 {
		httpx.ErrorMsg(w, http.StatusBadRequest, "Search term too long", "q must be <= 200 characters")
		return nil
	}
	// ReDoS guard.
	if searchMode == "regex" && searchTerm != "" {
		if msg, ok := httpx.ValidateUserRegex(searchTerm); !ok {
			httpx.ErrorMsg(w, http.StatusBadRequest, "Invalid regex", msg)
			return nil
		}
	}

	if dbDown(d, w, r) {
		return nil
	}

	// Hard cap so a caller cannot ?limit=1000000 the whole graph.
	limitParam := httpx.ArgInt(r, "limit", 0)
	if limitParam > 0 {
		limitParam = min(limitParam, 5000)
	}
	cypherLimit, displayLimit := 100, 10
	if limitParam > 0 {
		cypherLimit, displayLimit = limitParam, limitParam
	}

	cond := func(prop, termParam string) string {
		switch searchMode {
		case "exact":
			if caseSensitive {
				return fmt.Sprintf("%s = $%s", prop, termParam)
			}
			return fmt.Sprintf("toLower(%s) = toLower($%s)", prop, termParam)
		case "regex":
			// Case-insensitive regex matches a lowercased property.
			if caseSensitive {
				return fmt.Sprintf("%s =~ $%s", prop, termParam)
			}
			return fmt.Sprintf("toLower(%s) =~ $%s_lower", prop, termParam)
		}
		if caseSensitive {
			return fmt.Sprintf("%s CONTAINS $%s", prop, termParam)
		}
		return fmt.Sprintf("toLower(%s) CONTAINS toLower($%s)", prop, termParam)
	}
	termParams := func() map[string]any {
		if searchTerm == "" {
			return map[string]any{}
		}
		p := map[string]any{"search_term": searchTerm}
		if searchMode == "regex" && !caseSensitive {
			p["search_term_lower"] = lowerRegexLiterals(searchTerm)
		}
		return p
	}

	log := logger(d)
	if searchTerm != "" {
		log.Info(fmt.Sprintf("Search: '%s' (mode: %s, case: %s, type: %s)", searchTerm, searchMode, hostfilter.PyStr(caseSensitive), nodeType))
	} else {
		log.Info(fmt.Sprintf("Search: ALL (type: %s, limit: %d)", nodeType, limitParam))
	}

	ctx := r.Context()
	var (
		nodes          = []map[string]any{}
		nodeIDs        = map[string]struct{}{}
		userIDs        []string // insertion order of node ids (python iterated a set)
		softwareIDs    []string
		hostRecordsRaw []map[string]any
	)
	run := func(q *searchQuery) ([]map[string]any, error) {
		return d.DB.Query(ctx, q.sb.String(), q.params)
	}

	if nodeType == "all" || nodeType == "host" {
		q := &searchQuery{params: termParams()}
		if searchTerm != "" {
			fmt.Fprintf(&q.sb, "\n                    MATCH (h:Host)\n                    WHERE (%s OR %s)\n                ",
				cond("h.hostname", "search_term"), cond("h.os_version", "search_term"))
		} else {
			q.sb.WriteString("MATCH (h:Host) WHERE 1=1")
		}
		q.scope(platformFilter, teamFilter, labelFrag, labelParams)
		q.sb.WriteString(hostReturn)
		fmt.Fprintf(&q.sb, " LIMIT %d", cypherLimit)
		rows, err := run(q)
		if err != nil {
			return err
		}
		for _, rec := range rows {
			hostRecordsRaw = append(hostRecordsRaw, hostRecord(rec))
		}
	}

	if nodeType == "all" || nodeType == "user" {
		q := &searchQuery{params: termParams()}
		if searchTerm != "" {
			fmt.Fprintf(&q.sb, "\n                    MATCH (u:User)-[:USES]->(h:Host)\n                    WHERE (%s OR %s OR %s)\n                ",
				cond("u.username", "search_term"), cond("u.email", "search_term"), cond("u.fullname", "search_term"))
		} else {
			q.sb.WriteString("MATCH (u:User)-[:USES]->(h:Host) WHERE 1=1")
		}
		q.scope(platformFilter, teamFilter, labelFrag, labelParams)
		q.sb.WriteString(" RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname")
		fmt.Fprintf(&q.sb, " LIMIT %d", cypherLimit)
		rows, err := run(q)
		if err != nil {
			return err
		}
		for _, rec := range rows {
			id := "user_" + hostfilter.PyStr(rec["username"])
			if _, dup := nodeIDs[id]; dup {
				continue
			}
			nodes = append(nodes, map[string]any{
				"id":      id,
				"name":    rec["username"],
				"type":    "user",
				"details": or(or(rec["email"], rec["fullname"]), ""),
			})
			nodeIDs[id] = struct{}{}
			userIDs = append(userIDs, id)
		}
	}

	if nodeType == "all" || nodeType == "software" {
		q := &searchQuery{params: termParams()}
		if searchTerm != "" {
			fmt.Fprintf(&q.sb, "\n                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)\n                    WHERE (%s OR %s)\n                ",
				cond("s.name", "search_term"), cond("coalesce(s.display_name, s.name)", "search_term"))
			q.scope(platformFilter, teamFilter, labelFrag, labelParams)
			q.sb.WriteString(`
                    WITH s, COUNT(DISTINCT h) as host_count
                    RETURN s.name AS name, coalesce(s.display_name, s.name) AS display_name, s.last_version AS last_version, s.category AS category, s.wikidata_description AS description, host_count
                    ORDER BY host_count DESC, name
                `)
			fmt.Fprintf(&q.sb, " LIMIT %d", cypherLimit)
		} else {
			q.sb.WriteString("\n                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)\n                    WHERE 1=1\n                ")
			q.scope(platformFilter, teamFilter, labelFrag, labelParams)
			fmt.Fprintf(&q.sb, `
                    WITH s.name AS name, coalesce(s.display_name, s.name) AS display_name, s.last_version AS last_version, s.category AS category, s.wikidata_description AS description, COUNT(DISTINCT h) AS host_count
                    ORDER BY host_count DESC
                    LIMIT %d
                    RETURN name, display_name, last_version, category, description, host_count
                `, cypherLimit)
		}
		rows, err := run(q)
		if err != nil {
			return err
		}
		// Only the "ALL" (no term) listing is trimmed to displayLimit.
		softwareCount := 0
		for _, rec := range rows {
			id := "software_" + hostfilter.PyStr(rec["name"])
			if _, dup := nodeIDs[id]; dup {
				continue
			}
			if searchTerm == "" && softwareCount >= displayLimit {
				break
			}
			nodes = append(nodes, map[string]any{
				"id":           id,
				"name":         rec["name"],
				"display_name": or(rec["display_name"], rec["name"]),
				"type":         "software",
				"category":     rec["category"],
				"description":  rec["description"],
				"details": fmt.Sprintf("Latest: %s (on %s hosts)",
					hostfilter.PyStr(or(rec["last_version"], "unknown")), hostfilter.PyStr(rec["host_count"])),
			})
			nodeIDs[id] = struct{}{}
			softwareIDs = append(softwareIDs, id)
			softwareCount++
		}
	}

	// Connected hosts of loaded software / users. python used
	// str.replace(prefix, "") (every occurrence, not just the prefix); kept.
	connected := func(match, inParam string, names []string) error {
		q := &searchQuery{params: map[string]any{inParam: names}}
		q.sb.WriteString(match)
		q.scope(platformFilter, teamFilter, labelFrag, labelParams)
		q.sb.WriteString(hostReturn)
		fmt.Fprintf(&q.sb, " LIMIT %d", connectedHostCap)
		rows, err := run(q)
		if err != nil {
			return err
		}
		for _, rec := range rows {
			hostRecordsRaw = append(hostRecordsRaw, hostRecord(rec))
		}
		return nil
	}
	stripAll := func(ids []string, prefix string) []string {
		out := make([]string, len(ids))
		for i, id := range ids {
			out[i] = strings.ReplaceAll(id, prefix, "")
		}
		return out
	}
	if len(softwareIDs) > 0 && (nodeType == "software" || nodeType == "all") {
		if err := connected("\n                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)\n                WHERE s.name IN $software_names\n            ",
			"software_names", stripAll(softwareIDs, "software_")); err != nil {
			return err
		}
	}
	if len(userIDs) > 0 && (nodeType == "user" || nodeType == "all") {
		if err := connected("\n                MATCH (u:User)-[:USES]->(h:Host)\n                WHERE u.username IN $usernames\n            ",
			"usernames", stripAll(userIDs, "user_")); err != nil {
			return err
		}
	}

	// Materialize host nodes: dedupe by fleet_host_id, disambiguate the
	// display name when hostnames collide (many Macs are "mac.lan").
	seenFids := map[string]struct{}{}
	var uniqueHosts []map[string]any
	for _, hr := range hostRecordsRaw {
		fid := hr["fleet_host_id"]
		if fid == nil {
			continue
		}
		k := hostfilter.PyStr(fid)
		if _, dup := seenFids[k]; dup {
			continue
		}
		seenFids[k] = struct{}{}
		uniqueHosts = append(uniqueHosts, hr)
	}
	counts := hostfilter.HostnameCounts(uniqueHosts)
	var hostFids []int64
	for _, hr := range uniqueHosts {
		fid := hr["fleet_host_id"]
		id := "host_" + hostfilter.PyStr(fid)
		teamInfo := ""
		if truthy(hr["team_name"]) {
			teamInfo = " - Team: " + hostfilter.PyStr(hr["team_name"])
		}
		node := map[string]any{
			"id":            id,
			"name":          hr["hostname"],
			"display_name":  hostfilter.DisambiguatedDisplayName(hr["hostname"], fid, counts),
			"fleet_host_id": fid,
			"type":          "host",
			"details": fmt.Sprintf("%s (%s)%s", hostfilter.PyStr(or(hr["os_version"], "")),
				hostfilter.PyStr(or(hr["platform"], "")), teamInfo),
		}
		// Clusters and team colouring read these.
		if hr["team_id"] != nil {
			node["team_id"] = hr["team_id"]
		}
		if truthy(hr["team_name"]) {
			node["team_name"] = hr["team_name"]
		}
		nodes = append(nodes, node)
		nodeIDs[id] = struct{}{}
		// python re-parsed int(nid[5:]) and skipped non-integers.
		if n, err := strconv.ParseInt(id[len("host_"):], 10, 64); err == nil {
			hostFids = append(hostFids, n)
		}
	}

	// Links between loaded nodes. Both id lists are ANDed: edges are only
	// kept when both ends are loaded. Host side uses fleet_host_id, since
	// hostname is not unique.
	links := []map[string]any{}
	edges := func(match, listParam string, names []string, retClause, srcKey, srcPrefix, linkType string) error {
		if len(names) == 0 || len(hostFids) == 0 {
			return nil
		}
		q := &searchQuery{params: map[string]any{listParam: names, "host_fid_list": hostFids}}
		q.sb.WriteString(match)
		// python appended team before platform here (reverse of the loads).
		if teamFilter != "all" {
			q.sb.WriteString(" AND toString(h.team_id) = $team_id")
			q.params["team_id"] = teamFilter
		}
		q.scope(platformFilter, "all", labelFrag, labelParams)
		q.sb.WriteString(retClause)
		rows, err := run(q)
		if err != nil {
			return err
		}
		for _, rec := range rows {
			src := srcPrefix + hostfilter.PyStr(rec[srcKey])
			tgt := "host_" + hostfilter.PyStr(rec["fleet_host_id"])
			_, okS := nodeIDs[src]
			_, okT := nodeIDs[tgt]
			if okS && okT {
				links = append(links, map[string]any{"source": src, "target": tgt, "type": linkType})
			}
		}
		return nil
	}
	if err := edges("\n                    MATCH (u:User)-[:USES]->(h:Host)\n                 WHERE u.username IN $user_list AND h.fleet_host_id IN $host_fid_list",
		"user_list", stripAll(userIDs, "user_"),
		" RETURN DISTINCT u.username AS username, h.fleet_host_id AS fleet_host_id",
		"username", "user_", "uses"); err != nil {
		return err
	}
	if err := edges("\n                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)\n                 WHERE s.name IN $software_list AND h.fleet_host_id IN $host_fid_list",
		"software_list", stripAll(softwareIDs, "software_"),
		" RETURN DISTINCT s.name AS software_name, h.fleet_host_id AS fleet_host_id",
		"software_name", "software_", "installed"); err != nil {
		return err
	}

	desc := "ALL"
	if searchTerm != "" {
		desc = "'" + searchTerm + "'"
	}
	log.Info(fmt.Sprintf("Search %s (type: %s, platform: %s): Returning %d nodes and %d links",
		desc, nodeType, platformFilter, len(nodes), len(links)))

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"nodes":           nodes,
		"links":           links,
		"search_term":     searchTerm,
		"node_type":       nodeType,
		"platform_filter": platformFilter,
		"node_count":      len(nodes),
		"link_count":      len(links),
	})
	return nil
}

// searchSoftware is the legacy endpoint: 308 to /api/search scoped to
// software, first value of each arg kept (request.args.to_dict()).
func searchSoftware(w http.ResponseWriter, r *http.Request) {
	args := url.Values{}
	for k, v := range r.URL.Query() {
		args.Set(k, v[0])
	}
	args.Set("type", "software")
	http.Redirect(w, r, "/api/search?"+args.Encode(), http.StatusPermanentRedirect)
}
