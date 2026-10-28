package graphapi

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j/dbtype"

	"github.com/karmine05/fleet-hound/internal/graphdb"
	"github.com/karmine05/fleet-hound/internal/httpx"
	"github.com/karmine05/fleet-hound/internal/snapshot"
)

// CorrelateNodeCap is CORRELATE_NODE_CAP: max nodes in a /api/correlate ego network.
const CorrelateNodeCap = 500

var (
	kindLabel = map[string]string{"host": "Host", "user": "User", "software": "Software"}
	// Host nodes key on fleet_host_id (stable, unique) to match /api/graph/full ids.
	kindKey = map[string]string{"host": "fleet_host_id", "user": "username", "software": "name"}
)

// resolveTypedID is _resolve_typed_id: ^(host|user|software)_(.+)$ with
// python `.` semantics (the name may not contain a newline).
func resolveTypedID(typedID string) (kind, name string, ok bool) {
	if typedID == "" || utf8.RuneCountInString(typedID) > 400 {
		return "", "", false
	}
	kind, name, found := strings.Cut(typedID, "_")
	if !found || kindLabel[kind] == "" || name == "" || strings.Contains(name, "\n") {
		return "", "", false
	}
	return kind, name, true
}

// coerceTypedIDName is _coerce_typed_id_name: host ids are ints.
func coerceTypedIDName(kind, name string) (any, bool) {
	if kind != "host" {
		return name, true
	}
	v, err := strconv.ParseInt(strings.TrimSpace(name), 10, 64)
	if err != nil {
		return nil, false
	}
	return v, true
}

func asNode(v any) (dbtype.Node, bool) {
	switch t := v.(type) {
	case dbtype.Node:
		return t, true
	case *dbtype.Node:
		if t != nil {
			return *t, true
		}
	}
	return dbtype.Node{}, false
}

// serializeGraphNode is _serialize_graph_node: a driver Node -> the
// /api/graph/full node shape, or nil.
func serializeGraphNode(v any) map[string]any {
	n, ok := asNode(v)
	if !ok {
		return nil
	}
	props, _ := graphdb.Value(n).(map[string]any)
	switch {
	case slices.Contains(n.Labels, "Host"):
		fid := props["fleet_host_id"]
		if fid == nil {
			return nil
		}
		node := map[string]any{
			"id":            "host_" + pyFmt(fid),
			"name":          props["hostname"],
			"display_name":  props["hostname"],
			"fleet_host_id": fid,
			"type":          "host",
			"details":       hostDetails(props),
		}
		return withTeam(node, props)
	case slices.Contains(n.Labels, "User"):
		if !truthy(props["username"]) {
			return nil
		}
		return userNode(props)
	case slices.Contains(n.Labels, "Software"):
		name := props["name"]
		if !truthy(name) {
			return nil
		}
		node := map[string]any{
			"id":      "software_" + pyFmt(name),
			"name":    name,
			"type":    "software",
			"details": "Latest: " + orStr(props["last_version"], "unknown"),
		}
		if truthy(props["category"]) {
			node["category"] = props["category"]
		}
		if truthy(props["wikidata_description"]) {
			node["description"] = props["wikidata_description"]
		}
		return node
	}
	return nil
}

func linkTypeForRel(t string) string {
	switch t {
	case "USES":
		return "uses"
	case "INSTALLED_ON":
		return "installed"
	}
	return strings.ToLower(t)
}

// path replaces get_path (/api/path).
func (h *handlers) path(w http.ResponseWriter, r *http.Request) {
	if !h.dbReady(w, r) {
		return
	}
	q := r.URL.Query()
	fromID, toID := strings.TrimSpace(q.Get("from")), strings.TrimSpace(q.Get("to"))
	maxHops := httpx.ArgInt(r, "max_hops", 4)
	if maxHops < 1 || maxHops > 6 {
		httpx.Error(w, http.StatusBadRequest, "max_hops must be between 1 and 6")
		return
	}
	aKind, aRaw, okA := resolveTypedID(fromID)
	bKind, bRaw, okB := resolveTypedID(toID)
	if !okA || !okB {
		httpx.Error(w, http.StatusBadRequest, "Invalid typed id; expected <type>_<name>")
		return
	}
	aName, okA := coerceTypedIDName(aKind, aRaw)
	bName, okB := coerceTypedIDName(bKind, bRaw)
	if !okA || !okB {
		httpx.Error(w, http.StatusBadRequest, "Invalid typed id; host ids must be host_<fleet_host_id>")
		return
	}
	ctx, db := r.Context(), h.d.DB
	aLabel, aKey := kindLabel[aKind], kindKey[aKind]

	if fromID == toID {
		recs, err := db.Run(ctx, fmt.Sprintf("MATCH (n:%s {%s: $name}) RETURN n LIMIT 1", aLabel, aKey),
			map[string]any{"name": aName})
		if err != nil {
			h.log().Error("path identity lookup failed", "err", err)
			httpx.InternalError(w)
			return
		}
		if len(recs) == 0 {
			httpx.Error(w, http.StatusNotFound, "Node not found")
			return
		}
		n, _ := recs[0].Get("n")
		obj := serializeGraphNode(n)
		if obj == nil {
			httpx.Error(w, http.StatusNotFound, "Node not found")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"nodes": []any{obj}, "links": []any{}, "ordered_ids": []any{obj["id"]},
		})
		return
	}

	bLabel, bKey := kindLabel[bKind], kindKey[bKind]
	head := fmt.Sprintf("MATCH (a:%s {%s: $aname}), (b:%s {%s: $bname}) ", aLabel, aKey, bLabel, bKey)
	cypherBFS := head + fmt.Sprintf("MATCH p = (a)-[:USES|INSTALLED_ON *BFS 1..%d]-(b) ", maxHops) +
		"RETURN nodes(p) AS ns, relationships(p) AS rs LIMIT 1"
	cypherVarlen := head + fmt.Sprintf("MATCH p = (a)-[:USES|INSTALLED_ON *1..%d]-(b) ", maxHops) +
		"RETURN nodes(p) AS ns, relationships(p) AS rs " +
		"ORDER BY length(p) ASC LIMIT 1"
	params := map[string]any{"aname": aName, "bname": bName}

	strategy := "bfs"
	recs, err := db.Run(ctx, cypherBFS, params)
	switch {
	case err == nil:
	case graphdb.IsTransient(err):
		h.log().Warn("path BFS transient", "err", err)
		httpx.Error(w, http.StatusServiceUnavailable, "Database transient error")
		return
	case graphdb.IsClientError(err):
		h.log().Info("path BFS syntax not supported, falling back to variable-length", "err", err)
		strategy = "varlen"
		recs, err = db.Run(ctx, cypherVarlen, params)
		if err != nil {
			if graphdb.IsTransient(err) || graphdb.IsClientError(err) {
				h.log().Warn("path varlen failed", "err", err)
				httpx.Error(w, http.StatusServiceUnavailable, "Database transient error")
				return
			}
			h.log().Error("path varlen unexpected error", "err", err)
			httpx.Error(w, http.StatusInternalServerError, "Path query failed")
			return
		}
	default:
		h.log().Error("path query unexpected error", "err", err)
		httpx.InternalError(w)
		return
	}

	if len(recs) == 0 {
		h.log().Info("path: no path", "from", fromID, "to", toID, "max_hops", maxHops, "strategy", strategy)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"nodes": []any{}, "links": []any{}, "ordered_ids": []any{}})
		return
	}
	h.log().Info("path found", "from", fromID, "to", toID, "strategy", strategy)

	nsRaw, _ := recs[0].Get("ns")
	rsRaw, _ := recs[0].Get("rs")
	ns, _ := nsRaw.([]any)
	rs, _ := rsRaw.([]any)

	nodes := []any{}
	ordered := []string{}
	seen := map[string]struct{}{}
	for _, n := range ns {
		obj := serializeGraphNode(n)
		if obj == nil {
			continue
		}
		id := obj["id"].(string)
		ordered = append(ordered, id)
		if _, dup := seen[id]; !dup {
			nodes = append(nodes, obj)
			seen[id] = struct{}{}
		}
	}
	links := []any{}
	for i, rv := range rs {
		if i >= len(ordered)-1 {
			break
		}
		typ := "USES"
		if rel, ok := rv.(dbtype.Relationship); ok {
			typ = rel.Type
		}
		links = append(links, map[string]any{
			"source": ordered[i], "target": ordered[i+1], "type": linkTypeForRel(typ),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "links": links, "ordered_ids": ordered})
}

type corrRec struct {
	n, m any
	r    *dbtype.Relationship
}

// correlate replaces get_correlate (/api/correlate).
func (h *handlers) correlate(w http.ResponseWriter, r *http.Request) {
	if !h.dbReady(w, r) {
		return
	}
	typedID := strings.TrimSpace(r.URL.Query().Get("id"))
	depth := httpx.ArgInt(r, "depth", 2)
	if depth < 1 || depth > 3 {
		httpx.Error(w, http.StatusBadRequest, "depth must be between 1 and 3")
		return
	}
	kind, raw, ok := resolveTypedID(typedID)
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "Invalid typed id; expected <type>_<name>")
		return
	}
	name, ok := coerceTypedIDName(kind, raw)
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "Invalid typed id; host ids must be host_<fleet_host_id>")
		return
	}

	recs, truncated, found, err := h.correlateExpand(r, kind, name, depth)
	if err != nil {
		if graphdb.IsTransient(err) {
			h.log().Warn("correlate transient", "err", err)
			httpx.Error(w, http.StatusServiceUnavailable, "Database transient error")
			return
		}
		h.log().Error("correlate failed", "err", err)
		httpx.Error(w, http.StatusInternalServerError, "Correlate query failed")
		return
	}
	if !found {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"nodes": []any{}, "links": []any{}, "truncated": false})
		return
	}

	var order []string
	nodesByID := map[string]map[string]any{}
	put := func(obj map[string]any) {
		id := obj["id"].(string)
		if _, ok := nodesByID[id]; !ok {
			order = append(order, id)
		}
		nodesByID[id] = obj
	}
	byElement := map[string]map[string]any{}
	linkKeys := map[string]struct{}{}
	links := []any{}
	for _, rec := range recs {
		for _, gn := range []any{rec.n, rec.m} {
			if obj := serializeGraphNode(gn); obj != nil {
				put(obj)
				n, _ := asNode(gn)
				byElement[n.ElementId] = obj
			}
		}
		if rec.r == nil {
			continue
		}
		rel := rec.r
		// a and b are returned with r, so endpoints resolve through byElement;
		// a hollow endpoint (python serialized to None) is skipped.
		start, end := byElement[rel.StartElementId], byElement[rel.EndElementId]
		if start == nil || end == nil {
			continue
		}
		put(start)
		put(end)
		src, tgt := start, end
		switch rel.Type {
		case "USES":
			if start["type"] != "user" {
				src, tgt = end, start
			}
		case "INSTALLED_ON":
			if start["type"] != "software" {
				src, tgt = end, start
			}
		}
		key := rel.Type + "::" + src["id"].(string) + "::" + tgt["id"].(string)
		if _, dup := linkKeys[key]; dup {
			continue
		}
		linkKeys[key] = struct{}{}
		links = append(links, map[string]any{"source": src["id"], "target": tgt["id"], "type": linkTypeForRel(rel.Type)})
	}
	nodes := make([]any, 0, len(order))
	for _, id := range order {
		nodes = append(nodes, nodesByID[id])
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "links": links, "truncated": truncated})
}

// correlateExpand is the bounded hop-by-hop expansion of get_correlate: one
// LIMITed query per hop, the ego network capped at CorrelateNodeCap nodes.
func (h *handlers) correlateExpand(r *http.Request, kind string, name any, depth int) (recs []corrRec, truncated, found bool, err error) {
	ctx, db := r.Context(), h.d.DB
	seedRecs, err := db.Run(ctx, fmt.Sprintf("MATCH (n:%s {%s: $name}) RETURN n, id(n) AS nid LIMIT 1", kindLabel[kind], kindKey[kind]),
		map[string]any{"name": name})
	if err != nil || len(seedRecs) == 0 {
		return nil, false, false, err
	}
	seedN, _ := seedRecs[0].Get("n")
	seedID, _ := seedRecs[0].Get("nid")
	recs = append(recs, corrRec{n: seedN})
	seen := map[any]struct{}{seedID: {}}
	seenList := []any{seedID}
	frontier := []any{seedID}
	for range depth {
		budget := CorrelateNodeCap - len(seen)
		if budget <= 0 || len(frontier) == 0 {
			truncated = truncated || len(frontier) > 0
			break
		}
		rows, err := db.Run(ctx, "MATCH (a)-[r:USES|INSTALLED_ON]-(b) "+
			"WHERE id(a) IN $frontier AND NOT id(b) IN $seen "+
			"RETURN a, r, b, id(b) AS bid LIMIT $limit",
			map[string]any{"frontier": frontier, "seen": seenList, "limit": int64(budget + 1)})
		if err != nil {
			return nil, false, true, err
		}
		if len(rows) > budget {
			truncated = true
			rows = rows[:budget]
		}
		frontier = nil
		for _, row := range rows {
			a, _ := row.Get("a")
			b, _ := row.Get("b")
			rv, _ := row.Get("r")
			var rel *dbtype.Relationship
			switch rr := rv.(type) {
			case dbtype.Relationship:
				rel = &rr
			case *dbtype.Relationship:
				rel = rr
			}
			recs = append(recs, corrRec{n: a, m: b, r: rel})
			bid, _ := row.Get("bid")
			if _, dup := seen[bid]; !dup {
				seen[bid] = struct{}{}
				seenList = append(seenList, bid)
				frontier = append(frontier, bid)
			}
		}
	}
	return recs, truncated, true, nil
}

// snapshots replaces list_snapshots_route (/api/snapshots).
func (h *handlers) snapshots(w http.ResponseWriter, r *http.Request) error {
	items, err := snapshot.ListSnapshots(h.d.Cfg.SnapshotDir)
	if err != nil {
		return fmt.Errorf("list snapshots: %w", err)
	}
	if limitRaw := strings.TrimSpace(r.URL.Query().Get("limit")); limitRaw != "" {
		limit, err := pyInt(limitRaw)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "limit must be an integer")
			return nil
		}
		if limit < 1 {
			httpx.Error(w, http.StatusBadRequest, "limit must be positive")
			return nil
		}
		items = items[:min(limit, 500, len(items))]
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		out = append(out, map[string]any{
			"ts": it["ts"], "slug": it["slug"], "hosts": it["hosts"],
			"users": it["users"], "software": it["software"], "edges": it["edges"],
		})
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}

// sanitizeSnapshotToken is re.sub(r"[^A-Za-z0-9._\-]", "", token)[:100].
func sanitizeSnapshotToken(token string) string {
	var b strings.Builder
	for i := 0; i < len(token) && b.Len() < 100; i++ {
		c := token[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// resolveSnapshotPath is _resolve_snapshot_path: ts or slug -> on-disk path.
func (h *handlers) resolveSnapshotPath(token string) string {
	safe := sanitizeSnapshotToken(token)
	if safe == "" {
		return ""
	}
	dir := h.d.Cfg.SnapshotDir
	if c := filepath.Join(dir, safe+".jsonl.gz"); isFile(c) {
		return c
	}
	items, err := snapshot.ListSnapshots(dir)
	if err != nil {
		return ""
	}
	for _, it := range items {
		if it["ts"] == token || it["slug"] == token {
			if p, _ := it["path"].(string); p != "" && isFile(p) {
				return p
			}
		}
	}
	return ""
}

// diff replaces get_diff (/api/diff).
func (h *handlers) diff(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	a, b := strings.TrimSpace(q.Get("from")), strings.TrimSpace(q.Get("to"))
	if a == "" || b == "" {
		httpx.Error(w, http.StatusBadRequest, "from and to are required")
		return
	}
	aPath, bPath := h.resolveSnapshotPath(a), h.resolveSnapshotPath(b)
	if aPath == "" || bPath == "" {
		httpx.Error(w, http.StatusNotFound, "snapshot not found")
		return
	}
	res, err := snapshot.DiffSnapshots(aPath, bPath)
	if err != nil {
		h.log().Error("diff failed", "err", err)
		httpx.ErrorMsg(w, http.StatusInternalServerError, "Diff failed", httpx.DebugMsg(h.d.Debug(), err))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}
