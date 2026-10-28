// Package snapshot ports src/snapshot.py: gzip JSONL graph snapshots, the
// .meta.json sidecar, retention pruning, listing and diffing. Owner: agent A.
//
// On-disk format must stay compatible with python so existing snapshots
// under config/snapshots keep listing and diffing. Node lines and node hashes
// are byte-identical to python (internal/pyjson); the gzip container bytes
// differ (different deflate implementation), which no reader depends on.
package snapshot

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/karmine05/fleet-hound/internal/graphdb"
	"github.com/karmine05/fleet-hound/internal/pyjson"
)

// noisyProps is _NOISY_PROPS: excluded from the node hash and the property
// drift diff because they churn every cycle.
var noisyProps = map[string]struct{}{
	"last_seen": {}, "last_categorized": {}, "last_synced_iso": {},
	"last_label_sync_status": {}, "consecutive_failures": {},
	"last_label_sync_error": {}, "host_count": {}, "last_member_hash": {},
	"last_members_compressed": {},
}

// nodeHash is _node_hash: sha256 of json.dumps(filtered, sort_keys=True,
// separators=(",",":"), default=str).
func nodeHash(props pyjson.Ordered) string {
	filtered := make(map[string]any, len(props))
	for _, kv := range props {
		if _, noisy := noisyProps[kv.K]; !noisy {
			filtered[kv.K] = kv.V
		}
	}
	sum := sha256.Sum256(pyjson.Marshal(filtered))
	return hex.EncodeToString(sum[:])
}

func typedID(kind string, name any) string { return kind + "_" + pyjson.Str(name) }

// nodeQuery is one node section of _iter_graph.
type nodeQuery struct {
	kind, idKey string
	keys        []string
	cypher      string
	needTruthy  bool // `if not x: continue` (vs `is None`)
	count       string
}

var nodeQueries = []nodeQuery{
	{kind: "host", idKey: "fleet_host_id", count: "hosts",
		keys: []string{"hostname", "os_version", "platform", "ip", "last_seen", "team_id", "team_name"},
		cypher: `
                MATCH (h:Host)
                RETURN h.fleet_host_id AS fleet_host_id, h.hostname AS hostname,
                       h.os_version AS os_version,
                       h.platform AS platform, h.ip AS ip,
                       h.last_seen AS last_seen, h.team_id AS team_id,
                       h.team_name AS team_name
            `},
	{kind: "user", idKey: "username", count: "users", needTruthy: true,
		keys: []string{"username", "email", "fullname"},
		cypher: `
                MATCH (u:User)
                RETURN u.username AS username, u.email AS email, u.fullname AS fullname
            `},
	{kind: "software", idKey: "name", count: "software", needTruthy: true,
		keys: []string{"name", "display_name", "last_version", "versions", "category",
			"wikidata_description", "last_categorized", "sources", "extension_key", "kind"},
		cypher: `
                MATCH (s:Software)
                RETURN s.name AS name, s.display_name AS display_name,
                       s.last_version AS last_version,
                       s.versions AS versions,
                       s.category AS category,
                       s.wikidata_description AS wikidata_description,
                       s.last_categorized AS last_categorized,
                       s.sources AS sources,
                       s.extension_key AS extension_key,
                       s.kind AS kind
            `},
	{kind: "label", idKey: "fleet_id", count: "labels",
		keys: []string{"fleet_id", "name", "description", "label_type", "membership_type", "query"},
		cypher: `
                MATCH (l:Label)
                RETURN l.fleet_id AS fleet_id, l.name AS name,
                       l.description AS description,
                       l.label_type AS label_type,
                       l.membership_type AS membership_type,
                       l.query AS query
            `},
}

// edgeQuery is one edge section of _iter_graph: from/to record keys and
// whether each side needs truthiness (`not x`) or only non-None.
type edgeQuery struct {
	label, fromKind, fromKey, toKind, toKey string
	fromTruthy                              bool
	cypher                                  string
}

var edgeQueries = []edgeQuery{
	{label: "HAS_LABEL", fromKind: "host", fromKey: "hfid", toKind: "label", toKey: "lfid", cypher: `
                MATCH (h:Host)-[:HAS_LABEL]->(l:Label)
                RETURN h.fleet_host_id AS hfid, l.fleet_id AS lfid
            `},
	{label: "USES", fromKind: "user", fromKey: "uname", toKind: "host", toKey: "hfid", fromTruthy: true, cypher: `
                MATCH (u:User)-[:USES]->(h:Host)
                RETURN u.username AS uname, h.fleet_host_id AS hfid
            `},
	{label: "INSTALLED_ON", fromKind: "software", fromKey: "sname", toKind: "host", toKey: "hfid", fromTruthy: true, cypher: `
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                RETURN s.name AS sname, h.fleet_host_id AS hfid
            `},
}

// recData is Record.data() for snapshot lines: temporal values keep python's
// default=str form (neo4j DateTime.isoformat: 9 fractional digits, +HH:MM)
// instead of graphdb.Value's RFC3339, so lines match python byte for byte.
func recData(r *neo4j.Record) map[string]any {
	out := make(map[string]any, len(r.Keys))
	for i, k := range r.Keys {
		if t, ok := r.Values[i].(time.Time); ok {
			out[k] = t.Format("2006-01-02T15:04:05.000000000-07:00")
			continue
		}
		out[k] = graphdb.Value(r.Values[i])
	}
	return out
}

// writeGraph is _iter_graph + the gzip loop: streams every line into w and
// returns the counts.
func writeGraph(ctx context.Context, db *graphdb.DB, w io.Writer) (map[string]int, error) {
	counts := map[string]int{"hosts": 0, "users": 0, "software": 0, "labels": 0, "edges": 0}
	line := func(entry pyjson.Ordered) error {
		b := pyjson.Marshal(entry)
		b = append(b, '\n')
		_, err := w.Write(b)
		return err
	}
	for _, q := range nodeQueries {
		err := db.Stream(ctx, q.cypher, nil, func(r *neo4j.Record) error {
			rec := recData(r)
			id := rec[q.idKey]
			if (q.needTruthy && !pyjson.Truthy(id)) || id == nil {
				return nil
			}
			props := make(pyjson.Ordered, 0, len(q.keys))
			for _, k := range q.keys {
				if v := rec[k]; v != nil {
					props = append(props, pyjson.KV{K: k, V: v})
				}
			}
			counts[q.count]++
			return line(pyjson.Ordered{
				{K: "type", V: q.kind}, {K: "id", V: typedID(q.kind, id)},
				{K: "props", V: props}, {K: "hash", V: nodeHash(props)},
			})
		})
		if err != nil {
			return nil, fmt.Errorf("snapshot %s query: %w", q.kind, err)
		}
	}
	for _, q := range edgeQueries {
		err := db.Stream(ctx, q.cypher, nil, func(r *neo4j.Record) error {
			rec := recData(r)
			from, to := rec[q.fromKey], rec[q.toKey]
			if from == nil || to == nil || (q.fromTruthy && !pyjson.Truthy(from)) {
				return nil
			}
			counts["edges"]++
			return line(pyjson.Ordered{
				{K: "type", V: "edge"}, {K: "label", V: q.label},
				{K: "from", V: typedID(q.fromKind, from)}, {K: "to", V: typedID(q.toKind, to)},
			})
		})
		if err != nil {
			return nil, fmt.Errorf("snapshot %s query: %w", q.label, err)
		}
	}
	return counts, nil
}

// atomicWrite is the mkstemp + fsync + chmod 600 + os.replace pattern; fill
// writes the content. The temp file is removed on any failure.
func atomicWrite(path string, fill func(io.Writer) error) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", path, err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err = fill(f); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("fsync %s: %w", tmp, err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// SafeTS is _safe_ts: a filename-safe slug that keeps lexicographic order.
func SafeTS(ts string) string {
	return strings.NewReplacer(":", "", ".", "-", "+", "p").Replace(ts)
}

// metaJSON is json.dumps({"ts": ts, **counts}, indent=2).
func metaJSON(ts string, counts map[string]int) []byte {
	var b strings.Builder
	b.WriteString("{\n  \"ts\": ")
	pyjson.Quote(&b, ts)
	for _, k := range []string{"hosts", "users", "software", "labels", "edges"} {
		fmt.Fprintf(&b, ",\n  %q: %d", k, counts[k])
	}
	b.WriteString("\n}")
	return []byte(b.String())
}

// WriteSnapshot replaces write_snapshot(memgraph_uri, ts, out_dir, auth=,
// retain=, retain_days=): streams the full graph from db into
// <outDir>/<safe ts>.jsonl.gz plus the .meta.json sidecar (atomic writes),
// prunes old snapshots, and returns the .jsonl.gz path. Python opened its
// own driver from the URI; Go takes the DB handle.
func WriteSnapshot(ctx context.Context, db *graphdb.DB, ts string, outDir string, retain, retainDays int) (string, error) {
	slug := SafeTS(ts)
	snapPath := filepath.Join(outDir, slug+".jsonl.gz")
	metaPath := filepath.Join(outDir, slug+".meta.json")

	var counts map[string]int
	err := atomicWrite(snapPath, func(w io.Writer) error {
		gz, err := gzip.NewWriterLevel(w, 6)
		if err != nil {
			return err
		}
		bw := bufio.NewWriterSize(gz, 64<<10)
		if counts, err = writeGraph(ctx, db, bw); err != nil {
			return err
		}
		if err := bw.Flush(); err != nil {
			return fmt.Errorf("write snapshot: %w", err)
		}
		return gz.Close()
	})
	if err != nil {
		return "", err
	}
	meta := metaJSON(ts, counts)
	if err := atomicWrite(metaPath, func(w io.Writer) error {
		_, err := w.Write(meta)
		return err
	}); err != nil {
		return "", err
	}

	pruneOld(outDir, retain, retainDays)

	slog.Info(fmt.Sprintf("snapshot written: %s (%d hosts, %d users, %d software, %d labels, %d edges)",
		snapPath, counts["hosts"], counts["users"], counts["software"], counts["labels"], counts["edges"]))
	return snapPath, nil
}

// dropSnapshot unlinks a .jsonl.gz and its .meta.json sibling.
func dropSnapshot(outDir, gzPath string) {
	slug := strings.TrimSuffix(filepath.Base(gzPath), ".jsonl.gz")
	_ = os.Remove(gzPath)
	_ = os.Remove(filepath.Join(outDir, slug+".meta.json"))
}

// globSnapshots is sorted(out_dir.glob("*.jsonl.gz")). Python glob skips
// dotfiles for "*"; filepath.Glob does not, so they are filtered here.
func globSnapshots(outDir string) []string {
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, ".") && strings.HasSuffix(n, ".jsonl.gz") {
			out = append(out, filepath.Join(outDir, n))
		}
	}
	sort.Strings(out)
	return out
}

// pruneOld is _prune_old: age horizon (mtime) first, then the count cap.
func pruneOld(outDir string, retain, retainDays int) {
	gz := globSnapshots(outDir)
	if retainDays > 0 {
		cutoff := time.Now().Add(-time.Duration(retainDays) * 24 * time.Hour)
		survivors := gz[:0]
		for _, p := range gz {
			st, err := os.Stat(p)
			if err != nil { // can't stat: keep rather than risk deleting live data
				survivors = append(survivors, p)
				continue
			}
			if st.ModTime().Before(cutoff) {
				dropSnapshot(outDir, p)
			} else {
				survivors = append(survivors, p)
			}
		}
		gz = survivors
	}
	if retain > 0 && len(gz) > retain {
		for _, old := range gz[:len(gz)-retain] {
			dropSnapshot(outDir, old)
		}
	}
}

// pyInt is python int(x) for meta counts: ints, floats (truncated), numeric
// strings and bools; ok=false where python would raise.
func pyInt(v any) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return 0, false
		}
		return int64(t), true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(strings.ReplaceAll(t, "_", "")), 10, 64)
		return n, err == nil
	}
	return 0, false
}

// ListSnapshots replaces list_snapshots(out_dir): [{ts, slug, path, hosts,
// users, software, labels, edges}] newest first ([] when the dir is missing).
// A meta count python could not int() makes python raise; Go reports 0.
func ListSnapshots(outDir string) ([]map[string]any, error) {
	items := []map[string]any{}
	if st, err := os.Stat(outDir); err != nil || !st.IsDir() {
		return items, nil
	}
	for _, gz := range globSnapshots(outDir) {
		slug := strings.TrimSuffix(filepath.Base(gz), ".jsonl.gz")
		meta := map[string]any{}
		if data, err := os.ReadFile(filepath.Join(outDir, slug+".meta.json")); err == nil { // #nosec G304 -- path built from a glob of SnapshotDir
			if v, err := graphdb.DecodeJSON(data); err == nil {
				if m, ok := v.(map[string]any); ok {
					meta = m
				}
			}
		}
		ts, ok := meta["ts"]
		if !ok {
			ts = slug
		}
		item := map[string]any{"ts": ts, "slug": slug, "path": gz}
		for _, k := range []string{"hosts", "users", "software", "labels", "edges"} {
			n := int64(0)
			if v, ok := meta[k]; ok {
				n, _ = pyInt(v)
			}
			item[k] = n
		}
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool {
		return pyjson.Str(items[i]["ts"]) > pyjson.Str(items[j]["ts"])
	})
	return items, nil
}

// orderedNodes keeps python dict semantics: last write wins, first position.
type orderedNodes struct {
	order []string
	m     map[string]map[string]any
}

func (o *orderedNodes) put(id string, e map[string]any) {
	if _, ok := o.m[id]; !ok {
		o.order = append(o.order, id)
	}
	o.m[id] = e
}

// readSnapshot is _read_snapshot: ({id: node}, [edge]) from a .jsonl.gz.
func readSnapshot(path string) (*orderedNodes, []map[string]any, error) {
	f, err := os.Open(path) // #nosec G304 -- path from ListSnapshots or sanitizeSnapshotToken, confined to SnapshotDir
	if err != nil {
		return nil, nil, fmt.Errorf("open snapshot: %w", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, fmt.Errorf("read snapshot %s: %w", path, err)
	}
	defer gz.Close()
	nodes := &orderedNodes{m: map[string]map[string]any{}}
	var edges []map[string]any
	r := bufio.NewReaderSize(gz, 256<<10)
	for {
		raw, rerr := r.ReadBytes('\n')
		if line := strings.TrimSpace(string(raw)); line != "" {
			if v, err := graphdb.DecodeJSON([]byte(line)); err == nil {
				if entry, ok := v.(map[string]any); ok {
					if entry["type"] == "edge" {
						edges = append(edges, entry)
					} else if id, _ := entry["id"].(string); id != "" {
						nodes.put(id, entry)
					}
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, nil, fmt.Errorf("read snapshot %s: %w", path, rerr)
		}
	}
	return nodes, edges, nil
}

func edgeKey(e map[string]any) string {
	s := func(k string) string {
		if v, ok := e[k]; ok {
			return pyjson.Str(v)
		}
		return ""
	}
	return s("label") + "::" + s("from") + "::" + s("to")
}

// pyEqual is python == over decoded JSON values (1 == 1.0 == True).
func pyEqual(a, b any) bool {
	num := func(v any) (float64, bool) {
		switch t := v.(type) {
		case int64:
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
	if x, ok := num(a); ok {
		if y, ok := num(b); ok {
			if ai, ok := a.(int64); ok {
				if bi, ok := b.(int64); ok {
					return ai == bi
				}
			}
			return x == y
		}
		return false
	}
	switch t := a.(type) {
	case nil:
		return b == nil
	case string:
		u, ok := b.(string)
		return ok && t == u
	case []any:
		u, ok := b.([]any)
		if !ok || len(t) != len(u) {
			return false
		}
		for i := range t {
			if !pyEqual(t[i], u[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		u, ok := b.(map[string]any)
		if !ok || len(t) != len(u) {
			return false
		}
		for k, v := range t {
			w, ok := u[k]
			if !ok || !pyEqual(v, w) {
				return false
			}
		}
		return true
	}
	return false
}

func propsOf(e map[string]any) map[string]any {
	if m, ok := e["props"].(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func bucketOf(e map[string]any) string {
	s, _ := e["type"].(string)
	return s + "s"
}

// DiffSnapshots replaces diff_snapshots(a_path, b_path): the python diff
// dict (a older, b newer).
func DiffSnapshots(aPath, bPath string) (map[string]any, error) {
	aNodes, aEdges, err := readSnapshot(aPath)
	if err != nil {
		return nil, err
	}
	bNodes, bEdges, err := readSnapshot(bPath)
	if err != nil {
		return nil, err
	}
	newBuckets := func() map[string][]any {
		return map[string][]any{"hosts": {}, "users": {}, "software": {}, "edges": {}}
	}
	added, removed := newBuckets(), newBuckets()
	changed := []any{}

	for _, id := range bNodes.order {
		entry := bNodes.m[id]
		old, ok := aNodes.m[id]
		if !ok {
			if _, ok := added[bucketOf(entry)]; ok {
				added[bucketOf(entry)] = append(added[bucketOf(entry)], id)
			}
			continue
		}
		if pyEqual(old["hash"], entry["hash"]) {
			continue
		}
		oldP, newP := propsOf(old), propsOf(entry)
		drift := map[string]any{}
		for _, side := range []map[string]any{oldP, newP} {
			for k := range side {
				if _, noisy := noisyProps[k]; noisy {
					continue
				}
				if _, done := drift[k]; done {
					continue
				}
				if !pyEqual(oldP[k], newP[k]) {
					drift[k] = map[string]any{"old": oldP[k], "new": newP[k]}
				}
			}
		}
		if len(drift) > 0 {
			changed = append(changed, map[string]any{"id": id, "type": entry["type"], "props_changed": drift})
		}
	}
	for _, id := range aNodes.order {
		if _, ok := bNodes.m[id]; !ok {
			entry := aNodes.m[id]
			if _, ok := removed[bucketOf(entry)]; ok {
				removed[bucketOf(entry)] = append(removed[bucketOf(entry)], id)
			}
		}
	}

	index := func(edges []map[string]any) *orderedNodes {
		o := &orderedNodes{m: map[string]map[string]any{}}
		for _, e := range edges {
			o.put(edgeKey(e), e)
		}
		return o
	}
	ae, be := index(aEdges), index(bEdges)
	slim := func(e map[string]any) map[string]any {
		return map[string]any{"label": e["label"], "from": e["from"], "to": e["to"]}
	}
	for _, k := range be.order {
		if _, ok := ae.m[k]; !ok {
			added["edges"] = append(added["edges"], slim(be.m[k]))
		}
	}
	for _, k := range ae.order {
		if _, ok := be.m[k]; !ok {
			removed["edges"] = append(removed["edges"], slim(ae.m[k]))
		}
	}
	toAny := func(m map[string][]any) map[string]any {
		out := make(map[string]any, len(m))
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	return map[string]any{"added": toAny(added), "removed": toAny(removed), "changed": changed}, nil
}
