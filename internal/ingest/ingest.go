// Package ingest ports src/ingestion.py (MemgraphIngestion). Owner: agent A.
//
// Every Cypher statement, batch size, MERGE key and reap rule is the python
// one; label member hashes and blobs are byte-compatible so data written by
// either implementation keeps working with the other.
package ingest

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/karmine05/fleet-hound/internal/config"
	"github.com/karmine05/fleet-hound/internal/extintel"
	"github.com/karmine05/fleet-hound/internal/graphdb"
	"github.com/karmine05/fleet-hound/internal/pyjson"
)

// SoftwareIdentityVersion is SOFTWARE_IDENTITY_VERSION. Bump when the
// Fleet-row -> :Software identity or ingested fields change (3: Safari keyed
// by containing-app bundle ID and signing team; 4: Safari display name
// prefixed with the containing app).
const SoftwareIdentityVersion = 4

// DefaultReapAgeSeconds is the python reap_age_seconds default (7 days).
const DefaultReapAgeSeconds = 604800

const (
	hostBatchSize        = 5000 // HOST_BATCH_SIZE
	userBatchSize        = 5000 // USER_BATCH_SIZE
	softwareGroupFlush   = 200  // hosts-with-bundles per software flush
	softwareNodeChunk    = 5000 // _SOFTWARE_NODE_CHUNK
	softwareRelChunkRows = 5000 // SOFTWARE_REL_CHUNK_ROWS
	// 6 retries x 0.5s base exponential with full jitter (~16s worst case)
	// before a TransientError is declared fatal for that query.
	maxRetries = 6
	retryBase  = 500 * time.Millisecond
)

// LabelSyncStats replaces the LabelSyncStats dataclass.
type LabelSyncStats struct {
	LabelsSeen      int
	LabelsUnchanged int
	LabelsResynced  int
	LabelsReaped    int
	EdgesCreated    int
	EdgesDeleted    int
	OrphanMembers   int
	Errors          []string
}

// AsDict replaces LabelSyncStats.as_dict() (same snake_case keys).
func (s *LabelSyncStats) AsDict() map[string]any {
	errs := s.Errors
	if errs == nil {
		errs = []string{}
	}
	return map[string]any{
		"labels_seen": s.LabelsSeen, "labels_unchanged": s.LabelsUnchanged,
		"labels_resynced": s.LabelsResynced, "labels_reaped": s.LabelsReaped,
		"edges_created": s.EdgesCreated, "edges_deleted": s.EdgesDeleted,
		"orphan_members": s.OrphanMembers, "errors": errs,
	}
}

// canonicalIDs is json.dumps(sorted(ids), separators=(",",":")).
func canonicalIDs(ids []int64) []byte {
	sorted := append([]int64(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	b := make([]byte, 0, 2+len(sorted)*6)
	b = append(b, '[')
	for i, id := range sorted {
		if i > 0 {
			b = append(b, ',')
		}
		b = strconv.AppendInt(b, id, 10)
	}
	return append(b, ']')
}

// ComputeLabelMemberHash replaces compute_label_member_hash: sha256 hex of
// the canonical sorted host-id list (byte-identical to python so stored
// hashes keep matching). Hashes Fleet's stable numeric host id, not the
// mutable hostname.
func ComputeLabelMemberHash(fleetHostIDs []int64) string {
	sum := sha256.Sum256(canonicalIDs(fleetHostIDs))
	return hex.EncodeToString(sum[:])
}

// EncodeLabelMemberBlob replaces encode_label_member_blob: gzip (level 6) of
// the canonical JSON list, base64. Stored on Label.last_members_compressed.
func EncodeLabelMemberBlob(fleetHostIDs []int64) string {
	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, 6) // level 6 is valid: no error
	_, _ = gz.Write(canonicalIDs(fleetHostIDs))
	_ = gz.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// b64Alphabet filters like python b64decode(validate=False), which discards
// characters outside the alphabet before decoding.
func b64Clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '+', r == '/', r == '=':
			return r
		}
		return -1
	}, s)
}

// DecodeLabelMemberBlob replaces decode_label_member_blob: the id set, or
// ok=false for python None (missing/corrupt blob), so callers fall back to
// the full-rewrite path.
func DecodeLabelMemberBlob(blob any) (ids map[int64]struct{}, ok bool) {
	var s string
	switch t := blob.(type) {
	case string:
		s = t
	case []byte:
		s = string(t)
	default:
		return nil, false
	}
	if s == "" {
		return nil, false
	}
	gzBytes, err := base64.StdEncoding.DecodeString(b64Clean(s))
	if err != nil {
		return nil, false
	}
	zr, err := gzip.NewReader(bytes.NewReader(gzBytes))
	if err != nil {
		return nil, false
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, false
	}
	v, err := graphdb.DecodeJSON(raw)
	if err != nil {
		return nil, false
	}
	list, isList := v.([]any)
	if !isList {
		return nil, false
	}
	out := make(map[int64]struct{}, len(list))
	for _, x := range list {
		if x == nil {
			continue
		}
		n, ok := pyInt(x)
		if !ok {
			return nil, false
		}
		out[n] = struct{}{}
	}
	return out, true
}

// pyInt is python int(x) for JSON scalars.
func pyInt(v any) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case float64:
		return int64(t), true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		return n, err == nil
	}
	return 0, false
}

// Ingestion replaces class MemgraphIngestion. Python built its own driver
// from (uri, auth); Go receives a *graphdb.DB (the caller builds it with
// graphdb.New(uri, config.MemgraphAuth())).
type Ingestion struct {
	DB *graphdb.DB
	// FailedSoftwareHostIDs replaces failed_software_host_ids: fleet host ids
	// whose software rows failed to reach Memgraph this run. The ETL layer
	// must not advance the .state.json watermark when it is non-empty.
	FailedSoftwareHostIDs []int64
}

// New replaces MemgraphIngestion(uri, auth).
func New(db *graphdb.DB) *Ingestion { return &Ingestion{DB: db} }

// Close replaces close()/__exit__: closes the DB handle.
func (in *Ingestion) Close(ctx context.Context) { in.DB.Close(ctx) }

// swParallelism is _SOFTWARE_REL_PARALLELISM (env INGEST_SW_PARALLELISM,
// default 4, min 1); 1 forces serial chunk execution.
func swParallelism() int { return max(1, config.Int("INGEST_SW_PARALLELISM", 4)) }

func (in *Ingestion) markFailed(ids ...any) {
	for _, id := range ids {
		if n, ok := pyInt(id); ok {
			in.FailedSoftwareHostIDs = append(in.FailedSoftwareHostIDs, n)
		}
	}
}

// ---------------------------------------------------------------------------
// session helpers (python session.run / .single() / .data() / .consume())

type sess struct{ s neo4j.SessionWithContext }

func (in *Ingestion) open(ctx context.Context) (*sess, error) {
	s, err := in.DB.Session(ctx, neo4j.SessionConfig{})
	if err != nil {
		return nil, fmt.Errorf("open memgraph session: %w", err)
	}
	return &sess{s: s}, nil
}

func (s *sess) close(ctx context.Context) { _ = s.s.Close(ctx) }

func (s *sess) rows(ctx context.Context, q string, p map[string]any) ([]map[string]any, error) {
	res, err := s.s.Run(ctx, q, p)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for res.Next(ctx) {
		out = append(out, graphdb.Data(res.Record()))
	}
	return out, res.Err()
}

// single returns the first record's data, nil when there is none.
func (s *sess) single(ctx context.Context, q string, p map[string]any) (map[string]any, error) {
	rows, err := s.rows(ctx, q, p)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

func (s *sess) exec(ctx context.Context, q string, p map[string]any) error {
	res, err := s.s.Run(ctx, q, p)
	if err != nil {
		return err
	}
	_, err = res.Consume(ctx)
	return err
}

// execRetry replaces _execute_with_retry. Consumes the result so the
// auto-commit transaction closes before returning (parallel chunk sessions
// must see these writes).
//   - TransientError: retry with full-jitter exponential backoff; after the
//     budget, warn and return false.
//   - ServiceUnavailable / AuthError (or ctx cancellation): returned as an
//     error so the ETL cycle aborts without advancing the watermark.
//   - anything else: warn and return false.
func execRetry(ctx context.Context, s *sess, q string, p map[string]any, op string) (bool, error) {
	err := graphdb.Retry(ctx, maxRetries, retryBase, true, graphdb.IsTransient,
		func(ctx context.Context) error { return s.exec(ctx, q, p) })
	switch {
	case err == nil:
		return true, nil
	case ctx.Err() != nil:
		return false, fmt.Errorf("%s: %w", op, ctx.Err())
	case graphdb.IsServiceUnavailable(err) || graphdb.IsAuthError(err):
		return false, fmt.Errorf("%s: %w", op, err)
	case graphdb.IsTransient(err):
		slog.Warn(fmt.Sprintf("failed to %s after %d attempts", op, maxRetries))
	default:
		slog.Warn(fmt.Sprintf("failed to %s: %v", op, err))
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// constraints + one-shot migrations

// CreateConstraints replaces create_constraints(): unique constraints,
// indexes and the self-quiescing migrations. Individual statement failures
// are ignored like python; only failing to open a session is returned.
func (in *Ingestion) CreateConstraints(ctx context.Context) error {
	s, err := in.open(ctx)
	if err != nil {
		return err
	}
	defer s.close(ctx)

	// Legacy hostname-UNIQUE must go before the fleet_host_id one.
	_ = s.exec(ctx, "DROP CONSTRAINT ON (h:Host) ASSERT h.hostname IS UNIQUE;", nil)
	for _, q := range []string{
		"CREATE CONSTRAINT ON (u:User) ASSERT u.username IS UNIQUE;",
		"CREATE CONSTRAINT ON (h:Host) ASSERT h.fleet_host_id IS UNIQUE;",
		"CREATE CONSTRAINT ON (s:Software) ASSERT s.name IS UNIQUE;",
		"CREATE CONSTRAINT ON (l:Label) ASSERT l.fleet_id IS UNIQUE;",
		"CREATE INDEX ON :Label(name);",
		"CREATE INDEX ON :Host(hostname);",
		"CREATE INDEX ON :Software(extension_key);",
		"CREATE INDEX ON :Software(kind);",
	} {
		_ = s.exec(ctx, q, nil)
	}
	// One-shot: clear the legacy last_software_sync_iso property.
	_ = s.exec(ctx, "MATCH (h:Host) "+
		"WHERE h.last_software_sync_iso IS NOT NULL "+
		"SET h.last_software_sync_iso = NULL", nil)

	if _, err := dedupeCaseVariantSoftware(ctx, s); err != nil {
		slog.Warn(fmt.Sprintf("software case-variant dedupe skipped: %v", err))
	}
	if err := migrateExtensionNamesToKeys(ctx, s); err != nil {
		slog.Warn(fmt.Sprintf("extension_key name migration skipped: %v", err))
	}
	return nil
}

// isPathyName is _is_pathy_name: a software name that is really a path.
func isPathyName(n string) bool {
	if strings.ContainsAny(n, `\/`) {
		return true
	}
	r := []rune(n)
	if len(r) >= 2 && isAlpha(r[0]) && r[1] == ':' {
		return len(r) == 2 || r[2] == '\\' || r[2] == '/'
	}
	return false
}

func isAlpha(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r > 0x7f && strings.ToUpper(string(r)) != strings.ToLower(string(r)))
}

// migrateExtensionNamesToKeys is _migrate_extension_names_to_keys: rename
// extension nodes so s.name == s.extension_key, absorbing duplicates.
func migrateExtensionNamesToKeys(ctx context.Context, s *sess) error {
	rec, err := s.single(ctx, `
            MATCH (s:Software)
            WHERE s.extension_key IS NOT NULL
              AND s.extension_key STARTS WITH 'ext:'
              AND s.name <> s.extension_key
            RETURN count(s) AS n
            `, nil)
	if err != nil {
		return err
	}
	pending := int64(0)
	if rec != nil && pyjson.Truthy(rec["n"]) {
		pending, _ = pyInt(rec["n"])
	}
	if pending == 0 {
		return nil
	}
	slog.Info(fmt.Sprintf("extension_key name migration: %d node(s) to rename", pending))
	keyRows, err := s.rows(ctx, `
                MATCH (s:Software)
                WHERE s.extension_key IS NOT NULL
                  AND s.extension_key STARTS WITH 'ext:'
                RETURN DISTINCT s.extension_key AS k
                `, nil)
	if err != nil {
		return err
	}
	var keys []any
	for _, r := range keyRows {
		if pyjson.Truthy(r["k"]) {
			keys = append(keys, r["k"])
		}
	}
	renamed, absorbed := 0, 0
	for _, key := range keys {
		nodes, err := s.rows(ctx, `
                MATCH (s:Software {extension_key: $k})
                RETURN s.name AS name
                `, map[string]any{"k": key})
		if err != nil {
			return err
		}
		var names []string
		for _, n := range nodes {
			if name, ok := n["name"].(string); ok && name != "" {
				names = append(names, name)
			}
		}
		if len(names) == 0 {
			continue
		}
		keyStr, _ := key.(string)
		survivor := ""
		for _, n := range names {
			if n == keyStr {
				survivor = keyStr
			}
		}
		if survivor == "" {
			var pool []string
			for _, n := range names {
				if !isPathyName(n) {
					pool = append(pool, n)
				}
			}
			if len(pool) == 0 {
				pool = names
			}
			sort.Slice(pool, func(i, j int) bool {
				li, lj := utf8.RuneCountInString(pool[i]), utf8.RuneCountInString(pool[j])
				if li != lj {
					return li < lj
				}
				return pool[i] < pool[j]
			})
			survivor = pool[0]
		}
		for _, dname := range names {
			if dname == survivor {
				continue
			}
			if err := s.exec(ctx, `
                    MATCH (dup:Software {name: $dname})-[r:INSTALLED_ON]->(h:Host)
                    MATCH (canon:Software {name: $survivor})
                    MERGE (canon)-[nr:INSTALLED_ON]->(h)
                    ON CREATE SET nr.first_seen = r.first_seen
                    SET nr.version = coalesce(nr.version, r.version),
                        nr.source = coalesce(nr.source, r.source),
                        nr.browser = coalesce(nr.browser, r.browser),
                        nr.extension_for = coalesce(nr.extension_for, r.extension_for),
                        nr.installed_path = coalesce(nr.installed_path, r.installed_path),
                        nr.extension_key = coalesce(nr.extension_key, r.extension_key, $k),
                        nr.last_seen = CASE
                            WHEN r.last_seen IS NOT NULL AND (nr.last_seen IS NULL OR r.last_seen > nr.last_seen)
                            THEN r.last_seen ELSE nr.last_seen END,
                        nr.first_seen = CASE
                            WHEN r.first_seen IS NOT NULL AND (nr.first_seen IS NULL OR r.first_seen < nr.first_seen)
                            THEN r.first_seen ELSE nr.first_seen END
                    DELETE r
                    `, map[string]any{"dname": dname, "survivor": survivor, "k": key}); err != nil {
				return err
			}
			if err := s.exec(ctx, `
                    MATCH (canon:Software {name: $survivor}), (dup:Software {name: $dname})
                    SET canon.display_name = coalesce(canon.display_name, dup.display_name, dup.name),
                        canon.versions = coalesce(canon.versions, []) + [
                            v IN coalesce(dup.versions, []) WHERE NOT v IN coalesce(canon.versions, [])
                        ],
                        canon.sources = coalesce(canon.sources, []) + [
                            v IN coalesce(dup.sources, []) WHERE NOT v IN coalesce(canon.sources, [])
                        ]
                    WITH dup
                    DETACH DELETE dup
                    `, map[string]any{"survivor": survivor, "dname": dname}); err != nil {
				return err
			}
			absorbed++
		}
		if survivor != keyStr {
			// UNIQUE(name) would reject SET name=key if something owns it.
			clash, err := s.single(ctx, "MATCH (s:Software {name: $k}) RETURN s.name AS n", map[string]any{"k": key})
			if err != nil {
				return err
			}
			if clash == nil {
				if err := s.exec(ctx, `
                        MATCH (s:Software {name: $old})
                        SET s.name = $k,
                            s.display_name = coalesce(s.display_name, $old),
                            s.kind = coalesce(s.kind, 'browser_extension'),
                            s.extension_key = $k
                        `, map[string]any{"old": survivor, "k": key}); err != nil {
					return err
				}
				renamed++
			} else {
				slog.Warn(fmt.Sprintf("extension_key migration: cannot rename %s -> %s (name taken)",
					pyRepr(survivor), pyRepr(keyStr)))
			}
		} else if err := s.exec(ctx, `
                    MATCH (s:Software {name: $k})
                    SET s.kind = coalesce(s.kind, 'browser_extension'),
                        s.extension_key = $k
                    `, map[string]any{"k": key}); err != nil {
			return err
		}
	}
	slog.Info(fmt.Sprintf("extension_key name migration done renamed=%d absorbed=%d keys=%d",
		renamed, absorbed, len(keys)))
	return nil
}

// dedupeCaseVariantSoftware is _dedupe_case_variant_software: fold
// :Software nodes sharing toLower(name) into one lowercased node.
func dedupeCaseVariantSoftware(ctx context.Context, s *sess) (map[string]int, error) {
	clusterRows, err := s.rows(ctx, `
            MATCH (s:Software)
            WITH toLower(s.name) AS lname, collect(s.name) AS variants
            WHERE size(variants) > 1
            RETURN lname, variants
            `, nil)
	if err != nil {
		return nil, err
	}
	clusters, removed := 0, 0
	for _, row := range clusterRows {
		lname, _ := row["lname"].(string)
		var variants []string
		if vs, ok := row["variants"].([]any); ok {
			for _, v := range vs {
				if str, ok := v.(string); ok {
					variants = append(variants, str)
				}
			}
		}
		if len(variants) == 0 {
			continue
		}
		canonical := ""
		for _, v := range variants {
			if v == lname {
				canonical = lname
			}
		}
		if canonical == "" {
			sorted := append([]string(nil), variants...)
			sort.Strings(sorted)
			canonical = sorted[0]
		}
		var dups []any
		for _, v := range variants {
			if v != canonical {
				dups = append(dups, v)
			}
		}
		if dups == nil {
			dups = []any{}
		}
		p := map[string]any{"canon": canonical, "dups": dups}
		for _, q := range []string{`
                MATCH (canon:Software {name: $canon})
                UNWIND $dups AS dname
                MATCH (dup:Software {name: dname})
                OPTIONAL MATCH (dup)-[r:INSTALLED_ON]->(h:Host)
                WITH canon, dup, collect(DISTINCT h) AS hosts
                FOREACH (h IN hosts | MERGE (canon)-[:INSTALLED_ON]->(h))
                `, `
                MATCH (canon:Software {name: $canon})
                UNWIND $dups AS dname
                MATCH (dup:Software {name: dname})
                WITH canon, dup
                SET canon.versions = [v IN coalesce(canon.versions, []) + coalesce(dup.versions, []) | v]
                SET canon.sources  = [v IN coalesce(canon.sources, [])  + coalesce(dup.sources, [])  | v]
                `} {
			if err := s.exec(ctx, q, p); err != nil {
				return nil, err
			}
		}
		if err := s.exec(ctx, `
                MATCH (canon:Software {name: $canon})
                WITH canon,
                     [x IN coalesce(canon.versions, []) WHERE x IS NOT NULL] AS vs,
                     [x IN coalesce(canon.sources, []) WHERE x IS NOT NULL] AS ss
                UNWIND vs AS v
                WITH canon, ss, collect(DISTINCT v) AS vu
                UNWIND ss AS s
                WITH canon, vu, collect(DISTINCT s) AS su
                SET canon.versions = vu, canon.sources = su
                `, map[string]any{"canon": canonical}); err != nil {
			return nil, err
		}
		if err := s.exec(ctx, `
                UNWIND $dups AS dname
                MATCH (dup:Software {name: dname})
                DETACH DELETE dup
                `, map[string]any{"dups": dups}); err != nil {
			return nil, err
		}
		if canonical != lname {
			if err := s.exec(ctx, "MATCH (s:Software {name: $old}) SET s.name = $new",
				map[string]any{"old": canonical, "new": lname}); err != nil {
				return nil, err
			}
		}
		clusters++
		removed += len(dups)
	}
	rec, err := s.single(ctx, `
            MATCH (s:Software)
            WHERE s.name <> toLower(s.name)
            WITH s, toLower(s.name) AS lname
            SET s.name = lname
            RETURN count(s) AS n
            `, nil)
	if err != nil {
		return nil, err
	}
	renamed := int64(0)
	if rec != nil {
		renamed, _ = pyInt(rec["n"])
	}
	if clusters > 0 || renamed > 0 {
		slog.Info(fmt.Sprintf("software case-dedupe clusters=%d duplicates_removed=%d renamed=%d",
			clusters, removed, renamed))
	}
	return map[string]int{"clusters": clusters, "duplicates_removed": removed, "renamed": int(renamed)}, nil
}

// dedupeInstalledOnEdges is _dedupe_installed_on_edges: collapse duplicate
// INSTALLED_ON edges the parallel chunk MERGE race can create, scoped to the
// hosts written this cycle (nil = whole graph, empty = no-op).
func dedupeInstalledOnEdges(ctx context.Context, s *sess, fids []int64) (map[string]int64, error) {
	var param any
	if fids != nil {
		if len(fids) == 0 {
			return map[string]int64{"pairs": 0, "extras_removed": 0}, nil
		}
		param = fids
	}
	rec, err := s.single(ctx, `
            MATCH (s:Software)-[r:INSTALLED_ON]->(h:Host)
            WHERE $fids IS NULL OR h.fleet_host_id IN $fids
            WITH s, h, collect(r) AS rs
            WHERE size(rs) > 1
            WITH s, h, rs, size(rs) - 1 AS extras
            FOREACH (rel IN tail(rs) | DELETE rel)
            RETURN count(*) AS pairs, sum(extras) AS extras_removed
            `, map[string]any{"fids": param})
	if err != nil {
		return nil, err
	}
	var pairs, extras int64
	if rec != nil {
		pairs, _ = pyInt(rec["pairs"])
		extras, _ = pyInt(rec["extras_removed"])
	}
	if extras > 0 {
		slog.Info(fmt.Sprintf("installed_on edge dedupe: pairs=%d extras_removed=%d", pairs, extras))
	}
	return map[string]int64{"pairs": pairs, "extras_removed": extras}, nil
}

// ---------------------------------------------------------------------------
// host / user / software ingest

// hashKey normalises a value for use as a python dict/set key (1 == 1.0).
func hashKey(v any) any {
	if f, ok := v.(float64); ok && f == float64(int64(f)) {
		return int64(f)
	}
	switch v.(type) {
	case string, int64, float64, bool, nil:
		return v
	}
	return fmt.Sprint(v)
}

// extractUserIdentifiers is _extract_user_identifiers: only user-identifier
// keys, never host-level 'name'/'user'.
func extractUserIdentifiers(host map[string]any) []any {
	var out []any
	if raw, ok := host["users"].([]any); ok {
		for _, entry := range raw {
			switch e := entry.(type) {
			case map[string]any:
				if cand := pyjson.Or(e["username"], e["email"], e["display_name"]); pyjson.Truthy(cand) {
					out = append(out, cand)
				}
			case string:
				out = append(out, e)
			}
		}
	}
	for _, k := range []string{"primary_user", "owner"} {
		if v, ok := host[k].(string); ok && v != "" {
			out = append(out, v)
		}
	}
	seen := map[any]struct{}{}
	deduped := make([]any, 0, len(out))
	for _, u := range out {
		k := hashKey(u)
		if _, dup := seen[k]; !dup {
			seen[k] = struct{}{}
			deduped = append(deduped, u)
		}
	}
	return deduped
}

func strip(v any) any {
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return v
}

// safariApps builds {app path: [bundle ID, team ID or nil]} from the host's
// `apps` rows (python dict of tuples) for extintel.WithSafariApp.
func safariApps(softwareList []any) map[string]any {
	apps := map[string]any{}
	for _, x := range softwareList {
		s, ok := x.(map[string]any)
		if !ok || s["source"] != "apps" || !pyjson.Truthy(s["bundle_identifier"]) {
			continue
		}
		paths, _ := s["installed_paths"].([]any)
		sigs, _ := s["signature_information"].([]any)
		for _, pv := range paths {
			p, ok := pv.(string)
			if !ok {
				continue
			}
			var team any
			for _, iv := range sigs {
				i, ok := iv.(map[string]any)
				if ok && i["installed_path"] == p && pyjson.Truthy(i["team_identifier"]) {
					team = i["team_identifier"]
					break
				}
			}
			apps[p] = []any{s["bundle_identifier"], team}
		}
	}
	return apps
}

// cleanSoftware builds the per-host software rows: lowercased names, per-host
// dedupe (on extension_key for extensions), extension identity fields.
func cleanSoftware(softwareList []any) []any {
	var out []any
	seen := map[string]struct{}{}
	apps := safariApps(softwareList)
	for _, x := range softwareList {
		s, ok := x.(map[string]any)
		if !ok {
			continue
		}
		raw, _ := s["name"].(string)
		if raw == "" {
			continue
		}
		nameLC := strings.ToLower(strings.TrimSpace(raw))
		ext := extintel.DeriveExtensionIdentity(s)
		if ext != nil {
			ext = extintel.WithSafariApp(ext, apps)
		}
		dedupe := nameLC
		if ext != nil {
			if k, ok := ext["extension_key"].(string); ok && k != "" {
				dedupe = k
			}
		}
		if nameLC == "" {
			continue
		}
		if _, dup := seen[dedupe]; dup {
			continue
		}
		seen[dedupe] = struct{}{}
		source, _ := strip(pyjson.Or(s["source"], "")).(string)
		entry := map[string]any{
			"name":    nameLC,
			"version": pyjson.Or(s["version"], "unknown"),
			"source":  source,
		}
		if ext != nil {
			for k, v := range ext {
				entry[k] = v
			}
			// UNIQUE is on Software.name: for extensions the stable identity
			// (extension_key) is the MERGE key; the title is display_name.
			entry["name"] = ext["extension_key"]
			if !pyjson.Truthy(entry["display_name"]) {
				entry["display_name"] = nameLC
			}
			enc, count, maxCVSS, hasMax := extintel.SummarizeVulnerabilities(s["vulnerabilities"])
			entry["vulnerabilities_json"] = enc
			entry["vulnerability_count"] = int64(count)
			if hasMax {
				entry["max_cvss"] = maxCVSS
			} else {
				entry["max_cvss"] = nil
			}
			if sig := s["signature_information"]; pyjson.Truthy(sig) {
				// python json.dumps(sig, separators=(',',':'), default=str)[:4000];
				// ensure_ascii output is ASCII so byte truncation == char truncation.
				js := string(pyjson.Marshal(sig))
				if len(js) > 4000 {
					js = js[:4000]
				}
				entry["signature_information_json"] = js
			}
			entry["generated_cpe"] = orNil(s["generated_cpe"])
			entry["vendor"] = orNil(s["vendor"])
		}
		out = append(out, entry)
	}
	return out
}

func orNil(v any) any {
	if pyjson.Truthy(v) {
		return v
	}
	return nil
}

func swList(entry map[string]any) []map[string]any {
	raw, _ := entry["software_list"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, x := range raw {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func toAnySlice(ms []map[string]any) []any {
	out := make([]any, len(ms))
	for i, m := range ms {
		out[i] = m
	}
	return out
}

// CreateGraphRelationships replaces create_graph_relationships(hosts_data,
// extractor, global_users): streams Fleet host dicts (decoded with
// graphdb.DecodeJSON so ids are int64) into Memgraph. The python `extractor`
// argument was unused and is dropped. ServiceUnavailable/auth errors abort
// and are returned (caller must not advance the watermark); per-chunk
// failures are recorded in FailedSoftwareHostIDs.
func (in *Ingestion) CreateGraphRelationships(ctx context.Context, hosts iter.Seq[map[string]any], globalUsers []map[string]any) error {
	start := time.Now()
	nowISO := pyISO(time.Now().UTC(), true)

	s, err := in.open(ctx)
	if err != nil {
		return err
	}
	defer s.close(ctx)

	// 1. Users
	userLookup := map[any]map[string]any{}
	if len(globalUsers) > 0 {
		slog.Info(fmt.Sprintf("ingesting users count=%d", len(globalUsers)))
		var batch []map[string]any
		for _, u := range globalUsers {
			uname := pyjson.Or(u["username"], u["email"], u["name"])
			if !pyjson.Truthy(uname) {
				continue
			}
			userLookup[hashKey(uname)] = u
			batch = append(batch, map[string]any{
				"username": uname, "email": u["email"],
				"fullname": pyjson.Or(u["name"], u["full_name"]),
			})
			if len(batch) >= userBatchSize {
				if err := in.batchCreateUsers(ctx, s, batch); err != nil {
					return err
				}
				batch = nil
			}
		}
		if err := in.batchCreateUsers(ctx, s, batch); err != nil {
			return err
		}
	}

	// 2. Hosts & relationships (stream: size unknown until drained).
	slog.Info("ingesting host stream (size unknown until drained)")
	const progressInterval = 500

	var hostBatch, userRelBatch, swGrouped, emptySWHosts []map[string]any
	swWritten := map[int64]struct{}{}
	skippedNoID, skippedUnchangedSW := 0, 0
	var synthesized []any

	// Hosts whose software is already synced (watermark + >=1 edge): lets an
	// unchanged software_updated_at skip the rel rebuild. Failure just
	// disables the short-circuit.
	swSynced := map[any]any{}
	if rows, err := s.rows(ctx, "MATCH (h:Host) "+
		"WHERE h.fleet_software_updated_at_synced IS NOT NULL "+
		"  AND EXISTS((h)<-[:INSTALLED_ON]-(:Software)) "+
		"RETURN h.fleet_host_id AS id, "+
		"       h.fleet_software_updated_at_synced AS s", nil); err != nil {
		slog.Warn(fmt.Sprintf("sw_synced prefetch failed: %v; skipping short-circuit", err))
	} else {
		for _, r := range rows {
			swSynced[hashKey(r["id"])] = r["s"]
		}
	}

	idx := 0
	for host := range hosts {
		idx++
		if idx%progressInterval == 0 {
			slog.Info(fmt.Sprintf("processed hosts=%d/?", idx))
		}
		fid := host["id"]
		if fid == nil {
			skippedNoID++
			continue
		}
		hostname := strip(pyjson.Or(host["computer_name"], host["display_name"], host["hostname"]))
		if !pyjson.Truthy(hostname) {
			hostname = "fleet-host-" + pyjson.Str(fid)
			synthesized = append(synthesized, fid)
		}
		row := map[string]any{
			"hostname":        hostname,
			"fleet_host_id":   fid,
			"os_version":      host["os_version"],
			"platform":        host["platform"],
			"ip":              host["primary_ip"],
			"last_seen":       host["seen_time"],
			"team_id":         host["team_id"],
			"team_name":       host["team_name"],
			"last_ingest_iso": nowISO,
		}
		users := extractUserIdentifiers(host)
		// Stale USES pruning needs a positive signal: Fleet sent a users list.
		if _, ok := host["users"].([]any); ok {
			row["usernames"] = users
		} else {
			row["usernames"] = nil
		}
		hostBatch = append(hostBatch, row)
		for _, uname := range users {
			rel := map[string]any{"username": uname, "email": nil, "fullname": nil, "fleet_host_id": fid}
			if u := userLookup[hashKey(uname)]; u != nil {
				rel["email"] = u["email"]
				rel["fullname"] = pyjson.Or(u["name"], u["full_name"])
			}
			userRelBatch = append(userRelBatch, rel)
		}

		// Software. Skip the rel rebuild when Fleet's software_updated_at
		// (tagged with SoftwareIdentityVersion) matches the stored watermark.
		swRaw := host["software_updated_at"]
		var swUpdated any
		if pyjson.Truthy(swRaw) {
			swUpdated = pyjson.Str(swRaw) + "|" + strconv.Itoa(SoftwareIdentityVersion)
		}
		stored := swSynced[hashKey(fid)]
		var syncedRaw any
		if pyjson.Truthy(stored) {
			if first, _, _ := strings.Cut(pyjson.Str(stored), "|"); first != "" {
				syncedRaw = first
			}
		}
		swField, isList := host["software"].([]any)
		switch {
		case swUpdated != nil && stored == swUpdated:
			skippedUnchangedSW++
		case isList && len(swField) == 0 && pyjson.Truthy(swRaw) &&
			syncedRaw != nil && syncedRaw != swRaw:
			// Fleet re-inventoried (timestamp moved) and reports zero
			// software: drop stale INSTALLED_ON edges. An empty list without
			// a timestamp change may be a truncated fetch and keeps them.
			emptySWHosts = append(emptySWHosts, map[string]any{
				"fleet_host_id": fid, "fleet_software_updated_at": swUpdated,
			})
		default:
			if cleaned := cleanSoftware(swField); len(cleaned) > 0 {
				if n, ok := pyInt(fid); ok {
					swWritten[n] = struct{}{}
				}
				swGrouped = append(swGrouped, map[string]any{
					"fleet_host_id":             fid,
					"software_list":             cleaned,
					"fleet_software_updated_at": swUpdated,
				})
			}
		}

		// Hosts MUST flush before user/software rels: rel queries MATCH Host.
		hostsFull := len(hostBatch) >= hostBatchSize
		usersFull := len(userRelBatch) >= userBatchSize
		swFull := len(swGrouped) >= softwareGroupFlush
		if hostsFull || usersFull || swFull {
			if err := in.batchCreateHosts(ctx, s, hostBatch); err != nil {
				return err
			}
			hostBatch = nil
		}
		if usersFull {
			if err := in.batchCreateUserRelationships(ctx, s, userRelBatch); err != nil {
				return err
			}
			userRelBatch = nil
		}
		if swFull {
			if err := in.batchCreateSoftwareGrouped(ctx, s, swGrouped); err != nil {
				return err
			}
			swGrouped = nil
		}
	}

	// Final flush — hosts first so trailing rel batches can MATCH them.
	if err := in.batchCreateHosts(ctx, s, hostBatch); err != nil {
		return err
	}
	if err := in.batchCreateUserRelationships(ctx, s, userRelBatch); err != nil {
		return err
	}
	if err := in.batchCreateSoftwareGrouped(ctx, s, swGrouped); err != nil {
		return err
	}
	if len(emptySWHosts) > 0 {
		if _, err := execRetry(ctx, s, `
                    UNWIND $rows AS row
                    MATCH (h:Host {fleet_host_id: row.fleet_host_id})
                    OPTIONAL MATCH (:Software)-[r:INSTALLED_ON]->(h)
                    DELETE r
                    WITH DISTINCT h, row
                    SET h.fleet_software_updated_at_synced = row.fleet_software_updated_at
                `, map[string]any{"rows": toAnySlice(emptySWHosts)}, "prune INSTALLED_ON for emptied hosts"); err != nil {
			return err
		}
		slog.Info(fmt.Sprintf("pruned software edges on hosts now reporting none count=%d", len(emptySWHosts)))
	}

	// Post-ingest sweep of duplicate INSTALLED_ON edges, scoped to this
	// cycle's software hosts.
	fids := make([]int64, 0, len(swWritten))
	for id := range swWritten {
		fids = append(fids, id)
	}
	sort.Slice(fids, func(i, j int) bool { return fids[i] < fids[j] })
	if _, err := dedupeInstalledOnEdges(ctx, s, fids); err != nil {
		slog.Warn(fmt.Sprintf("post-ingest installed_on dedupe skipped: %v", err))
	}

	if skippedNoID > 0 {
		slog.Warn(fmt.Sprintf("skipped hosts missing_fleet_id=%d (cannot MERGE without identity)", skippedNoID))
	}
	if len(synthesized) > 0 {
		slog.Warn(fmt.Sprintf("synthesized hostname=fleet-host-<id> for %d hosts missing hostname in Fleet (fleet_host_ids=%s)",
			len(synthesized), previewIDs(synthesized)))
	}
	if skippedUnchangedSW > 0 {
		slog.Info(fmt.Sprintf("skipped software rel rebuild hosts=%d (software_updated_at unchanged)", skippedUnchangedSW))
	}
	slog.Info(fmt.Sprintf("ingestion completed elapsed=%.2fs", time.Since(start).Seconds()))
	return nil
}

// previewIDs is the python "[a, b, ...] (+N more)" log preview (first 20).
func previewIDs(ids []any) string {
	parts := make([]string, 0, 20)
	for i, id := range ids {
		if i == 20 {
			break
		}
		parts = append(parts, pyjson.Str(id))
	}
	s := "[" + strings.Join(parts, ", ") + "]"
	if len(ids) > 20 {
		s += fmt.Sprintf(" (+%d more)", len(ids)-20)
	}
	return s
}

func (in *Ingestion) batchCreateUsers(ctx context.Context, s *sess, batch []map[string]any) error {
	if len(batch) == 0 {
		return nil
	}
	_, err := execRetry(ctx, s, `
            UNWIND $users AS user
            MERGE (u:User {username: user.username})
            SET u.email = user.email, u.fullname = user.fullname
        `, map[string]any{"users": toAnySlice(batch)}, "create user batch")
	return err
}

// batchCreateHosts MERGEs on fleet_host_id; hostname and the rest are SET.
// On failure the hosts are marked failed (watermark held); on success stale
// USES edges are pruned for hosts where Fleet sent a users list.
func (in *Ingestion) batchCreateHosts(ctx context.Context, s *sess, batch []map[string]any) error {
	if len(batch) == 0 {
		return nil
	}
	p := map[string]any{"hosts": toAnySlice(batch)}
	ok, err := execRetry(ctx, s, `
            UNWIND $hosts AS host
            MERGE (h:Host {fleet_host_id: host.fleet_host_id})
            SET h.hostname = host.hostname,
                h.os_version = host.os_version,
                h.platform = host.platform,
                h.ip = host.ip,
                h.last_seen = host.last_seen,
                h.team_id = host.team_id,
                h.team_name = host.team_name,
                h.last_ingest_iso = host.last_ingest_iso,
                h.last_software_sync_iso = NULL
        `, p, "create host batch")
	if err != nil {
		return err
	}
	if !ok {
		for _, h := range batch {
			in.markFailed(h["fleet_host_id"])
		}
		return nil
	}
	_, err = execRetry(ctx, s, `
            UNWIND $hosts AS host
            WITH host WHERE host.usernames IS NOT NULL
            MATCH (u:User)-[r:USES]->(h:Host {fleet_host_id: host.fleet_host_id})
            WHERE NOT u.username IN host.usernames
            DELETE r
        `, p, "prune stale USES edges")
	return err
}

func (in *Ingestion) batchCreateUserRelationships(ctx context.Context, s *sess, batch []map[string]any) error {
	if len(batch) == 0 {
		return nil
	}
	ok, err := execRetry(ctx, s, `
            UNWIND $rels AS rel
            MATCH (h:Host {fleet_host_id: rel.fleet_host_id})
            MERGE (u:User {username: rel.username})
            SET u.email = rel.email, u.fullname = rel.fullname
            MERGE (u)-[:USES]->(h)
        `, map[string]any{"rels": toAnySlice(batch)}, "create user relationship batch")
	if err != nil {
		return err
	}
	if !ok {
		seen := map[any]struct{}{}
		for _, r := range batch {
			k := hashKey(r["fleet_host_id"])
			if _, dup := seen[k]; !dup {
				seen[k] = struct{}{}
				in.markFailed(r["fleet_host_id"])
			}
		}
	}
	return nil
}

const queryNodes = `
            UNWIND $software AS sw
            MERGE (s:Software {name: sw.name})
            ON CREATE SET s.versions = [sw.version],
                          s.first_version = sw.version,
                          s.last_version = coalesce(sw.last_version, sw.version),
                          s.sources = CASE
                              WHEN sw.source IS NULL OR sw.source = '' THEN []
                              ELSE [sw.source] END,
                          s.first_seen = $seen_at,
                          s.last_seen = $seen_at,
                          s.kind = sw.kind,
                          s.store = sw.store,
                          s.extension_key = sw.extension_key,
                          s.extension_id = sw.extension_id,
                          s.browser = sw.browser,
                          s.extension_for = sw.extension_for,
                          s.display_name = sw.display_name,
                          s.installed_paths = sw.installed_paths,
                          s.generated_cpe = sw.generated_cpe,
                          s.vendor = sw.vendor,
                          s.signature_information_json = sw.signature_information_json,
                          s.vulnerabilities_json = sw.vulnerabilities_json,
                          s.vulnerability_count = sw.vulnerability_count,
                          s.max_cvss = sw.max_cvss,
                          s.is_builtin = sw.is_builtin,
                          s.app_bundle_id = sw.app_bundle_id,
                          s.app_team_id = sw.app_team_id
            ON MATCH SET s.versions = CASE
                WHEN s.versions IS NULL THEN [sw.version]
                WHEN NOT sw.version IN s.versions THEN s.versions + [sw.version]
                ELSE s.versions END,
                s.last_version = CASE
                    WHEN sw.last_version IS NOT NULL THEN sw.last_version
                    ELSE s.last_version END,
                s.last_seen = $seen_at,
                s.first_seen = coalesce(s.first_seen, $seen_at),
                s.sources = CASE
                    WHEN sw.source IS NULL OR sw.source = '' THEN coalesce(s.sources, [])
                    WHEN s.sources IS NULL THEN [sw.source]
                    WHEN NOT sw.source IN s.sources THEN s.sources + [sw.source]
                    ELSE s.sources END,
                s.kind = CASE WHEN sw.kind IS NOT NULL THEN sw.kind ELSE s.kind END,
                s.store = CASE WHEN sw.store IS NOT NULL THEN sw.store ELSE s.store END,
                s.extension_key = CASE WHEN sw.extension_key IS NOT NULL THEN sw.extension_key ELSE s.extension_key END,
                s.extension_id = CASE WHEN sw.extension_id IS NOT NULL THEN sw.extension_id ELSE s.extension_id END,
                s.browser = CASE WHEN sw.browser IS NOT NULL THEN sw.browser ELSE s.browser END,
                s.extension_for = CASE WHEN sw.extension_for IS NOT NULL THEN sw.extension_for ELSE s.extension_for END,
                s.display_name = CASE WHEN sw.display_name IS NOT NULL THEN sw.display_name ELSE s.display_name END,
                s.installed_paths = CASE WHEN sw.installed_paths IS NOT NULL THEN sw.installed_paths ELSE s.installed_paths END,
                s.generated_cpe = CASE WHEN sw.generated_cpe IS NOT NULL THEN sw.generated_cpe ELSE s.generated_cpe END,
                s.vendor = CASE WHEN sw.vendor IS NOT NULL THEN sw.vendor ELSE s.vendor END,
                s.signature_information_json = CASE WHEN sw.signature_information_json IS NOT NULL THEN sw.signature_information_json ELSE s.signature_information_json END,
                s.vulnerabilities_json = CASE WHEN sw.vulnerabilities_json IS NOT NULL THEN sw.vulnerabilities_json ELSE s.vulnerabilities_json END,
                s.vulnerability_count = CASE WHEN sw.vulnerability_count IS NOT NULL THEN sw.vulnerability_count ELSE s.vulnerability_count END,
                s.max_cvss = CASE WHEN sw.max_cvss IS NOT NULL THEN sw.max_cvss ELSE s.max_cvss END,
                s.is_builtin = CASE WHEN sw.kind IS NOT NULL THEN sw.is_builtin ELSE s.is_builtin END,
                s.app_bundle_id = CASE WHEN sw.app_bundle_id IS NOT NULL THEN sw.app_bundle_id ELSE s.app_bundle_id END,
                s.app_team_id = CASE WHEN sw.kind IS NOT NULL THEN sw.app_team_id ELSE s.app_team_id END
        `

const deleteStaleQuery = `
            UNWIND $batches AS batch
            MATCH (h:Host {fleet_host_id: batch.fleet_host_id})<-[r:INSTALLED_ON]-(s:Software)
            WHERE NOT s.name IN batch.keep_ids
              AND NOT coalesce(s.extension_key, '') IN batch.keep_ids
            DELETE r
        `

const queryRels = `
            UNWIND $batches AS batch
            MATCH (h:Host {fleet_host_id: batch.fleet_host_id})
            WITH h, batch
            UNWIND batch.software_list AS sw
            MATCH (s:Software {name: sw.name})
            MERGE (s)-[r:INSTALLED_ON]->(h)
            ON CREATE SET r.first_seen = $seen_at
            SET r.last_seen = $seen_at,
                r.version = sw.version,
                r.source = sw.source,
                r.browser = CASE WHEN sw.browser IS NOT NULL THEN sw.browser ELSE r.browser END,
                r.extension_for = CASE WHEN sw.extension_for IS NOT NULL THEN sw.extension_for ELSE r.extension_for END,
                r.installed_path = CASE WHEN sw.installed_path IS NOT NULL THEN sw.installed_path ELSE r.installed_path END,
                r.extension_key = CASE WHEN sw.extension_key IS NOT NULL THEN sw.extension_key ELSE r.extension_key END
        `

const markSyncedQuery = `
            UNWIND $batches AS b
            MATCH (h:Host {fleet_host_id: b.fleet_host_id})
            SET h.fleet_software_updated_at_synced = b.fleet_software_updated_at
        `

type swKey struct{ name, version, source string }

// batchCreateSoftwareGrouped is _batch_create_software_grouped: node MERGE
// (single writer), then per-chunk prune / rel MERGE / watermark stamp fanned
// out over INGEST_SW_PARALLELISM sessions.
func (in *Ingestion) batchCreateSoftwareGrouped(ctx context.Context, s *sess, batch []map[string]any) error {
	if len(batch) == 0 {
		return nil
	}

	// 0. Every row of a name carries the same last_version: max(batch,
	// existing node) so ON CREATE / ON MATCH are order-independent.
	incoming := map[string]string{}
	for _, e := range batch {
		for _, sw := range swList(e) {
			n, _ := sw["name"].(string)
			v := sw["version"]
			if n == "" || !pyjson.Truthy(v) {
				continue
			}
			vs := pyjson.Str(v)
			if cur, ok := incoming[n]; !ok || compareVersionKey(vs, cur) > 0 {
				incoming[n] = vs
			}
		}
	}
	if len(incoming) > 0 {
		names := make([]any, 0, len(incoming))
		for n := range incoming {
			names = append(names, n)
		}
		existing := map[string]any{}
		rows, err := s.rows(ctx, "MATCH (s:Software) WHERE s.name IN $names "+
			"RETURN s.name AS name, s.last_version AS lv", map[string]any{"names": names})
		if err != nil {
			slog.Warn(fmt.Sprintf("last_version pre-read failed: %v", err))
		}
		for _, r := range rows {
			if n, ok := r["name"].(string); ok && pyjson.Truthy(r["lv"]) {
				existing[n] = r["lv"]
			}
		}
		for _, e := range batch {
			for _, sw := range swList(e) {
				n, _ := sw["name"].(string)
				if n == "" || !pyjson.Truthy(sw["version"]) {
					continue
				}
				inc := incoming[n]
				if ex, ok := existing[n]; ok && compareVersionKey(pyjson.Str(ex), inc) > 0 {
					sw["last_version"] = ex
				} else {
					sw["last_version"] = inc
				}
			}
		}
	}

	seenAt := pyISO(time.Now().UTC(), true)

	// 1. Unique software rows for the node MERGE.
	var unique []any
	seen := map[swKey]struct{}{}
	for _, e := range batch {
		for _, sw := range swList(e) {
			k := swKey{pyjson.Str(sw["name"]), pyjson.Str(sw["version"]), pyjson.Str(pyjson.Or(sw["source"], ""))}
			if _, dup := seen[k]; !dup {
				seen[k] = struct{}{}
				unique = append(unique, sw)
			}
		}
	}

	// 2. Node MERGE, chunked; stops at the first failed chunk (python all()).
	for i := 0; i < len(unique); i += softwareNodeChunk {
		ok, err := execRetry(ctx, s, queryNodes, map[string]any{
			"software": unique[i:min(i+softwareNodeChunk, len(unique))], "seen_at": seenAt,
		}, "create software nodes")
		if err != nil {
			return err
		}
		if !ok {
			// Rels would match no Software and the prune would wipe every
			// edge for these hosts: mark failed and skip.
			for _, e := range batch {
				in.markFailed(e["fleet_host_id"])
			}
			return nil
		}
	}

	// 3. Chunk by software rows per transaction.
	type chunk struct {
		entries []map[string]any
		rows    int
	}
	var chunks []chunk
	var cur chunk
	for _, e := range batch {
		n := len(swList(e))
		if len(cur.entries) > 0 && cur.rows+n > softwareRelChunkRows {
			chunks = append(chunks, cur)
			cur = chunk{}
		}
		cur.entries = append(cur.entries, e)
		cur.rows += n
	}
	if len(cur.entries) > 0 {
		chunks = append(chunks, cur)
	}

	var (
		mu        sync.Mutex
		failedIDs []any
	)
	fail := func(c []map[string]any) {
		mu.Lock()
		defer mu.Unlock()
		for _, e := range c {
			failedIDs = append(failedIDs, e["fleet_host_id"])
		}
	}
	runChunk := func(c chunk) error {
		// Each chunk gets its own session (sessions are not goroutine-safe).
		ws, err := in.open(ctx)
		if err != nil {
			return err
		}
		defer ws.close(ctx)
		del := make([]any, 0, len(c.entries))
		for _, e := range c.entries {
			keep := map[string]struct{}{}
			for _, sw := range swList(e) {
				for _, k := range []any{sw["name"], sw["extension_key"]} {
					if ks, ok := k.(string); ok && ks != "" {
						keep[ks] = struct{}{}
					}
				}
			}
			ids := make([]any, 0, len(keep))
			for k := range keep {
				ids = append(ids, k)
			}
			del = append(del, map[string]any{"fleet_host_id": e["fleet_host_id"], "keep_ids": ids})
		}
		ok, err := execRetry(ctx, ws, deleteStaleQuery, map[string]any{"batches": del},
			fmt.Sprintf("delete stale software rels (chunk hosts=%d)", len(c.entries)))
		if err != nil {
			return err
		}
		if !ok {
			fail(c.entries)
			return nil
		}
		ok, err = execRetry(ctx, ws, queryRels, map[string]any{"batches": toAnySlice(c.entries), "seen_at": seenAt},
			fmt.Sprintf("create grouped software rels (chunk hosts=%d sw_rows=%d)", len(c.entries), c.rows))
		if err != nil {
			return err
		}
		if !ok {
			fail(c.entries)
			return nil
		}
		var stamps []any
		for _, e := range c.entries {
			if pyjson.Truthy(e["fleet_software_updated_at"]) {
				stamps = append(stamps, map[string]any{
					"fleet_host_id": e["fleet_host_id"], "fleet_software_updated_at": e["fleet_software_updated_at"],
				})
			}
		}
		if len(stamps) > 0 {
			_, err = execRetry(ctx, ws, markSyncedQuery, map[string]any{"batches": stamps},
				fmt.Sprintf("stamp software_updated_at_synced (%d hosts)", len(stamps)))
		}
		return err
	}

	workers := min(swParallelism(), max(1, len(chunks)))
	if workers <= 1 || len(chunks) <= 1 {
		for _, c := range chunks {
			if err := runChunk(c); err != nil {
				return err
			}
		}
	} else {
		// Python swallowed a chunk exception here (logged only) and never
		// marked its hosts, letting the watermark advance. Go marks the
		// chunk failed and returns the first connection-level error.
		sem := make(chan struct{}, workers)
		var (
			wg       sync.WaitGroup
			firstErr error
		)
		for _, c := range chunks {
			sem <- struct{}{}
			wg.Add(1)
			go func(c chunk) {
				defer wg.Done()
				defer func() { <-sem }()
				if err := runChunk(c); err != nil {
					slog.Warn(fmt.Sprintf("software rel chunk crashed: %v", err))
					fail(c.entries)
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
				}
			}(c)
		}
		wg.Wait()
		if firstErr != nil {
			in.markFailed(failedIDs...)
			return firstErr
		}
	}

	if len(failedIDs) > 0 {
		slog.Warn(fmt.Sprintf("host_software_rels_failed hosts=%d fleet_host_ids=%s", len(failedIDs), previewIDs(failedIDs)))
		in.markFailed(failedIDs...)
	}

	// 4. Orphan accounting: entries whose fleet_host_id matched no :Host.
	orphans := int64(0)
	if rec, err := s.single(ctx, `
            UNWIND $batches AS batch
            OPTIONAL MATCH (h:Host {fleet_host_id: batch.fleet_host_id})
            WITH batch, h
            WHERE h IS NULL
            RETURN count(batch) AS orphans
        `, map[string]any{"batches": toAnySlice(batch)}); err == nil && rec != nil {
		orphans, _ = pyInt(rec["orphans"])
	}
	if orphans > 0 {
		slog.Warn(fmt.Sprintf("host_software_orphans=%d (fleet_host_id matched no :Host node — software dropped this cycle)", orphans))
	}
	return nil
}

// ---------------------------------------------------------------------------
// version ordering (_version_key)

type vpart struct {
	kind   int    // 0 numeric-led, 1 non-numeric
	num    string // digits without leading zeros ("" for -1 sentinel)
	neg    bool   // the (0,-1,0,"") empty-segment sentinel
	bare   int    // 1 when no suffix, 0 with suffix
	suffix string
}

// versionKey is _version_key: numeric-segment comparison where a suffix
// ranks below the bare number and purely non-numeric segments rank lowest.
func versionKey(v string) []vpart {
	var parts []vpart
	for _, seg := range strings.Split(v, ".") {
		if seg == "" {
			parts = append(parts, vpart{neg: true})
			continue
		}
		i := 0
		for i < len(seg) && seg[i] >= '0' && seg[i] <= '9' {
			i++
		}
		if i > 0 {
			num := strings.TrimLeft(seg[:i], "0")
			bare := 0
			if i == len(seg) {
				bare = 1
			}
			parts = append(parts, vpart{num: num, bare: bare, suffix: seg[i:]})
		} else {
			parts = append(parts, vpart{kind: 1, suffix: seg})
		}
	}
	return parts
}

func cmpNum(a, b vpart) int {
	switch {
	case a.neg && b.neg:
		return 0
	case a.neg:
		return -1
	case b.neg:
		return 1
	case len(a.num) != len(b.num):
		if len(a.num) < len(b.num) {
			return -1
		}
		return 1
	}
	return strings.Compare(a.num, b.num)
}

func comparePart(a, b vpart) int {
	if a.kind != b.kind {
		if a.kind < b.kind {
			return -1
		}
		return 1
	}
	if a.kind == 0 {
		if c := cmpNum(a, b); c != 0 {
			return c
		}
		if a.bare != b.bare {
			if a.bare < b.bare {
				return -1
			}
			return 1
		}
	}
	return strings.Compare(a.suffix, b.suffix)
}

// compareVersionKey compares _version_key(a) with _version_key(b) as python
// tuples (a shorter equal prefix sorts first).
func compareVersionKey(a, b string) int {
	ka, kb := versionKey(a), versionKey(b)
	for i := 0; i < len(ka) && i < len(kb); i++ {
		if c := comparePart(ka[i], kb[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(ka) < len(kb):
		return -1
	case len(ka) > len(kb):
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// labels

// SyncLabelsWithMembership replaces sync_labels_with_membership(labels,
// member_map, now_iso, reap_age_seconds). memberMap is {label fleet id:
// member host ids}; a label absent from it keeps its existing edges.
func (in *Ingestion) SyncLabelsWithMembership(ctx context.Context, labels []map[string]any, memberMap map[int64][]int64, nowISO string, reapAgeSeconds int) (*LabelSyncStats, error) {
	stats := &LabelSyncStats{}
	s, err := in.open(ctx)
	if err != nil {
		return nil, err
	}
	defer s.close(ctx)
	if len(labels) == 0 {
		// Empty payload: only age-based reaping (robust to one empty cycle).
		n, err := reapStaleLabels(ctx, s, []any{}, nowISO, reapAgeSeconds)
		if err != nil {
			return nil, err
		}
		stats.LabelsReaped = n
		return stats, nil
	}
	if err := batchMergeLabels(ctx, s, labels, nowISO); err != nil {
		return nil, err
	}
	present := []any{}
	for _, lbl := range labels {
		fid := lbl["id"]
		if fid == nil {
			stats.Errors = append(stats.Errors, "label without id: "+pyRepr(lbl["name"]))
			continue
		}
		present = append(present, fid)
		stats.LabelsSeen++
		key, ok := pyInt(fid)
		members, inMap := memberMap[key]
		if !ok || !inMap {
			// Membership fetch failed this cycle; keep existing edges.
			stats.LabelsUnchanged++
			continue
		}
		changed, added, removed, orphans, err := syncSingleLabelMembership(ctx, s, fid, members, nowISO)
		if err != nil {
			return nil, err
		}
		stats.OrphanMembers += orphans
		if changed {
			stats.LabelsResynced++
			stats.EdgesCreated += added
			stats.EdgesDeleted += removed
		} else {
			stats.LabelsUnchanged++
		}
	}
	if stats.OrphanMembers > 0 {
		slog.Info(fmt.Sprintf("ingestion: label sync orphan summary — orphan_members=%d (host ids in Fleet membership with no :Host node)", stats.OrphanMembers))
	}
	n, err := reapStaleLabels(ctx, s, present, nowISO, reapAgeSeconds)
	if err != nil {
		return nil, err
	}
	stats.LabelsReaped = n
	return stats, nil
}

func lowerOr(v any, def string) string {
	s, _ := pyjson.Or(v, def).(string)
	return strings.ToLower(s)
}

// batchMergeLabels is _batch_merge_labels: MERGE on fleet_id, refresh props.
func batchMergeLabels(ctx context.Context, s *sess, labels []map[string]any, nowISO string) error {
	var rows []any
	for _, lbl := range labels {
		if lbl["id"] == nil {
			continue
		}
		rows = append(rows, map[string]any{
			"fleet_id":        lbl["id"],
			"name":            lbl["name"],
			"description":     pyjson.Or(lbl["description"], ""),
			"label_type":      lowerOr(lbl["label_type"], "regular"),
			"membership_type": lowerOr(lbl["label_membership_type"], ""),
			"query":           pyjson.Or(lbl["query"], ""),
			"host_count":      pyjson.Or(lbl["host_count"], int64(0)),
			"now_iso":         nowISO,
		})
	}
	if rows == nil {
		rows = []any{}
	}
	_, err := execRetry(ctx, s, `
            UNWIND $rows AS row
            MERGE (l:Label {fleet_id: row.fleet_id})
            SET l.name = row.name,
                l.description = row.description,
                l.label_type = row.label_type,
                l.membership_type = row.membership_type,
                l.query = row.query,
                l.host_count = row.host_count,
                l.last_synced_iso = row.now_iso,
                l.last_label_sync_status = 'ok',
                l.consecutive_failures = 0
        `, map[string]any{"rows": rows}, "merge label nodes")
	return err
}

func int64Set(v any) map[int64]struct{} {
	out := map[int64]struct{}{}
	list, _ := v.([]any)
	for _, x := range list {
		if n, ok := pyInt(x); ok && x != nil {
			out[n] = struct{}{}
		}
	}
	return out
}

func sortedKeys(m map[int64]struct{}) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func presentHosts(ctx context.Context, s *sess, ids []int64) (map[int64]struct{}, error) {
	rec, err := s.single(ctx, "MATCH (h:Host) WHERE h.fleet_host_id IN $ids "+
		"RETURN collect(h.fleet_host_id) AS present", map[string]any{"ids": ids})
	if err != nil || rec == nil {
		return map[int64]struct{}{}, err
	}
	return int64Set(rec["present"]), nil
}

func countOf(rec map[string]any, key string, def int64) int64 {
	if rec == nil {
		return def
	}
	n, _ := pyInt(rec[key])
	return n
}

func setOrphans(ctx context.Context, s *sess, fid any, orphans []int64) error {
	capped := orphans
	if len(capped) > 50 {
		capped = capped[:50]
	}
	return s.exec(ctx, "MATCH (l:Label {fleet_id: $fid}) "+
		"SET l.orphan_member_count = $count, "+
		"    l.orphan_member_ids = $ids, "+
		"    l.orphan_member_truncated = $trunc",
		map[string]any{"fid": fid, "count": int64(len(orphans)), "ids": append([]int64{}, capped...), "trunc": len(orphans) > 50})
}

// syncSingleLabelMembership is _sync_single_label_membership: hash skip
// (with an edge-count drift check), per-host delta when a prior blob
// decodes, else full rewrite. Returns (changed, added, removed, orphans).
func syncSingleLabelMembership(ctx context.Context, s *sess, fid any, memberIDs []int64, nowISO string) (bool, int, int, int, error) {
	newHash := ComputeLabelMemberHash(memberIDs)
	prior, err := s.single(ctx, "MATCH (l:Label {fleet_id: $fid}) "+
		"RETURN l.last_member_hash AS h, l.last_members_compressed AS blob", map[string]any{"fid": fid})
	if err != nil {
		return false, 0, 0, 0, err
	}
	var priorHash, priorBlob any
	if prior != nil {
		priorHash, priorBlob = prior["h"], prior["blob"]
	}
	idsList := append([]int64{}, memberIDs...)
	sort.Slice(idsList, func(i, j int) bool { return idsList[i] < idsList[j] })
	hashMatch := priorHash == newHash

	if hashMatch {
		countRec, err := s.single(ctx, "MATCH (:Host)-[r:HAS_LABEL]->(:Label {fleet_id: $fid}) "+
			"RETURN count(r) AS c", map[string]any{"fid": fid})
		if err != nil {
			return false, 0, 0, 0, err
		}
		live := countOf(countRec, "c", 0)
		// Orphan members can never have an edge: compare to present hosts.
		presentRec, err := s.single(ctx, "MATCH (h:Host) WHERE h.fleet_host_id IN $ids RETURN count(h) AS c",
			map[string]any{"ids": idsList})
		if err != nil {
			return false, 0, 0, 0, err
		}
		if live == countOf(presentRec, "c", int64(len(memberIDs))) {
			orphanRec, err := s.single(ctx, `
                    MATCH (l:Label {fleet_id: $fid})
                    OPTIONAL MATCH (h:Host) WHERE h.fleet_host_id IN $ids
                    WITH l, collect(h.fleet_host_id) AS present
                    SET l.orphan_member_count = size([x IN $ids WHERE NOT x IN present]),
                        l.orphan_member_ids = [x IN $ids WHERE NOT x IN present][..50],
                        l.orphan_member_truncated = size([x IN $ids WHERE NOT x IN present]) > 50
                    RETURN l.orphan_member_count AS c
                    `, map[string]any{"fid": fid, "ids": idsList})
			if err != nil {
				return false, 0, 0, 0, err
			}
			return false, 0, 0, int(countOf(orphanRec, "c", 0)), nil
		}
		// Drift: fall through to the full-rewrite repair.
	}

	newSet := map[int64]struct{}{}
	for _, id := range memberIDs {
		newSet[id] = struct{}{}
	}
	newIDs := sortedKeys(newSet)
	newBlob := EncodeLabelMemberBlob(newIDs)
	priorSet, havePrior := DecodeLabelMemberBlob(priorBlob)

	var added, removed, orphans int
	if hashMatch || !havePrior {
		added, removed, orphans, err = fullRewriteLabelMembership(ctx, s, fid, newIDs)
	} else {
		added, removed, orphans, err = deltaApplyLabelMembership(ctx, s, fid, priorSet, newSet)
	}
	if err != nil {
		return false, 0, 0, 0, err
	}
	if err := s.exec(ctx, "MATCH (l:Label {fleet_id: $fid}) "+
		"SET l.last_member_hash = $h, "+
		"    l.last_members_compressed = $blob, "+
		"    l.last_synced_iso = $now",
		map[string]any{"fid": fid, "h": newHash, "blob": newBlob, "now": nowISO}); err != nil {
		return false, 0, 0, 0, err
	}
	return true, added, removed, orphans, nil
}

// deltaApplyLabelMembership is _delta_apply_label_membership: only the
// symmetric-difference edges, plus persisted orphan bookkeeping.
func deltaApplyLabelMembership(ctx context.Context, s *sess, fid any, priorSet, newSet map[int64]struct{}) (int, int, int, error) {
	var added, removed []int64
	for id := range newSet {
		if _, ok := priorSet[id]; !ok {
			added = append(added, id)
		}
	}
	for id := range priorSet {
		if _, ok := newSet[id]; !ok {
			removed = append(removed, id)
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i] < added[j] })
	sort.Slice(removed, func(i, j int) bool { return removed[i] < removed[j] })

	if len(removed) > 0 {
		if _, err := execRetry(ctx, s, `
                UNWIND $hids AS hid
                MATCH (h:Host {fleet_host_id: hid})-[r:HAS_LABEL]->(l:Label {fleet_id: $fid})
                DELETE r
                `, map[string]any{"hids": removed, "fid": fid}, "delete HAS_LABEL edges (delta)"); err != nil {
			return 0, 0, 0, err
		}
	}
	if len(added) > 0 {
		if _, err := execRetry(ctx, s, `
                UNWIND $hids AS hid
                MATCH (h:Host {fleet_host_id: hid})
                MATCH (l:Label {fleet_id: $fid})
                MERGE (h)-[:HAS_LABEL]->(l)
                `, map[string]any{"hids": added, "fid": fid}, "merge HAS_LABEL edges (delta)"); err != nil {
			return 0, 0, 0, err
		}
	}

	candidates := map[int64]struct{}{}
	if len(added) > 0 {
		present, err := presentHosts(ctx, s, added)
		if err != nil {
			return 0, 0, 0, err
		}
		for _, id := range added {
			if _, ok := present[id]; !ok {
				candidates[id] = struct{}{}
			}
		}
	}
	existingRec, err := s.single(ctx, "MATCH (l:Label {fleet_id: $fid}) "+
		"RETURN coalesce(l.orphan_member_ids, []) AS oids", map[string]any{"fid": fid})
	if err != nil {
		return 0, 0, 0, err
	}
	if existingRec != nil {
		for id := range int64Set(existingRec["oids"]) {
			candidates[id] = struct{}{}
		}
	}
	// Drop ids that left the label (covers `- removed` and `& new_set`).
	for id := range candidates {
		if _, ok := newSet[id]; !ok {
			delete(candidates, id)
		}
	}
	var final []int64
	if len(candidates) > 0 {
		still, err := presentHosts(ctx, s, sortedKeys(candidates))
		if err != nil {
			return 0, 0, 0, err
		}
		for _, id := range sortedKeys(candidates) {
			if _, ok := still[id]; !ok {
				final = append(final, id)
			}
		}
	}
	if err := setOrphans(ctx, s, fid, final); err != nil {
		return 0, 0, 0, err
	}
	return len(added), len(removed), len(final), nil
}

// fullRewriteLabelMembership is _full_rewrite_label_membership: delete all
// HAS_LABEL edges of the label and re-MERGE the current members.
func fullRewriteLabelMembership(ctx context.Context, s *sess, fid any, ids []int64) (int, int, int, error) {
	const countQ = "MATCH (:Host)-[r:HAS_LABEL]->(:Label {fleet_id: $fid}) RETURN count(r) AS c"
	p := map[string]any{"fid": fid}
	priorRec, err := s.single(ctx, countQ, p)
	if err != nil {
		return 0, 0, 0, err
	}
	priorEdges := countOf(priorRec, "c", 0)
	if err := s.exec(ctx, "MATCH (:Host)-[r:HAS_LABEL]->(:Label {fleet_id: $fid}) DELETE r", p); err != nil {
		return 0, 0, 0, err
	}
	if len(ids) == 0 {
		if err := s.exec(ctx, "MATCH (l:Label {fleet_id: $fid}) "+
			"SET l.orphan_member_count = 0, "+
			"    l.orphan_member_ids = [], "+
			"    l.orphan_member_truncated = false", p); err != nil {
			return 0, 0, 0, err
		}
		return 0, int(priorEdges), 0, nil
	}
	present, err := presentHosts(ctx, s, ids)
	if err != nil {
		return 0, 0, 0, err
	}
	var orphans []int64
	for _, id := range ids {
		if _, ok := present[id]; !ok {
			orphans = append(orphans, id)
		}
	}
	if err := setOrphans(ctx, s, fid, orphans); err != nil {
		return 0, 0, 0, err
	}
	if _, err := execRetry(ctx, s, `
                UNWIND $hids AS hid
                MATCH (h:Host {fleet_host_id: hid})
                MATCH (l:Label {fleet_id: $fid})
                MERGE (h)-[:HAS_LABEL]->(l)
                `, map[string]any{"hids": ids, "fid": fid}, "re-merge HAS_LABEL edges (full rewrite fallback)"); err != nil {
		return 0, 0, 0, err
	}
	// Count actual edges, not requested: missing hosts make MERGE no-op.
	postRec, err := s.single(ctx, countQ, p)
	if err != nil {
		return 0, 0, 0, err
	}
	return int(countOf(postRec, "c", 0)), int(priorEdges), len(orphans), nil
}

// reapStaleLabels is _reap_stale_labels: DETACH DELETE labels absent from
// this payload whose last_synced_iso is older than the cutoff.
func reapStaleLabels(ctx context.Context, s *sess, present []any, nowISO string, reapAgeSeconds int) (int, error) {
	p := map[string]any{"present": present, "cutoff": cutoffISO(nowISO, reapAgeSeconds)}
	rec, err := s.single(ctx, "MATCH (l:Label) "+
		"WHERE NOT l.fleet_id IN $present "+
		"  AND l.last_synced_iso < $cutoff "+
		"RETURN count(l) AS reaped", p)
	if err != nil {
		return 0, err
	}
	reaped := countOf(rec, "reaped", 0)
	if reaped > 0 {
		if err := s.exec(ctx, "MATCH (l:Label) "+
			"WHERE NOT l.fleet_id IN $present "+
			"  AND l.last_synced_iso < $cutoff "+
			"DETACH DELETE l", p); err != nil {
			return 0, err
		}
	}
	return int(reaped), nil
}

// ---------------------------------------------------------------------------
// reaps

// unattached: every node exists because of a host; hosts go last.
var unattached = []struct{ kind, match string }{
	{"software", "MATCH (n:Software) WHERE NOT EXISTS((n)-[:INSTALLED_ON]->(:Host))"},
	{"labels", "MATCH (n:Label) WHERE NOT EXISTS((n)<-[:HAS_LABEL]-(:Host))"},
	{"users", "MATCH (n:User) WHERE NOT EXISTS((n)-[:USES]->(:Host))"},
	{"hosts", "MATCH (n:Host) WHERE degree(n) = 0"},
}

// ReapUnattached replaces reap_unattached(): deletes Software/Label/User/Host
// with no host edge. Returns {"software","labels","users","hosts"} counts.
func (in *Ingestion) ReapUnattached(ctx context.Context) (map[string]any, error) {
	s, err := in.open(ctx)
	if err != nil {
		return nil, err
	}
	defer s.close(ctx)
	stats := map[string]any{}
	for _, u := range unattached {
		rec, err := s.single(ctx, u.match+" DETACH DELETE n RETURN count(n) AS n", nil)
		if err != nil {
			return nil, fmt.Errorf("reap unattached %s: %w", u.kind, err)
		}
		stats[u.kind] = int(countOf(rec, "n", 0))
	}
	return stats, nil
}

// ReapStaleHosts replaces reap_stale_hosts(now_iso, reap_age_seconds,
// team_ids): returns {"reaped": int, "cutoff_iso": string}.
// nowISO "" means now. Only call on full-scan cycles.
func (in *Ingestion) ReapStaleHosts(ctx context.Context, nowISO string, reapAgeSeconds int, teamIDs []int) (map[string]any, error) {
	if nowISO == "" {
		nowISO = pyISO(time.Now().UTC(), true)
	}
	cutoff := cutoffISO(nowISO, reapAgeSeconds)
	var teams any
	if len(teamIDs) > 0 {
		t := make([]int64, len(teamIDs))
		for i, id := range teamIDs {
			t[i] = int64(id)
		}
		teams = t
	}
	s, err := in.open(ctx)
	if err != nil {
		return nil, err
	}
	defer s.close(ctx)
	const where = "MATCH (h:Host) " +
		"WHERE h.last_ingest_iso IS NOT NULL " +
		"  AND h.last_ingest_iso < $cutoff " +
		"  AND ($teams IS NULL OR coalesce(h.team_id, 0) IN $teams) "
	p := map[string]any{"cutoff": cutoff, "teams": teams}
	rec, err := s.single(ctx, where+"RETURN count(h) AS n", p)
	if err != nil {
		return nil, fmt.Errorf("count stale hosts: %w", err)
	}
	reaped := countOf(rec, "n", 0)
	if reaped > 0 {
		if err := s.exec(ctx, where+"DETACH DELETE h", p); err != nil {
			return nil, fmt.Errorf("reap stale hosts: %w", err)
		}
	}
	return map[string]any{"reaped": int(reaped), "cutoff_iso": cutoff}, nil
}

// MarkLabelSyncFailure replaces mark_label_sync_failure(error_msg): flags
// every Label failed and bumps consecutive_failures; edges are untouched.
func (in *Ingestion) MarkLabelSyncFailure(ctx context.Context, errorMsg string) error {
	s, err := in.open(ctx)
	if err != nil {
		return err
	}
	defer s.close(ctx)
	if r := []rune(errorMsg); len(r) > 500 {
		errorMsg = string(r[:500])
	}
	return s.exec(ctx, "MATCH (l:Label) "+
		"SET l.last_label_sync_status = 'failed', "+
		"    l.consecutive_failures = coalesce(l.consecutive_failures, 0) + 1, "+
		"    l.last_label_sync_error = $err", map[string]any{"err": errorMsg})
}

// ---------------------------------------------------------------------------
// python datetime helpers

// pyISO is datetime.isoformat(): microseconds only when non-zero, offset as
// +HH:MM for aware values, none for naive ones.
func pyISO(t time.Time, aware bool) string {
	s := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	if aware {
		_, off := t.Zone()
		sign := '+'
		if off < 0 {
			sign, off = '-', -off
		}
		s += fmt.Sprintf("%c%02d:%02d", sign, off/3600, off%3600/60)
		if off%60 != 0 {
			s += fmt.Sprintf(":%02d", off%60)
		}
	}
	return s
}

// cutoffISO is (fromisoformat(now_iso.replace("Z","+00:00")) -
// timedelta(seconds=age)).isoformat(), falling back to now (UTC) when the
// timestamp does not parse. The result is compared as a string in Cypher, so
// it keeps the input's offset / naivety like python.
func cutoffISO(nowISO string, ageSeconds int) string {
	t, aware, ok := parsePyISO(strings.ReplaceAll(nowISO, "Z", "+00:00"))
	if !ok {
		t, aware = time.Now().UTC(), true
	}
	return pyISO(t.Add(-time.Duration(ageSeconds)*time.Second), aware)
}

func parsePyISO(s string) (time.Time, bool, bool) {
	for _, l := range []string{"2006-01-02T15:04:05Z07:00", "2006-01-02 15:04:05Z07:00",
		"2006-01-02T15:04Z07:00", "2006-01-02 15:04Z07:00"} {
		if t, err := time.Parse(l, s); err == nil {
			return t, true, true
		}
	}
	for _, l := range []string{"2006-01-02T15:04:05", "2006-01-02 15:04:05",
		"2006-01-02T15:04", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.Parse(l, s); err == nil {
			return t, false, true
		}
	}
	return time.Time{}, false, false
}

// pyRepr is repr() for log/error text: strings quoted python-style.
func pyRepr(v any) string {
	s, ok := v.(string)
	if !ok {
		return pyjson.Str(v)
	}
	q := "'"
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		q = `"`
	}
	s = strings.ReplaceAll(s, `\`, `\\`)
	if q == "'" {
		s = strings.ReplaceAll(s, "'", `\'`)
	}
	return q + s + q
}
