// Package extworker ports webviz/extension_worker.py: the leader-elected
// browser-extension intel worker (store metadata, blocklist, threat feeds,
// risk scores written back to :Software).
//
// One process wins an flock and runs the loop so store endpoints are never
// hammered in parallel. Status lives in a JSON file so every reader sees the
// same truth, and a manual refresh travels via a trigger-file mtime. Every
// network call is cached on disk and degrades to a local score when offline:
// the worker must never be the reason ingestion or the API is unavailable.
package extworker

import (
	"context"
	"crypto/sha1" // #nosec G505 -- not security: cache key/digest must match python hashlib.sha1 on-disk format
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/karmine05/fleet-hound/internal/app"
	"github.com/karmine05/fleet-hound/internal/extintel"
	"github.com/karmine05/fleet-hound/internal/graphdb"
	"github.com/karmine05/fleet-hound/internal/workerutil"
)

// RefreshIntervalSec is REFRESH_INTERVAL_SEC (6h).
const RefreshIntervalSec = 6 * 60 * 60

// Options are start_worker's keyword arguments.
type Options struct {
	IntervalSec int // 21600
	BatchSize   int // 50
	Parallelism int // 4
	LockPath    string
	TriggerPath string
	StatusPath  string
	CacheDir    string // <CONFIG_DIR>/extension_cache
	Enabled     bool
}

// Chrome-family listings come from one batched RPC, so a weekly refresh is
// cheap and doubles as the takedown check. Edge/AMO/Opera/App Store are one
// call per item.
const (
	listingTTLChromeSec = 7 * 24 * 60 * 60
	listingTTLMinSec    = 21 * 24 * 60 * 60
	listingTTLJitterSec = 7 * 24 * 60 * 60
	blocklistTTLSec     = 6 * 60 * 60
)

// Bump a version when the cached shape changes; pruneCache deletes the files
// of every other version.
const (
	listingKeyVersion  = "v14"
	manifestKeyVersion = "v13"
)

const extWhere = "(s.kind = 'browser_extension' OR s.extension_key STARTS WITH 'ext:')"

var inf = math.Inf(1)

// Package-derived fields of one immutable version, cached forever.
var manifestFields = []string{"manifest_version", "permissions", "optional_permissions",
	"host_permissions", "content_script_matches", "update_url",
	"homepage_url", "crx_hash_verified", "content_security_policy"}

var listingFields = []string{"updated_at", "featured", "established_publisher", "developer_verified",
	"developer_email", "developer_website", "trader",
	"privacy_disclosure", "privacy_policy_url"}

// chromeFamily: stores answered by the batched CWS RPC. Edge and Opera ask
// their own store first. adapterStores: stores with an anonymous adapter.
func inChromeFamily(store string) bool {
	_, ok := extintel.ChromiumStores[store]
	return ok && store != "edge" && store != "opera"
}

func inAdapterStores(store string) bool {
	_, ok := extintel.ChromiumStores[store]
	return ok || store == "firefox" || store == "safari"
}

// Test seams (python tests monkeypatch the same names).
var (
	fetchChromeListings   = extintel.FetchChromeListings
	fetchChromeMetadata   = extintel.FetchChromeMetadata
	fetchStoreMetadata    = extintel.FetchStoreMetadata
	fetchMozillaBlocklist = extintel.FetchMozillaBlocklist
	fetchThreatFeed       = extintel.FetchThreatFeed
	loadThreatFeeds       = extintel.LoadThreatFeeds
	analyzeExtension      = extintel.AnalyzeExtension
	knownPublishersPath   = extintel.KnownPublishersPath
)

// ---------------------------------------------------------------------------
// Disk cache
// ---------------------------------------------------------------------------

func cachePath(cacheDir, key string) string {
	sum := sha1.Sum([]byte(key)) // #nosec G401 -- not security: cache key/digest must match python hashlib.sha1 on-disk format
	digest := hex.EncodeToString(sum[:])[:20]
	var safe []rune
	for _, ch := range key {
		if len(safe) == 60 {
			break
		}
		if unicode.IsLetter(ch) || unicode.IsNumber(ch) || strings.ContainsRune("-_.", ch) {
			safe = append(safe, ch)
		} else {
			safe = append(safe, '_')
		}
	}
	return filepath.Join(cacheDir, string(safe)+"-"+digest+".json")
}

// cacheGet returns the cached object, or nil when missing, older than ttl,
// unreadable or not an object.
func cacheGet(cacheDir, key string, ttl float64) map[string]any {
	path := cachePath(cacheDir, key)
	st, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if time.Since(st.ModTime()).Seconds() > ttl {
		return nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		return nil
	}
	v, err := graphdb.DecodeJSON(data)
	if err != nil {
		return nil
	}
	m, _ := v.(map[string]any)
	return m
}

// cacheTouch restarts the TTL of a copy the server confirmed unchanged (304).
func cacheTouch(cacheDir, key string) {
	now := time.Now()
	if err := os.Chtimes(cachePath(cacheDir, key), now, now); err != nil {
		slog.Warn("extension cache touch failed", "key", key, "err", err)
	}
}

func cacheSet(cacheDir, key string, value any) {
	switch value.(type) {
	case map[string]any, []any:
	default:
		return
	}
	// Python-compatible text keeps float repr (4.0 stays 4.0) so a re-read
	// copy digests the same as the python worker's.
	if err := workerutil.AtomicWriteFile(cachePath(cacheDir, key), []byte(pyDumps(value)), ".extensions."); err != nil {
		slog.Warn("extension cache write failed", "key", key, "err", err)
	}
}

func cacheAge(cacheDir, key string) (float64, bool) {
	st, err := os.Stat(cachePath(cacheDir, key))
	if err != nil {
		return 0, false
	}
	return time.Since(st.ModTime()).Seconds(), true
}

type fetchFunc func(validators map[string]string) (map[string]map[string]any, extintel.FetchResult)

// conditionalFetch refreshes one expired cached document with a conditional
// GET. Returns (document or nil, fetched fresh). The ETag lives next to the
// copy under "<key>:meta" and is sent only while a copy exists to reuse.
func conditionalFetch(cacheDir, key string, fetch fetchFunc) (map[string]any, bool) {
	stale := cacheGet(cacheDir, key, inf)
	validators := map[string]string{}
	if stale != nil {
		if meta := cacheGet(cacheDir, key+":meta", inf); meta != nil {
			if etag, ok := meta["etag"].(string); ok && etag != "" {
				validators["etag"] = etag
			}
		}
	}
	result, fr := fetch(validators)
	if fr == extintel.FetchNotModified {
		cacheTouch(cacheDir, key)
		return stale, false
	}
	if fr == extintel.FetchOK && len(result) > 0 {
		doc := toAnyMap(result)
		cacheSet(cacheDir, key, doc)
		if validators["etag"] != "" {
			cacheSet(cacheDir, key+":meta", map[string]any{"etag": validators["etag"]})
		}
		return doc, true
	}
	return nil, false
}

func toAnyMap(m map[string]map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// pruneCache deletes listing/manifest files of retired key versions. Only
// `v<N>_*` files are candidates, so feed and blocklist copies are never
// touched.
func pruneCache(cacheDir string) int {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		slog.Warn("extensions: cannot list cache", "dir", cacheDir, "err", err)
		return 0
	}
	live := []string{listingKeyVersion + "_listing_", manifestKeyVersion + "_manifest_"}
	removed := 0
	for _, e := range entries {
		name := e.Name()
		if !isVersionedCacheName(name) || strings.HasPrefix(name, live[0]) || strings.HasPrefix(name, live[1]) {
			continue
		}
		if err := os.Remove(filepath.Join(cacheDir, name)); err != nil {
			slog.Warn("extensions: cannot prune", "name", name, "err", err)
			continue
		}
		removed++
	}
	return removed
}

// isVersionedCacheName is re.match(r"v\d+_", name).
func isVersionedCacheName(name string) bool {
	if !strings.HasPrefix(name, "v") {
		return false
	}
	i := 1
	for i < len(name) && name[i] >= '0' && name[i] <= '9' {
		i++
	}
	return i > 1 && i < len(name) && name[i] == '_'
}

// ---------------------------------------------------------------------------
// Shared status
// ---------------------------------------------------------------------------

type sharedStatus struct {
	path             string
	mu               sync.Mutex
	enabled          bool
	running          bool
	lastTickISO      any
	itemsScoredTotal int
	lastError        any
	lastCycle        any
	queueRemaining   int
	sources          any
	threatFeeds      any
	coverage         any
}

func newSharedStatus(path string, enabled, running bool) *sharedStatus {
	prior := readJSONMap(path)
	return &sharedStatus{
		path: path, enabled: enabled, running: running,
		lastTickISO:      prior["last_tick_iso"],
		itemsScoredTotal: pyInt(prior["items_scored_total"], 0),
		lastError:        prior["last_error"],
		lastCycle:        prior["last_cycle"],
		queueRemaining:   pyInt(prior["queue_remaining"], 0),
		sources:          prior["sources"],
		threatFeeds:      orEmptyList(prior["threat_feeds"]),
		coverage:         orEmptyList(prior["coverage"]),
	}
}

func (s *sharedStatus) update(fn func(*sharedStatus)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
	err := workerutil.AtomicWriteJSON(s.path, map[string]any{
		"enabled":            s.enabled,
		"running":            s.running,
		"last_tick_iso":      s.lastTickISO,
		"items_scored_total": s.itemsScoredTotal,
		"last_error":         s.lastError,
		"last_cycle":         s.lastCycle,
		"queue_remaining":    s.queueRemaining,
		"sources":            s.sources,
		"threat_feeds":       s.threatFeeds,
		"coverage":           s.coverage,
	}, ".extensions.")
	if err != nil { // e.g. read-only config: keep the loop alive, say so
		slog.Warn("extensions: status flush failed", "err", err)
	}
}

func (s *sharedStatus) snapshot() (itemsScored int, coverage any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.itemsScoredTotal, s.coverage
}

// ---------------------------------------------------------------------------
// Grouping, fingerprints, planning
// ---------------------------------------------------------------------------

type install struct{ path, platform any }

type group struct {
	key       string
	props     map[string]any
	memberFPs []any // python set of member intel_fingerprint values
	hostCount int
	versions  []string
	installs  []install
}

type workItem struct {
	group          *group
	record         map[string]any
	fingerprint    string
	base           string
	due            bool
	changed        bool
	blocklistEntry map[string]any
	feedHits       []map[string]any
}

func totalHosts(ctx context.Context, db *graphdb.DB) (int, error) {
	// Fails loudly: scoring with 0 would drop rare-in-fleet from every node.
	rec, err := db.Single(ctx, "MATCH (h:Host) RETURN count(h) AS n", nil)
	if err != nil {
		return 0, fmt.Errorf("count hosts: %w", err)
	}
	n, _ := graphdb.AsInt64(rec["n"])
	return int(n), nil
}

var allGroupsQuery = fmt.Sprintf(`
        MATCH (s:Software)
        WHERE %s
        MATCH (s)-[r:INSTALLED_ON]->(h:Host)
        WITH coalesce(s.extension_key, 'name:' + s.name) AS key,
             collect(DISTINCT s) AS nodes,
             count(DISTINCT h) AS host_count,
             collect(DISTINCT r.version) AS versions,
             collect(DISTINCT {path: r.installed_path, platform: h.platform}) AS installs
        RETURN key, [n IN nodes | properties(n)] AS members, host_count, versions, installs
        ORDER BY host_count DESC
    `, extWhere)

// allGroups returns every extension identity grouped by canonical key.
// Scoring once per key and writing to every member node keeps risk
// consistent across install paths/versions.
func allGroups(ctx context.Context, db *graphdb.DB) ([]*group, error) {
	rows, err := db.Query(ctx, allGroupsQuery, nil)
	if err != nil {
		return nil, fmt.Errorf("extension groups: %w", err)
	}
	return groupsFromRows(rows), nil
}

func groupsFromRows(rows []map[string]any) []*group {
	var groups []*group
	for _, row := range rows {
		var members []map[string]any
		for _, m := range asList(row["members"]) {
			if mm, ok := m.(map[string]any); ok {
				members = append(members, mm)
			}
		}
		if len(members) == 0 {
			continue
		}
		g := &group{key: pyStr(row["key"]), props: members[0]}
		for _, m := range members {
			g.memberFPs = append(g.memberFPs, m["intel_fingerprint"])
		}
		hc, _ := graphdb.AsInt64(row["host_count"])
		g.hostCount = int(hc)
		vs := map[string]struct{}{}
		for _, v := range asList(row["versions"]) {
			if truthy(v) {
				vs[pyStr(v)] = struct{}{}
			}
		}
		g.versions = sortedKeys(vs)
		seen := map[string]bool{}
		for _, i := range asList(row["installs"]) {
			im, ok := i.(map[string]any)
			if !ok {
				continue
			}
			in := install{path: im["path"], platform: im["platform"]}
			k := pyDumps([]any{in.path, in.platform})
			if !seen[k] {
				seen[k] = true
				g.installs = append(g.installs, in)
			}
		}
		// Keep path-less installs: store trust fails closed on them.
		sort.SliceStable(g.installs, func(a, b int) bool {
			pa, pb := orEmpty(g.installs[a].path), orEmpty(g.installs[b].path)
			if pa != pb {
				return pa < pb
			}
			return orEmpty(g.installs[a].platform) < orEmpty(g.installs[b].platform)
		})
		groups = append(groups, g)
	}
	return groups
}

func recordFor(g *group) map[string]any {
	record := make(map[string]any, len(g.props)+5)
	for k, v := range g.props {
		record[k] = v
	}
	record["host_count"] = g.hostCount
	versions := make([]any, len(g.versions))
	for i, v := range g.versions {
		versions[i] = v
	}
	record["versions"] = versions
	// Per-host installs: store trust needs every install to be a store install.
	installs := make([]any, len(g.installs))
	for i, in := range g.installs {
		installs[i] = map[string]any{"path": in.path, "platform": in.platform}
	}
	record["installs"] = installs
	// Nodes predating the ingestion change have no `store`; recover it from
	// the canonical key so the right adapter is still chosen.
	if !truthy(record["store"]) && strings.HasPrefix(g.key, "ext:") {
		if parts := strings.Split(g.key, ":"); len(parts) > 1 {
			record["store"] = parts[1]
		}
	}
	// Current rules, not the flag ingestion stored at the last ingest.
	record["is_builtin"] = extintel.IsBrowserBuiltin(record)
	return record
}

func recordVersions(record map[string]any) []string {
	var out []string
	for _, v := range asList(record["versions"]) {
		out = append(out, pyStr(v))
	}
	return out
}

func digest(v any) string {
	sum := sha1.Sum([]byte(pyDumps(v))) // #nosec G401 -- not security: cache key/digest must match python hashlib.sha1 on-disk format
	return hex.EncodeToString(sum[:])
}

func fileDigest(path string) any {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		return nil
	}
	sum := sha1.Sum(data) // #nosec G401 -- not security: cache key/digest must match python hashlib.sha1 on-disk format
	return hex.EncodeToString(sum[:])
}

// fingerprint hashes every scoring input except the store listing.
func fingerprint(record map[string]any, totalHosts int, threatDigest string, publishersDigest any) string {
	hostCount := pyInt(record["host_count"], 0)
	// Only the rare-in-fleet verdict, not the raw count: one enrolment would
	// otherwise change every fingerprint in the fleet.
	rare := totalHosts >= 10 && float64(hostCount)/float64(totalHosts) < 0.03
	var installs []any
	for _, i := range asList(record["installs"]) {
		im, _ := i.(map[string]any)
		installs = append(installs, []any{im["path"], im["platform"]})
	}
	if installs == nil {
		installs = []any{}
	}
	return digest([]any{extintel.ScorerVersion, record["store"], record["extension_id"],
		orEmptyList(record["versions"]), installs,
		record["host_count"], rare, threatDigest, publishersDigest,
		// Ingestion-owned node fields the scorer reads.
		record["name"], record["display_name"], record["vendor"],
		truthy(record["is_builtin"]), record["installed_paths"],
		record["max_cvss"], record["vulnerabilities"],
		record["app_bundle_id"], record["app_team_id"]})
}

// lookupID is the ID the store is asked about: Safari lists the containing
// app (by bundle ID), every other store lists the extension.
func lookupID(record map[string]any) string {
	if strings.ToLower(pyStrOr(record["store"])) == "safari" {
		return pyStrOr(record["app_bundle_id"])
	}
	return pyStrOr(record["extension_id"])
}

func listingKey(store, id string) string { return listingKeyVersion + ":listing:" + store + ":" + id }
func manifestKey(store, id, version string) string {
	return manifestKeyVersion + ":manifest:" + store + ":" + id + ":" + version
}

// withListing folds the cached listing in, so a refreshed listing that never
// reached the graph (failed write, restart) still differs next cycle.
func withListing(fp string, record map[string]any, cacheDir string) string {
	store := strings.ToLower(pyStrOr(record["store"]))
	id := lookupID(record)
	var cached any
	if id != "" && inAdapterStores(store) {
		if c := cacheGet(cacheDir, listingKey(store, id), inf); c != nil {
			cached = c
		}
	}
	return digest([]any{fp, cached})
}

func listingTTL(store, id string) float64 {
	if inChromeFamily(store) {
		return listingTTLChromeSec
	}
	// Stable per-ID jitter spreads Edge/AMO refreshes over a week.
	sum := sha1.Sum([]byte(id)) // #nosec G401 -- not security: cache key/digest must match python hashlib.sha1 on-disk format
	jitter := uint64(binary.BigEndian.Uint32(sum[:4]))
	return float64(listingTTLMinSec + jitter%(listingTTLJitterSec+1))
}

// listingDue: no cached listing, a host runs a newer version than the
// listing that was not already seen at the last fetch, a new hit, or TTL.
func listingDue(record map[string]any, cacheDir string, newHit bool) bool {
	store := strings.ToLower(pyStrOr(record["store"]))
	id := lookupID(record)
	if truthy(record["is_builtin"]) || id == "" || !inAdapterStores(store) {
		return false
	}
	key := listingKey(store, id)
	cached := cacheGet(cacheDir, key, inf)
	age, ok := cacheAge(cacheDir, key)
	if cached == nil || !ok || newHit || age > listingTTL(store, id) {
		return true
	}
	if store == "opera" && cached["store"] != "opera" && cached["resolved_from"] != "opera" {
		return true // cached before Opera had its own adapter (CWS-only answer)
	}
	latest := cached["version"]
	if !truthy(latest) {
		return false
	}
	// A store that stays behind must not be refetched every cycle.
	seen := map[string]bool{}
	for _, v := range asList(cached["host_versions"]) {
		if s, ok := v.(string); ok {
			seen[s] = true
		}
	}
	for _, v := range recordVersions(record) {
		if !seen[v] && extintel.CompareVersions(v, pyStr(latest)) > 0 {
			return true
		}
	}
	return false
}

// plan returns work items for groups whose fingerprint changed or whose
// listing is due.
func plan(groups []*group, cacheDir string, blocklist map[string]map[string]any,
	feedIndex map[string]map[string]any, total int, publishersDigest any) []*workItem {
	var work []*workItem
	for _, g := range groups {
		record := recordFor(g)
		id := pyStrOr(record["extension_id"])
		versions := recordVersions(record)
		if len(versions) == 0 {
			versions = []string{pyStrOr(record["last_version"])}
		}
		entry := extintel.MatchBlocklist(blocklist, id, versions)
		hits := extintel.MatchThreatFeeds(feedIndex, pyStrOr(record["store"]), id)
		var entryV any
		if entry != nil {
			entryV = entry
		}
		hitsV := make([]any, len(hits))
		for i, h := range hits {
			hitsV[i] = h
		}
		base := fingerprint(record, total, digest([]any{entryV, hitsV}), publishersDigest)
		fp := withListing(base, record, cacheDir)
		sig := pyStrOr(g.props["risk_signals_json"])
		newHit := entry != nil && !truthy(g.props["known_bad"])
		for _, h := range hits {
			if !strings.Contains(sig, `"threat-feed:`+pyStr(h["feed"])+`"`) {
				newHit = true
			}
		}
		due := listingDue(record, cacheDir, newHit)
		changed := false
		for _, m := range g.memberFPs {
			if s, ok := m.(string); !ok || s != fp {
				changed = true
			}
		}
		if due || changed {
			work = append(work, &workItem{group: g, record: record, fingerprint: fp, base: base,
				due: due, changed: changed, blocklistEntry: entry, feedHits: hits})
		}
	}
	return work
}

// ---------------------------------------------------------------------------
// Store breaker
// ---------------------------------------------------------------------------

// storeBreaker is the per-cycle set of stores that answered 429 /
// 503+Retry-After. Remaining items for a tripped store are skipped (not
// fetched, not stamped) and retried next cycle.
type storeBreaker struct {
	mu      sync.Mutex
	tripped map[string]bool
}

func newStoreBreaker() *storeBreaker { return &storeBreaker{tripped: map[string]bool{}} }

func breakerKey(store any) string {
	s := strings.ToLower(pyStrOr(store))
	if s == "" {
		s = "unknown"
	}
	switch s { // Chromium-family stores share the Chrome update2 endpoint.
	case "brave", "vivaldi", "chromium":
		return "chrome"
	}
	return s
}

func (b *storeBreaker) isTripped(store any) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tripped[breakerKey(store)]
}

// trip returns true only for the call that tripped it (log once).
func (b *storeBreaker) trip(store any) bool {
	k := breakerKey(store)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tripped[k] {
		return false
	}
	b.tripped[k] = true
	return true
}

func (b *storeBreaker) list() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return sortedKeys(b.tripped)
}

// ---------------------------------------------------------------------------
// Listing + scoring
// ---------------------------------------------------------------------------

func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// copyWith is python {**m, k: v}.
func copyWith(m map[string]any, k string, v any) map[string]any {
	out := clone(m)
	out[k] = v
	return out
}

func storeOf(record map[string]any) string {
	s := strings.ToLower(pyStrOr(record["store"]))
	if s == "" {
		return "unknown"
	}
	return s
}

// listingFor returns (store meta, state); state is local, cached, fetched,
// failed, stale or deferred. The store is asked only when due. A failed
// refetch falls back to the last good listing, flagged in error.
func listingFor(ctx context.Context, record map[string]any, cacheDir string, due bool,
	breaker *storeBreaker, prefetched map[string]any) (map[string]any, string) {
	store := storeOf(record)
	if truthy(record["is_builtin"]) {
		return map[string]any{"store": store, "status": "builtin"}, "local"
	}
	id := lookupID(record)
	if id == "" {
		msg := "missing extension id"
		if store == "safari" {
			msg = "containing app has no bundle ID in Fleet"
		}
		return map[string]any{"store": store, "status": "unknown", "error": msg}, "local"
	}
	if !inAdapterStores(store) {
		return map[string]any{"store": store, "status": "unknown",
			"error": fmt.Sprintf("no anonymous metadata adapter for store '%s'", store)}, "local"
	}
	key := listingKey(store, id)
	cached := cacheGet(cacheDir, key, inf)
	if cached != nil && !due {
		return cached, "cached"
	}
	const deferredErr = "store rate limited; listing refresh deferred"
	if breaker.isTripped(store) {
		if cached != nil {
			return copyWith(cached, "error", deferredErr), "stale"
		}
		return map[string]any{"store": store, "status": "unknown", "rate_limited": true, "error": deferredErr}, "deferred"
	}
	manifestFor := func(version string) map[string]any {
		return cacheGet(cacheDir, manifestKey(store, id, version), inf)
	}
	var meta map[string]any
	switch {
	case prefetched == nil:
		meta = fetchStoreMetadata(ctx, store, id, nil, manifestFor)
	case truthy(prefetched["listing_missing"]):
		// Not in the listing RPC: update2 tells unlisted from removed.
		meta = fetchChromeMetadata(ctx, id, nil, prefetched, manifestFor)
	default:
		meta = clone(prefetched)
	}
	if meta == nil {
		meta = map[string]any{}
	}
	if truthy(meta["rate_limited"]) {
		if breaker.trip(store) {
			slog.Warn(fmt.Sprintf("extension worker: %s store rate limited (%s); deferring its remaining items to next cycle",
				store, pyStr(meta["error"])))
		}
		if cached != nil {
			return copyWith(cached, "error", deferredErr), "stale"
		}
		return meta, "deferred"
	}
	if meta["status"] != "unknown" || !truthy(meta["error"]) {
		// Safari extensions of one app share its listing: merge their seen
		// versions while the listed version is unchanged.
		seen := map[string]struct{}{}
		if len(cached) > 0 && reflect.DeepEqual(cached["version"], meta["version"]) {
			for _, v := range asList(cached["host_versions"]) {
				seen[pyStr(v)] = struct{}{}
			}
		}
		for _, v := range recordVersions(record) {
			seen[v] = struct{}{}
		}
		hv := make([]any, 0, len(seen))
		for _, v := range sortedKeys(seen) {
			hv = append(hv, v)
		}
		cacheSet(cacheDir, key, copyWith(meta, "host_versions", hv))
		version := ""
		if s, ok := meta["version"].(string); ok {
			version = strings.TrimSpace(s)
		}
		if version != "" && truthy(meta["manifest_version"]) &&
			!(truthy(meta["manifest_error"]) || truthy(meta["manifest_unavailable"])) {
			mf := map[string]any{}
			for _, f := range manifestFields {
				if v, ok := meta[f]; ok && !isEmptyManifestValue(v) {
					mf[f] = v
				}
			}
			cacheSet(cacheDir, manifestKey(store, id, version), mf)
		}
		return meta, "fetched"
	}
	if cached != nil {
		return copyWith(cached, "error", fmt.Sprintf("refresh failed (%s); using cached listing", pyStr(meta["error"]))), "failed"
	}
	return meta, "failed"
}

// isEmptyManifestValue is `v in (None, [], "")`.
func isEmptyManifestValue(v any) bool {
	if v == nil {
		return true
	}
	if s, ok := v.(string); ok {
		return s == ""
	}
	rv := reflect.ValueOf(v)
	return (rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array) && rv.Len() == 0
}

func chromeDue(it *workItem) bool {
	return it.due && !truthy(it.record["is_builtin"]) && pyStrOr(it.record["extension_id"]) != "" &&
		inChromeFamily(strings.ToLower(pyStrOr(it.record["store"])))
}

// prefetchChrome does one batched listing RPC for every due Chrome-family
// item in the chunk.
func prefetchChrome(ctx context.Context, chunk []*workItem, breaker *storeBreaker) map[string]map[string]any {
	var ids []string
	for _, it := range chunk {
		if chromeDue(it) {
			ids = append(ids, pyStrOr(it.record["extension_id"]))
		}
	}
	if len(ids) == 0 || breaker.isTripped("chrome") {
		return map[string]map[string]any{}
	}
	listings := fetchChromeListings(ctx, ids, nil)
	for _, m := range listings {
		if truthy(m["rate_limited"]) {
			if breaker.trip("chrome") {
				slog.Warn("extension worker: chrome listing RPC rate limited; deferring Chrome-family items to next cycle")
			}
			break
		}
	}
	return listings
}

type scoreOutcome struct {
	item   *workItem
	result map[string]any
	state  string
	err    error
}

// scoreItem fetches (if due) and scores one identity; no DB writes. A nil
// result means nothing to write.
func scoreItem(ctx context.Context, it *workItem, cacheDir string, total int,
	breaker *storeBreaker, prefetched map[string]any) (out scoreOutcome) {
	out.item = it
	if ctx.Err() != nil {
		out.state = "deferred"
		return out
	}
	defer func() {
		if r := recover(); r != nil { // one bad item must not kill the cycle
			out.result, out.state, out.err = nil, "error", fmt.Errorf("panic: %v", r)
		}
	}()
	record := clone(it.record)
	meta, state := listingFor(ctx, record, cacheDir, it.due, breaker, prefetched)
	out.state = state
	localHit := it.blocklistEntry != nil || len(it.feedHits) > 0
	if state == "deferred" && !(it.changed && localHit) {
		return out
	}
	// A failed refresh is written so intel_error shows the broken adapter.
	if (state == "cached" || state == "local" || state == "stale") && !it.changed {
		return out
	}
	// The refetch may have replaced the cached listing.
	it.fingerprint = withListing(it.base, record, cacheDir)
	record["store_meta"] = meta
	out.result = analyzeExtension(record, extintel.AnalyzeOptions{
		BlocklistEntry: it.blocklistEntry, FeedHits: it.feedHits,
		FleetHostCount: total, HasFleetHostCount: true,
	})
	return out
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

const writeSet = `
        SET s.kind = 'browser_extension',
            s.extension_key = coalesce(s.extension_key, row.key),
            s.risk_score = row.risk_score,
            s.risk_band = row.risk_band,
            s.capability_score = row.capability_score,
            s.trust_score = row.trust_score,
            s.threat_score = row.threat_score,
            s.exposure_score = row.exposure_score,
            s.risk_signals_json = row.risk_signals_json,
            s.store_status = row.store_status,
            s.store_url = coalesce(row.store_url, s.store_url),
            s.publisher = coalesce(row.publisher, s.publisher),
            s.publisher_reputable = row.publisher_reputable,
            s.known_bad = row.known_bad,
            s.install_users = row.install_users,
            s.latest_version = coalesce(row.latest_version, s.latest_version),
            s.display_name = CASE WHEN row.store_name IS NOT NULL
                                   AND coalesce(s.display_name, '__MSG_') STARTS WITH '__MSG_'
                              THEN row.store_name ELSE s.display_name END,
            s.rating = row.rating,
            s.rating_count = row.rating_count,
            s.store_category = row.store_category,
            s.manifest_version = row.manifest_version,
            s.permissions = row.permissions,
            s.host_permissions = row.host_permissions,
            s.content_script_matches = row.content_script_matches,
            s.store_updated_at = row.updated_at,
            s.store_featured = row.featured,
            s.established_publisher = row.established_publisher,
            s.developer_verified = row.developer_verified,
            s.developer_email = row.developer_email,
            s.developer_website = row.developer_website,
            s.trader = row.trader,
            s.privacy_disclosure = row.privacy_disclosure,
            s.privacy_policy_url = row.privacy_policy_url,
            s.is_builtin = row.is_builtin,
            s.intel_error = row.intel_error,
            s.intel_fingerprint = row.intel_fingerprint,
            s.intel_refreshed_ts = row.refreshed_ts,
            s.intel_refreshed_at = row.refreshed_at
`

// One indexed property per MATCH: an OR across properties defeats the index.
const (
	writeByKey  = "UNWIND $rows AS row MATCH (s:Software {extension_key: row.key})" + writeSet
	writeByName = "UNWIND $rows AS row MATCH (s:Software {name: row.name}) " +
		"WHERE s.kind = 'browser_extension' AND coalesce(s.extension_key, row.key) = row.key" + writeSet
)

func rowFor(key string, result map[string]any, fp string) map[string]any {
	row := make(map[string]any, len(result)+16)
	for k, v := range result {
		row[k] = v
	}
	// Store taxonomy is NOT the software category (the enricher owns
	// s.category); keep the store's classification in its own field.
	row["store_category"] = row["category"]
	delete(row, "category")
	// Built-in results carry no store listing; write NULL for those fields.
	for _, f := range listingFields {
		if _, ok := row[f]; !ok {
			row[f] = nil
		}
	}
	row["key"] = key
	// Legacy groups have no extension_key; their members share the name.
	if strings.HasPrefix(key, "name:") {
		row["name"] = key[len("name:"):]
	} else {
		row["name"] = nil
	}
	row["risk_signals_json"] = extintel.SignalsJSON(result["risk_signals"])
	row["intel_fingerprint"] = fp
	now := time.Now()
	row["refreshed_ts"] = float64(now.UnixNano()) / 1e9
	row["refreshed_at"] = app.PyISO(now)
	delete(row, "risk_signals")
	for f, v := range row {
		// Neo4j rejects the whole UNWIND batch on one out-of-int64 parameter.
		if outOfInt64(v) {
			row[f] = nil
		}
	}
	return row
}

func outOfInt64(v any) bool {
	switch t := v.(type) {
	case uint64:
		return t > math.MaxInt64
	case uint:
		return uint64(t) > math.MaxInt64
	}
	return false
}

// rowWriter is the write surface (a seam for tests).
type rowWriter func(ctx context.Context, cypher string, rows []any) error

func dbRowWriter(db *graphdb.DB) rowWriter {
	return func(ctx context.Context, cypher string, rows []any) error {
		// Managed transactions retry Memgraph's TransientError ("conflicting
		// transactions") that a concurrent ETL write to the same nodes raises.
		_, err := db.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
			res, err := tx.Run(ctx, cypher, map[string]any{"rows": rows})
			if err != nil {
				return nil, err
			}
			return res.Consume(ctx)
		})
		return err
	}
}

func writeRows(ctx context.Context, write rowWriter, rows []map[string]any) error {
	var byKey, byName []any
	for _, r := range rows {
		if r["name"] == nil {
			byKey = append(byKey, r)
		} else {
			byName = append(byName, r)
		}
	}
	if len(byKey) > 0 {
		if err := write(ctx, writeByKey, byKey); err != nil {
			return fmt.Errorf("write by key: %w", err)
		}
	}
	if len(byName) > 0 {
		if err := write(ctx, writeByName, byName); err != nil {
			return fmt.Errorf("write by name: %w", err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Feeds, blocklist, coverage
// ---------------------------------------------------------------------------

// loadFeedIndex returns {feed_name: {"platform", "entries"}} plus per-feed
// health. A failed fetch falls back to the last good copy; a feed with no
// copy is reported, not fatal. entries are map[string]any (JSON-cache shape).
func loadFeedIndex(ctx context.Context, cacheDir string) (map[string]map[string]any, []any) {
	index := map[string]map[string]any{}
	health := []any{}
	for _, feed := range loadThreatFeeds() {
		name := pyStr(feed["name"])
		key := "feed:" + name
		entries := cacheGet(cacheDir, key, blocklistTTLSec)
		var errV any
		if entries == nil {
			entries, _ = conditionalFetch(cacheDir, key, func(v map[string]string) (map[string]map[string]any, extintel.FetchResult) {
				return fetchThreatFeed(ctx, feed, nil, v)
			})
			if entries == nil {
				errV = "fetch failed"
				if entries = cacheGet(cacheDir, key, inf); entries != nil {
					errV = "fetch failed; using stale copy"
				}
			}
		}
		n := 0
		if entries != nil {
			index[name] = map[string]any{"platform": feed["platform"], "entries": entries}
			n = len(entries)
		}
		health = append(health, map[string]any{"name": feed["name"], "platform": feed["platform"],
			"entries": n, "error": errV})
	}
	return index, health
}

func loadBlocklist(ctx context.Context, cacheDir string) (map[string]any, error) {
	const key = "mozilla:blocklist"
	if bl := cacheGet(cacheDir, key, blocklistTTLSec); bl != nil {
		return bl, nil
	}
	bl, _ := conditionalFetch(cacheDir, key, func(v map[string]string) (map[string]map[string]any, extintel.FetchResult) {
		return fetchMozillaBlocklist(ctx, nil, v)
	})
	if len(bl) > 0 {
		return bl, nil
	}
	// Fetch failed: an expired list beats none. Scoring with {} drops
	// known-bad extensions below their risk floor for a refresh window.
	bl = cacheGet(cacheDir, key, inf)
	if bl == nil {
		return nil, errors.New("Mozilla blocklist unavailable and no cached copy; skipping cycle")
	}
	slog.Warn("extension worker: blocklist fetch failed; using stale cache")
	return bl, nil
}

// blocklistEntries keeps python's isinstance(entry, dict) filter.
func blocklistEntries(bl map[string]any) map[string]map[string]any {
	out := make(map[string]map[string]any, len(bl))
	for k, v := range bl {
		if m, ok := v.(map[string]any); ok {
			out[k] = m
		}
	}
	return out
}

var coverageQuery = fmt.Sprintf(`
            MATCH (s:Software) WHERE %s
              AND EXISTS((s)-[:INSTALLED_ON]->(:Host))
              AND (NOT coalesce(s.is_builtin, false) OR coalesce(s.risk_score, 0) > 0)
            WITH coalesce(s.store, 'unknown') AS store, s
            RETURN store,
                   count(s) AS total,
                   count(s.extension_id) AS with_id,
                   sum(CASE WHEN s.store_status = 'public' THEN 1 ELSE 0 END) AS listed,
                   count(s.install_users) AS with_users,
                   count(s.rating) AS with_rating,
                   count(s.manifest_version) AS manifest_parsed,
                   count(s.developer_email) AS with_email,
                   sum(CASE WHEN s.risk_signals_json CONTAINS 'manifest-uninspected' THEN 1 ELSE 0 END) AS uninspected,
                   sum(CASE WHEN s.risk_signals_json CONTAINS 'weak-csp' THEN 1 ELSE 0 END) AS weak_csp,
                   sum(CASE WHEN s.risk_signals_json CONTAINS 'threat-feed:' THEN 1 ELSE 0 END) AS feed_hits,
                   collect(DISTINCT s.intel_error)[..5] AS errors
            ORDER BY total DESC
        `, extWhere)

// coverage returns per-store enrichment fill rates so a broken adapter
// shows up in status on its own.
func coverage(ctx context.Context, db *graphdb.DB) ([]any, error) {
	rows, err := db.Query(ctx, coverageQuery, nil)
	if err != nil {
		return nil, fmt.Errorf("extension coverage: %w", err)
	}
	out := make([]any, 0, len(rows))
	for _, row := range rows {
		errs := []any{}
		for _, e := range asList(row["errors"]) {
			if truthy(e) {
				errs = append(errs, e)
			}
		}
		row["errors"] = errs
		out = append(out, row)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Cycle + loop
// ---------------------------------------------------------------------------

// cycleDeps lets tests drive runCycle without a database.
type cycleDeps struct {
	totalHosts func(ctx context.Context) (int, error)
	groups     func(ctx context.Context) ([]*group, error)
	coverage   func(ctx context.Context) ([]any, error)
	write      rowWriter
	feedIndex  func(ctx context.Context, cacheDir string) (map[string]map[string]any, []any)
	blocklist  func(ctx context.Context, cacheDir string) (map[string]any, error)
}

func dbDeps(db *graphdb.DB) cycleDeps {
	return cycleDeps{
		totalHosts: func(ctx context.Context) (int, error) { return totalHosts(ctx, db) },
		groups:     func(ctx context.Context) ([]*group, error) { return allGroups(ctx, db) },
		coverage:   func(ctx context.Context) ([]any, error) { return coverage(ctx, db) },
		write:      dbRowWriter(db),
		feedIndex:  loadFeedIndex,
		blocklist:  loadBlocklist,
	}
}

func runCycle(ctx context.Context, d cycleDeps, st *sharedStatus, batchSize, parallelism int, cacheDir string) (map[string]any, error) {
	total, err := d.totalHosts(ctx)
	if err != nil {
		return nil, err
	}
	feedIndex, feedHealth := d.feedIndex(ctx, cacheDir)
	blocklist, err := d.blocklist(ctx, cacheDir)
	if err != nil {
		return nil, err
	}
	groups, err := d.groups(ctx)
	if err != nil {
		return nil, err
	}
	work := plan(groups, cacheDir, blocklistEntries(blocklist), feedIndex, total, fileDigest(knownPublishersPath()))
	st.update(func(s *sharedStatus) { s.queueRemaining = len(work) })

	var scored, errCount, deferred, cacheHits, skipped, done int
	fetched, failed := map[string]int{}, map[string]int{}
	breaker := newStoreBreaker()
	batchSize = max(1, batchSize)
	sem := make(chan struct{}, max(1, parallelism))
	// Drain the whole due set this cycle, one chunk (prefetch, score, write) at a time.
	for start := 0; start < len(work); start += batchSize {
		if ctx.Err() != nil {
			break
		}
		chunk := work[start:min(start+batchSize, len(work))]
		prefetched := prefetchChrome(ctx, chunk, breaker)
		results := make(chan scoreOutcome, len(chunk))
		var wg sync.WaitGroup
		for _, it := range chunk {
			var pre map[string]any
			if chromeDue(it) {
				pre = prefetched[pyStrOr(it.record["extension_id"])]
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(it *workItem, pre map[string]any) {
				defer wg.Done()
				defer func() { <-sem }()
				results <- scoreItem(ctx, it, cacheDir, total, breaker, pre)
			}(it, pre)
		}
		go func() { wg.Wait(); close(results) }()
		var rows []map[string]any
		for r := range results {
			store := storeOf(r.item.record)
			switch r.state {
			case "fetched":
				fetched[store]++
			case "failed":
				failed[store]++
			}
			switch {
			case r.err != nil:
				errCount++
				slog.Warn("extension scoring failed", "key", r.item.group.key, "err", r.err)
			case r.result != nil:
				if r.state == "cached" {
					cacheHits++
				}
				rows = append(rows, rowFor(r.item.group.key, r.result, r.item.fingerprint))
			case r.state == "deferred" || r.state == "stale":
				// No write keeps the old fingerprint, so it is retried next cycle.
				deferred++
			default:
				if r.state == "cached" {
					cacheHits++
				}
				skipped++
				done++
			}
		}
		if len(rows) > 0 {
			if err := writeRows(ctx, d.write, rows); err != nil {
				// One bad chunk must not kill the cycle.
				errCount += len(rows)
				slog.Warn("extension write failed", "groups", len(rows), "err", err)
			} else {
				scored += len(rows)
				done += len(rows)
			}
		}
		remaining := len(work) - done
		st.update(func(s *sharedStatus) { s.queueRemaining = remaining })
	}

	summary := map[string]any{
		"groups_seen":         len(groups),
		"due":                 len(work),
		"scored":              scored,
		"unchanged_skipped":   len(groups) - len(work) + skipped,
		"cache_hits":          cacheHits,
		"fetched":             fetched,
		"refresh_failed":      failed,
		"errors":              errCount,
		"deferred":            deferred,
		"rate_limited_stores": breaker.list(),
		"total_hosts":         total,
		"blocklist_entries":   len(blocklist),
		"tick_iso":            app.PyISO(time.Now()),
	}
	cov, err := d.coverage(ctx)
	var covV any = cov
	if err != nil { // health reporting must not fail the cycle
		slog.Warn("extension coverage query failed", "err", err)
		_, covV = st.snapshot()
	}
	remaining := len(work) - done
	st.update(func(s *sharedStatus) {
		s.coverage = covV
		s.itemsScoredTotal += scored
		s.queueRemaining = remaining
		s.lastCycle = summary
		s.sources = map[string]any{"mozilla_blocklist": len(blocklist) > 0, "store_metadata": true}
		s.threatFeeds = feedHealth
	})
	return summary, nil
}

func loop(ctx context.Context, db *graphdb.DB, st *sharedStatus, o Options) {
	lastTrigger := workerutil.TriggerMtime(o.TriggerPath)
	d := dbDeps(db)
	for ctx.Err() == nil {
		tickStart := time.Now()
		tick(ctx, db, d, st, o)
		// Sleep in small slices so a manual trigger is picked up quickly.
		remaining := max(1.0, float64(o.IntervalSec)-time.Since(tickStart).Seconds())
		lastTrigger = workerutil.SleepUntil(ctx, time.Now().Add(time.Duration(remaining*float64(time.Second))),
			o.TriggerPath, lastTrigger)
	}
	st.update(func(s *sharedStatus) { s.running = false })
	slog.Info("extensions: loop exited")
}

func tick(ctx context.Context, db *graphdb.DB, d cycleDeps, st *sharedStatus, o Options) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("extensions: cycle panicked", "panic", r)
			st.update(func(s *sharedStatus) { s.lastError = fmt.Sprint(r) })
		}
	}()
	if db == nil || !db.Available(ctx) {
		st.update(func(s *sharedStatus) { s.lastError = "database unavailable" })
		return
	}
	if _, err := runCycle(ctx, d, st, o.BatchSize, o.Parallelism, o.CacheDir); err != nil {
		if ctx.Err() != nil {
			return // shutdown, not a failure worth reporting
		}
		slog.Error("extensions: cycle failed", "err", err)
		msg := err.Error()
		st.update(func(s *sharedStatus) { s.lastError = msg })
		return
	}
	st.update(func(s *sharedStatus) { s.lastError = nil })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Start replaces start_worker(driver_provider, ...). Disabled or not leader
// returns (nil, nil); the leader prunes retired cache key versions first.
func Start(ctx context.Context, db *graphdb.DB, o Options) (*workerutil.Handle, error) {
	st := newSharedStatus(o.StatusPath, o.Enabled, false)
	if !o.Enabled {
		slog.Info("extensions: disabled via EXTENSION_WORKER_ENABLED=false")
		return nil, nil
	}
	lock := workerutil.TryAcquireLock(o.LockPath, "extensions")
	if lock == nil {
		slog.Info("extensions: another worker holds the lock; not starting loop", "lock", o.LockPath)
		return nil, nil
	}
	st.update(func(s *sharedStatus) { s.running = true })
	if n := pruneCache(o.CacheDir); n > 0 {
		slog.Info(fmt.Sprintf("extensions: pruned %d cache files of retired key versions", n))
	}
	h := workerutil.Go(ctx, lock, func(ctx context.Context) { loop(ctx, db, st, o) })
	slog.Info(fmt.Sprintf("extensions: started (interval=%ds, batch=%d, parallelism=%d, cache=%s, lock=%s)",
		o.IntervalSec, o.BatchSize, o.Parallelism, o.CacheDir, o.LockPath))
	return h, nil
}

// ReadStatus replaces read_status(path).
func ReadStatus(statusPath string) map[string]any {
	data := readJSONMap(statusPath)
	return map[string]any{
		"enabled":            truthy(data["enabled"]),
		"running":            truthy(data["running"]),
		"last_tick_iso":      data["last_tick_iso"],
		"items_scored_total": pyInt(data["items_scored_total"], 0),
		"last_error":         data["last_error"],
		"last_cycle":         data["last_cycle"],
		"queue_remaining":    pyInt(data["queue_remaining"], 0),
		"sources":            data["sources"],
		"threat_feeds":       orEmptyList(data["threat_feeds"]),
		"coverage":           orEmptyList(data["coverage"]),
	}
}

// FireTrigger replaces fire_trigger(path, cooldown_sec=30).
func FireTrigger(triggerPath string, cooldownSec float64) (bool, float64) {
	return workerutil.FireTrigger(triggerPath, cooldownSec, "extensions")
}

// ---------------------------------------------------------------------------
// python-semantics helpers
// ---------------------------------------------------------------------------

func readJSONMap(path string) map[string]any {
	data, err := os.ReadFile(path) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		return map[string]any{}
	}
	v, err := graphdb.DecodeJSON(data)
	if err != nil {
		return map[string]any{}
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// pyInt is int(v or 0) with def for unconvertible values.
func pyInt(v any, def int) int {
	if v == nil {
		return def
	}
	if n, ok := graphdb.AsInt64(v); ok {
		return int(n)
	}
	return def
}

// orEmptyList is `v or []`.
func orEmptyList(v any) any {
	if !truthy(v) {
		return []any{}
	}
	return v
}

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
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice, reflect.Map, reflect.Array:
		return rv.Len() > 0
	}
	return true
}

func asList(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case []string:
		out := make([]any, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out
	}
	return nil
}

// pyStr is python str(v) for scalars (None -> "None").
func pyStr(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case float64:
		return pyFloat(t)
	}
	return fmt.Sprint(v)
}

// pyStrOr is str(v or ""): "" for falsy values.
func pyStrOr(v any) string {
	if !truthy(v) {
		return ""
	}
	return pyStr(v)
}

func orEmpty(v any) string { return pyStrOr(v) }

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
