// Package etl ports src/etl.py (run_etl and the .state.json / cadence
// helpers), main.py (the `fleethound etl` CLI) and clear_db.py (the
// `fleethound clear-db` CLI).
package etl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/karmine05/fleet-hound/internal/app"
	"github.com/karmine05/fleet-hound/internal/config"
	"github.com/karmine05/fleet-hound/internal/enrich"
	"github.com/karmine05/fleet-hound/internal/fleet"
	"github.com/karmine05/fleet-hound/internal/graphdb"
	"github.com/karmine05/fleet-hound/internal/ingest"
	"github.com/karmine05/fleet-hound/internal/snapshot"
	"github.com/karmine05/fleet-hound/internal/workerutil"
)

// ErrAlreadyRunning replaces EtlAlreadyRunning: the ETL flock is held by
// another process.
var ErrAlreadyRunning = errors.New("etl: already running (lock held)")

// DefaultLockPath is _DEFAULT_LOCK_PATH.
const DefaultLockPath = ".etl.lock"

// watermarkSkewMargin is _WATERMARK_SKEW_MARGIN.
const watermarkSkewMargin = 5 * time.Minute

// compactLayout is _now_compact's "%Y-%m-%dT%H:%M:%S.%fZ".
const compactLayout = "2006-01-02T15:04:05.000000Z"

// Config replaces the ETLConfig dataclass. Zero values are NOT the python
// defaults; build with NewConfig and override.
type Config struct {
	FleetURL    string
	MemgraphURI string
	APIToken    string // "" = None
	Email       string
	Password    string
	Insecure    bool
	Debug       bool
	TeamIDs     []int
	FullScan    bool
	StatePath   string // ".state.json"
	SnapshotDir string // "config/snapshots"

	SnapshotRetainDays int // env SNAPSHOT_RETAIN_DAYS (30)
	SnapshotRetainMax  int // env SNAPSHOT_RETAIN_MAX (5000)

	EnrichLimit            int      // 250; 0 = python None (no limit)
	EnrichTargetNames      []string // nil = None
	SkipEnrichment         bool
	SkipSnapshot           bool
	SkipLabels             bool
	SkipAllLabelBuiltins   bool
	LabelReapAgeSeconds    int    // 7 days
	LockPath               string // "" = None -> "<dir of StatePath>/.etl.lock" (cwd default)
	SupplementLabelOrphans bool
	SupplementOrphanCap    int // 200
	SkipSoftwareReap       bool
	SkipHostReap           bool
	HostReapAgeSeconds     int // env HOST_REAP_AGE_DAYS (7) * 86400
}

// NewConfig returns a Config with the python dataclass defaults.
func NewConfig(fleetURL, memgraphURI string) Config {
	return Config{
		FleetURL: fleetURL, MemgraphURI: memgraphURI,
		StatePath: ".state.json", SnapshotDir: "config/snapshots",
		SnapshotRetainDays:  config.Int("SNAPSHOT_RETAIN_DAYS", 30),
		SnapshotRetainMax:   config.Int("SNAPSHOT_RETAIN_MAX", 5000),
		EnrichLimit:         250,
		LabelReapAgeSeconds: 7 * 24 * 60 * 60,
		SupplementOrphanCap: 200,
		HostReapAgeSeconds:  config.Int("HOST_REAP_AGE_DAYS", 7) * 24 * 60 * 60,
	}
}

// Result replaces the ETLResult dataclass. Pointer fields are python
// Optional (nil = None).
type Result struct {
	StartedISO            string
	FinishedISO           string
	DurationSec           float64
	HostsExtracted        int
	UsersExtracted        int
	TeamsSynced           []int
	FullScan              bool
	SnapshotPath          *string
	EnrichmentAttempted   bool
	EnrichmentError       *string
	SnapshotError         *string
	Error                 *string
	LabelSyncAttempted    bool
	LabelSyncError        *string
	LastLabelSyncISO      *string
	LabelSyncStats        map[string]any
	SkippedDueToLock      bool
	LabelOrphanCount      int
	LabelOrphansFetched   int
	SoftwareReapAttempted bool
	SoftwareReapStats     map[string]any
	SoftwareReapError     *string
	HostReapAttempted     bool
	HostReapStats         map[string]any
	HostReapError         *string
	FailedHostCount       int
}

func strOrNil(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func mapOrNil(m map[string]any) any {
	if m == nil {
		return nil
	}
	return m
}

func ptr(s string) *string { return &s }

// AsDict replaces ETLResult.as_dict(): same keys, duration rounded to 3dp,
// nil pointers/maps as JSON null, TeamsSynced never null ([]).
func (r *Result) AsDict() map[string]any {
	teams := r.TeamsSynced
	if teams == nil {
		teams = []int{}
	}
	return map[string]any{
		"started_iso":             r.StartedISO,
		"finished_iso":            r.FinishedISO,
		"duration_sec":            math.RoundToEven(r.DurationSec*1000) / 1000,
		"hosts_extracted":         r.HostsExtracted,
		"users_extracted":         r.UsersExtracted,
		"teams_synced":            teams,
		"full_scan":               r.FullScan,
		"snapshot_path":           strOrNil(r.SnapshotPath),
		"enrichment_attempted":    r.EnrichmentAttempted,
		"enrichment_error":        strOrNil(r.EnrichmentError),
		"snapshot_error":          strOrNil(r.SnapshotError),
		"error":                   strOrNil(r.Error),
		"label_sync_attempted":    r.LabelSyncAttempted,
		"label_sync_error":        strOrNil(r.LabelSyncError),
		"last_label_sync_iso":     strOrNil(r.LastLabelSyncISO),
		"label_sync_stats":        mapOrNil(r.LabelSyncStats),
		"skipped_due_to_lock":     r.SkippedDueToLock,
		"label_orphan_count":      r.LabelOrphanCount,
		"label_orphans_fetched":   r.LabelOrphansFetched,
		"software_reap_attempted": r.SoftwareReapAttempted,
		"software_reap_stats":     mapOrNil(r.SoftwareReapStats),
		"software_reap_error":     strOrNil(r.SoftwareReapError),
		"host_reap_attempted":     r.HostReapAttempted,
		"host_reap_stats":         mapOrNil(r.HostReapStats),
		"host_reap_error":         strOrNil(r.HostReapError),
		"failed_host_count":       r.FailedHostCount,
	}
}

// LoadState replaces load_state(path): parsed .state.json or {} (never fails).
func LoadState(path string) map[string]any {
	data, err := os.ReadFile(path) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("etl: ignoring unreadable state file", "path", path, "err", err)
		}
		return map[string]any{}
	}
	v, err := graphdb.DecodeJSON(data)
	if err != nil {
		slog.Warn("etl: ignoring unreadable state file", "path", path, "err", err)
		return map[string]any{}
	}
	m, ok := v.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return m
}

// SaveState replaces save_state(path, state): atomic write (temp
// "<name>.*.tmp" in the same dir, fsync, 0600, rename), indent=2 JSON.
// Python logged and swallowed failures; Go logs and returns the error.
func SaveState(path string, state map[string]any) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err == nil {
		err = workerutil.AtomicWriteFile(path, data, filepath.Base(path)+".")
	}
	if err != nil {
		slog.Warn("etl: failed to persist state", "path", path, "err", err)
		return fmt.Errorf("save state %s: %w", path, err)
	}
	return nil
}

// pyInt is python int(x) for the JSON value shapes a state file can hold.
func pyInt(v any) (int, bool) {
	switch t := v.(type) {
	case int64:
		return int(t), true
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return 0, false
		}
		return int(t), true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(t))
		return n, err == nil
	}
	return 0, false
}

// LoadFullScanCadence replaces load_full_scan_cadence(state_path):
// (cycles_since_full_scan, last_full_scan_iso; "" = None). Never fails.
func LoadFullScanCadence(statePath string) (int, string) {
	state := LoadState(statePath)
	cycles := 0
	if raw, ok := state["cycles_since_full_scan"]; ok {
		if n, ok := pyInt(raw); ok {
			cycles = n
		}
	}
	last, _ := state["last_full_scan_iso"].(string)
	return cycles, last
}

// SaveFullScanCadence replaces save_full_scan_cadence(state_path, ...):
// read-modify-write preserving other keys.
func SaveFullScanCadence(statePath string, cyclesSinceFullScan int, lastFullScanISO string) error {
	state := LoadState(statePath)
	state["cycles_since_full_scan"] = cyclesSinceFullScan
	state["last_full_scan_iso"] = lastFullScanISO
	return SaveState(statePath, state)
}

// parseISO is datetime.fromisoformat(s.replace("Z", "+00:00")) for the
// shapes fleet-hound writes. A value without an offset is taken as UTC
// (python would have raised TypeError comparing naive with aware).
func parseISO(s string) (time.Time, bool) {
	s = strings.ReplaceAll(s, "Z", "+00:00")
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02T15:04Z07:00",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	for _, layout := range []string{"2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999", "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// ShouldForceFullScan replaces should_force_full_scan(...): (force, reason)
// with reason "count", "elapsed" or "" (None). now is injectable.
func ShouldForceFullScan(cyclesSinceFullScan int, lastFullScanISO string, fullScanEvery int, intervalSec float64, now time.Time) (bool, string) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	// 0 disables periodic full scans, including the elapsed safety net
	// (its threshold would collapse to 0 and force every cycle).
	if fullScanEvery <= 0 {
		return false, ""
	}
	if cyclesSinceFullScan >= fullScanEvery {
		return true, "count"
	}
	threshold := float64(fullScanEvery) * intervalSec * 1.5
	if lastFullScanISO == "" {
		return true, "elapsed"
	}
	last, ok := parseISO(lastFullScanISO)
	if !ok {
		return true, "elapsed" // unparseable ISO -> treat as never ran
	}
	if now.Sub(last).Seconds() >= threshold {
		return true, "elapsed"
	}
	return false, ""
}

// etlFileLock replaces _etl_file_lock: mkdir parent, open 0600, flock
// EX|NB, truncate + write "<pid>\n" + fsync. Release by closing the file
// (python unlocked then closed). Held lock -> error wrapping ErrAlreadyRunning.
func etlFileLock(lockPath string) (*os.File, error) {
	if parent := filepath.Dir(lockPath); parent != "" {
		if err := os.MkdirAll(parent, 0o750); err != nil {
			return nil, fmt.Errorf("etl lock dir: %w", err)
		}
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		return nil, fmt.Errorf("etl lock open: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("another ETL is in progress (lock held: %s): %w", lockPath, ErrAlreadyRunning)
		}
		return nil, fmt.Errorf("etl lock flock: %w", err)
	}
	if err := f.Truncate(0); err == nil {
		if _, err := f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); err == nil {
			_ = f.Sync()
		}
	}
	return f, nil
}

func releaseLock(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	f.Close()
}

// resolveToken replaces _resolve_token.
func resolveToken(ctx context.Context, cfg Config) string {
	if cfg.APIToken != "" {
		slog.Info("etl: using API token authentication")
		return cfg.APIToken
	}
	if cfg.Email != "" && cfg.Password != "" {
		slog.Info("etl: authenticating with email/password (API token preferred)")
		auth := &fleet.Authenticator{FleetURL: cfg.FleetURL, Verify: !cfg.Insecure, TimeoutSec: 15}
		token, err := auth.Login(ctx, cfg.Email, cfg.Password, cfg.Debug)
		if err != nil || token == "" {
			slog.Error("etl: email/password login failed")
			return ""
		}
		return token
	}
	slog.Error("etl: no Fleet credentials supplied (FLEET_API_TOKEN or FLEET_EMAIL/FLEET_PASSWORD)")
	return ""
}

func (r *Result) finish(t0 time.Time) *Result {
	r.FinishedISO = app.PyISO(time.Now())
	r.DurationSec = time.Since(t0).Seconds()
	return r
}

// Run replaces run_etl(cfg): one Observe->Orient cycle. Never fails; errors
// are encoded in the Result (lock contention sets SkippedDueToLock).
func Run(ctx context.Context, cfg Config) *Result {
	t0 := time.Now()
	started := app.PyISO(t0)
	result := &Result{StartedISO: started, FinishedISO: started, FullScan: cfg.FullScan, TeamsSynced: []int{}}

	if cfg.FleetURL == "" {
		result.Error = ptr("FLEET_URL is required")
		return result.finish(t0)
	}
	if len(cfg.TeamIDs) == 0 {
		// Never default to "every team": the operator must pick the scope.
		result.Error = ptr("No Fleet teams selected; pass --teams or set OODA_TEAMS")
		return result.finish(t0)
	}
	token := resolveToken(ctx, cfg)
	if token == "" {
		result.Error = ptr("Fleet authentication failed")
		return result.finish(t0)
	}

	// Lock path: explicit cfg.LockPath > sibling of state file > cwd default.
	lockPath := cfg.LockPath
	if lockPath == "" {
		lockPath = filepath.Join(filepath.Dir(cfg.StatePath), DefaultLockPath)
	}
	lock, err := etlFileLock(lockPath)
	if err != nil {
		if errors.Is(err, ErrAlreadyRunning) {
			msg := fmt.Sprintf("another ETL is in progress (lock held: %s)", lockPath)
			slog.Warn("etl: " + msg + " — skipping this cycle")
			result.SkippedDueToLock = true
			result.Error = ptr(msg)
		} else {
			// python let a non-EAGAIN OSError escape run_etl; Go keeps the
			// "never fails" contract and reports it in the result.
			result.Error = ptr(err.Error())
		}
		return result.finish(t0)
	}
	defer releaseLock(lock)

	user, pass, _ := config.MemgraphAuth()
	db := graphdb.New(cfg.MemgraphURI, user, pass)
	// Cleanup must close the driver even when ctx is already cancelled.
	defer db.Close(context.Background())

	if err := runLocked(ctx, cfg, token, db, result); err != nil {
		slog.Error("etl: cycle failed", "err", err)
		result.Error = ptr(err.Error())
	}
	return result.finish(t0)
}

// stringMap keeps the string values of a JSON object (team_syncs).
func stringMap(v any) map[string]string {
	out := map[string]string{}
	m, _ := v.(map[string]any)
	for k, x := range m {
		if s, ok := x.(string); ok {
			out[k] = s
		}
	}
	return out
}

// runLocked is _run_etl_locked. A returned error is python's outer
// `except Exception` (result.error set by the caller).
func runLocked(ctx context.Context, cfg Config, token string, db *graphdb.DB, result *Result) error {
	state := LoadState(cfg.StatePath)
	// A full scan ignores per-team watermarks too: the host reap treats every
	// host it didn't see as gone.
	sinceMap := map[string]string{}
	globalSince := ""
	if !cfg.FullScan {
		sinceMap = stringMap(state["team_syncs"])
		globalSince, _ = state["last_run_timestamp"].(string)
	}
	now := time.Now().UTC()
	currentTS := now.Format(compactLayout)
	// Watermark is compared against Fleet's DB clock; back it off so hosts
	// updated within a few minutes of clock skew are re-fetched, not skipped.
	watermarkTS := now.Add(-watermarkSkewMargin).Format(compactLayout)

	extractor := fleet.NewExtractor(cfg.FleetURL, token, !cfg.Insecure, cfg.Debug)
	slog.Info("etl: extracting hosts", "full_scan", cfg.FullScan, "since", globalSince, "teams", cfg.TeamIDs)

	users, err := extractor.ExtractAllUsers(ctx)
	if err != nil {
		return err
	}
	result.UsersExtracted = len(users)

	// Streaming: one page (~500 hosts) at a time so memory is bounded by page
	// size, not fleet size. truncErr records a mid-walk failure.
	hostsSeen := 0
	var truncErr error
	hosts := func(yield func(map[string]any) bool) {
		for page, err := range extractor.ExtractHostPages(ctx, cfg.TeamIDs, globalSince, sinceMap) {
			if err != nil {
				truncErr = err
				return
			}
			for _, h := range page {
				hostsSeen++
				if !yield(h) {
					return
				}
			}
		}
	}
	slog.Info("etl: extracted users; host extraction will stream", "users", len(users))

	// Label payload + membership are fetched before ingest; the graph sync
	// runs after it.
	var labels []map[string]any
	memberMap := map[int64][]int64{}
	if !cfg.SkipLabels {
		labels, err = extractor.ExtractLabels(ctx, cfg.SkipAllLabelBuiltins)
		if err != nil {
			slog.Warn("etl: label pre-fetch failed", "err", err)
			labels, memberMap = nil, map[int64][]int64{}
		} else {
			if len(labels) == 0 {
				slog.Info("etl: /labels returned no labels (empty or filtered)")
			}
			for _, lbl := range labels {
				if lbl["id"] == nil {
					continue
				}
				lid, ok := graphdb.AsInt64(lbl["id"])
				if !ok {
					continue
				}
				members, ok := extractor.ExtractLabelHostMembership(ctx, lid)
				if !ok {
					// Fetch failed: leave the label out of memberMap so sync
					// keeps its existing edges instead of wiping them.
					continue
				}
				ids := make([]int64, 0, len(members))
				for _, m := range members {
					if m["id"] == nil {
						continue
					}
					if id, ok := graphdb.AsInt64(m["id"]); ok {
						ids = append(ids, id)
					}
				}
				memberMap[lid] = ids
			}
		}
	}

	slog.Info("etl: ingesting into Memgraph", "uri", cfg.MemgraphURI)
	in := ingest.New(db)
	if err := in.CreateConstraints(ctx); err != nil {
		return fmt.Errorf("create constraints: %w", err)
	}
	ingestErr := in.CreateGraphRelationships(ctx, hosts, users)
	if truncErr != nil {
		// python: the generator's RuntimeError escaped ingest and failed the
		// cycle before label sync / reaps / snapshot; the watermark is held.
		return truncErr
	}
	if ingestErr != nil {
		return fmt.Errorf("ingest hosts: %w", ingestErr)
	}
	result.HostsExtracted = hostsSeen

	// Orphan = label member with no :Host node in the graph.
	allIDs := map[int64]struct{}{}
	for _, ids := range memberMap {
		for _, id := range ids {
			allIDs[id] = struct{}{}
		}
	}
	sortedIDs := make([]int64, 0, len(allIDs))
	for id := range allIDs {
		sortedIDs = append(sortedIDs, id)
	}
	sort.Slice(sortedIDs, func(i, j int) bool { return sortedIDs[i] < sortedIDs[j] })
	rows, err := db.Query(ctx,
		"MATCH (h:Host) WHERE h.fleet_host_id IN $ids RETURN h.fleet_host_id AS id",
		map[string]any{"ids": sortedIDs})
	if err != nil {
		return fmt.Errorf("label orphan lookup: %w", err)
	}
	present := map[int64]struct{}{}
	for _, r := range rows {
		if id, ok := graphdb.AsInt64(r["id"]); ok && r["id"] != nil {
			present[id] = struct{}{}
		}
	}
	var orphans []int64
	for _, id := range sortedIDs {
		if _, ok := present[id]; !ok {
			orphans = append(orphans, id)
		}
	}
	result.LabelOrphanCount = len(orphans)
	slog.Info("etl: label orphan ids detected (host ids in Fleet membership with no :Host node)", "count", len(orphans))

	if cfg.SupplementLabelOrphans && len(orphans) > 0 {
		toFetch := orphans
		if limit := cfg.SupplementOrphanCap; len(orphans) > limit {
			toFetch = orphans[:max(limit, 0)]
			slog.Warn("etl: orphan supplement capped; remaining will be fetched in subsequent cycles",
				"cap", cfg.SupplementOrphanCap, "total", len(orphans))
		}
		var supplement []map[string]any
		for _, oid := range toFetch {
			if h := extractor.ExtractHostByID(ctx, oid); h != nil {
				supplement = append(supplement, h)
			}
		}
		if len(supplement) > 0 {
			seq := func(yield func(map[string]any) bool) {
				for _, h := range supplement {
					if !yield(h) {
						return
					}
				}
			}
			if err := in.CreateGraphRelationships(ctx, seq, users); err != nil {
				return fmt.Errorf("ingest orphan hosts: %w", err)
			}
			result.HostsExtracted = hostsSeen + len(supplement)
		}
		result.LabelOrphansFetched = len(supplement)
		slog.Info("etl: supplement fetched orphan hosts", "fetched", len(supplement), "requested", len(toFetch))
	}

	// Label sync: best-effort, never fails the cycle.
	if !cfg.SkipLabels {
		result.LabelSyncAttempted = true
		syncISO := app.PyISO(time.Now())
		stats, err := in.SyncLabelsWithMembership(ctx, labels, memberMap, syncISO, cfg.LabelReapAgeSeconds)
		if err != nil {
			msg := err.Error()
			slog.Warn("etl: label sync failed", "err", msg)
			result.LabelSyncError = ptr(msg)
			if err := in.MarkLabelSyncFailure(ctx, msg); err != nil {
				slog.Warn("etl: failed to mark label-sync failure on existing Label nodes", "err", err)
			}
		} else {
			result.LastLabelSyncISO = ptr(syncISO)
			result.LabelSyncStats = stats.AsDict()
			slog.Info("etl: label sync ok", "seen", stats.LabelsSeen, "unchanged", stats.LabelsUnchanged,
				"resynced", stats.LabelsResynced, "reaped", stats.LabelsReaped,
				"edges_added", stats.EdgesCreated, "edges_deleted", stats.EdgesDeleted,
				"orphan_members", stats.OrphanMembers)
		}
	}

	// Host reap: full-scan cycles only (delta cycles don't refresh quiet hosts).
	if cfg.FullScan && !cfg.SkipHostReap {
		result.HostReapAttempted = true
		stats, err := in.ReapStaleHosts(ctx, app.PyISO(time.Now()), cfg.HostReapAgeSeconds, cfg.TeamIDs)
		if err != nil {
			slog.Warn("etl: host reap failed", "err", err)
			result.HostReapError = ptr(err.Error())
		} else {
			result.HostReapStats = stats
			slog.Info("etl: host reap", "reaped", stats["reaped"], "cutoff_days", cfg.HostReapAgeSeconds/86400)
		}
	}

	// Unattached reap, after the host reap so its orphans go this cycle.
	if !cfg.SkipSoftwareReap {
		result.SoftwareReapAttempted = true
		stats, err := in.ReapUnattached(ctx)
		if err != nil {
			slog.Warn("etl: unattached reap failed", "err", err)
			result.SoftwareReapError = ptr(err.Error())
		} else {
			result.SoftwareReapStats = stats
			slog.Info("etl: unattached reap", "software", stats["software"], "labels", stats["labels"],
				"users", stats["users"], "hosts", stats["hosts"])
		}
	}

	result.FailedHostCount = len(in.FailedSoftwareHostIDs)

	// Orient: enrichment kick. Best-effort.
	if !cfg.SkipEnrichment {
		result.EnrichmentAttempted = true
		if err := enrich.RunCategorization(ctx, cfg.MemgraphURI, cfg.EnrichLimit, cfg.EnrichTargetNames); err != nil {
			slog.Warn("etl: enrichment failed", "err", err)
			result.EnrichmentError = ptr(err.Error())
		}
	}

	// Snapshot. Best-effort.
	if !cfg.SkipSnapshot {
		path, err := snapshot.WriteSnapshot(ctx, db, currentTS, cfg.SnapshotDir, cfg.SnapshotRetainMax, cfg.SnapshotRetainDays)
		if err != nil {
			slog.Warn("etl: snapshot write failed", "err", err)
			result.SnapshotError = ptr(err.Error())
		} else {
			result.SnapshotPath = ptr(path)
			slog.Info("etl: snapshot written", "path", path)
		}
	}

	// Advance watermarks only after a complete extract + ingest: a partial
	// software write must be re-sent by the next delta cycle.
	if result.FailedHostCount > 0 {
		if result.Error == nil {
			result.Error = ptr(fmt.Sprintf("Partial software writes on %d host(s); watermark not advanced", result.FailedHostCount))
		}
		slog.Warn("etl: skipping watermark save after partial software writes", "hosts", result.FailedHostCount)
		return nil
	}
	syncs, ok := state["team_syncs"].(map[string]any)
	if !ok {
		syncs = map[string]any{}
		state["team_syncs"] = syncs
	}
	for _, tid := range cfg.TeamIDs {
		syncs[strconv.Itoa(tid)] = watermarkTS
	}
	result.TeamsSynced = append([]int(nil), cfg.TeamIDs...)
	_ = SaveState(cfg.StatePath, state) // python logged and continued
	return nil
}
