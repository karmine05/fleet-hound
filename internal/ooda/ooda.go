// Package ooda ports webviz/ooda_worker.py: the leader-elected
// Observe -> Orient -> Decide -> Act supervisor.
//
// One process wins an flock and drives the loop (parallel ETL pulls would
// hammer Fleet and corrupt the state watermark). Cross-process state:
//
//   - STATUS file: every phase rewrites a small snapshot for /api/ooda/status.
//   - TRIGGER file: POST /api/ooda/trigger touches it; the loop wakes on mtime.
//   - CYCLES file: append-only JSONL of past cycles for /api/ooda/cycles.
//   - FINDINGS file: latest Decide output for /api/ooda/findings.
package ooda

import (
	"bufio"
	"bytes"
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
	"sync"
	"time"

	"github.com/karmine05/fleet-hound/internal/app"
	"github.com/karmine05/fleet-hound/internal/catalog"
	"github.com/karmine05/fleet-hound/internal/config"
	"github.com/karmine05/fleet-hound/internal/etl"
	"github.com/karmine05/fleet-hound/internal/graphdb"
	"github.com/karmine05/fleet-hound/internal/workerutil"
)

// CyclesKeep is _CYCLES_KEEP.
const CyclesKeep = 100

// Options are start_worker's keyword arguments.
type Options struct {
	IntervalSec          int // 1800
	FullScanEvery        int // 24 (0 disables periodic full scans)
	StatePath            string
	SnapshotDir          string
	LockPath             string
	TriggerPath          string
	StatusPath           string
	CyclesPath           string
	FindingsPath         string
	EnricherTriggerPath  string
	AuditLogPath         string
	ExtensionTriggerPath string // "" = python None (extension worker disabled)
	Enabled              bool
}

// Test seams (python tests monkeypatch the same names).
var (
	runETL = etl.Run
	nowFn  = time.Now
)

// phaseResult mirrors the PhaseResult dataclass; field order = asdict order.
type phaseResult struct {
	Name        string         `json:"name"`
	OK          bool           `json:"ok"`
	DurationSec float64        `json:"duration_sec"`
	Summary     map[string]any `json:"summary"`
	Error       *string        `json:"error"`
}

// cycleRecord mirrors the CycleRecord dataclass.
type cycleRecord struct {
	CycleID         int            `json:"cycle_id"`
	StartedISO      string         `json:"started_iso"`
	FinishedISO     string         `json:"finished_iso"`
	DurationSec     float64        `json:"duration_sec"`
	FullScan        bool           `json:"full_scan"`
	Phases          []phaseResult  `json:"phases"`
	FindingsSummary map[string]any `json:"findings_summary"`
	Error           *string        `json:"error"`
}

func strPtr(s string) *string { return &s }

// ---------------------------------------------------------------------------
// Shared status (mirrored to disk for cross-process reads)
// ---------------------------------------------------------------------------

type sharedStatus struct {
	path         string
	mu           sync.Mutex
	enabled      bool
	running      bool
	nextCycleID  int
	lastCycle    any
	lastPhase    any
	lastError    any
	cyclesTotal  int
	cyclesFailed int
}

// newSharedStatus loads prior counters. It deliberately does not flush: a
// non-leader would trample the leader's running=true.
func newSharedStatus(path string, enabled, running bool) *sharedStatus {
	prior := readJSONMap(path)
	return &sharedStatus{
		path: path, enabled: enabled, running: running,
		nextCycleID:  pyInt(prior["next_cycle_id"], 1),
		lastCycle:    prior["last_cycle"],
		lastPhase:    prior["last_phase"],
		lastError:    prior["last_error"],
		cyclesTotal:  pyInt(prior["cycles_total"], 0),
		cyclesFailed: pyInt(prior["cycles_failed"], 0),
	}
}

func (s *sharedStatus) flushLocked() {
	payload := map[string]any{
		"enabled":       s.enabled,
		"running":       s.running,
		"next_cycle_id": s.nextCycleID,
		"last_cycle":    s.lastCycle,
		"last_phase":    s.lastPhase,
		"last_error":    s.lastError,
		"cycles_total":  s.cyclesTotal,
		"cycles_failed": s.cyclesFailed,
	}
	if err := workerutil.AtomicWriteJSON(s.path, payload, ".ooda."); err != nil {
		slog.Warn("ooda: status flush failed", "err", err)
	}
}

// update applies fn under the lock and flushes (python update(**kwargs)).
func (s *sharedStatus) update(fn func(*sharedStatus)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
	s.flushLocked()
}

func (s *sharedStatus) setPhase(phase any) { s.update(func(s *sharedStatus) { s.lastPhase = phase }) }

func (s *sharedStatus) next() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextCycleID
}

func (s *sharedStatus) recordCycle(c cycleRecord) {
	s.update(func(s *sharedStatus) {
		s.nextCycleID = c.CycleID + 1
		s.lastCycle = c
		s.cyclesTotal++
		if c.Error != nil {
			s.cyclesFailed++
		}
	})
}

// ---------------------------------------------------------------------------
// Decide phase — read-only graph queries
// ---------------------------------------------------------------------------

const shadowITQuery = `
                    UNWIND $threshold_rows AS tr
                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host {platform: tr.platform})
                    WHERE any(x IN coalesce(s.sources, []) WHERE x IN $eligible)
                    WITH s, tr.platform AS platform, tr.threshold AS threshold,
                         count(DISTINCT h) AS host_count
                    WHERE host_count <= threshold
                    WITH s, min(host_count) AS host_count
                    RETURN s.name AS name,
                           s.category AS category,
                           host_count
                    ORDER BY (s.category IS NULL) DESC, host_count ASC, s.name ASC
                    LIMIT 50
                    `

// decidePhase computes Shadow IT outliers + graph totals. Returns
// (findings payload, summary for the cycle row).
func decidePhase(ctx context.Context, db *graphdb.DB) (map[string]any, map[string]any) {
	findings := map[string]any{
		"generated_iso": app.PyISO(nowFn()),
		"shadow_it":     []any{},
		"totals":        map[string]any{"hosts": 0, "users": 0, "software": 0, "uncategorized": 0},
	}
	summary := map[string]any{"shadow_it_count": 0, "uncategorized": 0, "hosts": 0}
	if db == nil || !db.Available(ctx) {
		return findings, summary
	}
	if err := decideQueries(ctx, db, findings, summary); err != nil {
		slog.Warn("ooda: decide queries failed", "err", err)
		findings["error"] = pyErrorName(err)
	}
	return findings, summary
}

func decideQueries(ctx context.Context, db *graphdb.DB, findings, summary map[string]any) error {
	count := func(q string) (int64, error) {
		rec, err := db.Single(ctx, q, nil)
		if err != nil {
			return 0, err
		}
		n, _ := graphdb.AsInt64(rec["c"])
		return n, nil
	}
	var totals [4]int64
	for i, q := range []string{
		"MATCH (h:Host) RETURN count(h) AS c",
		// Only nodes attached to a host are in the environment.
		"MATCH (u:User)-[:USES]->(:Host) RETURN count(DISTINCT u) AS c",
		"MATCH (s:Software)-[:INSTALLED_ON]->(:Host) RETURN count(DISTINCT s) AS c",
		"MATCH (s:Software)-[:INSTALLED_ON]->(:Host) WHERE s.category IS NULL " +
			"RETURN count(DISTINCT s) AS c",
	} {
		n, err := count(q)
		if err != nil {
			return fmt.Errorf("decide count: %w", err)
		}
		totals[i] = n
	}
	findings["totals"] = map[string]any{
		"hosts": totals[0], "users": totals[1], "software": totals[2], "uncategorized": totals[3],
	}
	summary["hosts"] = totals[0]
	summary["uncategorized"] = totals[3]

	// Same eligibility + per-platform threshold as /api/shadow-it so Decide
	// findings never disagree with the dashboard.
	thresholds, err := catalog.ComputePerPlatformThresholds(ctx, db, 0)
	if err != nil {
		return fmt.Errorf("decide thresholds: %w", err)
	}
	if len(thresholds) == 0 {
		findings["shadow_it"] = []any{}
		summary["shadow_it_count"] = 0
		return nil
	}
	// UNWIND a list of {platform, threshold}: Memgraph map indexing by a
	// variable key is not guaranteed across 2.x/3.x.
	platforms := make([]string, 0, len(thresholds))
	for p := range thresholds {
		platforms = append(platforms, p)
	}
	sort.Strings(platforms)
	rowsIn := make([]any, 0, len(platforms))
	for _, p := range platforms {
		rowsIn = append(rowsIn, map[string]any{"platform": p, "threshold": int64(thresholds[p])})
	}
	rows, err := db.Query(ctx, shadowITQuery, map[string]any{
		"eligible":       catalog.ShadowITSourceList(),
		"threshold_rows": rowsIn,
	})
	if err != nil {
		return fmt.Errorf("decide shadow it: %w", err)
	}
	shadow := make([]any, 0, len(rows))
	for _, r := range rows {
		if !truthy(r["name"]) {
			continue
		}
		hc, _ := graphdb.AsInt64(r["host_count"])
		shadow = append(shadow, map[string]any{"name": r["name"], "category": r["category"], "host_count": hc})
	}
	findings["shadow_it"] = shadow
	summary["shadow_it_count"] = len(shadow)
	return nil
}

// pyErrorName approximates python type(exc).__name__ for driver errors.
func pyErrorName(err error) string {
	switch {
	case graphdb.IsClientError(err):
		return "ClientError"
	case graphdb.IsAuthError(err):
		return "AuthError"
	case graphdb.IsTransient(err):
		return "TransientError"
	case graphdb.IsServiceUnavailable(err):
		return "ServiceUnavailable"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "CancelledError"
	}
	return "Exception"
}

// ---------------------------------------------------------------------------
// Observe config
// ---------------------------------------------------------------------------

// resolveETLConfig replaces _resolve_etl_config. ok=false means the cycle
// cannot run (logged). OODA_TEAMS is required: never default to all teams.
func resolveETLConfig(memgraphURI, statePath, snapshotDir string, fullScan bool) (etl.Config, bool) {
	fleetURL := config.StrTrim("FLEET_URL", "")
	// Superset of python: *_FILE variants are honoured for the secrets.
	apiToken := config.ResolveSecret("FLEET_API_TOKEN", "")
	email := config.StrTrim("FLEET_EMAIL", "")
	password := config.ResolveSecret("FLEET_PASSWORD", "")
	teamsRaw := config.StrTrim("OODA_TEAMS", "")

	if fleetURL == "" {
		slog.Error("ooda: FLEET_URL is empty — cannot run cycle")
		return etl.Config{}, false
	}
	if apiToken == "" && (email == "" || password == "") {
		slog.Error("ooda: no Fleet credentials (FLEET_API_TOKEN or FLEET_EMAIL+FLEET_PASSWORD)")
		return etl.Config{}, false
	}
	teamIDs, err := parseTeamIDs(teamsRaw)
	if err != nil {
		slog.Error("ooda: OODA_TEAMS is not a comma-separated integer list — cannot run cycle")
		return etl.Config{}, false
	}
	if len(teamIDs) == 0 {
		// Never default to every team; the operator must choose the scope.
		slog.Error("ooda: OODA_TEAMS is empty — set the Fleet team IDs to scan")
		return etl.Config{}, false
	}

	cfg := etl.NewConfig(fleetURL, memgraphURI)
	cfg.APIToken = apiToken
	cfg.Email = email
	cfg.Password = password
	cfg.Insecure = config.Bool("INSECURE", false)
	cfg.Debug = config.Bool("DEBUG", false)
	cfg.TeamIDs = teamIDs
	cfg.FullScan = fullScan
	cfg.StatePath = statePath
	cfg.SnapshotDir = snapshotDir
	// Orient kicks the dedicated enricher; don't inline-enrich during ETL.
	cfg.SkipEnrichment = true
	cfg.SkipSnapshot = false
	return cfg, true
}

// parseTeamIDs is sorted({int(x.strip()) for x in raw.split(",") if x.strip()}).
func parseTeamIDs(raw string) ([]int, error) {
	seen := map[int]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("parse team id %q: %w", part, err)
		}
		seen[n] = struct{}{}
	}
	out := make([]int, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Ints(out)
	return out, nil
}

// ---------------------------------------------------------------------------
// Persistence helpers
// ---------------------------------------------------------------------------

func marshalCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// appendJSONL replaces _append_jsonl: 0600 so the bind-mounted cycles log
// (scan cadence + inventory metadata) is not world-readable.
func appendJSONL(path string, row any) {
	_ = os.MkdirAll(filepath.Dir(path), 0o750)
	data, err := marshalCompact(row)
	if err != nil {
		slog.Warn("ooda: cycles append failed", "err", err)
		return
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		slog.Warn("ooda: cycles append failed", "err", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		slog.Warn("ooda: cycles append failed", "err", err)
	}
}

// trimJSONL replaces _trim_jsonl: keep the last `keep` lines.
func trimJSONL(path string, keep int) {
	data, err := os.ReadFile(path) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		return
	}
	lines := strings.SplitAfter(string(data), "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	if len(lines) <= keep {
		return
	}
	tail := strings.Join(lines[len(lines)-keep:], "")
	f, err := os.CreateTemp(filepath.Dir(path), ".oodacy.*.tmp")
	if err != nil {
		slog.Warn("ooda: cycles trim failed", "err", err)
		return
	}
	tmp := f.Name()
	_, werr := f.WriteString(tail)
	cerr := f.Close()
	if werr == nil && cerr == nil {
		werr = os.Rename(tmp, path)
	}
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp)
		slog.Warn("ooda: cycles trim failed", "err", errors.Join(werr, cerr))
	}
}

// auditCycle replaces _audit_cycle. Written here rather than via
// app.AppendAudit to keep python's 0600 create mode (cycle telemetry).
func auditCycle(path string, c cycleRecord) {
	_ = os.MkdirAll(filepath.Dir(path), 0o750)
	phases := make([]string, len(c.Phases))
	for i, p := range c.Phases {
		mark := ":FAIL"
		if p.OK {
			mark = ":OK"
		}
		phases[i] = p.Name + mark
	}
	ok := "False"
	if c.Error == nil {
		ok = "True"
	}
	line := fmt.Sprintf("%s - OODA_CYCLE - id=%d ok=%s duration=%.1fs phases=%s shadow_it=%v uncategorized=%v\n",
		app.PyISO(nowFn()), c.CycleID, ok, c.DurationSec, strings.Join(phases, ","),
		getOr(c.FindingsSummary, "shadow_it_count", 0), getOr(c.FindingsSummary, "uncategorized", 0))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		slog.Warn("ooda: audit write failed", "err", err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		slog.Warn("ooda: audit write failed", "err", err)
	}
}

func getOr(m map[string]any, k string, def any) any {
	if v, ok := m[k]; ok {
		return v
	}
	return def
}

func touch(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	now := time.Now()
	return os.Chtimes(path, now, now)
}

func sinceSec(t time.Time) float64 { return time.Since(t).Seconds() }

// ---------------------------------------------------------------------------
// Loop
// ---------------------------------------------------------------------------

type loopState struct {
	cyclesSinceFullScan int
	lastFullScanISO     string // "" = None
}

func loop(ctx context.Context, db *graphdb.DB, st *sharedStatus, o Options) {
	lastTrigger := workerutil.TriggerMtime(o.TriggerPath)
	// Restore cadence from disk so restarts keep counting.
	var ls loopState
	ls.cyclesSinceFullScan, ls.lastFullScanISO = etl.LoadFullScanCadence(o.StatePath)
	for ctx.Err() == nil {
		runCycle(ctx, db, st, o, &ls)
		interval := time.Duration(max(1.0, float64(o.IntervalSec)) * float64(time.Second))
		lastTrigger = workerutil.SleepUntil(ctx, time.Now().Add(interval), o.TriggerPath, lastTrigger)
	}
	st.update(func(s *sharedStatus) { s.running = false })
	slog.Info("ooda: loop exited")
}

func saveCadence(o Options, ls *loopState) {
	if err := etl.SaveFullScanCadence(o.StatePath, ls.cyclesSinceFullScan, ls.lastFullScanISO); err != nil {
		slog.Warn("ooda: cadence save failed", "err", err)
	}
}

// runCycle runs one cycle. A cancelled ctx (shutdown) abandons the cycle
// without recording it, like python's daemon thread dying at exit; this keeps
// shutdown from clobbering findings with an empty result.
func runCycle(ctx context.Context, db *graphdb.DB, st *sharedStatus, o Options, ls *loopState) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("ooda: cycle panicked", "panic", r)
			st.update(func(s *sharedStatus) { s.lastPhase = nil; s.lastError = fmt.Sprint(r) })
		}
	}()
	cycleStarted := nowFn()
	cycleID := st.next()

	fullScan, reason := etl.ShouldForceFullScan(ls.cyclesSinceFullScan, ls.lastFullScanISO,
		o.FullScanEvery, float64(o.IntervalSec), nowFn())
	if fullScan {
		priorCycles, priorISO := ls.cyclesSinceFullScan, ls.lastFullScanISO
		ls.cyclesSinceFullScan = 0
		ls.lastFullScanISO = app.PyISO(nowFn())
		// Persist BEFORE the ETL so a mid-cycle crash doesn't loop full scans.
		saveCadence(o, ls)
		slog.Info(fmt.Sprintf("ooda: forcing full_scan (reason=%s, cycles=%d, last=%s)",
			pyNone(reason), priorCycles, pyNone(priorISO)))
	} else {
		ls.cyclesSinceFullScan++
		if ls.lastFullScanISO == "" {
			ls.lastFullScanISO = app.PyISO(nowFn())
		}
		saveCadence(o, ls)
	}

	var phases []phaseResult
	var cycleError *string

	// Phase 1 — Observe (in-process ETL: extract, ingest, snapshot).
	st.setPhase("observe")
	phaseStarted := time.Now()
	cfg, ok := resolveETLConfig(config.StrTrim("MEMGRAPH_URI", "bolt://memgraph:7687"),
		o.StatePath, o.SnapshotDir, fullScan)
	if !ok {
		err := "missing or invalid Fleet credentials"
		phases = append(phases, phaseResult{Name: "observe", OK: false, DurationSec: 0, Summary: map[string]any{}, Error: &err})
		cycleError = &err
	} else {
		res := runETL(ctx, cfg)
		if ctx.Err() != nil {
			return
		}
		teams := res.TeamsSynced
		if teams == nil {
			teams = []int{}
		}
		var snap any
		if res.SnapshotPath != nil {
			snap = *res.SnapshotPath
		}
		phases = append(phases, phaseResult{
			Name: "observe", OK: res.Error == nil, DurationSec: sinceSec(phaseStarted),
			Summary: map[string]any{
				"hosts_extracted": res.HostsExtracted,
				"users_extracted": res.UsersExtracted,
				"snapshot_path":   snap,
				"full_scan":       res.FullScan,
				"teams_synced":    teams,
			},
			Error: res.Error,
		})
		if res.Error != nil {
			cycleError = res.Error
		}
	}

	// Phase 2 — Orient: wake the enricher and the extension worker.
	st.setPhase("orient")
	phaseStarted = time.Now()
	var orientErrs []string
	for _, t := range [][2]string{{"enricher", o.EnricherTriggerPath}, {"extension", o.ExtensionTriggerPath}} {
		if t[1] == "" {
			continue
		}
		if err := touch(t[1]); err != nil {
			msg := fmt.Sprintf("%s trigger failed: %v", t[0], err)
			orientErrs = append(orientErrs, msg)
			slog.Warn("ooda: " + msg)
		}
	}
	var orientErr *string
	if len(orientErrs) > 0 {
		orientErr = strPtr(strings.Join(orientErrs, "; "))
	}
	var extTrigger any
	if o.ExtensionTriggerPath != "" {
		extTrigger = o.ExtensionTriggerPath
	}
	phases = append(phases, phaseResult{
		Name: "orient", OK: orientErr == nil, DurationSec: sinceSec(phaseStarted),
		Summary: map[string]any{"enricher_trigger_path": o.EnricherTriggerPath, "extension_trigger_path": extTrigger},
		Error:   orientErr,
	})

	// Phase 3 — Decide: read-only graph queries, write findings.
	st.setPhase("decide")
	phaseStarted = time.Now()
	findings, findingsSummary := decidePhase(ctx, db)
	if ctx.Err() != nil {
		return
	}
	findings["cycle_id"] = cycleID
	var decideErr *string
	if err := workerutil.AtomicWriteJSON(o.FindingsPath, findings, ".ooda."); err != nil {
		decideErr = strPtr(fmt.Sprintf("findings write failed: %v", err))
		slog.Warn("ooda: " + *decideErr)
	}
	phases = append(phases, phaseResult{
		Name: "decide", OK: decideErr == nil, DurationSec: sinceSec(phaseStarted),
		Summary: findingsSummary, Error: decideErr,
	})

	// Phase 4 — Act: cycle history + audit. Auto-mutating actions are
	// intentionally absent; the operator drives writes via authorize-software.
	st.setPhase("act")
	phaseStarted = time.Now()
	cycleFinished := nowFn()
	duration := cycleFinished.Sub(cycleStarted).Seconds()
	phases = append(phases, phaseResult{
		Name: "act", OK: true, DurationSec: sinceSec(phaseStarted),
		Summary: map[string]any{"cycle_id": cycleID},
	})
	record := cycleRecord{
		CycleID: cycleID, StartedISO: app.PyISO(cycleStarted), FinishedISO: app.PyISO(cycleFinished),
		DurationSec: math.Round(duration*1000) / 1000, FullScan: fullScan,
		Phases: phases, FindingsSummary: findingsSummary, Error: cycleError,
	}
	// The helpers log and swallow their own I/O errors (python caught OSError
	// inside them), so the act phase stays ok.
	appendJSONL(o.CyclesPath, record)
	trimJSONL(o.CyclesPath, CyclesKeep)
	auditCycle(o.AuditLogPath, record)

	st.recordCycle(record)
	var lastErr any
	if cycleError != nil {
		lastErr = *cycleError
	}
	st.update(func(s *sharedStatus) { s.lastPhase = nil; s.lastError = lastErr })
}

func pyNone(s string) string {
	if s == "" {
		return "None"
	}
	return s
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Start replaces start_worker(driver_provider, ...). Disabled or not leader
// returns (nil, nil) without running the loop.
func Start(ctx context.Context, db *graphdb.DB, o Options) (*workerutil.Handle, error) {
	st := newSharedStatus(o.StatusPath, o.Enabled, false)
	if !o.Enabled {
		slog.Info("ooda: disabled via OODA_ENABLED=false")
		return nil, nil
	}
	lock := workerutil.TryAcquireLock(o.LockPath, "ooda")
	if lock == nil {
		slog.Info("ooda: another worker holds the lock; this worker will not run the loop", "lock", o.LockPath)
		return nil, nil
	}
	// Leader only — safe to publish state to disk.
	st.update(func(s *sharedStatus) { s.running = true })
	h := workerutil.Go(ctx, lock, func(ctx context.Context) { loop(ctx, db, st, o) })
	slog.Info(fmt.Sprintf("ooda: started (interval=%ds, full_scan_every=%d, lock=%s)",
		o.IntervalSec, o.FullScanEvery, o.LockPath))
	return h, nil
}

// ReadStatus replaces read_status(path).
func ReadStatus(statusPath string) map[string]any {
	data := readJSONMap(statusPath)
	return map[string]any{
		"enabled":       truthy(getOr(data, "enabled", false)),
		"running":       truthy(getOr(data, "running", false)),
		"next_cycle_id": pyInt(data["next_cycle_id"], 1),
		"last_phase":    data["last_phase"],
		"last_error":    data["last_error"],
		"cycles_total":  pyInt(data["cycles_total"], 0),
		"cycles_failed": pyInt(data["cycles_failed"], 0),
		"last_cycle":    data["last_cycle"],
	}
}

// FireTrigger replaces fire_trigger(path, cooldown_sec=60).
func FireTrigger(triggerPath string, cooldownSec float64) (bool, float64) {
	return workerutil.FireTrigger(triggerPath, cooldownSec, "ooda")
}

// ReadFindings replaces read_findings(path).
func ReadFindings(findingsPath string) map[string]any {
	if m, ok := readJSON(findingsPath).(map[string]any); ok {
		return m
	}
	return map[string]any{"generated_iso": nil, "shadow_it": []any{},
		"totals": map[string]any{"hosts": 0, "users": 0, "software": 0, "uncategorized": 0}}
}

// ReadCycles replaces read_cycles(path, limit): the last limit rows, newest
// first; [] on error or limit <= 0. Malformed lines are skipped.
func ReadCycles(cyclesPath string, limit int) []map[string]any {
	out := []map[string]any{}
	if limit <= 0 {
		return out
	}
	f, err := os.Open(cyclesPath) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		return out
	}
	defer f.Close()
	ring := make([]any, 0, limit)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		v, err := graphdb.DecodeJSON(line)
		if err != nil {
			continue
		}
		if len(ring) == limit {
			ring = ring[1:]
		}
		ring = append(ring, v)
	}
	if sc.Err() != nil {
		return []map[string]any{}
	}
	for i := len(ring) - 1; i >= 0; i-- {
		// python returned whatever json.loads produced; non-objects are not
		// valid cycle rows and the API shape is a list of objects.
		if m, ok := ring[i].(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// small python-semantics helpers
// ---------------------------------------------------------------------------

func readJSON(path string) any {
	data, err := os.ReadFile(path) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		return nil
	}
	v, err := graphdb.DecodeJSON(data)
	if err != nil {
		return nil
	}
	return v
}

func readJSONMap(path string) map[string]any {
	if m, ok := readJSON(path).(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// pyInt is int(v) with def for missing/None/unconvertible values.
func pyInt(v any, def int) int {
	switch t := v.(type) {
	case nil:
		return def
	case bool:
		if t {
			return 1
		}
		return 0
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n
		}
		return def
	}
	if n, ok := graphdb.AsInt64(v); ok {
		return int(n)
	}
	return def
}

// truthy is python bool(v).
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
