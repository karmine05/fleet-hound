// Package enrich ports webviz/enrich_worker.py (the leader-elected Wikipedia
// enricher) and categorize_software.py (catalog -> Wikipedia lookup chain,
// run_categorization, the `fleethound categorize` CLI). Owner: agent D.
package enrich

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/karmine05/fleet-hound/internal/app"
	"github.com/karmine05/fleet-hound/internal/catalog"
	"github.com/karmine05/fleet-hound/internal/config"
	"github.com/karmine05/fleet-hound/internal/graphdb"
	"github.com/karmine05/fleet-hound/internal/workerutil"
)

// Python defaults (LOCK_PATH_DEFAULT etc.); the server passes config values.
const (
	LockPathDefault    = "/tmp/fleet-hound-enricher.lock"
	TriggerPathDefault = "/tmp/fleet-hound-enricher.trigger"
)

// Options are start_worker's keyword arguments.
type Options struct {
	IntervalSec int // 300
	BatchSize   int // 25
	Parallelism int // 4
	LockPath    string
	TriggerPath string
	StatusPath  string // <CONFIG_DIR>/enricher_status.json
	Enabled     bool
}

func (o *Options) defaults() {
	if o.IntervalSec == 0 {
		o.IntervalSec = 300
	}
	if o.BatchSize == 0 {
		o.BatchSize = 25
	}
	if o.LockPath == "" {
		o.LockPath = LockPathDefault
	}
	if o.TriggerPath == "" {
		o.TriggerPath = TriggerPathDefault
	}
	if o.StatusPath == "" {
		o.StatusPath = config.ConfigPath("enricher_status.json")
	}
}

const (
	cypherPickUncategorized = `
                MATCH (s:Software)
                WHERE s.category IS NULL
                  AND any(x IN s.sources WHERE x IN $eligible)
                  AND coalesce(s.kind, '') <> 'browser_extension'
                  AND (s.last_categorization_attempt_iso IS NULL
                       OR s.last_categorization_attempt_iso < $cutoff_iso)
                MATCH (s)-[:INSTALLED_ON]->(h:Host)
                WITH s.name AS name, COUNT(DISTINCT h) AS host_count
                RETURN name
                ORDER BY host_count ASC
                LIMIT $limit
                `
	cypherMarkMiss = `
                MATCH (s:Software {name: $name})
                SET s.last_categorization_attempt_iso = $now_iso,
                    s.categorization_attempts = coalesce(s.categorization_attempts, 0) + 1
                `
	cypherWriteCategories = `
                MATCH (s:Software {name: $name})
                SET s.category = $category,
                    s.wikidata_description = $desc,
                    s.last_categorized = datetime(),
                    s.enrich_gate_passed = true
                `
	cypherQueueRemaining = "MATCH (s:Software) WHERE s.category IS NULL RETURN count(s) AS c"
)

func nowISO() string { return app.PyISO(time.Now()) }

func cutoffISO() string {
	return app.PyISO(time.Now().Add(-time.Duration(FailureCooldownDays()) * 24 * time.Hour))
}

// nilIfEmpty maps Go "" back to python None for Cypher parameters.
func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nonNil keeps an empty category list as [] (python `list(c) if c else []`).
func nonNil(c []string) []string {
	if c == nil {
		return []string{}
	}
	return c
}

func pickUncategorized(ctx context.Context, db *graphdb.DB, batchSize int) []string {
	rows, err := db.Query(ctx, cypherPickUncategorized, map[string]any{
		"limit":    int64(batchSize),
		"eligible": catalog.ShadowITSourceList(),
		// Misses are stamped with an attempt time; without this cooldown the
		// same rarest-N misses are re-picked forever.
		"cutoff_iso": cutoffISO(),
	})
	if err != nil {
		if graphdb.IsRetryable(err) {
			slog.Warn("enricher: pick_uncategorized transient error", "err", err)
		} else {
			slog.Error("enricher: pick_uncategorized failed", "err", err)
		}
		return nil
	}
	var names []string
	for _, r := range rows {
		if n, ok := r["name"].(string); ok && n != "" {
			names = append(names, n)
		}
	}
	return names
}

func markMiss(ctx context.Context, db *graphdb.DB, name string) {
	if _, err := db.Exec(ctx, cypherMarkMiss, map[string]any{"name": name, "now_iso": nowISO()}); err != nil {
		slog.Warn("enricher: mark_miss failed", "name", name, "err", err)
	}
}

func writeCategories(ctx context.Context, db *graphdb.DB, name string, cats []string, desc string) bool {
	_, err := db.Exec(ctx, cypherWriteCategories, map[string]any{
		"name": name, "category": nonNil(cats), "desc": nilIfEmpty(desc),
	})
	if err != nil {
		if graphdb.IsRetryable(err) {
			slog.Warn("enricher: write_categories transient error", "name", name, "err", err)
		} else {
			slog.Error("enricher: write_categories failed", "name", name, "err", err)
		}
		return false
	}
	return true
}

// statusFile is the on-disk shape; field order matches the python dict.
type statusFile struct {
	Enabled               bool  `json:"enabled"`
	Running               bool  `json:"running"`
	LastTickISO           any   `json:"last_tick_iso"`
	ItemsCategorizedTotal int64 `json:"items_categorized_total"`
	LastError             any   `json:"last_error"`
}

// sharedStatus is _SharedStatus: in-process state mirrored to the status file
// for cross-process reads.
type sharedStatus struct {
	path string
	mu   sync.Mutex
	st   statusFile
}

func newSharedStatus(path string, enabled bool) *sharedStatus {
	prior := workerutil.ReadJSONMap(path)
	// Deliberately not flushed here: only the leader writes, so non-leaders
	// never trample the leader's running=true.
	return &sharedStatus{path: path, st: statusFile{
		Enabled:               enabled,
		LastTickISO:           prior["last_tick_iso"],
		ItemsCategorizedTotal: pyInt(prior["items_categorized_total"]),
		LastError:             prior["last_error"],
	}}
}

func (s *sharedStatus) flushLocked() {
	if err := workerutil.AtomicWriteJSON(s.path, s.st, ".enricher."); err != nil {
		slog.Warn("enricher: status flush failed", "err", err)
	}
}

func (s *sharedStatus) update(fn func(*statusFile)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.st)
	s.flushLocked()
}

func (s *sharedStatus) addEnriched(n int) {
	if n <= 0 {
		return
	}
	s.update(func(st *statusFile) { st.ItemsCategorizedTotal += int64(n) })
}

func (s *sharedStatus) tick(lastErr any) {
	s.update(func(st *statusFile) { st.LastTickISO, st.LastError = nowISO(), lastErr })
}

type hit struct {
	name string
	cats []string
	desc string
	miss bool // python (name, None, None)
}

// fetchBatch is _fetch_batch: resolves names with bounded parallelism, each
// lookup followed by a 0.2s per-goroutine pause toward the Wikipedia API.
// Transient failures are dropped (retried next tick without a cooldown).
func fetchBatch(ctx context.Context, client *http.Client, names []string, parallelism int) []hit {
	sem := make(chan struct{}, max(1, parallelism))
	out := make(chan hit, len(names))
	var wg sync.WaitGroup
	for _, n := range names {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					slog.Warn("enricher: lookup error", "name", name, "err", r)
				}
			}()
			res, cats, desc := getSoftwareInfo(ctx, name, client)
			sleepCtx(ctx, 200*time.Millisecond)
			if res == resultHit && (len(cats) > 0 || desc != "") {
				out <- hit{name: name, cats: cats, desc: desc}
				return
			}
			if res == resultHit || res == resultMiss { // HIT with no data counts as a miss
				out <- hit{name: name, miss: true}
			}
		}(n)
	}
	wg.Wait()
	close(out)
	var hits []hit
	for h := range out {
		hits = append(hits, h)
	}
	return hits
}

func runTick(ctx context.Context, db *graphdb.DB, status *sharedStatus, client *http.Client, o Options) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("enricher: tick failed", "err", r)
			status.tick(fmt.Sprint(r))
		}
	}()
	if _, err := db.Driver(ctx); err != nil {
		status.tick("memgraph driver unavailable")
		return
	}
	items := pickUncategorized(ctx, db, o.BatchSize)
	if len(items) > 0 {
		slog.Info(fmt.Sprintf("enricher: tick picked %d uncategorized items", len(items)))
	}
	enriched := 0
	for _, h := range fetchBatch(ctx, client, items, o.Parallelism) {
		if ctx.Err() != nil {
			break
		}
		if h.miss {
			markMiss(ctx, db, h.name)
			continue
		}
		if writeCategories(ctx, db, h.name, h.cats, h.desc) {
			enriched++
		}
	}
	status.addEnriched(enriched)
	status.tick(nil)
}

func loop(ctx context.Context, db *graphdb.DB, status *sharedStatus, o Options) {
	defer func() {
		status.update(func(st *statusFile) { st.Running = false })
		slog.Info("enricher: loop exited")
	}()
	lastTrigger := workerutil.TriggerMtime(o.TriggerPath)
	client := newHTTPClient()
	// One-shot per leader start: drop enrichments written before the
	// software-relevance gate (idempotent, cheap once clean).
	if _, err := db.Driver(ctx); err == nil {
		if purged, err := PurgeNonSoftwareDescriptions(ctx, db, false); err != nil {
			slog.Warn("enricher: description purge skipped", "err", err)
		} else if len(purged) > 0 {
			slog.Info(fmt.Sprintf("enricher: cleared %d non-software Wikipedia descriptions", len(purged)))
		}
	}
	for ctx.Err() == nil {
		started := time.Now()
		runTick(ctx, db, status, client, o)
		// Sleep until next tick OR until the trigger file mtime advances.
		wait := math.Max(1, float64(o.IntervalSec)-time.Since(started).Seconds())
		lastTrigger = workerutil.SleepUntil(ctx, time.Now().Add(time.Duration(wait*float64(time.Second))),
			o.TriggerPath, lastTrigger)
	}
}

// Start replaces start_worker(driver_provider, ...): when enabled and this
// process wins the flock on LockPath, writes running=true to StatusPath and
// runs the loop in a goroutine until ctx is cancelled or Stop. Disabled or
// not leader returns a nil *Handle and nil error (python returned a status
// object that never ran). db.Driver is the python driver_provider.
func Start(ctx context.Context, db *graphdb.DB, o Options) (*workerutil.Handle, error) {
	o.defaults()
	status := newSharedStatus(o.StatusPath, o.Enabled)
	if !o.Enabled {
		slog.Info("enricher: disabled via ENRICHER_ENABLED=false")
		return nil, nil
	}
	lock := workerutil.TryAcquireLock(o.LockPath, "enricher")
	if lock == nil {
		slog.Info(fmt.Sprintf("enricher: another worker holds %s; this worker will not run the loop", o.LockPath))
		return nil, nil
	}
	// Leader only: safe to publish state to disk.
	status.update(func(st *statusFile) { st.Running = true })
	h := workerutil.Go(ctx, lock, func(ctx context.Context) { loop(ctx, db, status, o) })
	slog.Info(fmt.Sprintf("enricher: started (interval=%ds, batch=%d, parallelism=%d, lock=%s, trigger=%s, status=%s)",
		o.IntervalSec, o.BatchSize, o.Parallelism, o.LockPath, o.TriggerPath, o.StatusPath))
	return h, nil
}

// pyTruthy is python bool(v) for JSON-decoded values.
func pyTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// pyInt is python int(v) for a JSON number (truncating floats); 0 otherwise.
func pyInt(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case bool:
		if x {
			return 1
		}
	}
	return 0
}

// ReadStatus replaces read_status(path): {"enabled","running",
// "last_tick_iso","items_categorized_total","last_error"} with defaults
// when the file is missing.
func ReadStatus(statusPath string) map[string]any {
	d := workerutil.ReadJSONMap(statusPath)
	return map[string]any{
		"enabled":                 pyTruthy(d["enabled"]),
		"running":                 pyTruthy(d["running"]),
		"last_tick_iso":           d["last_tick_iso"],
		"items_categorized_total": pyInt(d["items_categorized_total"]),
		"last_error":              d["last_error"],
	}
}

// FireTrigger replaces fire_trigger(path, cooldown_sec=30).
func FireTrigger(triggerPath string, cooldownSec float64) (bool, float64) {
	return workerutil.FireTrigger(triggerPath, cooldownSec, "enricher")
}

// QueueRemaining replaces queue_remaining(driver_provider): count of
// uncategorized eligible software; 0 when the DB is unavailable.
func QueueRemaining(ctx context.Context, db *graphdb.DB) int {
	if db == nil {
		return 0
	}
	rec, err := db.Single(ctx, cypherQueueRemaining, nil)
	if err != nil || rec == nil {
		return 0
	}
	n, _ := graphdb.AsInt64(rec["c"])
	return int(n)
}
