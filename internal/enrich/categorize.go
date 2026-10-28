package enrich

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/karmine05/fleet-hound/internal/catalog"
	"github.com/karmine05/fleet-hound/internal/config"
	"github.com/karmine05/fleet-hound/internal/graphdb"
)

const (
	cypherPurgeSelect = "MATCH (s:Software) WHERE s.wikidata_description IS NOT NULL " +
		"  AND s.enrich_gate_passed IS NULL " +
		"RETURN s.name AS name, s.wikidata_description AS description"
	cypherPurgeClear = "UNWIND $names AS n MATCH (s:Software {name: n}) " +
		"SET s.category = NULL, s.wikidata_description = NULL, " +
		"    s.last_categorized = NULL, s.last_categorization_attempt_iso = $now"
	cypherCandidates = `
                        MATCH (s:Software)-[:INSTALLED_ON]->(h:Host {platform: $platform})
                        WHERE s.category IS NULL
                          AND any(src IN coalesce(s.sources, []) WHERE src IN $shadow_it_sources)
                          AND coalesce(s.kind, '') <> 'browser_extension'
                          AND (s.last_categorization_attempt_iso IS NULL
                               OR s.last_categorization_attempt_iso < $cutoff_iso)
                        WITH s.name AS name,
                             coalesce(s.sources, []) AS sources,
                             coalesce(s.category, []) AS db_categories,
                             count(DISTINCT h) AS host_count
                        WHERE host_count <= $threshold
                        RETURN name, sources, db_categories, host_count
                        ORDER BY host_count ASC
                        `
	cypherCatalogHit = `
                            MATCH (s:Software {name: $name})
                            SET s.category = $category,
                                s.wikidata_description = $desc,
                                s.last_categorized = datetime(),
                                s.enrich_gate_passed = true,
                                s.last_categorization_attempt_iso = $now_iso,
                                s.categorization_attempts = coalesce(s.categorization_attempts, 0) + 1,
                                s.categorization_source = 'catalog'
                        `
	cypherWikiHit = `
                            MATCH (s:Software {name: $name})
                            SET s.category = $category,
                                s.wikidata_description = $desc,
                                s.last_categorized = datetime(),
                                s.enrich_gate_passed = true,
                                s.last_categorization_attempt_iso = $now_iso,
                                s.categorization_attempts = coalesce(s.categorization_attempts, 0) + 1,
                                s.categorization_source = 'wikipedia'
                        `
	cypherMiss = `
                            MATCH (s:Software {name: $name})
                            SET s.last_categorization_attempt_iso = $now_iso,
                                s.categorization_attempts = coalesce(s.categorization_attempts, 0) + 1
                        `
)

// PurgeNonSoftwareDescriptions is purge_non_software_descriptions: clears
// Wikipedia enrichments written before the software-hint gate that fail it
// (catalog names and gate-passed entries are kept), stamping an attempt time
// so the cooldown applies. Idempotent; returns the cleared names.
func PurgeNonSoftwareDescriptions(ctx context.Context, db *graphdb.DB, dryRun bool) ([]string, error) {
	rows, err := db.Query(ctx, cypherPurgeSelect, nil)
	if err != nil {
		return nil, fmt.Errorf("purge select: %w", err)
	}
	names := []string{}
	for _, r := range rows {
		name, _ := r["name"].(string)
		desc, _ := r["description"].(string)
		if _, _, ok := catalog.Lookup(name); ok {
			continue
		}
		if !softwareHintRE.MatchString(desc) {
			names = append(names, name)
		}
	}
	if len(names) > 0 && !dryRun {
		if _, err := db.Exec(ctx, cypherPurgeClear, map[string]any{"names": names, "now": nowISO()}); err != nil {
			return nil, fmt.Errorf("purge clear: %w", err)
		}
	}
	return names, nil
}

// runWithRetry is run_query_with_retry: 3 attempts, 0.5s*2^i between
// retryable failures. Returns (false, nil) when retries are exhausted (python
// logged and returned False) and a non-nil error for failures python raised.
func runWithRetry(ctx context.Context, db *graphdb.DB, cypher string, params map[string]any) (bool, error) {
	err := graphdb.Retry(ctx, 3, 500*time.Millisecond, false, graphdb.IsRetryable,
		func(ctx context.Context) error { _, err := db.Exec(ctx, cypher, params); return err })
	if err == nil {
		return true, nil
	}
	if graphdb.IsRetryable(err) {
		slog.Warn(fmt.Sprintf("query failed after %d attempts: %v", 3, err))
		return false, nil
	}
	return false, fmt.Errorf("categorize write: %w", err)
}

// memgraphAuth is _memgraph_auth: env first (config.MemgraphAuth, which also
// honours *_FILE), then the .env file, field by field.
func memgraphAuth() (string, string) {
	if u, p, ok := config.MemgraphAuth(); ok {
		return u, p
	}
	env := dotEnv()
	user := config.ResolveSecret("MEMGRAPH_USER", "")
	if user == "" {
		user = pyStrip(env["MEMGRAPH_USER"])
	}
	pwd := config.ResolveSecret("MEMGRAPH_PASSWORD", "")
	if pwd == "" {
		if f := pyStrip(env["MEMGRAPH_PASSWORD_FILE"]); f != "" {
			if b, err := os.ReadFile(f); err == nil { // #nosec G304 -- path from operator env/config, not request input
				pwd = pyStrip(string(b))
			}
		}
	}
	if pwd == "" {
		pwd = pyStrip(env["MEMGRAPH_PASSWORD"])
	}
	if user != "" && pwd != "" {
		return user, pwd
	}
	return "", ""
}

type candidate struct {
	name    string
	sources []string
	dbCats  []string
	hostCnt int64
}

// selectCandidates is run_categorization's per-platform Shadow IT outlier
// scoping: per-platform host-count threshold, Shadow IT source filter,
// failure cooldown, then IsSystemPackage, rarest first, capped at limit.
func selectCandidates(ctx context.Context, db *graphdb.DB, limit int) ([]string, error) {
	pct := catalog.GetOutlierPct()
	thresholds, err := catalog.ComputePerPlatformThresholds(ctx, db, pct)
	if err != nil {
		return nil, fmt.Errorf("per-platform thresholds: %w", err)
	}
	limitLabel := "ALL"
	if limit != 0 {
		limitLabel = fmt.Sprintf("%d max", limit)
	}
	slog.Info(fmt.Sprintf("fetching shadow-IT candidates outlier_pct=%d%% min=2 shadow_it_sources(apps+extensions) limit=%s",
		int(pct*100), limitLabel))
	if len(thresholds) == 0 {
		slog.Info("no platforms detected; skipping")
		return nil, nil
	}
	platforms := make([]string, 0, len(thresholds))
	for p := range thresholds {
		platforms = append(platforms, p)
	}
	sort.Strings(platforms)
	parts := make([]string, len(platforms))
	for i, p := range platforms {
		parts[i] = fmt.Sprintf("%s=%d", p, thresholds[p])
	}
	slog.Info("per-platform thresholds " + strings.Join(parts, ", "))

	cutoff := cutoffISO()
	byName := map[string]*candidate{}
	var order []*candidate // python dict insertion order
	for _, p := range platforms {
		rows, err := db.Query(ctx, cypherCandidates, map[string]any{
			"platform": p, "threshold": int64(thresholds[p]),
			"shadow_it_sources": catalog.ShadowITSourceList(), "cutoff_iso": cutoff,
		})
		if err != nil {
			return nil, fmt.Errorf("candidates for platform %s: %w", p, err)
		}
		for _, r := range rows {
			name, ok := r["name"].(string)
			if !ok {
				continue // python would crash later on a null name
			}
			hc, _ := graphdb.AsInt64(r["host_count"])
			// Lowest host_count across platforms wins, so rarest items lead.
			if cur := byName[name]; cur == nil {
				c := &candidate{name: name, sources: catalog.SourcesFrom(r["sources"]),
					dbCats: catalog.SourcesFrom(r["db_categories"]), hostCnt: hc}
				byName[name] = c
				order = append(order, c)
			} else if hc < cur.hostCnt {
				*cur = candidate{name: name, sources: catalog.SourcesFrom(r["sources"]),
					dbCats: catalog.SourcesFrom(r["db_categories"]), hostCnt: hc}
			}
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return order[i].hostCnt < order[j].hostCnt })
	var list []string
	skipped := 0
	for _, c := range order {
		if catalog.IsSystemPackage(c.name, c.dbCats, c.sources) {
			skipped++
			continue
		}
		list = append(list, c.name)
		if limit != 0 && len(list) >= limit {
			break
		}
	}
	slog.Info(fmt.Sprintf("candidates outliers=%d after_system_filter=%d system_skipped=%d",
		len(byName), len(list), skipped))
	return list, nil
}

// RunCategorization replaces categorize_software.run_categorization(
// memgraph_uri, limit, target_names). limit 0 = python None (no limit);
// targetNames nil = None. Python caught its own errors and returned None;
// Go returns an error only for failures python would have raised.
func RunCategorization(ctx context.Context, memgraphURI string, limit int, targetNames []string) error {
	slog.Info("connecting to memgraph", "uri", memgraphURI)
	user, pwd := memgraphAuth()
	db := graphdb.New(memgraphURI, user, pwd, graphdb.WithInitRetry(1, 0))
	defer func() {
		// Cleanup must run even when the caller's ctx is already cancelled.
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		db.Close(cctx)
	}()
	if _, err := db.Driver(ctx); err != nil {
		slog.Error("could not connect to memgraph", "err", err)
		return nil
	}

	var list []string
	if len(targetNames) > 0 {
		preview := strings.Join(targetNames[:min(5, len(targetNames))], ", ")
		if len(targetNames) > 5 {
			preview += "..."
		}
		slog.Info("fetching specific software items=" + preview)
		list = targetNames
	} else {
		var err error
		if list, err = selectCandidates(ctx, db, limit); err != nil {
			return err
		}
	}
	if len(list) == 0 {
		slog.Info("no software to process")
		return nil
	}
	return enrichNames(ctx, db, newHTTPClient(), list)
}

// enrichNames is run_categorization's sequential processing loop.
func enrichNames(ctx context.Context, db *graphdb.DB, client *http.Client, list []string) error {
	total := len(list)
	slog.Info(fmt.Sprintf("processing items=%d catalog_size=%d (unknowns fall through to wikipedia REST)",
		total, catalog.CatalogSize()))
	var processed, updated, cachedMisses, transientSkips, catalogHits, consecutiveFailures int
	logEvery := max(1, total/10)
	slog.Info(fmt.Sprintf("enrichment starting total=%d", total))
	for _, name := range list {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("categorize cancelled: %w", err)
		}
		// Catalog hit: local, no network, no pacing.
		if cats, desc, ok := catalog.Lookup(name); ok {
			success, err := runWithRetry(ctx, db, cypherCatalogHit, map[string]any{
				"name": name, "category": nonNil(cats), "desc": nilIfEmpty(desc), "now_iso": nowISO(),
			})
			if err != nil {
				return err
			}
			if success {
				updated++
				catalogHits++
			}
			consecutiveFailures = 0
			processed++
			if processed%logEvery == 0 || processed == total {
				slog.Info(fmt.Sprintf("enriching progress=%d/%d updated=%d catalog=%d",
					processed, total, updated, catalogHits))
			}
			continue
		}

		res, cats, desc := getSoftwareInfo(ctx, name, client)
		now := nowISO()
		switch res {
		case resultHit:
			success, err := runWithRetry(ctx, db, cypherWikiHit, map[string]any{
				"name": name, "category": nonNil(cats), "desc": nilIfEmpty(desc), "now_iso": now,
			})
			if err != nil {
				return err
			}
			if success {
				updated++
			}
			consecutiveFailures = 0
		case resultMiss:
			// Stamp the attempt so the failure cooldown skips this name.
			if _, err := runWithRetry(ctx, db, cypherMiss, map[string]any{"name": name, "now_iso": now}); err != nil {
				return err
			}
			cachedMisses++
			consecutiveFailures = 0 // a miss is not a failure to back off on
		default:
			transientSkips++
			consecutiveFailures++
		}
		processed++
		if processed%logEvery == 0 || processed == total {
			slog.Info(fmt.Sprintf("enriching progress=%d/%d hits=%d miss_cached=%d transient=%d",
				processed, total, updated, cachedMisses, transientSkips))
		}
		pause := 200 * time.Millisecond
		if consecutiveFailures >= adaptiveBackoffTrigger {
			pause = adaptiveBackoffSleep
		}
		sleepCtx(ctx, pause)
	}
	slog.Info(fmt.Sprintf("enrichment finished hits=%d catalog=%d wikipedia=%d miss_cached=%d cooldown_days=%d transient=%d",
		updated, catalogHits, updated-catalogHits, cachedMisses, FailureCooldownDays(), transientSkips))
	return nil
}

// CategorizeMain is `fleethound categorize [--memgraph-uri U] [--limit N]
// [--names a,b]` (categorize_software.py __main__). Returns the exit code.
func CategorizeMain(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("categorize", flag.ContinueOnError)
	uri := fs.String("memgraph-uri", DefaultMemgraphURI(), "Memgraph Bolt URI (default: from MEMGRAPH_URI or .env)")
	limit := fs.Int("limit", 500, "Maximum items to process (default: 500, use 0 for ALL)")
	names := fs.String("names", "", "Comma-separated list of specific software names to enrich")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	var list []string
	if *names != "" {
		for _, n := range strings.Split(*names, ",") {
			list = append(list, pyStrip(n))
		}
	}
	if err := RunCategorization(ctx, *uri, *limit, list); err != nil {
		slog.Error("categorization failed", "err", err)
		return 1
	}
	return 0
}
