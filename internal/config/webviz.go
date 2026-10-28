package config

import (
	"errors"
	"path/filepath"
)

// Manual trigger cooldowns (webviz/app.py *_MANUAL_TRIGGER_COOLDOWN), seconds.
const (
	EnricherManualTriggerCooldown  = 30.0
	ExtensionManualTriggerCooldown = 30.0
	OODAManualTriggerCooldown      = 60.0
)

// Webviz is every setting webviz/app.py read once at import time.
// Field names map 1:1 to the Python module constants.
type Webviz struct {
	Port     int    // PORT (default 8080)
	BindHost string // WEBVIZ_BIND_HOST; default 127.0.0.1 (python dev default). Docker must set 0.0.0.0.

	MemgraphURI      string // MEMGRAPH_URI, default bolt://memgraph:7687, trimmed
	MemgraphUser     string // MEMGRAPH_USER(_FILE)
	MemgraphPassword string // MEMGRAPH_PASSWORD(_FILE)

	DebugErrorDetails bool // WEBVIZ_DEBUG_ERRORS (default false)

	APIToken           string // WEBVIZ_API_TOKEN(_FILE)
	RequireAuth        bool   // WEBVIZ_REQUIRE_AUTH (default false; Docker image sets true)
	AllowAnonymousRead bool   // WEBVIZ_ALLOW_ANONYMOUS_READ (default false)

	ConfigDir     string // CONFIG_DIR (default ./config, absolute)
	StaticDir     string // WEBVIZ_STATIC_DIR (default ./webviz/static)
	WhitelistFile string // <ConfigDir>/whitelist.json (python: /app/config/whitelist.json)
	AuditFile     string // <ConfigDir>/audit.log
	SnapshotDir   string // SNAPSHOT_DIR, default <ConfigDir>/snapshots

	EnricherEnabled     bool   // ENRICHER_ENABLED (default true)
	EnricherIntervalSec int    // ENRICHER_INTERVAL_SEC (300)
	EnricherBatchSize   int    // ENRICHER_BATCH_SIZE (25)
	EnricherParallelism int    // ENRICHER_PARALLELISM (4)
	EnricherLockPath    string // ENRICHER_LOCK_PATH (<ConfigDir>/.enricher.lock)
	EnricherTriggerPath string // ENRICHER_TRIGGER_PATH (<ConfigDir>/.enricher.trigger)
	EnricherStatusPath  string // ENRICHER_STATUS_PATH (<ConfigDir>/enricher_status.json)

	ExtensionWorkerEnabled     bool   // EXTENSION_WORKER_ENABLED (default true)
	ExtensionWorkerIntervalSec int    // EXTENSION_WORKER_INTERVAL_SEC (21600)
	ExtensionWorkerBatchSize   int    // EXTENSION_WORKER_BATCH_SIZE (50)
	ExtensionWorkerParallelism int    // EXTENSION_WORKER_PARALLELISM (4)
	ExtensionWorkerLockPath    string // EXTENSION_WORKER_LOCK_PATH (<ConfigDir>/.extensions.lock)
	ExtensionWorkerTriggerPath string // EXTENSION_WORKER_TRIGGER_PATH (<ConfigDir>/.extensions.trigger)
	ExtensionWorkerStatusPath  string // EXTENSION_WORKER_STATUS_PATH (<ConfigDir>/extension_status.json)
	ExtensionCacheDir          string // EXTENSION_CACHE_DIR (<ConfigDir>/extension_cache)

	OODAEnabled       bool   // OODA_ENABLED (default false)
	OODAIntervalSec   int    // OODA_INTERVAL_SEC (1800)
	OODAFullScanEvery int    // OODA_FULL_SCAN_EVERY (24; 0 disables)
	OODALockPath      string // OODA_LOCK_PATH (<ConfigDir>/.ooda.lock)
	OODATriggerPath   string // OODA_TRIGGER_PATH (<ConfigDir>/.ooda.trigger)
	OODAStatusPath    string // OODA_STATUS_PATH (<ConfigDir>/ooda_status.json)
	OODACyclesPath    string // OODA_CYCLES_PATH (<ConfigDir>/ooda_cycles.jsonl)
	OODAFindingsPath  string // OODA_FINDINGS_PATH (<ConfigDir>/ooda_findings.json)
	OODAStatePath     string // OODA_STATE_PATH (<ConfigDir>/.state.json)
	OODASnapshotDir   string // OODA_SNAPSHOT_DIR (default SnapshotDir)

	Insecure bool // INSECURE (only used for the boot warning here)
}

// ErrAuthRequired is returned by Validate when WEBVIZ_REQUIRE_AUTH=true and no
// token is configured (python raised SystemExit at import).
var ErrAuthRequired = errors.New("WEBVIZ_REQUIRE_AUTH=true but WEBVIZ_API_TOKEN/WEBVIZ_API_TOKEN_FILE is unset. " +
	"Set the token or unset WEBVIZ_REQUIRE_AUTH.")

// LoadWebviz reads the environment once. It never fails; call Validate.
func LoadWebviz() *Webviz {
	dir := ConfigDir()
	in := func(name string) string { return filepath.Join(dir, name) }
	user, pass := ResolveSecret("MEMGRAPH_USER", ""), ResolveSecret("MEMGRAPH_PASSWORD", "")
	snap := Str("SNAPSHOT_DIR", in("snapshots"))
	static := StrTrim("WEBVIZ_STATIC_DIR", "")
	if static == "" {
		static = "webviz/static"
	}
	if abs, err := filepath.Abs(static); err == nil {
		static = abs
	}
	c := &Webviz{
		Port:               Int("PORT", 8080),
		BindHost:           StrTrim("WEBVIZ_BIND_HOST", "127.0.0.1"),
		MemgraphURI:        StrTrim("MEMGRAPH_URI", "bolt://memgraph:7687"),
		MemgraphUser:       user,
		MemgraphPassword:   pass,
		DebugErrorDetails:  Bool("WEBVIZ_DEBUG_ERRORS", false),
		APIToken:           ResolveSecret("WEBVIZ_API_TOKEN", ""),
		RequireAuth:        Bool("WEBVIZ_REQUIRE_AUTH", false),
		AllowAnonymousRead: Bool("WEBVIZ_ALLOW_ANONYMOUS_READ", false),
		ConfigDir:          dir,
		StaticDir:          static,
		WhitelistFile:      in("whitelist.json"),
		AuditFile:          in("audit.log"),
		SnapshotDir:        snap,

		EnricherEnabled:     Bool("ENRICHER_ENABLED", true),
		EnricherIntervalSec: Int("ENRICHER_INTERVAL_SEC", 300),
		EnricherBatchSize:   Int("ENRICHER_BATCH_SIZE", 25),
		EnricherParallelism: Int("ENRICHER_PARALLELISM", 4),
		EnricherLockPath:    Str("ENRICHER_LOCK_PATH", in(".enricher.lock")),
		EnricherTriggerPath: Str("ENRICHER_TRIGGER_PATH", in(".enricher.trigger")),
		EnricherStatusPath:  Str("ENRICHER_STATUS_PATH", in("enricher_status.json")),

		ExtensionWorkerEnabled:     Bool("EXTENSION_WORKER_ENABLED", true),
		ExtensionWorkerIntervalSec: Int("EXTENSION_WORKER_INTERVAL_SEC", 21600),
		ExtensionWorkerBatchSize:   Int("EXTENSION_WORKER_BATCH_SIZE", 50),
		ExtensionWorkerParallelism: Int("EXTENSION_WORKER_PARALLELISM", 4),
		ExtensionWorkerLockPath:    Str("EXTENSION_WORKER_LOCK_PATH", in(".extensions.lock")),
		ExtensionWorkerTriggerPath: Str("EXTENSION_WORKER_TRIGGER_PATH", in(".extensions.trigger")),
		ExtensionWorkerStatusPath:  Str("EXTENSION_WORKER_STATUS_PATH", in("extension_status.json")),
		ExtensionCacheDir:          Str("EXTENSION_CACHE_DIR", in("extension_cache")),

		OODAEnabled:       Bool("OODA_ENABLED", false),
		OODAIntervalSec:   Int("OODA_INTERVAL_SEC", 1800),
		OODAFullScanEvery: Int("OODA_FULL_SCAN_EVERY", 24),
		OODALockPath:      Str("OODA_LOCK_PATH", in(".ooda.lock")),
		OODATriggerPath:   Str("OODA_TRIGGER_PATH", in(".ooda.trigger")),
		OODAStatusPath:    Str("OODA_STATUS_PATH", in("ooda_status.json")),
		OODACyclesPath:    Str("OODA_CYCLES_PATH", in("ooda_cycles.jsonl")),
		OODAFindingsPath:  Str("OODA_FINDINGS_PATH", in("ooda_findings.json")),
		OODAStatePath:     Str("OODA_STATE_PATH", in(".state.json")),
		OODASnapshotDir:   Str("OODA_SNAPSHOT_DIR", snap),

		Insecure: Bool("INSECURE", false),
	}
	return c
}

// Validate enforces the fail-closed startup rule.
func (c *Webviz) Validate() error {
	if c.RequireAuth && c.APIToken == "" {
		return ErrAuthRequired
	}
	return nil
}

// ExtensionTriggerForOODA is the extension trigger path handed to the OODA
// supervisor: empty (python None) when the extension worker is disabled.
func (c *Webviz) ExtensionTriggerForOODA() string {
	if c.ExtensionWorkerEnabled {
		return c.ExtensionWorkerTriggerPath
	}
	return ""
}
