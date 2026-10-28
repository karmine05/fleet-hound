// Package extintel ports src/extension_intel.py: browser-extension identity
// derivation, anonymous store adapters, the Mozilla blocklist, open threat
// feeds and the explainable risk scorer. Owner: agent C (also the
// `fleethound selfcheck` subcommand, python `python src/extension_intel.py`).
//
// Records are map[string]any throughout, exactly the python dicts (Fleet
// software rows, Cypher result rows, store metadata).
package extintel

import (
	"os"
	"strings"

	"github.com/karmine05/fleet-hound/internal/config"
)

// ScorerVersion is SCORER_VERSION.
const ScorerVersion = 14

// ChromiumStores is CHROMIUM_STORES. Treat as read-only.
var ChromiumStores = map[string]struct{}{
	"chrome": {}, "edge": {}, "brave": {}, "opera": {}, "vivaldi": {}, "chromium": {},
}

// FetchResult replaces the python tri-state of the conditional fetchers
// (a dict, the NOT_MODIFIED sentinel, or None/{} on failure).
type FetchResult int

const (
	// FetchOK: the returned map is the fresh document.
	FetchOK FetchResult = iota
	// FetchNotModified: the server answered 304 (python NOT_MODIFIED).
	FetchNotModified
	// FetchFailed: python returned None (threat feed) or {} (blocklist).
	FetchFailed
)

// HTTPClient replaces class HttpClient: size-capped GET/POST restricted to
// an allowlist of hosts, redirect guard, never raises (errors are returned in
// the Response). Timeout default 12s (per read, like urllib).
type HTTPClient struct {
	TimeoutSec float64
	fake       *fakeTransport // self-check/tests only
}

// ManifestFor replaces the `manifest_for(version)` callback: cached manifest
// fields for an immutable version, or nil (a hit skips the package download).
type ManifestFor func(version string) map[string]any

// AnalyzeOptions are analyze_extension's keyword arguments.
type AnalyzeOptions struct {
	BlocklistEntry map[string]any   // blocklist_entry (nil = None)
	FeedHits       []map[string]any // feed_hits (nil = None)
	// FleetHostCount is fleet_host_count; HasFleetHostCount=false means None.
	FleetHostCount    int
	HasFleetHostCount bool
}

// KnownPublishersPath replaces _known_publishers_path(): env
// KNOWN_PUBLISHERS_FILE (trimmed) if set, else <CONFIG_DIR>/known_publishers.json
// when it exists, else "" (python None). Python's second candidate was
// <repo>/config/known_publishers.json, which CONFIG_DIR=./config covers.
func KnownPublishersPath() string {
	if env := strings.TrimSpace(os.Getenv("KNOWN_PUBLISHERS_FILE")); env != "" {
		return env
	}
	if p := config.ConfigPath("known_publishers.json"); fileExists(p) {
		return p
	}
	return ""
}

// ThreatFeedsPath replaces _threat_feeds_path(): env
// EXTENSION_THREAT_FEEDS_FILE, else <CONFIG_DIR>/extension_threat_feeds.json
// when it exists, else "".
func ThreatFeedsPath() string {
	if env := strings.TrimSpace(os.Getenv("EXTENSION_THREAT_FEEDS_FILE")); env != "" {
		return env
	}
	if p := config.ConfigPath("extension_threat_feeds.json"); fileExists(p) {
		return p
	}
	return ""
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
