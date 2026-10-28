package extintel

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// Mozilla add-on blocklist
// ---------------------------------------------------------------------------

func conditionalHeaders(validators map[string]string) map[string]string {
	if etag := pyStrip(validators["etag"]); etag != "" {
		return map[string]string{"If-None-Match": etag}
	}
	return nil
}

// FetchMozillaBlocklist replaces fetch_mozilla_blocklist(client=,
// validators=): {guid: record}. Fails (FetchFailed, empty map) unless every
// page was read: a partial list must never be cached as the whole blocklist.
// validators ({"etag": ...}, may be nil) makes the first request
// conditional; a 304 is FetchNotModified, and a full read stores the new ETag
// back into validators.
func FetchMozillaBlocklist(ctx context.Context, client *HTTPClient, validators map[string]string) (map[string]map[string]any, FetchResult) {
	client = clientOr(client, 12)
	next := "https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/addons/records"
	records := map[string]map[string]any{}
	seen := map[string]bool{}
	etag := ""
	failed := func() (map[string]map[string]any, FetchResult) { return map[string]map[string]any{}, FetchFailed }
	for page := 0; page < 20; page++ {
		if next == "" || seen[next] {
			break
		}
		seen[next] = true
		var hdrs map[string]string
		if page == 0 {
			hdrs = conditionalHeaders(validators)
		}
		resp := client.Get(ctx, next, mozillaHosts, maxHTTPBytes, hdrs)
		if page == 0 && resp.Status == 304 {
			return nil, FetchNotModified
		}
		if resp.Status != 200 || len(resp.Body) == 0 || resp.Err != "" {
			why := resp.Err
			if why == "" {
				why = fmt.Sprint(resp.Status)
			}
			slog.Warn(fmt.Sprintf("mozilla blocklist page %d failed: %s; discarding partial list", page+1, why))
			return failed()
		}
		payload, ok := toMap(jsonBody(resp.Body))
		if !ok {
			slog.Warn(fmt.Sprintf("mozilla blocklist page %d is not JSON; discarding partial list", page+1))
			return failed()
		}
		if page == 0 {
			etag = header(resp.Headers, "ETag")
		}
		data, _ := toList(payload["data"])
		for _, r := range data {
			record, ok := toMap(r)
			if !ok || !truthy(record["guid"]) {
				continue
			}
			guid := pyStr(record["guid"])
			if prior, ok := records[guid]; ok {
				// Mozilla files separate records per blocked version range for
				// one GUID; keep every range, not just the last record.
				pr, _ := toList(prior["versionRange"])
				nr, _ := toList(record["versionRange"])
				record = copyMap(record)
				record["versionRange"] = append(append([]any{}, pr...), nr...)
			}
			records[guid] = record
		}
		// Kinto paginates via the Next-Page header; `next` kept as a fallback.
		next = header(resp.Headers, "Next-Page")
		if next == "" {
			next, _ = payload["next"].(string)
		}
	}
	if next != "" && !seen[next] {
		slog.Warn("mozilla blocklist has more than 20 pages; discarding partial list")
		return failed()
	}
	if validators != nil && etag != "" {
		validators["etag"] = etag
	}
	return records, FetchOK
}

var (
	guidRxMu    sync.Mutex
	guidRxCache = map[string]*regexp.Regexp{}
)

// guidRegex compiles a `/pattern/` blocklist GUID once; nil for plain or
// invalid GUIDs (including python-only syntax RE2 rejects).
func guidRegex(guid string) *regexp.Regexp {
	if len(guid) < 3 || !strings.HasPrefix(guid, "/") || !strings.HasSuffix(guid, "/") {
		return nil
	}
	guidRxMu.Lock()
	defer guidRxMu.Unlock()
	if rx, ok := guidRxCache[guid]; ok {
		return rx
	}
	rx, err := regexp.Compile(guid[1 : len(guid)-1])
	if err != nil {
		rx = nil
	}
	if len(guidRxCache) >= 4096 {
		guidRxCache = map[string]*regexp.Regexp{}
	}
	guidRxCache[guid] = rx
	return rx
}

// versionPart is one dot part of _version_key: numeric prefix (or "*" =
// infinity), then "no suffix" sorts after a suffix (1.0a < 1.0, like Mozilla
// pre-releases), then the suffix as a string.
type versionPart struct {
	inf      bool
	num      string // decimal digits without leading zeros ("0" for none)
	noSuffix bool
	suffix   string
}

func versionKey(version string) []versionPart {
	var key []versionPart
	for _, part := range strings.Split(pyStrip(version), ".") {
		if part == "*" { // "1.2.*" = any 1.2.x
			key = append(key, versionPart{inf: true, noSuffix: true})
			continue
		}
		i := 0
		for i < len(part) && part[i] >= '0' && part[i] <= '9' {
			i++
		}
		num := strings.TrimLeft(part[:i], "0")
		if num == "" {
			num = "0"
		}
		suffix, _, _ := strings.Cut(part[i:], "\n") // `.*` stops at a newline
		key = append(key, versionPart{num: num, noSuffix: suffix == "", suffix: suffix})
	}
	return key
}

func comparePart(a, b versionPart) int {
	switch {
	case a.inf && !b.inf:
		return 1
	case !a.inf && b.inf:
		return -1
	case !a.inf:
		if len(a.num) != len(b.num) {
			if len(a.num) < len(b.num) {
				return -1
			}
			return 1
		}
		if c := strings.Compare(a.num, b.num); c != 0 {
			return c
		}
	}
	if a.noSuffix != b.noSuffix {
		if b.noSuffix {
			return -1
		}
		return 1
	}
	return strings.Compare(a.suffix, b.suffix)
}

// CompareVersions replaces compare_versions(a, b): -1, 0 or 1.
func CompareVersions(a, b string) int {
	ka, kb := versionKey(a), versionKey(b)
	pad := versionPart{num: "0", noSuffix: true}
	for len(ka) < len(kb) {
		ka = append(ka, pad)
	}
	for len(kb) < len(ka) {
		kb = append(kb, pad)
	}
	for i := range ka {
		if c := comparePart(ka[i], kb[i]); c != 0 {
			return c
		}
	}
	return 0
}

func versionBlocked(entry map[string]any, versions []string) bool {
	rawRanges, _ := toList(entry["versionRange"])
	var ranges []map[string]any
	for _, r := range rawRanges {
		if m, ok := toMap(r); ok {
			ranges = append(ranges, m)
		}
	}
	var known []string
	for _, v := range versions {
		if pyStrip(v) != "" {
			known = append(known, v)
		}
	}
	if len(ranges) == 0 || len(known) == 0 {
		return true // no range = every version; unknown installed version fails closed
	}
	for _, rng := range ranges {
		lo := cleanStr(rng["minVersion"])
		if lo == "" {
			lo = "*"
		}
		hi := cleanStr(rng["maxVersion"])
		if hi == "" {
			hi = "*"
		}
		for _, v := range known {
			if (lo == "*" || CompareVersions(v, lo) >= 0) && (hi == "*" || CompareVersions(v, hi) <= 0) {
				return true
			}
		}
	}
	return false
}

// MatchBlocklist replaces match_blocklist(blocklist, id, versions): the
// record covering id at any of versions, or nil. GUIDs may be exact IDs or
// `/regex/` patterns (compiled lazily, memoised). Empty versions fails
// closed. Regex GUIDs are tried in sorted order (python: dict order).
func MatchBlocklist(blocklist map[string]map[string]any, extensionID string, versions []string) map[string]any {
	extensionID = pyStrip(extensionID)
	if extensionID == "" || len(blocklist) == 0 {
		return nil
	}
	if entry := blocklist[extensionID]; entry != nil && versionBlocked(entry, versions) {
		return entry
	}
	for _, guid := range sortedKeys(blocklist) {
		if !strings.HasPrefix(guid, "/") {
			continue
		}
		entry := blocklist[guid]
		if rx := guidRegex(guid); rx != nil && entry != nil && rx.MatchString(extensionID) && versionBlocked(entry, versions) {
			return entry
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Open threat feeds (config/extension_threat_feeds.json)
// ---------------------------------------------------------------------------

var (
	feedNameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,40}$`)
	feedIPHostRe  = regexp.MustCompile(`^(?:[\d.]+|\[?[0-9a-f:]+\]?)$`)
	feedPlatforms = map[string]map[string]struct{}{"chromium": ChromiumStores, "firefox": set("firefox")}
)

const feedMaxRows = 200_000

// feedSeverity: reason keywords -> (severity, threat). Matched as substrings
// of the lowercased reason; first tier that matches wins.
var feedSeverity = []struct {
	severity string
	threat   int64
	keywords []string
}{
	{"malicious", 100, []string{"malware", "spyware", "phish", "steal", "credential", "backdoor",
		"trojan", "ransom", "keylog", "exfiltrat", "cryptojack", "miner", "malicious", "rat "}},
	{"unwanted", 70, []string{"adware", "hijack", "bundl", "suspicious", "fraud", "scam",
		"affiliate", "injection", "tracking"}},
}

// LoadThreatFeeds replaces load_threat_feeds(): validated feed definitions
// from ThreatFeedsPath(); bad entries skipped with a warning.
func LoadThreatFeeds() []map[string]any {
	path := ThreatFeedsPath()
	if path == "" {
		slog.Error("threat feeds: no extension_threat_feeds.json found; no feed matching")
		return []map[string]any{}
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path from operator env/config, not request input
	var doc any
	if err == nil {
		doc, err = pyJSONLoads([]byte(decodeReplace(raw)))
	}
	if err != nil {
		slog.Error(fmt.Sprintf("threat feeds: cannot read %s: %v", path, err))
		return []map[string]any{}
	}
	var entries []any
	if m, ok := toMap(doc); ok {
		entries, _ = toList(m["feeds"])
	}
	feeds := []map[string]any{}
	for i, e := range entries {
		feed, err := validateFeed(e)
		if err != nil {
			slog.Warn(fmt.Sprintf("threat feeds: skipping entry %d: %v", i, err))
			continue
		}
		feeds = append(feeds, feed)
	}
	return feeds
}

func validateFeed(e any) (map[string]any, error) {
	raw, ok := toMap(e)
	if !ok {
		return nil, errors.New("entry is not an object")
	}
	name := cleanStr(raw["name"])
	if !feedNameRe.MatchString(name) {
		return nil, fmt.Errorf("invalid name %q", name)
	}
	rawURL := cleanStr(raw["url"])
	u, err := url.Parse(rawURL)
	host := ""
	if err == nil {
		host = strings.ToLower(u.Hostname())
	}
	if err != nil || u.Scheme != "https" || host == "" || !strings.Contains(host, ".") ||
		feedIPHostRe.MatchString(host) || strings.HasSuffix(host, ".local") {
		return nil, errors.New("url must be https on a public hostname")
	}
	if raw["format"] != "csv" {
		return nil, errors.New("format must be 'csv'")
	}
	platform, _ := raw["platform"].(string)
	if _, ok := feedPlatforms[platform]; !ok {
		return nil, errors.New("platform must be one of ['chromium', 'firefox']")
	}
	idField := cleanStr(raw["id_field"])
	if idField == "" {
		return nil, errors.New("id_field is required")
	}
	if _, ok := pyFromISO(strings.ReplaceAll(cleanStr(raw["added_at"]), "Z", "+00:00")); !ok {
		return nil, fmt.Errorf("Invalid isoformat string: %q", cleanStr(raw["added_at"]))
	}
	defReason := cleanStr(raw["default_reason"])
	if defReason == "" {
		defReason = "listed by threat feed"
	}
	return map[string]any{
		"name": name, "url": rawURL, "host": host, "platform": platform,
		"id_field":       idField,
		"reason_field":   optStr(cleanStr(raw["reason_field"])),
		"source_field":   optStr(cleanStr(raw["source_field"])),
		"date_field":     optStr(cleanStr(raw["date_field"])),
		"default_reason": defReason,
	}, nil
}

func feedIDOK(platform, extID string) bool {
	if platform == "chromium" {
		return chromeExtIDRe.MatchString(extID)
	}
	return firefoxGUIDMatch(extID)
}

// FetchThreatFeed replaces fetch_threat_feed(feed, client=, validators=):
// {extension_id_lower: {reason, source, date}}. FetchFailed is python None;
// validators ({"etag": ...}) makes the request conditional (304 =
// FetchNotModified) and receives the new ETag on a 200.
func FetchThreatFeed(ctx context.Context, feed map[string]any, client *HTTPClient, validators map[string]string) (map[string]map[string]any, FetchResult) {
	client = clientOr(client, 30)
	name := pyStr(feed["name"])
	host, _ := feed["host"].(string)
	feedURL, _ := feed["url"].(string)
	resp := client.Get(ctx, feedURL, set(host), 32*1024*1024, conditionalHeaders(validators))
	if resp.Status == 304 {
		return nil, FetchNotModified
	}
	if resp.Status != 200 || len(resp.Body) == 0 || resp.Err != "" {
		why := resp.Err
		if why == "" {
			why = fmt.Sprintf("HTTP %d", resp.Status)
		}
		slog.Warn(fmt.Sprintf("threat feed %s fetch failed: %s", name, why))
		return nil, FetchFailed
	}
	r := csv.NewReader(strings.NewReader(decodeSig(resp.Body)))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	fieldnames, err := r.Read()
	if err != nil && err != io.EOF {
		slog.Warn(fmt.Sprintf("threat feed %s parse failed: %v", name, err))
		return nil, FetchFailed
	}
	col := func(field any) int { // DictReader: a duplicated column name keeps the last
		f, _ := field.(string)
		idx := -1
		for i, n := range fieldnames {
			if n == f {
				idx = i
			}
		}
		return idx
	}
	idCol := col(feed["id_field"])
	if idCol < 0 {
		slog.Warn(fmt.Sprintf("threat feed %s: column %q missing", name, pyStr(feed["id_field"])))
		return nil, FetchFailed
	}
	reasonCol, sourceCol, dateCol := col(pyOr(feed["reason_field"], "")), col(pyOr(feed["source_field"], "")), col(pyOr(feed["date_field"], ""))
	defReason, _ := feed["default_reason"].(string)
	platform, _ := feed["platform"].(string)
	cell := func(row []string, i int) string {
		if i < 0 || i >= len(row) {
			return ""
		}
		return pyStrip(row[i])
	}
	entries := map[string]map[string]any{}
	for n := 0; n < feedMaxRows; n++ {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			slog.Warn(fmt.Sprintf("threat feed %s parse failed: %v", name, err))
			return nil, FetchFailed
		}
		extID := strings.ToLower(cell(row, idCol))
		if !feedIDOK(platform, extID) {
			continue
		}
		reason := cell(row, reasonCol)
		if reason == "" {
			reason = defReason
		}
		entries[extID] = map[string]any{
			"reason": runePrefix(reason, 120),
			"source": optStr(runePrefix(cell(row, sourceCol), 300)),
			"date":   optStr(runePrefix(cell(row, dateCol), 40)),
		}
	}
	if validators != nil {
		if etag := header(resp.Headers, "ETag"); etag != "" {
			validators["etag"] = etag
		}
	}
	return entries, FetchOK
}

// classifyFeedReason is classify_feed_reason: (severity, threat score) for a
// feed's free-text listing reason.
func classifyFeedReason(reason any) (string, int64) {
	text := strings.ToLower(cleanStr(reason)) + " "
	for _, tier := range feedSeverity {
		for _, k := range tier.keywords {
			if strings.Contains(text, k) {
				return tier.severity, tier.threat
			}
		}
	}
	return "listed", 45 // policy violation / removed for an unstated reason
}

// MatchThreatFeeds replaces match_threat_feeds(feed_index, store, id).
// feedIndex is {feed_name: {"platform": str, "entries": {id: hit}}}; entries
// may be map[string]map[string]any (FetchThreatFeed) or map[string]any (JSON
// cache). Hits are ordered by feed name.
func MatchThreatFeeds(feedIndex map[string]map[string]any, store, extensionID string) []map[string]any {
	hits := []map[string]any{}
	extID := strings.ToLower(pyStrip(extensionID))
	if extID == "" {
		return hits
	}
	names := make([]string, 0, len(feedIndex))
	for n := range feedIndex {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		feed := feedIndex[name]
		platform, _ := feed["platform"].(string)
		if !has(feedPlatforms[platform], store) {
			continue
		}
		var entry map[string]any
		switch es := feed["entries"].(type) {
		case map[string]map[string]any:
			entry = es[extID]
		case map[string]any:
			entry, _ = toMap(es[extID])
		}
		if len(entry) == 0 {
			continue
		}
		severity, threat := classifyFeedReason(entry["reason"])
		hit := map[string]any{"feed": name}
		mergeAll(hit, entry)
		hit["severity"] = severity
		hit["threat"] = threat
		hits = append(hits, hit)
	}
	return hits
}

// ---------------------------------------------------------------------------
// Graph-facing helpers
// ---------------------------------------------------------------------------

// SummarizeVulnerabilities replaces summarize_vulnerabilities: (json string
// capped at 20000 chars, count, max CVSS; hasMax=false is python None).
// Empty/nil input returns ("[]", 0, 0, false).
func SummarizeVulnerabilities(vulnerabilities any) (encoded string, count int, maxCVSS float64, hasMax bool) {
	list, ok := toList(vulnerabilities)
	if !ok || len(list) == 0 {
		return "[]", 0, 0, false
	}
	cleaned := []any{}
	for _, v := range list[:min(50, len(list))] {
		vuln, ok := toMap(v)
		if !ok {
			continue
		}
		cvss, cok := asFloat(pyOr(vuln["cvss_score"], vuln["cvss"], vuln["cvss_v3_score"]))
		if cok && (!hasMax || cvss > maxCVSS) { // python max(): keeps the first unless strictly greater
			maxCVSS, hasMax = cvss, true
		}
		epss, eok := asFloat(vuln["epss_probability"])
		cleaned = append(cleaned, map[string]any{
			"cve":              optStr(cleanStr(pyOr(vuln["cve"], vuln["cve_id"]))),
			"cvss_score":       optFloat(cvss, cok),
			"epss_probability": optFloat(epss, eok),
			"details":          optStr(runePrefix(cleanStr(vuln["details"]), 500)),
			"created_at":       optStr(cleanStr(vuln["created_at"])),
		})
	}
	return runePrefix(pyDumps(cleaned), 20_000), len(list), maxCVSS, hasMax
}

// SignalsJSON replaces signals_json(signals): compact JSON (python key order
// and escaping) capped at 20000 chars, "[]" for nil/empty.
func SignalsJSON(signals any) string {
	if !truthy(signals) {
		return "[]"
	}
	return runePrefix(pyDumps(signals), 20_000)
}
