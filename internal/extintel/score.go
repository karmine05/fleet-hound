package extintel

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Permission / capability analysis
// ---------------------------------------------------------------------------

var permissionWeights = map[string]int64{
	"debugger":                            25,
	"nativeMessaging":                     20,
	"proxy":                               20,
	"userScripts":                         15,
	"cookies":                             15,
	"webRequest":                          15,
	"declarativeNetRequest":               15,
	"declarativeNetRequestWithHostAccess": 15,
	"management":                          15,
	"scripting":                           12,
	"clipboardRead":                       12,
	"tabCapture":                          10,
	"history":                             8,
	"identity":                            8,
	"downloads":                           6,
	"offscreen":                           6,
	"activeTab":                           2,
	"storage":                             1,
	"contextMenus":                        1,
	"alarms":                              1,
	"notifications":                       1,
	"sidePanel":                           1,
}

// privacyWeights: Chrome Web Store data-collection disclosure codes that
// matter for exfiltration risk. Capped in total: a disclosure is honest
// self-reporting, a review signal rather than a verdict.
var privacyWeights = map[int64]int64{4: 4, 3: 3, 5: 3, 1: 2, 7: 2}

const privacyCap = 8

var cwsPrivacyLabels = map[int64]string{
	1: "personally identifiable information", 3: "financial and payment information",
	4: "authentication information", 5: "personal communications", 6: "location",
	7: "web history", 8: "user activity", 9: "website content",
}

var (
	allURLs       = set("<all_urls>", "*://*/*", "http://*/*", "https://*/*")
	hostPatternRe = regexp.MustCompile(`(?i)^(?:<all_urls>|\*://|[a-z]+://)`)
)

type strSet = map[string]struct{}

func sortedSet(s strSet) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func intersects(a, b strSet) bool {
	for k := range a {
		if has(b, k) {
			return true
		}
	}
	return false
}

func permissionSets(meta, record map[string]any) (perms, hosts, matches, optional strSet) {
	rawPerms := asStringList(pyOr(meta["permissions"], record["permissions"]))
	rawHosts := asStringList(pyOr(meta["host_permissions"], record["host_permissions"]))
	rawMatches := asStringList(pyOr(meta["content_script_matches"], record["content_script_matches"]))
	rawOptional := asStringList(pyOr(meta["optional_permissions"], record["optional_permissions"]))
	perms, hosts, matches, optional = strSet{}, set(rawHosts...), set(rawMatches...), strSet{}
	for _, p := range rawPerms {
		if hostPatternRe.MatchString(p) {
			hosts[p] = struct{}{}
		} else {
			perms[p] = struct{}{}
		}
	}
	for _, p := range rawOptional {
		if !hostPatternRe.MatchString(p) && !has(perms, p) {
			optional[p] = struct{}{}
		}
	}
	return perms, hosts, matches, optional
}

func capability(perms, hosts, matches, optional strSet, privacyCodes, csp any) (int64, []map[string]any) {
	var score int64
	signals := []map[string]any{}
	for _, perm := range sortedSet(perms) {
		if w := permissionWeights[perm]; w != 0 {
			score += w
			signals = append(signals, signal("permission:"+perm, w, "requests the '"+perm+"' permission"))
		}
	}
	// Optional permissions are granted at runtime, so half weight, and their
	// total never exceeds what the required permissions contribute.
	budget := score
	for _, perm := range sortedSet(optional) {
		w := min(pyRound(float64(permissionWeights[perm])*0.5), budget)
		if w > 0 {
			budget -= w
			score += w
			signals = append(signals, signal("optional-permission:"+perm, w,
				"may request the '"+perm+"' permission at runtime"))
		}
	}
	if intersects(hosts, allURLs) {
		score += 20
		signals = append(signals, signal("broad-host-access", 20,
			"host permissions include <all_urls> or an equivalent wildcard"))
	} else if len(hosts) > 0 {
		w := min(10, int64(len(hosts))*2)
		score += w
		signals = append(signals, signal("host-access", w, fmt.Sprintf("requests access to %d host pattern(s)", len(hosts))))
	}
	if intersects(matches, allURLs) {
		score += 10
		signals = append(signals, signal("content-script-all-urls", 10, "content script runs on every page"))
	} else if len(matches) > 0 {
		score += 5
		signals = append(signals, signal("content-script", 5, fmt.Sprintf("injects a content script into %d pattern(s)", len(matches))))
	}
	codes, _ := toList(privacyCodes)
	declaredSet := map[int64]struct{}{}
	for _, c := range codes {
		if i, ok := intOf(c); ok {
			if _, w := privacyWeights[i]; w {
				declaredSet[i] = struct{}{}
			}
		}
	}
	if len(declaredSet) > 0 {
		declared := make([]int64, 0, len(declaredSet))
		for c := range declaredSet {
			declared = append(declared, c)
		}
		sort.Slice(declared, func(i, j int) bool { return declared[i] < declared[j] })
		var sum int64
		labels := make([]string, len(declared))
		for i, c := range declared {
			sum += privacyWeights[c]
			labels[i] = cwsPrivacyLabels[c]
		}
		w := min(privacyCap, sum)
		score += w
		signals = append(signals, signal("declared-data-collection", w,
			"developer declares it collects: "+strings.Join(labels, ", ")))
	}
	// Content scripts reach page content too, so only discount when neither exists.
	if len(hosts) == 0 && len(matches) == 0 {
		score = pyRound(float64(score) * 0.6)
	}
	// After the discount: remote or eval'd code is risky whatever it can reach.
	if weak, ok := weakCSP(csp); ok {
		score += 15
		signals = append(signals, signal("weak-csp", 15, "content security policy: "+weak))
	}
	return min(100, score), signals
}

// ---------------------------------------------------------------------------
// Risk scoring
// ---------------------------------------------------------------------------

func riskBand(score int64) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	}
	return "low"
}

// parseISOValue is _parse_iso.
func parseISOValue(v any) (time.Time, bool) {
	if !truthy(v) {
		return time.Time{}, false
	}
	return pyFromISO(strings.ReplaceAll(pyStr(v), "Z", "+00:00"))
}

// metaStatus is `_clean_str(meta.status or record.store_status [or "unknown"]).lower()`.
func metaStatus(meta, record map[string]any, def any) string {
	return strings.ToLower(cleanStr(pyOr(meta["status"], record["store_status"], def)))
}

// nowFn is the scorer's clock (python datetime.now(timezone.utc)).
var nowFn = time.Now

func trustScore(meta, record map[string]any, reputable bool) (int64, []map[string]any) {
	status := metaStatus(meta, record, "unknown")
	signals := []map[string]any{}
	var score int64
	add := func(points int64, code, detail string) {
		score += points
		signals = append(signals, signal(code, -points, detail))
	}

	switch status {
	case "public":
		add(25, "store-listed", "listed in a public extension store")
	case "unlisted":
		add(5, "store-unlisted", "unlisted or self-distributed, but the store still serves it")
	case "unknown":
		add(8, "store-status-unknown", "store metadata unavailable")
	} // not_found/removed deliberately score 0.

	if reputable {
		add(20, "reputable-publisher", "publisher matches a known vendor")
	}
	if meta["developer_verified"] == true {
		add(10, "verified-developer", "store marks the developer as verified")
	} else if meta["established_publisher"] == true {
		add(10, "established-publisher", "store: verified website owner with no history of violations")
	}
	if meta["featured"] == true {
		add(5, "store-featured", "featured / recommended by the store")
	}
	if mv, ok := asInt(meta["manifest_version"]); ok && mv == 3 {
		add(8, "manifest-v3", "uses Manifest V3")
	}
	if updated, ok := parseISOValue(meta["updated_at"]); ok {
		// timedelta.days floors toward -inf.
		ageDays := int64(math.Floor(float64(nowFn().Sub(updated)) / float64(24*time.Hour)))
		var points int64
		switch {
		case ageDays <= 365:
			points = 10
		case ageDays <= 730:
			points = 4
		}
		add(points, "store-updated", fmt.Sprintf("last store update %d days ago", max(ageDays, 0)))
	}
	if users, ok := asInt(meta["users"]); ok && users > 0 {
		points := min(12, int64(float64(4*pyLog10(float64(users)+1))))
		add(points, "install-popularity", commaInt(users)+" store installs")
	}
	rating, rok := asFloat(meta["rating"])
	ratingCount := asIntOr0(meta["rating_count"])
	if rok && rating >= 4.0 && ratingCount >= 100 {
		add(5, "store-rating", fmt.Sprintf("rated %.1f from %s ratings", rating, commaInt(ratingCount)))
	}
	if meta["crx_hash_verified"] == true {
		add(5, "crx-hash-verified", "package SHA-256 matches the store's published hash")
	}
	return min(100, score), signals
}

func threatScore(meta, record map[string]any, blocklistEntry map[string]any) (int64, []map[string]any) {
	signals := []map[string]any{}
	var threat int64
	raise := func(floor int64, code, detail string) {
		threat = max(threat, floor)
		signals = append(signals, signal(code, floor, detail))
	}
	status := metaStatus(meta, record, nil)

	switch {
	case len(blocklistEntry) > 0:
		why := cleanStr(blocklistEntry["why"])
		if why == "" {
			why = "blocked by Mozilla"
		}
		raise(100, "mozilla-blocklist", why)
	case status == "removed" || status == "disabled":
		raise(45, "removed-from-store", "extension is no longer available in its store")
	case status == "not_found" || status == "sideloaded":
		raise(20, "not-in-store", "extension ID was not found in the expected public store")
	case status == "unlisted":
		raise(10, "unlisted", "unlisted or self-distributed extension")
	case status == "off_store":
		signals = append(signals, signal("not-in-app-store", 0,
			"containing app is not in the Mac App Store (direct download or sideloaded)"))
	}

	// Stores keep abuse reports private; a low rating from many reviewers is
	// the closest public complaint signal.
	rating, rok := asFloat(meta["rating"])
	ratingCount := asIntOr0(meta["rating_count"])
	if rok && rating < 2.5 && ratingCount >= 50 {
		raise(15, "poor-public-reputation", fmt.Sprintf("rated %.1f/5 by %s reviewers", rating, commaInt(ratingCount)))
	}

	// Never fail open: a package we could not inspect (store serves none, or
	// it exceeds our download cap, which an attacker can pad past) has an
	// unknown capability score, so it must not look clean.
	if truthy(meta["manifest_unavailable"]) && !truthy(meta["manifest_error"]) {
		raise(15, "manifest-uninspected", runePrefix(pyStr(meta["manifest_unavailable"]), 200))
	}
	if truthy(meta["manifest_error"]) {
		raise(30, "manifest-unparseable", runePrefix(pyStr(meta["manifest_error"]), 200))
	}

	maxCVSS, ok := asFloat(record["max_cvss"])
	if !ok {
		if vulns, isList := toList(record["vulnerabilities"]); isList {
			for _, v := range vulns {
				m, isMap := toMap(v)
				if !isMap {
					continue
				}
				if s, sok := asFloat(m["cvss_score"]); sok && (!ok || s > maxCVSS) {
					maxCVSS, ok = s, true
				}
			}
		}
	}
	if ok {
		detail := fmt.Sprintf("Fleet reports a CVSS %.1f vulnerability", maxCVSS)
		switch {
		case maxCVSS >= 9:
			raise(35, "critical-cve", detail)
		case maxCVSS >= 7:
			raise(25, "high-cve", detail)
		case maxCVSS > 0:
			raise(10, "known-cve", detail)
		}
	}
	return min(100, threat), signals
}

func exposureScore(hostCount, versionCount int64) int64 {
	score := min(60, pyRound(float64(15*pyLog10(float64(max(hostCount, 0))+1))))
	if versionCount > 2 {
		score += 10
	}
	return min(100, score)
}

func builtinResult() map[string]any {
	return map[string]any{
		"risk_score":       int64(0),
		"risk_band":        "low",
		"capability_score": int64(0),
		"trust_score":      int64(100),
		"threat_score":     int64(0),
		"exposure_score":   int64(0),
		"risk_signals": []map[string]any{
			signal("browser-builtin", 0, "vendor-shipped/component extension; never auto-flagged"),
		},
		"store_status":           "builtin",
		"is_builtin":             true,
		"publisher_reputable":    true,
		"known_bad":              false,
		"install_users":          nil,
		"manifest_version":       nil,
		"permissions":            []string{},
		"host_permissions":       []string{},
		"content_script_matches": []string{},
		"latest_version":         nil,
		"store_name":             nil,
		"store_url":              nil,
		"publisher":              nil,
		"category":               nil,
		"rating":                 nil,
		"rating_count":           nil,
		"updated_at":             nil,
		"intel_error":            nil,
	}
}

// AnalyzeExtension replaces analyze_extension(record, ...): an explainable
// 0-100 risk score for one extension identity. record holds the flattened
// node properties plus an optional "store_meta" map from FetchStoreMetadata.
// Deterministic, no I/O (besides the cached known-publishers file).
//
// Output types: integers int64, floats float64, string lists []string,
// risk_signals []map[string]any{code, weight (int64), detail}; nil is None.
func AnalyzeExtension(record map[string]any, opts AnalyzeOptions) map[string]any {
	if record == nil {
		record = map[string]any{}
	}
	meta, _ := toMap(record["store_meta"])
	if meta == nil {
		meta = map[string]any{}
	}
	store := strings.ToLower(cleanStr(pyOr(record["store"], meta["store"], "unknown")))
	extensionID := cleanStr(record["extension_id"])
	name := cleanStr(record["name"])
	displayName := cleanStr(record["display_name"])
	var installedPaths []any
	if s, ok := record["installed_paths"].(string); ok && s != "" {
		installedPaths = []any{s}
	} else if truthy(record["installed_paths"]) {
		installedPaths, _ = toList(record["installed_paths"])
	}
	feedHits := opts.FeedHits
	blocklistEntry := opts.BlocklistEntry

	// Recomputed, not read from the node: ingestion sets is_builtin only when
	// a host is re-ingested, so a stored flag lags behind built-in rule changes.
	builtin := isBuiltin(store, extensionID, installedPaths)
	// A blocklist or threat-feed hit always gets scored, even for a built-in
	// ID or path (an ID suffix or vendor-looking path is host-reported).
	if builtin && len(blocklistEntry) == 0 && len(feedHits) == 0 {
		return builtinResult()
	}

	perms, hosts, matches, optional := permissionSets(meta, record)
	capScore, capSignals := capability(perms, hosts, matches, optional,
		meta["privacy_codes"], meta["content_security_policy"])
	signals := append([]map[string]any{}, capSignals...)
	if store == "safari" {
		// Neutral, not "uninspected": no Safari package is published anywhere,
		// so the missing manifest says nothing about this extension.
		signals = append(signals, signal("manifest-not-published", 0,
			"Apple publishes no Safari extension package; permissions are not inspected"))
	}

	publisher := cleanStr(pyOr(meta["developer"], meta["publisher"], record["vendor"]))
	var reputable bool
	switch meta["store"] {
	case "chrome":
		reputable = chromePublisherIsReputable(meta["publisher_id"])
	case "firefox":
		reputable = amoAuthorIsReputable(meta["author_ids"])
	case "edge":
		reputable = edgeExtensionIsReputable(record["extension_id"], meta["status"])
	case "safari":
		// The bundle ID and seller are claimable by any app; the signing team is
		// not. Fail closed unless the key itself was bound to that team.
		team := cleanStr(record["app_team_id"])
		reputable = appleTeamIsReputable(team) &&
			strings.HasSuffix(strings.ToLower(cleanStr(record["extension_id"])), "@"+strings.ToLower(team))
	default:
		// Opera exposes only a developer username; names are display-only.
		reputable = false
	}
	var sideloadSignal map[string]any
	if reputable {
		rawID, _ := record["extension_id"].(string)
		if !storeInstallVerified(meta["store"], rawID, record["installs"]) {
			reputable = false
			sideloadSignal = signal("not-store-install", 0,
				"publisher is known, but not every host install is in the browser's store directory "+
					"(unpacked or unreported path); publisher trust not applied")
		}
	}
	trust, trustSignals := trustScore(meta, record, reputable)
	if sideloadSignal != nil {
		trustSignals = append(trustSignals, sideloadSignal)
	}
	threat, threatSignals := threatScore(meta, record, blocklistEntry)
	for _, hit := range feedHits {
		w := pyIntLoose(pyOr(hit["threat"], int64(0)))
		threat = max(threat, w)
		detail := pyStr(hit["feed"]) + ": " + pyStr(hit["reason"])
		if truthy(hit["date"]) {
			detail += " (listed " + pyStr(hit["date"]) + ")"
		}
		if truthy(hit["source"]) {
			detail += " — " + pyStr(hit["source"])
		}
		threatSignals = append(threatSignals, signal("threat-feed:"+pyStr(hit["feed"]), w, runePrefix(detail, 400)))
	}
	threat = min(100, threat)
	signals = append(signals, threatSignals...)

	hostCount := asIntOr0(record["host_count"])
	var versionCount int64
	if versions, ok := toList(record["versions"]); ok {
		versionCount = int64(len(versions))
	}
	exposure := exposureScore(hostCount, versionCount)

	// Vouched: a known publisher ID (reputable already requires a verified
	// store install), or a store badge on a listing with >= 100k users. A badge
	// alone proves a clean record, not brand identity.
	vouched := reputable ||
		((meta["developer_verified"] == true || meta["established_publisher"] == true) &&
			asIntOr0(meta["users"]) >= 100_000 &&
			storeInstallVerified(store, extensionID, record["installs"]))
	// Safari display names carry an "App › " prefix for people; the name
	// checks must see the extension's own name. Strip only the exact prefix
	// WithSafariApp adds, derived from the install path.
	if store == "safari" {
		for _, p := range installedPaths {
			if app := safariContainingApp(p); app != "" {
				prefix := strings.TrimSuffix(app[strings.LastIndex(app, "/")+1:], ".app") + " › "
				displayName = strings.TrimPrefix(displayName, prefix)
				break
			}
		}
	}
	nameSignals, namePenalty := nameAnomalySignals(name, displayName, vouched)
	signals = append(signals, nameSignals...)

	users, usersOK := asInt(meta["users"])
	if !usersOK {
		users, usersOK = asInt(record["install_users"])
	}

	var rarityPenalty int64
	if usersOK && users < 1000 {
		switch {
		case reputable:
			signals = append(signals, signal("low-installs-reputable-publisher", 0,
				"only "+commaInt(users)+" installs, but the publisher is known"))
		case users < 100:
			rarityPenalty += 8
			signals = append(signals, signal("very-low-installs", 8, "only "+commaInt(users)+" store installs"))
		default:
			rarityPenalty += 4
			signals = append(signals, signal("low-installs", 4, "only "+commaInt(users)+" store installs"))
		}
	}
	if hostCount <= 1 {
		rarityPenalty += 4
		signals = append(signals, signal("single-host", 4, "installed on at most one host in this fleet"))
	} else if opts.HasFleetHostCount && opts.FleetHostCount >= 10 {
		ratio := float64(hostCount) / float64(max(opts.FleetHostCount, 1))
		if ratio < 0.03 {
			rarityPenalty += 3
			signals = append(signals, signal("rare-in-fleet", 3,
				fmt.Sprintf("installed on %d/%d hosts", hostCount, opts.FleetHostCount)))
		}
	}

	// float64() around every product: Go may otherwise fuse multiply-add on
	// arm64, which rounds differently from python.
	risk := pyRound(float64(0.35*float64(capScore)) +
		float64(0.25*float64(100-trust)) +
		float64(0.25*float64(threat)) +
		float64(0.15*float64(exposure)) +
		float64(namePenalty) +
		float64(rarityPenalty))

	status := metaStatus(meta, record, "unknown")
	knownBad := len(blocklistEntry) > 0
	unwanted := false
	for _, h := range feedHits {
		if h["severity"] == "malicious" {
			knownBad = true
		}
		if h["severity"] == "unwanted" {
			unwanted = true
		}
	}
	switch {
	case knownBad:
		// A blocklisted extension is never "low" regardless of popularity.
		risk = max(risk, 85)
		if usersOK && users >= 100_000 {
			risk = max(risk, 96)
			signals = append(signals, signal("known-bad-at-scale", 30, "blocked extension with "+commaInt(users)+" installs"))
		} else if usersOK && users >= 10_000 {
			risk = max(risk, 92)
			signals = append(signals, signal("known-bad-popular", 20, "blocked extension with "+commaInt(users)+" installs"))
		}
	case len(feedHits) > 0:
		// Listed by an open threat feed: adware/hijacking is "high" outright;
		// an unexplained takedown ranks with a store removal.
		if unwanted {
			risk = max(risk, 70)
		} else {
			risk = max(risk, 60)
		}
	case status == "removed":
		risk = max(risk, 60)
	case status == "not_found" && namePenalty >= 18:
		risk = max(risk, 55)
	}
	risk = max(0, min(100, risk))
	signals = append(signals, trustSignals...)
	absWeight := func(s map[string]any) int64 {
		w := pyIntLoose(s["weight"])
		if w < 0 {
			return -w
		}
		return w
	}
	sort.SliceStable(signals, func(i, j int) bool { return absWeight(signals[i]) > absWeight(signals[j]) })

	storeName := cleanStr(meta["name"])
	var storeNameOut any
	if !strings.HasPrefix(storeName, "__MSG_") {
		storeNameOut = optStr(storeName)
	}
	var established any
	if meta["established_publisher"] == true {
		established = true
	}
	rating, ratingOK := asFloat(meta["rating"])
	ratingCount, rcOK := asInt(meta["rating_count"])
	mv, mvOK := asInt(meta["manifest_version"])
	return map[string]any{
		"risk_score":       risk,
		"risk_band":        riskBand(risk),
		"capability_score": capScore,
		"trust_score":      trust,
		"threat_score":     threat,
		"exposure_score":   exposure,
		"risk_signals":     signals,
		"store_status":     status,
		// Stays true for a threat-listed built-in, so the flag matches ingestion.
		"is_builtin":             builtin,
		"publisher_reputable":    reputable,
		"known_bad":              knownBad,
		"install_users":          optInt(users, usersOK),
		"manifest_version":       optInt(mv, mvOK),
		"permissions":            sortedSet(perms),
		"host_permissions":       sortedSet(hosts),
		"content_script_matches": sortedSet(matches),
		"latest_version":         optStr(cleanStr(meta["version"])),
		"store_name":             storeNameOut,
		"store_url":              optStr(cleanStr(meta["url"])),
		"publisher":              optStr(publisher),
		"category":               optStr(cleanStr(meta["category"])),
		"rating":                 optFloat(rating, ratingOK),
		"rating_count":           optInt(ratingCount, rcOK),
		"updated_at":             optStr(cleanStr(meta["updated_at"])),
		"featured":               optBool(meta["featured"]),
		"established_publisher":  established,
		"developer_verified":     optBool(meta["developer_verified"]),
		"developer_email":        optStr(cleanStr(meta["developer_email"])),
		"developer_website":      optStr(cleanStr(meta["developer_website"])),
		"trader":                 optBool(meta["trader"]),
		"privacy_disclosure":     optStr(cleanStr(meta["privacy_disclosure"])),
		"privacy_policy_url":     optStr(cleanStr(meta["privacy_policy_url"])),
		"intel_error":            optStr(cleanStr(meta["error"])),
	}
}

// ---------------------------------------------------------------------------
// Content security policy
// ---------------------------------------------------------------------------

// cspText is _csp_text: MV2 CSP is a string; MV3 is {extension_pages,
// sandbox}. Sandboxed pages have no extension API access and may legitimately
// eval, so only extension_pages counts.
func cspText(v any) any {
	if m, ok := toMap(v); ok {
		v = m["extension_pages"]
	}
	return optStr(runePrefix(cleanStr(v), 2000))
}

var cspDirectiveRe = regexp.MustCompile(`(?i)(?:^|;)\s*(script-src(?:-elem)?|default-src)\s+([^;]*)`)

// weakCSP is _weak_csp: why a CSP weakens script isolation. Script sources
// that let an extension run code the store never reviewed. 'wasm-unsafe-eval'
// is the MV3-sanctioned WebAssembly switch and is not counted.
func weakCSP(csp any) (string, bool) {
	directives := map[string][]string{}
	for _, m := range cspDirectiveRe.FindAllStringSubmatch(cleanStr(csp), -1) {
		name := strings.ToLower(m[1])
		if _, ok := directives[name]; !ok { // browsers honour the first
			directives[name] = pySplit(m[2])
		}
	}
	effective := func(names ...string) []string { // CSP fallback chain
		for _, n := range names {
			if d, ok := directives[n]; ok {
				return d
			}
		}
		return nil
	}
	// eval is governed by script-src; <script> loads by script-src-elem.
	for _, x := range effective("script-src", "default-src") {
		if strings.ToLower(x) == "'unsafe-eval'" {
			return "'unsafe-eval' lets it run code built from strings", true
		}
	}
	var remote []string
	seen := map[string]bool{}
	for _, x := range append(effective("script-src-elem", "script-src", "default-src"), effective("script-src", "default-src")...) {
		lx := strings.ToLower(x)
		if (strings.HasPrefix(lx, "http:") || strings.HasPrefix(lx, "https:") || strings.HasPrefix(x, "*")) && !seen[x] {
			seen[x] = true
			remote = append(remote, x)
		}
	}
	if len(remote) > 0 {
		return "loads scripts from " + strings.Join(remote[:min(3, len(remote))], ", "), true
	}
	return "", false
}
