package extintel

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// ---------------------------------------------------------------------------
// Name anomalies
// ---------------------------------------------------------------------------

// brands worth impersonating. Keep this list focused: every extra brand is a
// new false-positive source for legitimate look-alike names.
var brands = []string{
	"adguard", "adblock", "ublock", "lastpass", "bitwarden", "1password",
	"dashlane", "grammarly", "honey", "paypal", "metamask", "phantom",
	"rabby", "ledger", "trezor", "keeper", "norton", "mcafee", "avast",
	"avg", "malwarebytes", "kaspersky", "eset", "bitdefender", "sophos",
	"cloudflare", "google", "microsoft", "mozilla", "adobe", "apple",
	"amazon", "netflix", "spotify", "slack", "zoom", "notion", "evernote",
	"pocket", "darkreader", "ghostery", "privacybadger", "tampermonkey",
}

var brandSet = set(brands...)

// homoglyphs: Cyrillic/Greek characters that render like Latin letters. Used
// only to raise a signal, never to block.
var homoglyphs = func() map[rune]struct{} {
	m := map[rune]struct{}{}
	for _, r := range "абвгдеёжзийклмнопрстуфхцчшщъыьэюяαβγδεζηθικλμνξοπρστυφχψω" {
		m[r] = struct{}{}
	}
	return m
}()

// casefold is python str.casefold().
func casefold(s string) string { return cases.Fold().String(s) }

// nfkcFold is unicodedata.normalize("NFKC", s).casefold().
func nfkcFold(s string) string { return casefold(norm.NFKC.String(s)) }

// keepAZ09 is re.sub(r"[^a-z0-9]+", "", s).
func keepAZ09(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
}

func normaliseName(value string) string {
	v := nfkcFold(value)
	v = strings.ReplaceAll(v, "0", "o")
	v = strings.ReplaceAll(v, "1", "l")
	v = strings.ReplaceAll(v, "rn", "m")
	return keepAZ09(v)
}

// normalisedBrands: same mapping as the names they are compared with
// ("1password" -> "lpassword"), deduplicated in order.
var normalisedBrands = func() []string {
	seen := map[string]bool{}
	var out []string
	for _, b := range brands {
		n := normaliseName(b)
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}()

// publisherSuffixes: trailing legal/corporate words dropped before comparing
// publisher names, so "Google LLC" / "Meta Platforms, Inc." match.
var publisherSuffixes = set(
	"inc", "llc", "ltd", "limited", "corp", "corporation", "co", "company",
	"gmbh", "ag", "sa", "srl", "sro", "bv", "plc", "pty", "software", "systems",
	"security", "technologies", "platforms", "labs", "lab",
	// Store author names often append these (AMO: "1Password Devs").
	"devs", "dev", "developers", "developer", "team",
)

func editDistanceAtMostOne(a, b string) bool {
	if a == b {
		return true
	}
	if d := len(a) - len(b); d > 1 || d < -1 {
		return false
	}
	if len(a) == len(b) {
		var diffs []int
		for i := 0; i < len(a); i++ {
			if a[i] != b[i] {
				diffs = append(diffs, i)
			}
		}
		if len(diffs) <= 1 {
			return true
		}
		// A single adjacent transposition ("adgaurd" -> "adguard") is the most
		// common brand typo; Levenshtein distance 2 but worth flagging.
		if len(diffs) == 2 && diffs[1] == diffs[0]+1 {
			i, j := diffs[0], diffs[1]
			return a[i] == b[j] && a[j] == b[i]
		}
		return false
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	i, j := 0, 0
	skipped := false
	for i < len(a) && j < len(b) {
		if a[i] == b[j] {
			i++
			j++
			continue
		}
		if skipped {
			return false
		}
		skipped = true
		j++
	}
	return true
}

func signal(code string, weight int64, detail string) map[string]any {
	return map[string]any{"code": code, "weight": weight, "detail": detail}
}

// nameAnomalySignals is name_anomaly_signals: heuristic malformed/typosquat
// detection. Deliberately conservative: a hit is a review signal, not a
// verdict. vouched: the store vouches for the publisher of a verified store
// install, so a brand look-alike name is a real product; brand checks are
// reported but not penalised.
func nameAnomalySignals(name, displayName string, vouched bool) ([]map[string]any, int64) {
	display := displayName
	if display == "" {
		display = name
	}
	display = pyStrip(display)
	signals := []map[string]any{}
	var penalty int64
	add := func(code string, weight int64, detail string) {
		signals = append(signals, signal(code, weight, detail))
		penalty += weight
	}

	if display == "" {
		add("missing-name", 12, "extension has no name or display name")
		return signals, min(penalty, 35)
	}
	if strings.ContainsAny(display, `\/`) || strings.HasSuffix(display, ".crx") || strings.HasSuffix(display, ".xpi") {
		add("path-as-name", 12, "name looks like an install path: "+runePrefix(display, 120))
	}
	for _, r := range casefold(display) {
		if _, ok := homoglyphs[r]; ok {
			add("mixed-script-name", 20, "name contains Cyrillic/Greek characters that mimic Latin")
			break
		}
	}
	if strings.ContainsFunc(display, func(r rune) bool { return r <= 0x1f || r == 0x7f }) {
		add("control-characters", 15, "name contains control characters")
	}
	if n := len([]rune(display)); n > 80 {
		add("oversized-name", 6, fmt.Sprintf("name is %d characters", n))
	}
	if strings.Count(display, ".") >= 4 && !strings.Contains(display, " ") && !strings.HasSuffix(display, "@") {
		add("dotted-identifier-name", 4, "name looks like a reverse-DNS identifier")
	}

	compact := normaliseName(display)
	// The exact brand spelling ("1Password") is the brand itself, not a
	// typosquat; only look-alikes ("1Passw0rd", "adgaurd") are flagged.
	exact := keepAZ09(nfkcFold(display))
	var hit map[string]any
	var hitWeight int64
	if len(compact) >= 5 && !has(brandSet, exact) {
		for _, brand := range normalisedBrands {
			if editDistanceAtMostOne(compact, brand) {
				hit, hitWeight = signal("typosquat-brand", 18, "name is one edit away from the '"+brand+"' brand"), 18
				break
			}
			if strings.HasPrefix(compact, brand) && len(compact)-len(brand) <= 2 {
				suffix := compact[len(brand):]
				if has(set("x", "pro", "plus", "app", "ex", "official"), suffix) {
					hit, hitWeight = signal("brand-affix", 8, "name appends '"+suffix+"' to the '"+brand+"' brand"), 8
					break
				}
			}
		}
	}
	switch {
	case hit != nil && vouched:
		signals = append(signals, signal("brand-lookalike-vouched", 0,
			hit["detail"].(string)+", but the store vouches for this publisher; not penalised"))
	case hit != nil:
		add(hit["code"].(string), hitWeight, hit["detail"].(string))
	}
	return signals, min(penalty, 35)
}

// ---------------------------------------------------------------------------
// Publisher reputation (config/known_publishers.json, reloaded on change)
// ---------------------------------------------------------------------------

func normalisePublisher(value any) string {
	folded := nfkcFold(cleanStr(value))
	// re.sub(r"[^\w\s]+", "", ...)
	kept := strings.Map(func(r rune) rune {
		if isPyWord(r) || isPySpace(r) {
			return r
		}
		return -1
	}, folded)
	words := pySplit(kept)
	for len(words) > 1 && has(publisherSuffixes, words[len(words)-1]) {
		words = words[:len(words)-1]
	}
	return strings.Join(words, " ")
}

var (
	cwsPublisherIDRe = regexp.MustCompile(`^u[0-9a-f]{32}$`)
	appleTeamIDRe    = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	chromeExtIDRe    = regexp.MustCompile(`^[a-p]{32}$`)
)

type publisherSets struct {
	names, chromeIDs, edgeExtIDs, appleTeamIDs map[string]struct{}
	amoIDs                                     map[int64]struct{}
}

func emptyPublisherSets() publisherSets {
	return publisherSets{
		names: map[string]struct{}{}, chromeIDs: map[string]struct{}{},
		edgeExtIDs: map[string]struct{}{}, appleTeamIDs: map[string]struct{}{},
		amoIDs: map[int64]struct{}{},
	}
}

type pubKey struct {
	path  string
	mtime time.Time
}

var (
	pubMu    sync.Mutex
	pubCache struct {
		key  *pubKey
		sets publisherSets
	}
)

func parseKnownPublishers(doc any) (publisherSets, error) {
	out := emptyPublisherSets()
	m, _ := toMap(doc)
	entries, ok := toList(m["publishers"])
	if m == nil || !ok {
		return out, errors.New("expected an object with a 'publishers' list")
	}
	for idx, raw := range entries {
		entry, _ := toMap(raw)
		ids, authors, edgeExts, teams, err := validatePublisher(entry)
		if err != nil {
			var label any = raw
			if entry != nil {
				label = entry["name"]
			}
			slog.Warn(fmt.Sprintf("known_publishers: skipping entry %d (%v): %v", idx, pyStr(label), err))
			continue
		}
		// Only explicit match_names are name-trusted; `name` is a label. Entries
		// verified by Chrome ID alone must not become trusted names elsewhere.
		names, _ := toList(entry["match_names"])
		for _, n := range names {
			if np := normalisePublisher(n); np != "" {
				out.names[np] = struct{}{}
			}
		}
		for _, s := range ids {
			out.chromeIDs[s] = struct{}{}
		}
		for _, a := range authors {
			out.amoIDs[a] = struct{}{}
		}
		for _, s := range edgeExts {
			out.edgeExtIDs[s] = struct{}{}
		}
		for _, s := range teams {
			out.appleTeamIDs[s] = struct{}{}
		}
	}
	return out, nil
}

// idList validates entry[key] (`entry.get(key) or []`) element-wise.
func idList(entry map[string]any, key string, ok func(any) bool) ([]any, error) {
	v := entry[key]
	if !truthy(v) {
		return nil, nil
	}
	list, isList := toList(v)
	if !isList {
		return nil, fmt.Errorf("invalid %s %v", key, pyStr(v))
	}
	var bad []string
	for _, e := range list {
		if !ok(e) {
			bad = append(bad, pyStr(e))
		}
	}
	if bad != nil {
		return nil, fmt.Errorf("invalid %s %v", key, bad)
	}
	return list, nil
}

func validatePublisher(entry map[string]any) (ids []string, authors []int64, edgeExts, teams []string, err error) {
	if entry == nil || cleanStr(entry["name"]) == "" {
		return nil, nil, nil, nil, errors.New("missing name")
	}
	if _, ok := pyFromISO(strings.ReplaceAll(cleanStr(entry["added_at"]), "Z", "+00:00")); !ok {
		return nil, nil, nil, nil, fmt.Errorf("Invalid isoformat string: %q", cleanStr(entry["added_at"]))
	}
	strMatch := func(rx *regexp.Regexp) func(any) bool {
		return func(v any) bool { s, ok := v.(string); return ok && rx.MatchString(s) }
	}
	l, err := idList(entry, "chrome_publisher_ids", strMatch(cwsPublisherIDRe))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, v := range l {
		ids = append(ids, v.(string))
	}
	l, err = idList(entry, "amo_author_ids", func(v any) bool { i, ok := intOf(v); return ok && i > 0 })
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, v := range l {
		i, _ := intOf(v)
		authors = append(authors, i)
	}
	l, err = idList(entry, "edge_extension_ids", strMatch(chromeExtIDRe))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, v := range l {
		edgeExts = append(edgeExts, v.(string))
	}
	l, err = idList(entry, "apple_team_ids", strMatch(appleTeamIDRe))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, v := range l {
		teams = append(teams, v.(string))
	}
	return ids, authors, edgeExts, teams, nil
}

// knownPublishers is known_publishers(): reloaded when the file changes. A
// missing or unreadable file trusts nobody (logged), never a built-in default.
func knownPublishers() publisherSets {
	path := KnownPublishersPath()
	var key *pubKey
	if path != "" {
		if st, err := os.Stat(path); err == nil {
			key = &pubKey{path: path, mtime: st.ModTime()}
		}
	}
	pubMu.Lock()
	defer pubMu.Unlock()
	if key != nil && pubCache.key != nil && *key == *pubCache.key {
		return pubCache.sets
	}
	sets := emptyPublisherSets()
	if key == nil {
		shown := path
		if shown == "" {
			shown = "config/known_publishers.json"
		}
		slog.Warn(fmt.Sprintf("known_publishers: file not found (%s); no publisher is trusted", shown))
	} else if err := loadPublishers(path, &sets); err != nil {
		sets = emptyPublisherSets()
		slog.Warn(fmt.Sprintf("known_publishers: cannot load %s (%v); no publisher is trusted", path, err))
	} else {
		slog.Info(fmt.Sprintf("known_publishers: loaded %d names, %d Chrome publisher IDs, "+
			"%d AMO author IDs, %d Edge extension IDs, %d Apple team IDs from %s",
			len(sets.names), len(sets.chromeIDs), len(sets.amoIDs), len(sets.edgeExtIDs),
			len(sets.appleTeamIDs), path))
	}
	pubCache.key, pubCache.sets = key, sets
	return sets
}

func loadPublishers(path string, sets *publisherSets) error {
	data, err := os.ReadFile(path) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		return fmt.Errorf("read known publishers: %w", err)
	}
	doc, err := pyJSONLoads([]byte(decodeReplace(data)))
	if err != nil {
		return fmt.Errorf("parse known publishers: %w", err)
	}
	s, err := parseKnownPublishers(doc)
	if err != nil {
		return err
	}
	*sets = s
	return nil
}

// publisherIsReputable is publisher_is_reputable(*values): true when a
// store-sourced developer/publisher NAME is a known publisher. Normalized
// equality, not a word search, so "Box Hill Scams" / "Meta Tools" do not
// match "box" / "meta". Callers pass store fields only.
func publisherIsReputable(values ...any) bool {
	names := knownPublishers().names
	for _, v := range values {
		if truthy(v) && has(names, normalisePublisher(v)) {
			return true
		}
	}
	return false
}

// chromePublisherIsReputable: Chrome Web Store trust is by immutable
// publisher ID, never display name.
func chromePublisherIsReputable(publisherID any) bool {
	s, ok := publisherID.(string)
	return ok && s != "" && has(knownPublishers().chromeIDs, s)
}

// amoAuthorIsReputable: Firefox trust is by immutable AMO author user ID.
func amoAuthorIsReputable(authorIDs any) bool {
	ids := knownPublishers().amoIDs
	list, _ := toList(authorIDs)
	for _, v := range list {
		if i, ok := intOf(v); ok && has(ids, i) {
			return true
		}
	}
	return false
}

// appleTeamIsReputable: Safari trust is by the containing app's Apple
// code-signing team ID, never the App Store seller name.
func appleTeamIsReputable(teamID string) bool {
	return teamID != "" && has(knownPublishers().appleTeamIDs, teamID)
}

// edgeExtensionIsReputable: Edge exposes no publisher ID, so trust is per
// listed extension ID, and only while the Edge store reports it public.
func edgeExtensionIsReputable(extensionID, storeStatus any) bool {
	id, _ := extensionID.(string)
	return storeStatus == "public" && id != "" && has(knownPublishers().edgeExtIDs, id)
}

// ---------------------------------------------------------------------------
// Store install verification
// ---------------------------------------------------------------------------

// Browser-managed store directories, anchored at the user's home. Paths are
// matched whole after normalizing "\" to "/", so an unpacked extension placed
// in some other ".../Extensions/<id>/<ver>" does not pass.
const (
	homeRe        = `(?:/Users/[^/]+|/home/[^/]+|/root|[a-z]:/Users/[^/]+)`
	chromiumRoots = `Library/Application Support/(?:Google/Chrome(?: Beta| Canary| Dev)?|Chromium` +
		`|Microsoft Edge(?: Beta| Dev| Canary)?|BraveSoftware/Brave-Browser(?:-Beta|-Nightly)?` +
		`|Vivaldi|com\.operasoftware\.Opera|Arc/User Data|Comet|Dia/User Data)` +
		// Linux
		`|\.config/(?:google-chrome(?:-beta|-unstable)?|chromium|microsoft-edge(?:-beta|-dev)?` +
		`|BraveSoftware/Brave-Browser(?:-Beta|-Nightly)?|vivaldi|opera)` +
		`|snap/chromium/common/chromium` +
		// Windows
		`|AppData/Local/(?:Google/Chrome(?: Beta| Dev| SxS)?|Chromium` +
		`|Microsoft/Edge(?: Beta| Dev| SxS)?|BraveSoftware/Brave-Browser(?:-Beta|-Nightly)?` +
		`|Vivaldi)/User Data` +
		`|AppData/Roaming/Opera Software/Opera Stable`
	firefoxRoots = `Library/Application Support/Firefox/Profiles|\.mozilla/firefox` +
		`|snap/firefox/common/\.mozilla/firefox|\.var/app/org\.mozilla\.firefox/\.mozilla/firefox` +
		`|AppData/Roaming/Mozilla/Firefox/Profiles`
)

var (
	storePathMu    sync.Mutex
	storePathCache = map[string]*regexp.Regexp{}
)

func storePathRe(store, extensionID string) *regexp.Regexp {
	if store == "safari" { // App Store or not, the extension lives in its app bundle
		return safariAppexRe
	}
	k := store + "\x00" + extensionID
	storePathMu.Lock()
	defer storePathMu.Unlock()
	if rx, ok := storePathCache[k]; ok {
		return rx
	}
	eid := regexp.QuoteMeta(extensionID)
	var tail string
	if store == "firefox" {
		tail = `(?:` + firefoxRoots + `)/[^/]+/extensions/` + eid + `\.xpi`
	} else { // Chromium family + Edge; Opera has no profile segment
		tail = `(?:` + chromiumRoots + `)(?:/[^/]+)?/Extensions/` + eid + `/[^/]+/?`
	}
	rx, err := regexp.Compile(`(?i)^(?:` + homeRe + `/` + tail + `)$`)
	if err != nil { // e.g. an absurdly long host-reported ID: fail closed
		return nil
	}
	if len(storePathCache) >= 4096 {
		storePathCache = map[string]*regexp.Regexp{}
	}
	storePathCache[k] = rx
	return rx
}

// storeInstallVerified is store_install_verified: true when every host
// install of the extension is a store install. Fails closed: needs at least
// one install whose path positively matches a store directory. A missing path
// counts against trust, except on ChromeOS hosts (platform "chrome"), whose
// agent never reports extension paths; those never count as evidence.
//
// Residual: a local user who copies an unpacked extension INTO the real
// profile directory still passes.
func storeInstallVerified(store any, extensionID string, installs any) bool {
	st, _ := store.(string)
	// Safari extensions carry no ID of their own (see safariContainingApp).
	list, _ := toList(installs)
	if (extensionID == "" && st != "safari") || len(list) == 0 {
		return false
	}
	pattern := storePathRe(st, extensionID)
	if pattern == nil {
		return false
	}
	verified := 0
	for _, item := range list {
		var path, platform any
		if m, ok := toMap(item); ok {
			path, platform = m["path"], m["platform"]
		} else {
			path = item
		}
		p, _ := path.(string)
		p = strings.ReplaceAll(pyStrip(p), `\`, "/")
		if p == "" {
			if platform == "chrome" {
				continue
			}
			return false
		}
		if !pattern.MatchString(p) {
			return false
		}
		verified++
	}
	return verified > 0
}
