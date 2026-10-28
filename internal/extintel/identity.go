package extintel

import (
	"crypto/sha1" // #nosec G505 -- not security: stable fallback key, same as python hashlib.sha1
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"
)

var browserExtensionSources = set("chrome_extensions", "firefox_addons", "safari_extensions", "ie_extensions")

// chromiumBuiltinIDs are Chrome/Edge component extensions. Path heuristics
// cover the long tail; these IDs cover builds where Fleet does not return an
// installed path.
var chromiumBuiltinIDs = set(
	"aohghmighlieiainnegkcijnfilokake", // Google Docs
	"aapocclcgogkmnckokdopfmhonfmgoek", // Google Slides
	"felcaaldnbdncclmgdcncolpebgiejap", // Google Sheets
	"ghbmnnjooekpmoecnnnilnnbdlolhkhi", // Google Docs Offline
	"nmmhkkegccagdldgiimedpiccmgmieda", // Chrome Web Store payments
	"mhjfbmdgcfjbbpaeojofohoefgiehjai", // Chrome PDF viewer
	"nkeimhogjdpnpccoofpliimaahmaaome", // Chrome component (legacy)
	"pkedcjkdefgpdelpbcmbmeomcjbeemfm", // Chrome Media Router
)

var firefoxBuiltinSuffixes = []string{"@mozilla.org", "@mozilla.com"}

// isPyWord is python's unicode \w for one code point.
func isPyWord(r rune) bool { return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r) }

func isAtoP(r rune) bool { return r >= 'a' && r <= 'p' || r >= 'A' && r <= 'P' }

// extIDSearch is _EXT_ID_RE.search(c) (`\b([a-p]{32})\b`, IGNORECASE) with
// python's unicode word boundaries; returns the lowercased ID or "".
func extIDSearch(c string) string {
	runes := []rune(c)
	for i := 0; i+32 <= len(runes); i++ {
		if i > 0 && isPyWord(runes[i-1]) {
			continue
		}
		ok := true
		for _, r := range runes[i : i+32] {
			if !isAtoP(r) {
				ok = false
				break
			}
		}
		if !ok || (i+32 < len(runes) && isPyWord(runes[i+32])) {
			continue
		}
		return strings.ToLower(string(runes[i : i+32]))
	}
	return ""
}

// firefoxGUIDMatch is _FIREFOX_GUID_RE.match:
// `^(\{[0-9a-f-]{36}\}|[^@\s]+@[^@\s]+)$`, IGNORECASE.
func firefoxGUIDMatch(c string) bool {
	if len(c) == 38 && c[0] == '{' && c[37] == '}' {
		ok := true
		for _, r := range c[1:37] {
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r == '-') {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	local, domain, found := strings.Cut(c, "@")
	if !found || local == "" || domain == "" || strings.Contains(domain, "@") {
		return false
	}
	return !strings.ContainsFunc(c, isPySpace)
}

func inferStore(source, browser, extensionFor string, installedPaths []string) string {
	switch strings.ToLower(source) {
	case "firefox_addons":
		return "firefox"
	case "safari_extensions":
		return "safari"
	case "ie_extensions":
		return "edge"
	case "chrome_extensions":
	default:
		return "unknown"
	}
	b := strings.ToLower(browser + " " + extensionFor)
	for _, candidate := range []string{"edge", "brave", "opera", "vivaldi", "chromium"} {
		if strings.Contains(b, candidate) {
			return candidate
		}
	}
	// The install path is more reliable than osquery's `extension_for` on
	// Windows, where Edge can report `chrome`.
	for _, path := range installedPaths {
		p := strings.ToLower(path)
		switch {
		case strings.Contains(p, `microsoft\edge`) || strings.Contains(p, "microsoft edge.app"):
			return "edge"
		case strings.Contains(p, "brave"):
			return "brave"
		case strings.Contains(p, "opera"):
			return "opera"
		case strings.Contains(p, "vivaldi"):
			return "vivaldi"
		}
	}
	return "chrome"
}

func inferExtensionID(source, name, displayName string, installedPaths []string) string {
	candidates := append([]string{name, displayName}, installedPaths...)
	for _, cand := range candidates {
		c := pyStrip(cand)
		if c == "" {
			continue
		}
		if source == "chrome_extensions" || source == "ie_extensions" {
			if id := extIDSearch(c); id != "" {
				return id
			}
		}
		if source == "firefox_addons" && firefoxGUIDMatch(c) {
			return c
		}
		// "@" is reserved for keys bound to a signing team (WithSafariApp):
		// a host-reported name must never collide with one.
		if source == "safari_extensions" && strings.Count(c, ".") >= 2 &&
			!strings.Contains(c, " ") && !strings.Contains(c, "@") {
			return c
		}
	}
	return ""
}

// osquery reports only Safari extensions bundled in a top-level /Applications app.
var safariAppexRe = regexp.MustCompile(`^(/Applications/[^/]+\.app)/Contents/PlugIns/[^/]+\.appex/?$`)

// safariContainingApp is safari_containing_app: `/Applications/X.app` for a
// Safari `.appex` path, else "".
func safariContainingApp(path any) string {
	if m := safariAppexRe.FindStringSubmatch(cleanStr(path)); m != nil {
		return m[1]
	}
	return ""
}

// safariApp unpacks one value of WithSafariApp's apps map: python's
// (bundle ID, team ID or None) tuple, as []any{bundle, team} (also []string,
// [2]string, [2]any).
func safariApp(v any) (bundle, team any) {
	switch t := v.(type) {
	case [2]string:
		return t[0], t[1]
	case [2]any:
		return t[0], t[1]
	}
	if l, ok := toList(v); ok {
		if len(l) > 0 {
			bundle = l[0]
		}
		if len(l) > 1 {
			team = l[1]
		}
	}
	return bundle, team
}

// WithSafariApp replaces with_safari_app(ext, apps): binds a Safari extension
// to its containing app, returning a new map with extension_id/extension_key
// rewritten, or ext unchanged.
//
// apps is {app path: []any{bundle ID, team ID or nil}} from the same host's
// Fleet `apps` rows. Safari extensions carry no ID, so when the app is known
// the identity becomes `<app bundle ID>/<appex name>@<team>`: extensions of
// different apps never share a node (and its App Store lookup).
func WithSafariApp(ext map[string]any, apps map[string]any) map[string]any {
	path, _ := pyOr(ext["installed_path"], "").(string)
	appPath := safariContainingApp(path)
	if ext["store"] != "safari" || appPath == "" {
		return ext
	}
	// Extensions often share generic names ("Safari", "Extension"): show the app.
	appName := strings.TrimSuffix(appPath[strings.LastIndex(appPath, "/")+1:], ".app")
	if dn, ok := ext["display_name"].(string); ok && dn != "" && !strings.HasPrefix(dn, appName+" › ") {
		ext = copyMap(ext)
		ext["display_name"] = appName + " › " + dn
	}
	bundle, team := safariApp(apps[appPath])
	if !truthy(bundle) {
		return ext
	}
	// The signing team is part of the identity: differently signed copies
	// never share a node, so one host cannot lend another its team.
	trimmed := strings.TrimRight(path, "/")
	teamStr := "unsigned"
	if truthy(team) {
		teamStr = pyStr(team)
	}
	extID := pyStr(bundle) + "/" + trimmed[strings.LastIndex(trimmed, "/")+1:] + "@" + teamStr
	out := copyMap(ext)
	out["extension_id"] = extID
	out["extension_key"] = strings.ToLower("ext:safari:" + extID)
	out["app_bundle_id"] = bundle
	if truthy(team) {
		out["app_team_id"] = team
	} else {
		out["app_team_id"] = nil
	}
	return out
}

// DeriveExtensionIdentity replaces derive_extension_identity(software):
// additive extension fields (kind, extension_id, extension_key, browser,
// store, ...) for a Fleet software row, or nil when it is not an extension.
// Never fails: malformed Fleet rows fall back to a name-derived key so they
// still appear in the inventory instead of disappearing.
func DeriveExtensionIdentity(software map[string]any) map[string]any {
	if software == nil {
		return nil
	}
	source := strings.ToLower(cleanStr(software["source"]))
	if !has(browserExtensionSources, source) {
		return nil
	}
	name := cleanStr(software["name"])
	displayName := cleanStr(software["display_name"])
	browser := strings.ToLower(cleanStr(software["browser"]))
	extensionFor := strings.ToLower(cleanStr(software["extension_for"]))
	raw, ok := toList(software["installed_paths"])
	if !ok {
		raw = nil
		if truthy(software["installed_paths"]) {
			raw = []any{software["installed_paths"]}
		}
	}
	installedPaths := []string{}
	for _, p := range raw {
		if truthy(p) {
			installedPaths = append(installedPaths, pyStr(p))
		}
	}

	store := inferStore(source, browser, extensionFor, installedPaths)
	extID := cleanStr(software["extension_id"])
	if extID == "" {
		extID = inferExtensionID(source, name, displayName, installedPaths)
	}
	var extensionKey string
	if extID != "" {
		// Lowercase: ingestion lowercases Software.name, and name == extension_key
		// for extensions, so a mixed-case key would churn nodes every cycle.
		extensionKey = strings.ToLower("ext:" + store + ":" + extID)
	} else {
		// Stable fallback for malformed data. The store lookup is skipped, but
		// the inventory row still exists and can be reviewed.
		src := name
		if src == "" {
			src = displayName
		}
		sum := sha1.Sum([]byte(src)) // #nosec G401 -- not security: stable fallback key, see import
		extensionKey = "ext:" + store + ":name:" + hex.EncodeToString(sum[:])[:16]
	}

	var paths, first any
	if len(installedPaths) > 0 {
		n := min(len(installedPaths), 10)
		paths = append([]string(nil), installedPaths[:n]...)
		first = installedPaths[0]
	}
	dn := displayName
	if dn == "" {
		dn = name
	}
	return map[string]any{
		"kind":            "browser_extension",
		"store":           store,
		"extension_id":    optStr(extID),
		"extension_key":   extensionKey,
		"browser":         optStr(browser),
		"extension_for":   optStr(extensionFor),
		"display_name":    optStr(dn),
		"installed_paths": paths,
		"installed_path":  first,
		"is_builtin":      isBuiltin(store, extID, installedPaths),
	}
}

// Built-in (component) extension install roots per store, matched against the
// lowercased path with "/" -> "\". Windows: Program Files or the per-user
// AppData\Local install; macOS: the app bundle under /Applications.
const winRoot = `[a-z]:\\(?:program files(?: \(x86\))?|users\\[^\\]+\\appdata\\local)\\`

var builtinPathRes = map[string]*regexp.Regexp{
	"chrome":  regexp.MustCompile(`^` + winRoot + `google\\chrome\\application\\`),
	"edge":    regexp.MustCompile(`^` + winRoot + `microsoft\\edge\\application\\`),
	"brave":   regexp.MustCompile(`^` + winRoot + `bravesoftware\\brave-browser\\application\\`),
	"vivaldi": regexp.MustCompile(`^` + winRoot + `vivaldi\\application\\`),
	"firefox": regexp.MustCompile(`^(?:` + winRoot + `mozilla firefox\\` +
		`|\\applications\\firefox\.app\\contents\\resources\\` +
		`|\\usr\\lib(?:64)?\\firefox(?:-esr)?\\)browser\\features\\`),
}

// IsBrowserBuiltin replaces is_browser_builtin(record): true for
// vendor-shipped/component extensions that must never be flagged.
func IsBrowserBuiltin(record map[string]any) bool {
	return isBuiltin(cleanStr(record["store"]), cleanStr(record["extension_id"]), record["installed_paths"])
}

func isBuiltin(store, extID string, installedPaths any) bool {
	store = strings.ToLower(pyStrip(store))
	extID = strings.ToLower(pyStrip(extID))
	if store == "firefox" {
		for _, sfx := range firefoxBuiltinSuffixes {
			if strings.HasSuffix(extID, sfx) {
				return true
			}
		}
	}
	if has(ChromiumStores, store) && has(chromiumBuiltinIDs, extID) {
		return true
	}
	var paths []any
	if s, ok := installedPaths.(string); ok {
		if s != "" {
			paths = []any{s}
		}
	} else if truthy(installedPaths) {
		paths, _ = toList(installedPaths)
	}
	rx := builtinPathRes[store]
	for _, path := range paths {
		p := strings.ReplaceAll(strings.ToLower(pyStr(path)), "/", `\`)
		// Anchored at the browser's install root: a host-reported path is
		// attacker-influenced, so "...\application\" elsewhere is not built-in.
		if rx != nil && rx.MatchString(p) {
			return true
		}
		// Every App Store Safari extension lives in its app's Contents/PlugIns,
		// so only extensions bundled with Safari itself or the OS are built-in.
		if store == "safari" && (strings.HasPrefix(p, `\applications\safari.app\`) || strings.HasPrefix(p, `\system\`)) {
			return true
		}
	}
	return false
}
