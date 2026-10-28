package extintel

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	chromeHosts = set(
		"clients2.google.com",            // update2 endpoint
		"storage.googleapis.com",         // CRX CDN
		"clients2.googleusercontent.com", // CRX CDN (codebase target)
		"redirector.gvt1.com",            // CRX CDN redirector
		"edgedl.me.gvt1.com",             // CRX CDN edge download host
		"chromewebstore.google.com",      // listing RPC (batchexecute)
	)
	edgeHosts    = set("microsoftedge.microsoft.com")
	amoHosts     = set("addons.mozilla.org")
	mozillaHosts = set("firefox.settings.services.mozilla.com")
	operaHosts   = set("addons.opera.com")
	appleHosts   = set("itunes.apple.com")
)

const (
	maxManifestBytes = 1024 * 1024
	maxPackageBytes  = 50 * 1024 * 1024
)

// jsonBody is _json_loads: nil on any decode failure.
func jsonBody(body []byte) any {
	v, err := pyJSONLoads([]byte(decodeReplace(body)))
	if err != nil {
		return nil
	}
	return v
}

// markRateLimited is _mark_rate_limited: flag 429 / 503+Retry-After so the
// worker trips its per-store breaker. `error` is set so the result is never
// cached; `rate_limited` tells the worker to leave the item for next cycle.
func markRateLimited(meta map[string]any, status int, headers map[string]string) bool {
	if status == 429 || (status == 503 && header(headers, "Retry-After") != "") {
		meta["error"] = fmt.Sprintf("%s store HTTP %d (rate limited)", pyStr(meta["store"]), status)
		meta["rate_limited"] = true
		return true
	}
	return false
}

// first is _first: the first value not in (None, "", [], {}).
func first(data map[string]any, keys ...string) any {
	for _, k := range keys {
		if v := data[k]; !isBlank(v) {
			return v
		}
	}
	return nil
}

// localisedName is _localised_name. Go maps are unordered, so the
// any-locale fallback takes the first non-empty string by sorted key
// (python: JSON order).
func localisedName(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	m, ok := toMap(v)
	if !ok {
		return ""
	}
	for _, k := range []string{"en-US", "en", "en_GB"} {
		if s, ok := m[k].(string); ok {
			return s
		}
	}
	for _, k := range sortedKeys(m) {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func manifestFromMeta(meta map[string]any) map[string]any {
	manifest := first(meta, "manifest", "manifest_json", "manifestJson")
	if s, ok := manifest.(string); ok {
		v, err := pyJSONLoads([]byte(s))
		if err != nil {
			return map[string]any{}
		}
		manifest = v
	}
	if m, ok := toMap(manifest); ok {
		return m
	}
	return map[string]any{}
}

// manifestFields is _manifest_fields.
func manifestFields(meta map[string]any) map[string]any {
	manifest := manifestFromMeta(meta)
	if len(manifest) == 0 {
		return map[string]any{}
	}
	contentMatches := []string{}
	if list, ok := toList(manifest["content_scripts"]); ok {
		for _, cs := range list {
			if m, ok := toMap(cs); ok {
				contentMatches = append(contentMatches, asStringList(m["matches"])...)
			}
		}
	}
	mv, mvOK := asInt(manifest["manifest_version"])
	return map[string]any{
		"name":                    optStr(cleanStr(manifest["name"])),
		"version":                 optStr(cleanStr(manifest["version"])),
		"manifest_version":        optInt(mv, mvOK),
		"permissions":             asStringList(manifest["permissions"]),
		"optional_permissions":    asStringList(manifest["optional_permissions"]),
		"host_permissions":        asStringList(manifest["host_permissions"]),
		"content_script_matches":  contentMatches,
		"update_url":              optStr(cleanStr(manifest["update_url"])),
		"homepage_url":            optStr(cleanStr(manifest["homepage_url"])),
		"content_security_policy": cspText(manifest["content_security_policy"]),
	}
}

// mergeFields copies fields whose value is not in (None, [], ""); onlyMissing
// also skips keys meta already has a truthy value for.
func mergeFields(meta, fields map[string]any, onlyMissing bool) {
	for k, v := range fields {
		if isBlank(v) {
			if _, isMap := v.(map[string]any); !isMap {
				continue
			}
		}
		if onlyMissing && truthy(meta[k]) {
			continue
		}
		meta[k] = v
	}
}

// parseCRX is _parse_crx: manifest.json from a CRX2/CRX3 or plain ZIP payload.
func parseCRX(data []byte) (map[string]any, error) {
	if len(data) == 0 {
		return nil, errors.New("empty CRX payload")
	}
	zipBytes := data
	if bytes.HasPrefix(data, []byte("Cr24")) {
		if len(data) < 12 {
			return nil, errors.New("truncated CRX header")
		}
		skip := func(n uint64) []byte {
			if n >= uint64(len(data)) {
				return nil
			}
			return data[n:]
		}
		switch version := binary.LittleEndian.Uint32(data[4:8]); version {
		case 3:
			zipBytes = skip(12 + uint64(binary.LittleEndian.Uint32(data[8:12])))
		case 2:
			if len(data) < 16 {
				return nil, errors.New("truncated CRX2 header")
			}
			zipBytes = skip(16 + uint64(binary.LittleEndian.Uint32(data[8:12])) + uint64(binary.LittleEndian.Uint32(data[12:16])))
		default:
			return nil, fmt.Errorf("unsupported CRX version %d", version)
		}
	}
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("CRX payload is not a ZIP: %w", err)
	}
	if len(zr.File) > 5000 {
		return nil, errors.New("CRX contains too many files")
	}
	// Only manifest.json is ever decompressed, so cap that entry, not the
	// archive: real extensions exceed 80 MB uncompressed. The bounded read
	// holds even if the entry under-reports its size. Python's zipfile keeps
	// the last duplicate name.
	var entry *zip.File
	for _, f := range zr.File {
		if f.Name == "manifest.json" {
			entry = f
		}
	}
	if entry == nil {
		return nil, errors.New("CRX has no manifest.json")
	}
	rc, err := entry.Open()
	if err != nil {
		return nil, fmt.Errorf("open manifest.json: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(rc, maxManifestBytes+1))
	rc.Close()
	if err != nil {
		return nil, fmt.Errorf("read manifest.json: %w", err)
	}
	if len(raw) > maxManifestBytes {
		return nil, errors.New("manifest.json exceeds 1 MB")
	}
	v, err := pyJSONLoads([]byte(decodeSig(raw)))
	if err != nil {
		return nil, err
	}
	m, ok := toMap(v)
	if !ok {
		return nil, errors.New("manifest.json is not an object")
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Chrome Web Store
// ---------------------------------------------------------------------------

// Chrome Web Store listing facts come from the store front end's own
// batchexecute RPC. It is undocumented and internal: Google offers no public
// read API. Payload indices were mapped against rendered detail pages on
// 2026-10-27; a payload whose shape or ID does not match is rejected whole.
const (
	cwsRPCID  = "xY2Ddd"
	cwsRPCURL = "https://chromewebstore.google.com/_/ChromeWebStoreConsumerFeUi/data/" +
		"batchexecute?rpcids=" + cwsRPCID + "&hl=en&rt=c"
	// About 50 KB of response per listing: 40 keeps one POST far below the 8 MB cap.
	cwsRPCBatch = 40
)

// shortcut: the payload carries only the category slug; these labels were
// verified on live pages. Other slugs are shown raw; add pairs once confirmed.
var cwsCategoryLabels = map[string]string{
	"make_chrome_yours/accessibility": "Accessibility",
	"make_chrome_yours/privacy":       "Privacy & Security",
	"productivity/communication":      "Communication",
	"productivity/developer":          "Developer Tools",
	"productivity/education":          "Education",
	"productivity/tools":              "Tools",
	"productivity/workflow":           "Workflow & Planning",
}

var (
	emailDomainRe = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}$`)
	bundleIDRe    = regexp.MustCompile(`^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$`)
	operaSlugRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,100}$`)
)

// emailOK is _EMAIL_RE.match: `^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}$`.
func emailOK(s string) bool {
	local, domain, found := strings.Cut(s, "@")
	if !found {
		return false
	}
	n := len([]rune(local))
	return n >= 1 && n <= 64 && !strings.ContainsFunc(local, isPySpace) && emailDomainRe.MatchString(domain)
}

// at is _at: nested list indexing, nil when out of range or not a list.
func at(v any, path ...int) any {
	for _, i := range path {
		l, ok := v.([]any)
		if !ok || i >= len(l) {
			return nil
		}
		v = l[i]
	}
	return v
}

// httpURL is _http_url: the value when it is an http(s) URL with a host.
func httpURL(v any) any {
	s := cleanStr(v)
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil
	}
	return s
}

type rpcEnvelope struct {
	payload any
	code    any
}

// parseCWSRPC is _parse_cws_rpc: {tag: envelope} from a batchexecute body.
// Chunks are length-prefixed lines; only lines that parse as a JSON list hold
// envelopes, in any order. A null payload carries a gRPC-style code in env[5]:
// 5 for an ID the store never had, 7 for a removed item.
func parseCWSRPC(body []byte) (map[string]rpcEnvelope, error) {
	text := decodeReplace(body)
	if !strings.HasPrefix(text, ")]}'") {
		return nil, errors.New("listing RPC response lacks the )]}' prefix")
	}
	out := map[string]rpcEnvelope{}
	for _, line := range pySplitLines(text[4:]) {
		chunk, err := pyJSONLoads([]byte(line))
		if err != nil {
			continue
		}
		list, _ := chunk.([]any)
		for _, e := range list {
			env, ok := e.([]any)
			if !ok || len(env) <= 6 || env[0] != "wrb.fr" || env[1] != cwsRPCID {
				continue
			}
			tag, ok := env[6].(string)
			if !ok {
				continue
			}
			var code any
			if c, ok := intOf(at(env, 5, 0)); ok {
				code = c
			}
			out[tag] = rpcEnvelope{payload: env[2], code: code}
		}
	}
	return out, nil
}

// cwsListing is _cws_listing: listing and manifest fields from one RPC
// payload; an error means schema drift.
func cwsListing(extensionID string, payload any) (map[string]any, error) {
	s, ok := payload.(string)
	if !ok {
		return nil, errors.New("payload is not a JSON string")
	}
	data, err := pyJSONLoads([]byte(s))
	if err != nil {
		return nil, err
	}
	item, dev := at(data, 0), at(data, 10)
	if id, _ := at(item, 0).(string); id != extensionID || at(item, 0) == nil {
		return nil, errors.New("payload id or shape does not match the request")
	}
	if _, ok := dev.([]any); !ok {
		return nil, errors.New("payload id or shape does not match the request")
	}
	var manifest any
	if ms, ok := at(item, 18).(string); ok {
		if manifest, err = pyJSONLoads([]byte(ms)); err != nil {
			return nil, err
		}
	}
	mm, ok := toMap(manifest)
	if !ok {
		return nil, errors.New("payload has no manifest object")
	}

	out := map[string]any{"status": "public"}
	mergeFields(out, manifestFields(map[string]any{"manifest": mm}), false)
	// Store display name; the manifest name is often an unresolved __MSG_ key.
	if n := cleanStr(at(item, 2)); n != "" {
		out["name"] = n
	}
	if v, ok := at(data, 13).(string); ok && v != "" {
		out["version"] = v
	}
	if users, ok := intOf(at(item, 14)); ok && users >= 0 {
		out["users"] = users
	}
	if rating, ok := numOf(at(item, 3)); ok && rating >= 0 && rating <= 5 {
		out["rating"] = pyRound1(rating)
	}
	if rc, ok := intOf(at(item, 4)); ok && rc >= 0 {
		out["rating_count"] = rc
	}
	if slug, ok := at(item, 11, 0).(string); ok && slug != "" {
		if label, ok := cwsCategoryLabels[slug]; ok {
			out["category"] = label
		} else {
			out["category"] = slug
		}
	}
	out["featured"] = at(item, 9) == true
	// [0][8] and [0][15] tracked the "good record" badge on every listing
	// probed (2026-10-27); Google's own items show "developed by Google".
	if at(item, 8) == true && at(item, 15) == true {
		out["established_publisher"] = true
	}
	if updated, ok := numOf(at(data, 14, 0)); ok && updated > 0 && updated < 32_503_680_000 { // before year 3000
		out["updated_at"] = pyISOFromUnix(updated)
	}
	website := cleanStr(at(item, 7))
	if website != "" && !strings.Contains(website, "://") {
		website = "https://" + website // the store renders bare hosts as https links
	}
	if w := httpURL(website); w != nil {
		out["developer_website"] = w
	}
	if email := cleanStr(at(dev, 0)); emailOK(email) {
		out["developer_email"] = email
	}
	// Trader is a boolean here but 1 in the page's own blob: test truthiness.
	out["trader"] = truthy(at(dev, 3))
	codes := at(data, 7)
	if codes == nil {
		out["privacy_disclosure"] = "The developer has disclosed that it will not collect or use your data"
	} else if list, ok := codes.([]any); ok {
		ints := make([]int64, 0, len(list))
		labels := make([]string, 0, len(list))
		for _, c := range list {
			i, ok := intOf(c)
			if !ok {
				ints = nil
				break
			}
			ints = append(ints, i)
			if l, ok := cwsPrivacyLabels[i]; ok {
				labels = append(labels, l)
			} else {
				labels = append(labels, fmt.Sprintf("data category %d", i))
			}
		}
		if ints != nil {
			out["privacy_codes"] = ints
			out["privacy_disclosure"] = "The developer has disclosed that it collects or uses: " + strings.Join(labels, ", ")
		}
	}
	if u := httpURL(at(data, 33)); u != nil {
		out["privacy_policy_url"] = u
	}
	if pid, ok := at(dev, 10).(string); ok && cwsPublisherIDRe.MatchString(pid) {
		out["publisher_id"] = pid
	}
	// [10][5] is the name the store shows; [10][7] is the trader's legal
	// name, null for non-traders.
	if p := cleanStr(at(dev, 5)); p != "" {
		out["publisher"] = p
	} else if p := cleanStr(at(dev, 7)); p != "" {
		out["publisher"] = p
	}
	return out, nil
}

func chromeDetailURL(extensionID string) string {
	return "https://chromewebstore.google.com/detail/" + pyQuote(extensionID, "")
}

func clientOr(c *HTTPClient, timeoutSec float64) *HTTPClient {
	if c != nil {
		return c
	}
	return &HTTPClient{TimeoutSec: timeoutSec}
}

// FetchChromeListings replaces fetch_chrome_listings(ids, client=): {id:
// listing meta} from the Chrome Web Store listing RPC. Never fails.
//
// Invalid IDs are dropped before any request. A listed item gets status
// "public" with listing and manifest fields. A removed item (code 7) gets
// "removed". An ID the RPC does not know (code 5) gets status "unlisted" plus
// `listing_missing`, and update2 tells unlisted from never published. Any
// other per-envelope error is an error, never a missing listing.
func FetchChromeListings(ctx context.Context, extensionIDs []string, client *HTTPClient) map[string]map[string]any {
	client = clientOr(client, 12)
	var ids []string
	seen := map[string]bool{}
	for _, id := range extensionIDs {
		if chromeExtIDRe.MatchString(id) && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	out := map[string]map[string]any{}
	limited := map[string]any{"store": "chrome"}
	for start := 0; start < len(ids); start += cwsRPCBatch {
		chunk := ids[start:min(start+cwsRPCBatch, len(ids))]
		if truthy(limited["rate_limited"]) {
			// Rate limited on an earlier chunk: mark the rest without asking again.
			for _, eid := range chunk {
				m := map[string]any{"store": "chrome", "status": "unknown", "url": chromeDetailURL(eid)}
				mergeAll(m, limited)
				out[eid] = m
			}
			continue
		}
		reqs := make([]any, len(chunk))
		for n, eid := range chunk {
			reqs[n] = []any{cwsRPCID, pyDumps([]any{eid}), nil, strconv.Itoa(n + 1)}
		}
		freq := pyDumps([]any{reqs})
		resp := client.Post(ctx, cwsRPCURL, url.Values{"f.req": {freq}}, chromeHosts, maxHTTPBytes)
		limited = map[string]any{"store": "chrome"}
		markRateLimited(limited, resp.Status, resp.Headers)
		var payloads map[string]rpcEnvelope
		if !truthy(limited["rate_limited"]) {
			switch {
			case resp.Status != 200 || resp.Err != "":
				if resp.Err != "" {
					limited["error"] = resp.Err
				} else {
					limited["error"] = fmt.Sprintf("listing RPC HTTP %d", resp.Status)
				}
			default:
				p, err := parseCWSRPC(resp.Body)
				if err != nil {
					limited["error"] = err.Error()
				} else {
					payloads = p
				}
			}
		}
		for n, eid := range chunk {
			meta := map[string]any{"store": "chrome", "status": "unknown", "url": chromeDetailURL(eid)}
			env, found := payloads[strconv.Itoa(n+1)]
			switch {
			case payloads == nil:
				mergeAll(meta, limited)
			case !found:
				meta["error"] = "listing RPC returned no envelope for this id"
			case env.payload != nil:
				listing, err := cwsListing(eid, env.payload)
				if err != nil {
					meta["error"] = "listing RPC schema drift: " + err.Error()
				} else {
					mergeAll(meta, listing)
				}
			case env.code == int64(5):
				meta["status"] = "unlisted"
				meta["listing_missing"] = true
			case env.code == int64(7):
				meta["status"] = "removed"
			case env.code == int64(8):
				meta["rate_limited"] = true
				meta["error"] = "listing RPC code 8 (resource exhausted)"
			default:
				meta["error"] = "listing RPC error code " + pyStr(env.code)
			}
			out[eid] = meta
		}
	}
	return out
}

func mergeAll(dst, src map[string]any) {
	for k, v := range src {
		dst[k] = v
	}
}

// updatecheckAttrs finds the first <updatecheck> element (any namespace) in
// an update2 response. The whole document must parse (python ET.fromstring).
func updatecheckAttrs(body []byte) (map[string]string, error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	var attrs map[string]string
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return attrs, nil
		}
		if err != nil {
			return nil, err
		}
		if se, ok := tok.(xml.StartElement); ok && attrs == nil && se.Name.Local == "updatecheck" {
			attrs = map[string]string{}
			for _, a := range se.Attr {
				if a.Name.Space == "" {
					attrs[a.Name.Local] = a.Value
				}
			}
		}
	}
}

// FetchChromeMetadata replaces fetch_chrome_metadata(id, client=, listing=,
// manifest_for=). listing nil = not prefetched (this ID's FetchChromeListings
// result when the caller already batched it). manifestFor returns cached
// manifest fields for an immutable version, which skip the CRX download.
// Never fails (errors are in the returned map's "error"/"status").
func FetchChromeMetadata(ctx context.Context, extensionID string, client *HTTPClient, listing map[string]any, manifestFor ManifestFor) (meta map[string]any) {
	client = clientOr(client, 12)
	// Host-reported ID: only a real Chrome ID may reach a store URL or body.
	if !chromeExtIDRe.MatchString(extensionID) {
		return map[string]any{"store": "chrome", "status": "unknown", "error": "invalid chrome extension id"}
	}
	if listing != nil {
		meta = copyMap(listing)
	} else {
		meta = FetchChromeListings(ctx, []string{extensionID}, client)[extensionID]
	}
	missing := meta["listing_missing"]
	delete(meta, "listing_missing")
	if !truthy(missing) {
		return meta // listed (manifest came with it), rate limited, or failed
	}
	// The listing RPC serves only listed items. update2 still answers for
	// unlisted ones, which install by direct link and are a real malware
	// vector, so their package is fetched and inspected.
	meta["status"] = "unknown"
	query := pyQuote("id="+extensionID+"&uc", "")
	// Far-future Chrome version: update2 answers "noupdate" (no codebase) when
	// the item's minimum_chrome_version exceeds prodversion.
	u := "https://clients2.google.com/service/update2/crx" +
		"?response=updatecheck&prodversion=999.0&acceptformat=crx2,crx3&x=" + query
	resp := client.Get(ctx, u, chromeHosts, 1_000_000, nil)
	if markRateLimited(meta, resp.Status, resp.Headers) {
		return meta
	}
	if resp.Err != "" && resp.Status == 0 {
		meta["error"] = resp.Err
		return meta
	}
	if resp.Status != 200 || len(resp.Body) == 0 {
		meta["error"] = fmt.Sprintf("update2 HTTP %d", resp.Status)
		return meta
	}
	defer func() {
		if r := recover(); r != nil {
			meta["error"] = fmt.Sprintf("update2 parse failed: %v", r)
		}
	}()
	attrs, err := updatecheckAttrs(resp.Body)
	if err != nil {
		meta["error"] = "update2 parse failed: " + err.Error()
		return meta
	}
	if attrs == nil {
		meta["status"] = "not_found"
		meta["error"] = "update2 returned no updatecheck element"
		return meta
	}
	checkStatus := strings.ToLower(attrs["status"])
	if strings.HasPrefix(checkStatus, "error") {
		meta["status"] = "not_found"
		meta["error"] = checkStatus
		return meta
	}
	meta["status"] = "unlisted"
	version, hasVersion := attrs["version"]
	if hasVersion {
		meta["version"] = version
	} else {
		meta["version"] = nil
	}
	if manifestFor != nil && version != "" {
		if cached := manifestFor(version); len(cached) > 0 {
			mergeAll(meta, cached)
			return meta
		}
	}
	codebase := attrs["codebase"]
	expectedHash := strings.ToLower(attrs["hash_sha256"])
	if codebase == "" {
		// "noupdate": Google serves no package for this ID (e.g. MV2 items
		// Chrome no longer runs). Nothing was parsed, so nothing is suspect.
		cs := checkStatus
		if cs == "" {
			cs = "missing"
		}
		meta["manifest_unavailable"] = "update2 status " + cs + ", no codebase"
		return meta
	}
	crx := client.Get(ctx, codebase, chromeHosts, maxPackageBytes, nil)
	if crx.Status == 200 && crx.Err == "response too large" {
		// Our download cap, not a bad package (ad blockers bundle >50 MB of
		// filter lists). A truncated ZIP has no central directory to read.
		meta["manifest_unavailable"] = "CRX exceeds 50 MB download cap"
		return meta
	}
	if crx.Status != 200 || len(crx.Body) == 0 {
		if crx.Err != "" {
			meta["manifest_error"] = crx.Err
		} else {
			meta["manifest_error"] = fmt.Sprintf("CRX HTTP %d", crx.Status)
		}
		return meta
	}
	sum := sha256.Sum256(crx.Body)
	if expectedHash != "" {
		ok := hex.EncodeToString(sum[:]) == expectedHash
		meta["crx_hash_verified"] = ok
		if !ok {
			meta["manifest_error"] = "CRX SHA-256 does not match update2"
		}
	}
	manifest, err := parseCRX(crx.Body)
	if err != nil {
		meta["manifest_error"] = err.Error()
		return meta
	}
	mergeFields(meta, manifestFields(map[string]any{"manifest": manifest}), false)
	return meta
}

// ---------------------------------------------------------------------------
// Edge, AMO, Opera, Safari
// ---------------------------------------------------------------------------

func fetchEdgeMetadata(ctx context.Context, extensionID string, client *HTTPClient) map[string]any {
	client = clientOr(client, 12)
	meta := map[string]any{"store": "edge", "status": "unknown",
		"url": "https://microsoftedge.microsoft.com/addons/detail/" + extensionID}
	resp := client.Get(ctx, "https://microsoftedge.microsoft.com/addons/getproductdetailsbycrxid/"+extensionID,
		edgeHosts, 2_000_000, nil)
	if markRateLimited(meta, resp.Status, resp.Headers) {
		return meta
	}
	if resp.Status == 404 {
		meta["status"] = "not_found"
		meta["error"] = "edge detail returned 404"
		return meta
	}
	var raw any
	if len(resp.Body) > 0 {
		raw = jsonBody(resp.Body)
	}
	if resp.Status != 200 || raw == nil {
		if resp.Err != "" {
			meta["error"] = resp.Err
		} else {
			meta["error"] = fmt.Sprintf("edge detail HTTP %d", resp.Status)
		}
		return meta
	}
	if !truthy(raw) {
		meta["status"] = "not_found"
		meta["error"] = "edge detail returned an empty object"
		return meta
	}
	data, ok := toMap(raw)
	if !ok { // python: AttributeError, caught by fetch_store_metadata
		return map[string]any{"store": "edge", "status": "unknown", "error": "edge detail is not a JSON object"}
	}

	fields := manifestFields(data)
	developer := first(data, "developer", "developerName", "publisher", "publisherName")
	verified := first(data, "developerVerified", "isDeveloperVerified", "verified")
	if dm, ok := toMap(developer); ok {
		if v, has := dm["verified"]; has {
			verified = v
		}
		developer = first(dm, "name", "displayName", "publisherName")
	}
	updated := first(data, "lastUpdateDate", "lastUpdated", "updateDate")
	if f, ok := asNumberLoose(updated); ok && f > 0 { // live API returns epoch seconds
		updated = pyISOFromUnix(f)
	}
	var verifiedOut any
	if verified != nil {
		verifiedOut = truthy(verified)
	}
	users, uok := asInt(first(data, "activeInstallCount", "users", "userCount", "installCount"))
	rating, rok := asFloat(first(data, "rating", "averageRating"))
	rc, rcok := asInt(first(data, "ratingCount", "ratingsCount", "rating_count"))
	name := cleanStr(first(data, "name", "extensionName"))
	var nameOut any = optStr(name)
	if name == "" {
		nameOut = fields["name"]
	}
	ver := cleanStr(first(data, "version", "latestVersion"))
	var verOut any = optStr(ver)
	if ver == "" {
		verOut = fields["version"]
	}
	mergeAll(meta, map[string]any{
		"status":             "public",
		"name":               nameOut,
		"version":            verOut,
		"users":              optInt(users, uok),
		"rating":             optFloat(rating, rok),
		"rating_count":       optInt(rc, rcok),
		"developer":          optStr(cleanStr(developer)),
		"developer_verified": verifiedOut,
		"developer_website":  optStr(cleanStr(data["publisherWebsiteUri"])),
		"featured":           optBool(data["isBadgedAsFeatured"]),
		"category":           optStr(cleanStr(first(data, "category", "categories"))),
		"updated_at":         optStr(cleanStr(updated)),
		"privacy_policy_url": optStr(cleanStr(first(data, "privacyUrl", "privacyPolicyUrl", "privacyPolicy"))),
	})
	mergeFields(meta, fields, false)
	return meta
}

// asNumberLoose is `isinstance(v, (int, float))` (bool included).
func asNumberLoose(v any) (float64, bool) {
	if b, ok := v.(bool); ok {
		if b {
			return 1, true
		}
		return 0, true
	}
	return numOf(v)
}

func fetchAMOMetadata(ctx context.Context, guid string, client *HTTPClient, manifestFor ManifestFor) map[string]any {
	client = clientOr(client, 12)
	q := pyQuote(guid, "")
	meta := map[string]any{"store": "firefox", "status": "unknown",
		"url": "https://addons.mozilla.org/firefox/addon/" + q + "/"}
	resp := client.Get(ctx, "https://addons.mozilla.org/api/v5/addons/addon/"+q+"/", amoHosts, 2_000_000, nil)
	if markRateLimited(meta, resp.Status, resp.Headers) {
		return meta
	}
	switch resp.Status {
	case 401:
		meta["status"] = "unlisted"
		meta["error"] = "AMO returned 401 (unlisted or self-distributed)"
		return meta
	case 404:
		meta["status"] = "not_found"
		meta["error"] = "AMO returned 404 (built-in or unknown GUID)"
		return meta
	}
	var data map[string]any
	if len(resp.Body) > 0 {
		data, _ = toMap(jsonBody(resp.Body))
	}
	if resp.Status != 200 || data == nil {
		if resp.Err != "" {
			meta["error"] = resp.Err
		} else {
			meta["error"] = fmt.Sprintf("AMO HTTP %d", resp.Status)
		}
		return meta
	}

	current, _ := toMap(data["current_version"])
	if current == nil {
		current = map[string]any{}
	}
	fileInfo, _ := toMap(current["file"])
	if fileInfo == nil {
		fileInfo = map[string]any{}
	}
	authors, _ := data["authors"].([]any)
	// Numeric AMO user IDs are immutable; author display names are not.
	authorIDs := []int64{}
	for _, a := range authors {
		if am, ok := toMap(a); ok {
			if id, ok := intOf(am["id"]); ok && id > 0 {
				authorIDs = append(authorIDs, id)
			}
		}
	}
	meta["author_ids"] = authorIDs
	var developer any = ""
	if len(authors) > 0 {
		if am, ok := toMap(authors[0]); ok {
			developer = pyOr(first(am, "name", "username"), "")
		}
	}
	ratings, _ := toMap(data["ratings"])
	if ratings == nil {
		ratings = map[string]any{}
	}
	metaStatus := "public"
	switch strings.ToLower(cleanStr(data["status"])) {
	case "unlisted", "self":
		metaStatus = "unlisted"
	case "disabled", "removed", "deleted":
		metaStatus = "removed"
	}
	if data["is_disabled"] == true {
		metaStatus = "removed"
	}
	featured := false
	if promoted, ok := data["promoted"].([]any); ok {
		for _, p := range promoted {
			if pm, ok := toMap(p); ok && (pm["category"] == "recommended" || pm["category"] == "line") {
				featured = true
			}
		}
	}
	email := cleanStr(localisedName(data["support_email"]))
	homepage := data["homepage"]
	if hm, ok := toMap(homepage); ok {
		if u, has := hm["url"]; has { // v5: {"url": {locale: url}, ...}
			homepage = u
		}
	}
	var category any = data["category"]
	if !truthy(category) {
		category = nil
		if cats, ok := data["categories"].([]any); ok && len(cats) > 0 {
			category = cats[0]
		}
	}
	var emailOut any
	if emailOK(email) {
		emailOut = email
	}
	var privacyURL any
	if truthy(data["has_privacy_policy"]) {
		privacyURL = meta["url"].(string) + "privacy/"
	}
	updatedAt := cleanStr(current["created"])
	if updatedAt == "" {
		updatedAt = cleanStr(data["last_updated"])
	}
	users, uok := asInt(pyOr(data["average_daily_users"], data["weekly_downloads"]))
	rating, rok := asFloat(ratings["average"])
	rc, rcok := asInt(ratings["count"])
	mv, mvok := asInt(current["manifest_version"])
	mergeAll(meta, map[string]any{
		"status":           metaStatus,
		"name":             optStr(localisedName(data["name"])),
		"version":          optStr(cleanStr(current["version"])),
		"users":            optInt(users, uok),
		"rating":           optFloat(rating, rok),
		"rating_count":     optInt(rc, rcok),
		"developer":        optStr(cleanStr(developer)),
		"category":         optStr(cleanStr(category)),
		"updated_at":       optStr(updatedAt),
		"manifest_version": optInt(mv, mvok),
		"permissions":      asStringList(pyOr(fileInfo["permissions"], current["permissions"], data["permissions"])),
		"host_permissions": asStringList(pyOr(fileInfo["host_permissions"], current["host_permissions"],
			data["host_permissions"])),
		"optional_permissions": asStringList(pyOr(fileInfo["optional_permissions"], current["optional_permissions"],
			data["optional_permissions"])),
		"content_script_matches": asStringList(pyOr(current["content_script_matches"], data["content_script_matches"])),
		"crx_hash_verified":      nil,
		// Mozilla's "recommended"/"line" programs include a manual code review.
		"featured":           featured,
		"developer_email":    emailOut,
		"developer_website":  optStr(cleanStr(localisedName(homepage))),
		"privacy_policy_url": privacyURL,
		"created_at":         optStr(cleanStr(data["created"])),
	})
	if v, _ := meta["version"].(string); manifestFor != nil && v != "" {
		if cached := manifestFor(v); len(cached) > 0 {
			// A version's package never changes: reuse its parsed manifest, skip the XPI.
			mergeFields(meta, cached, true)
			return meta
		}
	}
	amoPackageManifest(ctx, meta, fileInfo, client)
	return meta
}

// amoPackageManifest fills manifest fields the AMO API omits (MV, content
// scripts) from the signed XPI.
func amoPackageManifest(ctx context.Context, meta, fileInfo map[string]any, client *HTTPClient) {
	u := cleanStr(fileInfo["url"])
	if !has(amoHosts, urlHost(u)) {
		meta["manifest_unavailable"] = "AMO lists no downloadable package"
		return
	}
	if asIntOr0(fileInfo["size"]) > maxPackageBytes {
		meta["manifest_unavailable"] = "XPI exceeds 50 MB download cap"
		return
	}
	resp := client.Get(ctx, u, amoHosts, maxPackageBytes, nil)
	if resp.Status == 200 && resp.Err == "response too large" {
		meta["manifest_unavailable"] = "XPI exceeds 50 MB download cap"
		return
	}
	if resp.Status != 200 || len(resp.Body) == 0 {
		if resp.Err != "" {
			meta["manifest_unavailable"] = resp.Err
		} else {
			meta["manifest_unavailable"] = fmt.Sprintf("XPI HTTP %d", resp.Status)
		}
		return
	}
	if expected := strings.ToLower(cleanStr(fileInfo["hash"])); strings.HasPrefix(expected, "sha256:") {
		sum := sha256.Sum256(resp.Body)
		ok := hex.EncodeToString(sum[:]) == expected[7:]
		meta["crx_hash_verified"] = ok
		if !ok {
			meta["manifest_error"] = "XPI SHA-256 does not match AMO"
			return
		}
	}
	manifest, err := parseCRX(resp.Body)
	if err != nil {
		meta["manifest_error"] = err.Error()
		return
	}
	// The API's permission lists stay authoritative; the package adds what it lacks.
	mergeFields(meta, manifestFields(map[string]any{"manifest": manifest}), true)
}

var (
	months = map[string]time.Month{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
		"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}
	operaDateRe   = regexp.MustCompile(`^([A-Za-z]+)\.?\s+(\d{1,2}),\s+(\d{4})$`)
	tagRe         = regexp.MustCompile(`<[^>]+>`)
	operaMetaRes  = map[string]*regexp.Regexp{}
	operaBylineRe = regexp.MustCompile(`(?s)class="h-byline".*?developer=[^"]*"[^>]*>(.*?)</a>`)
	operaRatingRe = regexp.MustCompile(`id="rating-value">\s*([0-9.]+)\s*<`)
	operaCountRe  = regexp.MustCompile(`id="rating-count"[^>]*>\s*([0-9,]+)\s*<`) // related items repeat reviewCount
	operaAboutRe  = regexp.MustCompile(`(?s)<dt>(.*?)</dt>\s*<dd[^>]*>(.*?)</dd>`)
	digitsCommaRe = regexp.MustCompile(`^[0-9,]+$`)
)

func init() {
	for _, n := range []string{"aoc:app_id", "aoc:slug", "og:title"} {
		operaMetaRes[n] = regexp.MustCompile(`<meta property="` + regexp.QuoteMeta(n) + `" content="([^"]*)"`)
	}
}

func htmlText(fragment string) string {
	return strings.Join(pySplit(html.UnescapeString(tagRe.ReplaceAllString(fragment, " "))), " ")
}

// operaDate parses 'Sept. 18, 2026' (the page's Django "N j, Y") as ISO.
func operaDate(text string) string {
	m := operaDateRe.FindStringSubmatch(text)
	if m == nil || len(m[1]) < 3 {
		return ""
	}
	month, ok := months[strings.ToLower(m[1][:3])]
	if !ok {
		return ""
	}
	y, _ := strconv.Atoi(m[3])
	d, _ := strconv.Atoi(m[2])
	t := time.Date(y, month, d, 0, 0, 0, 0, time.UTC)
	if t.Day() != d || t.Month() != month || y < 1 {
		return ""
	}
	return t.Format("2006-01-02T15:04:05") + "+00:00"
}

// operaListing is _opera_listing: listing fields from an addons.opera.com
// detail page; an error means drift.
func operaListing(extensionID, page string) (map[string]any, error) {
	metaProp := func(name string) string {
		if m := operaMetaRes[name].FindStringSubmatch(page); m != nil {
			return pyStrip(html.UnescapeString(m[1]))
		}
		return ""
	}
	if metaProp("aoc:app_id") != extensionID {
		return nil, errors.New("listing page id does not match the request")
	}
	slug := metaProp("aoc:slug")
	if !operaSlugRe.MatchString(slug) {
		return nil, errors.New("listing page has no valid slug")
	}
	out := map[string]any{"status": "public", "slug": slug,
		"url": "https://addons.opera.com/en/extensions/details/" + slug + "/"}
	if name := metaProp("og:title"); name != "" {
		out["name"] = name
	}
	if m := operaBylineRe.FindStringSubmatch(page); m != nil {
		if d := htmlText(m[1]); d != "" {
			out["developer"] = d
		}
	}
	if m := operaRatingRe.FindStringSubmatch(page); m != nil {
		f, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return nil, fmt.Errorf("could not convert string to float: %q", m[1])
		}
		if f >= 0 && f <= 5 {
			out["rating"] = pyRound1(f)
		}
	}
	if m := operaCountRe.FindStringSubmatch(page); m != nil {
		n, err := strconv.ParseInt(strings.ReplaceAll(m[1], ",", ""), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid literal for int(): %q", m[1])
		}
		out["rating_count"] = n
	}
	about := map[string]string{}
	for _, m := range operaAboutRe.FindAllStringSubmatch(page, -1) {
		about[htmlText(m[1])] = htmlText(m[2])
	}
	if dl := about["Downloads"]; digitsCommaRe.MatchString(dl) {
		n, err := strconv.ParseInt(strings.ReplaceAll(dl, ",", ""), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid literal for int(): %q", dl)
		}
		out["users"] = n // total downloads, not active users
	}
	if c := about["Category"]; c != "" {
		out["category"] = c
	}
	if v := about["Version"]; v != "" {
		out["version"] = v
	}
	if u := operaDate(about["Last update"]); u != "" {
		out["updated_at"] = u
	}
	if w := httpURL(about["Support page"]); w != nil {
		out["developer_website"] = w
	}
	return out, nil
}

// fetchOperaMetadata: addons.opera.com has no API: `details/app_id/<id>/`
// redirects to the listing page (404 for an ID the store does not list), and
// the CRX comes from `download/<slug>/`.
func fetchOperaMetadata(ctx context.Context, extensionID string, client *HTTPClient, manifestFor ManifestFor) map[string]any {
	client = clientOr(client, 12)
	if !chromeExtIDRe.MatchString(extensionID) {
		return map[string]any{"store": "opera", "status": "unknown", "error": "invalid opera extension id"}
	}
	meta := map[string]any{"store": "opera", "status": "unknown"}
	resp := client.Get(ctx, "https://addons.opera.com/en/extensions/details/app_id/"+extensionID+"/",
		operaHosts, 2_000_000, nil)
	if markRateLimited(meta, resp.Status, resp.Headers) {
		return meta
	}
	if resp.Status == 404 {
		meta["status"] = "not_found"
		meta["error"] = "Opera add-ons returned 404"
		return meta
	}
	if resp.Status != 200 || len(resp.Body) == 0 {
		if resp.Err != "" {
			meta["error"] = resp.Err
		} else {
			meta["error"] = fmt.Sprintf("Opera add-ons HTTP %d", resp.Status)
		}
		return meta
	}
	listing, err := operaListing(extensionID, decodeReplace(resp.Body))
	if err != nil {
		meta["error"] = "Opera listing parse failed: " + err.Error()
		return meta
	}
	mergeAll(meta, listing)
	if v, _ := meta["version"].(string); manifestFor != nil && v != "" {
		if cached := manifestFor(v); len(cached) > 0 {
			mergeAll(meta, cached)
			return meta
		}
	}
	crx := client.Get(ctx, "https://addons.opera.com/extensions/download/"+pyStr(meta["slug"])+"/",
		operaHosts, maxPackageBytes, nil)
	if markRateLimited(meta, crx.Status, crx.Headers) {
		return meta
	}
	if crx.Status == 0 || crx.Status >= 500 {
		// Transient (Opera resets bursts): an uncached "unknown" retries next
		// cycle instead of caching a manifest_error for weeks.
		why := crx.Err
		if why == "" {
			why = strconv.Itoa(crx.Status)
		}
		return map[string]any{"store": "opera", "status": "unknown", "error": "Opera CRX: " + why}
	}
	if crx.Status == 200 && crx.Err == "response too large" {
		meta["manifest_unavailable"] = "CRX exceeds 50 MB download cap"
		return meta
	}
	if crx.Status != 200 || len(crx.Body) == 0 {
		if crx.Err != "" {
			meta["manifest_error"] = crx.Err
		} else {
			meta["manifest_error"] = fmt.Sprintf("CRX HTTP %d", crx.Status)
		}
		return meta
	}
	manifest, err := parseCRX(crx.Body)
	if err != nil {
		meta["manifest_error"] = err.Error()
		return meta
	}
	// The listing's store name and version stay authoritative.
	mergeFields(meta, manifestFields(map[string]any{"manifest": manifest}), true)
	return meta
}

// fetchSafariMetadata: Mac App Store listing of the app that bundles a Safari
// extension, by the containing app's CFBundleIdentifier. The App Store serves
// no package, so the manifest is never inspected. Residual: the bundle ID is
// host-reported, so a non-App-Store app that claims a listed app's bundle ID
// inherits that listing.
func fetchSafariMetadata(ctx context.Context, bundleID string, client *HTTPClient) map[string]any {
	client = clientOr(client, 12)
	bundleID = pyStrip(bundleID)
	if len([]rune(bundleID)) > 255 || !bundleIDRe.MatchString(bundleID) {
		return map[string]any{"store": "safari", "status": "unknown", "error": "invalid app bundle id"}
	}
	meta := map[string]any{"store": "safari", "status": "unknown"}
	resp := client.Get(ctx, "https://itunes.apple.com/lookup?entity=macSoftware&bundleId="+pyQuote(bundleID, ""),
		appleHosts, 1_000_000, nil)
	if markRateLimited(meta, resp.Status, resp.Headers) {
		return meta
	}
	var data map[string]any
	if len(resp.Body) > 0 {
		data, _ = toMap(jsonBody(resp.Body))
	}
	results, ok := data["results"].([]any)
	if resp.Status != 200 || data == nil || !ok {
		if resp.Err != "" {
			meta["error"] = resp.Err
		} else {
			meta["error"] = fmt.Sprintf("iTunes lookup HTTP %d", resp.Status)
		}
		return meta
	}
	var app map[string]any
	for _, r := range results {
		//lint:ignore SA6005 python str.lower() parity, not Unicode case folding
		if rm, ok := toMap(r); ok && strings.ToLower(cleanStr(rm["bundleId"])) == strings.ToLower(bundleID) {
			app = rm
			break
		}
	}
	if app == nil {
		// Developer ID (notarized) distribution outside the App Store is a
		// normal Safari channel, unlike an off-store Chrome item: not "not_found".
		meta["status"] = "off_store"
		return meta
	}
	ratingCount := asIntOr0(app["userRatingCount"])
	var ratingOut any
	if rating, ok := asFloat(app["averageUserRating"]); ok && ratingCount > 0 && rating >= 0 && rating <= 5 {
		ratingOut = rating
	}
	var rcOut any
	if ratingCount != 0 {
		rcOut = ratingCount
	}
	developer := cleanStr(app["sellerName"])
	if developer == "" {
		developer = cleanStr(app["artistName"])
	}
	mergeAll(meta, map[string]any{
		"status":    "public",
		"name":      optStr(cleanStr(app["trackName"])),
		"version":   optStr(cleanStr(app["version"])),
		"developer": optStr(developer),
		// The lookup reports 0 for "no ratings"; only a counted rating means anything.
		"rating":            ratingOut,
		"rating_count":      rcOut,
		"category":          optStr(cleanStr(app["primaryGenreName"])),
		"updated_at":        optStr(cleanStr(app["currentVersionReleaseDate"])),
		"created_at":        optStr(cleanStr(app["releaseDate"])),
		"url":               httpURL(app["trackViewUrl"]),
		"developer_website": httpURL(app["sellerUrl"]),
	})
	return meta
}

// FetchStoreMetadata replaces fetch_store_metadata(store, id, client=,
// manifest_for=): dispatch to the anonymous adapter for store. Never fails.
// For safari, extensionID is the containing app's bundle ID.
func FetchStoreMetadata(ctx context.Context, store, extensionID string, client *HTTPClient, manifestFor ManifestFor) (out map[string]any) {
	store = strings.ToLower(pyStrip(store))
	extensionID = pyStrip(extensionID)
	if extensionID == "" {
		return map[string]any{"store": store, "status": "unknown", "error": "missing extension id"}
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Warn(fmt.Sprintf("extension metadata fetch failed store=%s id=%s: %v", store, extensionID, r))
			out = map[string]any{"store": store, "status": "unknown", "error": fmt.Sprint(r)}
		}
	}()
	switch store {
	case "chrome", "brave", "vivaldi", "chromium":
		return FetchChromeMetadata(ctx, extensionID, client, nil, manifestFor)
	case "opera":
		meta := fetchOperaMetadata(ctx, extensionID, client, manifestFor)
		// Opera also installs from the Chrome Web Store, so any Opera miss or
		// failure asks the CWS; a CWS miss or failure keeps Opera's answer.
		if meta["status"] != "public" && !truthy(meta["rate_limited"]) {
			chrome := FetchChromeMetadata(ctx, extensionID, client, nil, manifestFor)
			if chrome["status"] != "not_found" && chrome["status"] != "unknown" {
				chrome["resolved_from"] = "opera"
				return chrome
			}
		}
		return meta
	case "safari":
		return fetchSafariMetadata(ctx, extensionID, client)
	case "edge":
		meta := fetchEdgeMetadata(ctx, extensionID, client)
		// Edge installs from the Chrome Web Store too; an ID Edge's store does
		// not know is usually a CWS item, not an unknown sideload.
		if meta["status"] == "not_found" && chromeExtIDRe.MatchString(extensionID) {
			chrome := FetchChromeMetadata(ctx, extensionID, client, nil, manifestFor)
			// Only update2's own "unknown application" confirms Edge's miss; an
			// unlisted, removed or failed Chrome answer must not cache as not_found.
			if chrome["status"] != "not_found" {
				chrome["resolved_from"] = "edge"
				return chrome
			}
		}
		return meta
	case "firefox":
		return fetchAMOMetadata(ctx, extensionID, client, manifestFor)
	}
	return map[string]any{"store": store, "status": "unknown",
		"error": "no anonymous metadata adapter for store '" + store + "'"}
}
