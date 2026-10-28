package extintel

// Port of _self_check() (`python src/extension_intel.py`): same cases, same
// expected values. Run by `fleethound selfcheck` and by the package tests.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"
)

type checkFailure string

func check(cond bool, format string, args ...any) {
	if !cond {
		panic(checkFailure(fmt.Sprintf(format, args...)))
	}
}

func resp(status int, headers map[string]string, body, err string) Response {
	return Response{Status: status, Headers: headers, Body: []byte(body), Err: err}
}

// queue pops canned responses in order (python `self.responses.pop(0)`).
func queue(responses ...Response) func() Response {
	return func() Response {
		if len(responses) == 0 {
			panic("fake client: no response left")
		}
		r := responses[0]
		responses = responses[1:]
		return r
	}
}

// fakeSeq is python _Fake: GET and POST share one response queue.
func fakeSeq(responses ...Response) *HTTPClient {
	next := queue(responses...)
	return &HTTPClient{fake: &fakeTransport{
		get:  func(string, map[string]struct{}, int, map[string]string) Response { return next() },
		post: func(string, url.Values, map[string]struct{}, int) Response { return next() },
	}}
}

// noNet is python _NoNet: any network call fails the check.
func noNet() *HTTPClient { return &HTTPClient{fake: &fakeTransport{}} }

func hasSignal(result map[string]any, code string) bool {
	sigs, _ := result["risk_signals"].([]map[string]any)
	for _, s := range sigs {
		if s["code"] == code {
			return true
		}
	}
	return false
}

func analyze(rec map[string]any) map[string]any { return AnalyzeExtension(rec, AnalyzeOptions{}) }

func makeZip(files map[string][]byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range sortedKeys(files) {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Deflate})
		if err != nil {
			panic(err)
		}
		if _, err := w.Write(files[n]); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func writeJSONFile(path string, v any) {
	if err := os.WriteFile(path, []byte(mustJSON(v)), 0o600); err != nil {
		panic(err)
	}
}

// bumpMtime is os.utime(path, (getmtime(path) + d,) * 2).
func bumpMtime(path string, d time.Duration) {
	st, err := os.Stat(path)
	if err != nil {
		panic(err)
	}
	t := st.ModTime().Add(d)
	if err := os.Chtimes(path, t, t); err != nil {
		panic(err)
	}
}

func rep(s string, n int) string { return strings.Repeat(s, n) }

// cwsEnv is one batchexecute envelope for rpcBody; code nil means [5].
type cwsEnv struct {
	tag     string
	payload []any
	code    []any
}

func cwsPayload(eid, email string) []any {
	item := make([]any, 20)
	item[0], item[2], item[3], item[4], item[7], item[9] = eid, "Ex", 4.26, 1234, "example.org", true
	item[8], item[15] = true, true
	item[11], item[14] = []any{"productivity/workflow", nil, 4}, 100_000
	item[18] = mustJSON(map[string]any{"manifest_version": 3, "name": "__MSG_extName__", "version": "2.1",
		"permissions": []any{"tabs"}, "content_scripts": []any{map[string]any{"matches": []any{"<all_urls>"}}}})
	dev := make([]any, 11)
	dev[0], dev[3], dev[5], dev[7], dev[10] = email, 1, "Example", "Example Ltd", "u"+rep("1", 32)
	payload := make([]any, 34)
	payload[0], payload[7], payload[10], payload[13] = item, []any{1, 6}, dev, "2.1"
	payload[14], payload[33] = []any{1_790_000_000, 0}, "https://example.org/privacy"
	return payload
}

func rpcBody(envs ...cwsEnv) string {
	lines := []string{")]}'", ""}
	for _, e := range envs {
		var p any
		if e.payload != nil {
			p = mustJSON(e.payload)
		}
		code := e.code
		if code == nil {
			code = []any{5}
		}
		chunk := mustJSON([]any{[]any{"wrb.fr", cwsRPCID, p, nil, nil, code, e.tag}})
		lines = append(lines, fmt.Sprint(len(chunk)), chunk)
	}
	return strings.Join(lines, "\n")
}

// rpcClient is python _Rpc: asserts the RPC target, records forms and GET
// URLs; GET and POST share one response queue.
type rpcClient struct {
	forms, urls []string
}

func newRPC(responses ...Response) (*HTTPClient, *rpcClient) {
	rec := &rpcClient{}
	next := queue(responses...)
	return &HTTPClient{fake: &fakeTransport{
		post: func(u string, form url.Values, allowed map[string]struct{}, _ int) Response {
			check(reflect.DeepEqual(allowed, chromeHosts) && u == cwsRPCURL, "RPC posted to %s", u)
			rec.forms = append(rec.forms, form.Get("f.req"))
			return next()
		},
		get: func(u string, _ map[string]struct{}, _ int, _ map[string]string) Response {
			rec.urls = append(rec.urls, u)
			return next()
		},
	}}, rec
}

const (
	noUpdateXML = `<gupdate xmlns="http://www.google.com/update2/response"><app>` +
		`<updatecheck status="noupdate"/></app></gupdate>`
	unknownAppXML = `<gupdate xmlns="http://www.google.com/update2/response"><app>` +
		`<updatecheck status="error-unknownApplication"/></app></gupdate>`
)

// noUpdateClient is python _NoUpdate with overridable get/post.
func noUpdateClient(urls *[]string, get func(u string) (Response, bool), post func() Response) *HTTPClient {
	return &HTTPClient{fake: &fakeTransport{
		post: func(string, url.Values, map[string]struct{}, int) Response {
			if post != nil {
				return post()
			}
			return resp(200, nil, rpcBody(cwsEnv{tag: "1"}), "")
		},
		get: func(u string, _ map[string]struct{}, _ int, _ map[string]string) Response {
			if urls != nil {
				*urls = append(*urls, u)
			}
			if get != nil {
				if r, ok := get(u); ok {
					return r
				}
			}
			if strings.Contains(u, "update2") {
				return resp(200, nil, noUpdateXML, "")
			}
			return resp(404, nil, "", "")
		},
	}}
}

// SelfCheck replaces _self_check() (python `python src/extension_intel.py`):
// runs the in-file assertions and returns an error on the first failure.
// It temporarily points KNOWN_PUBLISHERS_FILE / EXTENSION_THREAT_FEEDS_FILE
// at fixtures and restores them.
func SelfCheck() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("extension_intel self-check failed: %v", r)
		}
	}()
	for _, k := range []string{"KNOWN_PUBLISHERS_FILE", "EXTENSION_THREAT_FEEDS_FILE"} {
		if old, ok := os.LookupEnv(k); ok {
			defer os.Setenv(k, old)
		} else {
			defer os.Unsetenv(k)
		}
	}
	// Self-check entrypoint: no caller context; every client here is a fake.
	ctx := context.Background()
	selfCheckPublishers(ctx)
	selfCheckChrome(ctx)
	return nil
}

func selfCheckPublishers(ctx context.Context) {
	// Self-check uses its own publisher fixture, independent of the operator list.
	pubs := []any{
		map[string]any{"name": "Google", "match_names": []any{"Google", "Google Ireland"}, "added_at": "2026-10-26T00:00:00Z",
			"chrome_publisher_ids": []any{"udcdd80226b381e8c9845d3e7861f0e71"}},
		map[string]any{"name": "Meta", "match_names": []any{"Meta"}, "added_at": "2026-10-26T00:00:00Z"},
		map[string]any{"name": "Mozilla", "match_names": []any{"Mozilla"}, "added_at": "2026-10-26T00:00:00Z",
			"amo_author_ids": []any{101}},
		map[string]any{"name": "Bad Amo", "added_at": "2026-10-26T00:00:00Z", "amo_author_ids": []any{"101"}}, // skipped
		map[string]any{"name": "Microsoft", "match_names": []any{"Microsoft"}, "added_at": "2026-10-26T00:00:00Z",
			"edge_extension_ids": []any{"jmjflgjpcpepeafmmgdpfkogkghcpiha"}},
		map[string]any{"name": "AdGuard", "match_names": []any{"AdGuard"}, "added_at": "2026-10-26T00:00:00Z"},
		map[string]any{"name": "1Password", "match_names": []any{"1Password", "AgileBits"}, "added_at": "2026-10-26T00:00:00Z",
			"chrome_publisher_ids": []any{"udb847e9815e2e1626d9ddb346d722811"}, "apple_team_ids": []any{"2BUA8C4S2C"}},
		map[string]any{"name": "Bad Team", "added_at": "2026-10-26T00:00:00Z", "apple_team_ids": []any{"2bua8c4s2c"}}, // skipped
		map[string]any{"name": "DuckDuckGo", "match_names": []any{"DuckDuckGo", "Duck Duck Go"}, "added_at": "2026-10-26T00:00:00Z"},
		map[string]any{"name": "No Timestamp"}, // skipped
		map[string]any{"name": "Bad Id", "added_at": "2026-10-26T00:00:00Z", "chrome_publisher_ids": []any{"x"}}, // skipped
	}
	tmp, err := os.CreateTemp("", "known_publishers-*.json")
	if err != nil {
		panic(err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	writeJSONFile(tmp.Name(), map[string]any{"publishers": pubs})
	os.Setenv("KNOWN_PUBLISHERS_FILE", tmp.Name())
	check(!publisherIsReputable("No Timestamp") && !publisherIsReputable("Bad Id"), "skipped entries must not be trusted")
	pubs = append(pubs, map[string]any{"name": "ChromeOnly", "added_at": "2026-10-26T00:00:00Z",
		"chrome_publisher_ids": []any{"u" + rep("2", 32)}})
	writeJSONFile(tmp.Name(), map[string]any{"publishers": pubs})
	bumpMtime(tmp.Name(), 2*time.Second)
	check(!publisherIsReputable("ChromeOnly"), "Chrome-ID-only entry must not trust its name")
	check(chromePublisherIsReputable("u"+rep("2", 32)), "chrome-only id")

	builtin := analyze(map[string]any{"store": "chrome", "extension_id": "ghbmnnjooekpmoecnnnilnnbdlolhkhi",
		"name": "google docs offline", "host_count": 32})
	check(builtin["risk_score"] == int64(0) && builtin["risk_band"] == "low", "builtin %v", builtin)

	bad := AnalyzeExtension(map[string]any{"store": "edge", "extension_id": "pdffkfellgipmhklpdmokmckkkfcopbh",
		"name": "adguard adblocker", "host_count": 3,
		"store_meta": map[string]any{"status": "public", "users": 11_548_306, "developer": "AdGuard Software Ltd"},
	}, AnalyzeOptions{BlocklistEntry: map[string]any{"why": "malicious"}})
	check(bad["risk_score"].(int64) >= 95 && bad["risk_band"] == "critical", "bad %v", bad)

	tinyUnknown := analyze(map[string]any{"store": "firefox", "extension_id": "agent@example.com",
		"name": "agent bridge", "host_count": 1,
		"store_meta": map[string]any{"status": "public", "users": 12, "developer": "unknown"}})
	check(tinyUnknown["risk_band"] == "medium" || tinyUnknown["risk_band"] == "high", "tiny_unknown %v", tinyUnknown)

	tinyKnown := analyze(map[string]any{"store": "firefox", "extension_id": "{ce9f4b1f-24b8-4e9a-9051-b9e472b1b2f2}",
		"name": "clear browsing data", "host_count": 1,
		"installs": []any{"/home/a/.mozilla/firefox/p.default/extensions/{ce9f4b1f-24b8-4e9a-9051-b9e472b1b2f2}.xpi"},
		"store_meta": map[string]any{"store": "firefox", "status": "public", "users": 41_759,
			"developer": "Mozilla", "author_ids": []any{101}}})
	check(tinyKnown["risk_band"] == "low" || tinyKnown["risk_band"] == "medium", "tiny_known %v", tinyKnown)
	check(hasSignal(tinyKnown, "reputable-publisher"), "tiny_known reputable")
	// Firefox trust is by AMO author ID: the right name with another ID is not trusted.
	amoSpoof := analyze(map[string]any{"store": "firefox", "extension_id": "spoof@example.com", "name": "x", "host_count": 1,
		"store_meta": map[string]any{"store": "firefox", "status": "public", "developer": "Mozilla", "author_ids": []any{999}}})
	check(amoSpoof["publisher_reputable"] == false, "AMO name match without ID must not be trusted")
	check(!publisherIsReputable("Bad Amo"), "string author IDs are rejected")
	// Edge: listed extension ID + public listing; the developer name alone earns nothing.
	edgeMeta := map[string]any{"store": "edge", "status": "public", "developer": "Microsoft Corporation"}
	edgePath := []any{"/Users/a/Library/Application Support/Microsoft Edge/Default/Extensions/jmjflgjpcpepeafmmgdpfkogkghcpiha/1.0_0"}
	listed := analyze(map[string]any{"store": "edge", "extension_id": "jmjflgjpcpepeafmmgdpfkogkghcpiha",
		"name": "x", "host_count": 1, "store_meta": edgeMeta, "installs": edgePath})
	other := analyze(map[string]any{"store": "edge", "extension_id": rep("b", 32), "name": "x",
		"host_count": 1, "store_meta": edgeMeta})
	goneMeta := copyMap(edgeMeta)
	goneMeta["status"] = "not_found"
	gone := analyze(map[string]any{"store": "edge", "extension_id": "jmjflgjpcpepeafmmgdpfkogkghcpiha",
		"name": "x", "host_count": 1, "installs": edgePath, "store_meta": goneMeta})
	check(listed["publisher_reputable"] == true && other["publisher_reputable"] == false, "edge listed/other")
	check(gone["publisher_reputable"] == false, "listed ID no longer on the store is not trusted")
	// An unpacked copy claiming the listed ID (manifest `key`) loses store trust.
	sideloaded := analyze(map[string]any{"store": "edge", "extension_id": "jmjflgjpcpepeafmmgdpfkogkghcpiha",
		"name": "x", "host_count": 2, "store_meta": edgeMeta,
		"installs": append(append([]any{}, edgePath...), "/Users/b/dev/copy/dist")})
	check(sideloaded["publisher_reputable"] == false && hasSignal(sideloaded, "not-store-install"), "sideloaded %v", sideloaded)
	eid := "jmjflgjpcpepeafmmgdpfkogkghcpiha"
	check(storeInstallVerified("chrome", eid, []any{
		`C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Extensions\` + eid + `\1_0`,
		map[string]any{"path": nil, "platform": "chrome"}}), "windows store install") // ChromeOS: no path reported
	for _, badInstalls := range [][]any{
		{"/tmp/x/Extensions/" + eid + "/1.0"}, // store-shaped, wrong root
		{"/Users/a/evil/Google/Chrome/Default/Extensions/" + eid + "/1.0"},
		{"/Users/a/Library/Application Support/Google/Chrome/Default/Extensions/" + eid + "/1/../../x"},
		{map[string]any{"path": nil, "platform": "darwin"}}, {}, // missing path fails closed
		{map[string]any{"path": nil, "platform": "chrome"}}, // ChromeOS-only: no evidence
	} {
		check(!storeInstallVerified("chrome", eid, badInstalls), "store install accepted: %v", badInstalls)
	}

	typo := analyze(map[string]any{"store": "chrome", "extension_id": rep("a", 32), "name": "adgaurd", "host_count": 1,
		"store_meta": map[string]any{"status": "public", "users": 50, "developer": "someone"}})
	check(hasSignal(typo, "typosquat-brand"), "typo %v", typo)

	// Brand list is normalised like names: the real brand is not its own typosquat.
	sigs, _ := nameAnomalySignals("1Password", "", false)
	check(len(sigs) == 0, "1Password flagged: %v", sigs)
	for _, n := range []string{"1Passw0rd", "G00gle"} {
		sigs, _ = nameAnomalySignals(n, "", false)
		check(len(sigs) > 0 && sigs[0]["code"] == "typosquat-brand", "%s not flagged", n)
	}

	// Reputation: store fields only, exact normalised names only.
	vendorOnly := analyze(map[string]any{"store": "chrome", "extension_id": rep("b", 32), "name": "helper",
		"vendor": "Google", "host_count": 1, "store_meta": map[string]any{"status": "public"}})
	check(vendorOnly["publisher_reputable"] == false, "vendor_only %v", vendorOnly)
	check(!publisherIsReputable("Box Hill Scams") && !publisherIsReputable("Meta Tools"), "word search")
	check(publisherIsReputable("Google LLC") && publisherIsReputable("Meta Platforms, Inc."), "suffixes")
	check(publisherIsReputable("AdGuard Software Ltd"), "AdGuard Software Ltd")

	// Capability: content-script matches cancel the "no host permissions" discount.
	noHosts, _ := capability(set("cookies"), strSet{}, strSet{}, strSet{}, nil, nil)
	withCS, _ := capability(set("cookies"), strSet{}, set("https://example.com/*"), strSet{}, nil, nil)
	check(noHosts == pyRound(15*0.6) && withCS == 15+5, "capability %d %d", noHosts, withCS)
	opt, optSignals := capability(set("storage"), set("https://a/*"), strSet{}, set("debugger"), nil, nil)
	check(opt == 1+1+2, "optional capped at required total: %d %v", opt, optSignals)
	opt, _ = capability(set("cookies"), set("https://a/*"), strSet{}, set("debugger"), nil, nil)
	check(opt == 15+12+2, "optional half weight: %d", opt)

	// Mozilla blocklist: regex GUIDs, versionRange, unknown version fails closed.
	blocklist := map[string]map[string]any{
		`/^((evil@a\.com)|(\{0000-bad\}))$/`: {"why": "regex", "versionRange": []any{}},
		"old@b.com": {"why": "old only", "versionRange": []any{
			map[string]any{"minVersion": "0", "maxVersion": "1.2.*"},
			map[string]any{"minVersion": "2.0b1", "maxVersion": "2.0"},
		}},
		"all@c.com": {"why": "all", "versionRange": []any{map[string]any{"minVersion": "0", "maxVersion": "*"}}},
	}
	mb := func(id string, versions ...string) map[string]any { return MatchBlocklist(blocklist, id, versions) }
	check(mb("evil@a.com")["why"] == "regex", "regex guid")
	check(mb("{0000-bad}", "9")["why"] == "regex", "regex guid braces")
	check(mb("evil@a.comx") == nil, "regex anchored")
	check(mb("old@b.com", "1.1")["why"] == "old only", "1.1")
	check(mb("old@b.com", "1.2.9") != nil, "1.2.9")
	check(mb("old@b.com", "1.10") == nil, "1.10")
	check(mb("old@b.com", "2.0a1") == nil, "2.0a1")
	check(mb("old@b.com", "2.0b3") != nil, "2.0b3")
	check(mb("old@b.com", "3.0") == nil, "3.0")
	check(mb("old@b.com", "3.0", "1.0") != nil, "3.0,1.0")
	check(mb("old@b.com") != nil, "fail closed")
	check(mb("all@c.com", "99.1") != nil, "all")
	check(mb("nobody@d.com", "1") == nil, "nobody")
	var roundTrip map[string]map[string]any
	check(json.Unmarshal([]byte(mustJSON(blocklist)), &roundTrip) == nil, "raw map stays cacheable")
	check(CompareVersions("1.10", "1.9") == 1 && CompareVersions("1.0", "1.0.0") == 0, "compare_versions")

	// Adapters: Edge 404 is not_found; 429 / 503+Retry-After flag the breaker;
	// blocklist follows the Next-Page header.
	edge404 := fetchEdgeMetadata(ctx, rep("x", 32), fakeSeq(resp(404, nil, `{"name":"x"}`, "")))
	check(edge404["status"] == "not_found", "edge_404 %v", edge404)
	edgeOK := fetchEdgeMetadata(ctx, rep("x", 32), fakeSeq(resp(200, nil, `{"name":"x"}`, "")))
	check(edgeOK["status"] == "public" && !truthy(edgeOK["error"]), "edge_ok %v", edgeOK)
	edge500 := fetchEdgeMetadata(ctx, rep("x", 32), fakeSeq(resp(500, nil, `{"name":"x"}`, "")))
	check(edge500["status"] == "unknown" && truthy(edge500["error"]), "edge_500 %v", edge500)
	amo429 := fetchAMOMetadata(ctx, "a@b", fakeSeq(resp(429, nil, "", "")), nil)
	check(truthy(amo429["rate_limited"]) && truthy(amo429["error"]), "amo_429 %v", amo429)
	chrome503 := FetchChromeMetadata(ctx, rep("a", 32), fakeSeq(resp(503, map[string]string{"retry-after": "60"}, "", "")), nil, nil)
	check(truthy(chrome503["rate_limited"]), "chrome_503 %v", chrome503)
	paged, res := FetchMozillaBlocklist(ctx, fakeSeq(
		resp(200, map[string]string{"Next-Page": "https://firefox.settings.services.mozilla.com/p2"}, `{"data":[{"guid":"a@b"}]}`, ""),
		resp(200, nil, `{"data":[{"guid":"c@d"}]}`, "")), nil)
	check(res == FetchOK && len(paged) == 2 && paged["a@b"] != nil && paged["c@d"] != nil, "paged %v", paged)
	// A failed later page discards the partial list instead of returning page 1 only.
	partial, res := FetchMozillaBlocklist(ctx, fakeSeq(
		resp(200, map[string]string{"Next-Page": "https://firefox.settings.services.mozilla.com/p2"}, `{"data":[{"guid":"a@b"}]}`, ""),
		resp(502, nil, "", "")), nil)
	check(res == FetchFailed && len(partial) == 0, "partial %v", partial)

	// Conditional GET: the ETag goes out as If-None-Match; 304 means "use the cache".
	condClient := func(sent *[]map[string]string, responses ...Response) *HTTPClient {
		next := queue(responses...)
		return &HTTPClient{fake: &fakeTransport{get: func(_ string, _ map[string]struct{}, _ int, h map[string]string) Response {
			*sent = append(*sent, h)
			return next()
		}}}
	}
	val := map[string]string{}
	var sent []map[string]string
	got, res := FetchMozillaBlocklist(ctx, condClient(&sent, resp(200, map[string]string{"ETag": `"v1"`}, `{"data":[{"guid":"a@b"}]}`, "")), val)
	check(res == FetchOK && len(got) == 1 && got["a@b"] != nil && reflect.DeepEqual(val, map[string]string{"etag": `"v1"`}), "etag stored %v", val)
	check(len(sent) == 1 && sent[0] == nil, "first request unconditional %v", sent)
	sent = nil
	_, res = FetchMozillaBlocklist(ctx, condClient(&sent, resp(304, nil, "", "")), val)
	check(res == FetchNotModified, "304 not modified")
	check(len(sent) == 1 && reflect.DeepEqual(sent[0], map[string]string{"If-None-Match": `"v1"`}), "conditional %v", sent)

	blob, count, maxCVSS, hasMax := SummarizeVulnerabilities([]any{
		map[string]any{"cve": "CVE-2024-0001", "cvss_score": 8.8},
		map[string]any{"cve": "CVE-2024-0002", "cvss_score": 5.1},
	})
	check(count == 2 && hasMax && maxCVSS == 8.8 && strings.Contains(blob, "CVE-2024-0001"), "summarize %s", blob)
	check(publisherIsReputable("1Password Devs"), "AMO author suffix")
	check(publisherIsReputable("AgileBits Inc") && publisherIsReputable("Duck Duck Go, Inc."), "AgileBits/DDG")
	check(publisherIsReputable("Google Ireland, Ltd.") && !publisherIsReputable("eyeo GmbH"), "Google Ireland/eyeo")
	// Chrome trust is by ID: a lookalike name with another ID is not reputable.
	check(chromePublisherIsReputable("udb847e9815e2e1626d9ddb346d722811"), "chrome id")
	check(!chromePublisherIsReputable("u"+rep("0", 32)) && !chromePublisherIsReputable(nil), "chrome id negative")
	chromeMeta := map[string]any{"store": "chrome", "status": "public", "publisher": "AgileBits Inc",
		"publisher_id": "u" + rep("1", 32)}
	spoof := analyze(map[string]any{"store": "chrome", "extension_id": rep("a", 32), "name": "x",
		"host_count": 1, "store_meta": chromeMeta})
	check(spoof["publisher_reputable"] == false, "Chrome name match without ID must not be trusted")
	// Host-reported IDs never reach a store URL unless they are real Chrome IDs.
	check(FetchChromeMetadata(ctx, "../publisher/x", noNet(), nil, nil)["error"] == "invalid chrome extension id", "invalid id")
	// Edits to the file are picked up without a restart (mtime change).
	pubs = append(pubs, map[string]any{"name": "Late Addition", "match_names": []any{"Late Addition"}, "added_at": "2026-10-27T00:00:00Z"})
	writeJSONFile(tmp.Name(), map[string]any{"publishers": pubs})
	bumpMtime(tmp.Name(), 5*time.Second)
	check(publisherIsReputable("Late Addition Inc"), "reload on mtime change")
	check(!publisherIsReputable("Totally Not 1Password Devs"), "Totally Not")
	// Safari: the App Store lists the containing app, looked up by its bundle ID.
	check(safariContainingApp("/Applications/Wipr.app/Contents/PlugIns/Wipr Extra.appex") == "/Applications/Wipr.app", "appex")
	check(safariContainingApp("/Users/a/Applications/X.app/Contents/PlugIns/X.appex") == "", "user appex")

	itunes := func(results []any, status int, urls *[]string) *HTTPClient {
		return &HTTPClient{fake: &fakeTransport{get: func(u string, _ map[string]struct{}, _ int, _ map[string]string) Response {
			if urls != nil {
				*urls = append(*urls, u)
			}
			return resp(status, nil, mustJSON(map[string]any{"resultCount": len(results), "results": results}), "")
		}}}
	}
	app := map[string]any{"bundleId": "com.1password.safari", "trackName": "1Password for Safari",
		"sellerName": "AgileBits Inc.", "version": "8.12.42", "averageUserRating": 0,
		"userRatingCount": 0, "currentVersionReleaseDate": "2026-10-22T16:41:31Z",
		"primaryGenreName": "Utilities", "sellerUrl": "https://1password.com",
		"trackViewUrl": "https://apps.apple.com/us/app/id1569813296?mt=12"}
	var itunesURLs []string
	sm := FetchStoreMetadata(ctx, "safari", "com.1password.safari", itunes([]any{app}, 200, &itunesURLs), nil)
	check(sm["status"] == "public" && sm["developer"] == "AgileBits Inc." && sm["rating"] == nil, "safari meta %v", sm)
	_, hasUnavailable := sm["manifest_unavailable"]
	check(strings.Contains(itunesURLs[0], "bundleId=com.1password.safari") && !hasUnavailable, "itunes url %v", itunesURLs)
	otherApp := fetchSafariMetadata(ctx, "com.evil.app", itunes([]any{app}, 200, nil)) // answer for another app
	check(otherApp["status"] == "off_store", "off_store %v", otherApp)
	off := analyze(map[string]any{"store": "safari", "name": "x", "host_count": 2, "store_meta": otherApp})
	check(off["threat_score"] == int64(0) && hasSignal(off, "not-in-app-store"), "off %v", off)
	apps := map[string]any{"/Applications/W.app": []any{"site.w", "TEAM1"}}
	ext := DeriveExtensionIdentity(map[string]any{"source": "safari_extensions", "name": "Wipr Extra",
		"installed_paths": []any{"/Applications/W.app/Contents/PlugIns/X.appex"}})
	bound := WithSafariApp(ext, apps)
	check(bound["extension_key"] == "ext:safari:site.w/x.appex@team1" && bound["app_team_id"] == "TEAM1", "bound %v", bound)
	check(strings.HasSuffix(WithSafariApp(ext, map[string]any{"/Applications/W.app": []any{"site.w", nil}})["extension_key"].(string), "@unsigned"), "unsigned")
	check(WithSafariApp(ext, map[string]any{})["extension_key"] == ext["extension_key"], "unbound key")
	check(bound["display_name"] == "W \u203a Wipr Extra", "display %v", bound["display_name"])
	check(WithSafariApp(bound, apps)["display_name"] == "W \u203a Wipr Extra", "idempotent")
	check(fetchSafariMetadata(ctx, "../x", itunes([]any{app}, 200, nil))["error"] == "invalid app bundle id", "bundle id")
	check(fetchSafariMetadata(ctx, "com.a.b", itunes([]any{}, 500, nil))["status"] == "unknown", "itunes 500")
	appex := "/Applications/1Password for Safari.app/Contents/PlugIns/1Password.appex"
	forged := DeriveExtensionIdentity(map[string]any{"source": "safari_extensions",
		"name": "com.1password.safari/1password.appex@2BUA8C4S2C"})
	check(!strings.Contains(forged["extension_key"].(string), "@"), "forged %v", forged) // cannot reach a team key
	installs := []any{map[string]any{"path": appex, "platform": "darwin"}}
	check(analyze(map[string]any{"store": "safari", "name": "1Password", "host_count": 3, // stale/unbound key
		"app_team_id": "2BUA8C4S2C", "extension_id": "com.1password.safari/1password.appex",
		"installs": installs, "store_meta": sm})["publisher_reputable"] == false, "unbound key")
	sr := analyze(map[string]any{"store": "safari", "name": "1Password", "host_count": 3, "app_team_id": "2BUA8C4S2C",
		"extension_id": "com.1password.safari/1password.appex@2BUA8C4S2C", "installs": installs, "store_meta": sm})
	check(sr["publisher_reputable"] == true && sr["store_status"] == "public", "sr %v", sr)
	check(analyze(map[string]any{"store": "safari", "name": "1Password", "host_count": 3, // seller name alone
		"app_team_id": "ZZZZZZZZZZ", "installs": installs, "store_meta": sm})["publisher_reputable"] == false, "seller name")
	check(analyze(map[string]any{"store": "safari", "name": "1Password", "host_count": 3, // unsigned app
		"installs": installs, "store_meta": sm})["publisher_reputable"] == false, "unsigned app")
	check(!hasSignal(sr, "manifest-uninspected"), "sr uninspected")
	check(hasSignal(sr, "manifest-not-published") && sr["threat_score"] == int64(0), "sr not published")
	moved := analyze(map[string]any{"store": "safari", "name": "1Password", "host_count": 3, "app_team_id": "2BUA8C4S2C",
		"extension_id": "com.1password.safari/1password.appex@2BUA8C4S2C",
		"installs":     []any{map[string]any{"path": "/tmp/1Password.appex", "platform": "darwin"}}, "store_meta": sm})
	check(moved["publisher_reputable"] == false && hasSignal(moved, "not-store-install"), "moved %v", moved)
}

func selfCheckChrome(ctx context.Context) {
	// Chrome listing RPC: envelopes map by tag, null payload = not served,
	// a payload for another ID is drift (no partial data), bad IDs never sent.
	aID, bID, cID, dID, eID := rep("a", 32), rep("b", 32), rep("c", 32), rep("d", 32), rep("e", 32)
	rpc, rec := newRPC(resp(200, nil, rpcBody(cwsEnv{tag: "3", payload: cwsPayload(dID, "dev@example.org")},
		cwsEnv{tag: "1", payload: cwsPayload(aID, "dev@example.org")}, cwsEnv{tag: "2"}), ""))
	listings := FetchChromeListings(ctx, []string{aID, "../x", bID, aID, cID}, rpc)
	check(len(rec.forms) == 1 && !strings.Contains(rec.forms[0], "../x") && strings.Count(rec.forms[0], aID) == 1, "forms %v", rec.forms)
	check(len(listings) == 3 && listings[aID] != nil && listings[bID] != nil && listings[cID] != nil, "listings %v", listings)
	hit := listings[aID]
	want := map[string]any{
		"store": "chrome", "status": "public", "url": "https://chromewebstore.google.com/detail/" + aID,
		"name": "Ex", "version": "2.1", "manifest_version": int64(3), "permissions": []string{"tabs"},
		"content_script_matches": []string{"<all_urls>"}, "users": int64(100_000), "rating": 4.3, "rating_count": int64(1234),
		"category": "Workflow & Planning", "featured": true, "updated_at": "2026-09-21T14:13:20+00:00",
		"developer_website": "https://example.org", "developer_email": "dev@example.org", "trader": true,
		"privacy_codes": []int64{1, 6}, "privacy_disclosure": "The developer has disclosed that it collects or uses: " +
			"personally identifiable information, location",
		"privacy_policy_url": "https://example.org/privacy", "publisher_id": "u" + rep("1", 32),
		"publisher": "Example", "established_publisher": true,
	}
	check(pyDumps(hit) == pyDumps(want), "listing\n got %s\nwant %s", pyDumps(hit), pyDumps(want))
	check(listings[bID]["status"] == "unlisted" && listings[bID]["listing_missing"] == true, "unlisted %v", listings[bID])
	drift := listings[cID]
	_, hasUsers := drift["users"]
	check(drift["status"] == "unknown" && strings.Contains(pyStr(drift["error"]), "schema drift") && !hasUsers, "drift %v", drift)
	// Null payloads: removed (7) is a takedown, transient codes are errors, not "unlisted".
	odd := cwsPayload(cID, "dev@example.org")
	odd[14] = []any{1e20}
	odd[0].([]any)[14] = json.Number("1180591620717411303424") // 2 ** 70
	nontrader := cwsPayload(dID, "dev@example.org")
	nontrader[10].([]any)[5], nontrader[10].([]any)[7], nontrader[0].([]any)[8] = "Solo Dev", nil, nil
	codedClient, _ := newRPC(resp(200, nil, rpcBody(cwsEnv{tag: "1", code: []any{7}}, cwsEnv{tag: "2", code: []any{14}},
		cwsEnv{tag: "3", payload: odd}, cwsEnv{tag: "4", payload: nontrader}, cwsEnv{tag: "5", code: []any{8}}), ""))
	coded := FetchChromeListings(ctx, []string{aID, bID, cID, dID, eID}, codedClient)
	_, missing := coded[aID]["listing_missing"]
	check(coded[aID]["status"] == "removed" && !missing, "removed %v", coded[aID])
	check(coded[bID]["status"] == "unknown" && strings.Contains(pyStr(coded[bID]["error"]), "code 14"), "code 14 %v", coded[bID])
	_, hasUpdated := coded[cID]["updated_at"]
	check(coded[cID]["status"] == "public" && !hasUpdated, "odd %v", coded[cID])
	_, hasEstablished := coded[dID]["established_publisher"]
	check(coded[dID]["publisher"] == "Solo Dev" && !hasEstablished, "nontrader %v", coded[dID])
	check(coded[eID]["rate_limited"] == true, "code 8 %v", coded[eID])
	deepClient, _ := newRPC(resp(200, nil, ")]}'\n"+rep("[", 100_000), ""))
	check(truthy(FetchChromeListings(ctx, []string{aID}, deepClient)[aID]["error"]), "deep nesting")
	badMailClient, _ := newRPC(resp(200, nil, rpcBody(cwsEnv{tag: "1", payload: cwsPayload(aID, "x@y")}), ""))
	badMail := FetchChromeListings(ctx, []string{aID}, badMailClient)[aID]
	_, hasMail := badMail["developer_email"]
	check(!hasMail && badMail["status"] == "public", "bad mail %v", badMail)
	limitedClient, _ := newRPC(resp(429, nil, "", ""))
	limited := FetchChromeListings(ctx, []string{aID, bID}, limitedClient)
	for _, m := range limited {
		check(m["rate_limited"] == true && truthy(m["error"]), "limited %v", m)
	}
	// After a 429 the later chunks are marked, not posted (one response queued).
	many := make([]string, cwsRPCBatch+1)
	for n := range many {
		var b strings.Builder
		for k := 0; k < 32; k++ {
			b.WriteByte("abcdefghijklmnop"[(n>>(4*k))&15])
		}
		many[n] = b.String()
	}
	manyClient, manyRec := newRPC(resp(429, nil, "", ""))
	limited = FetchChromeListings(ctx, many, manyClient)
	check(len(manyRec.forms) == 1 && len(limited) == len(many), "many %d %d", len(manyRec.forms), len(limited))
	for _, m := range limited {
		check(m["rate_limited"] == true, "many limited %v", m)
	}
	check(len(FetchChromeListings(ctx, []string{"nope"}, noNet())) == 0, "invalid ids never sent")
	// A cached manifest for the update2 version skips the CRX download.
	cachedClient, cachedRec := newRPC(resp(200, nil, `<gupdate><app><updatecheck status="ok" version="1.2" `+
		`codebase="https://clients2.googleusercontent.com/x.crx"/></app></gupdate>`, ""))
	cachedMV := FetchChromeMetadata(ctx, bID, cachedClient,
		map[string]any{"store": "chrome", "status": "unlisted", "listing_missing": true},
		func(v string) map[string]any {
			if v == "1.2" {
				return map[string]any{"manifest_version": int64(3), "crx_hash_verified": true}
			}
			return nil
		})
	check(cachedMV["manifest_version"] == int64(3) && cachedMV["status"] == "unlisted", "cached_mv %v", cachedMV)
	check(len(cachedRec.forms) == 0 && len(cachedRec.urls) == 1 && strings.Contains(cachedRec.urls[0], "update2"), "cached urls %v", cachedRec.urls)
	// Listed: the manifest came with the listing, so no update2 and no CRX.
	listedClient, listedRec := newRPC(resp(200, nil, rpcBody(cwsEnv{tag: "1", payload: cwsPayload(aID, "dev@example.org")}), ""))
	check(FetchChromeMetadata(ctx, aID, listedClient, nil, nil)["status"] == "public" && len(listedRec.urls) == 0, "listed no update2")
	goneClient, _ := newRPC(resp(200, nil, rpcBody(cwsEnv{tag: "1"}), ""),
		resp(200, nil, `<gupdate><app><updatecheck status="error-unknownApplication"/></app></gupdate>`, ""))
	gone := FetchChromeMetadata(ctx, bID, goneClient, nil, nil)
	_, missing = gone["listing_missing"]
	check(gone["status"] == "not_found" && !missing, "gone %v", gone)
	listing := hit

	// Large archives parse (only the manifest is read); a huge manifest does not.
	big := makeZip(map[string][]byte{"manifest.json": []byte(`{"manifest_version": 3}`), "blob.bin": make([]byte, 40<<20)})
	parsed, err := parseCRX(big)
	check(err == nil && pyDumps(parsed) == `{"manifest_version":3}`, "big zip %v %v", parsed, err)
	_, err = parseCRX(makeZip(map[string][]byte{"manifest.json": append(bytes.Repeat([]byte(" "), maxManifestBytes+10), "{}"...)}))
	check(err != nil && strings.Contains(err.Error(), "exceeds 1 MB"), "oversized manifest accepted: %v", err)

	hugeClient := noUpdateClient(nil, func(u string) (Response, bool) {
		if strings.Contains(u, "update2") {
			return resp(200, nil, `<gupdate><app><updatecheck status="ok" version="1" `+
				`codebase="https://clients2.googleusercontent.com/x.crx"/></app></gupdate>`, ""), true
		}
		if strings.HasSuffix(u, ".crx") {
			return resp(200, nil, "Cr24\x03\x00\x00\x00", "response too large"), true
		}
		return Response{}, false
	}, nil)
	huge := FetchChromeMetadata(ctx, cID, hugeClient, nil, nil)
	_, hasManifestErr := huge["manifest_error"]
	check(!hasManifestErr && strings.Contains(pyStr(huge["manifest_unavailable"]), "50 MB"), "huge %v", huge)

	selfCheckFeeds(ctx)

	// Edge falls back to the Chrome Web Store for IDs Edge's store does not know.
	edgeMissGet := func(u string) (Response, bool) {
		if strings.Contains(u, "microsoftedge") {
			return resp(404, nil, "", ""), true
		}
		return Response{}, false
	}
	via := FetchStoreMetadata(ctx, "edge", dID, noUpdateClient(nil, edgeMissGet, func() Response {
		return resp(200, nil, rpcBody(cwsEnv{tag: "1", payload: cwsPayload(dID, "dev@example.org")}), "")
	}), nil)
	check(via["store"] == "chrome" && via["resolved_from"] == "edge", "via %v", via)
	down := FetchStoreMetadata(ctx, "edge", dID, noUpdateClient(nil, edgeMissGet, func() Response {
		return resp(500, nil, "", "")
	}), nil)
	check(down["status"] == "unknown" && truthy(down["error"]), "down %v", down) // not a cacheable not_found

	// AMO: manifest_version and content scripts come from the signed XPI.
	xpi := makeZip(map[string][]byte{"manifest.json": []byte(mustJSON(map[string]any{"manifest_version": 2,
		"content_scripts": []any{map[string]any{"matches": []any{"<all_urls>"}, "js": []any{"c.js"}}}}))})
	amoClient := func(digest string) *HTTPClient {
		return &HTTPClient{fake: &fakeTransport{get: func(u string, allowed map[string]struct{}, _ int, _ map[string]string) Response {
			check(reflect.DeepEqual(allowed, amoHosts), "AMO allowlist")
			if strings.HasSuffix(u, ".xpi") {
				return Response{Status: 200, Body: xpi}
			}
			return resp(200, nil, mustJSON(map[string]any{"status": "public", "current_version": map[string]any{
				"version": "1", "file": map[string]any{
					"url":  "https://addons.mozilla.org/firefox/downloads/file/1/x.xpi",
					"hash": "sha256:" + digest, "size": len(xpi), "permissions": []any{"tabs"}}}}), "")
		}}}
	}
	sum := sha256.Sum256(xpi)
	amo := fetchAMOMetadata(ctx, "x@y.org", amoClient(hex.EncodeToString(sum[:])), nil)
	check(amo["manifest_version"] == int64(2) && pyDumps(amo["content_script_matches"]) == `["<all_urls>"]`, "amo %v", amo)
	check(pyDumps(amo["permissions"]) == `["tabs"]` && amo["crx_hash_verified"] == true, "amo perms %v", amo)
	tampered := fetchAMOMetadata(ctx, "x@y.org", amoClient(rep("0", 64)), nil)
	check(tampered["manifest_error"] == "XPI SHA-256 does not match AMO", "tampered %v", tampered)

	var nuURLs []string
	servedNone := FetchChromeMetadata(ctx, cID, noUpdateClient(&nuURLs, nil, nil), nil, nil)
	check(strings.Contains(nuURLs[0], "prodversion=999.0"), "prodversion %v", nuURLs)
	_, hasManifestErr = servedNone["manifest_error"]
	check(servedNone["status"] == "unlisted" && !hasManifestErr, "served_none %v", servedNone)
	nuResult := analyze(map[string]any{"store": "chrome", "extension_id": cID, "name": "x", "host_count": 1, "store_meta": servedNone})
	check(!hasSignal(nuResult, "manifest-unparseable"), "nu unparseable")
	// Uninspected must not fail open: it carries its own non-zero signal.
	check(hasSignal(nuResult, "manifest-uninspected"), "nu uninspected")
	check(nuResult["threat_score"].(int64) >= 15 && huge["crx_hash_verified"] == nil, "nu threat")

	listedMeta := copyMap(listing)
	listedMeta["status"] = "public"
	listedChrome := analyze(map[string]any{"store": "chrome", "extension_id": cID, "name": "x", "host_count": 1, "store_meta": listedMeta})
	for _, code := range []string{"store-featured", "install-popularity", "manifest-v3"} {
		check(hasSignal(listedChrome, code), "listed_chrome missing %s", code)
	}
	check(listedChrome["developer_email"] == "dev@example.org" && listedChrome["featured"] == true, "listed_chrome %v", listedChrome)
	panned := analyze(map[string]any{"store": "chrome", "extension_id": cID, "name": "x", "host_count": 1,
		"store_meta": map[string]any{"status": "public", "rating": 1.8, "rating_count": 400}})
	check(hasSignal(panned, "poor-public-reputation") && panned["threat_score"].(int64) >= 15, "panned %v", panned)

	selfCheckBuiltins()
	selfCheckOpera(ctx)
}

func selfCheckFeeds(ctx context.Context) {
	// Threat feeds: parse, classify, scope by platform, score.
	feedTmp, err := os.CreateTemp("", "feeds-*.json")
	if err != nil {
		panic(err)
	}
	feedTmp.Close()
	writeJSONFile(feedTmp.Name(), map[string]any{"feeds": []any{
		map[string]any{"name": "t", "url": "https://feeds.example.org/x.csv", "format": "csv", "platform": "chromium",
			"id_field": "id", "reason_field": "why", "added_at": "2026-10-27T00:00:00Z"},
		map[string]any{"name": "lan", "url": "https://192.168.1.5/x.csv", "format": "csv", "platform": "chromium",
			"id_field": "id", "added_at": "2026-10-27T00:00:00Z"}, // skipped: IP host
		map[string]any{"name": "plain", "url": "http://feeds.example.org/x.csv", "format": "csv", "platform": "chromium",
			"id_field": "id", "added_at": "2026-10-27T00:00:00Z"}, // skipped: not https
		map[string]any{"name": "nodate", "url": "https://feeds.example.org/x.csv", "format": "csv",
			"platform": "chromium", "id_field": "id"}, // skipped: no added_at
	}})
	os.Setenv("EXTENSION_THREAT_FEEDS_FILE", feedTmp.Name())
	feeds := LoadThreatFeeds()
	os.Remove(feedTmp.Name())
	check(len(feeds) == 1 && feeds[0]["name"] == "t", "feeds %v", feeds)

	feedClient := &HTTPClient{fake: &fakeTransport{get: func(_ string, allowed map[string]struct{}, _ int, _ map[string]string) Response {
		check(reflect.DeepEqual(allowed, set("feeds.example.org")), "feed allowlist %v", allowed)
		return resp(200, nil, "\ufeffid,why\n"+rep("a", 32)+",Malware\n"+rep("b", 32)+",Adware\n"+
			rep("c", 32)+",Policy Violation\nnot-an-id,Malware\n", "")
	}}}
	entries, res := FetchThreatFeed(ctx, feeds[0], feedClient, nil)
	check(res == FetchOK && len(entries) == 3 && entries[rep("a", 32)] != nil && entries[rep("b", 32)] != nil &&
		entries[rep("c", 32)] != nil, "entries %v", entries)
	fval := map[string]string{"etag": `"f1"`}
	var sent []map[string]string
	fcond := &HTTPClient{fake: &fakeTransport{get: func(_ string, _ map[string]struct{}, _ int, h map[string]string) Response {
		sent = append(sent, h)
		return resp(304, nil, "", "")
	}}}
	_, res = FetchThreatFeed(ctx, feeds[0], fcond, fval)
	check(res == FetchNotModified, "feed 304")
	check(len(sent) == 1 && reflect.DeepEqual(sent[0], map[string]string{"If-None-Match": `"f1"`}), "feed conditional %v", sent)
	index := map[string]map[string]any{"t": {"platform": "chromium", "entries": entries}}
	check(len(MatchThreatFeeds(index, "firefox", rep("a", 32))) == 0, "platform-scoped")
	vh := MatchThreatFeeds(index, "vivaldi", rep("A", 32))
	check(len(vh) == 1 && vh[0]["severity"] == "malicious", "vivaldi %v", vh)
	sev, _ := classifyFeedReason("Adware")
	check(sev == "unwanted", "Adware")
	sev, threat := classifyFeedReason("Policy Violation")
	check(sev == "listed" && threat == 45, "Policy Violation")
	for _, tc := range []struct {
		id    string
		floor int64
		bad   bool
	}{{rep("a", 32), 85, true}, {rep("b", 32), 70, false}, {rep("c", 32), 60, false}} {
		r := AnalyzeExtension(map[string]any{"store": "edge", "extension_id": tc.id, "name": "x", "host_count": 1,
			"store_meta": map[string]any{"status": "public", "users": 50}},
			AnalyzeOptions{FeedHits: MatchThreatFeeds(index, "edge", tc.id)})
		check(r["risk_score"].(int64) >= tc.floor && r["known_bad"] == tc.bad, "%s %v %v", tc.id, r["risk_score"], r["known_bad"])
		check(hasSignal(r, "threat-feed:t"), "threat-feed:t %v", r)
	}
}

func selfCheckBuiltins() {
	// Built-in ID/path never hides a blocklist or feed hit; the flag survives.
	fxBuiltin := map[string]any{"store": "firefox", "extension_id": "evil@mozilla.org", "name": "x",
		"host_count": 3, "versions": []any{"1.0"}}
	stale := analyze(map[string]any{"store": "safari", "is_builtin": true, "name": "Clipper", "host_count": 1,
		"installed_paths": []any{"/Applications/C.app/Contents/PlugIns/C.appex"}})
	check(stale["is_builtin"] == false && stale["risk_score"].(int64) > 0, "stale %v", stale)
	check(analyze(fxBuiltin)["risk_score"] == int64(0), "fx builtin")
	flagged := AnalyzeExtension(fxBuiltin, AnalyzeOptions{BlocklistEntry: map[string]any{"guid": "evil@mozilla.org"}})
	check(flagged["risk_score"].(int64) >= 85 && flagged["known_bad"] == true && flagged["is_builtin"] == true, "flagged %v", flagged)
	fed := AnalyzeExtension(fxBuiltin, AnalyzeOptions{FeedHits: []map[string]any{{"feed": "f", "reason": "adware",
		"severity": "unwanted", "threat": int64(70)}}})
	check(fed["risk_score"].(int64) >= 70 && fed["known_bad"] == false, "fed %v", fed)
	// Safari: only Safari.app / system extensions are built-in, not App Store app extensions.
	check(!IsBrowserBuiltin(map[string]any{"store": "safari", "extension_id": "com.x.ext",
		"installed_paths": []any{"/Applications/X.app/Contents/PlugIns/X Extension.appex"}}), "safari app ext")
	check(IsBrowserBuiltin(map[string]any{"store": "safari", "extension_id": "com.apple.y",
		"installed_paths": []any{"/Applications/Safari.app/Contents/PlugIns/Y.appex"}}), "safari builtin")
	check(!IsBrowserBuiltin(map[string]any{"store": "safari", "extension_id": "com.x.z",
		"installed_paths": []any{"/Users/a/Downloads/Safari.app/Contents/PlugIns/Z.appex"}}), "safari downloads")
	for _, tc := range []struct {
		store, path string
		want        bool
	}{
		{"chrome", `C:\Program Files\Google\Chrome\Application\120.0\resources\x`, true},
		{"chrome", `C:\Users\a\AppData\Local\Google\Chrome\Application\120.0\x`, true},
		{"chrome", `C:\Users\a\Desktop\Google\Chrome\Application\x`, false},
		{"brave", `C:\Users\x\Desktop\application\evil`, false},
		{"vivaldi", `C:\Program Files\Vivaldi\Application\6.0\x`, true},
		{"edge", `C:\Program Files (x86)\Microsoft\Edge\Application\156.0\BHO\x.dll`, true},
		{"firefox", "/Applications/Firefox.app/Contents/Resources/browser/features/a.xpi", true},
		{"firefox", `C:\Program Files\Mozilla Firefox\browser\features\a.xpi`, true},
		{"firefox", "/tmp/browser/features/a.xpi", false},
	} {
		got := IsBrowserBuiltin(map[string]any{"store": tc.store, "extension_id": "x", "installed_paths": []any{tc.path}})
		check(got == tc.want, "builtin %s %s = %v", tc.store, tc.path, got)
	}

	// Typosquat: a store-vouched publisher's look-alike name is not penalised.
	_, pen := nameAnomalySignals("Motion", "", false)
	check(pen == 18, "Motion penalty %d", pen)
	sig, pen := nameAnomalySignals("Motion", "", true)
	check(pen == 0 && len(sig) > 0 && sig[0]["code"] == "brand-lookalike-vouched", "vouched %v", sig)
	_, pen = nameAnomalySignals("Bitwardn", "", false)
	check(pen == 18, "Bitwardn penalty %d", pen)
	home := "/Users/a/Library/Application Support/Google/Chrome/Default/Extensions/"
	badge := map[string]any{"status": "public", "established_publisher": true, "users": 500_000}
	okInstalls := []any{map[string]any{"path": home + rep("e", 32) + "/1.0_0", "platform": "darwin"}}
	ok := analyze(map[string]any{"store": "chrome", "extension_id": rep("e", 32), "name": "Motion", "host_count": 2,
		"installs": okInstalls, "store_meta": badge})
	check(!hasSignal(ok, "typosquat-brand"), "badged ok %v", ok)
	unpacked := analyze(map[string]any{"store": "chrome", "extension_id": rep("e", 32), "name": "Motion", "host_count": 2,
		"installs": []any{map[string]any{"path": "/tmp/x", "platform": "darwin"}}, "store_meta": badge})
	check(hasSignal(unpacked, "typosquat-brand"), "unpacked %v", unpacked)
	smallBadge := copyMap(badge)
	smallBadge["users"] = 5_000
	small := analyze(map[string]any{"store": "chrome", "extension_id": rep("e", 32), "name": "Bitwardn", "host_count": 2,
		"installs": okInstalls, "store_meta": smallBadge})
	check(hasSignal(small, "typosquat-brand"), "small %v", small)

	// Declared data collection adds capability (capped), only for weighted codes.
	cap0, _ := capability(strSet{}, set("https://a.com/*"), strSet{}, strSet{}, nil, nil)
	cap1, sig1 := capability(strSet{}, set("https://a.com/*"), strSet{}, strSet{}, []any{4, 3, 5, 6}, nil)
	check(cap1-cap0 == privacyCap && sig1[len(sig1)-1]["code"] == "declared-data-collection", "privacy %v", sig1)
	cap2, _ := capability(strSet{}, strSet{}, strSet{}, strSet{}, []any{6, 9}, nil)
	check(cap2 == 0, "unweighted privacy codes %d", cap2)

	// Trust signals carry negative weights equal to the trust points they add.
	sumW := func(sigs []map[string]any) (s int64) {
		for _, x := range sigs {
			s += x["weight"].(int64)
		}
		return s
	}
	trust, tsig := trustScore(map[string]any{"status": "public", "manifest_version": 3, "featured": true}, map[string]any{}, false)
	check(trust == -sumW(tsig) && trust == 38, "trust %d %v", trust, tsig)
	utrust, usig := trustScore(map[string]any{"status": "unlisted"}, map[string]any{}, false)
	check(utrust == -sumW(usig) && utrust == 5, "utrust %d %v", utrust, usig)
}

func selfCheckOpera(ctx context.Context) {
	// Opera: addons.opera.com first (HTML listing + CRX), then the Chrome Web Store.
	oid := rep("k", 32)
	page := `<meta property="aoc:app_id" content="` + oid + `" /><meta property="aoc:slug" content="ublock" />` +
		`<meta property="og:title" content="uBlock Origin" /><h2 class="h-byline" itemprop="brand">` +
		`by <a href="/en/search/?developer=gorhill" itemprop="name">gorhill</a></h2>` +
		`<span class="rating" id="rating-value">4.8</span>` +
		`<span id="rating-count" itemprop="reviewCount">5,530</span>` +
		`<span class="total" itemprop="reviewCount">319</span>` +
		`<dt>Downloads</dt><dd>15,508,453</dd><dt>Category</dt><dd><a href="/c/">Privacy &amp; ` +
		`Security</a></dd><dt>Version</dt><dd>1.75.0</dd><dt>Last update</dt><dd>Sept. 18, 2026</dd>`
	ocrx := makeZip(map[string][]byte{"manifest.json": []byte(mustJSON(map[string]any{"manifest_version": 3,
		"name": "__MSG_n__", "permissions": []any{"cookies"}}))})
	opera := func(page string, status int, urls *[]string, crxDown bool, post func() Response) *HTTPClient {
		ft := &fakeTransport{get: func(u string, _ map[string]struct{}, _ int, _ map[string]string) Response {
			if urls != nil {
				*urls = append(*urls, u)
			}
			if strings.Contains(u, "/download/") {
				if crxDown {
					return resp(0, nil, "", "Connection reset by peer")
				}
				return Response{Status: 200, Body: ocrx}
			}
			return resp(status, nil, page, "")
		}}
		if post != nil {
			ft.post = func(string, url.Values, map[string]struct{}, int) Response { return post() }
		}
		return &HTTPClient{fake: ft}
	}
	downO := fetchOperaMetadata(ctx, oid, opera(page, 200, nil, true, nil), nil)
	check(downO["status"] == "unknown" && truthy(downO["error"]), "down_o %v", downO) // not cached
	om := FetchStoreMetadata(ctx, "opera", oid, opera(page, 200, nil, false, nil), nil)
	check(om["store"] == "opera" && om["status"] == "public" && om["developer"] == "gorhill" &&
		om["users"] == int64(15_508_453) && om["rating_count"] == int64(5_530), "om %v", om)
	check(om["name"] == "uBlock Origin" && om["manifest_version"] == int64(3) && pyDumps(om["permissions"]) == `["cookies"]`, "om manifest %v", om)
	check(strings.HasPrefix(pyStr(om["updated_at"]), "2026-09-18") && om["category"] == "Privacy & Security", "om date %v", om)
	check(om["url"] == "https://addons.opera.com/en/extensions/details/ublock/", "om url %v", om)
	var cachedURLs []string
	fetchOperaMetadata(ctx, oid, opera(page, 200, &cachedURLs, false, nil), func(string) map[string]any {
		return map[string]any{"manifest_version": int64(2)}
	})
	for _, u := range cachedURLs {
		check(!strings.Contains(u, "/download/"), "cached version: no CRX %v", cachedURLs)
	}
	wrong := fetchOperaMetadata(ctx, oid, opera(strings.ReplaceAll(page, oid, rep("j", 32)), 200, nil, false, nil), nil)
	check(wrong["status"] == "unknown" && strings.Contains(pyStr(wrong["error"]), "does not match"), "wrong %v", wrong)
	omDev := copyMap(om)
	omDev["developer"] = "AgileBits"
	check(analyze(map[string]any{"store": "opera", "extension_id": oid, "name": "x", "host_count": 1,
		"store_meta": omDev})["publisher_reputable"] == false, "opera names are display-only")

	ovia := FetchStoreMetadata(ctx, "opera", oid, opera("", 404, nil, false, func() Response {
		return resp(200, nil, rpcBody(cwsEnv{tag: "1", payload: cwsPayload(oid, "dev@example.org")}), "")
	}), nil)
	check(ovia["store"] == "chrome" && ovia["resolved_from"] == "opera", "ovia %v", ovia)
	onone := FetchStoreMetadata(ctx, "opera", oid, noUpdateClient(nil, func(u string) (Response, bool) {
		if strings.Contains(u, "update2") {
			return resp(200, nil, unknownAppXML, ""), true
		}
		return Response{}, false
	}, nil), nil)
	check(onone["store"] == "opera" && onone["status"] == "not_found", "onone %v", onone)

	// Weak CSP: eval or remote scripts, MV2 string or MV3 object; wasm-unsafe-eval is fine.
	weak := func(v any) (string, bool) { return weakCSP(v) }
	_, w := weak("script-src 'self' 'unsafe-eval'; object-src 'self'")
	check(w, "unsafe-eval")
	why, _ := weak("script-src 'self' https://evil.example")
	check(strings.Contains(why, "evil.example"), "remote script %q", why)
	_, w = weak(cspText(map[string]any{"extension_pages": "script-src 'self' 'wasm-unsafe-eval'"}))
	check(!w, "wasm-unsafe-eval")
	_, w = weak(nil)
	check(!w && cspText(map[string]any{"sandbox": 3}) == nil, "nil csp")
	_, w = weak(cspText(map[string]any{"sandbox": "sandbox allow-scripts; script-src 'self' 'unsafe-eval'",
		"extension_pages": "script-src 'self'"}))
	check(!w, "sandbox ignored")
	_, w = weak("default-src 'self' 'unsafe-eval'") // fallback directive
	check(w, "default-src fallback")
	_, w = weak("default-src 'self' 'unsafe-eval'; script-src 'self'")
	check(!w, "script-src overrides default-src")
	bw := []any{"/Applications/Bitwardn.app/Contents/PlugIns/B.appex"}
	typo := analyze(map[string]any{"store": "safari", "name": "ext:safari:x", "display_name": "Bitwardn \u203a Bitwardn",
		"installed_paths": bw, "host_count": 2, "store_meta": map[string]any{"status": "public"}})
	check(hasSignal(typo, "typosquat-brand"), "safari prefix stripped %v", typo)
	// An app name that itself contains " › " must not shift the split point.
	fake := analyze(map[string]any{"store": "safari", "name": "ext:safari:y",
		"display_name":    "Foo \u203a Bar \u203a Bitwardn",
		"installed_paths": []any{"/Applications/Foo \u203a Bar.app/Contents/PlugIns/B.appex"},
		"host_count":      2, "store_meta": map[string]any{"status": "public"}})
	check(hasSignal(fake, "typosquat-brand"), "app name with separator %v", fake)
	// Duplicate directive: the first one is what browsers enforce.
	_, w = weak("script-src 'self' 'unsafe-eval'; script-src 'self'")
	check(w, "first directive wins")
	_, w = weak("script-src 'self'; script-src-elem 'self' https://evil.example")
	check(w, "script-src-elem remote")
	weakR := analyze(map[string]any{"store": "firefox", "extension_id": "w@x", "name": "w", "host_count": 2,
		"store_meta": map[string]any{"status": "public", "content_security_policy": "script-src 'self' 'unsafe-eval'"}})
	check(hasSignal(weakR, "weak-csp") && weakR["capability_score"].(int64) >= 15, "weak %v", weakR)
	dnr, _ := capability(set("declarativeNetRequestWithHostAccess"), strSet{}, strSet{}, strSet{}, nil, nil)
	check(dnr > 0, "declarativeNetRequestWithHostAccess")
}
