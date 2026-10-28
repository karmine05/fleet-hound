package enrich

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/karmine05/fleet-hound/internal/catalog"
)

// UserAgent is categorize_software.USER_AGENT.
const UserAgent = "FleetHoundSoftwareCategorizer/1.0 (https://github.com/fleethound)"

// WikipediaRESTURL is WIKIPEDIA_REST_URL; %s is the percent-encoded title.
const WikipediaRESTURL = "https://en.wikipedia.org/api/rest_v1/page/summary/%s"

// Adaptive backoff (ADAPTIVE_BACKOFF_TRIGGER / _SECONDS).
const (
	adaptiveBackoffTrigger = 5
	adaptiveBackoffSleep   = 5 * time.Second
)

// softwareHintRE is _SOFTWARE_HINT_RE. A Wikipedia summary counts as a hit
// only if it mentions one of these. Go's \b is ASCII-only (python's is
// Unicode); the difference only shows next to non-ASCII letters.
var softwareHintRE = regexp.MustCompile(`(?i)\b(software|application|apps?|programs?|utilit(y|ies)|tools?|toolkit|librar(y|ies)|` +
	`framework|browser|editors?|clients?|servers?|daemon|shell|terminal|` +
	`command[- ]line|(linux|unix|shell) command|packages?|plug-?ins?|extensions?|` +
	`operating system|database|compiler|interpreter|` +
	`(programming|scripting|markup|query) language|ide|sdk|api|emulator|scanner|` +
	`messaging|messenger|driver|firmware|codec|compression|file formats?|typesetting|` +
	`graphics|open[- ]source|freeware|proprietary|vpn|antivirus|password manager|` +
	`cloud-based|web-based|web conferencing|communication (platform|service)|` +
	`online service|digital distribution|chatbot|generative artificial intelligence|` +
	`collaboration|` +
	`(video|computer|online|puzzle|indie|programming|simulation|survival|strategy|` +
	`roguelike|deck-building) game)\b`)

// result is the three-state EnrichResult.
type result int

const (
	resultHit       result = iota // found categories + description
	resultMiss                    // lookup succeeded but no entry (cache for cooldown)
	resultTransient               // timeout / 5xx: retry next cycle, no cooldown
)

// keywordToCategory is _KEYWORD_TO_CATEGORY (order matters).
var keywordToCategory = []struct {
	keywords []string
	cats     []string
}{
	{[]string{"password manager"}, []string{"Security Tool", "Password Manager"}},
	{[]string{"vpn", "virtual private network"}, []string{"Privacy Tool", "VPN"}},
	{[]string{"antivirus", "anti-virus", "endpoint detection"}, []string{"Security Tool", "Antivirus"}},
	{[]string{"encryption tool", "cryptographic"}, []string{"Security Tool"}},
	{[]string{"ssh client", "telnet client"}, []string{"Remote Access", "SSH Client"}},
	{[]string{"remote desktop", "remote control software"}, []string{"Remote Access", "Remote Desktop"}},
	{[]string{"web browser", "browser"}, []string{"Browser"}},
	{[]string{"instant messaging", "messaging app", "messenger"}, []string{"Communication", "Messaging"}},
	{[]string{"video conferencing", "video call", "video chat"}, []string{"Communication", "Video Conferencing"}},
	{[]string{"voice chat", "voice over ip", "voip"}, []string{"Communication", "Voice Chat"}},
	{[]string{"team collaboration"}, []string{"Communication", "Team Chat"}},
	{[]string{"note-taking", "note taking"}, []string{"Productivity", "Notes"}},
	{[]string{"task management", "to-do list", "todo"}, []string{"Productivity", "Task Management"}},
	{[]string{"project management", "kanban"}, []string{"Productivity", "Project Management"}},
	{[]string{"office suite", "word processor", "spreadsheet"}, []string{"Productivity", "Office Suite"}},
	{[]string{"pdf reader", "pdf viewer"}, []string{"Productivity", "PDF Reader"}},
	{[]string{"source-code editor", "code editor", "text editor for code"}, []string{"Developer Tool", "Editor"}},
	{[]string{"integrated development environment", "ide"}, []string{"Developer Tool", "IDE"}},
	{[]string{"api client", "api testing"}, []string{"Developer Tool", "API Client"}},
	{[]string{"git", "version control"}, []string{"Developer Tool", "Version Control"}},
	{[]string{"database client", "database manager", "sql client"}, []string{"Developer Tool", "Database Client"}},
	{[]string{"container runtime", "containerization"}, []string{"Developer Tool", "Container Runtime"}},
	{[]string{"javascript runtime"}, []string{"Developer Tool", "Runtime"}},
	{[]string{"file archiver", "archive manager"}, []string{"Utility", "Archive Manager"}},
	{[]string{"ftp client", "sftp client"}, []string{"Utility", "FTP Client"}},
	{[]string{"bittorrent client"}, []string{"Utility", "BitTorrent"}},
	{[]string{"clipboard manager"}, []string{"Utility", "Clipboard"}},
	{[]string{"window manager"}, []string{"Utility", "Window Manager"}},
	{[]string{"application launcher"}, []string{"Utility", "Launcher"}},
	{[]string{"cloud storage", "file hosting"}, []string{"Cloud Storage"}},
	{[]string{"media player"}, []string{"Media Player"}},
	{[]string{"music streaming"}, []string{"Media", "Music Streaming"}},
	{[]string{"video editor", "video editing"}, []string{"Media", "Video Editor"}},
	{[]string{"audio editor", "digital audio workstation"}, []string{"Media", "Audio Editor"}},
	{[]string{"streaming software", "broadcast software"}, []string{"Media", "Streaming"}},
	{[]string{"video transcoder", "video converter"}, []string{"Media", "Video Encoder"}},
	{[]string{"vector graphics", "vector editor"}, []string{"Design", "Vector Editor"}},
	{[]string{"raster graphics", "image editor", "image editing"}, []string{"Design", "Image Editor"}},
	{[]string{"3d modeling", "3d modelling", "3d graphics"}, []string{"Design", "3D Modeling"}},
	{[]string{"interface design", "ui design", "ux design"}, []string{"Design", "UI Design"}},
	{[]string{"digital painting"}, []string{"Design", "Image Editor"}},
	{[]string{"cryptocurrency wallet", "crypto wallet"}, []string{"Crypto", "Wallet"}},
	{[]string{"digital wallet"}, []string{"Crypto", "Wallet"}},
}

// isWordRune is python re's Unicode \w: alphanumeric or underscore.
func isWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r)
}

// keywordMatch is _keyword_match: `\b` + escape(keyword) + `\b` with python's
// Unicode boundaries. Every keyword starts and ends with a word character, so
// \b reduces to "no word rune immediately before/after".
func keywordMatch(keyword, text string) bool {
	for off := 0; off <= len(text)-len(keyword); {
		i := strings.Index(text[off:], keyword)
		if i < 0 {
			return false
		}
		start, end := off+i, off+i+len(keyword)
		before, _ := utf8.DecodeLastRuneInString(text[:start])
		after, _ := utf8.DecodeRuneInString(text[end:])
		if (start == 0 || !isWordRune(before)) && (end == len(text) || !isWordRune(after)) {
			return true
		}
		off = start + 1
	}
	return false
}

// InferCategoriesFromDescription is infer_categories_from_description: maps a
// Wikipedia description/extract onto the category taxonomy; ["Application"]
// when nothing matches.
func InferCategoriesFromDescription(description, extract string) []string {
	var parts []string
	for _, s := range []string{description, extract} {
		if s != "" {
			parts = append(parts, s)
		}
	}
	text := strings.ToLower(strings.Join(parts, " "))
	if text == "" {
		return []string{"Application"}
	}
	var matched []string
	for _, kc := range keywordToCategory {
		for _, k := range kc.keywords {
			if keywordMatch(k, text) {
				for _, c := range kc.cats {
					if !contains(matched, c) {
						matched = append(matched, c)
					}
				}
				break
			}
		}
	}
	if len(matched) == 0 {
		return []string{"Application"}
	}
	return matched
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// abbreviations is _ABBREVIATIONS: a period after these does not end a
// sentence. Company suffixes are deliberately absent.
var abbreviations = map[string]struct{}{
	"jr": {}, "sr": {}, "st": {}, "dr": {}, "mr": {}, "mrs": {}, "ms": {}, "vs": {}, "etc": {},
	"no": {}, "approx": {}, "e.g": {}, "i.e": {}, "u.s": {}, "u.k": {},
}

// firstSentence is _first_sentence(text, limit=300). Python split on
// `\.(?=\s+[A-Z0-9"'(])`; after whitespace collapsing the lookahead is
// exactly "a single space then one of those characters", checked by hand.
func firstSentence(text string, limit int) string {
	text = strings.Join(strings.FieldsFunc(text, unicode.IsSpace), " ")
	for i := 0; i+2 < len(text); i++ {
		if text[i] != '.' || text[i+1] != ' ' || !strings.ContainsRune(`ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"'(`, rune(text[i+2])) {
			continue
		}
		// Trailing [\w.]+ before the period (python `([\w.]+)$`).
		j := i
		for j > 0 {
			r, n := utf8.DecodeLastRuneInString(text[:j])
			if r != '.' && !isWordRune(r) {
				break
			}
			j -= n
		}
		token := strings.ToLower(text[j:i])
		if _, ok := abbreviations[token]; ok || utf8.RuneCountInString(token) == 1 {
			continue
		}
		return text[:i+1]
	}
	if r := []rune(text); len(r) > limit {
		return string(r[:limit])
	}
	return text
}

// quoteTitle is requests.utils.quote(s, safe=""): percent-encode every UTF-8
// byte except ASCII alphanumerics and "_.-~".
func quoteTitle(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x80 && (c == '_' || c == '.' || c == '-' || c == '~' ||
			('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9')) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// pyStrip is python str.strip() (Unicode whitespace).
func pyStrip(s string) string { return strings.TrimFunc(s, unicode.IsSpace) }

// newHTTPClient: python passed timeout=10 per request (connect/read); Go's
// Timeout bounds the whole request, which is stricter but equivalent in
// practice for a small JSON summary.
func newHTTPClient() *http.Client { return &http.Client{Timeout: 10 * time.Second} }

// wikiURL is overridable by tests only.
var wikiURL = WikipediaRESTURL

// getSoftwareInfo is get_software_info: catalog -> Wikipedia REST. On hit
// returns (categories, description); description "" stands for python None.
func getSoftwareInfo(ctx context.Context, name string, client *http.Client) (result, []string, string) {
	// Stage 1: local catalog.
	if cats, desc, ok := catalog.Lookup(name); ok {
		return resultHit, cats, desc
	}
	// Stage 2: Wikipedia REST API.
	u := fmt.Sprintf(wikiURL, quoteTitle(pyStrip(name)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		slog.Warn("wikipedia unexpected error", "name", name, "err", err)
		return resultTransient, nil, ""
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("wikipedia transient error", "name", name, "err", err)
		return resultTransient, nil, ""
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return resultMiss, nil, "" // not in Wikipedia: definite miss
	case resp.StatusCode == http.StatusTooManyRequests:
		wait := retryAfterSeconds(resp.Header.Get("Retry-After"))
		slog.Warn(fmt.Sprintf("rate limited by wikipedia; waiting %ds", wait))
		// Capped wait; unlike python it also ends on ctx cancellation.
		sleepCtx(ctx, time.Duration(wait)*time.Second)
		return resultTransient, nil, ""
	case resp.StatusCode >= 500:
		return resultTransient, nil, ""
	case resp.StatusCode != http.StatusOK:
		return resultMiss, nil, "" // other 4xx won't improve with retry
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil || data == nil {
		// Bad JSON, truncated body, or a non-object payload.
		return resultTransient, nil, ""
	}
	if s, _ := data["type"].(string); s == "disambiguation" {
		return resultMiss, nil, ""
	}
	description, _ := data["description"].(string)
	extract, _ := data["extract"].(string)
	if description == "" && extract == "" {
		return resultMiss, nil, ""
	}
	// Titles are bare package names; reject unrelated articles ("fish" the animal).
	if !softwareHintRE.MatchString(description + " " + extract) {
		return resultMiss, nil, ""
	}
	cats := InferCategoriesFromDescription(description, extract)
	short := description
	if extract != "" {
		short = firstSentence(extract, 300)
	}
	if short == "" {
		short = description
	}
	return resultHit, cats, short
}

// retryAfterSeconds: min(int(h), 120) when h is all digits, else 30.
func retryAfterSeconds(h string) int {
	if h == "" || strings.TrimLeft(h, "0123456789") != "" {
		return 30
	}
	n, err := strconv.Atoi(h)
	if err != nil || n > 120 { // err here is only overflow: python's int is unbounded
		return 120
	}
	return n
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// --- .env handling (categorize_software.load_env / _read_env_int) ---------

// loadEnv is load_env: minimal KEY=VALUE parser with quote handling and
// inline-comment stripping. Missing file -> empty map.
func loadEnv(path string) map[string]string {
	env := map[string]string{}
	f, err := os.Open(path) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		return env
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := pyStrip(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = pyStrip(v)
		if v != "" && (v[0] == '"' || v[0] == '\'') {
			if end := strings.IndexByte(v[1:], v[0]); end != -1 {
				v = v[1 : end+1]
			} else {
				v = v[1:]
			}
		} else {
			v, _, _ = strings.Cut(v, "#")
			v = pyStrip(v)
		}
		env[pyStrip(k)] = v
	}
	return env
}

// dotEnv is the module-level ENV = load_env() (".env" in the working dir).
var dotEnv = sync.OnceValue(func() map[string]string { return loadEnv(".env") })

// envOr is `os.environ.get(k) or ENV.get(k, "")`.
func envOr(k string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return dotEnv()[k]
}

// readEnvInt is _read_env_int.
func readEnvInt(key string, def int) int {
	raw := pyStrip(envOr(key))
	if raw == "" {
		return def
	}
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw = pyStrip(raw[:i])
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		slog.Warn(fmt.Sprintf("env var %s=%q is not a valid int; using default=%d", key, raw, def))
		return def
	}
	return n
}

// FailureCooldownDays is ENRICH_FAILURE_COOLDOWN_DAYS (env or .env, default 7).
var FailureCooldownDays = sync.OnceValue(func() int { return readEnvInt("ENRICH_FAILURE_COOLDOWN_DAYS", 7) })

// DefaultMemgraphURI is categorize_software.MEMGRAPH_URI.
func DefaultMemgraphURI() string {
	if v := envOr("MEMGRAPH_URI"); v != "" {
		return v
	}
	return "bolt://localhost:7687"
}
