// Package fleet ports src/auth.py (FleetAuthenticator) and src/extractor.py
// (FleetGraphExtractor).
//
// JSON from Fleet is decoded with graphdb.DecodeJSON (UseNumber ->
// int64/float64) so host/label/team ids stay integers like python.
package fleet

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/karmine05/fleet-hound/internal/graphdb"
)

// ReservedOSLabelNames is RESERVED_OS_LABEL_NAMES (Fleet built-in labels).
var ReservedOSLabelNames = map[string]struct{}{
	"All Hosts": {}, "macOS": {}, "Ubuntu Linux": {}, "CentOS Linux": {}, "MS Windows": {},
	"Red Hat Linux": {}, "All Linux": {}, "chrome": {}, "macOS 14+ (Sonoma+)": {}, "iOS": {},
	"iPadOS": {}, "Fedora Linux": {}, "Android": {},
}

// maxBodyBytes bounds one Fleet response in memory. Python had no cap; a
// 500-host populate_software page is tens of MB, so 1 GiB only stops a
// runaway or hostile server from exhausting the process.
const maxBodyBytes = 1 << 30

// response is the subset of requests.Response the python code used.
type response struct {
	status int
	header http.Header
	body   []byte
}

// jsonObject replaces resp.json() + dict access: ok=false for invalid JSON or
// a non-object payload (python raised ValueError / AttributeError).
func (r *response) jsonObject() (map[string]any, bool) {
	v, err := graphdb.DecodeJSON(r.body)
	if err != nil {
		return nil, false
	}
	m, ok := v.(map[string]any)
	return m, ok
}

// isTLSError matches requests.exceptions.SSLError: certificate or handshake
// failures, which python never retried.
func isTLSError(err error) bool {
	var (
		unknown   x509.UnknownAuthorityError
		hostname  x509.HostnameError
		invalid   x509.CertificateInvalidError
		verify    *tls.CertificateVerificationError
		recordHdr tls.RecordHeaderError
		alert     tls.AlertError
	)
	return errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &invalid) ||
		errors.As(err, &verify) || errors.As(err, &recordHdr) || errors.As(err, &alert)
}

func newHTTPClient(verify bool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone() // keeps proxy-from-env like requests
	if !verify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- opt-in --insecure / INSECURE=true (dev only), python verify=False
	}
	return &http.Client{Transport: tr}
}

// do sends req with requests-style timeouts: the response headers must
// arrive within timeout and the body must then finish within timeout
// (python's (connect, read) timeout is per socket operation, not total).
func do(ctx context.Context, c *http.Client, req *http.Request, timeout time.Duration) (*response, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := time.AfterFunc(timeout, cancel)
	defer timer.Stop()
	resp, err := c.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	timer.Reset(timeout)
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("response body exceeds %d bytes", maxBodyBytes)
	}
	return &response{status: resp.StatusCode, header: resp.Header, body: body}, nil
}

// sleepCtx is time.sleep that returns early (false) when ctx is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func secs(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }

// Authenticator replaces FleetAuthenticator(fleet_url, verify=True, timeout=15).
type Authenticator struct {
	FleetURL   string
	Verify     bool // false = INSECURE (skip TLS verification)
	TimeoutSec int  // default 15
}

// Login replaces login(email, password, debug): the API token, or "" plus an
// error (python returned None and logged).
func (a *Authenticator) Login(ctx context.Context, email, password string, debug bool) (string, error) {
	timeout := a.TimeoutSec
	if timeout <= 0 {
		timeout = 15
	}
	u := strings.TrimRight(a.FleetURL, "/") + "/api/v1/fleet/login"
	payload, err := json.Marshal(map[string]string{"email": email, "password": password})
	if err != nil {
		return "", fmt.Errorf("encode login body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := do(ctx, newHTTPClient(a.Verify), req, time.Duration(timeout)*time.Second)
	if err != nil {
		if debug {
			if isTLSError(err) {
				slog.Error("SSL error; retry with --insecure if using self-signed cert", "err", err)
			} else {
				slog.Warn("request exception", "err", err)
			}
		}
		return "", fmt.Errorf("fleet login: %w", err)
	}
	if debug {
		// Never log the body: a successful login response carries the session token.
		slog.Debug("login", "status", resp.status)
	}
	if resp.status != http.StatusOK {
		return "", fmt.Errorf("fleet login: status %d", resp.status)
	}
	data, ok := resp.jsonObject()
	if !ok {
		if debug {
			slog.Warn("login response was not valid JSON")
		}
		return "", errors.New("fleet login: response was not valid JSON")
	}
	// Common token locations (python `a or b or c`: first non-empty string).
	for _, k := range []string{"token", "access_token", "api_token"} {
		if s, _ := data[k].(string); s != "" {
			return s, nil
		}
	}
	if debug {
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		slog.Warn("token not found in response", "keys", keys)
	}
	return "", errors.New("fleet login: token not found in response")
}

// Extractor replaces FleetGraphExtractor(fleet_url, api_token, verify=True,
// timeout=60, debug=False).
type Extractor struct {
	FleetURL   string
	APIToken   string
	Verify     bool
	TimeoutSec int // default 60
	Debug      bool

	once   sync.Once
	client *http.Client
	// sleep is time.sleep; tests replace it to skip backoff waits.
	sleep func(ctx context.Context, d time.Duration) bool
}

// NewExtractor builds an Extractor with python defaults (timeout 60).
func NewExtractor(fleetURL, apiToken string, verify, debug bool) *Extractor {
	return &Extractor{FleetURL: fleetURL, APIToken: apiToken, Verify: verify, TimeoutSec: 60, Debug: debug}
}

func (e *Extractor) wait(ctx context.Context, d time.Duration) bool {
	if e.sleep != nil {
		return e.sleep(ctx, d)
	}
	return sleepCtx(ctx, d)
}

// get replaces _get(path, retries=5, timeout=None, params=...): GET with
// exponential backoff on 429/5xx and transport errors. nil = python None
// (TLS error, or transport errors on every attempt).
func (e *Extractor) get(ctx context.Context, path string, params url.Values, timeoutSec int) *response {
	const retries = 5
	e.once.Do(func() { e.client = newHTTPClient(e.Verify) })
	if timeoutSec <= 0 {
		timeoutSec = e.TimeoutSec
		if timeoutSec <= 0 {
			timeoutSec = 60
		}
	}
	u := strings.TrimRight(e.FleetURL, "/") + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	var last *response
	for attempt := 0; attempt < retries; attempt++ {
		if ctx.Err() != nil {
			return last
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			slog.Warn("request error", "path", path, "err", err)
			return nil
		}
		req.Header.Set("Authorization", "Bearer "+e.APIToken)
		req.Header.Set("Accept", "application/json")
		resp, err := do(ctx, e.client, req, time.Duration(timeoutSec)*time.Second)
		if err != nil {
			if isTLSError(err) {
				if e.Debug {
					slog.Error("SSL error", "path", path, "err", err)
				}
				return nil
			}
			if e.Debug {
				slog.Warn("request error", "path", path, "err", err)
			}
			if attempt < retries-1 {
				if !e.wait(ctx, secs(math.Min(0.5*math.Pow(2, float64(attempt)), 16))) {
					return nil
				}
				continue
			}
			return nil
		}
		last = resp
		switch resp.status {
		case 429, 500, 502, 503, 504:
			if attempt < retries-1 {
				// 2s, 6s, 18s, 54s (~80s total): Cloudflare 502 windows on
				// slow /hosts pages outlast a sub-10s schedule.
				backoff := math.Min(2.0*math.Pow(3, float64(attempt)), 60)
				ra := resp.header.Get("Retry-After")
				if (resp.status == 429 || resp.status == 503) && isDigits(ra) {
					n, err := strconv.Atoi(ra)
					if err != nil { // overflow: python min(int(ra), 120) caps it
						n = 120
					}
					backoff = math.Max(backoff, math.Min(float64(n), 120))
				}
				if e.Debug {
					slog.Warn("GET retrying", "path", path, "status", resp.status,
						"retrying_in", fmt.Sprintf("%.1fs", backoff), "attempt", fmt.Sprintf("%d/%d", attempt+1, retries))
				}
				if !e.wait(ctx, secs(backoff)) {
					return last
				}
				continue
			}
		}
		if e.Debug {
			slog.Debug("GET", "path", path, "status", resp.status)
		}
		return resp
	}
	return last
}

// isDigits is python str.isdigit() for ASCII (non-empty, all 0-9).
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func pageParams(page, perPage int) url.Values {
	return url.Values{"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(perPage)}}
}

// objects keeps the dict entries of a JSON list (python data.get(key, [])).
func objects(v any) []map[string]any {
	list, _ := v.([]any)
	out := make([]map[string]any, 0, len(list))
	for _, x := range list {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// listLen is len(data.get(key, [])) counting every element, so the
// short-page stop matches python even if Fleet returned a non-object row.
func listLen(v any) int {
	list, _ := v.([]any)
	return len(list)
}

// paginate walks a page/per_page endpoint until a short page; it returns
// the rows collected so far when a page fails (python `break`).
func (e *Extractor) paginate(ctx context.Context, path, key string, perPage int, pause time.Duration) []map[string]any {
	var out []map[string]any
	for page := 0; ; page++ {
		resp := e.get(ctx, path, pageParams(page, perPage), 0)
		if resp == nil || resp.status != http.StatusOK {
			if e.Debug {
				slog.Warn(path+" failed", "status", statusOf(resp))
			}
			return out
		}
		data, ok := resp.jsonObject()
		if !ok {
			if e.Debug {
				slog.Warn("failed to parse " + path + " JSON")
			}
			return out
		}
		out = append(out, objects(data[key])...)
		if listLen(data[key]) < perPage {
			return out
		}
		if pause > 0 && !e.wait(ctx, pause) {
			return out
		}
	}
}

func statusOf(r *response) string {
	if r == nil {
		return "no-resp"
	}
	return strconv.Itoa(r.status)
}

// ExtractAllUsers replaces extract_all_users(): every /api/v1/fleet/users row.
func (e *Extractor) ExtractAllUsers(ctx context.Context) ([]map[string]any, error) {
	users := e.paginate(ctx, "/api/v1/fleet/users", "users", 500, 500*time.Millisecond)
	if err := ctx.Err(); err != nil {
		return users, fmt.Errorf("extract users: %w", err)
	}
	if e.Debug {
		slog.Info("extracted users", "count", len(users))
	}
	return users, nil
}

// ExtractTeams replaces extract_teams() (main.py _list_teams).
func (e *Extractor) ExtractTeams(ctx context.Context) ([]map[string]any, error) {
	teams := e.paginate(ctx, "/api/v1/fleet/teams", "teams", 100, 0)
	if err := ctx.Err(); err != nil {
		return teams, fmt.Errorf("extract teams: %w", err)
	}
	return teams, nil
}

// ExtractHostPages replaces the extract_host_pages generator: yields one page
// (~500 hosts) at a time. A non-nil error ends the sequence (python raised
// mid-iteration, which etl treats as a truncated extract).
// since "" = no global watermark; sinceMap is {team id string: iso}.
//
// Python fetched every team when team_ids was empty. Owner rule: never scan
// all teams by default, so an empty teamIDs yields an error instead.
func (e *Extractor) ExtractHostPages(ctx context.Context, teamIDs []int, since string, sinceMap map[string]string) iter.Seq2[[]map[string]any, error] {
	return func(yield func([]map[string]any, error) bool) {
		if len(teamIDs) == 0 {
			yield(nil, errors.New("Fleet /hosts: no teams selected; refusing to scan every team"))
			return
		}
		for _, teamID := range teamIDs {
			// Effective since: the LATEST of global or team-specific.
			current := since
			if ts := sinceMap[strconv.Itoa(teamID)]; ts != "" && (current == "" || ts > current) {
				current = ts
			}
			if e.Debug {
				mode := "full_scan"
				if current != "" {
					mode = "since=" + current
				}
				slog.Info("fetching hosts", "team", teamID, "mode", mode)
			}
			params := url.Values{
				"per_page":          {"500"},
				"populate_users":    {"True"}, // requests encodes python True as "True"
				"populate_software": {"True"},
				"team_id":           {strconv.Itoa(teamID)},
			}
			// Differential fetch: sort by updated_at desc so filterHosts can
			// stop the pagination walk once it crosses the watermark.
			if current != "" {
				params.Set("order_key", "updated_at")
				params.Set("order_direction", "desc")
			}
			for page := 0; ; page++ {
				params.Set("page", strconv.Itoa(page))
				if e.Debug {
					slog.Debug("fetching hosts", "page", page)
				}
				// populate_software is expensive on big pages; CF upstream tops
				// out near 100s, so give the request 120s.
				resp := e.get(ctx, "/api/v1/fleet/hosts", params, 120)
				if resp == nil || resp.status != http.StatusOK {
					status := statusOf(resp)
					slog.Warn("host page fetch failed; stopping pagination so the ETL watermark is not advanced",
						"team", teamID, "page", page, "status", status)
					yield(nil, fmt.Errorf("Fleet /hosts truncated team=%d page=%d status=%s", teamID, page, status))
					return
				}
				data, ok := resp.jsonObject()
				if !ok {
					slog.Warn("failed to parse hosts JSON; stopping pagination so the ETL watermark is not advanced",
						"team", teamID, "page", page)
					yield(nil, fmt.Errorf("Fleet /hosts returned invalid JSON team=%d page=%d", teamID, page))
					return
				}
				valid, stop := filterHosts(objects(data["hosts"]), current)
				if len(valid) > 0 && !yield(valid, nil) {
					return
				}
				if stop && current != "" {
					if e.Debug {
						slog.Info("differential cutoff reached; stopping", "page", page)
					}
					break
				}
				meta, _ := data["meta"].(map[string]any)
				if more, _ := meta["has_next_results"].(bool); !more {
					break
				}
				// Light pacing between pages to avoid hammering Fleet.
				if !e.wait(ctx, 200*time.Millisecond) {
					yield(nil, fmt.Errorf("Fleet /hosts team=%d: %w", teamID, ctx.Err()))
					return
				}
			}
		}
	}
}

// filterHosts replaces _filter_hosts: keeps hosts updated after since and
// stops at the first older one (pages are sorted updated_at desc).
func filterHosts(hosts []map[string]any, since string) ([]map[string]any, bool) {
	if since == "" {
		return hosts, false
	}
	valid := make([]map[string]any, 0, len(hosts))
	for _, h := range hosts {
		updated, _ := h["updated_at"].(string)
		if updated == "" {
			valid = append(valid, h)
			continue
		}
		if updated > since {
			valid = append(valid, h)
			continue
		}
		return valid, true
	}
	return valid, false
}

// ExtractLabels replaces extract_labels(skip_all_builtins).
func (e *Extractor) ExtractLabels(ctx context.Context, skipAllBuiltins bool) ([]map[string]any, error) {
	labels := e.paginate(ctx, "/api/v1/fleet/labels", "labels", 100, 200*time.Millisecond)
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("extract labels: %w", err)
	}
	out := labels[:0]
	for _, l := range labels {
		if skipAllBuiltins {
			lt, _ := l["label_type"].(string)
			if strings.ToLower(lt) == "builtin" {
				continue
			}
		} else if name, ok := l["name"].(string); ok {
			if _, reserved := ReservedOSLabelNames[name]; reserved {
				continue
			}
		}
		out = append(out, l)
	}
	if e.Debug {
		slog.Info("extracted labels (post-filter)", "count", len(out))
	}
	return out, nil
}

// ExtractLabelHostMembership replaces extract_label_host_membership(id):
// member host rows, or ok=false for python None (fetch failed: keep edges).
func (e *Extractor) ExtractLabelHostMembership(ctx context.Context, labelID int64) (members []map[string]any, ok bool) {
	path := fmt.Sprintf("/api/v1/fleet/labels/%d/hosts", labelID)
	const perPage = 1000
	members = []map[string]any{}
	for page := 0; ; page++ {
		resp := e.get(ctx, path, pageParams(page, perPage), 0)
		if resp == nil || resp.status != http.StatusOK {
			if e.Debug {
				slog.Warn("label hosts fetch failed", "label", labelID, "status", statusOf(resp))
			}
			return nil, false
		}
		data, jok := resp.jsonObject()
		if !jok {
			if e.Debug {
				slog.Warn("failed to parse label hosts JSON", "label", labelID)
			}
			return nil, false
		}
		members = append(members, objects(data["hosts"])...)
		if listLen(data["hosts"]) < perPage {
			return members, true
		}
		if !e.wait(ctx, 200*time.Millisecond) {
			return nil, false
		}
	}
}

// ExtractHostByID replaces extract_host_by_id(id): nil when not fetched.
func (e *Extractor) ExtractHostByID(ctx context.Context, hostID int64) map[string]any {
	resp := e.get(ctx, fmt.Sprintf("/api/v1/fleet/hosts/%d", hostID), nil, 0)
	switch {
	case resp == nil:
		if e.Debug {
			slog.Warn("extract_host_by_id no_response", "host_id", hostID)
		}
		return nil
	case resp.status == http.StatusNotFound:
		if e.Debug {
			slog.Info("extract_host_by_id status=404 (host gone)", "host_id", hostID)
		}
		return nil
	case resp.status != http.StatusOK:
		if e.Debug {
			slog.Warn("extract_host_by_id unexpected_status", "host_id", hostID, "status", resp.status)
		}
		return nil
	}
	data, ok := resp.jsonObject()
	if !ok {
		if e.Debug {
			slog.Warn("extract_host_by_id failed_to_parse_json", "host_id", hostID)
		}
		return nil
	}
	host, ok := data["host"].(map[string]any)
	if !ok {
		if e.Debug {
			slog.Warn("extract_host_by_id unexpected_shape (no 'host' key)", "host_id", hostID)
		}
		return nil
	}
	return host
}
