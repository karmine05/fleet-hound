package extintel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

const (
	userAgent    = "fleet-hound-extension-intel/1.0 (+https://github.com/)"
	maxHTTPBytes = 8 * 1024 * 1024
)

// Response is python HttpClient's (status, headers, body, error) tuple.
// Status 0 means no HTTP answer; Err "" is python None.
type Response struct {
	Status  int
	Headers map[string]string
	Body    []byte
	Err     string
}

// fakeTransport stands in for the network in the self-check and tests.
type fakeTransport struct {
	get  func(rawURL string, allowed map[string]struct{}, maxBytes int, headers map[string]string) Response
	post func(rawURL string, form url.Values, allowed map[string]struct{}, maxBytes int) Response
}

var sharedTransport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 4
	return t
}()

func (c *HTTPClient) timeout() time.Duration {
	if c == nil || c.TimeoutSec <= 0 {
		return 12 * time.Second
	}
	return time.Duration(c.TimeoutSec * float64(time.Second))
}

// Get is HttpClient.get: GET restricted to allowedHosts (also on every
// redirect), body capped at maxBytes. headers are extra request headers, e.g.
// If-None-Match for a conditional GET. Never fails: errors are in Err.
func (c *HTTPClient) Get(ctx context.Context, rawURL string, allowedHosts map[string]struct{}, maxBytes int, headers map[string]string) Response {
	if c != nil && c.fake != nil {
		if c.fake.get == nil {
			panic("unexpected network GET " + rawURL)
		}
		return c.fake.get(rawURL, allowedHosts, maxBytes, headers)
	}
	return c.do(ctx, http.MethodGet, rawURL, nil, allowedHosts, maxBytes, headers)
}

// Post is HttpClient.post: form url-encoded; same allowlist, redirect guard,
// cap and return shape as Get.
func (c *HTTPClient) Post(ctx context.Context, rawURL string, form url.Values, allowedHosts map[string]struct{}, maxBytes int) Response {
	if c != nil && c.fake != nil {
		if c.fake.post == nil {
			panic("unexpected network POST " + rawURL)
		}
		return c.fake.post(rawURL, form, allowedHosts, maxBytes)
	}
	return c.do(ctx, http.MethodPost, rawURL, []byte(form.Encode()), allowedHosts, maxBytes, nil)
}

func urlHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// idleReader resets the idle timer on progress: python's urllib timeout is
// per socket operation, not a total deadline (a 50 MB CRX may take longer).
type idleReader struct {
	r io.Reader
	t *time.Timer
	d time.Duration
}

func (ir idleReader) Read(p []byte) (int, error) {
	n, err := ir.r.Read(p)
	if n > 0 {
		ir.t.Reset(ir.d)
	}
	return n, err
}

func (c *HTTPClient) do(ctx context.Context, method, rawURL string, body []byte, allowed map[string]struct{}, maxBytes int, extra map[string]string) Response {
	host := urlHost(rawURL)
	if !has(allowed, host) {
		return Response{Err: "host not allowlisted: " + host}
	}
	d := c.timeout()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var timedOut atomic.Bool
	idle := time.AfterFunc(d, func() { timedOut.Store(true); cancel() })
	defer idle.Stop()
	fail := func(err error) Response {
		if timedOut.Load() {
			return Response{Err: "timed out"}
		}
		// Drop the "Get <url>:" and "read tcp <local>-><remote>:" wrappers:
		// intel_error is shown in the UI and must not carry local addresses.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		var oe *net.OpError
		if errors.As(err, &oe) {
			err = oe.Err
		}
		return Response{Err: err.Error()}
	}

	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return fail(err)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	// urllib sends no Accept-Encoding: bodies (and CRX hashes) stay byte-exact.
	req.Header.Set("Accept-Encoding", "identity")
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	}
	client := &http.Client{
		Transport: sharedTransport,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			h := strings.ToLower(r.URL.Hostname())
			if !has(allowed, h) {
				return fmt.Errorf("redirect to non-allowlisted host: %s", h)
			}
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()
	if final := strings.ToLower(resp.Request.URL.Hostname()); !has(allowed, final) {
		return Response{Err: "redirected to non-allowlisted host: " + final}
	}
	data, err := io.ReadAll(io.LimitReader(idleReader{r: resp.Body, t: idle, d: d}, int64(maxBytes)+1))
	if err != nil {
		return fail(err)
	}
	headers := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	// urllib raises HTTPError for non-2xx: status, headers, body, no error.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Response{Status: resp.StatusCode, Headers: headers, Body: data}
	}
	if len(data) > maxBytes {
		return Response{Status: resp.StatusCode, Headers: headers, Body: data[:maxBytes], Err: "response too large"}
	}
	return Response{Status: resp.StatusCode, Headers: headers, Body: data}
}

// header is _header: case-insensitive lookup, stripped.
func header(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return pyStrip(v)
		}
	}
	return ""
}
