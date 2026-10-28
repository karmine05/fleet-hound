// Package httpx holds the request/response helpers that webviz/app.py
// exported to the route blueprints: jsonify, error bodies, _bounded_limit,
// _validate_user_regex, the whitelist Cypher clause, _word_match, and the
// loopback / client-IP checks used by auth.
package httpx

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/karmine05/fleet-hound/internal/graphdb"
)

// WriteJSON replaces `jsonify(v), status`: Content-Type application/json,
// compact body plus trailing newline (Flask adds one). Map keys are sorted
// (Flask sort_keys=True; encoding/json sorts maps). HTML characters are not
// escaped, matching python json.dumps.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		slog.Error("json encode failed", "err", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("{\"error\":\"Internal server error\"}\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// NoContent replaces `return ("", 204)`.
func NoContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

// Error writes {"error": msg} with status.
func Error(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]any{"error": msg})
}

// ErrorMsg writes {"error": msg, "message": message} with status.
func ErrorMsg(w http.ResponseWriter, status int, msg string, message any) {
	WriteJSON(w, status, map[string]any{"error": msg, "message": message})
}

// DebugMsg returns err.Error() when debug is on, else nil (python
// `str(exc) if DEBUG_ERROR_DETAILS else None`).
func DebugMsg(debug bool, err error) any {
	if debug && err != nil {
		return err.Error()
	}
	return nil
}

// DebugMsgOr is DebugMsg with a fallback string instead of nil
// (`str(exc) if DEBUG_ERROR_DETAILS else "internal error"`).
func DebugMsgOr(debug bool, err error, fallback string) string {
	if debug && err != nil {
		return err.Error()
	}
	return fallback
}

// NotFound writes the Flask 404 handler body: {"error": "Not found"}.
func NotFound(w http.ResponseWriter) { Error(w, http.StatusNotFound, "Not found") }

// InternalError writes the Flask 500 handler body.
func InternalError(w http.ResponseWriter) {
	Error(w, http.StatusInternalServerError, "Internal server error")
}

// DatabaseError writes the Flask ClientError handler body (400):
// {"error":"Database error","code":"BAD_REQUEST","message": str(err) | "invalid query"}.
func DatabaseError(w http.ResponseWriter, err error, debug bool) {
	slog.Error("Database error", "err", err)
	msg := "invalid query"
	if debug && err != nil {
		msg = err.Error()
	}
	WriteJSON(w, http.StatusBadRequest, map[string]any{
		"error": "Database error", "code": "BAD_REQUEST", "message": msg,
	})
}

// HandlerFunc is a handler that may return an error, mirroring a Flask view
// that lets an exception escape. Use with Handle.
type HandlerFunc func(w http.ResponseWriter, r *http.Request) error

// Handle adapts h to http.Handler. A returned error that is a Memgraph
// ClientError becomes the 400 DatabaseError body; any other error becomes the
// 500 InternalError body (Flask @errorhandler(ClientError) / (500)). The error
// is only written when the handler has not already written a response.
func Handle(debug bool, h HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tw := &trackingWriter{ResponseWriter: w}
		err := h(tw, r)
		if err == nil || tw.wrote {
			if err != nil {
				slog.Error("handler error after response started", "path", r.URL.Path, "err", err)
			}
			return
		}
		if graphdb.IsClientError(err) {
			DatabaseError(w, err, debug)
			return
		}
		slog.Error("Internal error", "path", r.URL.Path, "err", err)
		InternalError(w)
	})
}

type trackingWriter struct {
	http.ResponseWriter
	wrote bool
}

func (t *trackingWriter) WriteHeader(code int) {
	t.wrote = true
	t.ResponseWriter.WriteHeader(code)
}

func (t *trackingWriter) Write(b []byte) (int, error) {
	t.wrote = true
	return t.ResponseWriter.Write(b)
}

func (t *trackingWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }

// DecodeJSONBody replaces request.get_json(silent=True): returns the decoded
// value (numbers normalised with graphdb.FromJSON, like python json) or nil
// when the Content-Type is not JSON (application/json or application/*+json,
// as Flask checks), the body is empty, or it does not parse. The body is
// capped at maxBytes (<=0 means 1 MiB). Callers apply `or {}` and the
// isinstance(dict) check themselves.
func DecodeJSONBody(r *http.Request, maxBytes int64) any {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	if r.Body == nil || !IsJSONContentType(r.Header.Get("Content-Type")) {
		return nil
	}
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBytes))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	return graphdb.FromJSON(v)
}

// IsJSONContentType is werkzeug's Request.is_json mimetype test.
func IsJSONContentType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "application/json" || (strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+json"))
}

// Arg is request.args.get(name) with a default when the key is absent. A
// present-but-empty value returns "" (like the werkzeug MultiDict).
func Arg(r *http.Request, name, def string) string {
	q := r.URL.Query()
	if vs, ok := q[name]; ok && len(vs) > 0 {
		return vs[0]
	}
	return def
}

// ArgInt is `int(request.args.get(name, def))` falling back to def on a
// missing or non-integer value (python int() strips whitespace).
func ArgInt(r *http.Request, name string, def int) int {
	raw, ok := r.URL.Query()[name]
	if !ok || len(raw) == 0 {
		return def
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw[0]))
	if err != nil {
		return def
	}
	return v
}

// ArgBool is the `str(value or "").strip().lower() in ("1","true","yes","on")`
// pattern used for boolean query flags.
func ArgBool(r *http.Request, name string) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// Clamp returns v limited to [lo, hi].
func Clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// BoundedLimit replaces _bounded_limit(default=5000, hard_cap=20000):
// ?limit= parsed as int (default on failure), clamped to [1, hardCap].
func BoundedLimit(r *http.Request, def, hardCap int) int {
	return Clamp(ArgInt(r, "limit", def), 1, hardCap)
}
