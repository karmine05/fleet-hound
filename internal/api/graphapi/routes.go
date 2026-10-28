// Package graphapi ports webviz/routes/graph.py, webviz/graph_sample.py,
// webviz/routes/blast_radius.py and webviz/routes/traversal.py. Owner: agent G.
package graphapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/karmine05/fleet-hound/internal/app"
	"github.com/karmine05/fleet-hound/internal/graphdb"
	"github.com/karmine05/fleet-hound/internal/httpx"
)

// Register mounts this package's routes on mux. Patterns use Go 1.22
// method syntax ("GET /api/x" also serves HEAD, as Flask did).
func Register(mux *http.ServeMux, d *app.Deps) {
	h := &handlers{d: d}
	dbg := d.Debug()
	mux.Handle("GET /api/graph", httpx.Handle(dbg, h.graph))
	mux.HandleFunc("GET /api/graph/full", h.graphFull)
	mux.Handle("GET /api/software/{software_name}/hosts", httpx.Handle(dbg, h.softwareHosts))
	mux.Handle("GET /api/host/{hostname}/software", httpx.Handle(dbg, h.hostSoftware))
	mux.Handle("GET /api/blast-radius", httpx.Handle(dbg, h.blastRadius))
	mux.HandleFunc("GET /api/path", h.path)
	mux.HandleFunc("GET /api/correlate", h.correlate)
	mux.Handle("GET /api/snapshots", httpx.Handle(dbg, h.snapshots))
	mux.HandleFunc("GET /api/diff", h.diff)
}

type handlers struct{ d *app.Deps }

func (h *handlers) log() *slog.Logger {
	if h.d.Log != nil {
		return h.d.Log
	}
	return slog.Default()
}

// dbReady is python `if not driver` -> 500 "Database connection failed".
func (h *handlers) dbReady(w http.ResponseWriter, r *http.Request) bool {
	if h.d.DB == nil || !h.d.DB.Available(r.Context()) {
		httpx.Error(w, http.StatusInternalServerError, "Database connection failed")
		return false
	}
	return true
}

// pyFmt renders v like a python f-string placeholder.
func pyFmt(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case int64:
		return strconv.FormatInt(t, 10)
	case int:
		return strconv.Itoa(t)
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1e16 {
			return strconv.FormatFloat(t, 'f', 1, 64)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// truthy is python bool(v) for the value types records carry.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case bool:
		return t
	case int64:
		return t != 0
	case int:
		return t != 0
	case float64:
		return t != 0
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	return true
}

// orStr is f"{v or def}".
func orStr(v any, def string) string {
	if truthy(v) {
		return pyFmt(v)
	}
	return def
}

// orVal is `v or def` keeping the value type (for JSON fields).
func orVal(v, def any) any {
	if truthy(v) {
		return v
	}
	return def
}

func hostDetails(rec map[string]any) string {
	return orStr(rec["os_version"], "") + " (" + orStr(rec["platform"], "") + ")"
}

// withTeam is graph.py _with_team.
func withTeam(node, rec map[string]any) map[string]any {
	if rec["team_id"] != nil {
		node["team_id"] = rec["team_id"]
	}
	if truthy(rec["team_name"]) {
		node["team_name"] = rec["team_name"]
	}
	return node
}

func userNode(rec map[string]any) map[string]any {
	return map[string]any{
		"id":      "user_" + pyFmt(rec["username"]),
		"name":    rec["username"],
		"type":    "user",
		"details": orVal(rec["email"], orVal(rec["fullname"], "")),
	}
}

// pyInt is python int(s) for query-string values: surrounding whitespace
// allowed, optional sign, decimal digits.
func pyInt(s string) (int, error) {
	return strconv.Atoi(strings.TrimSpace(s))
}

// jsonLoads is python json.loads for a query param: a single JSON value,
// numbers normalised like python, trailing data rejected.
func jsonLoads(s string) (any, error) {
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("extra data after JSON value")
	}
	return graphdb.FromJSON(v), nil
}
