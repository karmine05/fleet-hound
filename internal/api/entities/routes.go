// Package entities ports webviz/routes/entities.py, labels.py and search.py
// (host_filters / hostname_utils live in internal/hostfilter). Owner: agent F.
package entities

import (
	"log/slog"
	"net/http"

	"github.com/karmine05/fleet-hound/internal/app"
	"github.com/karmine05/fleet-hound/internal/httpx"
)

// Register mounts this package's routes on mux. Patterns use Go 1.22
// method syntax ("GET /api/x" also serves HEAD, as Flask did). Views that
// had no try/except in python go through httpx.Handle so an escaping
// Memgraph ClientError becomes the Flask 400 body and anything else the 500.
func Register(mux *http.ServeMux, d *app.Deps) {
	h := func(fn httpx.HandlerFunc) http.Handler { return httpx.Handle(d.Debug(), fn) }
	mux.Handle("GET /api/hosts", h(func(w http.ResponseWriter, r *http.Request) error { return getHosts(d, w, r) }))
	mux.Handle("GET /api/users", h(func(w http.ResponseWriter, r *http.Request) error { return getUsers(d, w, r) }))
	mux.Handle("GET /api/software", h(func(w http.ResponseWriter, r *http.Request) error { return getSoftware(d, w, r) }))
	mux.Handle("GET /api/teams", h(func(w http.ResponseWriter, r *http.Request) error { return getTeams(d, w, r) }))
	mux.Handle("GET /api/platforms", h(func(w http.ResponseWriter, r *http.Request) error { return getPlatforms(d, w, r) }))
	mux.Handle("GET /api/relationships", h(func(w http.ResponseWriter, r *http.Request) error { return getRelationships(d, w, r) }))
	mux.HandleFunc("GET /api/labels", func(w http.ResponseWriter, r *http.Request) { getLabels(d, w, r) })
	mux.HandleFunc("GET /api/labels/scope-count", func(w http.ResponseWriter, r *http.Request) { getLabelScopeCount(d, w, r) })
	mux.Handle("GET /api/search", h(func(w http.ResponseWriter, r *http.Request) error { return searchAll(d, w, r) }))
	mux.HandleFunc("GET /api/search/software", searchSoftware)
}

// dbDown is the python `if not driver: return 500` guard. It writes the
// response and returns true when Memgraph is unavailable.
func dbDown(d *app.Deps, w http.ResponseWriter, r *http.Request) bool {
	if d.DB != nil && d.DB.Available(r.Context()) {
		return false
	}
	httpx.Error(w, http.StatusInternalServerError, "Database connection failed")
	return true
}

func logger(d *app.Deps) *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

// truthy is python bool(v) for the scalar/list values Memgraph returns.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
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

// or is python `a or b`.
func or(a, b any) any {
	if truthy(a) {
		return a
	}
	return b
}
