package server

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/karmine05/fleet-hound/internal/graphdb"
	"github.com/karmine05/fleet-hound/internal/httpx"
)

// handleMeta replaces get_meta (/api/meta). Never fails: DB problems yield
// 200 with connected=false.
func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	zero := func(connected bool) map[string]any {
		return map[string]any{"hosts": 0, "users": 0, "software": 0, "connected": connected}
	}
	if !s.db.Available(r.Context()) {
		httpx.WriteJSON(w, http.StatusOK, zero(false))
		return
	}
	row, err := s.db.Single(r.Context(), `
                MATCH (h:Host) WITH count(h) AS hosts
                OPTIONAL MATCH (u:User)-[:USES]->(:Host) WITH hosts, count(DISTINCT u) AS users
                OPTIONAL MATCH (s:Software)-[:INSTALLED_ON]->(:Host)
                RETURN hosts, users, count(DISTINCT s) AS software
            `, nil)
	if err != nil {
		s.log.Warn("meta query failed", "err", err)
		httpx.WriteJSON(w, http.StatusOK, zero(false))
		return
	}
	if row == nil {
		httpx.WriteJSON(w, http.StatusOK, zero(true))
		return
	}
	n := func(k string) int64 { v, _ := graphdb.AsInt64(row[k]); return v }
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"hosts": n("hosts"), "users": n("users"), "software": n("software"), "connected": true,
	})
}

// handleHealth replaces health_check (/api/health). A healthy probe also
// boots the background workers (python's autonomy bootstrap).
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !s.db.Available(r.Context()) {
		httpx.WriteJSON(w, http.StatusServiceUnavailable,
			map[string]any{"status": "unhealthy", "database": "disconnected"})
		return
	}
	if _, err := s.db.Single(r.Context(), "RETURN 1", nil); err != nil {
		s.log.Error("Health check failed", "err", err)
		payload := map[string]any{"status": "unhealthy", "database": "error"}
		if s.cfg.DebugErrorDetails {
			payload["error"] = err.Error()
		}
		httpx.WriteJSON(w, http.StatusServiceUnavailable, payload)
		return
	}
	s.ensureEnricherStarted()
	s.ensureOODAStarted()
	s.ensureExtensionWorkerStarted()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "healthy", "database": "connected"})
}

// handleAuthorizeSoftware replaces authorize_software (POST
// /api/authorize-software).
func (s *Server) handleAuthorizeSoftware(w http.ResponseWriter, r *http.Request) error {
	body := httpx.DecodeJSONBody(r, 0)
	if body == nil {
		body = map[string]any{}
	}
	data, ok := body.(map[string]any)
	if !ok {
		// Python: `get_json(...) or {}` turns falsy JSON ([], 0, "") into {},
		// so only a truthy non-object reaches this branch.
		if isFalsyJSON(body) {
			data = map[string]any{}
		} else {
			httpx.Error(w, http.StatusBadRequest, "Invalid JSON body")
			return nil
		}
	}
	var name string
	switch v := data["software_name"].(type) {
	case nil:
	case string:
		name = v
	case bool:
		if v {
			return s.authorizeError(w, fmt.Errorf("'bool' object has no attribute 'strip'"))
		}
	default:
		if !isFalsyJSON(v) {
			return s.authorizeError(w, fmt.Errorf("software_name is not a string"))
		}
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		httpx.Error(w, http.StatusBadRequest, "Software name required")
		return nil
	}
	if len([]rune(name)) > 500 {
		httpx.ErrorMsg(w, http.StatusBadRequest, "Software name too long",
			"software_name must be <= 500 characters")
		return nil
	}
	added, err := s.deps.Whitelist.Add(r.Context(), name)
	if err != nil {
		return s.authorizeError(w, err)
	}
	if added {
		s.deps.Audit("AUTHORIZE", "Authorized software: "+name)
		s.log.Info("Authorized software: " + name)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "message": name + " authorized"})
	return nil
}

func (s *Server) authorizeError(w http.ResponseWriter, err error) error {
	s.log.Error("Error authorizing software", "err", err)
	payload := map[string]any{"error": "Internal server error"}
	if s.cfg.DebugErrorDetails {
		payload["details"] = err.Error()
	}
	httpx.WriteJSON(w, http.StatusInternalServerError, payload)
	return nil
}

func isFalsyJSON(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case bool:
		return !t
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	case int64:
		return t == 0
	case float64:
		return t == 0
	}
	return false
}

// handleIndex replaces index(): static/index.html with no-store headers.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "0")
	s.serveFile(w, r, "index.html", false)
}

// handleStatic replaces Flask's /static/<path:filename> with
// SEND_FILE_MAX_AGE_DEFAULT=0 (revalidate every time via ETag).
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	s.serveFile(w, r, r.PathValue("path"), true)
}

// serveFile serves name from the static dir through an os.Root, so ".." and
// symlinks cannot escape it. Directories and missing files are JSON 404s.
func (s *Server) serveFile(w http.ResponseWriter, r *http.Request, name string, revalidate bool) {
	if name == "" || !fs.ValidPath(name) {
		httpx.NotFound(w)
		return
	}
	root, err := os.OpenRoot(s.cfg.StaticDir)
	if err != nil {
		s.log.Error("static dir unavailable", "dir", s.cfg.StaticDir, "err", err)
		httpx.NotFound(w)
		return
	}
	defer root.Close()
	f, err := root.Open(name)
	if err != nil {
		httpx.NotFound(w)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		httpx.NotFound(w)
		return
	}
	h := w.Header()
	base := path.Base(name)
	if strings.HasSuffix(base, ".js") {
		h.Set("Content-Type", "application/javascript; charset=utf-8")
	}
	h.Set("Content-Disposition", "inline; filename="+base)
	h.Set("ETag", fmt.Sprintf(`"%d-%d"`, st.ModTime().UnixNano(), st.Size()))
	if revalidate {
		h.Set("Cache-Control", "no-cache, max-age=0")
		h.Set("Expires", time.Now().UTC().Format(http.TimeFormat))
	}
	http.ServeContent(w, r, base, st.ModTime(), f)
}
