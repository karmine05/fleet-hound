// Package server ports webviz/app.py: the HTTP app (auth middleware,
// security headers, error handlers, /api/meta, /api/health,
// /api/authorize-software, index + static serving), background-worker
// wiring and the process lifecycle that gunicorn used to provide.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/karmine05/fleet-hound/internal/api/entities"
	"github.com/karmine05/fleet-hound/internal/api/graphapi"
	"github.com/karmine05/fleet-hound/internal/api/shadowit"
	"github.com/karmine05/fleet-hound/internal/api/workersapi"
	"github.com/karmine05/fleet-hound/internal/app"
	"github.com/karmine05/fleet-hound/internal/config"
	"github.com/karmine05/fleet-hound/internal/enrich"
	"github.com/karmine05/fleet-hound/internal/extworker"
	"github.com/karmine05/fleet-hound/internal/graphdb"
	"github.com/karmine05/fleet-hound/internal/httpx"
	"github.com/karmine05/fleet-hound/internal/ooda"
	"github.com/karmine05/fleet-hound/internal/workerutil"
)

// RequestTimeout mirrors gunicorn --timeout 120: request contexts are
// cancelled after this long so slow Cypher stops instead of running on.
const RequestTimeout = 120 * time.Second

// CSP is the Content-Security-Policy python set on every response.
const CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; " +
	"object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

// publicPaths is PUBLIC_PATHS.
var publicPaths = map[string]bool{"/api/health": true, "/": true}

// Server is the webviz app. Build with New; serve Handler().
type Server struct {
	cfg  *config.Webviz
	db   *graphdb.DB
	log  *slog.Logger
	deps *app.Deps
	mux  *http.ServeMux

	tokenSum [32]byte // sha256(WEBVIZ_API_TOKEN), compared in constant time

	// workerCtx parents every background worker; cancelled by StopWorkers.
	workerCtx    context.Context
	workerCancel context.CancelFunc

	enricherOnce, oodaOnce, extOnce sync.Once
	handlesMu                       sync.Mutex
	handles                         []*workerutil.Handle
}

// New builds the app. cfg must already be validated (cfg.Validate()).
// Workers are not started until the first healthy /api/health or the first
// request to a route that calls Deps.Ensure*.
func New(cfg *config.Webviz, db *graphdb.DB, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{cfg: cfg, db: db, log: log, mux: http.NewServeMux()}
	s.tokenSum = sha256.Sum256([]byte(cfg.APIToken))
	// Background lifecycle root: workers outlive any single request.
	s.workerCtx, s.workerCancel = context.WithCancel(context.Background())
	s.deps = &app.Deps{
		Cfg:                  cfg,
		DB:                   db,
		Log:                  log,
		Whitelist:            &app.Whitelist{Path: cfg.WhitelistFile},
		StartEnricher:        s.ensureEnricherStarted,
		StartOODA:            s.ensureOODAStarted,
		StartExtensionWorker: s.ensureExtensionWorkerStarted,
	}
	s.routes()
	return s
}

// Deps exposes the dependency bundle (tests, cmd).
func (s *Server) Deps() *app.Deps { return s.deps }

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /api/meta", s.handleMeta)
	m.HandleFunc("GET /api/health", s.handleHealth)
	m.Handle("POST /api/authorize-software", httpx.Handle(s.cfg.DebugErrorDetails, s.handleAuthorizeSoftware))
	m.HandleFunc("GET /{$}", s.handleIndex)
	m.HandleFunc("GET /static/{path...}", s.handleStatic)

	entities.Register(m, s.deps)
	graphapi.Register(m, s.deps)
	shadowit.Register(m, s.deps)
	workersapi.Register(m, s.deps)
}

// Handler returns the full middleware chain:
// recover -> access log -> security headers -> auth -> timeout -> router.
func (s *Server) Handler() http.Handler {
	var h http.Handler = http.HandlerFunc(s.route)
	h = withTimeout(h)
	h = s.enforceAuth(h)
	h = securityHeaders(h)
	h = accessLog(h)
	h = s.recoverer(h)
	return h
}

// route dispatches to the mux, turning its plain-text 404/405 into the
// Flask JSON bodies.
func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	if _, pat := s.mux.Handler(r); pat != "" || r.Method == http.MethodConnect {
		s.mux.ServeHTTP(w, r)
		return
	}
	if allowed := s.allowedMethods(r); len(allowed) > 0 {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
		httpx.Error(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if p := r.URL.Path; p != "" && cleanPath(p) != p {
		s.mux.ServeHTTP(w, r) // mux issues the 301 to the cleaned path
		return
	}
	httpx.NotFound(w)
}

func (s *Server) allowedMethods(r *http.Request) []string {
	var out []string
	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		r2 := r.Clone(r.Context())
		r2.Method = m
		if _, pat := s.mux.Handler(r2); pat != "" {
			out = append(out, m)
		}
	}
	if len(out) > 0 && contains(out, "GET") {
		out = append(out, "HEAD")
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, e := range xs {
		if e == x {
			return true
		}
	}
	return false
}

func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	np := path.Clean(p)
	if strings.HasSuffix(p, "/") && np != "/" {
		np += "/"
	}
	return np
}

// stateChanging is _STATE_CHANGING_METHODS.
var stateChanging = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// extractToken replaces _extract_token_from_request: "Authorization:
// Bearer <t>" (case-insensitive scheme) else X-Api-Token, both trimmed.
// Query-string tokens are not accepted (python never did).
func extractToken(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(auth) >= 7 && strings.EqualFold(auth[:7], "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return strings.TrimSpace(r.Header.Get("X-Api-Token"))
}

// enforceAuth replaces the @before_request _enforce_auth hook.
func (s *Server) enforceAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		// Judge the cleaned path too, so "/static/../api/x" cannot dodge
		// the gate (the mux would redirect it, but fail closed anyway).
		cp := cleanPath(p)
		if publicPaths[p] && publicPaths[cp] {
			next.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(p, "/api/") && !strings.HasPrefix(cp, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		if s.cfg.APIToken != "" {
			// Hash both sides so the compare is length-independent.
			sum := sha256.Sum256([]byte(extractToken(r)))
			if subtle.ConstantTimeCompare(sum[:], s.tokenSum[:]) != 1 {
				httpx.Error(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		// No token configured: writes are always denied (CSRF / drive-by).
		if stateChanging[r.Method] {
			httpx.ErrorMsg(w, http.StatusUnauthorized, "Unauthorized",
				"Set WEBVIZ_API_TOKEN to enable state-changing API calls.")
			return
		}
		// Reads: loopback peer AND loopback Host header (DNS-rebinding /
		// local tunnel defence), else explicit anonymous-read opt-in.
		if httpx.IsLoopback(httpx.ClientIP(r)) && httpx.IsLoopbackHost(r.Host) {
			next.ServeHTTP(w, r)
			return
		}
		if s.cfg.AllowAnonymousRead {
			next.ServeHTTP(w, r)
			return
		}
		httpx.ErrorMsg(w, http.StatusUnauthorized, "Unauthorized",
			"Set WEBVIZ_API_TOKEN, or WEBVIZ_ALLOW_ANONYMOUS_READ=true for read-only access.")
	})
}

// securityHeaders replaces @after_request _security_headers. Headers are
// set before the handler runs, so a handler can still override them
// (python used setdefault).
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", CSP)
		next.ServeHTTP(w, r)
	})
}

func withTimeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), RequestTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// recoverer replaces Flask's @errorhandler(500): a panicking handler gets the
// JSON 500 body instead of a dropped connection.
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.Error("Internal error", "path", r.URL.Path, "panic", fmt.Sprint(v))
				httpx.InternalError(w)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (sw *statusWriter) WriteHeader(code int) {
	if sw.status == 0 {
		sw.status = code
	}
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	if sw.status == 0 {
		sw.status = http.StatusOK
	}
	n, err := sw.ResponseWriter.Write(b)
	sw.bytes += n
	return n, err
}

func (sw *statusWriter) Unwrap() http.ResponseWriter { return sw.ResponseWriter }

// accessLog replaces gunicorn --access-logfile -.
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		st := sw.status
		if st == 0 {
			st = http.StatusOK
		}
		slog.Info("access", "remote", httpx.ClientIP(r), "method", r.Method,
			"path", r.URL.Path, "status", st, "bytes", sw.bytes,
			"ms", time.Since(start).Milliseconds(), "ua", r.UserAgent())
	})
}

// ---------------------------------------------------------------------------
// Worker lifecycle (_ensure_*_started). Each runs once per process; a failed
// start is logged and not retried, like python's *_INIT_DONE flags. Leader
// election across processes is the flock inside each worker's Start.
// ---------------------------------------------------------------------------

func (s *Server) track(h *workerutil.Handle) {
	if h == nil {
		return
	}
	s.handlesMu.Lock()
	s.handles = append(s.handles, h)
	s.handlesMu.Unlock()
}

func (s *Server) ensureEnricherStarted() {
	s.enricherOnce.Do(func() {
		h, err := enrich.Start(s.workerCtx, s.db, enrich.Options{
			IntervalSec: s.cfg.EnricherIntervalSec, BatchSize: s.cfg.EnricherBatchSize,
			Parallelism: s.cfg.EnricherParallelism, LockPath: s.cfg.EnricherLockPath,
			TriggerPath: s.cfg.EnricherTriggerPath, StatusPath: s.cfg.EnricherStatusPath,
			Enabled: s.cfg.EnricherEnabled,
		})
		if err != nil {
			s.log.Error("enricher start failed", "err", err)
		}
		s.track(h)
	})
}

func (s *Server) ensureOODAStarted() {
	s.oodaOnce.Do(func() {
		h, err := ooda.Start(s.workerCtx, s.db, ooda.Options{
			IntervalSec: s.cfg.OODAIntervalSec, FullScanEvery: s.cfg.OODAFullScanEvery,
			StatePath: s.cfg.OODAStatePath, SnapshotDir: s.cfg.OODASnapshotDir,
			LockPath: s.cfg.OODALockPath, TriggerPath: s.cfg.OODATriggerPath,
			StatusPath: s.cfg.OODAStatusPath, CyclesPath: s.cfg.OODACyclesPath,
			FindingsPath: s.cfg.OODAFindingsPath, EnricherTriggerPath: s.cfg.EnricherTriggerPath,
			AuditLogPath: s.cfg.AuditFile, ExtensionTriggerPath: s.cfg.ExtensionTriggerForOODA(),
			Enabled: s.cfg.OODAEnabled,
		})
		if err != nil {
			s.log.Error("ooda start failed", "err", err)
		}
		s.track(h)
	})
}

func (s *Server) ensureExtensionWorkerStarted() {
	s.extOnce.Do(func() {
		h, err := extworker.Start(s.workerCtx, s.db, extworker.Options{
			IntervalSec: s.cfg.ExtensionWorkerIntervalSec, BatchSize: s.cfg.ExtensionWorkerBatchSize,
			Parallelism: s.cfg.ExtensionWorkerParallelism, LockPath: s.cfg.ExtensionWorkerLockPath,
			TriggerPath: s.cfg.ExtensionWorkerTriggerPath, StatusPath: s.cfg.ExtensionWorkerStatusPath,
			CacheDir: s.cfg.ExtensionCacheDir, Enabled: s.cfg.ExtensionWorkerEnabled,
		})
		if err != nil {
			s.log.Error("extension worker start failed", "err", err)
		}
		s.track(h)
	})
}

// StopWorkers replaces the atexit _stop_* hooks: signals every worker and
// waits for them until ctx expires.
func (s *Server) StopWorkers(ctx context.Context) {
	s.workerCancel()
	s.handlesMu.Lock()
	hs := append([]*workerutil.Handle(nil), s.handles...)
	s.handlesMu.Unlock()
	for _, h := range hs {
		h.Stop()
	}
	for _, h := range hs {
		if err := h.Wait(ctx); err != nil {
			s.log.Warn("worker did not stop before deadline", "err", err)
		}
	}
}
