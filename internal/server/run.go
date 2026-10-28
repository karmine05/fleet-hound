package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/karmine05/fleet-hound/internal/config"
	"github.com/karmine05/fleet-hound/internal/graphdb"
)

// Shutdown budgets (gunicorn --graceful-timeout 30; compose stop_grace_period 45s).
const (
	gracefulTimeout   = 30 * time.Second
	workerStopTimeout = 10 * time.Second
)

// Run is `fleethound serve`: the gunicorn + webviz/app.py replacement.
// Fails closed (exit 1) when WEBVIZ_REQUIRE_AUTH=true and no token is set.
// Stops on SIGTERM/SIGINT: drains HTTP, stops workers, closes the driver.
func Run(ctx context.Context, args []string) int {
	cfg := config.LoadWebviz()
	if err := cfg.Validate(); err != nil {
		slog.Error(err.Error())
		return 1
	}
	logPosture(cfg)

	db := graphdb.New(cfg.MemgraphURI, cfg.MemgraphUser, cfg.MemgraphPassword)
	srv := New(cfg, db, slog.Default())

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	addr := net.JoinHostPort(cfg.BindHost, strconv.Itoa(cfg.Port))
	hs := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      RequestTimeout + 10*time.Second, // >= gunicorn --timeout 120
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	errc := make(chan error, 1)
	go func() {
		slog.Info("Starting Fleet Hound Web Dashboard", "addr", addr, "memgraph_uri", cfg.MemgraphURI)
		errc <- hs.ListenAndServe()
	}()

	code := 0
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server failed", "err", err)
			code = 1
		}
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	}

	// Cleanup must run after the signal context is cancelled.
	sctx, cancel := context.WithTimeout(context.Background(), gracefulTimeout)
	defer cancel()
	if err := hs.Shutdown(sctx); err != nil {
		slog.Warn("http shutdown incomplete", "err", err)
	}
	// Cleanup: worker stop and driver close also run after ctx is cancelled.
	wctx, wcancel := context.WithTimeout(context.Background(), workerStopTimeout)
	defer wcancel()
	srv.StopWorkers(wctx)
	db.Close(wctx)
	return code
}

func logPosture(cfg *config.Webviz) {
	if cfg.APIToken == "" {
		if cfg.AllowAnonymousRead {
			slog.Warn("WEBVIZ_API_TOKEN is unset and WEBVIZ_ALLOW_ANONYMOUS_READ=true: " +
				"anyone with network access can read /api/* GETs. POST/PUT/DELETE still " +
				"require a token. Front this with an authenticated reverse proxy in production.")
		} else {
			slog.Warn("WEBVIZ_API_TOKEN is unset. /api/* GET requests are restricted to loopback " +
				"clients. Set WEBVIZ_API_TOKEN for remote access, or " +
				"WEBVIZ_ALLOW_ANONYMOUS_READ=true behind a trusted proxy.")
		}
	}
	if cfg.Insecure && cfg.OODAEnabled {
		slog.Warn("INSECURE=true with OODA_ENABLED=true: the supervisor will talk to " +
			"FLEET_URL with TLS verification DISABLED on every cycle. This is a " +
			"sustained MITM-exposure posture, not a one-shot dev override. Unset " +
			"INSECURE in production and front Fleet with a valid TLS cert.")
	}
}

// Healthcheck is `fleethound healthcheck`: GET
// http://127.0.0.1:$PORT/api/health (5s timeout), exit 0 on HTTP 200 else 1.
// Replaces the python one-liner in the Dockerfile / compose healthcheck.
func Healthcheck(ctx context.Context, args []string) int {
	port := config.Int("PORT", 8080)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	url := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/api/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 1
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return 0
	}
	return 1
}
