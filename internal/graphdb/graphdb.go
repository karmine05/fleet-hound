// Package graphdb wraps the Memgraph Bolt driver. It replaces the
// _get_driver / _reset_driver / _DriverProxy trio in webviz/app.py and the
// per-module GraphDatabase.driver(...) calls in src/ and categorize_software.py.
package graphdb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j/config"
)

// Python _DRIVER_INIT_RETRIES / _DRIVER_INIT_BACKOFF_SEC.
const (
	DefaultInitRetries = 5
	DefaultInitBackoff = 2 * time.Second
)

// ErrUnavailable mirrors the python ServiceUnavailable("Memgraph driver is not
// connected") raised by _DriverProxy.session when no driver could be built.
var ErrUnavailable = errors.New("memgraph driver is not connected")

// Runner is the minimal query surface. *DB implements it; packages that only
// need to read take a Runner so tests can pass a fake.
type Runner interface {
	// Query runs cypher in an auto-commit transaction and returns every
	// record converted with Data (python [r.data() for r in session.run(...)]).
	Query(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error)
}

// DB is a lazily connected, resettable driver handle, safe for concurrent use.
type DB struct {
	uri         string
	user, pass  string
	log         *slog.Logger
	initRetries int
	initBackoff time.Duration

	mu     sync.Mutex
	driver neo4j.DriverWithContext
}

// Option customises New.
type Option func(*DB)

// WithInitRetry overrides the connect retry budget (python 5 x 2s).
func WithInitRetry(attempts int, backoff time.Duration) Option {
	return func(db *DB) {
		if attempts < 1 {
			attempts = 1
		}
		db.initRetries, db.initBackoff = attempts, backoff
	}
}

// WithLogger sets the logger (default slog.Default()).
func WithLogger(l *slog.Logger) Option { return func(db *DB) { db.log = l } }

// New returns a lazy handle; nothing connects until first use. Empty user or
// password means no auth (python auth=None).
func New(uri, user, password string, opts ...Option) *DB {
	db := &DB{uri: uri, user: user, pass: password, log: slog.Default(),
		initRetries: DefaultInitRetries, initBackoff: DefaultInitBackoff}
	for _, o := range opts {
		o(db)
	}
	return db
}

// URI is the Bolt URI this handle connects to.
func (db *DB) URI() string { return db.uri }

func (db *DB) auth() neo4j.AuthToken {
	if db.user != "" && db.pass != "" {
		return neo4j.BasicAuth(db.user, db.pass, "")
	}
	return neo4j.NoAuth()
}

// Driver replaces _get_driver: returns the connected driver, creating it on
// first use with a bounded retry (initRetries x initBackoff, verified with
// RETURN 1). An auth failure stops retrying immediately. On failure the error
// wraps ErrUnavailable (or is the auth error) and the next call retries.
func (db *DB) Driver(ctx context.Context) (neo4j.DriverWithContext, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.driver != nil {
		return db.driver, nil
	}
	var lastErr error
	for attempt := 1; attempt <= db.initRetries; attempt++ {
		drv, err := neo4j.NewDriverWithContext(db.uri, db.auth(), func(c *config.Config) {
			c.UserAgent = "fleet-hound"
		})
		if err == nil {
			err = probe(ctx, drv)
			if err != nil {
				_ = drv.Close(ctx)
			}
		}
		if err == nil {
			db.log.Info("Connected to Memgraph", "uri", db.uri)
			db.driver = drv
			return drv, nil
		}
		if IsAuthError(err) {
			db.log.Error("Memgraph auth failed", "err", err)
			return nil, fmt.Errorf("memgraph auth: %w", err)
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
		if attempt < db.initRetries {
			db.log.Warn("Memgraph connect attempt failed, retrying",
				"attempt", attempt, "of", db.initRetries, "err", err, "backoff", db.initBackoff)
			select {
			case <-ctx.Done():
			case <-time.After(db.initBackoff):
			}
		}
	}
	db.log.Error("Failed to connect to Memgraph", "attempts", db.initRetries, "err", lastErr)
	return nil, fmt.Errorf("%w: %v", ErrUnavailable, lastErr)
}

func probe(ctx context.Context, drv neo4j.DriverWithContext) error {
	s := drv.NewSession(ctx, neo4j.SessionConfig{})
	defer s.Close(ctx)
	res, err := s.Run(ctx, "RETURN 1", nil)
	if err != nil {
		return err
	}
	_, err = res.Consume(ctx)
	return err
}

// Available replaces `if not driver:` (_DriverProxy.__bool__): it tries to
// connect and reports whether a driver exists.
func (db *DB) Available(ctx context.Context) bool {
	_, err := db.Driver(ctx)
	return err == nil
}

// Reset replaces _reset_driver: closes and drops the cached driver so the
// next call rebuilds it.
func (db *DB) Reset(ctx context.Context) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.driver != nil {
		_ = db.driver.Close(ctx)
		db.driver = nil
	}
}

// Close is Reset under its shutdown name.
func (db *DB) Close(ctx context.Context) { db.Reset(ctx) }

// Session opens a session on the lazily-built driver (python
// driver.session()). Callers must Close it. Escape hatch for code that needs
// explicit transactions or streaming beyond Run/Stream.
func (db *DB) Session(ctx context.Context, cfg neo4j.SessionConfig) (neo4j.SessionWithContext, error) {
	drv, err := db.Driver(ctx)
	if err != nil {
		return nil, err
	}
	return drv.NewSession(ctx, cfg), nil
}

// Run executes cypher as an auto-commit transaction (python session.run) and
// collects the raw records. Raw records keep Node/Relationship/Path values for
// code that needs labels/element ids (traversal.py).
func (db *DB) Run(ctx context.Context, cypher string, params map[string]any) ([]*neo4j.Record, error) {
	var out []*neo4j.Record
	err := db.Stream(ctx, cypher, params, func(r *neo4j.Record) error {
		out = append(out, r)
		return nil
	})
	return out, err
}

// Stream runs cypher auto-commit and calls fn per record without
// materialising the result (snapshot.py _iter_graph). A non-nil error from fn
// stops iteration and is returned.
func (db *DB) Stream(ctx context.Context, cypher string, params map[string]any, fn func(*neo4j.Record) error) error {
	s, err := db.Session(ctx, neo4j.SessionConfig{})
	if err != nil {
		return err
	}
	defer s.Close(ctx)
	res, err := s.Run(ctx, cypher, params)
	if err != nil {
		return err
	}
	for res.Next(ctx) {
		if err := fn(res.Record()); err != nil {
			return err
		}
	}
	return res.Err()
}

// Query implements Runner: Run + Data on every record.
func (db *DB) Query(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
	recs, err := db.Run(ctx, cypher, params)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, len(recs))
	for i, r := range recs {
		out[i] = Data(r)
	}
	return out, nil
}

// Single is python session.run(...).single() followed by .data(): the first
// record's data, or nil when the result is empty.
func (db *DB) Single(ctx context.Context, cypher string, params map[string]any) (map[string]any, error) {
	var first map[string]any
	err := db.Stream(ctx, cypher, params, func(r *neo4j.Record) error {
		if first == nil {
			first = Data(r)
		}
		return nil
	})
	return first, err
}

// Exec is python session.run(...).consume(): run auto-commit, discard rows,
// return the summary.
func (db *DB) Exec(ctx context.Context, cypher string, params map[string]any) (neo4j.ResultSummary, error) {
	s, err := db.Session(ctx, neo4j.SessionConfig{})
	if err != nil {
		return nil, err
	}
	defer s.Close(ctx)
	res, err := s.Run(ctx, cypher, params)
	if err != nil {
		return nil, err
	}
	return res.Consume(ctx)
}

// ExecuteWrite is python session.execute_write(fn): a managed write
// transaction with the driver's built-in retry on transient errors.
func (db *DB) ExecuteWrite(ctx context.Context, fn neo4j.ManagedTransactionWork) (any, error) {
	s, err := db.Session(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	if err != nil {
		return nil, err
	}
	defer s.Close(ctx)
	return s.ExecuteWrite(ctx, fn)
}

// ExecuteRead is python session.execute_read(fn).
func (db *DB) ExecuteRead(ctx context.Context, fn neo4j.ManagedTransactionWork) (any, error) {
	s, err := db.Session(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	if err != nil {
		return nil, err
	}
	defer s.Close(ctx)
	return s.ExecuteRead(ctx, fn)
}
