// Package app holds the dependencies the route packages receive. It replaces
// the module-level names the Flask blueprints imported from webviz/app.py
// (driver, logger, DEBUG_ERROR_DETAILS, the worker constants, audit_log,
// load_whitelist, _ensure_*_started, _get_driver/_reset_driver).
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/karmine05/fleet-hound/internal/config"
	"github.com/karmine05/fleet-hound/internal/graphdb"
	"github.com/karmine05/fleet-hound/internal/httpx"
	"github.com/karmine05/fleet-hound/internal/workerutil"
)

// Deps is passed to every route package's Register.
type Deps struct {
	Cfg *config.Webviz // every env-derived setting (python module constants)
	DB  *graphdb.DB    // `driver` / _get_driver() / _reset_driver()
	Log *slog.Logger   // `logger`

	Whitelist *Whitelist // load_whitelist / save_whitelist / WHITELIST_FILE

	// Idempotent worker boot hooks (_ensure_enricher_started,
	// _ensure_ooda_started, _ensure_extension_worker_started). Never nil
	// once the server builds Deps; tests may leave them nil and call
	// EnsureEnricher etc., which tolerate nil.
	StartEnricher        func()
	StartOODA            func()
	StartExtensionWorker func()
}

// Debug is DEBUG_ERROR_DETAILS.
func (d *Deps) Debug() bool { return d.Cfg != nil && d.Cfg.DebugErrorDetails }

// EnsureEnricher calls StartEnricher when set.
func (d *Deps) EnsureEnricher() {
	if d.StartEnricher != nil {
		d.StartEnricher()
	}
}

// EnsureOODA calls StartOODA when set.
func (d *Deps) EnsureOODA() {
	if d.StartOODA != nil {
		d.StartOODA()
	}
}

// EnsureExtensionWorker calls StartExtensionWorker when set.
func (d *Deps) EnsureExtensionWorker() {
	if d.StartExtensionWorker != nil {
		d.StartExtensionWorker()
	}
}

// Audit replaces audit_log(action, details): appends
// "<utc isoformat> - <action> - <details>\n" to Cfg.AuditFile, with \n and \r
// in details escaped as literal "\\n"/"\\r". Failures are logged, not
// returned (python swallowed them too).
func (d *Deps) Audit(action, details string) {
	if d.Cfg == nil {
		return
	}
	if err := AppendAudit(d.Cfg.AuditFile, action, details); err != nil {
		slog.Error("Error writing audit log", "err", err)
	}
}

// PyISO formats t like python datetime.now(timezone.utc).isoformat():
// "2026-10-28T12:34:56.123456+00:00" (microseconds omitted when zero).
func PyISO(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05") + "+00:00"
	}
	return t.Format("2006-01-02T15:04:05.000000") + "+00:00"
}

// AppendAudit is the file-level audit append used by Deps.Audit and by the
// OODA worker's audit entries (same line format).
func AppendAudit(path, action, details string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir audit dir: %w", err)
	}
	safe := strings.NewReplacer("\n", `\n`, "\r", `\r`).Replace(details)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s - %s - %s\n", PyISO(time.Now()), action, safe); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return nil
}

// Whitelist is the authorized-software store (config/whitelist.json, a JSON
// array of strings written with indent=2).
type Whitelist struct {
	Path string
}

// Load replaces load_whitelist(): the raw JSON value's entries, or an empty
// slice when the file is missing or unparseable (logged). A JSON value that
// is not an array yields an empty slice (python returned it as-is and the
// callers iterated it; only arrays are ever written).
func (w *Whitelist) Load() []any {
	data, err := os.ReadFile(w.Path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Error("Error loading whitelist", "err", err)
		}
		return []any{}
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		slog.Error("Error parsing whitelist JSON (corrupted file?)", "err", err)
		return []any{}
	}
	arr, ok := v.([]any)
	if !ok {
		return []any{}
	}
	return arr
}

// Normalized is _normalize_whitelist(load_whitelist()).
func (w *Whitelist) Normalized() []string { return httpx.NormalizeWhitelist(w.Load()) }

// Save replaces save_whitelist(list): atomic write (temp file
// "whitelist.json.<rand>.tmp" in the same dir, fsync, chmod 0600, rename),
// JSON indent=2. Python logged and swallowed failures; Save returns them so
// the caller can log.
func (w *Whitelist) Save(entries []string) error {
	if entries == nil {
		entries = []string{}
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("encode whitelist: %w", err)
	}
	if err := workerutil.AtomicWriteFile(w.Path, data, filepath.Base(w.Path)+"."); err != nil {
		return fmt.Errorf("save whitelist: %w", err)
	}
	return nil
}

// Add replaces the locked read-modify-write in authorize_software: under an
// exclusive flock on "<Path>.lock" it loads + normalizes, appends name when
// absent and saves. Returns whether it was added.
func (w *Whitelist) Add(ctx context.Context, name string) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(w.Path), 0o750); err != nil {
		return false, fmt.Errorf("mkdir whitelist dir: %w", err)
	}
	lf, err := os.OpenFile(w.Path+".lock", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return false, fmt.Errorf("open whitelist lock: %w", err)
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return false, fmt.Errorf("lock whitelist: %w", err)
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN) //nolint:errcheck
	if err := ctx.Err(); err != nil {
		return false, err
	}
	list := w.Normalized()
	for _, e := range list {
		if e == name {
			return false, nil
		}
	}
	if err := w.Save(append(list, name)); err != nil {
		// python save_whitelist logged and swallowed; the route still
		// reported success and audited. Surface it in the log only.
		slog.Error("Error saving whitelist", "err", err)
	}
	return true, nil
}
