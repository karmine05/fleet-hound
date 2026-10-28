// Package workerutil ports webviz/worker_util.py: cross-process plumbing for
// the leader-elected background workers (enrich, extworker, ooda).
//
//   - Leader election: exclusive non-blocking flock on a tmpfs file.
//   - Status: JSON files written atomically (temp file, fsync, rename).
//   - Manual refresh: a trigger file whose mtime advances; the loop polls it
//     while sleeping, and the mtime also enforces a shared cooldown.
package workerutil

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// TriggerPoll is TRIGGER_POLL_SEC.
const TriggerPoll = time.Second

// AtomicWriteJSON replaces atomic_write_json(path, payload, prefix=".worker."):
// compact JSON (separators=(",",":")), temp file in the same dir with the
// given prefix (default ".worker.") and ".tmp" suffix, fsync, chmod 0600,
// rename over path. Returns the error: a status file that silently stops
// updating hides a dead worker. Values json cannot encode fail (python used
// default=str; callers pass strings for such values).
func AtomicWriteJSON(path string, payload any, prefix string) error {
	if prefix == "" {
		prefix = ".worker."
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	data := bytes.TrimRight(buf.Bytes(), "\n")
	return AtomicWriteFile(path, data, prefix)
}

// AtomicWriteFile writes data to path via temp file + fsync + chmod 0600 +
// rename, creating the parent directory if needed.
func AtomicWriteFile(path string, data []byte, prefix string) error {
	parent := filepath.Dir(path)
	_ = os.MkdirAll(parent, 0o750) // CreateTemp below reports the real cause
	f, err := os.CreateTemp(parent, prefix+"*.tmp")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", path, err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("fsync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s: %w", path, err)
	}
	ok = true
	return nil
}

// ReadJSON replaces read_json(path, default): decodes path into v and
// reports success. Missing or malformed files return false and leave v
// untouched; the caller applies its default.
func ReadJSON(path string, v any) bool {
	data, err := os.ReadFile(path) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		return false
	}
	return json.Unmarshal(data, v) == nil
}

// ReadJSONMap is ReadJSON for the common "dict or {}" case: a JSON object
// decodes to its map; anything else (missing, malformed, non-object) is {}.
func ReadJSONMap(path string) map[string]any {
	var m map[string]any
	if !ReadJSON(path, &m) || m == nil {
		return map[string]any{}
	}
	return m
}

// TryAcquireLock replaces try_acquire_lock(lock_path, name): opens/creates
// lockPath (0600), takes LOCK_EX|LOCK_NB, truncates it and writes "<pid>\n".
// Returns the open file holding the lock, or nil when another process holds
// it (or the lock cannot be taken, which is logged). Keep the file open for
// the lifetime of leadership; closing it releases the lock.
func TryAcquireLock(lockPath, name string) *os.File {
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		slog.Warn(name+": cannot open lock file", "path", lockPath, "err", err)
		return nil
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			slog.Warn(name+": lock acquisition failed", "err", err)
		}
		return nil
	}
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	return f
}

// TriggerMtime replaces trigger_mtime: the file's mtime as unix seconds
// (fractional), 0 when it does not exist.
func TriggerMtime(triggerPath string) float64 {
	st, err := os.Stat(triggerPath)
	if err != nil {
		return 0
	}
	return float64(st.ModTime().UnixNano()) / 1e9
}

// SleepUntil replaces sleep_until(deadline, trigger_path=, last_trigger=,
// stop_event=): sleeps until deadline, ctx cancellation (the stop event), or a
// trigger mtime newer than lastTrigger. Returns the trigger mtime to compare
// against next time (lastTrigger when not triggered).
func SleepUntil(ctx context.Context, deadline time.Time, triggerPath string, lastTrigger float64) float64 {
	for ctx.Err() == nil && time.Now().Before(deadline) {
		if m := TriggerMtime(triggerPath); m > lastTrigger {
			return m
		}
		select {
		case <-ctx.Done():
		case <-time.After(TriggerPoll):
		}
	}
	return lastTrigger
}

// FireTrigger replaces fire_trigger(trigger_path, cooldown_sec=, name=):
// touches the trigger file unless its mtime is within cooldownSec. The
// cooldown reads the file's own mtime so every process shares it. Returns
// (fired, retryAfterSec); retryAfterSec is max(1, remaining) when rate
// limited and 0 when fired or when the touch failed (logged).
func FireTrigger(triggerPath string, cooldownSec float64, name string) (bool, float64) {
	now := float64(time.Now().UnixNano()) / 1e9
	last := TriggerMtime(triggerPath)
	if last > 0 && (now-last) < cooldownSec {
		return false, max(1.0, cooldownSec-(now-last))
	}
	_ = os.MkdirAll(filepath.Dir(triggerPath), 0o750)
	if err := touch(triggerPath); err != nil {
		slog.Error(name+": trigger touch failed", "err", err)
		return false, 0
	}
	return true, 0
}

func touch(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	now := time.Now()
	return os.Chtimes(path, now, now)
}

// Handle is what a worker Start returns in place of python's
// (status, stop_event) tuple. Stop cancels the loop; Wait blocks until the
// loop goroutine returns or ctx expires. A zero-value / nil Handle (worker
// disabled or not leader) is valid: Stop and Wait are no-ops.
type Handle struct {
	cancel context.CancelFunc
	done   chan struct{}
	lock   *os.File
	once   sync.Once
}

// Go starts loop in a goroutine bound to a child of parent and returns its
// Handle. lock (may be nil) is the leader lock file, released after the loop
// exits. The loop must return promptly once its ctx is cancelled.
func Go(parent context.Context, lock *os.File, loop func(ctx context.Context)) *Handle {
	ctx, cancel := context.WithCancel(parent)
	h := &Handle{cancel: cancel, done: make(chan struct{}), lock: lock}
	go func() {
		defer close(h.done)
		loop(ctx)
	}()
	return h
}

// Running reports whether this Handle owns a live loop.
func (h *Handle) Running() bool {
	if h == nil || h.done == nil {
		return false
	}
	select {
	case <-h.done:
		return false
	default:
		return true
	}
}

// Stop requests the loop to exit (python stop_event.set()).
func (h *Handle) Stop() {
	if h == nil || h.cancel == nil {
		return
	}
	h.cancel()
}

// Wait blocks until the loop exits or ctx is done, then releases the leader
// lock if the loop exited.
func (h *Handle) Wait(ctx context.Context) error {
	if h == nil || h.done == nil {
		return nil
	}
	select {
	case <-h.done:
		h.once.Do(func() {
			if h.lock != nil {
				_ = h.lock.Close()
			}
		})
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
