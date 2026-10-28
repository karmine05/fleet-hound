// Package config holds the environment helpers shared by every subcommand
// and the webviz server configuration that webviz/app.py read at import time.
package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// StrToBool replaces main.py str_to_bool: true for "true", "1", "yes", "on"
// (case-insensitive). No whitespace trimming, exactly like the Python.
func StrToBool(v string) bool {
	switch strings.ToLower(v) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// Bool replaces webviz/app.py _bool_env: the trimmed, lowercased value is
// true for 1/true/yes/on; unset or empty returns def; anything else is false.
func Bool(name string, def bool) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if raw == "" {
		return def
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// Str returns os.Getenv(name), or def when the variable is unset. Like
// os.environ.get(name, def): a set-but-empty value is returned as "".
func Str(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}

// StrTrim is Str with surrounding whitespace removed (os.environ.get(...).strip()).
func StrTrim(name, def string) string {
	return strings.TrimSpace(Str(name, def))
}

// Int replaces the `try: int(os.environ.get(NAME, "def")) except ValueError: def`
// pattern. Python's int() strips whitespace, so this trims too.
func Int(name string, def int) int {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return def
	}
	return v
}

// Float is Int for float64 (float(os.environ.get(...)) with fallback).
func Float(name string, def float64) float64 {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return def
	}
	return v
}

// ResolveSecret replaces webviz/app.py _resolve_secret: <NAME>_FILE first
// (file content trimmed; used only when non-empty), then <NAME>, trimmed.
// An unreadable *_FILE is logged and falls through to the env var.
func ResolveSecret(name, def string) string {
	fileVar := name + "_FILE"
	if path := strings.TrimSpace(os.Getenv(fileVar)); path != "" {
		data, err := os.ReadFile(path) // #nosec G304 G703 -- path from operator env/config, not request input
		if err != nil {
			slog.Warn("failed to read secret file", "var", fileVar, "path", path, "err", err)
		} else if v := strings.TrimSpace(string(data)); v != "" {
			return v
		}
	}
	return strings.TrimSpace(Str(name, def))
}

// MemgraphAuth returns the Bolt credentials. It replaces the four Python
// copies (webviz/app.py _build_auth, src/ingestion.py / clear_db.py /
// categorize_software.py _memgraph_auth). MEMGRAPH_USER and
// MEMGRAPH_PASSWORD each honour *_FILE (the webviz superset; the ingestion
// copy only honoured MEMGRAPH_PASSWORD_FILE). ok is false unless both are set,
// which means "connect without auth" exactly like the Python None.
func MemgraphAuth() (user, password string, ok bool) {
	user = ResolveSecret("MEMGRAPH_USER", "")
	password = ResolveSecret("MEMGRAPH_PASSWORD", "")
	if user == "" || password == "" {
		return "", "", false
	}
	return user, password, true
}

// ConfigDir is the runtime config directory. The Python hardcoded /app/config
// (container) or <repo>/config. Go reads CONFIG_DIR, defaulting to ./config
// relative to the working directory (WORKDIR /app in Docker -> /app/config).
// The result is absolute when the working directory can be resolved.
func ConfigDir() string {
	dir := StrTrim("CONFIG_DIR", "")
	if dir == "" {
		dir = "config"
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

// ConfigPath joins name onto ConfigDir().
func ConfigPath(name string) string {
	return filepath.Join(ConfigDir(), name)
}

// StateFile is main.py STATE_FILE: env STATE_FILE, default ".state.json"
// relative to the working directory (compose sets /app/config/.state.json).
func StateFile() string {
	return Str("STATE_FILE", ".state.json")
}

// SnapshotDirCLI is main.py SNAPSHOT_DIR: env SNAPSHOT_DIR, default
// "config/snapshots" relative to the working directory.
func SnapshotDirCLI() string {
	return Str("SNAPSHOT_DIR", "config/snapshots")
}
