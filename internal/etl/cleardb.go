package etl

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/karmine05/fleet-hound/internal/config"
	"github.com/karmine05/fleet-hound/internal/graphdb"
)

// clear_db.py defaults, aligned with stop.sh --purge.
const (
	defaultClearStateFile          = ".state.json"
	defaultClearETLLock            = ".etl.lock"
	defaultClearSnapshotDir        = "config/snapshots"
	defaultClearWhitelistFile      = "config/whitelist.json"
	defaultClearContainerStateFile = "config/.state.json"
)

// errAborted is the operator typing anything but DELETE at the prompt.
var errAborted = errors.New("aborted")

// errNeedsYes is the non-interactive refusal (python SystemExit(2)).
var errNeedsYes = errors.New("confirmation required")

// cypherQuerier is the slice of *graphdb.DB clear-db uses (tests fake it).
type cypherQuerier interface {
	Query(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error)
}

func firstNonEmpty(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v := m[k]; v != nil && v != "" {
			return v
		}
	}
	return nil
}

func propList(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, p := range t {
			out = append(out, fmt.Sprint(p))
		}
		return out
	}
	return nil
}

// dropAllConstraints replaces _drop_all_constraints.
func dropAllConstraints(ctx context.Context, db cypherQuerier, out io.Writer) int {
	rows, err := db.Query(ctx, "SHOW CONSTRAINT INFO", nil)
	if err != nil {
		rows = nil
	}
	dropped := 0
	if len(rows) > 0 {
		for _, r := range rows {
			ctype := strings.ToLower(graphdb.AsString(firstNonEmpty(r, "constraint type", "constraint_type", "type")))
			label := graphdb.AsString(firstNonEmpty(r, "label", "Label"))
			props := propList(firstNonEmpty(r, "properties", "property", "Properties"))
			if label == "" || len(props) == 0 {
				continue
			}
			var cypher string
			switch {
			case strings.Contains(ctype, "unique"):
				parts := make([]string, len(props))
				for i, p := range props {
					parts[i] = "n." + p
				}
				cypher = fmt.Sprintf("DROP CONSTRAINT ON (n:%s) ASSERT %s IS UNIQUE;", label, strings.Join(parts, ", "))
			case strings.Contains(ctype, "exist"):
				// Memgraph "exists" constraints are single-property.
				cypher = fmt.Sprintf("DROP CONSTRAINT ON (n:%s) ASSERT EXISTS (n.%s);", label, props[0])
			default:
				continue
			}
			if _, err := db.Query(ctx, cypher, nil); err != nil {
				fmt.Fprintf(out, "⚠️  Failed to drop constraint %q: %v\n", cypher, err)
				continue
			}
			dropped++
		}
		return dropped
	}
	// Fallback: the constraints fleet-hound creates (keep in sync with ingest).
	for _, cypher := range []string{
		"DROP CONSTRAINT ON (u:User) ASSERT u.username IS UNIQUE;",
		"DROP CONSTRAINT ON (h:Host) ASSERT h.hostname IS UNIQUE;", // legacy
		"DROP CONSTRAINT ON (h:Host) ASSERT h.fleet_host_id IS UNIQUE;",
		"DROP CONSTRAINT ON (s:Software) ASSERT s.name IS UNIQUE;",
		"DROP CONSTRAINT ON (l:Label) ASSERT l.fleet_id IS UNIQUE;",
	} {
		if _, err := db.Query(ctx, cypher, nil); err == nil {
			dropped++
		}
	}
	return dropped
}

// dropAllIndexes replaces _drop_all_indexes.
func dropAllIndexes(ctx context.Context, db cypherQuerier, out io.Writer) int {
	rows, err := db.Query(ctx, "SHOW INDEX INFO", nil)
	if err != nil {
		rows = nil
	}
	dropped := 0
	if len(rows) > 0 {
		for _, r := range rows {
			label := graphdb.AsString(firstNonEmpty(r, "label", "Label"))
			if label == "" {
				continue
			}
			// A composite index reports a property list; python formatted the
			// list repr (always failing), Go joins it into valid syntax.
			props := propList(firstNonEmpty(r, "property", "Property"))
			cypher := fmt.Sprintf("DROP INDEX ON :%s;", label)
			if len(props) > 0 {
				cypher = fmt.Sprintf("DROP INDEX ON :%s(%s);", label, strings.Join(props, ", "))
			}
			if _, err := db.Query(ctx, cypher, nil); err != nil {
				fmt.Fprintf(out, "⚠️  Failed to drop index %q: %v\n", cypher, err)
				continue
			}
			dropped++
		}
		return dropped
	}
	for _, cypher := range []string{
		"DROP INDEX ON :Label(name);",
		"DROP INDEX ON :Host(hostname);",
		"DROP INDEX ON :Software(extension_key);",
		"DROP INDEX ON :Software(kind);",
	} {
		if _, err := db.Query(ctx, cypher, nil); err == nil {
			dropped++
		}
	}
	return dropped
}

// confirmClear is the clear_memgraph prompt: nil to proceed.
func confirmClear(in io.Reader, interactive bool, out, errOut io.Writer) error {
	if !interactive {
		fmt.Fprintln(errOut, "Refusing to clear database without confirmation in non-interactive mode. Use --yes to override.")
		return errNeedsYes
	}
	fmt.Fprint(out, "⚠️  This will DELETE ALL DATA in Memgraph AND wipe host-side runtime state. Type DELETE to continue (or anything else to abort): ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	if strings.TrimSpace(line) != "DELETE" {
		fmt.Fprintln(out, "Aborted.")
		return errAborted
	}
	return nil
}

// clearMemgraph replaces the database half of clear_memgraph.
func clearMemgraph(ctx context.Context, db cypherQuerier, uri string, keepSchema bool, out io.Writer) error {
	fmt.Fprintf(out, "Connecting to Memgraph at %s...\n", uri)
	fmt.Fprintln(out, "Clearing all data from Memgraph...")
	// DETACH DELETE removes nodes and their relationships in one pass.
	if _, err := db.Query(ctx, "MATCH (n) DETACH DELETE n", nil); err != nil {
		return fmt.Errorf("clear nodes: %w", err)
	}
	if !keepSchema {
		fmt.Fprintln(out, "Dropping all constraints...")
		fmt.Fprintf(out, "  %d constraint(s) dropped\n", dropAllConstraints(ctx, db, out))
		fmt.Fprintln(out, "Dropping all indexes...")
		fmt.Fprintf(out, "  %d index(es) dropped\n", dropAllIndexes(ctx, db, out))
	} else {
		fmt.Fprintln(out, "Preserving constraints + indexes (--keep-schema)")
	}
	count := func(cypher string) (int64, error) {
		rows, err := db.Query(ctx, cypher, nil)
		if err != nil || len(rows) == 0 {
			return 0, err
		}
		n, _ := graphdb.AsInt64(rows[0]["count"])
		return n, nil
	}
	nodes, err := count("MATCH (n) RETURN count(n) AS count")
	if err != nil {
		return fmt.Errorf("count nodes: %w", err)
	}
	rels, err := count("MATCH ()-[r]->() RETURN count(r) AS count")
	if err != nil {
		return fmt.Errorf("count relationships: %w", err)
	}
	fmt.Fprintf(out, "Database cleared. Remaining nodes: %d, relationships: %d\n", nodes, rels)
	fmt.Fprintln(out, "✅ Memgraph database cleared successfully!")
	return nil
}

// purgePath replaces _purge_path: removes a file or directory tree.
func purgePath(path, label string, out io.Writer) bool {
	if path == "" {
		return false
	}
	if _, err := os.Stat(path); err != nil { // os.path.exists follows symlinks
		return false
	}
	var err error
	if st, lerr := os.Lstat(path); lerr == nil && st.IsDir() {
		err = os.RemoveAll(path)
	} else {
		err = os.Remove(path)
	}
	if err != nil {
		fmt.Fprintf(out, "⚠️  Failed to remove %s (%s): %v\n", label, path, err)
		return false
	}
	fmt.Fprintf(out, "✅ %s (%s) removed\n", label, path)
	return true
}

// purgeHostState replaces purge_host_state.
func purgeHostState(out io.Writer, stateFile, etlLock, snapshotDir, whitelistFile, containerStateFile string) {
	fmt.Fprintln(out, "Wiping host-side runtime state...")
	removed := false
	for _, p := range [][2]string{
		{stateFile, "ETL state"},
		{etlLock, "ETL lock"},
		{snapshotDir, "Snapshot dir"},
		{whitelistFile, "OODA whitelist"},
		{containerStateFile, "Container state"},
	} {
		if purgePath(p[0], p[1], out) {
			removed = true
		}
	}
	if !removed {
		fmt.Fprintln(out, "ℹ️  No host-side state artifacts to remove.")
	}
}

// ClearDBMain is `fleethound clear-db [flags]` (clear_db.py): --memgraph-uri,
// --yes, --state-file, --etl-lock, --snapshot-dir, --whitelist-file,
// --container-state-file, --keep-schema, --keep-files. Returns the exit code.
//
// Differs from python: answering anything but DELETE now also skips the file
// purge (python printed "Aborted." and then wiped the files anyway).
func ClearDBMain(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("fleethound clear-db", flag.ContinueOnError)
	uri := fs.String("memgraph-uri", config.Str("MEMGRAPH_URI", "bolt://localhost:7687"), "Memgraph Bolt URI")
	yes := fs.Bool("yes", false, "Skip interactive confirmation prompt (dangerous).")
	stateFile := fs.String("state-file", defaultClearStateFile, "Path to host-side ETL state file")
	etlLock := fs.String("etl-lock", defaultClearETLLock, "Path to host-side ETL lock file")
	snapshotDir := fs.String("snapshot-dir", defaultClearSnapshotDir, "Path to ETL snapshot directory")
	whitelistFile := fs.String("whitelist-file", defaultClearWhitelistFile, "Path to OODA whitelist file")
	containerState := fs.String("container-state-file", defaultClearContainerStateFile, "Path to container-side state file. Set to empty string to skip.")
	keepSchema := fs.Bool("keep-schema", false, "Drop nodes/edges only; preserve constraints + indexes.")
	keepFiles := fs.Bool("keep-files", false, "Clear Memgraph only; preserve host-side state files.")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "fleethound clear-db: unrecognized arguments: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}

	if !*yes {
		switch err := confirmClear(os.Stdin, isTTY(os.Stdin), os.Stdout, os.Stderr); {
		case errors.Is(err, errNeedsYes):
			return 2
		case errors.Is(err, errAborted):
			return 0
		}
	}

	user, pass, _ := config.MemgraphAuth()
	db := graphdb.New(*uri, user, pass)
	// Cleanup must close the driver even when ctx is already cancelled.
	defer db.Close(context.Background())
	if err := clearMemgraph(ctx, db, *uri, *keepSchema, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "clear-db failed:", err)
		return 1
	}
	if *keepFiles {
		fmt.Println("Preserving host-side state files (--keep-files)")
		return 0
	}
	purgeHostState(os.Stdout, *stateFile, *etlLock, *snapshotDir, *whitelistFile, *containerState)
	return 0
}
