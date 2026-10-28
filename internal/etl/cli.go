package etl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/karmine05/fleet-hound/internal/config"
	"github.com/karmine05/fleet-hound/internal/fleet"
	"github.com/karmine05/fleet-hound/internal/graphdb"
)

// LoadEnvFile replaces main.py load_env_file: KEY=VALUE lines, # comments,
// one layer of matching single/double quotes stripped. Missing file -> {}.
func LoadEnvFile(path string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(path) // #nosec G304 -- path from operator env/config, not request input
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' && value[len(value)-1] == '"' || value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}
		out[key] = value
	}
	return out
}

// ParseTeamIDs replaces _parse_team_ids: "1,2" -> sorted unique ints.
func ParseTeamIDs(raw string) ([]int, error) {
	seen := map[int]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid team id %q: %w", part, err)
		}
		seen[n] = struct{}{}
	}
	ids := make([]int, 0, len(seen))
	for n := range seen {
		ids = append(ids, n)
	}
	sort.Ints(ids)
	return ids, nil
}

// pyStr renders a JSON value like python str() for the team table.
func pyStr(v any) string {
	if v == nil {
		return "None"
	}
	return fmt.Sprint(v)
}

// PrintTeams replaces _print_teams.
func PrintTeams(w io.Writer, teams []map[string]any) {
	fmt.Fprintln(w, "\nAvailable teams:")
	fmt.Fprintf(w, "   %-8s No team (unassigned hosts)\n", "[0]")
	for _, t := range teams {
		id, ok := t["id"]
		if !ok {
			id = "?"
		}
		name, ok := t["name"]
		if !ok {
			name = "Unknown"
		}
		fmt.Fprintf(w, "%-11s %s\n", "   ["+pyStr(id)+"]", pyStr(name))
	}
}

// interactiveTeamSelect replaces _interactive_team_select: prompts until at
// least one valid team is named. No "all" default. EOF is an error.
func interactiveTeamSelect(in io.Reader, out io.Writer, teams []map[string]any) ([]int, error) {
	valid := map[int]struct{}{0: {}}
	for _, t := range teams {
		if t["id"] == nil {
			continue
		}
		if id, ok := graphdb.AsInt64(t["id"]); ok {
			valid[int(id)] = struct{}{}
		}
	}
	PrintTeams(out, teams)
	r := bufio.NewReader(in)
	for {
		fmt.Fprintln(out, "\nSelect team IDs to scan (comma-separated, e.g. '1,2'):")
		fmt.Fprint(out, "   > ")
		line, err := r.ReadString('\n')
		if err != nil && (line == "" || !errors.Is(err, io.EOF)) {
			return nil, fmt.Errorf("read team selection: %w", err)
		}
		picked, perr := ParseTeamIDs(strings.TrimRight(line, "\r\n"))
		if perr != nil {
			fmt.Fprintln(out, "   team IDs must be integers")
		} else {
			var unknown []int
			for _, id := range picked {
				if _, ok := valid[id]; !ok {
					unknown = append(unknown, id)
				}
			}
			switch {
			case len(picked) == 0:
				fmt.Fprintln(out, "   at least one team is required")
			case len(unknown) > 0:
				fmt.Fprintf(out, "   unknown team IDs: %s\n", pyIntList(unknown))
			default:
				return picked, nil
			}
		}
		if err != nil { // EOF after a rejected last line
			return nil, fmt.Errorf("read team selection: %w", err)
		}
	}
}

// pyIntList renders []int like python str(list): "[1, 2]".
func pyIntList(ids []int) string {
	parts := make([]string, len(ids))
	for i, n := range ids {
		parts[i] = strconv.Itoa(n)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// isTTY is python sys.stdin.isatty(): a termios ioctl, so /dev/null (a
// character device but not a terminal) is correctly non-interactive.
func isTTY(f *os.File) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(ioctlGetTermios), uintptr(unsafe.Pointer(&t)))
	return errno == 0
}

// envLookup is main.py `{**load_env_file('.env'), **os.environ}.get`.
type envLookup map[string]string

func (e envLookup) get(k, def string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	if v, ok := e[k]; ok {
		return v
	}
	return def
}

// secret is get plus <NAME>_FILE from the process env, trimmed on both
// branches (python main.py read only the plain variable, untrimmed).
func (e envLookup) secret(k string) string {
	if p := strings.TrimSpace(os.Getenv(k + "_FILE")); p != "" {
		if data, err := os.ReadFile(p); err != nil { // #nosec G304 G703 -- path from operator env/config, not request input
			slog.Warn("failed to read secret file", "var", k+"_FILE", "err", err)
		} else if v := strings.TrimSpace(string(data)); v != "" {
			return v
		}
	}
	return strings.TrimSpace(e.get(k, ""))
}

// Main is `fleethound etl [flags]` (main.py): flags --fleet-url, --email,
// --api-token, --memgraph-uri, --insecure, --debug-auth, --dump-host-sample,
// --teams, --full-scan, --complete-enrichment, --enrich-software, plus the
// Go-only --list-teams (prints the team table and exits 0; replaces the
// `python -c 'main._list_teams(...)'` call in start.sh). Returns the exit code.
func Main(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("fleethound etl", flag.ContinueOnError)
	fleetURLFlag := fs.String("fleet-url", "", "Fleet server URL (default: from .env)")
	emailFlag := fs.String("email", "", "Fleet user email (default: from .env)")
	tokenFlag := fs.String("api-token", "", "Fleet API token (preferred)")
	memgraphFlag := fs.String("memgraph-uri", "", "Memgraph URI (default: from .env or bolt://localhost:7687)")
	insecureFlag := fs.Bool("insecure", false, "Disable TLS verification (dev only)")
	debugFlag := fs.Bool("debug-auth", false, "Print auth diagnostics")
	dumpFlag := fs.Bool("dump-host-sample", false, "Write first host object to hosts_sample.json then exit")
	teamsFlag := fs.String("teams", "", "Comma-separated Team IDs (e.g. '1,2'). Required unless OODA_TEAMS is set; prompts on a TTY.")
	fullScanFlag := fs.Bool("full-scan", false, "Ignore last run timestamp and refetch everything")
	completeFlag := fs.Bool("complete-enrichment", false, "Enrich ALL uncategorized software (slow)")
	enrichFlag := fs.String("enrich-software", "", "Comma-separated software names to enrich immediately")
	listTeamsFlag := fs.Bool("list-teams", false, "Print the Fleet team table and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "fleethound etl: unrecognized arguments: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}

	// Process environment wins over the file (Docker passes Compose env).
	env := envLookup(LoadEnvFile(".env"))

	or := func(a, b string) string {
		if a != "" {
			return a
		}
		return b
	}
	fleetURL := or(*fleetURLFlag, env.get("FLEET_URL", ""))
	email := or(*emailFlag, env.get("FLEET_EMAIL", ""))
	// No --password flag: a CLI password leaks via `ps` and shell history.
	password := env.secret("FLEET_PASSWORD")
	apiToken := or(strings.TrimSpace(*tokenFlag), env.secret("FLEET_API_TOKEN"))
	memgraphURI := or(*memgraphFlag, env.get("MEMGRAPH_URI", "bolt://localhost:7687"))
	insecure := *insecureFlag || config.StrToBool(env.get("INSECURE", "false"))
	debug := *debugFlag || config.StrToBool(env.get("DEBUG", "false"))

	if fleetURL == "" {
		slog.Error("FLEET_URL is required (set in .env or use --fleet-url)")
		return 1
	}
	if !(apiToken != "" || (email != "" && password != "")) {
		slog.Error("provide FLEET_API_TOKEN (preferred) or FLEET_EMAIL+FLEET_PASSWORD in .env")
		return 1
	}

	// Resolve the Fleet token once: team listing and --dump-host-sample need it.
	token := func() string {
		if apiToken != "" {
			return apiToken
		}
		auth := &fleet.Authenticator{FleetURL: fleetURL, Verify: !insecure, TimeoutSec: 15}
		t, err := auth.Login(ctx, email, password, debug)
		if err != nil {
			return ""
		}
		return t
	}
	listTeams := func(tok string) []map[string]any {
		teams, err := fleet.NewExtractor(fleetURL, tok, !insecure, debug).ExtractTeams(ctx)
		if err != nil {
			slog.Warn("team listing incomplete", "err", err)
		}
		return teams
	}

	if *listTeamsFlag {
		tok := token()
		if tok == "" {
			slog.Error("login failed")
			return 1
		}
		PrintTeams(os.Stdout, listTeams(tok))
		return 0
	}

	// Team scope is mandatory: never fall back to scanning every team.
	teamIDs, err := ParseTeamIDs(or(*teamsFlag, env.get("OODA_TEAMS", "")))
	if err != nil {
		slog.Error("--teams / OODA_TEAMS must be comma-separated integers")
		return 1
	}
	if len(teamIDs) == 0 {
		tok := token()
		if tok == "" {
			slog.Error("login failed")
			return 1
		}
		teams := listTeams(tok)
		if !isTTY(os.Stdin) {
			PrintTeams(os.Stdout, teams)
			slog.Error("no teams selected; pass --teams or set OODA_TEAMS")
			return 1
		}
		if teamIDs, err = interactiveTeamSelect(os.Stdin, os.Stdout, teams); err != nil {
			slog.Error("team selection aborted", "err", err)
			return 1
		}
	}

	// --dump-host-sample bypasses the full ETL: a thin diagnostic.
	if *dumpFlag {
		tok := token()
		if tok == "" {
			slog.Error("login failed")
			return 1
		}
		ext := fleet.NewExtractor(fleetURL, tok, !insecure, debug)
		var first []map[string]any
		for page, err := range ext.ExtractHostPages(ctx, teamIDs, "", map[string]string{}) {
			if err != nil {
				slog.Error("host sample fetch failed", "err", err)
				return 1
			}
			first = page
			break
		}
		if len(first) == 0 {
			slog.Info("no hosts extracted")
			return 0
		}
		// Same directory as the watermark so it stays inside the writable
		// config mount when a container runs this diagnostic.
		samplePath := filepath.Join(filepath.Dir(config.StateFile()), "hosts_sample.json")
		data, err := json.MarshalIndent(first[0], "", "  ")
		if err == nil {
			err = os.WriteFile(samplePath, data, 0o600)
		}
		if err != nil {
			slog.Error("write host sample failed", "path", samplePath, "err", err)
			return 1
		}
		slog.Info("wrote host sample (first host object)", "path", samplePath)
		return 0
	}

	var targetNames []string
	if *enrichFlag != "" {
		for _, n := range strings.Split(*enrichFlag, ",") {
			targetNames = append(targetNames, strings.TrimSpace(n))
		}
	}
	cfg := NewConfig(fleetURL, memgraphURI)
	cfg.APIToken, cfg.Email, cfg.Password = apiToken, email, password
	cfg.Insecure, cfg.Debug = insecure, debug
	cfg.TeamIDs = teamIDs
	cfg.FullScan = *fullScanFlag
	cfg.StatePath = config.StateFile()
	cfg.SnapshotDir = config.SnapshotDirCLI()
	if *completeFlag {
		cfg.EnrichLimit = 0
	}
	cfg.EnrichTargetNames = targetNames
	// The in-container enricher worker already categorizes in the background;
	// inline enrichment only on request.
	cfg.SkipEnrichment = config.StrToBool(env.get("ENRICHER_ENABLED", "false")) && !(*completeFlag || targetNames != nil)

	slog.Info("extracting from Fleet", "url", fleetURL)
	if insecure {
		slog.Warn("TLS verification disabled (dev only)")
	}

	result := Run(ctx, cfg)
	if result.Error != nil {
		slog.Error("ETL failed: " + *result.Error)
		return 1
	}
	slog.Info("hosts extracted", "count", result.HostsExtracted)
	slog.Info("users extracted", "count", result.UsersExtracted)
	if result.EnrichmentError != nil {
		slog.Warn("enrichment: " + *result.EnrichmentError)
	}
	if result.SnapshotPath != nil {
		slog.Info("snapshot", "path", *result.SnapshotPath)
	} else if result.SnapshotError != nil {
		slog.Warn("snapshot: " + *result.SnapshotError)
	}
	slog.Info("duration", "elapsed", fmt.Sprintf("%.1fs", result.DurationSec))
	slog.Info("synced", "teams", pyIntList(result.TeamsSynced))
	slog.Info("dashboard url=http://localhost:8080")
	return 0
}
