// Command fleethound is the single binary that replaces the python entry
// points: webviz (gunicorn webviz.app:app), main.py, clear_db.py,
// categorize_software.py and `python src/extension_intel.py`.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/karmine05/fleet-hound/internal/enrich"
	"github.com/karmine05/fleet-hound/internal/etl"
	"github.com/karmine05/fleet-hound/internal/extintel"
	"github.com/karmine05/fleet-hound/internal/server"
)

const usage = `usage: fleethound <command> [flags]

commands:
  serve        run the web dashboard + background workers
  etl          one ETL pass from Fleet into Memgraph
  clear-db     wipe Memgraph and local runtime state
  categorize   enrich uncategorized software via Wikipedia
  selfcheck    run the extension-intel self-check
  healthcheck  GET /api/health on 127.0.0.1:$PORT; exit 0 when healthy
`

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	// Process entrypoint: the root context lives for the whole command.
	ctx := context.Background()
	cmd, args := os.Args[1], os.Args[2:]
	var code int
	switch cmd {
	case "serve":
		code = server.Run(ctx, args)
	case "etl":
		code = etl.Main(ctx, args)
	case "clear-db":
		code = etl.ClearDBMain(ctx, args)
	case "categorize":
		code = enrich.CategorizeMain(ctx, args)
	case "selfcheck":
		if err := extintel.SelfCheck(); err != nil {
			fmt.Fprintln(os.Stderr, "selfcheck failed:", err)
			code = 1
		} else {
			fmt.Println("extension_intel self-check: OK")
		}
	case "healthcheck":
		code = server.Healthcheck(ctx, args)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		code = 2
	}
	os.Exit(code)
}
