# Fleet Hound Web Dashboard

Security-analysis UI and API for the Fleet Hound graph: one self-contained page served by the `fleethound serve` Go binary, backed by Memgraph.

The dashboard only ships as a container. There is no supported host-side `fleethound serve` path: the image carries the exact code, env, and read-only filesystem assumptions the app is built for.

## Running it

From the repository root:

```bash
./start.sh                    # memgraph + webviz, waits for health, prints OODA status
open http://127.0.0.1:8080
```

Compose publishes the dashboard on `127.0.0.1:8080` only. To reach it from another machine, put nginx/traefik in front for TLS and keep `WEBVIZ_API_TOKEN` set.

```bash
docker compose logs -f webviz           # app + access log
docker compose ps                      # container health
docker compose up -d --no-deps webviz  # restart the dashboard only
```

The container healthcheck calls `GET /api/health`, which pings Memgraph; a container that reports `unhealthy` means the DB is unreachable, not that the server is down.

## Authentication

`WEBVIZ_REQUIRE_AUTH=true` is baked into the image: the container refuses to start unless `WEBVIZ_API_TOKEN` (or `WEBVIZ_API_TOKEN_FILE`) is set. Send the token as:

```
Authorization: Bearer <token>
```

or

```
X-Api-Token: <token>
```

The UI prompts on first load and stores the token in `localStorage` under `webvizApiToken`; it never appears in a URL. `GET /api/health` and `GET /` stay anonymous so probes and the login screen work.

Generate one with `openssl rand -hex 32`.

## Views

| Tab | What it shows |
|-----|---------------|
| **Overview** (`Command Deck`) | Sampled fleet constellation, headline counts, Shadow IT severity, extension risk, fleet delta, current OODA cycle. First visit opens here; returning operators resume their last tab. |
| **Graph** | Force-directed network: type-coloured nodes, risk halo, degree sizing, zoom/pan, label declutter, selection inspector, Pathfinder. |
| **Blast Radius** | Impact cascade (seed → hosts → identities → platforms) with the four-axis radar behind a `Cascade / Radar` toggle. |
| **Shadow IT** | Severity ring + detection-mix ribbon over the filterable detection table. |
| **Extensions** | Prevalence × risk matrix over the scored extension inventory. |
| **Changes** | Snapshot timeline, delta ribbon, and a filterable node/edge/property diff. |

UI guarantees:

- **Theme** — dark by default, light mode via the topbar toggle; the choice persists before first paint (no flash).
- **Motion** — every transition has a reduced-motion equivalent, and layout/data stay identical.
- **Keyboard** — tabs are a real tablist, graph nodes are focusable and open on Enter/Space, `Esc` clears selection, `+`/`−`/`0` zoom.
- **Truthfulness** — sampled graphs say "sample", stale data is timestamped, and metrics show their denominator (`10 of 32 hosts`).

## Architecture

The server code lives in Go under `internal/`; this directory holds only the static UI.

```text
internal/
├── server/              # HTTP server, auth, security headers, worker lifecycle
├── api/                 # one package per endpoint group (entities, graphapi, shadowit, workersapi)
├── api/graphapi/sample.go  # degree-ranked, type-balanced sampler for the Command Deck
├── enrich/              # Wikipedia categorization (leader-elected, cached)
├── extworker/           # extension metadata + risk scoring (leader-elected, cached)
└── ooda/                # Observe→Orient→Decide→Act supervisor
webviz/
└── static/
    ├── index.html       # markup only
    ├── app.js           # all UI logic (D3 v7); event bindings at the bottom
    ├── app.css          # all styles
    ├── boot.js          # pre-paint theme + boot-error banner (loaded in <head>)
    ├── d3.v7.min.js     # vendored, no CDN
    └── fonts/           # local woff2, no external requests
```

No build step, no bundler, no npm. Edit the files in `static/` and rebuild the image to ship. The server sends `Content-Security-Policy: script-src 'self'`, so never add inline `<script>` or `on*=` attributes: bind events in `app.js` with `addEventListener`.

## API

All routes are under `/api/` and require the token except `/api/health`.

| Route | Notes |
|-------|-------|
| `GET /api/health` | DB ping. Anonymous. |
| `GET /api/meta` | Node/edge counts for the topbar. |
| `GET /api/hosts`, `/users`, `/software`, `/teams`, `/platforms` | Paginated inventories. |
| `GET /api/labels`, `/labels/scope-count` | Fleet label facets and per-label host counts. |
| `GET /api/search?type=…&q=…&limit=…` | Type-scoped search (accepts the same scope params as the views). |
| `GET /api/graph` | Graph payload with team/platform/label filters. |
| `GET /api/graph/full?sample=N` | Full graph, or a `20–300` node sample with `sample`/`total_nodes`/`total_links` in the response. |
| `GET /api/host/<hostname>/software`, `/api/software/<name>/hosts` | Complete neighbourhood for one node. |
| `GET /api/blast-radius?type=user\|software&id=…` | `team` defaults to `all`; response carries `metrics`, `details`, `scores`, and `scope.totals` (hosts/users/teams denominators). |
| `GET /api/path?from=…&to=…` | Shortest path for Pathfinder. |
| `GET /api/shadow-it` | Detections + summary counts; honours `config/whitelist.json`. |
| `POST /api/authorize-software` | Approve/deny a title; takes effect on the next read. |
| `GET /api/extensions` | Scored inventory; filters: `risk`, `store`, `search`, `known_bad`, `include_builtin`. |
| `GET /api/extensions/status`, `POST /api/extensions/refresh`, `GET /api/extensions/detail` | Worker state and per-extension detail. |
| `GET /api/snapshots?limit=N` | Newest-first snapshot metadata (all by default; `limit` caps at 500). |
| `GET /api/diff?from=<ts>&to=<ts>` | Added/removed/changed nodes, edges, and properties. |
| `GET /api/enricher/status`, `POST /api/enricher/trigger` | Wikipedia worker. |
| `GET /api/ooda/status`, `/findings`, `/cycles`, `POST /api/ooda/trigger` | Autonomy supervisor. |

Errors are JSON: `{"error": "...", "message": "..."}` with a 4xx/5xx status. Detail text is only included when `WEBVIZ_DEBUG_ERRORS=true`.

## Configuration

Read from the container environment (supplied by `.env` through Compose):

| Variable | Default | Notes |
|----------|---------|-------|
| `MEMGRAPH_URI` | `bolt://memgraph:7687` | Set by Compose. |
| `MEMGRAPH_USER` / `MEMGRAPH_PASSWORD` | — | Bolt auth; `_FILE` variants supported. |
| `WEBVIZ_API_TOKEN` | — | Required by the production image. |
| `WEBVIZ_REQUIRE_AUTH` | `true` (image) | Refuse to start without a token. |
| `PORT` | `8080` | HTTP listen port. |
| `WEBVIZ_BIND_HOST` | `0.0.0.0` (image) | Listen address; `127.0.0.1` outside the image. |
| `STATE_FILE` | `/app/config/.state.json` | Compose sets it; the rootfs is read-only. |
| `SNAPSHOT_DIR` | `config/snapshots` | Under the `/app/config` mount. |
| `SNAPSHOT_RETAIN_DAYS` / `SNAPSHOT_RETAIN_MAX` | `30` / `5000` | Pruned after each ETL run. |
| `ENRICHER_ENABLED`, `ENRICHER_INTERVAL_SEC`, `ENRICHER_BATCH_SIZE` | `true` / worker defaults | Wikipedia categorization. |
| `EXTENSION_WORKER_ENABLED`, `_INTERVAL_SEC`, `_BATCH_SIZE`, `_PARALLELISM` | `true` / worker defaults | Extension intel. |
| `OODA_ENABLED`, `OODA_INTERVAL_SEC`, `OODA_FULL_SCAN_EVERY` | `false` | Autonomous ETL. |
| `OODA_TEAMS` | *(required)* | Fleet team IDs to scan, comma-separated. ETL and OODA refuse to run without it; `./start.sh` prompts once and saves it. |
| `SHADOW_IT_OUTLIER_PCT` | `0.03` | Rarity threshold per platform. |
| `SHADOW_IT_INCLUDE_LINUX_PACKAGES` | `false` | Opt in to `deb`/`rpm` detections. |

## Performance notes

- `/api/graph/full` without `sample` returns everything; the Overview always asks for a sample (`120` desktop, fewer on phones) so first paint stays cheap.
- Long force simulations are bounded; labels are counter-scaled and decluttered rather than rendered for every node.
- Blast-radius and Shadow IT queries are scoped by team/platform/label before traversal, so the walk never starts from the whole graph.
- Workers are leader-elected with `flock` locks, so two server processes sharing `/app/config` don't double-hit Wikipedia or the extension stores.

## Troubleshooting

```bash
# Is the DB reachable?
docker compose exec -T webviz fleethound healthcheck && echo healthy

# 401 from the API
grep '^WEBVIZ_API_TOKEN=' .env | tail -1

# Blank dashboard / stale data
docker compose logs --tail=100 webviz
docker compose exec -T webviz fleethound etl --full-scan
```

The UI keeps the last successful payload on screen when a refresh fails and shows a stale marker; an empty graph usually means the ETL has not run yet, not that the API is broken.

## Tests

Unit tests are `*_test.go` files next to the code and are **local-only**:
`.gitignore` keeps them out of the repo on purpose. Run them from the repo root:

```bash
go test -race ./...
```

Tests that read a live Memgraph or webviz only run when `FLEETHOUND_LIVE_BOLT`
(and, for the parity checks, `FLEETHOUND_LIVE_WEBVIZ` + `WEBVIZ_API_TOKEN`) are set.
