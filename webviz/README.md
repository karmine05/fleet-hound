# Fleet Hound Web Dashboard

Security-analysis UI and API for the Fleet Hound graph: one self-contained page served by Flask + Gunicorn, backed by Memgraph.

The dashboard only ships as a container. There is no supported host-side `python webviz/app.py` path — the image carries the exact code, env, and read-only filesystem assumptions the app is built for.

## Running it

From the repository root:

```bash
./start.sh                    # memgraph + webviz, waits for health, prints OODA status
open http://127.0.0.1:8080
```

Compose publishes the dashboard on `127.0.0.1:8080` only. To reach it from another machine, put nginx/traefik in front for TLS and keep `WEBVIZ_API_TOKEN` set.

```bash
docker compose logs -f webviz           # app + gunicorn access log
docker compose ps                      # container health
docker compose up -d --no-deps webviz  # restart the dashboard only
```

The container healthcheck calls `GET /api/health`, which pings Memgraph; a container that reports `unhealthy` means the DB is unreachable, not that gunicorn is down.

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

```text
webviz/
├── app.py               # Flask routes, auth, scope/label filters, blast radius, diff
├── graph_sample.py      # degree-ranked, type-balanced sampler for the Command Deck
├── enrich_worker.py     # Wikidata categorization (leader-elected, cached)
├── extension_worker.py  # extension metadata + risk scoring (leader-elected, cached)
├── ooda_worker.py       # Observe→Orient→Decide→Act supervisor
└── static/
    ├── index.html       # entire UI: markup, CSS, D3 v7 logic
    ├── d3.v7.min.js     # vendored, no CDN
    └── fonts/           # local woff2, no external requests
```

No build step, no bundler, no npm. Editing `static/index.html` is the whole front-end workflow; rebuild the image to ship it.

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
| `GET /api/snapshots?limit=N` | Newest-first snapshot metadata (default 100, cap 500). |
| `GET /api/diff?from=<ts>&to=<ts>` | Added/removed/changed nodes, edges, and properties. |
| `GET /api/enricher/status`, `POST /api/enricher/trigger` | Wikidata worker. |
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
| `PORT` | `8080` | Gunicorn bind port. |
| `STATE_FILE` | `/app/config/.state.json` | Compose sets it; the rootfs is read-only. |
| `SNAPSHOT_DIR` | `config/snapshots` | Under the `/app/config` mount. |
| `SNAPSHOT_RETAIN_DAYS` / `SNAPSHOT_RETAIN_MAX` | `30` / `5000` | Pruned after each ETL run. |
| `ENRICHER_ENABLED`, `ENRICHER_INTERVAL_SEC`, `ENRICHER_BATCH_SIZE` | `true` / worker defaults | Wikidata categorization. |
| `EXTENSION_WORKER_ENABLED`, `_INTERVAL_SEC`, `_BATCH_SIZE`, `_PARALLELISM` | `true` / worker defaults | Extension intel. |
| `OODA_ENABLED`, `OODA_INTERVAL_SEC`, `OODA_FULL_SCAN_EVERY`, `OODA_TEAMS` | `false` | Autonomous ETL. |
| `SHADOW_IT_OUTLIER_PCT` | `0.03` | Rarity threshold per platform. |
| `SHADOW_IT_INCLUDE_LINUX_PACKAGES` | `false` | Opt in to `deb`/`rpm` detections. |

## Performance notes

- `/api/graph/full` without `sample` returns everything; the Overview always asks for a sample (`120` desktop, fewer on phones) so first paint stays cheap.
- Long force simulations are bounded; labels are counter-scaled and decluttered rather than rendered for every node.
- Blast-radius and Shadow IT queries are scoped by team/platform/label before traversal, so the walk never starts from the whole graph.
- Workers are leader-elected with `fcntl` locks, so two gunicorn workers don't double-hit Wikidata or the extension stores.

## Troubleshooting

```bash
# Is the DB reachable?
docker compose exec -T webviz python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/api/health').read())"

# 401 from the API
grep '^WEBVIZ_API_TOKEN=' .env | tail -1

# Blank dashboard / stale data
docker compose logs --tail=100 webviz
docker compose exec -T webviz python main.py --full-scan
```

The UI keeps the last successful payload on screen when a refresh fails and shows a stale marker; an empty graph usually means the ETL has not run yet, not that the API is broken.

## Tests

The pure-function test suite lives in `tests/` and is **local-only** — `.gitignore`
keeps it out of the repo on purpose. Run it from the repo root with a Python that
has the project's dependencies installed:

```bash
python3 -m unittest discover -s tests -v
```

It covers the graph sampler, ingest identity/version handling, ETL cadence, and
the Shadow IT eligibility gate. No Flask app import and no Memgraph required.
