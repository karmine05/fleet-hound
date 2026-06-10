<!-- generated-by: gsd-doc-writer -->
# Fleet Hound 🩸🐶
> **High-Performance Infrastructure Graph Analysis & Risk Quantization for Fleet.**

[![Platform: Fleet](https://img.shields.io/badge/Platform-Fleet-blue?style=for-the-badge&logo=fleet)](https://fleetdm.com)
[![Graph: Memgraph](https://img.shields.io/badge/Graph-Memgraph-brightgreen?style=for-the-badge&logo=neo4j)](https://memgraph.com)

Fleet Hound pulls hosts, users, and installed-software inventory from a [Fleet](https://fleetdm.com) MDM/osquery server, builds an `(:User)-[:USES]->(:Host)<-[:INSTALLED_ON]-(:Software)` graph in [Memgraph](https://memgraph.com), enriches software nodes with [Wikidata](https://www.wikidata.org) categories, and serves a Flask dashboard for blast-radius queries, Shadow IT detection, and per-snapshot graph diffs.

![Universal Security Graph](assets/PIC-5.png)

---

## Capabilities

| Capability | What it does | Backed by |
|------------|--------------|-----------|
| **Universal Security Graph** | Models every host, user, and software install as nodes/edges in a Bolt-protocol graph DB. | `src/ingestion.py` → Memgraph (`bolt://localhost:7687`) |
| **Differential ETL** | Tracks `last_run_timestamp` per team in `.state.json`, fetches only `updated_at` deltas on subsequent runs. Use `--full-scan` to override. | `main.py`, `src/etl.py`, `src/extractor.py` |
| **Blast Radius & Path Tracing** | Given a compromised host, user, or piece of software, walks the graph to surface every reachable asset across host reach, user impact, lateral movement, and platform spread. | `GET /api/blast-radius`, `GET /api/path` |
| **Shadow IT Detection** | Flags software a user *deliberately installed* that is rare across the fleet (≤ a per-platform host threshold), high-risk by category, or version-sprawled. Native apps + browser/IDE extensions are in scope; OS plumbing, dev-language deps, subprocess helpers, and (by default) Linux distro packages are filtered out. Whitelist suppresses approved names. | `GET /api/shadow-it`, `src/shadow_it_filter.py`, `categorize_software.py` |
| **Wikidata Enrichment** | Continuous background worker hits Wikidata SPARQL to attach `category` + `description` properties to `Software` nodes. Single-leader across gunicorn workers via fcntl flock. | `webviz/enrich_worker.py`, `categorize_software.py` |
| **Graph Snapshots & Diff** | Streams the full graph to gzipped JSONL per ETL run; UI surfaces node/edge churn between any two snapshots. | `src/snapshot.py`, `GET /api/snapshots`, `GET /api/diff` |
| **Software Authorization Whitelist** | Operators mark software as approved, mutating Shadow IT scoring on the next read. Persisted atomically. | `POST /api/authorize-software` |
| **Autonomous OODA loop** | Optional in-container supervisor that drives Observe→Orient→Decide→Act cycles on a timer. Pulls deltas, kicks enrichment, computes Shadow IT findings, audits each cycle. | `webviz/ooda_worker.py` |

![Blast Radius Analysis](assets/PIC-3.png)
![Cluster Detail](assets/PIC-4.png)

---

## Architecture

```text
                   ┌──────────────────┐
                   │  Fleet server    │  (REST: /api/v1/fleet/*)
                   └────────┬─────────┘
                            │ Bearer token
                            ▼
                   ┌──────────────────┐
                   │  main.py         │  CLI ETL: extract → ingest → snapshot
                   │  (src/etl.py)    │
                   └────────┬─────────┘
                            │ Bolt
                            ▼
                   ┌──────────────────┐    ┌──────────────────┐
                   │   Memgraph       │◀───│ enrich_worker    │  (Wikidata SPARQL)
                   │   :7687 / :7444  │    │ (fcntl-elected)  │
                   └────────┬─────────┘    └──────────────────┘
                            │ Bolt
                            ▼
                   ┌──────────────────┐
                   │   webviz/app.py  │  Flask + Gunicorn (4 workers)
                   │   :8080          │  Bearer-token auth, /api/*
                   └──────────────────┘
```

Two long-lived services run under Docker Compose: `memgraph` (the graph DB) and `webviz` (the Flask dashboard). The `main.py` CLI is invoked manually or on cron from the host to populate the graph. When `OODA_ENABLED=true` the webviz container also runs the ETL itself on a timer — the host CLI becomes optional.

---

## Quick start

**Prerequisites:** Docker, Docker Compose, Python 3.x, and a Fleet API token.

### Getting Started (5 minutes)

**Step 1: Set up the environment**

```bash
# One-time setup
./setup.sh
```

**Step 2: Configure Fleet connection**

```bash
# Copy example env file
cp .env.example .env

# Edit with your Fleet credentials
# Required: FLEET_URL, FLEET_API_TOKEN
$EDITOR .env
```

**Step 3: Start the stack**

```bash
# Boot Memgraph + dashboard
./start.sh
```

**Step 4: Pull your first data**

```bash
# Activate venv if not already done
source venv/bin/activate

# Initial baseline sync
python3 main.py --full-scan
```

**Step 5: Open the dashboard**

```bash
open http://localhost:8080
```

**Optional: Start + sync in one command**

```bash
# Boot stack and immediately run full sync
./start.sh --full-scan
```

---

## Environment variables

**Required:**
- `FLEET_URL` - Your Fleet server URL
- `FLEET_API_TOKEN` - Fleet API bearer token

**Recommended for production:**
- `WEBVIZ_API_TOKEN` - Dashboard API token (generate with `openssl rand -hex 32`)
- `MEMGRAPH_USER` / `MEMGRAPH_PASSWORD` - Database authentication
open http://localhost:8080
```

The dashboard runs on `http://localhost:8080`. Front it with a reverse proxy for TLS + auth in production.

---

## Common operations

### Sync data

```bash
python3 main.py                  # Delta sync (incremental)
python3 main.py --full-scan      # Full resync
python3 main.py --teams 1,2      # Team-scoped sync
```

### Wipe and re-baseline

```bash
python3 clear_db.py --yes        # Clear database + reset state
python3 main.py --full-scan      # Fresh baseline
```

### Check logs

```bash
docker logs fleet-webviz         # Dashboard logs
docker logs fleet-memgraph       # Database logs
```

### Stop the stack

```bash
./stop.sh
```

![Shadow IT Detection](assets/PIC-2.png)

---

## CLI reference (`main.py`)

| Flag | Purpose |
|------|---------|
| `--fleet-url URL` | Fleet base URL. Falls back to `FLEET_URL` in `.env`. |
| `--api-token TOKEN` | Fleet API token (recommended). Falls back to `FLEET_API_TOKEN`. |
| `--email`, `--password` | Legacy email/password login via `POST /api/v1/fleet/login`. |
| `--memgraph-uri URI` | Bolt URI. Default `bolt://localhost:7687`. |
| `--insecure` | Skip TLS verify (self-signed Fleet certs only). |
| `--debug-auth` | Print auth status code + 300-char body snippet for diagnostics. |
| `--teams 1,2,3` | Restrict extraction to specific Fleet team IDs. |
| `--full-scan` | Ignore `.state.json` and re-fetch every host. |
| `--complete-enrichment` | After ingest, enrich **every** uncategorized `Software` node via Wikidata (slow). Default caps at 250 outliers. |
| `--enrich-software "Slack,Zoom"` | Force Wikidata enrichment for specific names. |
| `--dump-host-sample` | Write the first host object to `hosts_sample.json` and exit. |

### Other entry points

```bash
# Run only the Wikidata categorizer (no Fleet pull, no ingest).
python3 categorize_software.py
python3 categorize_software.py --limit 0   # all uncategorized
```

---

## Configuration (`.env`)

| Variable | Required | Notes |
|----------|----------|-------|
| `FLEET_URL` | yes | Base URL of your Fleet server. |
| `FLEET_API_TOKEN` | yes | Bearer token. Alternative: `FLEET_EMAIL` + `FLEET_PASSWORD`. |
| `MEMGRAPH_URI` | no | Default `bolt://localhost:7687`. |
| `MEMGRAPH_USER` / `MEMGRAPH_PASSWORD` | no | Bolt auth. Use `MEMGRAPH_PASSWORD_FILE` for mounted secrets. |
| `WEBVIZ_API_TOKEN` | no | When set, every `/api/*` call must send `Authorization: Bearer <token>` or `X-Api-Token: <token>`. |
| `WEBVIZ_REQUIRE_AUTH` | no | `true` refuses to start unless a token is configured. |
| `WEBVIZ_ALLOW_ANONYMOUS_READ` | no | `true` allows GETs from any client when no token is set (default: loopback only). |
| `PORT` | no | Dashboard listen port. Default `8080`. |
| `DEBUG` | no | `true` to enable extractor + auth diagnostics. |
| `ENRICHER_ENABLED` / `_INTERVAL_SEC` / `_BATCH_SIZE` | no | Wikidata categorizer worker tuning. |
| `OODA_ENABLED` / `_INTERVAL_SEC` / `_FULL_SCAN_EVERY` / `_TEAMS` | no | Autonomous supervisor (see below). |
| `SHADOW_IT_OUTLIER_PCT` | no | Outlier threshold as a fraction of a platform's hosts. Default `0.03` (3%). Software on ≤ `max(2, platform_hosts × pct)` hosts of its platform is flagged. |
| `SHADOW_IT_INCLUDE_LINUX_PACKAGES` | no | `true`/`1`/`yes`/`on` includes Linux distro packages (`deb`/`rpm`) in Shadow IT detection. **Default OFF** — osquery can't distinguish a deliberate `apt install` from a transitive dependency, so the bucket is noisy. |

See `.env.example` for the canonical list and defaults.

---

## Dashboard API surface (selected)

All routes are under `/api/`. With a token configured, send it as `Authorization: Bearer <token>` or `X-Api-Token: <token>`.

| Route | Purpose |
|-------|---------|
| `GET /api/health` | DB ping. Used by Docker healthcheck. |
| `GET /api/meta` | Counts for the topbar pill. |
| `GET /api/blast-radius?type=…&id=…` | Reachability set from a seed node. |
| `GET /api/path?from=…&to=…` | Shortest path between two typed IDs. |
| `GET /api/shadow-it` | Outlier-software ranking with whitelist suppression. |
| `POST /api/authorize-software` | Mark software as approved. |
| `GET /api/snapshots`, `GET /api/diff?a=…&b=…` | Snapshot list and per-property diff. |
| `GET /api/ooda/status`, `/findings`, `/cycles`, `POST /trigger` | OODA supervisor introspection. |
| `GET /api/enricher/status`, `POST /api/enricher/trigger` | Wikidata enricher introspection. |

![Shadow IT Details](assets/PIC-1.png)

### How Shadow IT detection works

Premise: **ubiquitous software is sanctioned; rare software is suspect.** Three detectors run over the graph, all sharing one eligibility gate (`src/shadow_it_filter.py`).

**Eligibility gate** — a candidate must be a *deliberate user install*:
- **In scope:** native apps (`apps`/`programs`/`homebrew_packages`/`chocolatey_packages`) and browser/IDE extensions (`chrome`/`firefox`/`safari`/`ie` extensions, `vscode`/`atom`/`jetbrains` plugins).
- **Filtered out:** OS plumbing (regex over `lib*`, kernel, CUDA, MS runtimes…), dev-language transitive deps (`npm`/`pip`/`gem`/`cargo`/`go_binaries`), subprocess noise (Electron `… Helper (GPU)`, auto-updaters, crash reporters, build/test binaries), junk display names, and — **by default** — Linux distro packages (`deb`/`rpm`; opt in with `SHADOW_IT_INCLUDE_LINUX_PACKAGES=true`).

**Detectors:**
1. **Outlier (rarity)** — flag software installed on ≤ `max(2, platform_hosts × SHADOW_IT_OUTLIER_PCT)` hosts of its platform. Per-platform so 1-of-10 Linux ≠ 1-of-100 Windows. `host_count == 1` → high risk, else medium.
2. **High-risk category** — curated brand list (remote-access, personal file-sync, personal messaging, crypto miners, Tor/VPN). Word-boundary match on enriched Wikidata category first, then name. Always high risk.
3. **Version sprawl** — >2 distinct versions of one title across the fleet (patch-hygiene signal).

A `whitelist.json` of operator-approved names suppresses matches on the next read.

See `webviz/README.md` for the full route list and request/response shapes.

---

## Autonomous mode (OODA)

For unattended operation, set the OODA supervisor flags in `.env`:

```ini
OODA_ENABLED=true
OODA_INTERVAL_SEC=1800        # 30-minute cycle
OODA_FULL_SCAN_EVERY=24       # refresh per-team watermarks every ~12h
```

`docker compose up -d` then runs the loop in-process (Observe → Orient → Decide → Act). Cycle state is exposed at `GET /api/ooda/status` and `GET /api/ooda/cycles`; trigger an out-of-band cycle with `POST /api/ooda/trigger` (60s cooldown).

---

## Repository layout

```text
prod/
├── main.py                  # CLI ETL entrypoint (thin shim over src/etl.py)
├── categorize_software.py   # Wikidata enrichment
├── clear_db.py              # wipe Memgraph
├── start.sh / stop.sh       # docker compose wrappers
├── docker-compose.yml       # memgraph + webviz services
├── src/                     # ETL logic (etl, extractor, ingestion, snapshot, auth)
├── webviz/                  # Flask routes, gunicorn workers, OODA + enricher
├── config/                  # Memgraph conf & OODA logs
├── scripts/smoke.sh         # post-deploy smoke test
└── assets/                  # README screenshots
```

---

## License

Released under the [MIT License](LICENSE). Copyright (c) 2025 Fleet Hound Contributors.
