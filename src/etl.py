"""Reusable Observe→Orient core for Fleet Hound.

`run_etl()` is a single, side-effecting call: it authenticates against Fleet,
pulls hosts/users (delta or full), ingests into Memgraph, optionally kicks
Wikidata categorization, and writes a snapshot. Returns a structured summary
that callers (CLI in `main.py`, the OODA supervisor in `webviz/ooda_worker.py`)
can log, audit, or expose over HTTP.

The module deliberately has no argparse / stdin / colorized printing — those
belong in the CLI shim. Output is logging + return value.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import urllib3

from categorize_software import run_categorization
from src.auth import FleetAuthenticator
from src.extractor import FleetGraphExtractor
from src.ingestion import MemgraphIngestion, _memgraph_auth as _mg_auth
from src.snapshot import write_snapshot

logger = logging.getLogger(__name__)


@dataclass
class ETLConfig:
    """Inputs needed for a single ETL run.

    All paths are explicit so the same code path works from the host CLI
    (writing to `prod/.state.json` and `prod/config/snapshots/`) and from
    inside the webviz container (writing to `/app/config/.state.json` and
    `/app/config/snapshots/`).
    """

    fleet_url: str
    memgraph_uri: str
    api_token: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    insecure: bool = False
    debug: bool = False
    team_ids: list[int] = field(default_factory=list)
    full_scan: bool = False
    state_path: str = ".state.json"
    snapshot_dir: str = "config/snapshots"
    enrich_limit: Optional[int] = 250
    enrich_target_names: Optional[list[str]] = None
    skip_enrichment: bool = False
    skip_snapshot: bool = False


@dataclass
class ETLResult:
    started_iso: str
    finished_iso: str
    duration_sec: float
    hosts_extracted: int = 0
    users_extracted: int = 0
    teams_synced: list[int] = field(default_factory=list)
    full_scan: bool = False
    snapshot_path: Optional[str] = None
    enrichment_attempted: bool = False
    enrichment_error: Optional[str] = None
    snapshot_error: Optional[str] = None
    error: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "started_iso": self.started_iso,
            "finished_iso": self.finished_iso,
            "duration_sec": round(self.duration_sec, 3),
            "hosts_extracted": self.hosts_extracted,
            "users_extracted": self.users_extracted,
            "teams_synced": self.teams_synced,
            "full_scan": self.full_scan,
            "snapshot_path": self.snapshot_path,
            "enrichment_attempted": self.enrichment_attempted,
            "enrichment_error": self.enrichment_error,
            "snapshot_error": self.snapshot_error,
            "error": self.error,
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_compact() -> str:
    # Same shape main.py wrote so existing watermark files keep parsing.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def load_state(state_path: str) -> dict:
    p = Path(state_path)
    if not p.exists():
        return {}
    try:
        with p.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("etl: ignoring unreadable state file %s: %s", state_path, exc)
        return {}


def save_state(state_path: str, state: dict) -> None:
    p = Path(state_path)
    parent = p.parent if str(p.parent) else Path(".")
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            dir=str(parent),
            prefix=p.name + ".",
            suffix=".tmp",
        ) as fh:
            tmp_path = fh.name
            json.dump(state, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        os.replace(tmp_path, str(p))
    except Exception as exc:
        logger.warning("etl: failed to persist state %s: %s", state_path, exc)
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def _resolve_token(cfg: ETLConfig) -> Optional[str]:
    if cfg.api_token:
        logger.info("etl: using API token authentication")
        return cfg.api_token
    if cfg.email and cfg.password:
        logger.info("etl: authenticating with email/password (API token preferred)")
        auth = FleetAuthenticator(cfg.fleet_url, verify=not cfg.insecure)
        token = auth.login(cfg.email, cfg.password, debug=cfg.debug)
        if not token:
            logger.error("etl: email/password login failed")
            return None
        return token
    logger.error("etl: no Fleet credentials supplied (FLEET_API_TOKEN or FLEET_EMAIL/FLEET_PASSWORD)")
    return None


def run_etl(cfg: ETLConfig) -> ETLResult:
    """Single Observe→Orient cycle. Never raises; encodes errors in the result."""
    started = _now_iso()
    t0 = datetime.now(timezone.utc).timestamp()
    result = ETLResult(started_iso=started, finished_iso=started, duration_sec=0.0,
                      full_scan=cfg.full_scan)

    if cfg.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if not cfg.fleet_url:
        result.error = "FLEET_URL is required"
        result.finished_iso = _now_iso()
        result.duration_sec = datetime.now(timezone.utc).timestamp() - t0
        return result

    token = _resolve_token(cfg)
    if not token:
        result.error = "Fleet authentication failed"
        result.finished_iso = _now_iso()
        result.duration_sec = datetime.now(timezone.utc).timestamp() - t0
        return result

    state = load_state(cfg.state_path)
    since_map = state.get("team_syncs", {}) if isinstance(state, dict) else {}
    global_since = None if cfg.full_scan else state.get("last_run_timestamp")
    current_ts = _now_compact()

    try:
        extractor = FleetGraphExtractor(
            cfg.fleet_url, token, verify=not cfg.insecure, debug=cfg.debug
        )

        logger.info("etl: extracting hosts (full_scan=%s, since=%s, teams=%s)",
                    cfg.full_scan, global_since, cfg.team_ids or "ALL")
        hosts = extractor.extract_host_data(
            team_ids=cfg.team_ids,
            since=global_since,
            since_map=since_map,
        )
        users = extractor.extract_all_users()
        result.hosts_extracted = len(hosts)
        result.users_extracted = len(users)
        logger.info("etl: extracted %d hosts, %d users", len(hosts), len(users))

        logger.info("etl: ingesting into Memgraph %s", cfg.memgraph_uri)
        with MemgraphIngestion(cfg.memgraph_uri) as ingestion:
            ingestion.create_constraints()
            ingestion.create_graph_relationships(hosts, extractor, global_users=users)

        # Orient: enrichment kick. Best-effort — never breaks a cycle.
        if not cfg.skip_enrichment:
            result.enrichment_attempted = True
            try:
                run_categorization(
                    memgraph_uri=cfg.memgraph_uri,
                    limit=cfg.enrich_limit,
                    target_names=cfg.enrich_target_names,
                )
            except Exception as exc:
                msg = f"{type(exc).__name__}: {exc}"
                logger.warning("etl: enrichment failed: %s", msg)
                result.enrichment_error = msg

        # Snapshot. Best-effort — never breaks a cycle.
        if not cfg.skip_snapshot:
            try:
                snap_path = write_snapshot(
                    cfg.memgraph_uri,
                    current_ts,
                    Path(cfg.snapshot_dir),
                    auth=_mg_auth(),
                )
                result.snapshot_path = str(snap_path)
                logger.info("etl: snapshot written to %s", snap_path)
            except Exception as exc:
                msg = f"{type(exc).__name__}: {exc}"
                logger.warning("etl: snapshot write failed: %s", msg)
                result.snapshot_error = msg

        # Advance watermarks.
        if cfg.team_ids:
            state.setdefault("team_syncs", {})
            for tid in cfg.team_ids:
                state["team_syncs"][str(tid)] = current_ts
            result.teams_synced = list(cfg.team_ids)
        else:
            state["last_run_timestamp"] = current_ts
            try:
                all_teams = extractor.extract_teams()
                state.setdefault("team_syncs", {})
                synced = []
                for t in all_teams:
                    tid = t.get("id")
                    if tid is not None:
                        state["team_syncs"][str(tid)] = current_ts
                        synced.append(int(tid))
                result.teams_synced = synced
            except Exception as exc:
                logger.warning("etl: failed to refresh per-team watermarks: %s", exc)
        save_state(cfg.state_path, state)

    except Exception as exc:
        msg = f"{type(exc).__name__}: {exc}"
        logger.exception("etl: cycle failed")
        result.error = msg

    result.finished_iso = _now_iso()
    result.duration_sec = datetime.now(timezone.utc).timestamp() - t0
    return result
