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

import contextlib
import errno
import fcntl
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


_DEFAULT_LOCK_PATH = ".etl.lock"


@contextlib.contextmanager
def _etl_file_lock(lock_path: str):
    """Process-level non-blocking advisory lock for the ETL cycle.

    Mirrors the flock pattern used in webviz/enrich_worker.py for the
    enrichment leader election. If a second ETL process tries to acquire
    while one holds it, the second exits cleanly via OSError → context
    manager raises so the caller can log + skip without partial state.

    Why a process lock:
      Plan section R5 (outside voice) — without this, two overlapping ETL
      runs could both DETACH HAS_LABEL for the same label, then both
      re-MERGE, producing relationship duplication or partial sets between
      the two write phases. The lock guarantees one cycle at a time.
    """
    parent = Path(lock_path).parent
    if str(parent):
        parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                raise EtlAlreadyRunning(
                    f"another ETL is in progress (lock held: {lock_path})"
                ) from e
            raise
        os.write(fd, f"{os.getpid()}\n".encode())
        os.fsync(fd)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


class EtlAlreadyRunning(RuntimeError):
    """Raised when ETL file lock is already held by another process."""


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
    skip_labels: bool = False
    skip_all_label_builtins: bool = False  # legacy posture; default keeps functional builtins
    label_reap_age_seconds: int = 7 * 24 * 60 * 60  # T2: 7-day age-based reap
    lock_path: Optional[str] = None  # None → derive from state_path parent
    supplement_label_orphans: bool = False
    # When True, the ETL cycle fetches each orphan host_id via /api/v1/fleet/hosts/{id}
    # and appends it to the hosts list before create_graph_relationships so the missing
    # :Host node is created and the next label sync can form the HAS_LABEL edge.
    supplement_orphan_cap: int = 200
    # Maximum extra /hosts/{id} calls per cycle when supplement_label_orphans is True.
    # Bounded to prevent a misconfigured label from fanning out unboundedly.


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
    # Label sync (added v1.27 — see plan 1B/2B)
    label_sync_attempted: bool = False
    label_sync_error: Optional[str] = None
    last_label_sync_iso: Optional[str] = None
    label_sync_stats: Optional[dict] = None
    skipped_due_to_lock: bool = False
    # Label orphan tracking (added 260519-j0t)
    label_orphan_count: int = 0
    label_orphans_fetched: int = 0

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
            "label_sync_attempted": self.label_sync_attempted,
            "label_sync_error": self.label_sync_error,
            "last_label_sync_iso": self.last_label_sync_iso,
            "label_sync_stats": self.label_sync_stats,
            "skipped_due_to_lock": self.skipped_due_to_lock,
            "label_orphan_count": self.label_orphan_count,
            "label_orphans_fetched": self.label_orphans_fetched,
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


def load_full_scan_cadence(state_path: str) -> tuple:
    """Return (cycles_since_full_scan: int, last_full_scan_iso: Optional[str]).

    Reads the two cadence keys added in plan 260519-k2n from .state.json.
    Missing or malformed keys are silently defaulted: (0, None).
    Never raises.
    """
    state = load_state(state_path)
    try:
        cycles = int(state.get("cycles_since_full_scan", 0))
    except (TypeError, ValueError):
        cycles = 0
    last_iso = state.get("last_full_scan_iso")
    if not isinstance(last_iso, str) or not last_iso:
        last_iso = None
    return (cycles, last_iso)


def save_full_scan_cadence(
    state_path: str,
    *,
    cycles_since_full_scan: int,
    last_full_scan_iso: str,
) -> None:
    """Read-modify-write .state.json to persist cadence keys.

    Preserves all existing keys (last_run_timestamp, team_syncs, …)
    so this is purely additive and backward-compatible.
    """
    state = load_state(state_path)
    state["cycles_since_full_scan"] = cycles_since_full_scan
    state["last_full_scan_iso"] = last_full_scan_iso
    save_state(state_path, state)


def should_force_full_scan(
    cycles_since_full_scan: int,
    last_full_scan_iso: Optional[str],
    full_scan_every: int,
    interval_sec: float,
    now: Optional[datetime] = None,
) -> tuple:
    """Decide whether the next cycle should be a full scan.

    Returns (force: bool, reason: Optional[str]) where reason is one of:
      "count"   — cycles_since_full_scan >= full_scan_every
      "elapsed" — wall-clock elapsed since last_full_scan_iso >= 1.5x expected window
      None      — no trigger condition met

    Count threshold is checked first; elapsed-time is the safety net for the
    post-restart case where the in-memory counter was lost.

    The `now` parameter is injectable for deterministic unit tests; production
    callers omit it and get datetime.now(timezone.utc).
    """
    if now is None:
        now = datetime.now(timezone.utc)

    # Count threshold (primary trigger).
    if full_scan_every > 0 and cycles_since_full_scan >= full_scan_every:
        return (True, "count")

    # Elapsed-time guard (secondary trigger / post-restart safety net).
    threshold_sec = full_scan_every * interval_sec * 1.5
    if last_full_scan_iso is None:
        return (True, "elapsed")
    try:
        last_dt = datetime.fromisoformat(last_full_scan_iso.replace("Z", "+00:00"))
        elapsed = (now - last_dt).total_seconds()
        if elapsed >= threshold_sec:
            return (True, "elapsed")
    except ValueError:
        # Unparseable ISO → treat as never ran.
        return (True, "elapsed")

    return (False, None)


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
    """Single Observe→Orient cycle. Never raises; encodes errors in the result.

    Wraps the cycle in a file lock (see _etl_file_lock) to prevent two
    overlapping ETL processes from racing on label-sync DETACH+re-MERGE
    (plan section R5). If the lock is already held, returns immediately
    with skipped_due_to_lock=True so the caller (CLI / OODA supervisor)
    can log + continue without partial state.
    """
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

    # Resolve lock path: explicit cfg.lock_path > sibling of state file > cwd default.
    if cfg.lock_path:
        lock_path = cfg.lock_path
    else:
        state_p = Path(cfg.state_path)
        lock_path = str(state_p.parent / _DEFAULT_LOCK_PATH) if str(state_p.parent) else _DEFAULT_LOCK_PATH

    try:
        with _etl_file_lock(lock_path):
            return _run_etl_locked(cfg, token, result, t0)
    except EtlAlreadyRunning as e:
        logger.warning("etl: %s — skipping this cycle", e)
        result.skipped_due_to_lock = True
        result.error = str(e)
        result.finished_iso = _now_iso()
        result.duration_sec = datetime.now(timezone.utc).timestamp() - t0
        return result


def _run_etl_locked(cfg: ETLConfig, token: str, result: ETLResult, t0: float) -> ETLResult:
    """Body of run_etl, executed under the file lock."""

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

        # --- Label extraction (moved BEFORE host ingest) ---
        # Labels and membership are fetched here so we can compute orphan ids
        # (member ids with no corresponding :Host node) BEFORE create_graph_relationships.
        # This allows the optional supplement path to back-fill missing hosts so the
        # label sync in the same cycle can create the HAS_LABEL edges (no two-cycle wait).
        labels = []
        member_map: dict = {}
        if not cfg.skip_labels:
            try:
                labels = extractor.extract_labels(
                    skip_all_builtins=cfg.skip_all_label_builtins,
                )
                if not labels:
                    logger.info("etl: /labels returned no labels (empty or filtered)")
                for lbl in labels:
                    lid = lbl.get("id")
                    if lid is None:
                        continue
                    members = extractor.extract_label_host_membership(lid)
                    member_map[lid] = [
                        m.get("id") for m in members if m.get("id") is not None
                    ]
            except Exception as exc:
                logger.warning("etl: label pre-fetch failed: %s", exc)
                labels = []
                member_map = {}

        # Compute orphan ids: member ids in any label not already in hosts.
        known_host_ids = {h.get("id") for h in hosts if h.get("id") is not None}
        all_member_ids: set = set()
        for ids in member_map.values():
            all_member_ids.update(ids)
        orphan_ids = sorted(all_member_ids - known_host_ids)
        result.label_orphan_count = len(orphan_ids)
        logger.info(
            "etl: label orphan ids detected=%d (host ids in Fleet membership with no :Host node)",
            len(orphan_ids),
        )

        # Optional supplement fetch: back-fill orphan hosts before ingest so the
        # label sync in this same cycle can create the missing HAS_LABEL edges.
        # Honor supplement_orphan_cap during the fan-out, not at the end (CLAUDE.md
        # pagination-cap rule). Default off; set cfg.supplement_label_orphans=True
        # or FLEET_SUPPLEMENT_LABEL_ORPHANS=1 (env wiring is a follow-up commit).
        if cfg.supplement_label_orphans and orphan_ids:
            cap = cfg.supplement_orphan_cap
            to_fetch = orphan_ids[:cap]
            if len(orphan_ids) > cap:
                logger.warning(
                    "etl: orphan supplement capped at %d (total=%d); remaining will be "
                    "fetched in subsequent cycles",
                    cap, len(orphan_ids),
                )
            fetched = 0
            for oid in to_fetch:
                host_dict = extractor.extract_host_by_id(oid)
                if host_dict is not None:
                    hosts.append(host_dict)
                    fetched += 1
            result.label_orphans_fetched = fetched
            result.hosts_extracted = len(hosts)
            logger.info(
                "etl: supplement fetched %d/%d orphan hosts",
                fetched, len(to_fetch),
            )

        logger.info("etl: ingesting into Memgraph %s", cfg.memgraph_uri)
        with MemgraphIngestion(cfg.memgraph_uri) as ingestion:
            ingestion.create_constraints()
            ingestion.create_graph_relationships(hosts, extractor, global_users=users)

            # Label sync stage. Best-effort: matches enrichment/snapshot
            # posture per plan section 2B. /labels failures don't break the
            # cycle; existing edges + last-known-good state are preserved
            # and surfaced via the freshness signal.
            if not cfg.skip_labels:
                result.label_sync_attempted = True
                try:
                    label_sync_iso = _now_iso()
                    stats = ingestion.sync_labels_with_membership(
                        labels, member_map, label_sync_iso,
                        reap_age_seconds=cfg.label_reap_age_seconds,
                    )
                    result.last_label_sync_iso = label_sync_iso
                    result.label_sync_stats = stats.as_dict()
                    logger.info(
                        "etl: label sync ok — seen=%d unchanged=%d resynced=%d "
                        "reaped=%d edges_added=%d edges_deleted=%d orphan_members=%d",
                        stats.labels_seen, stats.labels_unchanged,
                        stats.labels_resynced, stats.labels_reaped,
                        stats.edges_created, stats.edges_deleted,
                        stats.orphan_members,
                    )
                except Exception as exc:
                    msg = f"{type(exc).__name__}: {exc}"
                    logger.warning("etl: label sync failed: %s", msg)
                    result.label_sync_error = msg
                    try:
                        ingestion.mark_label_sync_failure(msg)
                    except Exception as inner:
                        logger.warning(
                            "etl: failed to mark label-sync failure on existing "
                            "Label nodes: %s", inner,
                        )

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
