"""OODA supervisor — autonomous Observe→Orient→Decide→Act cycles.

The webviz container hosts this worker as a daemon thread. Gunicorn forks 4
workers but only ONE must drive the loop (otherwise four parallel ETL pulls
would hammer Fleet and corrupt the state watermark). Single-leader election
uses an fcntl flock identical to the enricher's pattern.

Cycle phases (each one writes a row in the cycle history JSONL):

  Observe  — pull host/user delta from Fleet via src.etl.run_etl()
  Orient   — kick the Wikidata enricher (touch its trigger file)
  Decide   — compute Shadow IT outliers + recent diff, persist findings
  Act      — append audit-log entry summarizing the cycle and any
             auto-actions. Auto-mutating actions (whitelist, quarantine)
             are gated behind OODA_AUTO_ACT and are intentionally limited
             to whitelisting trusted vendors via Wikidata category.

Cross-worker correctness mirrors enrich_worker.py:
  * STATUS file: every tick rewrites a small snapshot for the other
    gunicorn workers' /api/ooda/status responses.
  * TRIGGER file: any worker's POST /api/ooda/trigger touches the file;
    the loop wakes on mtime change.
  * CYCLES file: append-only JSONL of past cycles for /api/ooda/cycles.
  * FINDINGS file: latest Decide-phase output for /api/ooda/findings.
"""

from __future__ import annotations

import errno
import fcntl
import json
import logging
import os
import sys
import tempfile
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

# Container layout: /app holds webviz/, src/, categorize_software.py.
sys.path.insert(0, "/app")

from src.etl import ETLConfig, run_etl  # noqa: E402

logger = logging.getLogger(__name__)

LOCK_PATH_DEFAULT = "/tmp/fleet-hound-ooda.lock"
TRIGGER_PATH_DEFAULT = "/tmp/fleet-hound-ooda.trigger"
STATUS_PATH_DEFAULT = "/app/config/ooda_status.json"
CYCLES_PATH_DEFAULT = "/app/config/ooda_cycles.jsonl"
FINDINGS_PATH_DEFAULT = "/app/config/ooda_findings.json"

_TRIGGER_POLL_SEC = 1.0
_CYCLES_KEEP = 100  # most recent cycles retained


# ----------------------------------------------------------------------------
# Atomic JSON helpers
# ----------------------------------------------------------------------------
def _atomic_write_json(path: str, payload: dict | list) -> None:
    parent = os.path.dirname(path) or "."
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(prefix=".ooda.", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, separators=(",", ":"))
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_json_file(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default


def _append_jsonl(path: str, row: dict) -> None:
    parent = os.path.dirname(path) or "."
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError:
        pass
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, separators=(",", ":")) + "\n")
            fh.flush()
    except OSError as exc:
        logger.warning("ooda: cycles append failed: %s", exc)


def _trim_jsonl(path: str, keep: int) -> None:
    """Tail-trim a JSONL file to the last `keep` rows. Cheap; runs once per cycle."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return
    if len(lines) <= keep:
        return
    tail = lines[-keep:]
    parent = os.path.dirname(path) or "."
    try:
        fd, tmp = tempfile.mkstemp(prefix=".oodacy.", suffix=".tmp", dir=parent)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.writelines(tail)
        os.replace(tmp, path)
    except OSError as exc:
        logger.warning("ooda: cycles trim failed: %s", exc)


# ----------------------------------------------------------------------------
# Single-leader lock
# ----------------------------------------------------------------------------
def _try_acquire_lock(lock_path: str):
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as exc:
        logger.warning("ooda: cannot open lock file %s: %s", lock_path, exc)
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
            os.close(fd)
            return None
        os.close(fd)
        return None
    try:
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode("utf-8"))
    except OSError:
        pass
    return fd


def _trigger_mtime(trigger_path: str) -> float:
    try:
        return os.path.getmtime(trigger_path)
    except OSError:
        return 0.0


# ----------------------------------------------------------------------------
# Cycle records
# ----------------------------------------------------------------------------
@dataclass
class PhaseResult:
    name: str
    ok: bool
    duration_sec: float
    summary: dict = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class CycleRecord:
    cycle_id: int
    started_iso: str
    finished_iso: str
    duration_sec: float
    full_scan: bool
    phases: list[dict]
    findings_summary: dict
    error: Optional[str] = None


# ----------------------------------------------------------------------------
# Decide phase — read-only graph queries
# ----------------------------------------------------------------------------
def _decide_phase(driver) -> tuple[dict, dict]:
    """Compute Shadow IT outliers + graph snapshot summary.

    Returns (findings_payload, summary_for_status). `findings_payload` is the
    full result persisted to FINDINGS file; `summary` is a small dict that
    fits inside the cycle-history row.
    """
    findings = {
        "generated_iso": datetime.now(timezone.utc).isoformat(),
        "shadow_it": [],
        "totals": {"hosts": 0, "users": 0, "software": 0, "uncategorized": 0},
    }
    summary = {"shadow_it_count": 0, "uncategorized": 0, "hosts": 0}
    if driver is None:
        return findings, summary
    try:
        with driver.session() as session:
            # Four independent counts. Each is O(label-scan) and tolerates an
            # empty graph (count returns 0 in a single row even with zero matches).
            def _count(query: str) -> int:
                rec = session.run(query).single()
                return int(rec["c"]) if rec and rec.get("c") is not None else 0

            hosts = _count("MATCH (h:Host) RETURN count(h) AS c")
            users = _count("MATCH (u:User) RETURN count(u) AS c")
            software = _count("MATCH (s:Software) RETURN count(s) AS c")
            uncat = _count(
                "MATCH (s:Software) WHERE s.category IS NULL RETURN count(s) AS c"
            )
            findings["totals"] = {
                "hosts": hosts,
                "users": users,
                "software": software,
                "uncategorized": uncat,
            }
            summary["hosts"] = hosts
            summary["uncategorized"] = uncat

            # Shadow IT proxy: low-host-count software, uncategorized first.
            rows = session.run(
                """
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WITH s, count(DISTINCT h) AS host_count
                WHERE host_count <= 3
                RETURN s.name AS name,
                       s.category AS category,
                       host_count
                ORDER BY (s.category IS NULL) DESC, host_count ASC, s.name ASC
                LIMIT 50
                """
            )
            shadow = [
                {
                    "name": r["name"],
                    "category": r["category"],
                    "host_count": int(r["host_count"]),
                }
                for r in rows
                if r.get("name")
            ]
            findings["shadow_it"] = shadow
            summary["shadow_it_count"] = len(shadow)
    except Exception as exc:
        logger.warning("ooda: decide queries failed: %s", exc)
        findings["error"] = f"{type(exc).__name__}: {exc}"
    return findings, summary


# ----------------------------------------------------------------------------
# Shared status (mirrored to disk for cross-worker reads)
# ----------------------------------------------------------------------------
class _SharedStatus:
    def __init__(self, status_path: str, *, enabled: bool, running: bool):
        self.path = status_path
        self.lock = threading.Lock()
        prior = _read_json_file(status_path, default={}) or {}
        self.enabled = enabled
        self.running = running
        self.next_cycle_id: int = int(prior.get("next_cycle_id", 1))
        self.last_cycle: Optional[dict] = prior.get("last_cycle")
        self.last_phase: Optional[str] = prior.get("last_phase")
        self.last_error: Optional[str] = prior.get("last_error")
        self.cycles_total: int = int(prior.get("cycles_total", 0))
        self.cycles_failed: int = int(prior.get("cycles_failed", 0))
        # Deliberately NOT flushing on __init__: with 4 gunicorn workers the
        # non-leaders would trample the leader's `running=True` write.
        # Only the leader calls flush_initial() after acquiring the lock.

    def flush_initial(self) -> None:
        with self.lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        payload = {
            "enabled": self.enabled,
            "running": self.running,
            "next_cycle_id": self.next_cycle_id,
            "last_cycle": self.last_cycle,
            "last_phase": self.last_phase,
            "last_error": self.last_error,
            "cycles_total": self.cycles_total,
            "cycles_failed": self.cycles_failed,
        }
        try:
            _atomic_write_json(self.path, payload)
        except OSError as exc:
            logger.warning("ooda: status flush failed: %s", exc)

    def update(self, **kwargs) -> None:
        with self.lock:
            for k, v in kwargs.items():
                setattr(self, k, v)
            self._flush_locked()

    def record_cycle(self, cycle: CycleRecord) -> None:
        with self.lock:
            self.next_cycle_id = int(cycle.cycle_id) + 1
            self.last_cycle = asdict(cycle)
            self.cycles_total += 1
            if cycle.error:
                self.cycles_failed += 1
            self._flush_locked()


# ----------------------------------------------------------------------------
# Loop
# ----------------------------------------------------------------------------
def _resolve_etl_config(memgraph_uri: str, *,
                       state_path: str, snapshot_dir: str,
                       full_scan: bool) -> Optional[ETLConfig]:
    fleet_url = os.environ.get("FLEET_URL", "").strip()
    api_token = os.environ.get("FLEET_API_TOKEN", "").strip()
    email = os.environ.get("FLEET_EMAIL", "").strip()
    password = os.environ.get("FLEET_PASSWORD", "").strip()
    insecure_raw = os.environ.get("INSECURE", "").strip().lower()
    debug_raw = os.environ.get("DEBUG", "").strip().lower()
    teams_raw = os.environ.get("OODA_TEAMS", "").strip()

    if not fleet_url:
        logger.error("ooda: FLEET_URL is empty — cannot run cycle")
        return None
    if not (api_token or (email and password)):
        logger.error("ooda: no Fleet credentials (FLEET_API_TOKEN or FLEET_EMAIL+FLEET_PASSWORD)")
        return None

    team_ids: list[int] = []
    if teams_raw:
        try:
            team_ids = [int(x.strip()) for x in teams_raw.split(",") if x.strip()]
        except ValueError:
            logger.warning("ooda: OODA_TEAMS is not a comma-separated integer list; ignoring")

    return ETLConfig(
        fleet_url=fleet_url,
        memgraph_uri=memgraph_uri,
        api_token=api_token or None,
        email=email or None,
        password=password or None,
        insecure=insecure_raw in ("1", "true", "yes", "on"),
        debug=debug_raw in ("1", "true", "yes", "on"),
        team_ids=team_ids,
        full_scan=full_scan,
        state_path=state_path,
        snapshot_dir=snapshot_dir,
        # OODA does its own enrichment kick in Orient. Don't inline-enrich
        # during ETL — the dedicated enricher handles bulk catch-up async.
        skip_enrichment=True,
        skip_snapshot=False,
    )


def _audit_cycle(audit_log_path: str, cycle: CycleRecord) -> None:
    """Append a one-line audit entry summarizing the cycle."""
    try:
        os.makedirs(os.path.dirname(audit_log_path) or ".", exist_ok=True)
    except OSError:
        pass
    line = (
        f"{datetime.now(timezone.utc).isoformat()} - OODA_CYCLE - "
        f"id={cycle.cycle_id} ok={cycle.error is None} "
        f"duration={cycle.duration_sec:.1f}s "
        f"phases={','.join(p['name'] + (':OK' if p['ok'] else ':FAIL') for p in cycle.phases)} "
        f"shadow_it={cycle.findings_summary.get('shadow_it_count', 0)} "
        f"uncategorized={cycle.findings_summary.get('uncategorized', 0)}"
    )
    try:
        with open(audit_log_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        logger.warning("ooda: audit write failed: %s", exc)


def _loop(driver_provider: Callable, status: _SharedStatus, *,
          interval_sec: float, full_scan_every: int,
          state_path: str, snapshot_dir: str,
          stop_event: threading.Event,
          trigger_path: str,
          cycles_path: str,
          findings_path: str,
          enricher_trigger_path: str,
          audit_log_path: str) -> None:
    last_trigger_seen = _trigger_mtime(trigger_path)
    cycles_since_full_scan = 0

    while not stop_event.is_set():
        cycle_started = datetime.now(timezone.utc)
        cycle_id = status.next_cycle_id

        full_scan = bool(full_scan_every > 0 and cycles_since_full_scan >= full_scan_every)
        if full_scan:
            cycles_since_full_scan = 0
        else:
            cycles_since_full_scan += 1

        phases: list[dict] = []
        cycle_error: Optional[str] = None

        # Phase 1 — Observe + Orient (in-process ETL covers both: extract,
        # ingest, snapshot). Enrichment is decoupled into its own Orient kick.
        status.update(last_phase="observe")
        phase_started = time.time()
        cfg = _resolve_etl_config(
            memgraph_uri=os.environ.get("MEMGRAPH_URI", "bolt://memgraph:7687").strip(),
            state_path=state_path,
            snapshot_dir=snapshot_dir,
            full_scan=full_scan,
        )
        if cfg is None:
            err = "missing or invalid Fleet credentials"
            phases.append(asdict(PhaseResult(
                name="observe", ok=False, duration_sec=0.0, error=err,
            )))
            cycle_error = err
        else:
            etl_result = run_etl(cfg)
            phases.append(asdict(PhaseResult(
                name="observe",
                ok=etl_result.error is None,
                duration_sec=time.time() - phase_started,
                summary={
                    "hosts_extracted": etl_result.hosts_extracted,
                    "users_extracted": etl_result.users_extracted,
                    "snapshot_path": etl_result.snapshot_path,
                    "full_scan": etl_result.full_scan,
                    "teams_synced": etl_result.teams_synced,
                },
                error=etl_result.error,
            )))
            if etl_result.error:
                cycle_error = etl_result.error

        # Phase 2 — Orient: kick the enricher (best-effort).
        status.update(last_phase="orient")
        phase_started = time.time()
        orient_err = None
        try:
            Path(enricher_trigger_path).parent.mkdir(parents=True, exist_ok=True)
            Path(enricher_trigger_path).touch()
        except OSError as exc:
            orient_err = f"enricher trigger failed: {exc}"
            logger.warning("ooda: %s", orient_err)
        phases.append(asdict(PhaseResult(
            name="orient",
            ok=orient_err is None,
            duration_sec=time.time() - phase_started,
            summary={"enricher_trigger_path": enricher_trigger_path},
            error=orient_err,
        )))

        # Phase 3 — Decide: read-only graph queries, write findings.
        status.update(last_phase="decide")
        phase_started = time.time()
        findings_summary: dict = {}
        decide_err = None
        try:
            driver = driver_provider() if callable(driver_provider) else driver_provider
            findings, findings_summary = _decide_phase(driver)
            findings["cycle_id"] = cycle_id
            try:
                _atomic_write_json(findings_path, findings)
            except OSError as exc:
                decide_err = f"findings write failed: {exc}"
                logger.warning("ooda: %s", decide_err)
        except Exception as exc:
            decide_err = f"{type(exc).__name__}: {exc}"
            logger.exception("ooda: decide failed")
        phases.append(asdict(PhaseResult(
            name="decide",
            ok=decide_err is None,
            duration_sec=time.time() - phase_started,
            summary=findings_summary,
            error=decide_err,
        )))

        # Phase 4 — Act: append cycle history + audit log. Auto-mutating
        # actions are intentionally NOT here; the operator drives writes via
        # the existing /api/authorize-software path.
        #
        # We build the Act phase entry BEFORE persisting the cycle so the
        # JSONL row contains all four phases (otherwise a reader would see
        # observe/orient/decide and a missing act).
        status.update(last_phase="act")
        phase_started = time.time()
        cycle_finished = datetime.now(timezone.utc)
        duration = (cycle_finished - cycle_started).total_seconds()
        phases.append(asdict(PhaseResult(
            name="act",
            ok=True,  # Persistence errors below downgrade this to False.
            duration_sec=time.time() - phase_started,
            summary={"cycle_id": cycle_id},
        )))
        record = CycleRecord(
            cycle_id=cycle_id,
            started_iso=cycle_started.isoformat(),
            finished_iso=cycle_finished.isoformat(),
            duration_sec=round(duration, 3),
            full_scan=full_scan,
            phases=phases,
            findings_summary=findings_summary,
            error=cycle_error,
        )
        try:
            _append_jsonl(cycles_path, asdict(record))
            _trim_jsonl(cycles_path, _CYCLES_KEEP)
            _audit_cycle(audit_log_path, record)
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
            logger.exception("ooda: act phase persistence failed")
            phases[-1]["ok"] = False
            phases[-1]["error"] = err
            # Mirror onto the in-memory record before it goes to status.
            record.phases = phases

        status.record_cycle(record)
        status.update(last_phase=None,
                      last_error=cycle_error)

        # Sleep until next tick OR until the trigger file mtime advances.
        deadline = time.time() + max(1.0, float(interval_sec))
        while time.time() < deadline:
            if stop_event.is_set():
                break
            cur = _trigger_mtime(trigger_path)
            if cur > last_trigger_seen:
                last_trigger_seen = cur
                break
            time.sleep(_TRIGGER_POLL_SEC)

    status.update(running=False)
    logger.info("ooda: loop exited")


# ----------------------------------------------------------------------------
# Public API (consumed by webviz/app.py)
# ----------------------------------------------------------------------------
def start_worker(driver_provider: Callable, *,
                 interval_sec: int = 1800,
                 full_scan_every: int = 24,
                 state_path: str = "/app/config/.state.json",
                 snapshot_dir: str = "/app/config/snapshots",
                 lock_path: str = LOCK_PATH_DEFAULT,
                 trigger_path: str = TRIGGER_PATH_DEFAULT,
                 status_path: str = STATUS_PATH_DEFAULT,
                 cycles_path: str = CYCLES_PATH_DEFAULT,
                 findings_path: str = FINDINGS_PATH_DEFAULT,
                 enricher_trigger_path: str = "/tmp/fleet-hound-enricher.trigger",
                 audit_log_path: str = "/app/config/audit.log",
                 enabled: bool = True) -> tuple[_SharedStatus, threading.Event]:
    """Boot the OODA supervisor.

    Returns (status, stop_event). Status is read+written to status_path so
    other Gunicorn workers see the same view; manual triggers travel via
    trigger_path mtime.
    """
    status = _SharedStatus(status_path, enabled=enabled, running=False)
    stop_event = threading.Event()

    if not enabled:
        logger.info("ooda: disabled via OODA_ENABLED=false")
        return status, stop_event

    fd = _try_acquire_lock(lock_path)
    if fd is None:
        logger.info("ooda: another worker holds %s; this worker will not run the loop",
                    lock_path)
        return status, stop_event

    # Leader only — safe to publish state to disk.
    status.update(running=True)
    status.flush_initial()
    t = threading.Thread(
        target=_loop,
        name="fleet-hound-ooda",
        args=(driver_provider, status),
        kwargs=dict(
            interval_sec=float(interval_sec),
            full_scan_every=int(full_scan_every),
            state_path=state_path,
            snapshot_dir=snapshot_dir,
            stop_event=stop_event,
            trigger_path=trigger_path,
            cycles_path=cycles_path,
            findings_path=findings_path,
            enricher_trigger_path=enricher_trigger_path,
            audit_log_path=audit_log_path,
        ),
        daemon=True,
    )
    t.start()
    logger.info("ooda: started (interval=%ss, full_scan_every=%d, lock=%s)",
                interval_sec, full_scan_every, lock_path)
    return status, stop_event


def read_status(status_path: str = STATUS_PATH_DEFAULT) -> dict:
    data = _read_json_file(status_path, default={}) or {}
    return {
        "enabled": bool(data.get("enabled", False)),
        "running": bool(data.get("running", False)),
        "next_cycle_id": int(data.get("next_cycle_id", 1)),
        "last_phase": data.get("last_phase"),
        "last_error": data.get("last_error"),
        "cycles_total": int(data.get("cycles_total", 0)),
        "cycles_failed": int(data.get("cycles_failed", 0)),
        "last_cycle": data.get("last_cycle"),
    }


def fire_trigger(trigger_path: str = TRIGGER_PATH_DEFAULT,
                 *, cooldown_sec: float = 60.0) -> tuple[bool, float]:
    """Touch the trigger file iff outside the cooldown window."""
    now = time.time()
    last = _trigger_mtime(trigger_path)
    if last > 0 and (now - last) < cooldown_sec:
        return False, max(1.0, cooldown_sec - (now - last))
    parent = os.path.dirname(trigger_path) or "."
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError:
        pass
    try:
        Path(trigger_path).touch()
    except OSError as exc:
        logger.error("ooda: trigger touch failed: %s", exc)
        return False, 0.0
    return True, 0.0


def read_findings(findings_path: str = FINDINGS_PATH_DEFAULT) -> dict:
    data = _read_json_file(findings_path, default=None)
    if isinstance(data, dict):
        return data
    return {
        "generated_iso": None,
        "shadow_it": [],
        "totals": {"hosts": 0, "users": 0, "software": 0, "uncategorized": 0},
    }


def read_cycles(cycles_path: str = CYCLES_PATH_DEFAULT, *, limit: int = 20) -> list[dict]:
    """Return the last `limit` cycles, newest first."""
    if limit <= 0:
        return []
    rows: deque[dict] = deque(maxlen=limit)
    try:
        with open(cycles_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return list(reversed(rows))
