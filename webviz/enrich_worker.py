"""Continuous Wikidata enrichment worker for Software nodes.

Runs as a daemon thread inside the webviz Flask process. Gunicorn launches 4
workers, but only ONE of them must run the enrichment loop — otherwise the
four would hammer Wikidata in parallel and burn through rate limits. Selection
uses an fcntl flock on a tmpfs-mounted lock file: the first worker to acquire
the exclusive lock starts the loop; the others fail-open and never start.

Cross-worker correctness:
  * Status: persisted to a JSON file (STATUS_FILE) on every tick. Any worker's
    /api/enricher/status reads the same file, so all workers report the same
    truth. items_categorized_total survives restarts because the loop reads
    the file on startup.
  * Manual trigger: a file mtime (TRIGGER_FILE) is the single source of truth.
    The loop polls its mtime during sleep; any worker's POST handler can
    "touch" the file. Cooldown is enforced by reading the same mtime, so
    rate-limiting is shared across workers.

Categorization logic (Wikidata SPARQL + DB write) is reused from
categorize_software.py so we don't fork the query.
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from neo4j.exceptions import ServiceUnavailable, SessionExpired, TransientError

# Use absolute import — Dockerfile copies prod/categorize_software.py to /app/.
sys.path.insert(0, "/app")
from categorize_software import EnrichResult, get_software_info  # noqa: E402

logger = logging.getLogger(__name__)

LOCK_PATH_DEFAULT = "/tmp/fleet-hound-enricher.lock"
TRIGGER_PATH_DEFAULT = "/tmp/fleet-hound-enricher.trigger"
STATUS_PATH_DEFAULT = "/app/config/enricher_status.json"

# Trigger poll resolution. The loop's sleep is interrupted at this granularity
# to check the trigger file's mtime; smaller = more responsive triggers, more CPU.
_TRIGGER_POLL_SEC = 1.0


def _atomic_write_json(path: str, payload: dict) -> None:
    """Write JSON atomically (temp + rename). Tolerant of EROFS on the parent."""
    parent = os.path.dirname(path) or "."
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(prefix=".enricher.", suffix=".tmp", dir=parent)
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


def _read_status_file(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _try_acquire_lock(lock_path: str):
    """Return an open file descriptor holding an exclusive flock, or None."""
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as exc:
        logger.warning("enricher: cannot open lock file %s: %s", lock_path, exc)
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


def _pick_uncategorized(driver, batch_size: int):
    try:
        with driver.session() as session:
            result = session.run(
                """
                MATCH (s:Software)
                WHERE s.category IS NULL
                OPTIONAL MATCH (s)-[:INSTALLED_ON]->(h:Host)
                WITH s.name AS name, COUNT(DISTINCT h) AS host_count
                RETURN name
                ORDER BY host_count ASC
                LIMIT $limit
                """,
                limit=int(batch_size),
            )
            return [r["name"] for r in result if r.get("name")]
    except (TransientError, ServiceUnavailable, SessionExpired) as exc:
        logger.warning("enricher: pick_uncategorized transient error: %s", exc)
        return []
    except Exception as exc:
        logger.error("enricher: pick_uncategorized failed: %s", exc)
        return []


def _write_categories(driver, name: str, categories, description) -> bool:
    try:
        with driver.session() as session:
            session.run(
                """
                MATCH (s:Software {name: $name})
                SET s.category = $category,
                    s.wikidata_description = $desc,
                    s.last_categorized = datetime()
                """,
                name=name,
                category=list(categories) if categories else [],
                desc=description,
            )
        return True
    except (TransientError, ServiceUnavailable, SessionExpired) as exc:
        logger.warning("enricher: write_categories transient error for %s: %s", name, exc)
        return False
    except Exception as exc:
        logger.error("enricher: write_categories failed for %s: %s", name, exc)
        return False


def _queue_remaining(driver) -> int:
    try:
        with driver.session() as session:
            rec = session.run(
                "MATCH (s:Software) WHERE s.category IS NULL RETURN count(s) AS c"
            ).single()
            return int(rec["c"]) if rec else 0
    except Exception:
        return 0


def _trigger_mtime(trigger_path: str) -> float:
    try:
        return os.path.getmtime(trigger_path)
    except OSError:
        return 0.0


class _SharedStatus:
    """Mutable in-process state mirrored to STATUS_FILE for cross-worker reads."""

    def __init__(self, status_path: str, *, enabled: bool, running: bool):
        self.path = status_path
        self.lock = threading.Lock()
        prior = _read_status_file(status_path)
        self.enabled = enabled
        self.running = running
        self.last_tick_iso: Optional[str] = prior.get("last_tick_iso")
        self.items_categorized_total: int = int(prior.get("items_categorized_total", 0))
        self.last_error: Optional[str] = prior.get("last_error")
        # Deliberately NOT flushing on __init__: with 4 gunicorn workers the
        # non-leaders would trample the leader's `running=True` write.
        # Only the leader calls flush_initial() after acquiring the lock.

    def flush_initial(self):
        with self.lock:
            self._flush_locked()

    def _flush_locked(self):
        payload = {
            "enabled": self.enabled,
            "running": self.running,
            "last_tick_iso": self.last_tick_iso,
            "items_categorized_total": self.items_categorized_total,
            "last_error": self.last_error,
        }
        try:
            _atomic_write_json(self.path, payload)
        except OSError as exc:
            logger.warning("enricher: status flush failed: %s", exc)

    def update(self, **kwargs):
        with self.lock:
            for k, v in kwargs.items():
                setattr(self, k, v)
            self._flush_locked()

    def add_enriched(self, count: int):
        if count <= 0:
            return
        with self.lock:
            self.items_categorized_total += int(count)
            self._flush_locked()


def _loop(driver_provider, status: _SharedStatus, *,
          interval_sec: float, batch_size: int,
          stop_event: threading.Event,
          trigger_path: str):
    http = requests.Session()
    last_trigger_seen = _trigger_mtime(trigger_path)
    try:
        while not stop_event.is_set():
            tick_started = time.time()
            try:
                driver = driver_provider()
                if driver is None:
                    status.update(last_error="memgraph driver unavailable",
                                  last_tick_iso=datetime.now(timezone.utc).isoformat())
                else:
                    items = _pick_uncategorized(driver, batch_size)
                    if items:
                        logger.info("enricher: tick picked %d uncategorized items", len(items))
                    enriched = 0
                    for name in items:
                        if stop_event.is_set():
                            break
                        try:
                            status_code, payload = get_software_info(name, http)
                        except Exception as exc:
                            logger.warning("enricher: lookup error for %r: %s", name, exc)
                            status_code, payload = EnrichResult.TRANSIENT, None
                        if status_code == EnrichResult.HIT and payload:
                            categories, desc = payload
                            if categories or desc:
                                if _write_categories(driver, name, categories, desc):
                                    enriched += 1
                        time.sleep(0.2)
                    if enriched:
                        status.add_enriched(enriched)
                    status.update(
                        last_tick_iso=datetime.now(timezone.utc).isoformat(),
                        last_error=None,
                    )
            except Exception as exc:
                logger.exception("enricher: tick failed")
                status.update(last_error=str(exc),
                              last_tick_iso=datetime.now(timezone.utc).isoformat())

            # Sleep until next tick OR until trigger file mtime advances.
            elapsed = time.time() - tick_started
            deadline = time.time() + max(1.0, float(interval_sec) - elapsed)
            while time.time() < deadline:
                if stop_event.is_set():
                    break
                cur_mtime = _trigger_mtime(trigger_path)
                if cur_mtime > last_trigger_seen:
                    last_trigger_seen = cur_mtime
                    break
                time.sleep(_TRIGGER_POLL_SEC)
    finally:
        http.close()
        status.update(running=False)
        logger.info("enricher: loop exited")


def start_worker(driver_provider, *,
                 interval_sec: int = 300,
                 batch_size: int = 25,
                 lock_path: str = LOCK_PATH_DEFAULT,
                 trigger_path: str = TRIGGER_PATH_DEFAULT,
                 status_path: str = STATUS_PATH_DEFAULT,
                 enabled: bool = True) -> tuple[_SharedStatus, threading.Event]:
    """Boot the enricher.

    Returns (status, stop_event). Status is read+written to status_path so other
    Gunicorn workers see the same view via /api/enricher/status. Manual triggers
    travel via trigger_path mtime (touch to fire), so they work no matter which
    worker handles the POST.
    """
    # Read the persisted status first so non-holder workers can still report
    # accurate cumulative counters in their /api/enricher/status responses.
    status = _SharedStatus(status_path, enabled=enabled, running=False)
    stop_event = threading.Event()

    if not enabled:
        logger.info("enricher: disabled via ENRICHER_ENABLED=false")
        return status, stop_event

    fd = _try_acquire_lock(lock_path)
    if fd is None:
        logger.info("enricher: another worker holds %s; this worker will not run the loop",
                    lock_path)
        return status, stop_event

    # Leader only — safe to publish state to disk.
    status.update(running=True)
    status.flush_initial()
    t = threading.Thread(
        target=_loop,
        name="fleet-hound-enricher",
        args=(driver_provider, status),
        kwargs=dict(
            interval_sec=float(interval_sec),
            batch_size=int(batch_size),
            stop_event=stop_event,
            trigger_path=trigger_path,
        ),
        daemon=True,
    )
    t.start()
    logger.info("enricher: started (interval=%ss, batch=%d, lock=%s, trigger=%s, status=%s)",
                interval_sec, batch_size, lock_path, trigger_path, status_path)
    return status, stop_event


def read_status(status_path: str = STATUS_PATH_DEFAULT) -> dict:
    """Read the cross-worker shared status. Returns sane defaults if missing."""
    data = _read_status_file(status_path)
    return {
        "enabled": bool(data.get("enabled", False)),
        "running": bool(data.get("running", False)),
        "last_tick_iso": data.get("last_tick_iso"),
        "items_categorized_total": int(data.get("items_categorized_total", 0)),
        "last_error": data.get("last_error"),
    }


def fire_trigger(trigger_path: str = TRIGGER_PATH_DEFAULT,
                 *, cooldown_sec: float = 30.0) -> tuple[bool, float]:
    """Touch the trigger file iff outside the cooldown window.

    Cooldown is enforced by the file's existing mtime, so all 4 gunicorn workers
    share it. Returns (fired, retry_after_sec). retry_after_sec is 0 when fired,
    otherwise the seconds until cooldown expires.
    """
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
        logger.error("enricher: trigger touch failed: %s", exc)
        return False, 0.0
    return True, 0.0


def queue_remaining(driver_provider) -> int:
    """Cheap count of un-categorized software, used by /api/enricher/status."""
    drv = driver_provider() if callable(driver_provider) else driver_provider
    if drv is None:
        return 0
    return _queue_remaining(drv)
