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

import logging
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests
from neo4j.exceptions import ServiceUnavailable, SessionExpired, TransientError

# Use absolute import — Dockerfile copies prod/categorize_software.py to /app/.
sys.path.insert(0, "/app")
from categorize_software import (  # noqa: E402
    ENRICH_FAILURE_COOLDOWN_DAYS,
    EnrichResult,
    purge_non_software_descriptions,
    SHADOW_IT_SOURCES,
    get_software_info,
)

try:  # Docker layout: /app/webviz on sys.path
    from worker_util import (atomic_write_json, fire_trigger as _fire_trigger, read_json,
                             sleep_until, trigger_mtime as _trigger_mtime, try_acquire_lock)
except ImportError:  # imported as the webviz package
    from webviz.worker_util import (atomic_write_json, fire_trigger as _fire_trigger,  # type: ignore
                                    read_json, sleep_until, trigger_mtime as _trigger_mtime,
                                    try_acquire_lock)

logger = logging.getLogger(__name__)


def _read_status(path: str) -> dict:
    data = read_json(path, {})
    return data if isinstance(data, dict) else {}


LOCK_PATH_DEFAULT = "/tmp/fleet-hound-enricher.lock"
TRIGGER_PATH_DEFAULT = "/tmp/fleet-hound-enricher.trigger"
STATUS_PATH_DEFAULT = "/app/config/enricher_status.json"

def _pick_uncategorized(driver, batch_size: int):
    try:
        with driver.session() as session:
            result = session.run(
                """
                MATCH (s:Software)
                WHERE s.category IS NULL
                  AND any(x IN s.sources WHERE x IN $eligible)
                  AND coalesce(s.kind, '') <> 'browser_extension'
                  AND (s.last_categorization_attempt_iso IS NULL
                       OR s.last_categorization_attempt_iso < $cutoff_iso)
                OPTIONAL MATCH (s)-[:INSTALLED_ON]->(h:Host)
                WITH s.name AS name, COUNT(DISTINCT h) AS host_count
                RETURN name
                ORDER BY host_count ASC
                LIMIT $limit
                """,
                limit=int(batch_size),
                eligible=list(SHADOW_IT_SOURCES),
                # Misses are stamped with an attempt time; without this cooldown
                # the same rarest-N misses are re-picked forever.
                cutoff_iso=(datetime.now(timezone.utc)
                            - timedelta(days=ENRICH_FAILURE_COOLDOWN_DAYS)).isoformat(),
            )
            return [r["name"] for r in result if r.get("name")]
    except (TransientError, ServiceUnavailable, SessionExpired) as exc:
        logger.warning("enricher: pick_uncategorized transient error: %s", exc)
        return []
    except Exception as exc:
        logger.error("enricher: pick_uncategorized failed: %s", exc)
        return []


def _mark_miss(driver, name: str) -> None:
    try:
        with driver.session() as session:
            session.run(
                """
                MATCH (s:Software {name: $name})
                SET s.last_categorization_attempt_iso = $now_iso,
                    s.categorization_attempts = coalesce(s.categorization_attempts, 0) + 1
                """,
                name=name, now_iso=datetime.now(timezone.utc).isoformat(),
            ).consume()
    except Exception as exc:
        logger.warning("enricher: mark_miss failed for %s: %s", name, exc)


def _write_categories(driver, name: str, categories, description) -> bool:
    try:
        with driver.session() as session:
            session.run(
                """
                MATCH (s:Software {name: $name})
                SET s.category = $category,
                    s.wikidata_description = $desc,
                    s.last_categorized = datetime(),
                    s.enrich_gate_passed = true
                """,
                name=name,
                category=list(categories) if categories else [],
                desc=description,
            ).consume()
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


class _SharedStatus:
    """Mutable in-process state mirrored to STATUS_FILE for cross-worker reads."""

    def __init__(self, status_path: str, *, enabled: bool, running: bool):
        self.path = status_path
        self.lock = threading.Lock()
        prior = _read_status(status_path)
        self.enabled = enabled
        self.running = running
        self.last_tick_iso: Optional[str] = prior.get("last_tick_iso")
        self.items_categorized_total: int = int(prior.get("items_categorized_total", 0))
        self.last_error: Optional[str] = prior.get("last_error")
        # Deliberately NOT flushing on __init__: with multiple gunicorn workers the
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
            atomic_write_json(self.path, payload, prefix=".enricher.")
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


_LOCAL = threading.local()


def _fetch_batch(names, *, parallelism: int, stop_event: threading.Event):
    """Resolve metadata for `names` concurrently.

    Each worker thread gets its own requests.Session (sessions are not
    thread-safe) and paces itself after every lookup, so parallelism
    multiplies throughput within a short batch rather than hammering
    Wikipedia continuously. DB writes stay on the caller's thread — one
    writer at a time, same as before.
    """
    def _lookup(name):
        http = getattr(_LOCAL, "http", None)
        if http is None:
            http = requests.Session()
            _LOCAL.http = http
        try:
            status_code, payload = get_software_info(name, http)
        except Exception as exc:
            logger.warning("enricher: lookup error for %r: %s", name, exc)
            return None
        time.sleep(0.2)  # per-thread pacing toward the Wikipedia API
        if status_code == EnrichResult.HIT and payload:
            categories, desc = payload
            if categories or desc:
                return (name, categories, desc)
        if status_code in (EnrichResult.MISS, EnrichResult.HIT):  # HIT with no data counts as a miss
            return (name, None, None)
        return None  # transient: retry next tick without a cooldown

    hits = []
    with ThreadPoolExecutor(max_workers=max(1, int(parallelism)),
                            thread_name_prefix="enrich") as pool:
        futures = {pool.submit(_lookup, n): n for n in names}
        for fut in as_completed(futures):
            if stop_event.is_set():
                break
            try:
                hit = fut.result()
            except Exception as exc:
                logger.warning("enricher: lookup failed for %r: %s", futures[fut], exc)
                continue
            if hit:
                hits.append(hit)
    return hits


def _loop(driver_provider, status: _SharedStatus, *,
          interval_sec: float, batch_size: int,
          parallelism: int = 4,
          stop_event: threading.Event,
          trigger_path: str):
    last_trigger_seen = _trigger_mtime(trigger_path)
    # One-shot per leader start: drop enrichments written before the
    # software-relevance gate (idempotent, cheap once clean).
    try:
        driver = driver_provider()
        if driver is not None:
            purged = purge_non_software_descriptions(driver)
            if purged:
                logger.info("enricher: cleared %d non-software Wikipedia descriptions", len(purged))
    except Exception as exc:
        logger.warning("enricher: description purge skipped: %s", exc)
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
                    for name, categories, desc in _fetch_batch(
                            items, parallelism=parallelism, stop_event=stop_event):
                        if stop_event.is_set():
                            break
                        if categories is None and desc is None:
                            _mark_miss(driver, name)
                            continue
                        if _write_categories(driver, name, categories, desc):
                            enriched += 1
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
            last_trigger_seen = sleep_until(
                time.time() + max(1.0, float(interval_sec) - elapsed), trigger_path=trigger_path,
                last_trigger=last_trigger_seen, stop_event=stop_event)
    finally:
        status.update(running=False)
        logger.info("enricher: loop exited")


def start_worker(driver_provider, *,
                 interval_sec: int = 300,
                 batch_size: int = 25,
                 parallelism: int = 4,
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

    fd = try_acquire_lock(lock_path, "enricher")
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
            parallelism=int(parallelism),
            stop_event=stop_event,
            trigger_path=trigger_path,
        ),
        daemon=True,
    )
    t.start()
    logger.info("enricher: started (interval=%ss, batch=%d, parallelism=%d, lock=%s, trigger=%s, status=%s)",
                interval_sec, batch_size, parallelism, lock_path, trigger_path, status_path)
    return status, stop_event


def read_status(status_path: str = STATUS_PATH_DEFAULT) -> dict:
    """Read the cross-worker shared status. Returns sane defaults if missing."""
    data = _read_status(status_path)
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
    Returns (fired, retry_after_sec)."""
    return _fire_trigger(trigger_path, cooldown_sec=cooldown_sec, name="enricher")


def queue_remaining(driver_provider) -> int:
    """Cheap count of un-categorized software, used by /api/enricher/status."""
    drv = driver_provider() if callable(driver_provider) else driver_provider
    if drv is None:
        return 0
    return _queue_remaining(drv)
