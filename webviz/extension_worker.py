"""Leader-elected browser-extension intel worker.

Same cross-process contract as ``enrich_worker.py``:

* One Gunicorn worker wins an ``fcntl`` flock and runs the loop; the others
  fall through so store endpoints are never hammered four times in parallel.
* Status lives in a JSON file under ``/app/config`` so every worker's
  ``/api/extensions/status`` reads the same truth and counters survive
  restarts.
* Manual refresh travels via a tmpfs trigger-file mtime, so the trigger works
  no matter which worker handles the POST.

Data sources are the anonymous ones in ``src/extension_intel.py``. Every
network call is cached on disk and degrades to a local score when offline —
the worker must never be the reason ingestion or the API is unavailable.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

try:  # Docker layout: /app/webviz + /app/src on sys.path
    from src.extension_intel import (
        analyze_extension,
        fetch_mozilla_blocklist,
        fetch_store_metadata,
        match_blocklist,
        signals_json,
    )
except ImportError:  # repo layout: `python3 webviz/extension_worker.py`
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from src.extension_intel import (  # type: ignore
        analyze_extension,
        fetch_mozilla_blocklist,
        fetch_store_metadata,
        match_blocklist,
        signals_json,
    )

logger = logging.getLogger(__name__)

LOCK_PATH_DEFAULT = "/tmp/fleet-hound-extensions.lock"
TRIGGER_PATH_DEFAULT = "/tmp/fleet-hound-extensions.trigger"
STATUS_PATH_DEFAULT = "/app/config/extension_status.json"
CACHE_DIR_DEFAULT = "/app/config/extension_cache"

METADATA_TTL_SEC = 24 * 60 * 60
BLOCKLIST_TTL_SEC = 6 * 60 * 60
REFRESH_INTERVAL_SEC = 6 * 60 * 60

_TRIGGER_POLL_SEC = 1.0

_EXT_WHERE = "(s.kind = 'browser_extension' OR s.extension_key STARTS WITH 'ext:')"


def _atomic_write_json(path: str, payload: dict) -> None:
    parent = os.path.dirname(path) or "."
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError:
        pass
    try:
        fd, tmp = tempfile.mkstemp(prefix=".extensions.", suffix=".tmp", dir=parent)
    except OSError:
        return
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, separators=(",", ":"), default=str)
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


def _read_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _try_acquire_lock(lock_path: str):
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        os.close(fd)
        if exc.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
            logger.warning("extensions: lock acquisition failed: %s", exc)
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


def _cache_path(cache_dir: str, key: str) -> str:
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:20]
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in key)[:60]
    return os.path.join(cache_dir, f"{safe}-{digest}.json")


def _cache_get(cache_dir: str, key: str, ttl: float):
    path = _cache_path(cache_dir, key)
    try:
        if (time.time() - os.path.getmtime(path)) > ttl:
            return None
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _cache_set(cache_dir: str, key: str, value) -> None:
    if not isinstance(value, (dict, list)):
        return
    try:
        _atomic_write_json(_cache_path(cache_dir, key), value)
    except Exception as exc:  # noqa: BLE001 — cache is best-effort, but not silent
        logger.warning("extension cache write failed key=%s: %s", key, exc)


class _SharedStatus:
    def __init__(self, status_path: str, *, enabled: bool, running: bool):
        self.path = status_path
        self.lock = threading.Lock()
        prior = _read_json(status_path)
        self.enabled = enabled
        self.running = running
        self.last_tick_iso = prior.get("last_tick_iso")
        self.items_scored_total = int(prior.get("items_scored_total", 0) or 0)
        self.last_error = prior.get("last_error")
        self.last_cycle = prior.get("last_cycle")
        self.queue_remaining = int(prior.get("queue_remaining", 0) or 0)
        self.sources = prior.get("sources")

    def update(self, **fields):
        with self.lock:
            for key, value in fields.items():
                setattr(self, key, value)
            self._flush_locked()

    def flush_initial(self):
        with self.lock:
            self._flush_locked()

    def _flush_locked(self):
        _atomic_write_json(self.path, {
            "enabled": self.enabled,
            "running": self.running,
            "last_tick_iso": self.last_tick_iso,
            "items_scored_total": self.items_scored_total,
            "last_error": self.last_error,
            "last_cycle": self.last_cycle,
            "queue_remaining": self.queue_remaining,
            "sources": self.sources,
        })


def _total_hosts(driver) -> int:
    try:
        with driver.session() as session:
            rec = session.run("MATCH (h:Host) RETURN count(h) AS n").single()
        return int(rec["n"]) if rec else 0
    except Exception:
        return 0


def _pick_stale(driver, limit: int, cutoff_ts: float):
    query = f"""
        MATCH (s:Software)
        WHERE {_EXT_WHERE}
          AND (s.intel_refreshed_ts IS NULL OR s.intel_refreshed_ts < $cutoff)
        OPTIONAL MATCH (s)-[r:INSTALLED_ON]->(h:Host)
        WITH s, count(DISTINCT h) AS host_count,
             collect(DISTINCT r.version) AS versions,
             collect(DISTINCT h.hostname) AS hosts
        RETURN properties(s) AS props, host_count, versions, hosts
        ORDER BY host_count DESC
        LIMIT $limit
    """
    with driver.session() as session:
        return [dict(record) for record in session.run(
            query, cutoff=float(cutoff_ts), limit=int(limit)
        )]


def _group_rows(rows):
    """Group per-node rows by canonical extension key.

    A single extension can exist as several :Software nodes when Fleet reports
    different install paths/versions (the MERGE key is still `name`). Scoring
    once per canonical key and writing to every member node keeps the risk
    consistent and halves the store calls.
    """
    groups: dict[str, dict] = {}
    for row in rows:
        props = row.get("props") or {}
        key = props.get("extension_key") or f"name:{props.get('name')}"
        group = groups.setdefault(key, {
            "key": key,
            "names": [],
            "hostnames": set(),
            "versions": set(),
            "props": props,
        })
        group["names"].append(props.get("name"))
        for host in row.get("hosts") or []:
            if host:
                group["hostnames"].add(host)
        for version in row.get("versions") or []:
            if version:
                group["versions"].add(version)
    return list(groups.values())


class _StoreBreaker:
    """Per-cycle, thread-safe set of stores that answered 429 / 503+Retry-After.

    Once tripped, remaining items for that store are skipped (not fetched, not
    stamped) so they are retried next cycle instead of hammering the store.
    """

    # Chromium-family stores share the Chrome update2 endpoint.
    _ENDPOINT = {"brave": "chrome", "opera": "chrome", "vivaldi": "chrome", "chromium": "chrome"}

    def __init__(self):
        self._lock = threading.Lock()
        self._tripped: set[str] = set()

    def _key(self, store) -> str:
        store = str(store or "unknown").lower()
        return self._ENDPOINT.get(store, store)

    def is_tripped(self, store) -> bool:
        with self._lock:
            return self._key(store) in self._tripped

    def trip(self, store) -> bool:
        """Return True only for the call that tripped it (log once)."""
        key = self._key(store)
        with self._lock:
            if key in self._tripped:
                return False
            self._tripped.add(key)
            return True

    def tripped(self) -> list[str]:
        with self._lock:
            return sorted(self._tripped)


def _metadata_for(record: dict, cache_dir: str, breaker: _StoreBreaker | None = None):
    store = record.get("store") or "unknown"
    if record.get("is_builtin"):
        return {"store": store, "status": "builtin"}
    if not record.get("extension_id"):
        return {"store": store, "status": "unknown", "error": "missing extension id"}
    extension_id = record["extension_id"]
    version = record.get("last_version") or ""
    # v4: Chrome metadata gained `publisher_id` (trust is by ID); older entries lack it.
    cache_key = f"v4:{store}:{extension_id}:{version}"
    cached = _cache_get(cache_dir, cache_key, METADATA_TTL_SEC)
    if cached is not None:
        return cached
    if breaker is not None and breaker.is_tripped(store):
        return {"store": store, "status": "unknown", "rate_limited": True,
                "error": "store rate limited earlier this cycle; deferred"}
    meta = fetch_store_metadata(store, extension_id)
    if meta.get("rate_limited"):
        if breaker is not None and breaker.trip(store):
            logger.warning("extension worker: %s store rate limited (%s); deferring "
                           "its remaining items to next cycle", store, meta.get("error"))
        return meta
    if not meta.get("error") or meta.get("status") == "public":
        _cache_set(cache_dir, cache_key, meta)
    return meta


def _write_result(driver, names, result: dict, extension_key: str) -> bool:
    query = """
        UNWIND $names AS n
        MATCH (s:Software)
        WHERE s.name = n OR s.extension_key = n OR s.extension_key = $extension_key
        SET s.kind = 'browser_extension',
            s.extension_key = coalesce(s.extension_key, $extension_key),
            s.risk_score = $risk_score,
            s.risk_band = $risk_band,
            s.capability_score = $capability_score,
            s.trust_score = $trust_score,
            s.threat_score = $threat_score,
            s.exposure_score = $exposure_score,
            s.risk_signals_json = $risk_signals_json,
            s.store_status = $store_status,
            s.store_url = coalesce($store_url, s.store_url),
            s.publisher = coalesce($publisher, s.publisher),
            s.publisher_reputable = $publisher_reputable,
            s.known_bad = $known_bad,
            s.install_users = $install_users,
            s.latest_version = coalesce($latest_version, s.latest_version),
            s.rating = $rating,
            s.rating_count = $rating_count,
            s.store_category = $store_category,
            s.manifest_version = $manifest_version,
            s.permissions = $permissions,
            s.host_permissions = $host_permissions,
            s.content_script_matches = $content_script_matches,
            s.is_builtin = $is_builtin,
            s.intel_error = $intel_error,
            s.intel_refreshed_ts = $refreshed_ts,
            s.intel_refreshed_at = $refreshed_at
    """
    payload = dict(result)
    # Store taxonomy is NOT the software category: the enricher owns
    # s.category (Wikidata). Keep the store's classification in its own
    # field so the two never clobber each other.
    payload["store_category"] = payload.pop("category", None)
    payload.update({
        "names": list(names),
        "extension_key": extension_key,
        "risk_signals_json": signals_json(result.get("risk_signals")),
        "refreshed_ts": time.time(),
        "refreshed_at": datetime.now(timezone.utc).isoformat(),
    })
    with driver.session() as session:
        session.run(query, **payload).consume()
    return True


def _score_group(group, *, blocklist: dict, total_hosts: int, cache_dir: str,
                 stop_event: threading.Event, breaker: _StoreBreaker | None = None):
    """Fetch store metadata + score one extension identity (no DB writes).

    Safe to run in a thread pool: each group owns its record dict, cache
    files are keyed per extension, and the graph write happens later on the
    caller's thread.
    """
    props = group["props"]
    record = dict(props)
    record["host_count"] = len(group["hostnames"])
    record["versions"] = sorted(group["versions"])
    # Nodes predating the ingestion change have no `store`; recover it from
    # the canonical key so the right adapter is still chosen.
    if not record.get("store") and str(group["key"]).startswith("ext:"):
        record["store"] = str(group["key"]).split(":")[1]
    if stop_event.is_set():
        return group, None, None
    try:
        meta = _metadata_for(record, cache_dir, breaker)
        if meta.get("rate_limited"):
            # No result => not written, intel_refreshed_ts not advanced => retried next cycle.
            return group, None, None
        record["store_meta"] = meta
        versions = record["versions"] or [record.get("last_version")]
        result = analyze_extension(
            record,
            blocklist_entry=match_blocklist(
                blocklist, record.get("extension_id") or "", versions
            ),
            fleet_host_count=total_hosts,
        )
        return group, result, None
    except Exception as exc:  # noqa: BLE001 — surfaced as (group, None, exc)
        return group, None, exc


def _run_cycle(driver, status: _SharedStatus, *, batch_size: int,
               cache_dir: str, stop_event: threading.Event,
               parallelism: int = 4) -> dict:
    total_hosts = _total_hosts(driver)
    cutoff = time.time() - REFRESH_INTERVAL_SEC
    rows = _pick_stale(driver, batch_size, cutoff)
    groups = _group_rows(rows)

    blocklist = _cache_get(cache_dir, "mozilla:blocklist", BLOCKLIST_TTL_SEC)
    if not isinstance(blocklist, dict):
        blocklist = fetch_mozilla_blocklist()
        if blocklist:
            _cache_set(cache_dir, "mozilla:blocklist", blocklist)
        else:
            # Fetch failed: an expired list beats none. Scoring with {} drops
            # known-bad extensions below their risk floor for a full refresh window.
            blocklist = _cache_get(cache_dir, "mozilla:blocklist", float("inf"))
            if not isinstance(blocklist, dict):
                raise RuntimeError("Mozilla blocklist unavailable and no cached copy; skipping cycle")
            logger.warning("extension worker: blocklist fetch failed; using stale cache")

    scored = 0
    errors = 0
    deferred = 0
    breaker = _StoreBreaker()
    with ThreadPoolExecutor(max_workers=max(1, int(parallelism)),
                            thread_name_prefix="ext") as pool:
        futures = [
            pool.submit(_score_group, group, blocklist=blocklist,
                        total_hosts=total_hosts, cache_dir=cache_dir,
                        stop_event=stop_event, breaker=breaker)
            for group in groups
        ]
        for fut in as_completed(futures):
            try:
                group, result, exc = fut.result()
            except Exception as exc:
                errors += 1
                logger.warning("extension scoring failed: %s", exc)
                continue
            if exc is not None:
                errors += 1
                logger.warning("extension scoring failed key=%s: %s", group["key"], exc)
                continue
            if result is None:
                deferred += 1
                continue
            try:
                _write_result(driver, group["names"], result, group["key"])
                scored += 1
            except Exception as exc:  # noqa: BLE001 — one bad write must not kill the cycle
                errors += 1
                logger.warning("extension write failed key=%s: %s", group["key"], exc)

    remaining = 0
    try:
        remaining = queue_remaining(driver)
    except Exception:
        pass

    summary = {
        "groups_seen": len(groups),
        "scored": scored,
        "errors": errors,
        "deferred": deferred,
        "rate_limited_stores": breaker.tripped(),
        "total_hosts": total_hosts,
        "blocklist_entries": len(blocklist),
        "tick_iso": datetime.now(timezone.utc).isoformat(),
    }
    status.update(
        items_scored_total=status.items_scored_total + scored,
        queue_remaining=remaining,
        last_cycle=summary,
        sources={
            "mozilla_blocklist": bool(blocklist),
            "store_metadata": True,
        },
    )
    return summary


def _loop(driver_provider, status: _SharedStatus, *, interval_sec: float,
          batch_size: int, cache_dir: str, stop_event: threading.Event,
          trigger_path: str, parallelism: int = 4):
    last_trigger = _trigger_mtime(trigger_path)
    while not stop_event.is_set():
        tick_start = time.time()
        try:
            driver = driver_provider() if callable(driver_provider) else driver_provider
            if driver is None:
                status.update(last_error="database unavailable")
            else:
                _run_cycle(driver, status, batch_size=batch_size, cache_dir=cache_dir,
                           stop_event=stop_event, parallelism=parallelism)
                status.update(last_error=None)
        except Exception as exc:
            logger.error("extensions: cycle failed: %s", exc, exc_info=True)
            status.update(last_error=str(exc))

        # Sleep in small slices so a manual trigger is picked up quickly while
        # still honouring the configured interval.
        remaining = max(1.0, interval_sec - (time.time() - tick_start))
        deadline = time.time() + remaining
        while not stop_event.is_set() and time.time() < deadline:
            mtime = _trigger_mtime(trigger_path)
            if mtime > last_trigger:
                last_trigger = mtime
                break
            time.sleep(_TRIGGER_POLL_SEC)
    status.update(running=False)
    logger.info("extensions: loop exited")


def start_worker(driver_provider, *, interval_sec: int = REFRESH_INTERVAL_SEC,
                 batch_size: int = 50,
                 parallelism: int = 4,
                 lock_path: str = LOCK_PATH_DEFAULT,
                 trigger_path: str = TRIGGER_PATH_DEFAULT,
                 status_path: str = STATUS_PATH_DEFAULT,
                 cache_dir: str = CACHE_DIR_DEFAULT,
                 enabled: bool = True):
    """Boot the extension worker. Returns (status, stop_event)."""
    status = _SharedStatus(status_path, enabled=enabled, running=False)
    stop_event = threading.Event()
    if not enabled:
        logger.info("extensions: disabled via EXTENSION_WORKER_ENABLED=false")
        return status, stop_event

    fd = _try_acquire_lock(lock_path)
    if fd is None:
        logger.info("extensions: another worker holds %s; not starting loop", lock_path)
        return status, stop_event

    status.update(running=True)
    thread = threading.Thread(
        target=_loop,
        name="fleet-hound-extensions",
        args=(driver_provider, status),
        kwargs=dict(
            interval_sec=float(interval_sec),
            batch_size=int(batch_size),
            cache_dir=cache_dir,
            stop_event=stop_event,
            trigger_path=trigger_path,
            parallelism=int(parallelism),
        ),
        daemon=True,
    )
    thread.start()
    logger.info(
        "extensions: started (interval=%ss, batch=%d, parallelism=%d, cache=%s, lock=%s)",
        interval_sec, batch_size, parallelism, cache_dir, lock_path,
    )
    return status, stop_event


def read_status(status_path: str = STATUS_PATH_DEFAULT) -> dict:
    data = _read_json(status_path)
    return {
        "enabled": bool(data.get("enabled", False)),
        "running": bool(data.get("running", False)),
        "last_tick_iso": data.get("last_tick_iso"),
        "items_scored_total": int(data.get("items_scored_total", 0) or 0),
        "last_error": data.get("last_error"),
        "last_cycle": data.get("last_cycle"),
        "queue_remaining": int(data.get("queue_remaining", 0) or 0),
        "sources": data.get("sources"),
    }


def fire_trigger(trigger_path: str = TRIGGER_PATH_DEFAULT, *,
                 cooldown_sec: float = 30.0) -> tuple[bool, float]:
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
        logger.error("extensions: trigger touch failed: %s", exc)
        return False, 0.0
    return True, 0.0


def queue_remaining(driver_provider) -> int:
    driver = driver_provider() if callable(driver_provider) else driver_provider
    if driver is None:
        return 0
    cutoff = time.time() - REFRESH_INTERVAL_SEC
    try:
        with driver.session() as session:
            rec = session.run(
                f"""
                MATCH (s:Software)
                WHERE {_EXT_WHERE}
                  AND (s.intel_refreshed_ts IS NULL OR s.intel_refreshed_ts < $cutoff)
                RETURN count(s) AS n
                """,
                cutoff=float(cutoff),
            ).single()
        return int(rec["n"]) if rec else 0
    except Exception:
        return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(read_status(), indent=2))
