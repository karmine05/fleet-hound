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

import hashlib
import json
import logging
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

try:  # Docker layout: /app/webviz + /app/src on sys.path
    from src.extension_intel import (
        CHROMIUM_STORES,
        SCORER_VERSION,
        _known_publishers_path,
        analyze_extension,
        compare_versions,
        fetch_chrome_listings,
        fetch_chrome_metadata,
        fetch_mozilla_blocklist,
        fetch_store_metadata,
        fetch_threat_feed,
        is_browser_builtin,
        NOT_MODIFIED,
        load_threat_feeds,
        match_blocklist,
        match_threat_feeds,
        signals_json,
    )
except ImportError:  # repo layout: `python3 webviz/extension_worker.py`
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from src.extension_intel import (  # type: ignore
        CHROMIUM_STORES,
        SCORER_VERSION,
        _known_publishers_path,
        analyze_extension,
        compare_versions,
        fetch_chrome_listings,
        fetch_chrome_metadata,
        fetch_mozilla_blocklist,
        fetch_store_metadata,
        fetch_threat_feed,
        is_browser_builtin,
        NOT_MODIFIED,
        load_threat_feeds,
        match_blocklist,
        match_threat_feeds,
        signals_json,
    )

try:  # Docker layout: /app/webviz on sys.path
    from worker_util import (atomic_write_json, fire_trigger as _fire_trigger, read_json,
                             sleep_until, trigger_mtime as _trigger_mtime, try_acquire_lock)
except ImportError:  # imported as the webviz package
    from webviz.worker_util import (atomic_write_json, fire_trigger as _fire_trigger,  # type: ignore
                                    read_json, sleep_until, trigger_mtime as _trigger_mtime,
                                    try_acquire_lock)

logger = logging.getLogger(__name__)

LOCK_PATH_DEFAULT = "/tmp/fleet-hound-extensions.lock"
TRIGGER_PATH_DEFAULT = "/tmp/fleet-hound-extensions.trigger"
STATUS_PATH_DEFAULT = "/app/config/extension_status.json"
CACHE_DIR_DEFAULT = "/app/config/extension_cache"

# Chrome-family listings come from one batched RPC, so a weekly refresh is
# cheap and doubles as the takedown check. Edge/AMO are one call per item.
LISTING_TTL_CHROME_SEC = 7 * 24 * 60 * 60
LISTING_TTL_MIN_SEC = 21 * 24 * 60 * 60
LISTING_TTL_JITTER_SEC = 7 * 24 * 60 * 60
BLOCKLIST_TTL_SEC = 6 * 60 * 60
REFRESH_INTERVAL_SEC = 6 * 60 * 60

_EXT_WHERE = "(s.kind = 'browser_extension' OR s.extension_key STARTS WITH 'ext:')"

_CHROME_FAMILY = CHROMIUM_STORES - {"edge"}
_ADAPTER_STORES = CHROMIUM_STORES | {"firefox"}
# Package-derived fields of one immutable version, cached forever.
_MANIFEST_FIELDS = ("manifest_version", "permissions", "optional_permissions",
                    "host_permissions", "content_script_matches", "update_url",
                    "homepage_url", "crx_hash_verified")


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


def _cache_touch(cache_dir: str, key: str) -> None:
    """Restart the TTL of a cached copy the server confirmed unchanged (304)."""
    try:
        os.utime(_cache_path(cache_dir, key))
    except OSError as exc:
        logger.warning("extension cache touch failed key=%s: %s", key, exc)


def _conditional_fetch(cache_dir: str, key: str, fetch):
    """Refresh one expired cached document with a conditional GET.

    Returns (document or None, fetched_fresh). The ETag lives next to the
    copy under `<key>:meta` and is sent only while a copy exists to reuse.
    """
    stale = _cache_get(cache_dir, key, float("inf"))
    meta = _cache_get(cache_dir, f"{key}:meta", float("inf")) if stale is not None else None
    validators = {"etag": meta["etag"]} if isinstance(meta, dict) and meta.get("etag") else {}
    result = fetch(validators)
    if result is NOT_MODIFIED:
        _cache_touch(cache_dir, key)
        return stale, False
    if result:
        _cache_set(cache_dir, key, result)
        if validators.get("etag"):
            _cache_set(cache_dir, f"{key}:meta", validators)
        return result, True
    return None, False


def _cache_set(cache_dir: str, key: str, value) -> None:
    if not isinstance(value, (dict, list)):
        return
    try:
        atomic_write_json(_cache_path(cache_dir, key), value, prefix=".extensions.")
    except Exception as exc:  # noqa: BLE001 — cache is best-effort, but not silent
        logger.warning("extension cache write failed key=%s: %s", key, exc)


class _SharedStatus:
    def __init__(self, status_path: str, *, enabled: bool, running: bool):
        self.path = status_path
        self.lock = threading.Lock()
        prior = read_json(status_path, {})
        prior = prior if isinstance(prior, dict) else {}
        self.enabled = enabled
        self.running = running
        self.last_tick_iso = prior.get("last_tick_iso")
        self.items_scored_total = int(prior.get("items_scored_total", 0) or 0)
        self.last_error = prior.get("last_error")
        self.last_cycle = prior.get("last_cycle")
        self.queue_remaining = int(prior.get("queue_remaining", 0) or 0)
        self.sources = prior.get("sources")
        self.threat_feeds = prior.get("threat_feeds") or []
        self.coverage = prior.get("coverage") or []

    def update(self, **fields):
        with self.lock:
            for key, value in fields.items():
                setattr(self, key, value)
            self._flush_locked()

    def flush_initial(self):
        with self.lock:
            self._flush_locked()

    def _flush_locked(self):
        try:
            self._write_locked()
        except OSError as exc:  # e.g. read-only config: keep the loop alive, say so
            logger.warning("extensions: status flush failed: %s", exc)

    def _write_locked(self):
        atomic_write_json(self.path, {
            "enabled": self.enabled,
            "running": self.running,
            "last_tick_iso": self.last_tick_iso,
            "items_scored_total": self.items_scored_total,
            "last_error": self.last_error,
            "last_cycle": self.last_cycle,
            "queue_remaining": self.queue_remaining,
            "sources": self.sources,
            "threat_feeds": self.threat_feeds,
            "coverage": self.coverage,
        }, prefix=".extensions.")


def _total_hosts(driver) -> int:
    # Raises: scoring with 0 would drop rare-in-fleet from every node at once.
    with driver.session() as session:
        rec = session.run("MATCH (h:Host) RETURN count(h) AS n").single()
    return int(rec["n"]) if rec else 0


def _cache_age(cache_dir: str, key: str) -> float | None:
    try:
        return time.time() - os.path.getmtime(_cache_path(cache_dir, key))
    except OSError:
        return None


# Bump a version when the cached shape changes; prune_cache() deletes the
# files of every other version. v12: listings carry integer privacy_codes.
LISTING_KEY_VERSION = "v12"
MANIFEST_KEY_VERSION = "v11"


def _listing_key(store: str, extension_id: str) -> str:
    return f"{LISTING_KEY_VERSION}:listing:{store}:{extension_id}"


def _manifest_key(store: str, extension_id: str, version: str) -> str:
    return f"{MANIFEST_KEY_VERSION}:manifest:{store}:{extension_id}:{version}"


_VERSIONED_CACHE_RE = re.compile(r"v\d+_")


def prune_cache(cache_dir: str) -> int:
    """Delete listing/manifest files of retired key versions. Returns the count.

    Only `v<N>_*` files are candidates, so feed and blocklist copies and any
    unknown file are never touched.
    """
    live = (f"{LISTING_KEY_VERSION}_listing_", f"{MANIFEST_KEY_VERSION}_manifest_")
    removed = 0
    try:
        names = os.listdir(cache_dir)
    except OSError as exc:
        logger.warning("extensions: cannot list cache %s: %s", cache_dir, exc)
        return 0
    for name in names:
        if _VERSIONED_CACHE_RE.match(name) and not name.startswith(live):
            try:
                os.unlink(os.path.join(cache_dir, name))
                removed += 1
            except OSError as exc:
                logger.warning("extensions: cannot prune %s: %s", name, exc)
    return removed


def _listing_ttl(store: str, extension_id: str) -> float:
    if store in _CHROME_FAMILY:
        return LISTING_TTL_CHROME_SEC
    # Stable per-ID jitter spreads Edge/AMO refreshes over a week instead of one burst.
    jitter = int(hashlib.sha1(extension_id.encode("utf-8")).hexdigest()[:8], 16)
    return LISTING_TTL_MIN_SEC + jitter % (LISTING_TTL_JITTER_SEC + 1)


def _digest(value) -> str:
    return hashlib.sha1(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                   default=str).encode("utf-8")).hexdigest()


def _file_digest(path) -> str | None:
    if not path:
        return None
    try:
        with open(path, "rb") as fh:
            return hashlib.sha1(fh.read()).hexdigest()
    except OSError:
        return None


def _all_groups(driver) -> list[dict]:
    """Every extension identity, grouped by canonical key in the query.

    A single extension can exist as several :Software nodes when Fleet reports
    different install paths/versions (the MERGE key is still `name`). Scoring
    once per canonical key and writing to every member node keeps the risk
    consistent and halves the store calls. Hosts are counted, not collected.
    """
    query = f"""
        MATCH (s:Software)
        WHERE {_EXT_WHERE}
        OPTIONAL MATCH (s)-[r:INSTALLED_ON]->(h:Host)
        WITH coalesce(s.extension_key, 'name:' + s.name) AS key,
             collect(DISTINCT s) AS nodes,
             count(DISTINCT h) AS host_count,
             collect(DISTINCT r.version) AS versions,
             collect(DISTINCT {{path: r.installed_path, platform: h.platform}}) AS installs
        RETURN key, [n IN nodes | properties(n)] AS members, host_count, versions, installs
        ORDER BY host_count DESC
    """
    with driver.session() as session:
        rows = [dict(record) for record in session.run(query)]
    groups = []
    for row in rows:
        members = [m for m in row.get("members") or [] if isinstance(m, dict)]
        if not members:
            continue
        installs = {(i.get("path"), i.get("platform"))
                    for i in row.get("installs") or [] if isinstance(i, dict)}
        groups.append({
            "key": row["key"],
            "props": members[0],
            "fingerprints": {m.get("intel_fingerprint") for m in members},
            "host_count": int(row.get("host_count") or 0),
            "versions": sorted({str(v) for v in row.get("versions") or [] if v}),
            # Keep path-less installs: store trust fails closed on them.
            "installs": sorted(installs, key=lambda t: (t[0] or "", t[1] or "")),
        })
    return groups


def _record_for(group: dict) -> dict:
    record = dict(group["props"])
    record["host_count"] = group["host_count"]
    record["versions"] = list(group["versions"])
    # Per-host installs: store trust needs every install to be a store install.
    record["installs"] = [{"path": p, "platform": pl} for p, pl in group["installs"]]
    # Nodes predating the ingestion change have no `store`; recover it from
    # the canonical key so the right adapter is still chosen.
    if not record.get("store") and str(group["key"]).startswith("ext:"):
        record["store"] = str(group["key"]).split(":")[1]
    # Current rules, not the flag ingestion stored at the host's last ingest.
    record["is_builtin"] = is_browser_builtin(record)
    return record


def _fingerprint(record: dict, *, total_hosts: int, threat_digest: str,
                 publishers_digest: str | None) -> str:
    """Hash of every scoring input except the store listing (see _with_listing)."""
    # Only the rare-in-fleet verdict, not the raw count: one enrolment would
    # otherwise change every fingerprint in the fleet.
    rare = total_hosts >= 10 and record["host_count"] / total_hosts < 0.03
    return _digest([SCORER_VERSION, record.get("store"), record.get("extension_id"),
                    record["versions"], [[i["path"], i["platform"]] for i in record["installs"]],
                    record["host_count"], rare, threat_digest, publishers_digest,
                    # Ingestion-owned node fields the scorer reads.
                    record.get("name"), record.get("display_name"), record.get("vendor"),
                    bool(record.get("is_builtin")), record.get("installed_paths"),
                    record.get("max_cvss"), record.get("vulnerabilities")])


def _with_listing(fingerprint: str, record: dict, cache_dir: str) -> str:
    """Fold the cached listing in, so a refreshed listing that never reached the
    graph (failed write, restart) still differs from the node next cycle."""
    store = str(record.get("store") or "").lower()
    extension_id = record.get("extension_id") or ""
    cached = (_cache_get(cache_dir, _listing_key(store, extension_id), float("inf"))
              if extension_id and store in _ADAPTER_STORES else None)
    return _digest([fingerprint, cached])


def _listing_due(record: dict, cache_dir: str, *, new_hit: bool) -> bool:
    """Whether this identity needs a store call: no cached listing, a host runs
    a newer version than the listing that was not already seen at the last
    fetch, a new blocklist/feed hit, or TTL expiry."""
    store = str(record.get("store") or "").lower()
    extension_id = record.get("extension_id") or ""
    if record.get("is_builtin") or not extension_id or store not in _ADAPTER_STORES:
        return False
    key = _listing_key(store, extension_id)
    cached = _cache_get(cache_dir, key, float("inf"))
    age = _cache_age(cache_dir, key)
    if cached is None or age is None or new_hit or age > _listing_ttl(store, extension_id):
        return True
    latest = cached.get("version")
    # A store that stays behind (dev build, lagging listing) must not be refetched every cycle.
    seen = set(cached.get("host_versions") or [])
    return bool(latest) and any(compare_versions(v, str(latest)) > 0
                                for v in record["versions"] if v not in seen)


def _plan(groups, *, cache_dir: str, blocklist: dict, feed_index: dict,
          total_hosts: int, publishers_digest: str | None) -> list[dict]:
    """Work items for groups whose fingerprint changed or whose listing is due."""
    work = []
    for group in groups:
        record = _record_for(group)
        extension_id = record.get("extension_id") or ""
        entry = match_blocklist(blocklist, extension_id,
                                record["versions"] or [record.get("last_version")])
        hits = match_threat_feeds(feed_index or {}, record.get("store") or "", extension_id)
        base = _fingerprint(record, total_hosts=total_hosts,
                            threat_digest=_digest([entry, hits]),
                            publishers_digest=publishers_digest)
        fingerprint = _with_listing(base, record, cache_dir)
        sig = group["props"].get("risk_signals_json") or ""
        new_hit = (entry is not None and not group["props"].get("known_bad")) or any(
            f'"threat-feed:{h["feed"]}"' not in sig for h in hits)
        due = _listing_due(record, cache_dir, new_hit=new_hit)
        changed = group["fingerprints"] != {fingerprint}
        if due or changed:
            work.append({"group": group, "record": record, "fingerprint": fingerprint, "base": base,
                         "due": due, "changed": changed,
                         "blocklist_entry": entry, "feed_hits": hits})
    return work


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


def _listing_for(record: dict, cache_dir: str, *, due: bool, breaker: _StoreBreaker,
                 prefetched: dict | None = None):
    """(store meta, state); state is local, cached, fetched, failed, stale or
    deferred.

    The store is asked only when `due`. A failed refetch falls back to the
    last good listing, flagged in intel_error, so offline never drops data.
    A rate-limited store yields the last good listing as "stale", or the
    "deferred" stub when there is none.
    """
    store = str(record.get("store") or "unknown").lower()
    if record.get("is_builtin"):
        return {"store": store, "status": "builtin"}, "local"
    extension_id = record.get("extension_id")
    if not extension_id:
        return {"store": store, "status": "unknown", "error": "missing extension id"}, "local"
    if store not in _ADAPTER_STORES:
        return {"store": store, "status": "unknown",
                "error": f"no anonymous metadata adapter for store '{store}'"}, "local"
    key = _listing_key(store, extension_id)
    cached = _cache_get(cache_dir, key, float("inf"))
    if cached is not None and not due:
        return cached, "cached"
    deferred = {"store": store, "status": "unknown", "rate_limited": True,
                "error": "store rate limited; listing refresh deferred"}
    if breaker.is_tripped(store):
        return ({**cached, "error": deferred["error"]}, "stale") if cached is not None \
            else (deferred, "deferred")

    def manifest_for(version):
        return _cache_get(cache_dir, _manifest_key(store, extension_id, version), float("inf"))

    if prefetched is None:
        meta = fetch_store_metadata(store, extension_id, manifest_for=manifest_for)
    elif prefetched.get("listing_missing"):
        # Not in the listing RPC: update2 tells unlisted from removed.
        meta = fetch_chrome_metadata(extension_id, listing=prefetched, manifest_for=manifest_for)
    else:
        meta = dict(prefetched)
    if meta.get("rate_limited"):
        if breaker.trip(store):
            logger.warning("extension worker: %s store rate limited (%s); deferring "
                           "its remaining items to next cycle", store, meta.get("error"))
        return ({**cached, "error": deferred["error"]}, "stale") if cached is not None \
            else (meta, "deferred")
    if meta.get("status") != "unknown" or not meta.get("error"):
        _cache_set(cache_dir, key, {**meta, "host_versions": list(record.get("versions") or [])})
        version = _clean_version(meta.get("version"))
        if version and meta.get("manifest_version") and not (
                meta.get("manifest_error") or meta.get("manifest_unavailable")):
            _cache_set(cache_dir, _manifest_key(store, extension_id, version),
                       {f: meta[f] for f in _MANIFEST_FIELDS if meta.get(f) not in (None, [], "")})
        return meta, "fetched"
    if cached is not None:
        return {**cached, "error": f"refresh failed ({meta.get('error')}); using cached listing"}, "failed"
    return meta, "failed"


def _clean_version(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _chrome_due(item: dict) -> bool:
    record = item["record"]
    return (item["due"] and not record.get("is_builtin") and bool(record.get("extension_id"))
            and str(record.get("store") or "").lower() in _CHROME_FAMILY)


def _prefetch_chrome(chunk, breaker: _StoreBreaker) -> dict[str, dict]:
    """One batched listing RPC for every due Chrome-family item in the chunk."""
    ids = [item["record"]["extension_id"] for item in chunk if _chrome_due(item)]
    if not ids or breaker.is_tripped("chrome"):
        return {}
    listings = fetch_chrome_listings(ids)
    if any(m.get("rate_limited") for m in listings.values()) and breaker.trip("chrome"):
        logger.warning("extension worker: chrome listing RPC rate limited; deferring "
                       "Chrome-family items to next cycle")
    return listings


LISTING_FIELDS = ("updated_at", "featured", "established_publisher", "developer_verified",
                  "developer_email", "developer_website", "trader",
                  "privacy_disclosure", "privacy_policy_url")


def _score_item(item: dict, *, cache_dir: str, total_hosts: int,
                stop_event: threading.Event, breaker: _StoreBreaker,
                prefetched: dict | None = None):
    """Fetch (if due) and score one extension identity (no DB writes).

    Returns (item, result or None, state, exc). No result means nothing to
    write: deferred with no local verdict to publish, or nothing changed and
    the listing was neither refreshed nor failed to refresh.
    Thread-safe: cache files are keyed per extension and writes happen later
    on the caller's thread.
    """
    if stop_event.is_set():
        return item, None, "deferred", None
    try:
        record = dict(item["record"])
        meta, state = _listing_for(record, cache_dir, due=item["due"], breaker=breaker,
                                   prefetched=prefetched)
        local_hit = item["blocklist_entry"] is not None or bool(item["feed_hits"])
        if state == "deferred" and not (item["changed"] and local_hit):
            return item, None, state, None
        # A failed refresh is written so intel_error shows the broken adapter.
        if state in ("cached", "local", "stale") and not item["changed"]:
            return item, None, state, None
        # The refetch may have replaced the cached listing.
        item["fingerprint"] = _with_listing(item["base"], record, cache_dir)
        record["store_meta"] = meta
        result = analyze_extension(record, blocklist_entry=item["blocklist_entry"],
                                   feed_hits=item["feed_hits"], fleet_host_count=total_hosts)
        return item, result, state, None
    except Exception as exc:  # noqa: BLE001 — surfaced as (item, None, "error", exc)
        return item, None, "error", exc


_WRITE_SET = """
        SET s.kind = 'browser_extension',
            s.extension_key = coalesce(s.extension_key, row.key),
            s.risk_score = row.risk_score,
            s.risk_band = row.risk_band,
            s.capability_score = row.capability_score,
            s.trust_score = row.trust_score,
            s.threat_score = row.threat_score,
            s.exposure_score = row.exposure_score,
            s.risk_signals_json = row.risk_signals_json,
            s.store_status = row.store_status,
            s.store_url = coalesce(row.store_url, s.store_url),
            s.publisher = coalesce(row.publisher, s.publisher),
            s.publisher_reputable = row.publisher_reputable,
            s.known_bad = row.known_bad,
            s.install_users = row.install_users,
            s.latest_version = coalesce(row.latest_version, s.latest_version),
            s.display_name = CASE WHEN row.store_name IS NOT NULL
                                   AND coalesce(s.display_name, '__MSG_') STARTS WITH '__MSG_'
                              THEN row.store_name ELSE s.display_name END,
            s.rating = row.rating,
            s.rating_count = row.rating_count,
            s.store_category = row.store_category,
            s.manifest_version = row.manifest_version,
            s.permissions = row.permissions,
            s.host_permissions = row.host_permissions,
            s.content_script_matches = row.content_script_matches,
            s.store_updated_at = row.updated_at,
            s.store_featured = row.featured,
            s.established_publisher = row.established_publisher,
            s.developer_verified = row.developer_verified,
            s.developer_email = row.developer_email,
            s.developer_website = row.developer_website,
            s.trader = row.trader,
            s.privacy_disclosure = row.privacy_disclosure,
            s.privacy_policy_url = row.privacy_policy_url,
            s.is_builtin = row.is_builtin,
            s.intel_error = row.intel_error,
            s.intel_fingerprint = row.intel_fingerprint,
            s.intel_refreshed_ts = row.refreshed_ts,
            s.intel_refreshed_at = row.refreshed_at
"""
# One indexed property per MATCH: an OR across properties defeats the index.
_WRITE_BY_KEY = "UNWIND $rows AS row MATCH (s:Software {extension_key: row.key})" + _WRITE_SET
_WRITE_BY_NAME = ("UNWIND $rows AS row MATCH (s:Software {name: row.name}) "
                  "WHERE s.kind = 'browser_extension' AND coalesce(s.extension_key, row.key) = row.key"
                  + _WRITE_SET)


def _row_for(key: str, result: dict, fingerprint: str) -> dict:
    row = dict(result)
    # Store taxonomy is NOT the software category: the enricher owns
    # s.category (Wikidata). Keep the store's classification in its own
    # field so the two never clobber each other.
    row["store_category"] = row.pop("category", None)
    # Built-in results carry no store listing; write NULL for those fields.
    for field in LISTING_FIELDS:
        row.setdefault(field, None)
    row.update({
        "key": key,
        # Legacy groups have no extension_key; their members share the name.
        "name": key[len("name:"):] if key.startswith("name:") else None,
        "risk_signals_json": signals_json(result.get("risk_signals")),
        "intel_fingerprint": fingerprint,
        "refreshed_ts": time.time(),
        "refreshed_at": datetime.now(timezone.utc).isoformat(),
    })
    row.pop("risk_signals", None)
    for field, value in row.items():
        # Neo4j rejects the whole UNWIND batch on one out-of-int64 parameter.
        if type(value) is int and not -2 ** 63 <= value < 2 ** 63:
            row[field] = None
    return row


def _write_rows(driver, rows: list[dict]) -> None:
    by_name = [r for r in rows if r["name"] is not None]
    by_key = [r for r in rows if r["name"] is None]
    # Managed transactions retry Memgraph's TransientError ("conflicting
    # transactions"), which a concurrent ETL write to the same nodes raises.
    with driver.session() as session:
        if by_key:
            session.execute_write(lambda tx: tx.run(_WRITE_BY_KEY, rows=by_key).consume())
        if by_name:
            session.execute_write(lambda tx: tx.run(_WRITE_BY_NAME, rows=by_name).consume())


def _load_feed_index(cache_dir: str) -> tuple[dict, list[dict]]:
    """{feed_name: {"platform", "entries"}} plus per-feed health for status.

    A failed fetch falls back to the last good copy; a feed with no copy at
    all is reported, not fatal, so one dead feed never stops scoring.
    """
    index, health = {}, []
    for feed in load_threat_feeds():
        key = f"feed:{feed['name']}"
        entries = _cache_get(cache_dir, key, BLOCKLIST_TTL_SEC)
        error = None
        if not isinstance(entries, dict):
            entries, _ = _conditional_fetch(
                cache_dir, key, lambda v, feed=feed: fetch_threat_feed(feed, validators=v))
            if entries is None:
                error = "fetch failed"
                entries = _cache_get(cache_dir, key, float("inf"))
                if isinstance(entries, dict):
                    error = "fetch failed; using stale copy"
        if isinstance(entries, dict):
            index[feed["name"]] = {"platform": feed["platform"], "entries": entries}
        health.append({"name": feed["name"], "platform": feed["platform"],
                       "entries": len(entries) if isinstance(entries, dict) else 0,
                       "error": error})
    return index, health


def _coverage(driver) -> list[dict]:
    """Per-store enrichment fill rates, so a broken adapter shows up in status
    on its own instead of being noticed one extension at a time."""
    with driver.session() as session:
        rows = session.run(f"""
            MATCH (s:Software) WHERE {_EXT_WHERE}
              AND (NOT coalesce(s.is_builtin, false) OR coalesce(s.risk_score, 0) > 0)
            WITH coalesce(s.store, 'unknown') AS store, s
            RETURN store,
                   count(s) AS total,
                   count(s.extension_id) AS with_id,
                   sum(CASE WHEN s.store_status = 'public' THEN 1 ELSE 0 END) AS listed,
                   count(s.install_users) AS with_users,
                   count(s.rating) AS with_rating,
                   count(s.manifest_version) AS manifest_parsed,
                   count(s.developer_email) AS with_email,
                   sum(CASE WHEN s.risk_signals_json CONTAINS 'manifest-uninspected' THEN 1 ELSE 0 END) AS uninspected,
                   sum(CASE WHEN s.risk_signals_json CONTAINS 'threat-feed:' THEN 1 ELSE 0 END) AS feed_hits,
                   collect(DISTINCT s.intel_error)[..5] AS errors
            ORDER BY total DESC
        """).data()
    for row in rows:
        row["errors"] = [e for e in row.get("errors") or [] if e]
    return rows


def _load_blocklist(cache_dir: str) -> dict:
    blocklist = _cache_get(cache_dir, "mozilla:blocklist", BLOCKLIST_TTL_SEC)
    if isinstance(blocklist, dict):
        return blocklist
    blocklist, _ = _conditional_fetch(cache_dir, "mozilla:blocklist",
                                      lambda v: fetch_mozilla_blocklist(validators=v))
    if blocklist:
        return blocklist
    # Fetch failed: an expired list beats none. Scoring with {} drops
    # known-bad extensions below their risk floor for a full refresh window.
    blocklist = _cache_get(cache_dir, "mozilla:blocklist", float("inf"))
    if not isinstance(blocklist, dict):
        raise RuntimeError("Mozilla blocklist unavailable and no cached copy; skipping cycle")
    logger.warning("extension worker: blocklist fetch failed; using stale cache")
    return blocklist


def _run_cycle(driver, status: _SharedStatus, *, batch_size: int,
               cache_dir: str, stop_event: threading.Event,
               parallelism: int = 4) -> dict:
    total_hosts = _total_hosts(driver)
    feed_index, feed_health = _load_feed_index(cache_dir)
    blocklist = _load_blocklist(cache_dir)
    groups = _all_groups(driver)
    work = _plan(groups, cache_dir=cache_dir, blocklist=blocklist, feed_index=feed_index,
                 total_hosts=total_hosts,
                 publishers_digest=_file_digest(_known_publishers_path()))
    status.update(queue_remaining=len(work))

    scored = errors = deferred = cache_hits = skipped = done = 0
    fetched: dict[str, int] = {}
    failed: dict[str, int] = {}
    breaker = _StoreBreaker()
    batch_size = max(1, int(batch_size))
    # Drain the whole due set this cycle, one chunk (prefetch, score, write) at a time.
    with ThreadPoolExecutor(max_workers=max(1, int(parallelism)),
                            thread_name_prefix="ext") as pool:
        for start in range(0, len(work), batch_size):
            if stop_event.is_set():
                break
            chunk = work[start:start + batch_size]
            prefetched = _prefetch_chrome(chunk, breaker)
            futures = [
                pool.submit(_score_item, item, cache_dir=cache_dir, total_hosts=total_hosts,
                            stop_event=stop_event, breaker=breaker,
                            prefetched=prefetched.get(item["record"]["extension_id"])
                            if _chrome_due(item) else None)
                for item in chunk
            ]
            rows = []
            for fut in as_completed(futures):
                item, result, state, exc = fut.result()
                store = str(item["record"].get("store") or "unknown").lower()
                if state == "fetched":
                    fetched[store] = fetched.get(store, 0) + 1
                elif state == "failed":
                    failed[store] = failed.get(store, 0) + 1
                if exc is not None:
                    errors += 1
                    logger.warning("extension scoring failed key=%s: %s", item["group"]["key"], exc)
                elif result is not None:
                    cache_hits += state == "cached"
                    rows.append(_row_for(item["group"]["key"], result, item["fingerprint"]))
                elif state in ("deferred", "stale"):
                    # No write keeps the old fingerprint, so it is retried next cycle.
                    deferred += 1
                else:
                    cache_hits += state == "cached"
                    skipped += 1
                    done += 1
            if rows:
                try:
                    _write_rows(driver, rows)
                    scored += len(rows)
                    done += len(rows)
                except Exception as exc:  # noqa: BLE001 — one bad chunk must not kill the cycle
                    errors += len(rows)
                    logger.warning("extension write failed for %d groups: %s", len(rows), exc)
            status.update(queue_remaining=len(work) - done)

    summary = {
        "groups_seen": len(groups),
        "due": len(work),
        "scored": scored,
        "unchanged_skipped": len(groups) - len(work) + skipped,
        "cache_hits": cache_hits,
        "fetched": fetched,
        "refresh_failed": failed,
        "errors": errors,
        "deferred": deferred,
        "rate_limited_stores": breaker.tripped(),
        "total_hosts": total_hosts,
        "blocklist_entries": len(blocklist),
        "tick_iso": datetime.now(timezone.utc).isoformat(),
    }
    try:
        coverage = _coverage(driver)
    except Exception as exc:  # noqa: BLE001 — health reporting must not fail the cycle
        logger.warning("extension coverage query failed: %s", exc)
        coverage = status.coverage
    status.update(
        coverage=coverage,
        items_scored_total=status.items_scored_total + scored,
        queue_remaining=len(work) - done,
        last_cycle=summary,
        sources={
            "mozilla_blocklist": bool(blocklist),
            "store_metadata": True,
        },
        threat_feeds=feed_health,
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
        last_trigger = sleep_until(time.time() + remaining, trigger_path=trigger_path,
                                   last_trigger=last_trigger, stop_event=stop_event)
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

    fd = try_acquire_lock(lock_path, "extensions")
    if fd is None:
        logger.info("extensions: another worker holds %s; not starting loop", lock_path)
        return status, stop_event

    status.update(running=True)
    pruned = prune_cache(cache_dir)
    if pruned:
        logger.info("extensions: pruned %d cache files of retired key versions", pruned)
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
    data = read_json(status_path, {})
    data = data if isinstance(data, dict) else {}
    return {
        "enabled": bool(data.get("enabled", False)),
        "running": bool(data.get("running", False)),
        "last_tick_iso": data.get("last_tick_iso"),
        "items_scored_total": int(data.get("items_scored_total", 0) or 0),
        "last_error": data.get("last_error"),
        "last_cycle": data.get("last_cycle"),
        "queue_remaining": int(data.get("queue_remaining", 0) or 0),
        "sources": data.get("sources"),
        "threat_feeds": data.get("threat_feeds") or [],
        "coverage": data.get("coverage") or [],
    }


def fire_trigger(trigger_path: str = TRIGGER_PATH_DEFAULT, *,
                 cooldown_sec: float = 30.0) -> tuple[bool, float]:
    return _fire_trigger(trigger_path, cooldown_sec=cooldown_sec, name="extensions")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(read_status(), indent=2))
