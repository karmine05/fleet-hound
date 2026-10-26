"""Enricher / OODA / extension-worker status+trigger and /api/extensions.*.

Split from webviz/app.py (Phase 5 monolith -> blueprints). The Flask `app`,
auth middleware, driver singleton and worker-lifecycle state stay in
webviz/app.py; this Blueprint holds one coherent endpoint group. App-level
names are imported at module top; safe because app.py registers every
blueprint at the very bottom, after all of them are bound.
"""

from flask import Blueprint, jsonify, request
from neo4j.exceptions import ServiceUnavailable, TransientError
import json
from webviz.app import DEBUG_ERROR_DETAILS, ENRICHER_ENABLED, ENRICHER_MANUAL_TRIGGER_COOLDOWN, ENRICHER_STATUS_PATH, ENRICHER_TRIGGER_PATH, EXTENSION_MANUAL_TRIGGER_COOLDOWN, EXTENSION_WORKER_ENABLED, EXTENSION_WORKER_INTERVAL_SEC, EXTENSION_WORKER_STATUS_PATH, EXTENSION_WORKER_TRIGGER_PATH, OODA_CYCLES_PATH, OODA_ENABLED, OODA_FINDINGS_PATH, OODA_FULL_SCAN_EVERY, OODA_INTERVAL_SEC, OODA_MANUAL_TRIGGER_COOLDOWN, OODA_STATUS_PATH, OODA_TRIGGER_PATH, _ensure_enricher_started, _ensure_extension_worker_started, _ensure_ooda_started, _get_driver, _reset_driver, audit_log, driver, logger

bp = Blueprint("workers", __name__)

@bp.route("/api/enricher/status")
def enricher_status():
    _ensure_enricher_started()
    try:
        from enrich_worker import read_status, queue_remaining as _qr
        snap = read_status(ENRICHER_STATUS_PATH)
        # Override `enabled` with the live config so a status file written
        # in a previous run can't claim the worker is enabled when the env
        # has flipped it off.
        snap["enabled"] = ENRICHER_ENABLED
        snap["queue_remaining"] = _qr(_get_driver)
    except Exception as exc:
        logger.error("enricher status failed: %s", exc)
        snap = {
            "enabled": ENRICHER_ENABLED, "running": False,
            "last_tick_iso": None, "items_categorized_total": 0,
            "last_error": str(exc) if DEBUG_ERROR_DETAILS else None,
            "queue_remaining": 0,
        }
    return jsonify(snap)

@bp.route("/api/enricher/trigger", methods=["POST"])
def enricher_trigger():
    _ensure_enricher_started()
    if not ENRICHER_ENABLED:
        return jsonify({"error": "Enricher disabled"}), 503
    try:
        from enrich_worker import fire_trigger
    except Exception as exc:
        logger.error("enricher import failed at trigger time: %s", exc)
        return jsonify({"error": "Enricher unavailable"}), 503
    fired, retry_after = fire_trigger(ENRICHER_TRIGGER_PATH,
                                      cooldown_sec=ENRICHER_MANUAL_TRIGGER_COOLDOWN)
    if not fired:
        return jsonify({
            "error": "Rate limited",
            "retry_after_sec": int(retry_after),
        }), 429
    return ("", 204)

@bp.route("/api/ooda/status")
def ooda_status():
    _ensure_ooda_started()
    try:
        from ooda_worker import read_status
        snap = read_status(OODA_STATUS_PATH)
        # Override `enabled` with the live config so a stale status file
        # cannot claim the worker is enabled when env has flipped it off.
        snap["enabled"] = OODA_ENABLED
        snap["interval_sec"] = OODA_INTERVAL_SEC
        snap["full_scan_every"] = OODA_FULL_SCAN_EVERY
    except Exception as exc:
        logger.error("ooda status failed: %s", exc)
        snap = {
            "enabled": OODA_ENABLED, "running": False,
            "next_cycle_id": 1, "last_phase": None,
            "last_error": str(exc) if DEBUG_ERROR_DETAILS else None,
            "cycles_total": 0, "cycles_failed": 0, "last_cycle": None,
            "interval_sec": OODA_INTERVAL_SEC,
            "full_scan_every": OODA_FULL_SCAN_EVERY,
        }
    return jsonify(snap)

@bp.route("/api/ooda/trigger", methods=["POST"])
def ooda_trigger():
    _ensure_ooda_started()
    if not OODA_ENABLED:
        return jsonify({"error": "OODA disabled"}), 503
    try:
        from ooda_worker import fire_trigger as _fire
    except Exception as exc:
        logger.error("ooda import failed at trigger time: %s", exc)
        return jsonify({"error": "OODA unavailable"}), 503
    fired, retry_after = _fire(OODA_TRIGGER_PATH,
                               cooldown_sec=OODA_MANUAL_TRIGGER_COOLDOWN)
    if not fired:
        return jsonify({"error": "Rate limited",
                        "retry_after_sec": int(retry_after)}), 429
    audit_log("ooda_trigger", "manual cycle requested")
    return ("", 204)

@bp.route("/api/ooda/findings")
def ooda_findings():
    _ensure_ooda_started()
    try:
        from ooda_worker import read_findings
        return jsonify(read_findings(OODA_FINDINGS_PATH))
    except Exception as exc:
        logger.error("ooda findings failed: %s", exc)
        return jsonify({"error": "Findings unavailable",
                        "message": str(exc) if DEBUG_ERROR_DETAILS else "internal error"}), 500

@bp.route("/api/ooda/cycles")
def ooda_cycles():
    _ensure_ooda_started()
    try:
        limit = int(request.args.get("limit", 20))
    except ValueError:
        limit = 20
    limit = max(1, min(limit, 100))
    try:
        from ooda_worker import read_cycles
        return jsonify(read_cycles(OODA_CYCLES_PATH, limit=limit))
    except Exception as exc:
        logger.error("ooda cycles failed: %s", exc)
        return jsonify({"error": "Cycles unavailable",
                        "message": str(exc) if DEBUG_ERROR_DETAILS else "internal error"}), 500

_EXT_WHERE = "(s.kind = 'browser_extension' OR s.extension_key STARTS WITH 'ext:')"

def _ext_bool_arg(value) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")

def _extension_filter_clause(args) -> tuple[str, dict]:
    """Shared WHERE builder for the list + summary queries."""
    clauses = [_EXT_WHERE]
    params: dict = {}

    risk = (args.get("risk") or "all").strip().lower()
    if risk in ("low", "medium", "high", "critical"):
        clauses.append("s.risk_band = $risk")
        params["risk"] = risk
    elif risk == "unassessed":
        clauses.append("s.risk_band IS NULL")

    store = (args.get("store") or "all").strip().lower()
    if store not in ("", "all"):
        clauses.append("s.store = $store")
        params["store"] = store

    known_bad = (args.get("known_bad") or "").strip().lower()
    if known_bad in ("1", "true", "yes", "on"):
        clauses.append("coalesce(s.known_bad, false) = true")

    if not _ext_bool_arg(args.get("include_builtin")):
        clauses.append("coalesce(s.is_builtin, false) = false")

    search = (args.get("search") or "").strip()
    if search:
        clauses.append(
            "("
            "toLower(coalesce(s.display_name, '')) CONTAINS toLower($q) OR "
            "toLower(s.name) CONTAINS toLower($q) OR "
            "toLower(coalesce(s.extension_id, '')) CONTAINS toLower($q) OR "
            "toLower(coalesce(s.publisher, '')) CONTAINS toLower($q)"
            ")"
        )
        params["q"] = search

    return " AND ".join(clauses), params

def _ext_signals_from_props(props: dict) -> list:
    raw = props.get("risk_signals_json")
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else []
    except (TypeError, ValueError):
        return []

def _ext_group_rows(rows) -> list[dict]:
    """Collapse per-node rows into one row per canonical extension key."""
    groups: dict[str, dict] = {}
    for row in rows:
        props = row.get("props") or {}
        key = props.get("extension_key") or f"name:{props.get('name')}"
        existing = groups.get(key)
        if existing is None:
            existing = groups[key] = {
                "extension_key": key,
                "name": props.get("name"),
                "display_name": props.get("display_name") or props.get("name"),
                "store": props.get("store"),
                "extension_id": props.get("extension_id"),
                "browser": props.get("browser"),
                "vendor": props.get("vendor"),
                "publisher": props.get("publisher"),
                "publisher_reputable": bool(props.get("publisher_reputable")),
                "is_builtin": bool(props.get("is_builtin")),
                "known_bad": bool(props.get("known_bad")),
                "store_status": props.get("store_status"),
                "store_url": props.get("store_url"),
                "latest_version": props.get("latest_version"),
                "install_users": props.get("install_users"),
                "rating": props.get("rating"),
                "rating_count": props.get("rating_count"),
                "category": props.get("category"),
                "manifest_version": props.get("manifest_version"),
                "permissions": props.get("permissions") or [],
                "host_permissions": props.get("host_permissions") or [],
                "content_script_matches": props.get("content_script_matches") or [],
                "risk_score": props.get("risk_score"),
                "risk_band": props.get("risk_band"),
                "capability_score": props.get("capability_score"),
                "trust_score": props.get("trust_score"),
                "threat_score": props.get("threat_score"),
                "exposure_score": props.get("exposure_score"),
                "risk_signals": _ext_signals_from_props(props),
                "vulnerability_count": props.get("vulnerability_count") or 0,
                "max_cvss": props.get("max_cvss"),
                "intel_refreshed_at": props.get("intel_refreshed_at"),
                "intel_error": props.get("intel_error"),
                "hostnames": set(),
                "versions": set(),
            }
        for host in row.get("hosts") or []:
            if host:
                existing["hostnames"].add(host)
        for version in row.get("versions") or []:
            if version:
                existing["versions"].add(version)
        # Several nodes can map to one key; prefer the scored one.
        if props.get("risk_score") is not None and existing.get("risk_score") is None:
            existing["risk_score"] = props.get("risk_score")
            existing["risk_band"] = props.get("risk_band")
            existing["risk_signals"] = _ext_signals_from_props(props)

    out = []
    for group in groups.values():
        hostnames = sorted(group.pop("hostnames"))
        versions = sorted(group.pop("versions"))
        group["host_count"] = len(hostnames)
        group["hostnames"] = hostnames[:50]
        group["versions"] = versions[:20]
        out.append(group)
    out.sort(key=lambda g: (g.get("risk_score") is None,
                            -(g.get("risk_score") or 0),
                            -g.get("host_count", 0)))
    return out

@bp.route("/api/extensions")
def get_extensions():
    """Browser-extension inventory with risk scores, grouped by canonical key.

    Query params: risk (low|medium|high|critical|unassessed|all), store,
    search, known_bad, include_builtin.
    """
    _ensure_extension_worker_started()
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    try:
        limit = int(request.args.get("limit", 1000))
    except ValueError:
        limit = 1000
    limit = max(1, min(limit, 5000))

    where, params = _extension_filter_clause(request.args)
    list_query = f"""
        MATCH (s:Software)
        WHERE {where}
        OPTIONAL MATCH (s)-[r:INSTALLED_ON]->(h:Host)
        WITH s, count(DISTINCT h) AS host_count,
             collect(DISTINCT r.version) AS versions,
             collect(DISTINCT h.hostname) AS hosts
        RETURN properties(s) AS props, host_count, versions, hosts
        ORDER BY host_count DESC
        LIMIT $limit
    """
    band_query = f"""
        MATCH (s:Software)
        WHERE {where}
        RETURN coalesce(s.risk_band, 'unassessed') AS band,
               count(DISTINCT coalesce(s.extension_key, 'name:' + s.name)) AS n
    """
    host_query = f"""
        MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
        WHERE {where}
        RETURN count(DISTINCT h) AS n
    """

    try:
        with driver.session() as session:
            rows = [dict(record) for record in session.run(list_query, **params, limit=limit)]
            band_rows = [dict(record) for record in session.run(band_query, **params)]
            host_row = session.run(host_query, **params).single()
    except (ServiceUnavailable, TransientError) as exc:
        # Only a dead connection warrants a new driver; resetting on a
        # TransientError would yank the pool from the background workers.
        if isinstance(exc, ServiceUnavailable):
            _reset_driver()
        logger.error("extensions list unavailable: %s", exc)
        return jsonify({"error": "Database temporarily unavailable"}), 503
    except Exception as exc:
        logger.error("extensions list failed: %s", exc, exc_info=True)
        return jsonify({
            "error": "Extensions query failed",
            "message": str(exc) if DEBUG_ERROR_DETAILS else None,
        }), 500

    extensions = _ext_group_rows(rows)
    summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
               "unassessed": 0, "affected_hosts": int(host_row["n"]) if host_row else 0}
    for band in band_rows:
        name = band.get("band") or "unassessed"
        count = int(band.get("n") or 0)
        if name in summary:
            summary[name] = count
        summary["total"] += count

    return jsonify({
        "extensions": extensions,
        "summary": summary,
        "total": summary["total"],
        "worker": _extension_status_snapshot(),
    })

def _extension_status_snapshot() -> dict:
    try:
        from extension_worker import read_status, queue_remaining as _qr
        snap = read_status(EXTENSION_WORKER_STATUS_PATH)
        snap["enabled"] = EXTENSION_WORKER_ENABLED
        snap["interval_sec"] = EXTENSION_WORKER_INTERVAL_SEC
        snap["queue_remaining"] = _qr(_get_driver)
        return snap
    except Exception as exc:
        logger.error("extension status failed: %s", exc)
        return {
            "enabled": EXTENSION_WORKER_ENABLED, "running": False,
            "interval_sec": EXTENSION_WORKER_INTERVAL_SEC, "queue_remaining": 0,
            "last_error": str(exc) if DEBUG_ERROR_DETAILS else None,
        }

@bp.route("/api/extensions/status")
def extensions_status():
    _ensure_extension_worker_started()
    return jsonify(_extension_status_snapshot())

@bp.route("/api/extensions/refresh", methods=["POST"])
def extensions_refresh():
    _ensure_extension_worker_started()
    if not EXTENSION_WORKER_ENABLED:
        return jsonify({"error": "Extension worker disabled"}), 503
    try:
        from extension_worker import fire_trigger as _fire
    except Exception as exc:
        logger.error("extension worker import failed at trigger time: %s", exc)
        return jsonify({"error": "Extension worker unavailable"}), 503
    fired, retry_after = _fire(
        EXTENSION_WORKER_TRIGGER_PATH,
        cooldown_sec=EXTENSION_MANUAL_TRIGGER_COOLDOWN,
    )
    if not fired:
        return jsonify({"error": "Rate limited", "retry_after_sec": int(retry_after)}), 429
    audit_log("extensions_refresh", "manual extension intel refresh requested")
    return ("", 204)

@bp.route("/api/extensions/detail")
def extension_detail():
    _ensure_extension_worker_started()
    key = (request.args.get("key") or "").strip()
    if not key:
        return jsonify({"error": "key parameter required"}), 400
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    name_fallback = key[5:] if key.startswith("name:") else key
    query = """
        MATCH (s:Software)
        WHERE s.extension_key = $key OR s.name = $name_fallback
        OPTIONAL MATCH (s)-[r:INSTALLED_ON]->(h:Host)
        RETURN properties(s) AS props,
               collect(DISTINCT {
                   hostname: h.hostname,
                   version: r.version,
                   source: r.source,
                   browser: r.browser,
                   installed_path: r.installed_path,
                   first_seen: r.first_seen,
                   last_seen: r.last_seen
               }) AS hosts
    """
    try:
        with driver.session() as session:
            records = [dict(record) for record in session.run(
                query, key=key, name_fallback=name_fallback
            )]
    except Exception as exc:
        logger.error("extension detail failed: %s", exc, exc_info=True)
        return jsonify({
            "error": "Extension query failed",
            "message": str(exc) if DEBUG_ERROR_DETAILS else None,
        }), 500

    if not records:
        return jsonify({"error": "Extension not found"}), 404

    nodes = [row.get("props") or {} for row in records]
    hosts: dict[str, dict] = {}
    for row in records:
        for host in row.get("hosts") or []:
            if not isinstance(host, dict) or not host.get("hostname"):
                continue
            existing = hosts.get(host["hostname"])
            if existing is None or (host.get("last_seen") or "") > (existing.get("last_seen") or ""):
                hosts[host["hostname"]] = host

    primary = max(nodes, key=lambda p: (p.get("risk_score") or -1))
    merged = dict(primary)
    # The worker writes NULL (property removed) for fields a store doesn't
    # publish; give the UI stable keys anyway.
    for field in ("risk_band", "risk_score", "capability_score", "trust_score",
                  "threat_score", "exposure_score", "install_users",
                  "manifest_version", "rating", "rating_count", "publisher",
                  "store_status", "store_url", "latest_version", "category"):
        merged.setdefault(field, None)
    merged["extension_key"] = primary.get("extension_key") or key
    merged["risk_signals"] = _ext_signals_from_props(primary)
    merged["risk_signals_json"] = None
    try:
        merged["vulnerabilities"] = json.loads(primary.get("vulnerabilities_json") or "[]")
    except (TypeError, ValueError):
        merged["vulnerabilities"] = []
    host_list = sorted(hosts.values(), key=lambda h: h.get("hostname") or "")
    return jsonify({
        "extension": merged,
        "hosts": host_list,
        "host_count": len(host_list),
        "node_count": len(nodes),
    })
