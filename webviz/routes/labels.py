"""Fleet label endpoints: /api/labels + /api/labels/scope-count.

Split from webviz/app.py (Phase 5 monolith -> blueprints). The Flask `app`,
auth middleware, driver singleton and worker-lifecycle state stay in
webviz/app.py; this Blueprint holds one coherent endpoint group. App-level
names are imported at module top; safe because app.py registers every
blueprint at the very bottom, after all of them are bound.
"""

from flask import Blueprint, jsonify, request
from neo4j.exceptions import ServiceUnavailable, TransientError
from webviz.host_filters import FilterValidationError, apply_composite_filter, apply_host_filters
import json
from webviz.app import driver, logger

bp = Blueprint("labels", __name__)

@bp.route("/api/labels")
def get_labels():
    """List Fleet labels (user-defined + functional builtins) for scoping.

    Plan section 1A/1E/2B. Powers the UI multi-select widget and any
    consumer that needs to know:
      - which labels exist in this graph
      - how many hosts each one currently scopes
      - how fresh the label sync is, per-label

    Response schema (one entry per label):
        {
          "fleet_id": int,
          "name": str,
          "description": str | "",
          "label_type": "regular" | "builtin",
          "membership_type": "dynamic" | "manual" | "",
          "host_count": int,           # live count from graph (HAS_LABEL edges)
          "last_synced_iso": str,
          "last_label_sync_status": "ok" | "stale" | "failed",
          "consecutive_failures": int,
          "orphan_member_count": int,  # host ids in Fleet membership with no :Host node
          "orphan_member_ids": list[int],  # up to 50 orphan host ids
          "orphan_member_truncated": bool, # true when >50 orphans exist
        }

    Notes:
      - The osquery `query` field that defines a dynamic label is NOT
        included by default. It can be large and is rarely needed for the
        scoping UX. Pass `?include_query=true` to retrieve it.
      - host_count comes from the live graph (count of HAS_LABEL edges),
        not from Fleet's metadata. This catches drift between Fleet's
        cached counter and what's actually in our graph.
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    include_query = request.args.get("include_query", "").strip().lower() == "true"

    # l.query is the (potentially large) osquery that defines a dynamic
    # label. It is only needed behind ?include_query=true, so only SELECT it
    # then — the UI fires /api/labels on every label-chip toggle and paying
    # for the query text every time is pure waste.
    query_select = "                       l.query AS query,\n" if include_query else ""

    try:
        with driver.session() as session:
            result = session.run(
                f"""
                MATCH (l:Label)
                OPTIONAL MATCH (l)<-[r:HAS_LABEL]-(:Host)
                WITH l, count(r) AS live_host_count
                RETURN l.fleet_id AS fleet_id,
                       l.name AS name,
                       coalesce(l.description, '') AS description,
                       coalesce(l.label_type, 'regular') AS label_type,
                       coalesce(l.membership_type, '') AS membership_type,
                       live_host_count AS host_count,
                       coalesce(l.last_synced_iso, '') AS last_synced_iso,
                       coalesce(l.last_label_sync_status, 'unknown') AS last_label_sync_status,
                       coalesce(l.consecutive_failures, 0) AS consecutive_failures,
{query_select}                       coalesce(l.orphan_member_count, 0) AS orphan_member_count,
                       coalesce(l.orphan_member_ids, []) AS orphan_member_ids,
                       coalesce(l.orphan_member_truncated, false) AS orphan_member_truncated
                ORDER BY l.name
"""
            )
            payload = []
            for r in result:
                entry = {
                    "fleet_id": r["fleet_id"],
                    "name": r["name"],
                    "description": r["description"],
                    "label_type": r["label_type"],
                    "membership_type": r["membership_type"],
                    "host_count": int(r["host_count"]) if r["host_count"] is not None else 0,
                    "last_synced_iso": r["last_synced_iso"],
                    "last_label_sync_status": r["last_label_sync_status"],
                    "consecutive_failures": int(r["consecutive_failures"] or 0),
                    "orphan_member_count": int(r["orphan_member_count"] or 0),
                    "orphan_member_ids": list(r["orphan_member_ids"] or []),
                    "orphan_member_truncated": bool(r["orphan_member_truncated"]),
                }
                if include_query and r["query"]:
                    entry["query"] = r["query"]
                payload.append(entry)
            return jsonify(payload)
    except (TransientError, ServiceUnavailable) as exc:
        logger.warning("/api/labels transient: %s", exc)
        return jsonify({
            "error": "Database transient error",
            "message": "Memgraph is unreachable. Retry in a moment.",
        }), 503
    except Exception as exc:
        logger.error("/api/labels failed: %s", exc, exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@bp.route("/api/labels/scope-count")
def get_label_scope_count():
    """Pre-flight host count for a candidate label scope.

    Drives the zero-host empty-state UX in the label widget (plan-design-review
    Pass 2 finding 2A). On every chip toggle the UI fires this endpoint with
    the candidate scope; on count == 0 the widget surfaces the "Switch to OR
    (matches N hosts)" CTA with a pre-computed alternative count.

    Query params: same shape as /api/search etc.
        ?labels=A,B&label_op=AND|OR  → count of hosts in scope
        ?team=N&platform=X           → optional, filters the count
        ?include_alt=true            → also return alternative count for
                                       the OPPOSITE label_op (so the UI can
                                       render "Switch to OR (matches N)" without
                                       a second round-trip)

    Response:
        {
          "count": int,
          "labels": [...],         # echoed for client-side state alignment
          "label_op": "AND"|"OR",
          "alt_count": int|null,   # only when ?include_alt=true
          "alt_label_op": "OR"|"AND"|null
        }
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    # TODO-2: composite scoping. When `?expr=<json>` is provided, route
    # through apply_composite_filter for arbitrary boolean expressions over
    # team/platform/labels. Otherwise fall back to the flat-AND
    # apply_host_filters path. The expr param is the opt-in — no separate
    # feature flag needed.
    expr_raw = (request.args.get("expr") or "").strip()
    if expr_raw:
        try:
            expr_obj = json.loads(expr_raw)
        except (ValueError, TypeError) as exc:
            return jsonify({
                "error": "Invalid expr",
                "message": f"expr must be valid JSON: {exc}",
            }), 400
        try:
            flt_fragment, flt_params = apply_composite_filter(expr_obj)
        except FilterValidationError as exc:
            return jsonify({"error": "Invalid filter", "message": str(exc)}), 400
    else:
        try:
            flt_fragment, flt_params = apply_host_filters(request.args)
        except FilterValidationError as exc:
            return jsonify({"error": "Invalid filter", "message": str(exc)}), 400

    include_alt = request.args.get("include_alt", "").strip().lower() == "true"
    labels_csv = (request.args.get("labels") or "").strip()
    label_names = [s.strip() for s in labels_csv.split(",") if s.strip()] if labels_csv else []
    label_op = (request.args.get("label_op") or "AND").strip().upper()
    if label_op not in ("AND", "OR"):
        # Unreachable when apply_host_filters validates label_op, but defense
        # in depth in case the helper signature changes later.
        return jsonify({"error": "Invalid label_op"}), 400

    try:
        with driver.session() as session:
            count_query = (
                "MATCH (h:Host) WHERE 1=1" + flt_fragment + " RETURN count(h) AS c"
            )
            rec = session.run(count_query, **flt_params).single()
            count = int(rec["c"]) if rec and rec["c"] is not None else 0

            payload = {
                "count": count,
                "labels": label_names,
                "label_op": label_op,
                "alt_count": None,
                "alt_label_op": None,
            }

            if include_alt and label_names and len(label_names) >= 2:
                # Compute the count under the OPPOSITE op so the UI's
                # "Switch to OR (matches N hosts)" CTA can pre-render without
                # a second fetch. Only meaningful when ≥2 labels are selected
                # (with one label, AND and OR are equivalent).
                alt_op = "OR" if label_op == "AND" else "AND"
                alt_args = dict(request.args)
                alt_args["label_op"] = alt_op
                alt_fragment, alt_params = apply_host_filters(alt_args)
                alt_query = (
                    "MATCH (h:Host) WHERE 1=1" + alt_fragment + " RETURN count(h) AS c"
                )
                alt_rec = session.run(alt_query, **alt_params).single()
                payload["alt_count"] = (
                    int(alt_rec["c"]) if alt_rec and alt_rec["c"] is not None else 0
                )
                payload["alt_label_op"] = alt_op

            return jsonify(payload)
    except (TransientError, ServiceUnavailable) as exc:
        logger.warning("/api/labels/scope-count transient: %s", exc)
        return jsonify({
            "error": "Database transient error",
            "message": "Memgraph is unreachable. Retry in a moment.",
        }), 503
    except Exception as exc:
        logger.error("/api/labels/scope-count failed: %s", exc, exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
