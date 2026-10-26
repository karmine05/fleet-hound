"""Path/correlate/snapshot-diff: /api/path, /api/correlate, /api/snapshots, /api/diff.

Split from webviz/app.py (Phase 5 monolith -> blueprints). The Flask `app`,
auth middleware, driver singleton and worker-lifecycle state stay in
webviz/app.py; this Blueprint holds one coherent endpoint group. App-level
names are imported at module top; safe because app.py registers every
blueprint at the very bottom, after all of them are bound.
"""

from flask import Blueprint, jsonify, request
from neo4j.exceptions import ClientError, TransientError
from pathlib import Path
import re
from webviz.app import DEBUG_ERROR_DETAILS, SNAPSHOT_DIR, driver, logger

bp = Blueprint("traversal", __name__)

_TYPED_ID_RE = re.compile(r"^(host|user|software)_(.+)$")
# Max nodes in a /api/correlate ego network; matches the graph render budget order.
CORRELATE_NODE_CAP = 500

def _resolve_typed_id(typed_id: str):
    """Parse `host_<hostname>` / `user_<username>` / `software_<name>` into (kind, name).

    Returns (None, None) on bad input.
    """
    if not typed_id or len(typed_id) > 400:
        return None, None
    m = _TYPED_ID_RE.match(typed_id)
    if not m:
        return None, None
    return m.group(1), m.group(2)

def _node_label_for_kind(kind: str) -> str:
    return {"host": "Host", "user": "User", "software": "Software"}[kind]

def _key_prop_for_kind(kind: str) -> str:
    # Host nodes are keyed on fleet_host_id (stable, unique) to match the
    # id format emitted by /api/graph/full and /api/search. hostname is
    # display-only and may collide across distinct hosts.
    return {"host": "fleet_host_id", "user": "username", "software": "name"}[kind]

def _coerce_typed_id_name(kind: str, name: str):
    """Convert the parsed typed-id name to the type expected by the cypher
    key for that kind. host: fleet_host_id is int; user/software: str.
    Returns None on coercion failure (caller treats as not-found).
    """
    if kind == "host":
        try:
            return int(name)
        except (TypeError, ValueError):
            return None
    return name

def _serialize_graph_node(record_obj):
    """Map a Memgraph node object to the same node shape as /api/graph/full.

    Host node id is keyed on fleet_host_id (stable, unique) so that nodes
    returned by /api/path and /api/correlate match node ids in the main
    graph view. Without this, hover-correlation highlights would silently
    fail because host_<hostname> never matches host_<fid>.
    """
    labels = list(record_obj.labels) if hasattr(record_obj, "labels") else []
    props = dict(record_obj) if record_obj else {}

    if "Host" in labels:
        hostname = props.get("hostname")
        fleet_host_id = props.get("fleet_host_id")
        if fleet_host_id is None:
            return None
        node = {
            "id": f"host_{fleet_host_id}",
            "name": hostname,
            "display_name": hostname,
            "fleet_host_id": fleet_host_id,
            "type": "host",
            "details": f"{props.get('os_version') or ''} ({props.get('platform') or ''})",
        }
        if props.get("team_id") is not None:
            node["team_id"] = props.get("team_id")
        if props.get("team_name"):
            node["team_name"] = props.get("team_name")
        return node
    if "User" in labels:
        username = props.get("username")
        if not username:
            return None
        return {
            "id": f"user_{username}",
            "name": username,
            "type": "user",
            "details": props.get("email") or props.get("fullname") or "",
        }
    if "Software" in labels:
        name = props.get("name")
        if not name:
            return None
        node = {
            "id": f"software_{name}",
            "name": name,
            "type": "software",
            "details": f"Latest: {props.get('last_version') or 'unknown'}",
        }
        if props.get("category"):
            node["category"] = props["category"]
        if props.get("wikidata_description"):
            node["description"] = props["wikidata_description"]
        return node
    return None

def _link_type_for_rel(rel_type: str) -> str:
    return {"USES": "uses", "INSTALLED_ON": "installed"}.get(rel_type, rel_type.lower())

@bp.route("/api/path")
def get_path():
    """Shortest path between two typed-id nodes via USES / INSTALLED_ON edges.

    Query: from=<typed-id>&to=<typed-id>&max_hops=<1..6>
    Returns: {nodes, links, ordered_ids}
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    from_id = request.args.get("from", "").strip()
    to_id = request.args.get("to", "").strip()
    try:
        max_hops = int(request.args.get("max_hops", 4))
    except ValueError:
        max_hops = 4
    if max_hops < 1 or max_hops > 6:
        return jsonify({"error": "max_hops must be between 1 and 6"}), 400

    a_kind, a_name = _resolve_typed_id(from_id)
    b_kind, b_name = _resolve_typed_id(to_id)
    if not a_kind or not b_kind:
        return jsonify({"error": "Invalid typed id; expected <type>_<name>"}), 400

    # Coerce the parsed name to match the cypher key type. Host kind keys on
    # fleet_host_id (int); other kinds remain string. Reject early if coerce
    # fails (e.g. `host_<hostname>` passed to a host endpoint that now expects
    # a fleet_host_id) so the caller gets a clean 400.
    a_name = _coerce_typed_id_name(a_kind, a_name)
    b_name = _coerce_typed_id_name(b_kind, b_name)
    if a_name is None or b_name is None:
        return jsonify({"error": "Invalid typed id; host ids must be host_<fleet_host_id>"}), 400

    # Identity case: same node both endpoints. Skip the DB roundtrip and return
    # a degenerate "path" containing just that node so the client can render it.
    if from_id == to_id:
        a_label = _node_label_for_kind(a_kind)
        a_key = _key_prop_for_kind(a_kind)
        try:
            with driver.session() as session:
                rec = session.run(
                    f"MATCH (n:{a_label} {{{a_key}: $name}}) RETURN n LIMIT 1",
                    name=a_name,
                ).single()
        except Exception as exc:
            logger.error("path identity lookup failed: %s", exc)
            return jsonify({"error": "Internal server error"}), 500
        if not rec:
            return jsonify({"error": "Node not found"}), 404
        node_obj = _serialize_graph_node(rec["n"])
        if not node_obj:
            return jsonify({"error": "Node not found"}), 404
        return jsonify({
            "nodes": [node_obj],
            "links": [],
            "ordered_ids": [node_obj["id"]],
        })

    a_label = _node_label_for_kind(a_kind)
    b_label = _node_label_for_kind(b_kind)
    a_key = _key_prop_for_kind(a_kind)
    b_key = _key_prop_for_kind(b_kind)

    # Strategy 1: Memgraph BFS extension — fastest, returns shortest path natively.
    # Strategy 2: Standard variable-length pattern with manual ORDER BY length(p).
    #             Used when the BFS syntax is rejected by older Memgraph versions.
    cypher_bfs = (
        f"MATCH (a:{a_label} {{{a_key}: $aname}}), (b:{b_label} {{{b_key}: $bname}}) "
        f"MATCH p = (a)-[:USES|INSTALLED_ON *BFS 1..{max_hops}]-(b) "
        f"RETURN nodes(p) AS ns, relationships(p) AS rs LIMIT 1"
    )
    cypher_varlen = (
        f"MATCH (a:{a_label} {{{a_key}: $aname}}), (b:{b_label} {{{b_key}: $bname}}) "
        f"MATCH p = (a)-[:USES|INSTALLED_ON *1..{max_hops}]-(b) "
        f"RETURN nodes(p) AS ns, relationships(p) AS rs "
        f"ORDER BY length(p) ASC LIMIT 1"
    )

    rec = None
    strategy_used = None
    try:
        with driver.session() as session:
            rec = session.run(cypher_bfs, aname=a_name, bname=b_name).single()
        strategy_used = "bfs"
    except TransientError as exc:
        logger.warning("path BFS transient: %s", exc)
        return jsonify({"error": "Database transient error"}), 503
    except ClientError as exc:
        logger.info("path BFS syntax not supported, falling back to variable-length: %s", exc)
        try:
            with driver.session() as session:
                rec = session.run(cypher_varlen, aname=a_name, bname=b_name).single()
            strategy_used = "varlen"
        except (TransientError, ClientError) as exc2:
            logger.warning("path varlen failed: %s", exc2)
            return jsonify({"error": "Database transient error"}), 503
        except Exception as exc2:
            logger.error("path varlen unexpected error: %s", exc2, exc_info=True)
            return jsonify({"error": "Path query failed"}), 500
    except Exception as exc:
        logger.error("path query unexpected error: %s", exc, exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

    if not rec:
        logger.info("path: no path between %s and %s within %d hops (strategy=%s)",
                    from_id, to_id, max_hops, strategy_used or "?")
        return jsonify({"nodes": [], "links": [], "ordered_ids": []})

    logger.info("path: %s -> %s (strategy=%s)", from_id, to_id, strategy_used)

    nodes_raw = rec["ns"] or []
    rels_raw = rec["rs"] or []

    nodes = []
    seen_ids = set()
    ordered_ids = []
    for n in nodes_raw:
        node_obj = _serialize_graph_node(n)
        if not node_obj:
            continue
        ordered_ids.append(node_obj["id"])
        if node_obj["id"] not in seen_ids:
            nodes.append(node_obj)
            seen_ids.add(node_obj["id"])

    links = []
    for idx, r in enumerate(rels_raw):
        if idx >= len(ordered_ids) - 1:
            break
        links.append({
            "source": ordered_ids[idx],
            "target": ordered_ids[idx + 1],
            "type": _link_type_for_rel(r.type if hasattr(r, "type") else "USES"),
        })

    return jsonify({"nodes": nodes, "links": links, "ordered_ids": ordered_ids})

@bp.route("/api/correlate")
def get_correlate():
    """Ego network for a typed-id node.

    Query: id=<typed-id>&depth=<1..3>
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    typed_id = request.args.get("id", "").strip()
    try:
        depth = int(request.args.get("depth", 2))
    except ValueError:
        depth = 2
    if depth < 1 or depth > 3:
        return jsonify({"error": "depth must be between 1 and 3"}), 400

    kind, name = _resolve_typed_id(typed_id)
    if not kind:
        return jsonify({"error": "Invalid typed id; expected <type>_<name>"}), 400

    name = _coerce_typed_id_name(kind, name)
    if name is None:
        return jsonify({"error": "Invalid typed id; host ids must be host_<fleet_host_id>"}), 400

    label = _node_label_for_kind(kind)
    key = _key_prop_for_kind(kind)

    # Bounded hop-by-hop expansion. A variable-length path match enumerates
    # every path (popular software x hosts x their software) and blocked a
    # gunicorn worker for seconds per hover; here each hop is one LIMITed
    # query and the whole ego network is capped at CORRELATE_NODE_CAP nodes.
    recs = []
    truncated = False
    try:
        with driver.session() as session:
            seed = session.run(
                f"MATCH (n:{label} {{{key}: $name}}) RETURN n, id(n) AS nid LIMIT 1",
                name=name,
            ).single()
            if seed is None:
                return jsonify({"nodes": [], "links": [], "truncated": False})
            recs.append({"n": seed["n"]})
            seen = {seed["nid"]}
            frontier = [seed["nid"]]
            for _ in range(depth):
                budget = CORRELATE_NODE_CAP - len(seen)
                if budget <= 0 or not frontier:
                    truncated = truncated or bool(frontier)
                    break
                rows = list(session.run(
                    "MATCH (a)-[r:USES|INSTALLED_ON]-(b) "
                    "WHERE id(a) IN $frontier AND NOT id(b) IN $seen "
                    # Return a and b too: a bare relationship carries hollow
                    # endpoint nodes (no labels/properties).
                    "RETURN a, r, b, id(b) AS bid LIMIT $limit",
                    frontier=frontier, seen=list(seen), limit=budget + 1,
                ))
                if len(rows) > budget:
                    truncated = True
                    rows = rows[:budget]
                frontier = []
                for row in rows:
                    recs.append({"n": row["a"], "m": row["b"], "r": [row["r"]]})
                    if row["bid"] not in seen:
                        seen.add(row["bid"])
                        frontier.append(row["bid"])
    except TransientError as exc:
        logger.warning("correlate transient: %s", exc)
        return jsonify({"error": "Database transient error"}), 503
    except Exception as exc:
        logger.error("correlate failed: %s", exc)
        return jsonify({"error": "Correlate query failed"}), 500

    nodes_by_id = {}
    link_keys = set()
    links = []

    by_element_id = {}
    for rec in recs:
        for graph_node in (rec.get("n"), rec.get("m")):
            obj = _serialize_graph_node(graph_node)
            if obj:
                nodes_by_id[obj["id"]] = obj
                by_element_id[graph_node.element_id] = obj
        rels = rec.get("r") or []
        # Walk the relationship list — each rel has start_node / end_node / type.
        for r in rels:
            try:
                start_obj = by_element_id.get(r.start_node.element_id) or _serialize_graph_node(r.start_node)
                end_obj = by_element_id.get(r.end_node.element_id) or _serialize_graph_node(r.end_node)
            except AttributeError:
                continue
            if not start_obj or not end_obj:
                continue
            nodes_by_id[start_obj["id"]] = start_obj
            nodes_by_id[end_obj["id"]] = end_obj
            # USES edges always go user -> host, INSTALLED_ON go software -> host.
            # Normalise direction for the frontend.
            if r.type == "USES":
                src, tgt = (start_obj, end_obj) if start_obj["type"] == "user" else (end_obj, start_obj)
            elif r.type == "INSTALLED_ON":
                src, tgt = (start_obj, end_obj) if start_obj["type"] == "software" else (end_obj, start_obj)
            else:
                src, tgt = start_obj, end_obj
            key_str = f"{r.type}::{src['id']}::{tgt['id']}"
            if key_str in link_keys:
                continue
            link_keys.add(key_str)
            links.append({
                "source": src["id"],
                "target": tgt["id"],
                "type": _link_type_for_rel(r.type),
            })

    return jsonify({"nodes": list(nodes_by_id.values()), "links": links, "truncated": truncated})

@bp.route("/api/snapshots")
def list_snapshots_route():
    """List available graph snapshots (newest first).

    `?limit=<n>` is optional (default 100, cap 500). The Overview asks for 8,
    Changes asks for 60; callers that omit it keep the old behaviour.
    """
    try:
        from src.snapshot import list_snapshots as _ls
    except Exception as exc:
        logger.error("snapshot module unavailable: %s", exc)
        return jsonify([])
    items = _ls(Path(SNAPSHOT_DIR))
    limit_raw = (request.args.get("limit") or "").strip()
    if limit_raw:
        try:
            limit = int(limit_raw)
        except (TypeError, ValueError):
            return jsonify({"error": "limit must be an integer"}), 400
        if limit < 1:
            return jsonify({"error": "limit must be positive"}), 400
        items = items[: min(limit, 500)]
    # Caller doesn't need the absolute path; expose ts + counts.
    return jsonify([
        {
            "ts": item["ts"],
            "slug": item["slug"],
            "hosts": item["hosts"],
            "users": item["users"],
            "software": item["software"],
            "edges": item["edges"],
        }
        for item in items
    ])

def _resolve_snapshot_path(token: str):
    """Map a `ts` or `slug` from a query param to an on-disk path. Returns None if missing."""
    if not token:
        return None
    safe = re.sub(r"[^A-Za-z0-9._\-]", "", token)[:100]
    if not safe:
        return None
    candidate = Path(SNAPSHOT_DIR) / f"{safe}.jsonl.gz"
    if candidate.is_file():
        return candidate
    # Fall back to a ts -> slug match against list_snapshots metadata.
    try:
        from src.snapshot import list_snapshots as _ls
    except Exception:
        return None
    for item in _ls(Path(SNAPSHOT_DIR)):
        if item["ts"] == token or item["slug"] == token:
            p = Path(item["path"])
            if p.is_file():
                return p
    return None

@bp.route("/api/diff")
def get_diff():
    """Diff between two snapshots: ?from=<ts>&to=<ts>."""
    a_token = request.args.get("from", "").strip()
    b_token = request.args.get("to", "").strip()
    if not a_token or not b_token:
        return jsonify({"error": "from and to are required"}), 400

    a_path = _resolve_snapshot_path(a_token)
    b_path = _resolve_snapshot_path(b_token)
    if not a_path or not b_path:
        return jsonify({"error": "snapshot not found"}), 404

    try:
        from src.snapshot import diff_snapshots as _diff
    except Exception as exc:
        logger.error("snapshot module unavailable: %s", exc)
        return jsonify({"error": "snapshot subsystem unavailable"}), 500

    try:
        result = _diff(a_path, b_path)
    except Exception as exc:
        logger.error("diff failed: %s", exc, exc_info=True)
        return jsonify({"error": "Diff failed", "message": str(exc) if DEBUG_ERROR_DETAILS else None}), 500
    return jsonify(result)
