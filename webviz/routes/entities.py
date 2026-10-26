"""Entity list endpoints: hosts, users, software, teams, platforms, relationships.

Split from webviz/app.py (Phase 5 monolith -> blueprints). The Flask `app`,
auth middleware, driver singleton and worker-lifecycle state stay in
webviz/app.py; this Blueprint holds one coherent endpoint group. App-level
names are imported at module top; safe because app.py registers every
blueprint at the very bottom, after all of them are bound.
"""

from flask import Blueprint

from flask import jsonify, request
from webviz.app import _bounded_limit, driver

bp = Blueprint("entities", __name__)

@bp.route("/api/hosts")
def get_hosts():
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    limit = _bounded_limit()
    with driver.session() as session:
        result = session.run(
            """
            MATCH (h:Host)
            RETURN h.hostname AS hostname, h.os_version AS os_version,
                   h.platform AS platform, h.ip AS ip, h.last_seen AS last_seen
            LIMIT $limit
            """,
            limit=limit,
        )
        return jsonify([r.data() for r in result])

@bp.route("/api/users")
def get_users():
    """Get users per host - only users that are connected to hosts"""
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    limit = _bounded_limit()
    with driver.session() as session:
        result = session.run("""
            MATCH (u:User)-[:USES]->(h:Host)
            RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname,
                   h.hostname AS hostname, h.platform AS platform
            ORDER BY h.hostname, u.username
            LIMIT $limit
        """, limit=limit)
        users = [r.data() for r in result]
        # Filter out any users that don't have proper host connections
        filtered_users = [user for user in users if user.get('hostname')]
        return jsonify(filtered_users)

@bp.route("/api/software")
def get_software():
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    limit = _bounded_limit()
    with driver.session() as session:
        # Sorted by install count so a defaulted `limit` returns the most
        # widespread software first (an unordered LIMIT is arbitrary).
        # OPTIONAL MATCH keeps orphan Software nodes that have no INSTALLED_ON
        # edge — they surface with host_count = 0 at the end of the list
        # instead of vanishing (a plain MATCH would silently drop them).
        # `versions` is capped at 25 entries per software: it's the largest
        # field in the response (a single browser node can carry dozens of
        # historical versions) and the list view only needs a sample of the
        # spread, not the full history. The cap is applied in Python (keeps
        # the Cypher portable and the row shape simple); 25 entries is enough
        # to render any realistic "N versions" badge.
        result = session.run(
            """
            MATCH (s:Software)
            OPTIONAL MATCH (s)-[:INSTALLED_ON]->(h:Host)
            WITH s, count(DISTINCT h) AS host_count
            ORDER BY host_count DESC, s.name ASC
            RETURN s.name AS name,
                   coalesce(s.display_name, s.name) AS display_name,
                   s.versions AS versions,
                   s.last_version AS last_version,
                   s.kind AS kind,
                   s.extension_key AS extension_key,
                   host_count
            LIMIT $limit
            """,
            limit=limit,
        )
        rows = []
        for r in result:
            row = r.data()
            versions = row.get("versions") or []
            row["versions"] = versions[:25]
            rows.append(row)
        return jsonify(rows)

@bp.route("/api/teams")
def get_teams():
    """Get all unique teams from hosts."""
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    with driver.session() as session:
        result = session.run("""
            MATCH (h:Host)
            WHERE h.team_id IS NOT NULL
            RETURN DISTINCT h.team_id AS team_id, h.team_name AS team_name
            ORDER BY h.team_name
        """)
        teams = [{"id": str(r['team_id']), "name": r['team_name']} for r in result]
        return jsonify(teams)

@bp.route("/api/platforms")
def get_platforms():
    """Get all unique platforms from hosts."""
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    with driver.session() as session:
        result = session.run("""
            MATCH (h:Host)
            WHERE h.platform IS NOT NULL AND h.platform <> ""
            RETURN DISTINCT h.platform AS platform
            ORDER BY h.platform
        """)
        platforms = [r['platform'] for r in result]
        return jsonify(platforms)

@bp.route("/api/relationships")
def get_relationships():
    """List all USES + INSTALLED_ON edges. Bounded so a multi-million-edge fleet
    can't OOM the response. Use the per-entity endpoints for full traversals.
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        limit = int(request.args.get("limit", 5000))
    except ValueError:
        limit = 5000
    limit = max(1, min(limit, 10000))

    half = max(1, limit // 2)
    rows = []
    with driver.session() as session:
        uses = session.run(
            """
            MATCH (u:User)-[:USES]->(h:Host)
            RETURN 'USES' AS type, u.username AS from_name, h.hostname AS to_host
            LIMIT $limit
            """,
            limit=half,
        )
        rows.extend(r.data() for r in uses)
        installed = session.run(
            """
            MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
            RETURN 'INSTALLED_ON' AS type, s.name AS from_name, h.hostname AS to_host
            LIMIT $limit
            """,
            limit=limit - half,
        )
        rows.extend(r.data() for r in installed)
    return jsonify(rows)
