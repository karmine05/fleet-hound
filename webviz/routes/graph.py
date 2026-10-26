"""D3 force-graph: /api/graph, /api/graph/full, /api/software/<n>/hosts, /api/host/<h>/software.

Split from webviz/app.py (Phase 5 monolith -> blueprints). The Flask `app`,
auth middleware, driver singleton and worker-lifecycle state stay in
webviz/app.py; this Blueprint holds one coherent endpoint group. App-level
names are imported at module top; safe because app.py registers every
blueprint at the very bottom, after all of them are bound.
"""

from flask import Blueprint, jsonify, request
from neo4j.exceptions import TransientError
from webviz.host_filters import FilterValidationError, apply_composite_filter, apply_host_filters
from webviz.hostname_utils import hostname_counts as _hostname_counts, disambiguated_display_name
import json
from webviz.app import DEBUG_ERROR_DETAILS, driver, logger

bp = Blueprint("graph", __name__)

@bp.route("/api/graph")
def get_graph_data():
    """Get graph data formatted for D3.js force layout.

    Host node id is keyed on fleet_host_id (stable, unique) to match the
    id format used elsewhere (/api/graph/full, /api/search, /api/path,
    /api/correlate). Without this consistency, links from one endpoint
    don't resolve against nodes from another when both are mixed by the
    client (hover correlation, cross-view jumps).
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    with driver.session() as session:
        nodes = []

        # Host nodes - only hosts that have users connected. Pull
        # fleet_host_id alongside hostname; collapse by fleet_host_id (not
        # hostname) so Fleet's default-hostname collisions (mac.lan ×4)
        # render as distinct nodes with disambiguated display labels.
        host_result = session.run("""
            MATCH (h:Host)<-[:USES]-(u:User)
            RETURN DISTINCT h.fleet_host_id AS fleet_host_id,
                            h.hostname AS hostname,
                            h.os_version AS os_version,
                            h.platform AS platform
        """)
        host_records = list(host_result)
        hostname_counts = _hostname_counts(host_records)

        for record in host_records:
            fid = record['fleet_host_id']
            hn = record['hostname']
            if fid is None:
                continue
            display_name = disambiguated_display_name(hn, fid, hostname_counts)
            nodes.append({
                "id": f"host_{fid}",
                "name": hn,
                "display_name": display_name,
                "fleet_host_id": fid,
                "type": "host",
                "details": f"{record['os_version'] or ''} ({record['platform'] or ''})"
            })

        user_result = session.run("""
            MATCH (u:User)-[:USES]->(h:Host)
            RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname
        """)
        for record in user_result:
            nodes.append({
                "id": f"user_{record['username']}",
                "name": record['username'],
                "type": "user",
                "details": record['email'] or record['fullname'] or ''
            })

        # User→Host edges keyed on fleet_host_id for symmetry with node ids.
        links = []
        rel_result = session.run("""
            MATCH (u:User)-[r:USES]->(h:Host)
            RETURN DISTINCT 'uses' AS type, u.username AS from_name,
                            h.fleet_host_id AS to_host_id
        """)
        for record in rel_result:
            links.append({
                "source": f"user_{record['from_name']}",
                "target": f"host_{record['to_host_id']}",
                "type": record['type']
            })

        return jsonify({"nodes": nodes, "links": links})

@bp.route("/api/graph/full")
def get_full_graph_data():
    """Get scoped graph data including software for expansion.

    Supports the same scoping params as /api/search and /api/shadow-it:
        ?team=<id>           — filter Hosts by team_id
        ?platform=<name>     — filter Hosts by platform substring
        ?labels=A,B          — filter Hosts by HAS_LABEL membership
        ?label_op=AND|OR     — multi-label semantics (default AND)
        ?expr=<json>         — composite boolean expression (alternative)

    Filtering applies at the Host level. Users and Software cascade: only
    surfaces if connected to at least one Host that survived filtering. This
    ensures the graph shows only entities ACTUALLY in the selected scope —
    no orphan apps that aren't part of the chosen labels.
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    # Parse scoping filters once. Apply the same fragment to every host-anchored
    # query (Hosts, Users via h, Software via h) so the cascade is consistent.
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

    try:
        with driver.session() as session:
            # Get all nodes including software (only connected nodes)
            nodes = []
            node_ids = set()  # Track node IDs to ensure links are valid

            # Host nodes — only hosts with relationships (users or software).
            # `flt_fragment` always begins with " AND " or is empty, so it
            # appends cleanly after the existing connected-host predicate.
            host_query = (
                "MATCH (h:Host) "
                "WHERE (EXISTS((h)<-[:USES]-(:User)) OR EXISTS((h)<-[:INSTALLED_ON]-(:Software)))"
                + flt_fragment +
                " RETURN h.fleet_host_id AS fleet_host_id, "
                "        h.hostname AS hostname, h.os_version AS os_version, "
                "        h.platform AS platform, h.team_id AS team_id, "
                "        h.team_name AS team_name"
            )
            host_records = list(session.run(host_query, **flt_params))

            # Detect hostname collisions inside this scope so the viz can
            # disambiguate `mac.lan #1229` vs `mac.lan #1367` for distinct
            # physical machines that share Fleet's default hostname. Without
            # this, 4 different Macs all render as identical "mac.lan" red dots
            # and the operator can't tell which is which.
            hostname_counts = _hostname_counts(host_records)

            for record in host_records:
                # Node id is keyed on fleet_host_id (stable, unique). hostname
                # carries the current display label. This eliminates duplicate
                # nodes when Fleet reports the same host with different casing.
                fid = record['fleet_host_id']
                hn = record['hostname']
                node_id = f"host_{fid}"
                display_name = disambiguated_display_name(hn, fid, hostname_counts)
                node_obj = {
                    "id": node_id,
                    "name": hn,
                    "display_name": display_name,
                    "fleet_host_id": fid,
                    "type": "host",
                    "details": f"{record['os_version'] or ''} ({record['platform'] or ''})",
                }
                if record['team_id'] is not None:
                    node_obj['team_id'] = record['team_id']
                if record['team_name']:
                    node_obj['team_name'] = record['team_name']
                nodes.append(node_obj)
                node_ids.add(node_id)

            # User nodes — only those connected to a host that survived the
            # filter. Without this cascade, the graph would include users from
            # hosts the operator just scoped OUT.
            user_query = (
                "MATCH (u:User)-[:USES]->(h:Host) "
                "WHERE 1=1" + flt_fragment +
                " RETURN DISTINCT u.username AS username, u.email AS email, "
                "        u.fullname AS fullname"
            )
            user_result = session.run(user_query, **flt_params)
            for record in user_result:
                node_id = f"user_{record['username']}"
                nodes.append({
                    "id": node_id,
                    "name": record['username'],
                    "type": "user",
                    "details": record['email'] or record['fullname'] or ''
                })
                node_ids.add(node_id)

            # Software nodes — top 50 by host_count WITHIN the filtered scope.
            # The host_count we report is the in-scope count, not the global
            # count, so the badge ("on N hosts") matches what the operator
            # actually sees in the graph.
            software_query = (
                "MATCH (s:Software)-[:INSTALLED_ON]->(h:Host) "
                "WHERE 1=1" + flt_fragment +
                " WITH s, COUNT(DISTINCT h) AS host_count "
                "ORDER BY host_count DESC "
                "LIMIT 50 "
                "RETURN s.name AS name, coalesce(s.display_name, s.name) AS display_name, s.last_version AS last_version, "
                "        s.category AS category, "
                "        s.wikidata_description AS description, "
                "        host_count"
            )
            software_result = session.run(software_query, **flt_params)
            for record in software_result:
                node_id = f"software_{record['name']}"
                node_obj = {
                    "id": node_id,
                    "name": record['name'],
                    "display_name": record.get('display_name') or record['name'],
                    "type": "software",
                    "details": f"Latest: {record['last_version'] or 'unknown'} (on {record['host_count']} hosts)",
                }
                if record['category']:
                    node_obj['category'] = record['category']
                if record['description']:
                    node_obj['description'] = record['description']
                nodes.append(node_obj)
                node_ids.add(node_id)

            # Get relationships - only for nodes that exist
            links = []

            # User-Host relationships — target keyed on fleet_host_id to match
            # the node ids emitted above.
            rel_result = session.run("""
                MATCH (u:User)-[r:USES]->(h:Host)
                RETURN 'uses' AS type, u.username AS from_name,
                       h.fleet_host_id AS to_host_id
            """)
            for record in rel_result:
                source_id = f"user_{record['from_name']}"
                target_id = f"host_{record['to_host_id']}"

                # Only add link if both nodes exist
                if source_id in node_ids and target_id in node_ids:
                    links.append({
                        "source": source_id,
                        "target": target_id,
                        "type": record['type']
                    })

            # Software-Host relationships (only for loaded software nodes)
            # Build list of software names we've loaded to filter the query
            software_names = [node['name'] for node in nodes if node['type'] == 'software']

            if software_names:
                # Query only relationships for the software we've loaded
                # This is much more memory efficient than loading all relationships
                software_rel_result = session.run("""
                    MATCH (s:Software)-[r:INSTALLED_ON]->(h:Host)
                    WHERE s.name IN $software_names
                    RETURN 'installed' AS type, s.name AS from_name,
                           h.fleet_host_id AS to_host_id
                """, software_names=software_names)

                added_software_links = 0
                for record in software_rel_result:
                    source_id = f"software_{record['from_name']}"
                    target_id = f"host_{record['to_host_id']}"

                    # Only add link if both nodes exist
                    if source_id in node_ids and target_id in node_ids:
                        links.append({
                            "source": source_id,
                            "target": target_id,
                            "type": record['type']
                        })
                        added_software_links += 1

                logger.info(f"Software links: {added_software_links} added")

            logger.info(f"Full graph API: Returning {len(nodes)} nodes and {len(links)} links")
            meta = {}
            sample_raw = (request.args.get("sample") or "").strip()
            if sample_raw:
                try:
                    sample_n = int(sample_raw)
                except (TypeError, ValueError):
                    return jsonify({"error": "sample must be an integer"}), 400
                if sample_n < 20 or sample_n > 300:
                    return jsonify({"error": "sample must be between 20 and 300"}), 400
                from webviz.graph_sample import sample_graph
                nodes, links, meta = sample_graph(nodes, links, sample_n)
                logger.info(
                    "Full graph sample: kept %d/%d nodes, %d/%d links",
                    len(nodes), meta.get("total_nodes"),
                    len(links), meta.get("total_links"),
                )
            return jsonify({"nodes": nodes, "links": links, **meta})

    except TransientError as e:
        error_msg = str(e)
        if "Memory limit exceeded" in error_msg:
            logger.error(f"Memory limit exceeded while loading full graph: {error_msg}")
            payload = {
                "error": "Dataset too large for available memory",
                "message": "The dataset is too large to load all at once. Try increasing Memgraph's memory limit in docker-compose.yml or use the filtered view instead.",
            }
            if DEBUG_ERROR_DETAILS:
                payload["details"] = error_msg
            return jsonify(payload), 507  # HTTP 507 Insufficient Storage
        else:
            logger.error(f"Transient error in get_full_graph_data: {error_msg}")
            payload = {"error": "Database transient error"}
            if DEBUG_ERROR_DETAILS:
                payload["details"] = error_msg
            return jsonify(payload), 503

    except Exception as e:
        logger.error(f"Unexpected error in get_full_graph_data: {e}", exc_info=True)
        payload = {"error": "Internal server error"}
        if DEBUG_ERROR_DETAILS:
            payload["details"] = str(e)
        return jsonify(payload), 500

@bp.route("/api/software/<software_name>/hosts")
def get_software_hosts(software_name):
    """Get ALL hosts that have a specific software installed.

    Software names are stored lowercase in the graph (see
    src/ingestion.py — name is normalized at ingest to collapse the
    "Ollama" / "ollama" / "OLLAMA" case-variant duplicates Fleet
    exposes from heterogeneous osquery sources). Lowercase the URL
    param before MATCH so a request for `/api/software/Ollama/hosts`
    resolves to the same node as `/api/software/ollama/hosts`.
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    software_name = (software_name or "").strip().lower()
    if not software_name:
        return jsonify({"error": "Software name required"}), 400

    with driver.session() as session:
        # Check if software exists
        software_check = session.run(
            "MATCH (s:Software {name: $name}) "
            "RETURN s.name AS name, "
            "       coalesce(s.display_name, s.name) AS display_name, "
            "       s.last_version AS last_version",
            name=software_name
        )
        software_data = software_check.single()
        if not software_data:
            return jsonify({"error": "Software not found"}), 404
        
        nodes = []
        node_ids = set()
        
        # Add the software node
        software_id = f"software_{software_name}"
        nodes.append({
            "id": software_id,
            "name": software_name,
            "display_name": software_data.get("display_name") or software_name,
            "type": "software",
            "details": f"Latest: {software_data['last_version'] or 'unknown'}"
        })
        node_ids.add(software_id)
        
        # Get ALL hosts that have this software. DISTINCT on fleet_host_id
        # because duplicate INSTALLED_ON edges can exist for the same
        # (Software, Host) pair (legacy data from before edge-dedupe);
        # without DISTINCT each duplicate edge becomes a duplicate node.
        # Node id keyed on fleet_host_id (stable, unique). hostname is for
        # display only — multiple distinct hosts share Fleet's default
        # hostname (mac.lan, etc.) and must be disambiguated via #<fid>.
        host_result = session.run("""
            MATCH (s:Software {name: $name})-[:INSTALLED_ON]->(h:Host)
            RETURN DISTINCT h.fleet_host_id AS fleet_host_id,
                            h.hostname AS hostname,
                            h.os_version AS os_version,
                            h.platform AS platform
        """, name=software_name)

        host_records_raw = list(host_result)
        hostname_counts = _hostname_counts(host_records_raw)

        for record in host_records_raw:
            fid = record['fleet_host_id']
            hn = record['hostname']
            host_id = f"host_{fid}"
            if host_id in node_ids:
                continue  # belt-and-suspenders: skip if same fid already added
            display_name = disambiguated_display_name(hn, fid, hostname_counts)
            nodes.append({
                "id": host_id,
                "name": hn,
                "display_name": display_name,
                "fleet_host_id": fid,
                "type": "host",
                "details": f"{record['os_version'] or ''} ({record['platform'] or ''})"
            })
            node_ids.add(host_id)

        # Get users connected to these hosts
        user_result = session.run("""
            MATCH (s:Software {name: $name})-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
            RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname
        """, name=software_name)

        for record in user_result:
            user_id = f"user_{record['username']}"
            if user_id in node_ids:
                continue
            nodes.append({
                "id": user_id,
                "name": record['username'],
                "type": "user",
                "details": record['email'] or record['fullname'] or ''
            })
            node_ids.add(user_id)

        # Get ALL relationships
        links = []

        # Software-Host relationships. DISTINCT to collapse duplicate edges
        # and reference target hosts by fleet_host_id to match node ids above.
        software_host_links = session.run("""
            MATCH (s:Software {name: $name})-[:INSTALLED_ON]->(h:Host)
            RETURN DISTINCT h.fleet_host_id AS fleet_host_id
        """, name=software_name)

        seen_sw_links = set()
        for record in software_host_links:
            target_id = f"host_{record['fleet_host_id']}"
            link_key = (software_id, target_id)
            if link_key in seen_sw_links:
                continue
            seen_sw_links.add(link_key)
            if target_id in node_ids:
                links.append({
                    "source": software_id,
                    "target": target_id,
                    "type": "installed"
                })

        # User-Host relationships (for hosts that have this software)
        user_host_links = session.run("""
            MATCH (s:Software {name: $name})-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
            RETURN DISTINCT u.username AS username, h.fleet_host_id AS fleet_host_id
        """, name=software_name)

        seen_uh_links = set()
        for record in user_host_links:
            source_id = f"user_{record['username']}"
            target_id = f"host_{record['fleet_host_id']}"
            link_key = (source_id, target_id)
            if link_key in seen_uh_links:
                continue
            seen_uh_links.add(link_key)
            if source_id in node_ids and target_id in node_ids:
                links.append({
                    "source": source_id,
                    "target": target_id,
                    "type": "uses"
                })
        
        logger.info(f"Software {software_name}: Returning {len(nodes)} nodes and {len(links)} links")
        return jsonify({"nodes": nodes, "links": links})

@bp.route("/api/host/<hostname>/software")
def get_host_software(hostname):
    """Get ALL software installed on a specific host.

    Looks the host up by case-insensitive hostname so that the side panel
    still resolves when the URL casing differs from the surviving canonical
    casing in the graph (e.g. an old bookmark, a copy-pasted link, or two
    Fleet hosts whose names differ only in case). Once we have the host we
    pivot to its fleet_host_id (stable id) for all subsequent rel lookups
    to guarantee we follow edges of exactly one logical machine.
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    with driver.session() as session:
        # Case-insensitive host lookup. LIMIT 1 because, in the rare event
        # two enrolled Fleet hosts share a lowercased hostname, we pick the
        # one with the most recent activity to populate the side panel.
        host_result = session.run(
            "MATCH (h:Host) "
            "WHERE toLower(h.hostname) = toLower($hostname) "
            "RETURN h.fleet_host_id AS fleet_host_id, h.hostname AS hostname, "
            "       h.os_version AS os_version, h.platform AS platform "
            "ORDER BY h.last_seen DESC LIMIT 1",
            hostname=hostname
        )
        host_data = host_result.single()
        if not host_data:
            return jsonify({"error": "Host not found"}), 404

        fleet_host_id = host_data['fleet_host_id']
        canonical_hostname = host_data['hostname']

        nodes = []
        node_ids = set()

        # Add the host node — id keyed on fleet_host_id, name shows the
        # canonical (most-recently-ingested) hostname casing. display_name
        # mirrors name here (single-host detail view; no collision context),
        # but the field exists so client code that reads
        # `d.display_name || d.name` produces the expected label.
        host_id = f"host_{fleet_host_id}"
        nodes.append({
            "id": host_id,
            "name": canonical_hostname,
            "display_name": canonical_hostname,
            "fleet_host_id": fleet_host_id,
            "type": "host",
            "details": f"{host_data['os_version'] or ''} ({host_data['platform'] or ''})"
        })
        node_ids.add(host_id)

        # Get ALL users connected to this host — match by fleet_host_id.
        user_result = session.run("""
            MATCH (u:User)-[:USES]->(h:Host {fleet_host_id: $fleet_host_id})
            RETURN u.username AS username, u.email AS email, u.fullname AS fullname
        """, fleet_host_id=fleet_host_id)

        for record in user_result:
            user_id = f"user_{record['username']}"
            nodes.append({
                "id": user_id,
                "name": record['username'],
                "type": "user",
                "details": record['email'] or record['fullname'] or ''
            })
            node_ids.add(user_id)

        # Get ALL software installed on this host
        software_result = session.run("""
            MATCH (s:Software)-[:INSTALLED_ON]->(h:Host {fleet_host_id: $fleet_host_id})
            RETURN s.name AS name,
                   coalesce(s.display_name, s.name) AS display_name,
                   s.last_version AS last_version
            ORDER BY coalesce(s.display_name, s.name)
        """, fleet_host_id=fleet_host_id)

        for record in software_result:
            software_id = f"software_{record['name']}"
            nodes.append({
                "id": software_id,
                "name": record['name'],
                "display_name": record.get('display_name') or record['name'],
                "type": "software",
                "details": f"Latest: {record['last_version'] or 'unknown'}"
            })
            node_ids.add(software_id)

        # Get ALL relationships for this host
        links = []

        # User-Host relationships
        user_links = session.run("""
            MATCH (u:User)-[:USES]->(h:Host {fleet_host_id: $fleet_host_id})
            RETURN u.username AS username
        """, fleet_host_id=fleet_host_id)

        for record in user_links:
            source_id = f"user_{record['username']}"
            if source_id in node_ids:
                links.append({
                    "source": source_id,
                    "target": host_id,
                    "type": "uses"
                })

        # Software-Host relationships
        software_links = session.run("""
            MATCH (s:Software)-[:INSTALLED_ON]->(h:Host {fleet_host_id: $fleet_host_id})
            RETURN s.name AS name
        """, fleet_host_id=fleet_host_id)

        for record in software_links:
            source_id = f"software_{record['name']}"
            if source_id in node_ids:
                links.append({
                    "source": source_id,
                    "target": host_id,
                    "type": "installed"
                })

        logger.info(f"Host {canonical_hostname} (id={fleet_host_id}): Returning {len(nodes)} nodes and {len(links)} links")
        return jsonify({"nodes": nodes, "links": links})
