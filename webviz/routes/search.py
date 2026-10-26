"""Universal search: /api/search + /api/search/software.

Split from webviz/app.py (Phase 5 monolith -> blueprints). The Flask `app`,
auth middleware, driver singleton and worker-lifecycle state stay in
webviz/app.py; this Blueprint holds one coherent endpoint group. App-level
names are imported at module top; safe because app.py registers every
blueprint at the very bottom, after all of them are bound.
"""

from flask import Blueprint, jsonify, request
from webviz.host_filters import FilterValidationError, apply_label_filter
from webviz.hostname_utils import hostname_counts as _hostname_counts, disambiguated_display_name
from webviz.app import _validate_user_regex, driver, logger

bp = Blueprint("search", __name__)

@bp.route("/api/search")
def search_all():
    """Universal search endpoint for all node types (hosts, users, software).

    Query parameters:
    - q: search term (optional - if empty, returns ALL nodes of specified type)
    - type: node type filter ('all', 'host', 'user', 'software') - default 'all'
    - platform: platform filter ('all', 'ubuntu', 'darwin', 'windows') - default 'all'

    Returns full relationship graph with matching nodes and their connections.
    """
    search_term = request.args.get('q', '').strip()
    node_type = request.args.get('type', 'all').strip().lower()
    platform_filter = request.args.get('platform', 'all').strip().lower()
    team_filter = request.args.get('team', 'all').strip()

    # Label scoping (plan section 1E + 2A): bolted on additively via the
    # apply_label_filter helper so existing team/platform logic stays intact.
    # The label fragment always starts with " AND " or is empty; appending
    # it after the existing inline team/platform AND chain is safe.
    try:
        label_flt_fragment, label_flt_params = apply_label_filter(request.args)
    except FilterValidationError as exc:
        return jsonify({"error": "Invalid filter", "message": str(exc)}), 400

    # Advanced search parameters
    search_mode = request.args.get('mode', 'wildcard').strip().lower()  # wildcard, exact, regex
    case_sensitive = request.args.get('case', 'false').strip().lower() == 'true'

    # Validate key inputs BEFORE touching the database so callers get a 400 even
    # when Memgraph is down — and so a malicious regex never reaches the DB.
    allowed_node_types = {'all', 'host', 'user', 'software'}
    if node_type not in allowed_node_types:
        return jsonify({
            "error": "Invalid node type",
            "message": f"type must be one of {sorted(allowed_node_types)}",
        }), 400

    allowed_search_modes = {'wildcard', 'exact', 'regex'}
    if search_mode not in allowed_search_modes:
        return jsonify({
            "error": "Invalid search mode",
            "message": f"mode must be one of {sorted(allowed_search_modes)}",
        }), 400

    # Basic input size guardrails (avoid pathological queries / regex)
    if len(search_term) > 200:
        return jsonify({
            "error": "Search term too long",
            "message": "q must be <= 200 characters",
        }), 400

    # ReDoS guard: when caller asked for regex mode, validate the pattern up-front
    # so catastrophic-backtracking patterns never reach Memgraph.
    if search_mode == "regex" and search_term:
        ok, msg = _validate_user_regex(search_term)
        if not ok:
            return jsonify({"error": "Invalid regex", "message": msg}), 400

    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    # Limit parameter. Hard-capped so an authenticated (or loopback) caller
    # cannot `?limit=1000000` the whole graph into one response.
    try:
        limit_param = int(request.args.get('limit', 0))
    except (TypeError, ValueError):
        limit_param = 0
    if limit_param > 0:
        limit_param = min(limit_param, 5000)

    cypher_limit = limit_param if limit_param > 0 else 100
    display_limit = limit_param if limit_param > 0 else 10


    # Helper function to generate search condition based on mode
    def get_search_condition(property_name, term_param_name):
        if search_mode == 'exact':
            if case_sensitive:
                return f"{property_name} = ${term_param_name}"
            return f"toLower({property_name}) = toLower(${term_param_name})"

        if search_mode == 'regex':
            # Regex match using =~. For case-insensitive regex we match against a lowercased property.
            if case_sensitive:
                return f"{property_name} =~ ${term_param_name}"
            return f"toLower({property_name}) =~ ${term_param_name}_lower"

        # wildcard (default): substring match
        if case_sensitive:
            return f"{property_name} CONTAINS ${term_param_name}"
        return f"toLower({property_name}) CONTAINS toLower(${term_param_name})"
    

    # Prepare search logging
    if search_term:
        logger.info(f"Search: '{search_term}' (mode: {search_mode}, case: {case_sensitive}, type: {node_type})")
    else:
        logger.info(f"Search: ALL (type: {node_type}, limit: {limit_param})")

    with driver.session() as session:
        nodes = []
        node_ids = set()
        # Cache raw host records here; we materialize the viz nodes in a second
        # pass once every host has been collected so display_name can be
        # disambiguated for hostname collisions (mac.lan #1229 vs mac.lan #1367
        # — multiple Macs share Fleet's default hostname).
        host_records_raw: list = []

        # Search/load hosts
        if node_type in ['all', 'host']:
            if search_term:
                # Search hosts by hostname or OS version
                host_condition = get_search_condition('h.hostname', 'search_term')
                os_condition = get_search_condition('h.os_version', 'search_term')

                host_query = f"""
                    MATCH (h:Host)
                    WHERE ({host_condition} OR {os_condition})
                """
                if platform_filter != 'all':
                    host_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                if team_filter != 'all':
                    host_query += " AND toString(h.team_id) = $team_id"
                host_query += label_flt_fragment
                host_query += " RETURN DISTINCT h.fleet_host_id AS fleet_host_id, h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform, h.team_name AS team_name"
                # Apply limit to search results too if requested
                if limit_param > 0:
                    host_query += f" LIMIT {cypher_limit}"

                params = {'search_term': search_term}
                if search_mode == 'regex' and not case_sensitive:
                    params['search_term_lower'] = search_term.lower()
                if platform_filter != 'all':
                    params['platform'] = platform_filter
                if team_filter != 'all':
                    params['team_id'] = team_filter
                params.update(label_flt_params)
                host_result = session.run(host_query, **params)
            else:
                # No search term: return ALL hosts (with optional platform and team filters)
                host_query = "MATCH (h:Host) WHERE 1=1"
                params = {}

                if platform_filter != 'all':
                    host_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                    params['platform'] = platform_filter
                if team_filter != 'all':
                    host_query += " AND toString(h.team_id) = $team_id"
                    params['team_id'] = team_filter
                host_query += label_flt_fragment
                params.update(label_flt_params)

                host_query += " RETURN DISTINCT h.fleet_host_id AS fleet_host_id, h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform, h.team_name AS team_name"
                # Apply default limit if no term
                host_query += f" LIMIT {cypher_limit}"

                host_result = session.run(host_query, **params)

            for record in host_result:
                host_records_raw.append({
                    'fleet_host_id': record['fleet_host_id'],
                    'hostname': record['hostname'],
                    'os_version': record['os_version'],
                    'platform': record['platform'],
                    'team_name': record['team_name'],
                })

        # Search/load users
        if node_type in ['all', 'user']:
            if search_term:
                # Search users by username, email, or fullname
                # Search users by username, email, or fullname
                username_cond = get_search_condition('u.username', 'search_term')
                email_cond = get_search_condition('u.email', 'search_term')
                fullname_cond = get_search_condition('u.fullname', 'search_term')
                
                user_query = f"""
                    MATCH (u:User)-[:USES]->(h:Host)
                    WHERE ({username_cond} OR {email_cond} OR {fullname_cond})
                """
                params = {'search_term': search_term}
                if search_mode == 'regex' and not case_sensitive:
                    params['search_term_lower'] = search_term.lower()

                if platform_filter != 'all':
                    user_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                    params['platform'] = platform_filter
                if team_filter != 'all':
                    user_query += " AND toString(h.team_id) = $team_id"
                    params['team_id'] = team_filter
                user_query += label_flt_fragment
                params.update(label_flt_params)

                user_query += " RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname"
                if limit_param > 0:
                    user_query += f" LIMIT {cypher_limit}"

                user_result = session.run(user_query, **params)
            else:
                # No search term: return ALL users (with optional platform and team filters)
                user_query = "MATCH (u:User)-[:USES]->(h:Host) WHERE 1=1"
                params = {}

                if platform_filter != 'all':
                    user_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                    params['platform'] = platform_filter
                if team_filter != 'all':
                    user_query += " AND toString(h.team_id) = $team_id"
                    params['team_id'] = team_filter
                user_query += label_flt_fragment
                params.update(label_flt_params)

                user_query += " RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname"
                user_query += f" LIMIT {cypher_limit}"

                user_result = session.run(user_query, **params)

            for record in user_result:
                user_id = f"user_{record['username']}"
                if user_id not in node_ids:
                    nodes.append({
                        "id": user_id,
                        "name": record['username'],
                        "type": "user",
                        "details": record['email'] or record['fullname'] or ''
                    })
                    node_ids.add(user_id)

        # Search/load software
        if node_type in ['all', 'software']:
            if search_term:
                # Search software by stable id (`name`) or human title.
                software_cond = (
                    f"({get_search_condition('s.name', 'search_term')} OR "
                    f"{get_search_condition('coalesce(s.display_name, s.name)', 'search_term')})"
                )
                
                software_query = f"""
                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                    WHERE {software_cond}
                """
                params = {'search_term': search_term}
                if search_mode == 'regex' and not case_sensitive:
                    params['search_term_lower'] = search_term.lower()

                if platform_filter != 'all':
                    software_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                    params['platform'] = platform_filter
                if team_filter != 'all':
                    software_query += " AND toString(h.team_id) = $team_id"
                    params['team_id'] = team_filter
                software_query += label_flt_fragment
                params.update(label_flt_params)

                software_query += """
                    WITH s, COUNT(DISTINCT h) as host_count
                    RETURN s.name AS name, coalesce(s.display_name, s.name) AS display_name, s.last_version AS last_version, s.category AS category, s.wikidata_description AS description, host_count
                """
                if limit_param > 0:
                    software_query += f" LIMIT {cypher_limit}"

                software_result = session.run(software_query, **params)
            else:
                # No search term: return top 100 software by host count (with optional platform and team filters)
                software_query = """
                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                    WHERE 1=1
                """
                params = {}

                if platform_filter != 'all':
                    software_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                    params['platform'] = platform_filter
                if team_filter != 'all':
                    software_query += " AND toString(h.team_id) = $team_id"
                    params['team_id'] = team_filter
                software_query += label_flt_fragment
                params.update(label_flt_params)

                software_query += f"""
                    WITH s.name AS name, coalesce(s.display_name, s.name) AS display_name, s.last_version AS last_version, s.category AS category, s.wikidata_description AS description, COUNT(DISTINCT h) AS host_count
                    ORDER BY host_count DESC
                    LIMIT {cypher_limit}
                    RETURN name, display_name, last_version, category, description, host_count
                """
                software_result = session.run(software_query, **params)

            # Limit to 10 unique software items for visualization ONLY when showing "ALL" (no search term)
            # When user searches for specific software, show ALL matching results
            software_count = 0
            for record in software_result:
                software_id = f"software_{record['name']}"
                if software_id not in node_ids:
                    # Only apply limit when there's no search term (the "ALL" case)
                    if not search_term and software_count >= display_limit:
                        break
                    nodes.append({
                        "id": software_id,
                        "name": record['name'],
                        "display_name": record.get('display_name') or record['name'],
                        "type": "software",
                        "category": record.get('category'),
                        "description": record.get('description'),
                        "details": f"Latest: {record['last_version'] or 'unknown'} (on {record.get('host_count', 0)} hosts)"
                    })
                    node_ids.add(software_id)
                    software_count += 1

        # If we loaded software or users, we need to also load their connected hosts
        # to ensure we have complete relationships
        software_ids_loaded = [nid for nid in node_ids if nid.startswith('software_')]
        user_ids_loaded = [nid for nid in node_ids if nid.startswith('user_')]

        if software_ids_loaded and (node_type == 'software' or node_type == 'all'):
            # Load hosts connected to the software we loaded
            software_names = [sid.replace('software_', '') for sid in software_ids_loaded]
            host_query = """
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE s.name IN $software_names
            """
            params = {'software_names': software_names}

            if platform_filter != 'all':
                host_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                params['platform'] = platform_filter
            if team_filter != 'all':
                host_query += " AND toString(h.team_id) = $team_id"
                params['team_id'] = team_filter
            # Label scope: the matched software was already label-scoped, but this
            # connected-host pass would otherwise pull in EVERY host with that
            # software (any label) — leaking out-of-scope hosts onto the graph.
            host_query += label_flt_fragment
            params.update(label_flt_params)

            host_query += " RETURN DISTINCT h.fleet_host_id AS fleet_host_id, h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform, h.team_name AS team_name"

            host_result = session.run(host_query, **params)
            for record in host_result:
                host_records_raw.append({
                    'fleet_host_id': record['fleet_host_id'],
                    'hostname': record['hostname'],
                    'os_version': record['os_version'],
                    'platform': record['platform'],
                    'team_name': record['team_name'],
                })

        if user_ids_loaded and (node_type == 'user' or node_type == 'all'):
            # Load hosts connected to the users we loaded
            usernames = [uid.replace('user_', '') for uid in user_ids_loaded]
            host_query = """
                MATCH (u:User)-[:USES]->(h:Host)
                WHERE u.username IN $usernames
            """
            params = {'usernames': usernames}

            if platform_filter != 'all':
                host_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                params['platform'] = platform_filter
            if team_filter != 'all':
                host_query += " AND toString(h.team_id) = $team_id"
                params['team_id'] = team_filter
            # Label scope: matched users were label-scoped, but this connected-host
            # pass would otherwise pull in EVERY host they use (any label).
            host_query += label_flt_fragment
            params.update(label_flt_params)

            host_query += " RETURN DISTINCT h.fleet_host_id AS fleet_host_id, h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform, h.team_name AS team_name"

            host_result = session.run(host_query, **params)
            for record in host_result:
                host_records_raw.append({
                    'fleet_host_id': record['fleet_host_id'],
                    'hostname': record['hostname'],
                    'os_version': record['os_version'],
                    'platform': record['platform'],
                    'team_name': record['team_name'],
                })

        # Materialize host viz nodes — dedupe by fleet_host_id, disambiguate
        # display when hostname collides. Runs AFTER both load passes so we
        # have the full set of hosts in scope.
        seen_fids: set = set()
        host_records_unique: list = []
        for hr in host_records_raw:
            fid = hr['fleet_host_id']
            if fid is None or fid in seen_fids:
                continue
            seen_fids.add(fid)
            host_records_unique.append(hr)

        hostname_counts = _hostname_counts(host_records_unique)
        for hr in host_records_unique:
            fid = hr['fleet_host_id']
            hn = hr['hostname']
            host_id = f"host_{fid}"
            display_name = disambiguated_display_name(hn, fid, hostname_counts)
            team_info = f" - Team: {hr.get('team_name', 'No team')}" if hr.get('team_name') else ""
            nodes.append({
                "id": host_id,
                "name": hn,
                "display_name": display_name,
                "fleet_host_id": fid,
                "type": "host",
                "details": f"{hr['os_version'] or ''} ({hr['platform'] or ''}){team_info}",
            })
            node_ids.add(host_id)

        # Now get all relationships between the loaded nodes
        links = []

        # Get user-host relationships
        if node_ids:
            # Build filter conditions. Host filter uses fleet_host_id (the
            # viz node id key); hostname is NOT unique and would over-match
            # across collision groups like 4 distinct macs named "mac.lan".
            user_ids_list = [nid.replace('user_', '') for nid in node_ids if nid.startswith('user_')]
            host_fids_list: list = []
            for nid in node_ids:
                if not nid.startswith('host_'):
                    continue
                try:
                    host_fids_list.append(int(nid[len('host_'):]))
                except ValueError:
                    continue

            if user_ids_list or host_fids_list:
                user_host_query = """
                    MATCH (u:User)-[:USES]->(h:Host)
                """
                conditions = []
                params = {}

                if user_ids_list:
                    conditions.append("u.username IN $user_list")
                    params['user_list'] = user_ids_list
                if host_fids_list:
                    conditions.append("h.fleet_host_id IN $host_fid_list")
                    params['host_fid_list'] = host_fids_list

                if conditions:
                    user_host_query += " WHERE " + " OR ".join(conditions)

                # Apply team filter to relationships to prevent cross-team contamination
                if team_filter != 'all':
                    if conditions:
                        user_host_query += " AND toString(h.team_id) = $team_id"
                    else:
                        user_host_query += " WHERE toString(h.team_id) = $team_id"
                    params['team_id'] = team_filter

                # Apply platform filter to relationships
                if platform_filter != 'all':
                    if conditions or team_filter != 'all':
                        user_host_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                    else:
                        user_host_query += " WHERE toLower(h.platform) CONTAINS toLower($platform)"
                    params['platform'] = platform_filter

                # Apply label scope to relationships (mirrors team/platform above)
                # so edges to out-of-scope hosts are never emitted. WHERE always
                # exists here (the enclosing guard requires a non-empty id list).
                user_host_query += label_flt_fragment
                params.update(label_flt_params)

                user_host_query += " RETURN DISTINCT u.username AS username, h.fleet_host_id AS fleet_host_id"

                user_host_result = session.run(user_host_query, **params)

                for record in user_host_result:
                    source_id = f"user_{record['username']}"
                    target_id = f"host_{record['fleet_host_id']}"
                    if source_id in node_ids and target_id in node_ids:
                        links.append({
                            "source": source_id,
                            "target": target_id,
                            "type": "uses"
                        })

        # Get software-host relationships
        if node_ids:
            software_ids_list = [nid.replace('software_', '') for nid in node_ids if nid.startswith('software_')]
            host_fids_list = []
            for nid in node_ids:
                if not nid.startswith('host_'):
                    continue
                try:
                    host_fids_list.append(int(nid[len('host_'):]))
                except ValueError:
                    continue

            if software_ids_list or host_fids_list:
                software_host_query = """
                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                """
                conditions = []
                params = {}

                if software_ids_list:
                    conditions.append("s.name IN $software_list")
                    params['software_list'] = software_ids_list
                if host_fids_list:
                    conditions.append("h.fleet_host_id IN $host_fid_list")
                    params['host_fid_list'] = host_fids_list

                if conditions:
                    software_host_query += " WHERE " + " OR ".join(conditions)

                # Apply team filter to relationships to prevent cross-team contamination
                if team_filter != 'all':
                    if conditions:
                        software_host_query += " AND toString(h.team_id) = $team_id"
                    else:
                        software_host_query += " WHERE toString(h.team_id) = $team_id"
                    params['team_id'] = team_filter

                # Apply platform filter to relationships
                if platform_filter != 'all':
                    if conditions or team_filter != 'all':
                        software_host_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                    else:
                        software_host_query += " WHERE toLower(h.platform) CONTAINS toLower($platform)"
                    params['platform'] = platform_filter

                # Apply label scope to relationships (mirrors team/platform above)
                # so INSTALLED edges to out-of-scope hosts are never emitted. WHERE
                # always exists here (the enclosing guard requires a non-empty id list).
                software_host_query += label_flt_fragment
                params.update(label_flt_params)

                software_host_query += " RETURN DISTINCT s.name AS software_name, h.fleet_host_id AS fleet_host_id"

                software_host_result = session.run(software_host_query, **params)

                for record in software_host_result:
                    source_id = f"software_{record['software_name']}"
                    target_id = f"host_{record['fleet_host_id']}"
                    if source_id in node_ids and target_id in node_ids:
                        links.append({
                            "source": source_id,
                            "target": target_id,
                            "type": "installed"
                        })

        search_desc = f"'{search_term}'" if search_term else "ALL"
        logger.info(f"Search {search_desc} (type: {node_type}, platform: {platform_filter}): Returning {len(nodes)} nodes and {len(links)} links")

        return jsonify({
            "nodes": nodes,
            "links": links,
            "search_term": search_term,
            "node_type": node_type,
            "platform_filter": platform_filter,
            "node_count": len(nodes),
            "link_count": len(links)
        })

@bp.route("/api/search/software")
def search_software():
    """Legacy endpoint - redirects to new universal search endpoint.

    Kept for backward compatibility with existing frontend code.
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    search_term = request.args.get('q', '').strip()
    platform_filter = request.args.get('platform', 'all').strip().lower()

    with driver.session() as session:
        nodes = []
        node_ids = set()

        # Search for ALL software matching the search term (case-insensitive, partial match)
        # If search_term is empty, return ALL software
        if search_term:
            software_query = """
                MATCH (s:Software)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                   OR toLower(coalesce(s.display_name, '')) CONTAINS toLower($search_term)
                RETURN DISTINCT s.name AS name,
                       coalesce(s.display_name, s.name) AS display_name,
                       s.last_version AS last_version
                ORDER BY coalesce(s.display_name, s.name)
            """
            software_result = session.run(software_query, search_term=search_term)
        else:
            # No search term: return top 100 software by host count
            # Apply platform filter if specified to reduce data
            if platform_filter != 'all':
                software_query = """
                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                    WHERE toLower(h.platform) CONTAINS toLower($platform)
                    WITH s.name AS name,
                         coalesce(s.display_name, s.name) AS display_name,
                         s.last_version AS last_version,
                         COUNT(DISTINCT h) AS host_count
                    ORDER BY host_count DESC
                    LIMIT 100
                    RETURN name, display_name, last_version, host_count
                """
                software_result = session.run(software_query, platform=platform_filter)
            else:
                software_query = """
                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                    WITH s.name AS name,
                         coalesce(s.display_name, s.name) AS display_name,
                         s.last_version AS last_version,
                         COUNT(DISTINCT h) AS host_count
                    ORDER BY host_count DESC
                    LIMIT 100
                    RETURN name, display_name, last_version, host_count
                """
                software_result = session.run(software_query)

        software_list = [record for record in software_result]

        if not software_list:
            msg = f"No software found matching '{search_term}'" if search_term else "No software found"
            return jsonify({"nodes": [], "links": [], "message": msg}), 200

        # Add matching software nodes - limit to 10 unique items ONLY when showing "ALL" (no search term)
        # When user searches for specific software, show ALL matching results
        software_count = 0
        for record in software_list:
            # Only apply limit when there's no search term (the "ALL" case)
            if not search_term and software_count >= 10:
                break
            software_id = f"software_{record['name']}"
            nodes.append({
                "id": software_id,
                "name": record['name'],
                "display_name": record.get('display_name') or record['name'],
                "type": "software",
                "details": f"Latest: {record['last_version'] or 'unknown'} (on {record.get('host_count', 0)} hosts)"
            })
            node_ids.add(software_id)
            software_count += 1

        # Get ALL hosts that have any of the matching software, with optional
        # platform filter. Keyed on fleet_host_id (stable, unique) — hostname
        # is NOT unique (Fleet's default "mac.lan" collision) and would both
        # over-match and never line up with the host_<fid> ids the rest of the
        # app emits.
        if platform_filter == 'all':
            host_result = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                RETURN DISTINCT h.fleet_host_id AS fleet_host_id,
                               h.hostname AS hostname,
                               h.os_version AS os_version,
                               h.platform AS platform
            """, search_term=search_term)
        else:
            host_result = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                  AND toLower(h.platform) CONTAINS toLower($platform)
                RETURN DISTINCT h.fleet_host_id AS fleet_host_id,
                               h.hostname AS hostname,
                               h.os_version AS os_version,
                               h.platform AS platform
            """, search_term=search_term, platform=platform_filter)

        host_records = [record for record in host_result if record['fleet_host_id'] is not None]
        hostname_counts = _hostname_counts(host_records)
        for record in host_records:
            fid = record['fleet_host_id']
            host_id = f"host_{fid}"
            if host_id not in node_ids:
                hn = record['hostname']
                nodes.append({
                    "id": host_id,
                    "name": hn,
                    "display_name": disambiguated_display_name(hn, fid, hostname_counts),
                    "fleet_host_id": fid,
                    "type": "host",
                    "details": f"{record['os_version'] or ''} ({record['platform'] or ''})"
                })
                node_ids.add(host_id)

        # Get users connected to these hosts (with platform filter if applicable)
        if platform_filter == 'all':
            user_result = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname
            """, search_term=search_term)
        else:
            user_result = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                  AND toLower(h.platform) CONTAINS toLower($platform)
                RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname
            """, search_term=search_term, platform=platform_filter)

        for record in user_result:
            user_id = f"user_{record['username']}"
            if user_id not in node_ids:
                nodes.append({
                    "id": user_id,
                    "name": record['username'],
                    "type": "user",
                    "details": record['email'] or record['fullname'] or ''
                })
                node_ids.add(user_id)

        # Get all relationships
        links = []

        # Software-Host relationships (with platform filter if applicable)
        if platform_filter == 'all':
            software_host_links = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                RETURN s.name AS software_name, h.fleet_host_id AS fleet_host_id
            """, search_term=search_term)
        else:
            software_host_links = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                  AND toLower(h.platform) CONTAINS toLower($platform)
                RETURN s.name AS software_name, h.fleet_host_id AS fleet_host_id
            """, search_term=search_term, platform=platform_filter)

        for record in software_host_links:
            source_id = f"software_{record['software_name']}"
            target_id = f"host_{record['fleet_host_id']}"
            if source_id in node_ids and target_id in node_ids:
                links.append({
                    "source": source_id,
                    "target": target_id,
                    "type": "installed"
                })

        # User-Host relationships (for hosts that have the matching software, with platform filter)
        if platform_filter == 'all':
            user_host_links = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                RETURN DISTINCT u.username AS username, h.fleet_host_id AS fleet_host_id
            """, search_term=search_term)
        else:
            user_host_links = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                  AND toLower(h.platform) CONTAINS toLower($platform)
                RETURN DISTINCT u.username AS username, h.fleet_host_id AS fleet_host_id
            """, search_term=search_term, platform=platform_filter)

        for record in user_host_links:
            source_id = f"user_{record['username']}"
            target_id = f"host_{record['fleet_host_id']}"
            if source_id in node_ids and target_id in node_ids:
                links.append({
                    "source": source_id,
                    "target": target_id,
                    "type": "uses"
                })

        search_desc = f"'{search_term}'" if search_term else "ALL"
        logger.info(f"Software search {search_desc} (platform: {platform_filter}): Found {len(software_list)} software, returning {len(nodes)} nodes and {len(links)} links")
        return jsonify({
            "nodes": nodes,
            "links": links,
            "search_term": search_term,
            "platform_filter": platform_filter,
            "software_count": len(software_list)
        })
