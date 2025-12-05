from flask import Flask, jsonify, send_from_directory, request
from neo4j import GraphDatabase
from neo4j.exceptions import TransientError
import os
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static')
MEMGRAPH_URI = os.environ.get("MEMGRAPH_URI", "bolt://memgraph:7687")

# Test connection to Memgraph with retry logic
driver = None
max_retries = 5
retry_count = 0

while retry_count < max_retries and not driver:
    try:
        driver = GraphDatabase.driver(MEMGRAPH_URI)
        with driver.session() as session:
            session.run("RETURN 1")
        logger.info(f"✓ Connected to Memgraph at {MEMGRAPH_URI}")
        break
    except Exception as e:
        retry_count += 1
        if retry_count < max_retries:
            logger.warning(f"Connection attempt {retry_count} failed, retrying... ({e})")
            import time
            time.sleep(2)
        else:
            logger.error(f"✗ Failed to connect to Memgraph after {max_retries} attempts: {e}")
            driver = None

@app.route("/api/hosts")
def get_hosts():
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    with driver.session() as session:
        result = session.run("MATCH (h:Host) RETURN h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform, h.ip AS ip, h.last_seen AS last_seen")
        return jsonify([r.data() for r in result])

@app.route("/api/users")
def get_users():
    """Get users per host - only users that are connected to hosts"""
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    with driver.session() as session:
        result = session.run("""
            MATCH (u:User)-[:USES]->(h:Host) 
            RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname, 
                   h.hostname AS hostname, h.platform AS platform
            ORDER BY h.hostname, u.username
        """)
        users = [r.data() for r in result]
        # Filter out any users that don't have proper host connections
        filtered_users = [user for user in users if user.get('hostname')]
        return jsonify(filtered_users)

@app.route("/api/software")
def get_software():
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    with driver.session() as session:
        result = session.run("MATCH (s:Software) RETURN s.name AS name, s.versions AS versions, s.last_version AS last_version")
        return jsonify([r.data() for r in result])

@app.route("/api/teams")
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

@app.route("/api/platforms")
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

@app.route("/api/search")
def search_all():
    """Universal search endpoint for all node types (hosts, users, software).

    Query parameters:
    - q: search term (optional - if empty, returns ALL nodes of specified type)
    - type: node type filter ('all', 'host', 'user', 'software') - default 'all'
    - platform: platform filter ('all', 'ubuntu', 'darwin', 'windows') - default 'all'

    Returns full relationship graph with matching nodes and their connections.
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    search_term = request.args.get('q', '').strip()
    node_type = request.args.get('type', 'all').strip().lower()
    platform_filter = request.args.get('platform', 'all').strip().lower()
    team_filter = request.args.get('team', 'all').strip()

    with driver.session() as session:
        nodes = []
        node_ids = set()

        # Search/load hosts
        if node_type in ['all', 'host']:
            if search_term:
                # Search hosts by hostname or OS version
                host_query = """
                    MATCH (h:Host)
                    WHERE toLower(h.hostname) CONTAINS toLower($search_term)
                       OR toLower(h.os_version) CONTAINS toLower($search_term)
                """
                if platform_filter != 'all':
                    host_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                if team_filter != 'all':
                    host_query += " AND toString(h.team_id) = $team_id"
                host_query += " RETURN DISTINCT h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform, h.team_name AS team_name"

                params = {'search_term': search_term}
                if platform_filter != 'all':
                    params['platform'] = platform_filter
                if team_filter != 'all':
                    params['team_id'] = team_filter
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

                host_query += " RETURN DISTINCT h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform, h.team_name AS team_name"
                host_result = session.run(host_query, **params)

            for record in host_result:
                host_id = f"host_{record['hostname']}"
                team_info = f" - Team: {record.get('team_name', 'No team')}" if record.get('team_name') else ""
                nodes.append({
                    "id": host_id,
                    "name": record['hostname'],
                    "type": "host",
                    "details": f"{record['os_version'] or ''} ({record['platform'] or ''}){team_info}"
                })
                node_ids.add(host_id)

        # Search/load users
        if node_type in ['all', 'user']:
            if search_term:
                # Search users by username, email, or fullname
                user_query = """
                    MATCH (u:User)-[:USES]->(h:Host)
                    WHERE (toLower(u.username) CONTAINS toLower($search_term)
                       OR toLower(u.email) CONTAINS toLower($search_term)
                       OR toLower(u.fullname) CONTAINS toLower($search_term))
                """
                params = {'search_term': search_term}

                if platform_filter != 'all':
                    user_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                    params['platform'] = platform_filter
                if team_filter != 'all':
                    user_query += " AND toString(h.team_id) = $team_id"
                    params['team_id'] = team_filter

                user_query += " RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname"
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

                user_query += " RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname"
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
                # Search software by name
                software_query = """
                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                    WHERE toLower(s.name) CONTAINS toLower($search_term)
                """
                params = {'search_term': search_term}

                if platform_filter != 'all':
                    software_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                    params['platform'] = platform_filter
                if team_filter != 'all':
                    software_query += " AND toString(h.team_id) = $team_id"
                    params['team_id'] = team_filter

                software_query += " RETURN DISTINCT s.name AS name, s.last_version AS last_version"
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

                software_query += """
                    WITH s.name AS name, s.last_version AS last_version, COUNT(DISTINCT h) AS host_count
                    ORDER BY host_count DESC
                    LIMIT 100
                    RETURN name, last_version, host_count
                """
                software_result = session.run(software_query, **params)

            # Limit to 10 unique software items for visualization ONLY when showing "ALL" (no search term)
            # When user searches for specific software, show ALL matching results
            software_count = 0
            for record in software_result:
                software_id = f"software_{record['name']}"
                if software_id not in node_ids:
                    # Only apply limit when there's no search term (the "ALL" case)
                    if not search_term and software_count >= 10:
                        break
                    nodes.append({
                        "id": software_id,
                        "name": record['name'],
                        "type": "software",
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

            host_query += " RETURN DISTINCT h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform, h.team_name AS team_name"

            host_result = session.run(host_query, **params)
            for record in host_result:
                host_id = f"host_{record['hostname']}"
                if host_id not in node_ids:
                    team_info = f" - Team: {record.get('team_name', 'No team')}" if record.get('team_name') else ""
                    nodes.append({
                        "id": host_id,
                        "name": record['hostname'],
                        "type": "host",
                        "details": f"{record['os_version'] or ''} ({record['platform'] or ''}){team_info}"
                    })
                    node_ids.add(host_id)

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

            host_query += " RETURN DISTINCT h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform, h.team_name AS team_name"

            host_result = session.run(host_query, **params)
            for record in host_result:
                host_id = f"host_{record['hostname']}"
                if host_id not in node_ids:
                    team_info = f" - Team: {record.get('team_name', 'No team')}" if record.get('team_name') else ""
                    nodes.append({
                        "id": host_id,
                        "name": record['hostname'],
                        "type": "host",
                        "details": f"{record['os_version'] or ''} ({record['platform'] or ''}){team_info}"
                    })
                    node_ids.add(host_id)

        # Now get all relationships between the loaded nodes
        links = []

        # Get user-host relationships
        if node_ids:
            user_host_query = """
                MATCH (u:User)-[:USES]->(h:Host)
                WHERE $user_filter OR $host_filter
                RETURN DISTINCT u.username AS username, h.hostname AS hostname
            """
            # Build filter conditions
            user_ids_list = [nid.replace('user_', '') for nid in node_ids if nid.startswith('user_')]
            host_ids_list = [nid.replace('host_', '') for nid in node_ids if nid.startswith('host_')]

            if user_ids_list or host_ids_list:
                user_host_query = """
                    MATCH (u:User)-[:USES]->(h:Host)
                """
                conditions = []
                params = {}

                if user_ids_list:
                    conditions.append("u.username IN $user_list")
                    params['user_list'] = user_ids_list
                if host_ids_list:
                    conditions.append("h.hostname IN $host_list")
                    params['host_list'] = host_ids_list

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

                user_host_query += " RETURN DISTINCT u.username AS username, h.hostname AS hostname"

                user_host_result = session.run(user_host_query, **params)

                for record in user_host_result:
                    source_id = f"user_{record['username']}"
                    target_id = f"host_{record['hostname']}"
                    if source_id in node_ids and target_id in node_ids:
                        links.append({
                            "source": source_id,
                            "target": target_id,
                            "type": "uses"
                        })

        # Get software-host relationships
        if node_ids:
            software_ids_list = [nid.replace('software_', '') for nid in node_ids if nid.startswith('software_')]
            host_ids_list = [nid.replace('host_', '') for nid in node_ids if nid.startswith('host_')]

            if software_ids_list or host_ids_list:
                software_host_query = """
                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                """
                conditions = []
                params = {}

                if software_ids_list:
                    conditions.append("s.name IN $software_list")
                    params['software_list'] = software_ids_list
                if host_ids_list:
                    conditions.append("h.hostname IN $host_list")
                    params['host_list'] = host_ids_list

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

                software_host_query += " RETURN DISTINCT s.name AS software_name, h.hostname AS hostname"

                software_host_result = session.run(software_host_query, **params)

                for record in software_host_result:
                    source_id = f"software_{record['software_name']}"
                    target_id = f"host_{record['hostname']}"
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

@app.route("/api/search/software")
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
                RETURN DISTINCT s.name AS name, s.last_version AS last_version
                ORDER BY s.name
            """
            software_result = session.run(software_query, search_term=search_term)
        else:
            # No search term: return top 100 software by host count
            # Apply platform filter if specified to reduce data
            if platform_filter != 'all':
                software_query = """
                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                    WHERE toLower(h.platform) CONTAINS toLower($platform)
                    WITH s.name AS name, s.last_version AS last_version, COUNT(DISTINCT h) AS host_count
                    ORDER BY host_count DESC
                    LIMIT 100
                    RETURN name, last_version, host_count
                """
                software_result = session.run(software_query, platform=platform_filter)
            else:
                software_query = """
                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                    WITH s.name AS name, s.last_version AS last_version, COUNT(DISTINCT h) AS host_count
                    ORDER BY host_count DESC
                    LIMIT 100
                    RETURN name, last_version, host_count
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
                "type": "software",
                "details": f"Latest: {record['last_version'] or 'unknown'} (on {record.get('host_count', 0)} hosts)"
            })
            node_ids.add(software_id)
            software_count += 1

        # Get ALL hosts that have any of the matching software, with optional platform filter
        if platform_filter == 'all':
            host_result = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                RETURN DISTINCT h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform
            """, search_term=search_term)
        else:
            host_result = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                  AND toLower(h.platform) CONTAINS toLower($platform)
                RETURN DISTINCT h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform
            """, search_term=search_term, platform=platform_filter)

        for record in host_result:
            host_id = f"host_{record['hostname']}"
            if host_id not in node_ids:
                nodes.append({
                    "id": host_id,
                    "name": record['hostname'],
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
                RETURN s.name AS software_name, h.hostname AS hostname
            """, search_term=search_term)
        else:
            software_host_links = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                  AND toLower(h.platform) CONTAINS toLower($platform)
                RETURN s.name AS software_name, h.hostname AS hostname
            """, search_term=search_term, platform=platform_filter)

        for record in software_host_links:
            source_id = f"software_{record['software_name']}"
            target_id = f"host_{record['hostname']}"
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
                RETURN DISTINCT u.username AS username, h.hostname AS hostname
            """, search_term=search_term)
        else:
            user_host_links = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                  AND toLower(h.platform) CONTAINS toLower($platform)
                RETURN DISTINCT u.username AS username, h.hostname AS hostname
            """, search_term=search_term, platform=platform_filter)

        for record in user_host_links:
            source_id = f"user_{record['username']}"
            target_id = f"host_{record['hostname']}"
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

@app.route("/api/graph")
def get_graph_data():
    """Get graph data formatted for D3.js force layout"""
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    
    with driver.session() as session:
        # Get all nodes (only those with relationships)
        nodes = []

        # Host nodes - only hosts that have users connected
        host_result = session.run("""
            MATCH (h:Host)<-[:USES]-(u:User)
            RETURN DISTINCT h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform
        """)
        for record in host_result:
            nodes.append({
                "id": f"host_{record['hostname']}",
                "name": record['hostname'],
                "type": "host",
                "details": f"{record['os_version'] or ''} ({record['platform'] or ''})"
            })

        # User nodes (only those connected to hosts)
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
        
        # Get ONLY user-host relationships for clean initial view
        links = []
        rel_result = session.run("""
            MATCH (u:User)-[r:USES]->(h:Host)
            RETURN 'uses' AS type, u.username AS from_name, h.hostname AS to_host
        """)
        
        for record in rel_result:
            source_id = f"user_{record['from_name']}"
            target_id = f"host_{record['to_host']}"
            
            links.append({
                "source": source_id,
                "target": target_id,
                "type": record['type']
            })
        
        return jsonify({"nodes": nodes, "links": links})

@app.route("/api/graph/full")
def get_full_graph_data():
    """Get full graph data including software for expansion"""
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        with driver.session() as session:
            # Get all nodes including software (only connected nodes)
            nodes = []
            node_ids = set()  # Track node IDs to ensure links are valid

            # Host nodes - only hosts with relationships (users or software)
            host_result = session.run("""
                MATCH (h:Host)
                WHERE EXISTS((h)<-[:USES]-(:User)) OR EXISTS((h)<-[:INSTALLED_ON]-(:Software))
                RETURN h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform
            """)
            for record in host_result:
                node_id = f"host_{record['hostname']}"
                nodes.append({
                    "id": node_id,
                    "name": record['hostname'],
                    "type": "host",
                    "details": f"{record['os_version'] or ''} ({record['platform'] or ''})"
                })
                node_ids.add(node_id)

            # User nodes
            user_result = session.run("""
                MATCH (u:User)-[:USES]->(h:Host)
                RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname
            """)
            for record in user_result:
                node_id = f"user_{record['username']}"
                nodes.append({
                    "id": node_id,
                    "name": record['username'],
                    "type": "user",
                    "details": record['email'] or record['fullname'] or ''
                })
                node_ids.add(node_id)

            # Software nodes - ultra memory-efficient approach
            # Load top 50 software globally by host count (simplest, most memory-efficient)
            # This avoids expensive COLLECT operations on large datasets
            software_result = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WITH s.name AS name, s.last_version AS last_version, COUNT(DISTINCT h) AS host_count
                ORDER BY host_count DESC
                LIMIT 50
                RETURN name, last_version, host_count
            """)
            for record in software_result:
                node_id = f"software_{record['name']}"
                nodes.append({
                    "id": node_id,
                    "name": record['name'],
                    "type": "software",
                    "details": f"Latest: {record['last_version'] or 'unknown'} (on {record['host_count']} hosts)"
                })
                node_ids.add(node_id)

            # Get relationships - only for nodes that exist
            links = []

            # User-Host relationships
            rel_result = session.run("""
                MATCH (u:User)-[r:USES]->(h:Host)
                RETURN 'uses' AS type, u.username AS from_name, h.hostname AS to_host
            """)
            for record in rel_result:
                source_id = f"user_{record['from_name']}"
                target_id = f"host_{record['to_host']}"

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
                    RETURN 'installed' AS type, s.name AS from_name, h.hostname AS to_host
                """, software_names=software_names)

                added_software_links = 0
                for record in software_rel_result:
                    source_id = f"software_{record['from_name']}"
                    target_id = f"host_{record['to_host']}"

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
            return jsonify({"nodes": nodes, "links": links})

    except TransientError as e:
        error_msg = str(e)
        if "Memory limit exceeded" in error_msg:
            logger.error(f"Memory limit exceeded while loading full graph: {error_msg}")
            return jsonify({
                "error": "Dataset too large for available memory",
                "message": "The dataset is too large to load all at once. Try increasing Memgraph's memory limit in docker-compose.yml or use the filtered view instead.",
                "details": error_msg
            }), 507  # HTTP 507 Insufficient Storage
        else:
            logger.error(f"Transient error in get_full_graph_data: {error_msg}")
            return jsonify({"error": "Database transient error", "details": error_msg}), 503

    except Exception as e:
        logger.error(f"Unexpected error in get_full_graph_data: {e}", exc_info=True)
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@app.route("/api/software/<software_name>/hosts")
def get_software_hosts(software_name):
    """Get ALL hosts that have a specific software installed"""
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    
    with driver.session() as session:
        # Check if software exists
        software_check = session.run(
            "MATCH (s:Software {name: $name}) RETURN s.name AS name, s.last_version AS last_version",
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
            "type": "software",
            "details": f"Latest: {software_data['last_version'] or 'unknown'}"
        })
        node_ids.add(software_id)
        
        # Get ALL hosts that have this software
        host_result = session.run("""
            MATCH (s:Software {name: $name})-[:INSTALLED_ON]->(h:Host)
            RETURN h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform
        """, name=software_name)
        
        for record in host_result:
            host_id = f"host_{record['hostname']}"
            nodes.append({
                "id": host_id,
                "name": record['hostname'],
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
            nodes.append({
                "id": user_id,
                "name": record['username'],
                "type": "user",
                "details": record['email'] or record['fullname'] or ''
            })
            node_ids.add(user_id)
        
        # Get ALL relationships
        links = []
        
        # Software-Host relationships
        software_host_links = session.run("""
            MATCH (s:Software {name: $name})-[:INSTALLED_ON]->(h:Host)
            RETURN h.hostname AS hostname
        """, name=software_name)
        
        for record in software_host_links:
            target_id = f"host_{record['hostname']}"
            if target_id in node_ids:
                links.append({
                    "source": software_id,
                    "target": target_id,
                    "type": "installed"
                })
        
        # User-Host relationships (for hosts that have this software)
        user_host_links = session.run("""
            MATCH (s:Software {name: $name})-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
            RETURN u.username AS username, h.hostname AS hostname
        """, name=software_name)
        
        for record in user_host_links:
            source_id = f"user_{record['username']}"
            target_id = f"host_{record['hostname']}"
            if source_id in node_ids and target_id in node_ids:
                links.append({
                    "source": source_id,
                    "target": target_id,
                    "type": "uses"
                })
        
        logger.info(f"Software {software_name}: Returning {len(nodes)} nodes and {len(links)} links")
        return jsonify({"nodes": nodes, "links": links})

@app.route("/api/host/<hostname>/software")
def get_host_software(hostname):
    """Get ALL software installed on a specific host"""
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    
    with driver.session() as session:
        # Get the host
        host_result = session.run(
            "MATCH (h:Host {hostname: $hostname}) RETURN h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform",
            hostname=hostname
        )
        host_data = host_result.single()
        if not host_data:
            return jsonify({"error": "Host not found"}), 404
        
        nodes = []
        node_ids = set()
        
        # Add the host node
        host_id = f"host_{hostname}"
        nodes.append({
            "id": host_id,
            "name": hostname,
            "type": "host",
            "details": f"{host_data['os_version'] or ''} ({host_data['platform'] or ''})"
        })
        node_ids.add(host_id)
        
        # Get ALL users connected to this host
        user_result = session.run("""
            MATCH (u:User)-[:USES]->(h:Host {hostname: $hostname})
            RETURN u.username AS username, u.email AS email, u.fullname AS fullname
        """, hostname=hostname)
        
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
            MATCH (s:Software)-[:INSTALLED_ON]->(h:Host {hostname: $hostname})
            RETURN s.name AS name, s.last_version AS last_version
            ORDER BY s.name
        """, hostname=hostname)
        
        for record in software_result:
            software_id = f"software_{record['name']}"
            nodes.append({
                "id": software_id,
                "name": record['name'],
                "type": "software",
                "details": f"Latest: {record['last_version'] or 'unknown'}"
            })
            node_ids.add(software_id)
        
        # Get ALL relationships for this host
        links = []
        
        # User-Host relationships
        user_links = session.run("""
            MATCH (u:User)-[:USES]->(h:Host {hostname: $hostname})
            RETURN u.username AS username
        """, hostname=hostname)
        
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
            MATCH (s:Software)-[:INSTALLED_ON]->(h:Host {hostname: $hostname})
            RETURN s.name AS name
        """, hostname=hostname)
        
        for record in software_links:
            source_id = f"software_{record['name']}"
            if source_id in node_ids:
                links.append({
                    "source": source_id,
                    "target": host_id,
                    "type": "installed"
                })
        
        logger.info(f"Host {hostname}: Returning {len(nodes)} nodes and {len(links)} links")
        return jsonify({"nodes": nodes, "links": links})

@app.route("/api/health")
def health_check():
    """Health check endpoint for monitoring"""
    if not driver:
        return jsonify({
            "status": "unhealthy",
            "database": "disconnected"
        }), 503

    try:
        with driver.session() as session:
            result = session.run("RETURN 1")
            result.single()
        return jsonify({
            "status": "healthy",
            "database": "connected",
            "memgraph_uri": MEMGRAPH_URI
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "database": "error",
            "error": str(e)
        }), 503

@app.route("/api/relationships")
def get_relationships():
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    with driver.session() as session:
        result = session.run("""
            MATCH (u:User)-[r:USES]->(h:Host)
            RETURN 'USES' AS type, u.username AS from_name, h.hostname AS to_host
            UNION
            MATCH (s:Software)-[r:INSTALLED_ON]->(h:Host)
            RETURN 'INSTALLED_ON' AS type, s.name AS from_name, h.hostname AS to_host
        """)
        return jsonify([r.data() for r in result])

@app.route("/")
def index():
    """Serve the main web interface"""
    return send_from_directory(app.static_folder, "index.html")

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal error: {error}")
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    debug_mode = os.environ.get("DEBUG", "False").lower() == "true"

    logger.info(f"Starting Fleet Hound Web Dashboard on port {port}")
    logger.info(f"Debug mode: {debug_mode}")
    logger.info(f"Memgraph URI: {MEMGRAPH_URI}")

    app.run(host="0.0.0.0", port=port, debug=debug_mode)
