from flask import Flask, jsonify, send_from_directory, request
from neo4j import GraphDatabase
from neo4j.exceptions import TransientError, ClientError
import atexit
import os
import logging
import json
import tempfile
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static')
MEMGRAPH_URI = os.environ.get("MEMGRAPH_URI", "bolt://memgraph:7687")

# Only include raw backend error details in API responses if explicitly enabled.
# This keeps safer defaults for "production-ready" usage while still allowing debugging.
DEBUG_ERROR_DETAILS = os.environ.get("WEBVIZ_DEBUG_ERRORS", "false").lower() == "true"

# Configuration for persistence
WHITELIST_FILE = '/app/config/whitelist.json'
AUDIT_FILE = '/app/config/audit.log'

def load_whitelist():
    """Load authorized software list"""
    if not os.path.exists(WHITELIST_FILE):
        return []
    try:
        with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing whitelist JSON (corrupted file?): {e}")
        return []
    except Exception as e:
        logger.error(f"Error loading whitelist: {e}")
        return []

def save_whitelist(whitelist):
    """Save authorized software list"""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(WHITELIST_FILE), exist_ok=True)
        # Atomic write to avoid partial/corrupted JSON on crash.
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode='w',
                encoding='utf-8',
                delete=False,
                dir=os.path.dirname(WHITELIST_FILE),
                prefix=os.path.basename(WHITELIST_FILE) + '.',
                suffix='.tmp',
            ) as f:
                tmp_path = f.name
                json.dump(whitelist, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
            os.replace(tmp_path, WHITELIST_FILE)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
    except Exception as e:
        logger.error(f"Error saving whitelist: {e}")

def audit_log(action, details):
    """Log actions to audit file"""
    try:
        os.makedirs(os.path.dirname(AUDIT_FILE), exist_ok=True)
        # Keep one action per line (avoid newlines in user-controlled details).
        safe_details = (details or "").replace("\n", "\\n").replace("\r", "\\r")
        with open(AUDIT_FILE, 'a', encoding='utf-8') as f:
            timestamp = datetime.now().isoformat()
            f.write(f"{timestamp} - {action} - {safe_details}\n")
    except Exception as e:
        logger.error(f"Error writing audit log: {e}")


@atexit.register
def _close_memgraph_driver():
    """Best-effort cleanup for the global Neo4j/Memgraph driver."""
    global driver
    try:
        if driver:
            driver.close()
    except Exception:
        pass

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
    

    # Advanced search parameters
    search_mode = request.args.get('mode', 'wildcard').strip().lower()  # wildcard, exact, regex
    case_sensitive = request.args.get('case', 'false').strip().lower() == 'true'

    # Validate key inputs (keep permissive where possible for backwards compatibility)
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
    
    # Limit parameter
    try:
        limit_param = int(request.args.get('limit', 0))
    except ValueError:
        limit_param = 0
    
    # Default limits
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
                host_query += " RETURN DISTINCT h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform, h.team_name AS team_name"
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
                # Apply default limit if no term
                host_query += f" LIMIT {cypher_limit}"
                
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
                # Search software by name
                software_cond = get_search_condition('s.name', 'search_term')
                
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

                software_query += """
                    WITH s, COUNT(DISTINCT h) as host_count
                    RETURN s.name AS name, s.last_version AS last_version, s.category AS category, s.wikidata_description AS description, host_count
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

                software_query += f"""
                    WITH s.name AS name, s.last_version AS last_version, s.category AS category, s.wikidata_description AS description, COUNT(DISTINCT h) AS host_count
                    ORDER BY host_count DESC
                    LIMIT {cypher_limit}
                    RETURN name, last_version, category, description, host_count
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

@app.route("/api/blast-radius")
def get_blast_radius():
    """Calculate blast radius metrics for a given node type and ID.
    
    Query parameters:
    - type: 'user' or 'software'
    - id: The specific ID (username or software name)
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    node_type = request.args.get('type')
    node_id = request.args.get('id')
    team_filter = request.args.get('team', 'all')
    ignore_defaults = request.args.get('ignore_defaults', 'false').lower() == 'true'
    
    if not node_type or not node_id:
        return jsonify({"error": "Missing type or id parameter"}), 400

    allowed_types = {'user', 'software'}
    if node_type not in allowed_types:
        return jsonify({
            "error": "Invalid type",
            "message": f"type must be one of {sorted(allowed_types)}",
        }), 400

    if len(node_id) > 300:
        return jsonify({
            "error": "Invalid id",
            "message": "id must be <= 300 characters",
        }), 400

    with driver.session() as session:
        metrics = {
            "host_reach": 0,
            "user_impact": 0,
            "lateral_movement": 0,
            "platform_diversity": 0
        }
        
        details = {
            "hosts": [],
            "users": [],
            "teams": [],
            "platforms": []
        }
        
        # Prepare team filter clause
        team_clause = ""
        params = {"id": node_id}
        
        if team_filter != 'all':
            team_clause = "AND toString(h.team_id) = $team_id"
            params["team_id"] = team_filter

        # Common logic for finding impacted users on compromised hosts
        # This is where we apply the ignore_defaults filter
        user_exclusion_clause = "AND u.username <> $id" if node_type == 'user' else ""
        
        # Handle exclusions (dynamic list from frontend preferred)
        excluded_users_param = request.args.get('excluded_users', '')
        
        if excluded_users_param:
            # Frontend provided specific list
            excluded_users = [u.strip() for u in excluded_users_param.split(',') if u.strip()]
            if len(excluded_users) > 1000:
                return jsonify({
                    "error": "excluded_users too large",
                    "message": "excluded_users must contain <= 1000 usernames",
                }), 400
            if excluded_users:
                user_exclusion_clause += " AND NOT u.username IN $defaults"
                params['defaults'] = excluded_users
        elif ignore_defaults:
            # Fallback for backward compatibility
            default_accounts = ['root', 'Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount']
            user_exclusion_clause += " AND NOT u.username IN $defaults"
            params['defaults'] = default_accounts

        if node_type == 'user':
            # For a User, blast radius is:
            # 1. Hosts they have access to
            # 2. Other Users on those hosts (lateral movement potential)
            
            # Find hosts accessed by this user (filtered by team)
            host_query = f"""
                MATCH (u:User {{username: $id}})-[:USES]->(h:Host)
                WHERE 1=1 {team_clause}
                RETURN collect(DISTINCT h) as hosts
            """
            result = session.run(host_query, **params)
            
            hosts = result.single()['hosts']
            metrics['host_reach'] = len(hosts)
            details['hosts'] = [h['hostname'] for h in hosts]
            details['platforms'] = list(set([h['platform'] for h in hosts if h.get('platform')]))
            metrics['platform_diversity'] = len(details['platforms'])
            
            # Teams involved
            teams = set()
            for h in hosts:
                if h.get('team_name'):
                    teams.add(h['team_name'])
            # We don't use 'Team Impact' metric anymore, but we keep details
            # metrics['team_impact'] = len(teams) 
            details['teams'] = list(teams)

            # Potential impacted users (people who use the same machines)
            if hosts:
                host_names = [h['hostname'] for h in hosts]
                # Note: We don't filter impacted users by team, we see ALL users on the affected hosts
                # because if a host is compromised, all users on it are at risk regardless of their team.
                # However, the HOSTS themselves were filtered by the team earlier.
                
                user_query = f"""
                    MATCH (u:User)-[:USES]->(h:Host)
                    WHERE h.hostname IN $hostnames {user_exclusion_clause}
                    RETURN collect(DISTINCT u.username) as users
                """
                # Update params with hostnames for this query
                query_params = {**params, "hostnames": host_names}
                
                user_res = session.run(user_query, **query_params)
                impacted_users = user_res.single()['users']
                metrics['user_impact'] = len(impacted_users)
                details['users'] = impacted_users

        elif node_type == 'software':
            # For Software, blast radius is:
            # 1. Hosts installed on
            # 2. Users on those hosts
            
            # Find hosts for software (filtered by team)
            host_query = f"""
                MATCH (s:Software {{name: $id}})-[:INSTALLED_ON]->(h:Host)
                WHERE 1=1 {team_clause}
                RETURN collect(DISTINCT h) as hosts, s.category as category, s.wikidata_description as description
            """
            result = session.run(host_query, **params)
            record = result.single()
            hosts = record['hosts']
            metrics['category'] = record['category']
            metrics['description'] = record['description']
            
            metrics['host_reach'] = len(hosts)
            details['hosts'] = [h['hostname'] for h in hosts]
            details['platforms'] = list(set([h['platform'] for h in hosts if h.get('platform')]))
            metrics['platform_diversity'] = len(details['platforms'])
            
            # Teams involved
            teams = set()
            for h in hosts:
                if h.get('team_name'):
                    teams.add(h['team_name'])
            details['teams'] = list(teams)
            
            # Impacted users
            if hosts:
                host_names = [h['hostname'] for h in hosts]
                
                user_query = f"""
                    MATCH (u:User)-[:USES]->(h:Host)
                    WHERE h.hostname IN $hostnames {user_exclusion_clause}
                    RETURN collect(DISTINCT u.username) as users
                """
                query_params = {**params, "hostnames": host_names}
                
                user_res = session.run(user_query, **query_params)
                impacted_users = user_res.single()['users']
                metrics['user_impact'] = len(impacted_users)
                details['users'] = impacted_users
        
        # Calculate Lateral Movement Potential (Threat Hunting Metric)
        # Definition: Count of UNIQUE hosts accessible by the 'impacted_users', EXCLUDING the originally affected hosts.
        # This represents "Where can they go next?"
        
        lateral_hosts = []
        metrics['lateral_movement'] = 0
        
        if details['users'] and len(details['users']) > 0:
            # We have impacted users. Find where they can go.
            # Avoid re-scanning original hosts.
            original_host_names = details['hosts']
            
            lateral_res = session.run("""
                MATCH (u:User)-[:USES]->(h:Host)
                WHERE u.username IN $users 
                  AND NOT h.hostname IN $original_hosts
                RETURN collect(DISTINCT h.hostname) as lateral_hosts
            """, users=details['users'], original_hosts=original_host_names)
            
            lateral_hosts = lateral_res.single()['lateral_hosts']
            metrics['lateral_movement'] = len(lateral_hosts)
            
        # Add lateral hosts count to details for potential display (though we might not list them all if too many)
        # details['lateral_hosts'] = lateral_hosts 

        # Calculate normalized scores (0-100) for radar chart
        # Key Change: Use GLOBAL totals for "Team Impact" and others to avoid skewing.
        # If we select a team, the impact is 1 team. 1/TotalTeams is small, but accurate.
        # This prevents "100% Team Impact" when filtering by a single team.

        # Fetch Global Totals (ignoring filters)
        global_totals = session.run("""
            MATCH (h:Host)
            WITH count(h) as total_hosts
            MATCH (u:User)
            WITH total_hosts, count(u) as total_users
            MATCH (t:Team)
            RETURN total_hosts, total_users, count(t) as total_teams
        """).single()
        
        # When normalizing:
        # - Host/User Reach: Normalize against the SCOPE (if I filter by team, 50% of THAT team impacted is high impact).
        # - Team Impact: Normalize against GLOBAL (impacting 1 team out of 20 is "Low" organizational spread).
        
        # Let's refine based on user feedback "shouldn't skew the team to become max".
        # This implies they want Team Impact to be relative to the Whole Org.
        
        global_total_teams = global_totals['total_teams'] if global_totals else 1
        
        # For Host/User, do we normalize against TEAM totals or GLOBAL totals?
        # If I want to see "How bad is this for the team?", I should use Team Totals.
        # If I want to see "How bad is this for the company?", I use Global.
        # Given the "drill down" nature, Team Totals for hosts/users makes sense (saturation of the team).
        # BUT Team Impact must be Global.
        
        # Calculate scoped totals (for Host/User normalization - saturation of the filtered scope)
        if team_filter != 'all':
            scoped_totals = session.run("""
                MATCH (h:Host) WHERE toString(h.team_id) = $team_id
                WITH count(h) as total_hosts
                OPTIONAL MATCH (u:User)-[:USES]->(h:Host) WHERE toString(h.team_id) = $team_id
                RETURN total_hosts, count(DISTINCT u) as total_users
            """, team_id=team_filter).single()
        else:
            scoped_totals = global_totals # Same as global if no filter
            
        total_hosts = scoped_totals['total_hosts'] if scoped_totals else 1
        total_users = scoped_totals['total_users'] if scoped_totals else 1
        
        # Prevent division by zero
        total_hosts = max(total_hosts, 1)
        total_users = max(total_users, 1)
        
        # Normalization for Lateral Movement:
        # Relative to total hosts in the scope? Or Global?
        # Lateral movement usually implies moving ANYWHERE in the org preferably.
        # But if we are scoped to a team, maybe "Lateral movement within team"?
        # If I filter by team, I want to see impact ON THAT TEAM.
        # So lateral movement should probably be filtered by team if a filter is active?
        # My lateral query didn't filter by team.
        # Let's adjust lateral query to respect team filter if present?
        # Actually, lateral movement often crosses team boundaries (that's the danger).
        # So "Lateral Potential" should probably be GLOBAL (where can they go in the whole org?).
        # Let's stick to Global potential for Lateral Move, normalized against GLOBAL total hosts.
        
        global_total_hosts = global_totals['total_hosts'] if global_totals else 1
        global_total_hosts = max(global_total_hosts, 1)

        scores = {
            "Host Reach": min(int((metrics['host_reach'] / total_hosts) * 100), 100),
            "User Impact": min(int((metrics['user_impact'] / total_users) * 100), 100),
            # New Metric: Lateral Movement (Normalized against GLOBAL hosts usually, or maybe scoped?)
            # Let's Use Global Hosts to show "Access to X% of the entire fleet"
            "Lateral Movement": min(int((metrics['lateral_movement'] / global_total_hosts) * 100), 100),
            "Platform Diversity": min(int((metrics['platform_diversity'] / 3) * 100), 100)
        }
        
        return jsonify({
            "metrics": metrics,
            "scores": scores,
            "details": details,
            "scope": {
                "team_filter": team_filter,
                "totals": {
                    "hosts": total_hosts,
                    "users": total_users,
                    "teams": global_total_teams
                }
            }
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
        payload = {
            "status": "unhealthy",
            "database": "error",
        }
        if DEBUG_ERROR_DETAILS:
            payload["error"] = str(e)
        return jsonify(payload), 503

@app.route("/api/authorize-software", methods=['POST'])
def authorize_software():
    """Authorize a software (whitelist it)"""
    try:
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"error": "Invalid JSON body"}), 400

        software_name = (data.get('software_name') or '').strip()
        
        if not software_name:
            return jsonify({"error": "Software name required"}), 400

        if len(software_name) > 500:
            return jsonify({
                "error": "Software name too long",
                "message": "software_name must be <= 500 characters",
            }), 400
            
        whitelist = load_whitelist()
        if software_name not in whitelist:
            whitelist.append(software_name)
            save_whitelist(whitelist)
            audit_log("AUTHORIZE", f"Authorized software: {software_name}")
            logger.info(f"Authorized software: {software_name}")
            
        return jsonify({"status": "success", "message": f"{software_name} authorized"}), 200
    except Exception as e:
        logger.error(f"Error authorizing software: {e}", exc_info=True)
        payload = {"error": "Internal server error"}
        if DEBUG_ERROR_DETAILS:
            payload["details"] = str(e)
        return jsonify(payload), 500

@app.route("/api/shadow-it")
def get_shadow_it():
    """Detect Shadow IT - unauthorized or risky software installations.
    
    Query parameters:
    - team: team filter ('all' or team_id)
    - platform: platform filter ('all', 'windows', 'darwin', 'ubuntu')
    - risk: risk level filter ('all', 'high', 'medium', 'low')
    - detection_type: detection type filter ('all', 'outlier', 'high_risk', 'version_sprawl')
    
    Returns Shadow IT detections with risk scores and recommendations.
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    
    team_filter = request.args.get('team', 'all')
    platform_filter = request.args.get('platform', 'all').lower()
    risk_filter = request.args.get('risk', 'all').lower()
    detection_type_filter = request.args.get('detection_type', 'all').lower()
    host_count_filter = request.args.get('host_count', 'all')  # New filter
    user_count_filter = request.args.get('user_count', 'all')  # New filter
    software_type_filter = request.args.get('software_type', 'all')  # New filter
    
    # Software type detection patterns
    def detect_software_type(software_name):
        """Detect the type of software based on name patterns"""
        name_lower = software_name.lower()
        
        # Browser Extensions
        if any(x in name_lower for x in ['-extension', 'chrome extension', 'firefox addon', 'safari extension', 'edge extension']):
            return 'Browser Extension'
        
        # VSCode Extensions  
        if any(x in name_lower for x in ['vscode-', '.vscode', 'code-extension']):
            return 'VSCode Extension'
        
        # Package Managers
        if name_lower.startswith('npm:') or name_lower.startswith('@'):
            return 'npm Package'
        if name_lower.startswith('pip:') or name_lower.startswith('python-'):
            return 'Python Package'
        if name_lower.startswith('gem:'):
            return 'Ruby Gem'
        
        # Operating System Components
        if any(x in name_lower for x in ['microsoft', 'windows', 'macos', 'darwin', 'linux', 'ubuntu']):
            return 'OS Component'
        
        # Development Tools
        if any(x in name_lower for x in ['git', 'node', 'python', 'java', 'docker', 'kubernetes']):
            return 'Developer Tool'
        
        # Default
        return 'Application'
    
    # High-risk software patterns (case-insensitive)
    HIGH_RISK_PATTERNS = {
        'Remote Access Tools': ['teamviewer', 'anydesk', 'chrome remote desktop', 'vnc', 'logmein', 'gotomypc', 'remotepc', 'splashtop', 'remote desktop'],
        'File Sharing': ['dropbox', 'wetransfer', 'mega', 'sync.com', 'tresorit', 'pcloud', 'bittorrent', 'utorrent', 'qbittorrent', 'file sharing'],
        'Communication Apps': ['telegram', 'signal', 'whatsapp', 'discord', 'wechat', 'line', 'viber', 'kik', 'instant messaging', 'voip', 'videotelephony'],
        'Developer Tools': ['docker', 'virtualbox', 'vmware', 'wireshark', 'burp suite', 'metasploit', 'nmap', 'aircrack', 'packet analyzer', 'penetration testing'],
	        # NOTE: Avoid overly-generic patterns like "miner" because they produce false positives
	        # for legitimate software (e.g., GNOME Tracker components like "tracker-miner-fs").
	        'Cryptocurrency': ['nicehash', 'cgminer', 'ethminer', 'xmrig', 'phoenixminer', 'claymore', 'minergate', 'cryptocurrency', 'bitcoin'],
        'Tor/Privacy Tools': ['tor browser', 'tails', 'proxifier', 'psiphon', 'tunnelbear', 'nordvpn', 'expressvpn', 'anonymizing proxy', 'vpn'],
    }
    
    
    with driver.session() as session:
        # Get total host count for percentage thresholds
        total_hosts_res = session.run("MATCH (h:Host) RETURN count(h) AS count")
        total_hosts_count = total_hosts_res.single()['count'] or 1
        
        # Thresholds
        OUTLIER_THRESHOLD = max(2, int(total_hosts_count * 0.05)) # 5% threshold, min 2
        MANAGED_THRESHOLD = int(total_hosts_count * 0.30) # 30% threshold for "common" software
        
        detections = []
        detection_id_counter = 1
        
        # Load whitelist
        whitelist = load_whitelist()
        
        # Build team and platform filters
        team_clause = ""
        platform_clause = ""
        whitelist_clause = ""
        filter_params = {}
        
        if team_filter != 'all':
            team_clause = "AND toString(h.team_id) = $team_id"
            filter_params['team_id'] = team_filter
        
        if platform_filter != 'all':
            platform_clause = "AND toLower(h.platform) CONTAINS toLower($platform)"
            filter_params['platform'] = platform_filter
            
        if whitelist:
            whitelist_clause = "AND NOT s.name IN $whitelist"
            filter_params['whitelist'] = whitelist
        
        # ===== DETECTION 1: Outlier Software (installed on very few hosts) =====
        if detection_type_filter in ['all', 'outlier']:
            outlier_query = f"""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE 1=1 {team_clause} {platform_clause} {whitelist_clause}
                WITH s.name AS software_name, s.last_version AS version, s.category AS db_category, s.wikidata_description AS db_desc,
                COUNT(DISTINCT h) AS host_count,
                COLLECT(DISTINCT h.hostname) AS hosts,
                COLLECT(DISTINCT h.platform) AS platforms
                WHERE host_count <= $outlier_threshold
                RETURN software_name, version, host_count, hosts, platforms, db_category, db_desc
                ORDER BY host_count ASC, software_name ASC
            """
            
            # Add outlier_threshold to filter_params
            filter_params['outlier_threshold'] = OUTLIER_THRESHOLD
            
            result = session.run(outlier_query, **filter_params)
            for record in result:
                # Get users on affected hosts
                users_query = """
                    MATCH (s:Software {name: $software_name})-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
                    RETURN COLLECT(DISTINCT u.username) AS users
                """
                users_result = session.run(users_query, software_name=record['software_name'])
                users_record = users_result.single()
                users = users_record['users'] if users_record else []
                
                # Risk level based on install count
                risk_level = "high" if record['host_count'] == 1 else "medium"
                
                # Apply host count filter
                if host_count_filter != 'all':
                    if host_count_filter == '1' and record['host_count'] != 1:
                        continue
                    elif host_count_filter == '2' and record['host_count'] != 2:
                        continue
                    elif host_count_filter == '3+' and record['host_count'] < 3:
                        continue
                
                # Apply user count filter
                user_count = len(users)
                if user_count_filter != 'all':
                    if user_count_filter == '1' and user_count != 1:
                        continue
                    elif user_count_filter == '2' and user_count != 2:
                        continue
                    elif user_count_filter == '3+' and user_count < 3:
                        continue
                
                # Detect software type
                software_type = detect_software_type(record['software_name'])

                # Apply software type filter
                if software_type_filter != 'all' and software_type != software_type_filter:
                    continue
                
                if risk_filter == 'all' or risk_filter == risk_level:
                    detections.append({
                        "id": f"outlier_{detection_id_counter}",
                        "software_name": record['software_name'],
                        "software_type": software_type,
                        "risk_level": risk_level,
                        "category": "Outlier Software",
                        "db_category": record.get('db_category'),
                        "wikidata_description": record.get('db_desc'),
                        "detection_type": "outlier",
                        "host_count": record['host_count'],
                        "affected_hosts": record['hosts'],
                        "affected_users": users,
                        "platforms": record['platforms'],
                        "version": record['version'] or "Unknown",
                        "recommendation": f"Verify if this software is authorized. Found on only {record['host_count']} host(s). Consider removing if unauthorized.",
                        "details": f"Installed on {record['host_count']} host(s) only - unusual for enterprise software",
                        "risk_reason": f"Risk is {risk_level.upper()} because this software is installed on only {record['host_count']} host(s) (<{OUTLIER_THRESHOLD} threshold).",
                    })
                    detection_id_counter += 1
        
        # ===== DETECTION 2: High-Risk Category Software =====
        if detection_type_filter in ['all', 'high_risk']:
            # Get all software
            all_software_query = f"""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE 1=1 {team_clause} {platform_clause} {whitelist_clause}
                WITH s.name AS software_name, s.last_version AS version, s.category AS db_category, s.wikidata_description AS db_desc,
                COUNT(DISTINCT h) AS host_count,
                COLLECT(DISTINCT h.hostname) AS hosts,
                COLLECT(DISTINCT h.platform) AS platforms
                RETURN software_name, version, host_count, hosts, platforms, db_category, db_desc
            """
            
            result = session.run(all_software_query, **filter_params)
            
            for record in result:
                software_lower = record['software_name'].lower()
                matched_category = None
                
                # Check against dynamic categories first
                db_categories = record.get('db_category') or []
                for db_cat in db_categories:
                    db_cat_lower = db_cat.lower()
                    for category, patterns in HIGH_RISK_PATTERNS.items():
                        # Check if any high-risk pattern matches the dynamic category
                        if any(p in db_cat_lower for p in patterns) or category.lower() in db_cat_lower:
                            matched_category = category
                            break
                    if matched_category:
                        break
                
                # Fallback to name pattern matching if no dynamic category match
                if not matched_category:
                    for category, patterns in HIGH_RISK_PATTERNS.items():
                        for pattern in patterns:
                            if pattern in software_lower:
                                matched_category = category
                                break
                        if matched_category:
                            break
                
                if matched_category:
                    # Skip flagged Developer Tools if they are widely deployed (>30%)
                    if matched_category == 'Developer Tools' and record['host_count'] > MANAGED_THRESHOLD:
                        continue
                        
                    # Get users on affected hosts
                    users_query = """
                        MATCH (s:Software {name: $software_name})-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
                        RETURN COLLECT(DISTINCT u.username) AS users
                    """
                    users_result = session.run(users_query, software_name=record['software_name'])
                    users_record = users_result.single()
                    users = users_record['users'] if users_record else []
                    
                    # All high-risk category detections are high risk
                    risk_level = "high"
                    
                    # Apply host count filter
                    if host_count_filter != 'all':
                        if host_count_filter == '1' and record['host_count'] != 1:
                            continue
                        elif host_count_filter == '2' and record['host_count'] != 2:
                            continue
                        elif host_count_filter == '3+' and record['host_count'] < 3:
                            continue
                    
                    # Apply user count filter
                    user_count = len(users)
                    if user_count_filter != 'all':
                        if user_count_filter == '1' and user_count != 1:
                            continue
                        elif user_count_filter == '2' and user_count != 2:
                            continue
                        elif user_count_filter == '3+' and user_count < 3:
                            continue
                    
                    # Detect software type
                    software_type = detect_software_type(record['software_name'])
                    
                    # Apply software type filter
                    if software_type_filter != 'all' and software_type != software_type_filter:
                        continue
                    
                    if risk_filter == 'all' or risk_filter == risk_level:
                        # Category-specific recommendations
                        recommendations = {
                            'Remote Access Tools': "Verify authorization. Remote access tools can be used for data exfiltration. Replace with approved enterprise solution.",
                            'File Sharing': "Verify authorization. File sharing apps may lead to data leakage. Use approved enterprise file sharing.",
                            'Communication Apps': "Verify authorization. Unofficial communication apps may bypass DLP policies. Use approved enterprise messaging.",
                            'Developer Tools': "Verify if host is authorized dev machine. Developer tools on production systems pose security risks.",
                            'Cryptocurrency': "CRITICAL: Remove immediately. Cryptocurrency miners consume resources and may indicate compromise.",
                            'Tor/Privacy Tools': "CRITICAL: Investigate immediately. Privacy/anonymity tools may indicate malicious activity or policy violation.",
                        }
                        
                        detections.append({
                            "id": f"highrisk_{detection_id_counter}",
                            "software_name": record['software_name'],
                            "software_type": software_type,
                            "risk_level": risk_level,
                            "category": matched_category,
                            "detection_type": "high_risk",
                            "host_count": record['host_count'],
                            "affected_hosts": record['hosts'],
                            "affected_users": users,
                            "platforms": record['platforms'],
                            "version": record['version'] or "Unknown",
                            "recommendation": recommendations.get(matched_category, "Review and verify authorization"),
                            "details": f"High-risk category: {matched_category}",
                            "risk_reason": f"Risk is HIGH because '{record['software_name']}' matches the '{matched_category}' category, which is flagged for security review."
                        })
                        detection_id_counter += 1
        
        # ===== DETECTION 3: Version Sprawl (multiple versions of same software) =====
        if detection_type_filter in ['all', 'version_sprawl']:
            version_sprawl_query = f"""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE s.last_version IS NOT NULL 
                  AND s.last_version <> '' 
                  {team_clause} {platform_clause} {whitelist_clause}
                WITH s.name AS software_name, 
                     COUNT(DISTINCT s.last_version) AS version_count,
                     COLLECT(DISTINCT s.last_version) AS versions,
                     COUNT(DISTINCT h) AS host_count,
                     COLLECT(DISTINCT h.hostname) AS hosts
                WHERE version_count > 2
                RETURN software_name, version_count, versions, host_count, hosts
                ORDER BY version_count DESC
                LIMIT 20
            """
            
            result = session.run(version_sprawl_query, **filter_params)
            for record in result:
                # Get users on affected hosts
                users_query = """
                    MATCH (s:Software {name: $software_name})-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
                    RETURN COLLECT(DISTINCT u.username) AS users
                """
                users_result = session.run(users_query, software_name=record['software_name'])
                users_record = users_result.single()
                users = users_record['users'] if users_record else []
                
                # Risk level based on version count
                if record['version_count'] > 5:
                    risk_level = "high"
                elif record['version_count'] > 3:
                    risk_level = "medium"
                else:
                    risk_level = "low"
                
                # Apply host count filter
                if host_count_filter != 'all':
                    if host_count_filter == '1' and record['host_count'] != 1:
                        continue
                    elif host_count_filter == '2' and record['host_count'] != 2:
                        continue
                    elif host_count_filter == '3+' and record['host_count'] < 3:
                        continue
                
                # Apply user count filter
                user_count = len(users)
                if user_count_filter != 'all':
                    if user_count_filter == '1' and user_count != 1:
                        continue
                    elif user_count_filter == '2' and user_count != 2:
                        continue
                    elif user_count_filter == '3+' and user_count < 3:
                        continue
                
                # Detect software type
                software_type = detect_software_type(record['software_name'])

                # Apply software type filter
                if software_type_filter != 'all' and software_type != software_type_filter:
                    continue
                
                if risk_filter == 'all' or risk_filter == risk_level:
                    detections.append({
                        "id": f"sprawl_{detection_id_counter}",
                        "software_name": record['software_name'],
                        "software_type": software_type,
                        "risk_level": risk_level,
                        "category": "Version Management",
                        "detection_type": "version_sprawl",
                        "host_count": record['host_count'],
                        "affected_hosts": record['hosts'],
                        "affected_users": users,
                        "platforms": [],
                        "version": f"{record['version_count']} versions: {', '.join(record['versions'][:3])}{'...' if len(record['versions']) > 3 else ''}",
                        "recommendation": f"Standardize software versions across fleet. Currently running {record['version_count']} different versions.",
                        "details": f"Version sprawl detected - {record['version_count']} different versions installed",
                        "risk_reason": f"Risk is {risk_level.upper()} because there are {record['version_count']} distinct versions installed, indicating poor patch management."
                    })
                    detection_id_counter += 1
        
        # ===== Calculate Summary Metrics =====
        summary = {
            "total_detections": len(detections),
            "high_risk": len([d for d in detections if d['risk_level'] == 'high']),
            "medium_risk": len([d for d in detections if d['risk_level'] == 'medium']),
            "low_risk": len([d for d in detections if d['risk_level'] == 'low']),
            "affected_hosts": len(set([host for d in detections for host in d['affected_hosts']])),
            "affected_users": len(set([user for d in detections for user in d['affected_users']])),
        }
        
        # Calculate category distribution
        risk_distribution = {}
        for detection in detections:
            category = detection['category']
            risk_distribution[category] = risk_distribution.get(category, 0) + 1
        
        logger.info(f"Shadow IT scan (team: {team_filter}, platform: {platform_filter}): {summary['total_detections']} detections")
        
        return jsonify({
            "summary": summary,
            "detections": detections,
            "risk_distribution": risk_distribution,
            "filters": {
                "team": team_filter,
                "platform": platform_filter,
                "risk": risk_filter,
                "detection_type": detection_type_filter
            }
        })

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
    response = send_from_directory(app.static_folder, "index.html")
    # Prevent caching to ensure fresh code is always loaded
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(ClientError)
def handle_database_error(error):
    """Handle database client errors (e.g. invalid regex)"""
    logger.error(f"Database error: {error}")
    # Return 400 Bad Request for client errors (like bad regex)
    return jsonify({
        "error": "Database error", 
        "message": str(error),
        "code": "BAD_REQUEST"
    }), 400

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
