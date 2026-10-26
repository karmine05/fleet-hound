"""Blast-radius metrics: /api/blast-radius.

Split from webviz/app.py (Phase 5 monolith -> blueprints). The Flask `app`,
auth middleware, driver singleton and worker-lifecycle state stay in
webviz/app.py; this Blueprint holds one coherent endpoint group. App-level
names are imported at module top; safe because app.py registers every
blueprint at the very bottom, after all of them are bound.
"""

from flask import Blueprint, jsonify, request
from webviz.host_filters import FilterValidationError, apply_label_filter
from webviz.app import driver

bp = Blueprint("blast_radius", __name__)

@bp.route("/api/blast-radius")
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
    team_filter = (request.args.get('team') or 'all').strip() or 'all'
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

    # Software name lookup is case-insensitive against a graph that now
    # stores names lowercase (see ingestion case-dedupe). Users (USES edge
    # endpoints) stay case-sensitive because usernames are exact identifiers.
    if node_type == 'software':
        node_id = node_id.strip().lower()

    # Label scoping (plan 1E): bolted on additively. label_clause is merged
    # alongside team_clause into every Cypher query that filters on hosts.
    try:
        label_flt_fragment, label_flt_params = apply_label_filter(request.args)
    except FilterValidationError as exc:
        return jsonify({"error": "Invalid filter", "message": str(exc)}), 400

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

        # Prepare team + label filter clauses. team_clause uses the legacy
        # inline pattern; label_clause comes from apply_label_filter so it
        # supports multi-label AND/OR semantics. Both inject into the same
        # WHERE chain via f-string interpolation below.
        team_clause = ""
        label_clause = label_flt_fragment
        params = {"id": node_id}

        if team_filter != 'all':
            team_clause = "AND toString(h.team_id) = $team_id"
            params["team_id"] = team_filter

        params.update(label_flt_params)

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
                WHERE 1=1 {team_clause} {label_clause}
                RETURN collect(DISTINCT h) as hosts
            """
            result = session.run(host_query, **params)
            _h_rec = result.single()
            hosts = (_h_rec['hosts'] if _h_rec else []) or []
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
                user_rec = user_res.single()
                impacted_users = (user_rec['users'] if user_rec else []) or []
                metrics['user_impact'] = len(impacted_users)
                details['users'] = impacted_users

        elif node_type == 'software':
            # For Software, blast radius is:
            # 1. Hosts installed on
            # 2. Users on those hosts
            #
            # Two-step query because the previous one-step COLLECT version
            # returned 0 rows when the team/label scope produced no matching
            # hosts — and `result.single()` was None, crashing on
            # `record['hosts']`. Splitting the metadata fetch from the host
            # set lets us render an empty-blast-radius result cleanly when
            # the operator scopes to a label this software isn't in.
            sw_meta = session.run(
                "MATCH (s:Software {name: $id}) "
                "RETURN s.category AS category, "
                "       s.wikidata_description AS description LIMIT 1",
                id=node_id,
            ).single()
            if sw_meta is None:
                metrics['category'] = None
                metrics['description'] = None
            else:
                metrics['category'] = sw_meta['category']
                metrics['description'] = sw_meta['description']

            host_query = f"""
                MATCH (s:Software {{name: $id}})-[:INSTALLED_ON]->(h:Host)
                WHERE 1=1 {team_clause} {label_clause}
                RETURN collect(DISTINCT h) AS hosts
            """
            host_rec = session.run(host_query, **params).single()
            hosts = (host_rec['hosts'] if host_rec else []) or []
            
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
                user_rec = user_res.single()
                impacted_users = (user_rec['users'] if user_rec else []) or []
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
            
            _lat_rec = lateral_res.single()
            lateral_hosts = (_lat_rec['lateral_hosts'] if _lat_rec else []) or []
            metrics['lateral_movement'] = len(lateral_hosts)
            
        # Add lateral hosts count to details for potential display (though we might not list them all if too many)
        # details['lateral_hosts'] = lateral_hosts 

        # Calculate normalized scores (0-100) for radar chart
        # Key Change: Use GLOBAL totals for "Team Impact" and others to avoid skewing.
        # If we select a team, the impact is 1 team. 1/TotalTeams is small, but accurate.
        # This prevents "100% Team Impact" when filtering by a single team.

        # Fetch Global Totals (ignoring filters). Team membership lives on
        # Host.team_id; there are no (:Team) nodes in this schema, so a
        # MATCH (t:Team) here returned no row and every denominator silently
        # fell back to 1.
        global_totals = session.run("""
            MATCH (h:Host)
            WITH count(h) AS total_hosts, count(DISTINCT h.team_id) AS total_teams
            MATCH (u:User)
            RETURN total_hosts, total_teams, count(u) AS total_users
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
