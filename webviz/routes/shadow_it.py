"""Shadow IT detection: /api/shadow-it (outlier / high-risk / version-sprawl).

Split from webviz/app.py (Phase 5 monolith -> blueprints). The Flask `app`,
auth middleware, driver singleton and worker-lifecycle state stay in
webviz/app.py; this Blueprint holds one coherent endpoint group. App-level
names are imported at module top; safe because app.py registers every
blueprint at the very bottom, after all of them are bound.
"""

import os
import threading
import time

from flask import Blueprint, current_app, jsonify, make_response, request
from webviz.host_filters import FilterValidationError, apply_label_filter
from src.shadow_it_filter import MIN_OUTLIER_HOSTS as _MIN_OUTLIER_HOSTS, classify_extension_type as _classify_extension_type, compute_per_platform_thresholds as _compute_per_platform_thresholds, get_outlier_pct as _get_outlier_pct, is_system_package as _is_system_package
from webviz.app import WHITELIST_FILE, _normalize_whitelist, _whitelist_clause, _word_match, driver, load_whitelist, logger

bp = Blueprint("shadow_it", __name__)

def _shadow_it_users_by_software(session, software_names, scope_clause="", scope_params=None):
    """Map software name -> sorted list of usernames on hosts that have it.

    Batched form of the per-software user lookup that used to run once per
    detection candidate inside /api/shadow-it — up to one Bolt round-trip per
    software (thousands of queries on a normal fleet, the endpoint's dominant
    cost). One `s.name IN $names` query returns every candidate's user set;
    names with no reachable user simply map to [].
    """
    names = list(dict.fromkeys(n for n in software_names if n))
    if not names:
        return {}
    rows = session.run(
        """
        MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
        WHERE s.name IN $names """ + scope_clause + """
        RETURN s.name AS name, COLLECT(DISTINCT u.username) AS users
        """,
        names=names,
        **(scope_params or {}),
    )
    return {r["name"]: sorted(r["users"] or []) for r in rows}

# Short per-worker response cache. Keyed on the query args plus the whitelist
# mtime, so approving software is visible on the next read in every worker;
# graph changes from an ETL cycle show up within the TTL.
SHADOW_CACHE_TTL_SEC = 30
_SHADOW_CACHE_MAX = 64
# Extension worker bands -> Shadow IT levels (the Shadow IT UI has no "critical").
_EXT_BAND_TO_LEVEL = {"critical": "high", "high": "high", "medium": "medium", "low": "low"}
_shadow_cache: dict = {}
_shadow_cache_lock = threading.Lock()


@bp.route("/api/shadow-it")
def get_shadow_it():
    try:
        wl_mtime = os.path.getmtime(WHITELIST_FILE)
    except OSError:
        wl_mtime = 0.0
    key = (tuple(sorted(request.args.items(multi=True))), wl_mtime)
    now = time.monotonic()
    with _shadow_cache_lock:
        hit = _shadow_cache.get(key)
    if hit and now - hit[0] < SHADOW_CACHE_TTL_SEC:
        return current_app.response_class(hit[1], mimetype="application/json")
    resp = make_response(_get_shadow_it_uncached())
    if resp.status_code == 200:
        with _shadow_cache_lock:
            if len(_shadow_cache) >= _SHADOW_CACHE_MAX:
                _shadow_cache.clear()
            _shadow_cache[key] = (now, resp.get_data())
    return resp


def _get_shadow_it_uncached():
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

    # Label scoping (plan 1E): bolted on additively. label_flt_fragment
    # is appended to each detection query's WHERE chain alongside team_clause
    # and platform_clause; label_flt_params merge into filter_params.
    try:
        label_flt_fragment, label_flt_params = apply_label_filter(request.args)
    except FilterValidationError as exc:
        return jsonify({"error": "Invalid filter", "message": str(exc)}), 400
    
    # Software type detection patterns
    def detect_software_type(software_name, sources=None):
        """Detect the type of software.

        The osquery install `source` is the authoritative signal — an
        extension named "binhex.ninja" carries no name hint, only its
        `chrome_extensions`/`vscode_extensions` source reveals what it is.
        Source-based classification therefore runs FIRST; name heuristics are
        the fallback for software with no usable source.
        """
        # Source-authoritative: browser / IDE extension channels.
        ext_type = _classify_extension_type(sources)
        if ext_type:
            return ext_type

        name_lower = software_name.lower()

        # Browser Extensions (name fallback)
        if any(x in name_lower for x in ['-extension', 'chrome extension', 'firefox addon', 'safari extension', 'edge extension']):
            return 'Browser Extension'

        # VSCode Extensions (name fallback)
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
    
    # High-risk Shadow IT patterns. Curated list of specific brand/binary names
    # that are end-user-installable and bypass IT review. All matches are
    # word-boundary, not substring (see _word_match).
    #
    # Deliberately excluded:
    #   * Generic terms ('line', 'voip', 'vpn', 'remote desktop',
    #     'instant messaging', 'videotelephony', 'cryptocurrency', 'bitcoin',
    #     'anonymizing proxy', 'file sharing', 'penetration testing').
    #     These match either OS components (readline -> 'line', RDP -> 'remote
    #     desktop') or are too broad to drive a security action.
    #   * Sanctioned dual-use dev/security tools (docker, virtualbox, vmware,
    #     wireshark, burp suite, metasploit, nmap, aircrack). These are
    #     legitimate engineering tools; an outlier check on non-engineering
    #     teams is the right signal, not a blanket high-risk flag.
    HIGH_RISK_PATTERNS = {
        # Personal remote-access tools — data exfil risk, bypasses jump-host policy.
        'Remote Access Tools': [
            'teamviewer', 'anydesk', 'chrome remote desktop', 'logmein',
            'gotomypc', 'remotepc', 'splashtop', 'realvnc', 'tightvnc',
            'ultravnc', 'screenconnect', 'connectwise control', 'parsec',
        ],
        # Personal file-sync — DLP bypass, exfil risk.
        'File Sharing': [
            'dropbox', 'wetransfer', 'mega', 'sync.com', 'tresorit', 'pcloud',
            'bittorrent', 'utorrent', 'qbittorrent', 'transmission',
            'deluge', 'vuze', 'frostwire', 'limewire',
        ],
        # Personal messaging — bypasses corporate IM/DLP.
        'Communication Apps': [
            'telegram', 'telegram desktop',
            'signal', 'signal desktop',
            'whatsapp', 'whatsapp desktop',
            'discord', 'wechat', 'viber', 'kik messenger', 'qq', 'skype',
        ],
        # Crypto miners — almost always shadow IT or compromise indicator.
        'Cryptocurrency Mining': [
            'nicehash', 'cgminer', 'ethminer', 'xmrig', 'phoenixminer',
            'claymore miner', 'minergate', 'bfgminer', 'sgminer', 'lolminer',
            't-rex miner', 'gminer', 'teamredminer',
        ],
        # Privacy / anonymity / personal VPNs (specific brands only — generic
        # 'vpn' catches enterprise VPN clients).
        'Tor/Privacy Tools': [
            'tor browser', 'tails', 'proxifier', 'psiphon', 'tunnelbear',
            'nordvpn', 'expressvpn', 'protonvpn', 'mullvad', 'surfshark',
            'private internet access', 'cyberghost', 'ipvanish',
            'hotspot shield',
        ],
    }
    
    
    with driver.session() as session:
        # Per-platform outlier thresholds. SHADOW_IT_OUTLIER_PCT (env, default
        # 3%) controls the percentage. Per-platform avoids the global-threshold
        # bug where a software on 1 of 10 Linux servers and a software on 1 of
        # 100 Windows hosts would both count the same toward outlier scoring,
        # even though the first is a much stronger signal.
        outlier_pct = _get_outlier_pct()
        platform_thresholds = _compute_per_platform_thresholds(session, outlier_pct)

        # The detection queries below operate on a single composite scope
        # (team_clause + platform_clause + label_clause). Use the MOST
        # restrictive matching threshold across the platforms in scope:
        #   - platform_filter set: use that platform's threshold
        #   - platform_filter='all': use max threshold across platforms (so
        #     software has to be rare on every platform it appears on, not
        #     just one)
        # Falls back to a global-style computation if the platform map is
        # empty (no hosts ingested yet).
        if platform_thresholds:
            if platform_filter and platform_filter != 'all':
                # Best-effort lookup; Fleet platforms are stored as strings
                # like "darwin", "windows", "ubuntu", "rhel". Match
                # case-insensitively with substring rules to mirror the
                # frontend's behavior.
                pf_lower = platform_filter.lower()
                matched = [
                    t for p, t in platform_thresholds.items()
                    if p and pf_lower in p.lower()
                ]
                OUTLIER_THRESHOLD = (
                    max(matched) if matched else max(platform_thresholds.values())
                )
            else:
                OUTLIER_THRESHOLD = max(platform_thresholds.values())
        else:
            total_hosts_count = (
                session.run("MATCH (h:Host) RETURN count(h) AS count")
                .single()['count'] or 1
            )
            OUTLIER_THRESHOLD = max(_MIN_OUTLIER_HOSTS, int(total_hosts_count * outlier_pct))

        detections = []
        detection_id_counter = 1
        
        # Load whitelist
        whitelist = _normalize_whitelist(load_whitelist())
        
        # Build team and platform filters
        team_clause = ""
        platform_clause = ""
        whitelist_clause = ""
        # label_clause is the apply_label_filter fragment renamed for visual
        # parity with the other inline clauses. Always begins with " AND " or
        # is empty; injects into the same `WHERE 1=1 {team_clause} ...` chain.
        label_clause = label_flt_fragment
        filter_params = {}

        if team_filter != 'all':
            team_clause = "AND toString(h.team_id) = $team_id"
            filter_params['team_id'] = team_filter

        if platform_filter != 'all':
            platform_clause = "AND toLower(h.platform) CONTAINS toLower($platform)"
            filter_params['platform'] = platform_filter

        if whitelist:
            whitelist_clause = _whitelist_clause("s")
            filter_params['whitelist'] = whitelist

        filter_params.update(label_flt_params)
        # Same host scope for affected_users, so user counts match affected_hosts.
        user_scope = f"{team_clause} {platform_clause} {label_clause}"
        
        # ===== DETECTION 1: Outlier Software (installed on very few hosts) =====
        if detection_type_filter in ['all', 'outlier']:
            outlier_query = f"""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE 1=1 {team_clause} {platform_clause} {whitelist_clause} {label_clause}
                WITH s.name AS software_name,
                     coalesce(s.display_name, s.name) AS display_name,
                     s.last_version AS version,
                     s.category AS db_category, s.wikidata_description AS db_desc,
                     s.sources AS db_sources,
                     s.risk_band AS ext_band, s.risk_score AS ext_score,
                     COUNT(DISTINCT h) AS host_count,
                     COLLECT(DISTINCT h.hostname) AS hosts,
                     COLLECT(DISTINCT h.platform) AS platforms
                WHERE host_count <= $outlier_threshold
                RETURN software_name, display_name, version, host_count, hosts, platforms,
                       db_category, db_desc, db_sources, ext_band, ext_score
                ORDER BY host_count ASC, display_name ASC
            """
            
            # Add outlier_threshold to filter_params
            filter_params['outlier_threshold'] = OUTLIER_THRESHOLD
            
            outlier_rows = list(session.run(outlier_query, **filter_params))
            # Batch the per-software user lookup (replaces the N+1 pattern:
            # one query for every candidate instead of one per candidate).
            outlier_users_by_name = _shadow_it_users_by_software(session, [r['software_name'] for r in outlier_rows], user_scope, filter_params)
            for record in outlier_rows:
                # Skip OS-managed system packages and dev-language transitive
                # deps — neither is a deliberate user install. Browser/IDE
                # extensions are NOT skipped (2026-06-10): they are first-class
                # Shadow IT. The `sources` field carries the osquery install
                # channel (apps, programs, deb_packages, npm_packages,
                # chrome_extensions, vscode_extensions ...) and is the strongest
                # signal.
                if _is_system_package(
                    record['software_name'],
                    record.get('db_category') or [],
                    record.get('db_sources') or [],
                ):
                    continue

                users = outlier_users_by_name.get(record['software_name'], [])

                # Risk level based on install count, unless the extension
                # worker already scored this node: its band wins, so the
                # Shadow IT and Extensions views agree on the same software.
                risk_level = "high" if record['host_count'] == 1 else "medium"
                risk_reason = (f"Risk is {risk_level.upper()} because this software is installed on only "
                               f"{record['host_count']} host(s) (<{OUTLIER_THRESHOLD} threshold).")
                ext_band = record.get('ext_band')
                if ext_band in _EXT_BAND_TO_LEVEL:
                    risk_level = _EXT_BAND_TO_LEVEL[ext_band]
                    risk_reason = (f"Risk is {risk_level.upper()} from the browser-extension risk score "
                                   f"({record.get('ext_score')}/100, band {ext_band}). Installed on "
                                   f"{record['host_count']} host(s).")
                
                # Apply host count filter
                if host_count_filter != 'all':
                    if host_count_filter == '1' and record['host_count'] != 1 or host_count_filter == '2' and record['host_count'] != 2 or host_count_filter == '3+' and record['host_count'] < 3:
                        continue
                
                # Apply user count filter
                user_count = len(users)
                if user_count_filter != 'all':
                    if user_count_filter == '1' and user_count != 1 or user_count_filter == '2' and user_count != 2 or user_count_filter == '3+' and user_count < 3:
                        continue
                
                # Detect software type (source-authoritative — extensions
                # are identified by their install channel, not their name).
                software_type = detect_software_type(
                    record['software_name'], record.get('db_sources') or []
                )

                # Apply software type filter
                if software_type_filter != 'all' and software_type != software_type_filter:
                    continue

                if risk_filter == 'all' or risk_filter == risk_level:
                    detections.append({
                        "id": f"outlier_{detection_id_counter}",
                        "software_name": record['software_name'],
                        "display_name": record.get('display_name') or record['software_name'],
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
                        "risk_reason": risk_reason,
                    })
                    detection_id_counter += 1
        
        # ===== DETECTION 2: High-Risk Category Software =====
        if detection_type_filter in ['all', 'high_risk']:
            # Get all software
            all_software_query = f"""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE 1=1 {team_clause} {platform_clause} {whitelist_clause} {label_clause}
                WITH s.name AS software_name,
                     coalesce(s.display_name, s.name) AS display_name,
                     s.last_version AS version,
                     s.category AS db_category, s.wikidata_description AS db_desc,
                     s.sources AS db_sources,
                     COUNT(DISTINCT h) AS host_count
                RETURN software_name, display_name, version, host_count,
                       db_category, db_desc, db_sources
            """
            # Two passes: classify every software from this light aggregate, then
            # collect hosts/platforms/users only for the matches. Collecting
            # hostnames for the whole catalog was a near-full graph scan.
            high_risk_rows = list(session.run(all_software_query, **filter_params))
            high_risk_matches = []
            for record in high_risk_rows:
                software_lower = record['software_name'].lower()
                display_lower = (record.get('display_name') or record['software_name']).lower()
                db_categories = record.get('db_category') or []
                db_sources = record.get('db_sources') or []

                # Skip OS-managed system packages and dev-language transitive
                # deps outright — never Shadow IT regardless of name overlap
                # with high-risk patterns. Browser/IDE extensions ARE evaluated
                # (2026-06-10) so a high-risk extension still surfaces here.
                if _is_system_package(record['software_name'], db_categories, db_sources):
                    continue

                matched_category = None

                # 1. Wikidata category-based matching first (highest signal:
                # the enrichment job has already classified the software).
                for db_cat in db_categories:
                    db_cat_lower = db_cat.lower()
                    for category, patterns in HIGH_RISK_PATTERNS.items():
                        if _word_match(category.lower(), db_cat_lower) or any(
                            _word_match(p, db_cat_lower) for p in patterns
                        ):
                            matched_category = category
                            break
                    if matched_category:
                        break

                # 2. Fallback: word-boundary match on software name or title.
                # Plain substring match is unsafe (libreadline8 -> 'line').
                if not matched_category:
                    for category, patterns in HIGH_RISK_PATTERNS.items():
                        for pattern in patterns:
                            if _word_match(pattern, software_lower) or _word_match(pattern, display_lower):
                                matched_category = category
                                break
                        if matched_category:
                            break

                if matched_category:
                    high_risk_matches.append((dict(record), matched_category))

            matched_names = [r['software_name'] for r, _ in high_risk_matches]
            host_detail = {}
            if matched_names:
                detail_query = f"""
                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                    WHERE s.name IN $matched_names {team_clause} {platform_clause} {whitelist_clause} {label_clause}
                    RETURN s.name AS software_name,
                           COLLECT(DISTINCT h.hostname) AS hosts,
                           COLLECT(DISTINCT h.platform) AS platforms
                """
                host_detail = {
                    r['software_name']: r
                    for r in session.run(detail_query, matched_names=matched_names, **filter_params)
                }
            high_risk_users_by_name = _shadow_it_users_by_software(session, matched_names, user_scope, filter_params)
            for record, matched_category in high_risk_matches:
                detail = host_detail.get(record['software_name'])
                record['hosts'] = detail['hosts'] if detail else []
                record['platforms'] = detail['platforms'] if detail else []
                db_sources = record.get('db_sources') or []
                users = high_risk_users_by_name.get(record['software_name'], [])
                
                # All high-risk category detections are high risk
                risk_level = "high"
                
                # Apply host count filter
                if host_count_filter != 'all':
                    if host_count_filter == '1' and record['host_count'] != 1 or host_count_filter == '2' and record['host_count'] != 2 or host_count_filter == '3+' and record['host_count'] < 3:
                        continue
                
                # Apply user count filter
                user_count = len(users)
                if user_count_filter != 'all':
                    if user_count_filter == '1' and user_count != 1 or user_count_filter == '2' and user_count != 2 or user_count_filter == '3+' and user_count < 3:
                        continue
                
                # Detect software type (source-authoritative).
                software_type = detect_software_type(
                    record['software_name'], db_sources
                )

                # Apply software type filter
                if software_type_filter != 'all' and software_type != software_type_filter:
                    continue

                if risk_filter == 'all' or risk_filter == risk_level:
                    # Category-specific recommendations. Keys must match
                    # HIGH_RISK_PATTERNS exactly.
                    recommendations = {
                        'Remote Access Tools': "Verify authorization. Remote access tools can be used for data exfiltration. Replace with approved enterprise solution.",
                        'File Sharing': "Verify authorization. File sharing apps may lead to data leakage. Use approved enterprise file sharing.",
                        'Communication Apps': "Verify authorization. Unofficial communication apps may bypass DLP policies. Use approved enterprise messaging.",
                        'Cryptocurrency Mining': "CRITICAL: Remove immediately. Cryptocurrency miners consume resources and may indicate compromise.",
                        'Tor/Privacy Tools': "CRITICAL: Investigate immediately. Privacy/anonymity tools may indicate malicious activity or policy violation.",
                    }
                    
                    detections.append({
                        "id": f"highrisk_{detection_id_counter}",
                        "software_name": record['software_name'],
                        "display_name": record.get('display_name') or record['software_name'],
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
        #
        # Count distinct versions across the INSTALLED_ON EDGES (r.version = the
        # version running on each host at last sync), NOT the node's
        # s.last_version. s.last_version is a SINGLE node property (the max seen
        # so far), so `COUNT(DISTINCT s.last_version)` can only ever be 1 per
        # software and this detector would never fire. r.version is refreshed on
        # every sync and stale rels are pruned, so it reflects the live
        # per-host version distribution — which is exactly what "sprawl" means.
        # The 'unknown' sentinel (ingestion default when Fleet reports no
        # version) is excluded so a host with missing version data can't be
        # mistaken for a distinct installed version.
        if detection_type_filter in ['all', 'version_sprawl']:
            version_sprawl_query = f"""
                MATCH (s:Software)-[r:INSTALLED_ON]->(h:Host)
                WHERE r.version IS NOT NULL
                  AND r.version <> ''
                  AND r.version <> 'unknown'
                  {team_clause} {platform_clause} {whitelist_clause} {label_clause}
                WITH s.name AS software_name,
                     coalesce(s.display_name, s.name) AS display_name,
                     s.category AS db_category,
                     s.sources AS db_sources,
                     COUNT(DISTINCT r.version) AS version_count,
                     COLLECT(DISTINCT r.version) AS versions,
                     COUNT(DISTINCT h) AS host_count,
                     COLLECT(DISTINCT h.hostname) AS hosts
                WHERE version_count > 2
                RETURN software_name, display_name, db_category, db_sources, version_count, versions, host_count, hosts
                ORDER BY version_count DESC
                LIMIT 20
            """

            version_sprawl_rows = list(session.run(version_sprawl_query, **filter_params))
            # Batched user lookup (replaces the per-candidate N+1 query).
            version_sprawl_users_by_name = _shadow_it_users_by_software(session, [r['software_name'] for r in version_sprawl_rows], user_scope, filter_params)
            for record in version_sprawl_rows:
                # System packages and dev-language deps routinely show many
                # versions across distro releases / lockfile drift — that's
                # package-manager state, not Shadow IT. Extensions remain
                # in-scope (2026-06-10).
                if _is_system_package(
                    record['software_name'],
                    record.get('db_category') or [],
                    record.get('db_sources') or [],
                ):
                    continue

                users = version_sprawl_users_by_name.get(record['software_name'], [])
                
                # Risk level based on version count
                if record['version_count'] > 5:
                    risk_level = "high"
                elif record['version_count'] > 3:
                    risk_level = "medium"
                else:
                    risk_level = "low"
                
                # Apply host count filter
                if host_count_filter != 'all':
                    if host_count_filter == '1' and record['host_count'] != 1 or host_count_filter == '2' and record['host_count'] != 2 or host_count_filter == '3+' and record['host_count'] < 3:
                        continue
                
                # Apply user count filter
                user_count = len(users)
                if user_count_filter != 'all':
                    if user_count_filter == '1' and user_count != 1 or user_count_filter == '2' and user_count != 2 or user_count_filter == '3+' and user_count < 3:
                        continue
                
                # Detect software type (source-authoritative).
                software_type = detect_software_type(
                    record['software_name'], record.get('db_sources') or []
                )

                # Apply software type filter
                if software_type_filter != 'all' and software_type != software_type_filter:
                    continue

                if risk_filter == 'all' or risk_filter == risk_level:
                    detections.append({
                        "id": f"sprawl_{detection_id_counter}",
                        "software_name": record['software_name'],
                        "display_name": record.get('display_name') or record['software_name'],
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
