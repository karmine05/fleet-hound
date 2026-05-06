import os
import time

from neo4j import GraphDatabase
from neo4j.exceptions import TransientError


def _memgraph_auth():
    """Build a (user, password) tuple from MEMGRAPH_USER/MEMGRAPH_PASSWORD env, or None.

    MEMGRAPH_PASSWORD_FILE takes precedence over MEMGRAPH_PASSWORD so secrets can
    be mounted as files instead of being committed in plaintext env vars.
    """
    user = os.environ.get("MEMGRAPH_USER", "").strip()
    pwd_file = os.environ.get("MEMGRAPH_PASSWORD_FILE", "").strip()
    pwd = ""
    if pwd_file:
        try:
            with open(pwd_file, "r", encoding="utf-8") as fh:
                pwd = fh.read().strip()
        except OSError:
            pwd = ""
    if not pwd:
        pwd = os.environ.get("MEMGRAPH_PASSWORD", "").strip()
    if user and pwd:
        return (user, pwd)
    return None


class MemgraphIngestion:
    def __init__(self, uri="bolt://localhost:7687", auth=None):
        if auth is None:
            auth = _memgraph_auth()
        self.driver = GraphDatabase.driver(uri, auth=auth)
        self.batch_size = 5000  # Optimized batch size
        self.max_retries = 3

    def close(self):
        """Close the underlying database driver."""
        self.driver.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def create_constraints(self):
        """Create unique constraints on graph nodes."""
        with self.driver.session() as session:
            # Try to create constraints, ignore if they already exist
            constraints = [
                "CREATE CONSTRAINT ON (u:User) ASSERT u.username IS UNIQUE;",
                "CREATE CONSTRAINT ON (h:Host) ASSERT h.hostname IS UNIQUE;",
                "CREATE CONSTRAINT ON (s:Software) ASSERT s.name IS UNIQUE;"
            ]
            for constraint in constraints:
                try:
                    session.run(constraint)
                except Exception:
                    # Constraint already exists, ignore
                    pass

    def create_graph_relationships(self, hosts_data, extractor, global_users=None):
        """
        Ingest hosts, users, software, and relationships into Memgraph.

        Performance optimizations:
        - Parallel batch processing using ThreadPoolExecutor
        - Grouped software ingestion (per host) to reduce graph traversals
        - Optimized batch sizes
        """
        start_time = time.time()
        
        # Optimize batch sizing for different data types.
        # Users/Hosts are light, so larger batches amortize Bolt round-trips.
        # Software is grouped per-host so the flush threshold is in HOSTS-with-bundles,
        # not raw software rows — see software_grouped_batch flush below.
        HOST_BATCH_SIZE = 5000
        USER_BATCH_SIZE = 5000

        with self.driver.session() as session:
            # 1. Users
            user_lookup = {}
            if global_users:
                print(f"💾 Ingesting {len(global_users)} users...")
                user_batch = []
                for user in global_users:
                    uname = user.get('username') or user.get('email') or user.get('name')
                    if uname:
                        user_lookup[uname] = user
                        user_batch.append({
                            'username': uname,
                            'email': user.get('email'),
                            'fullname': user.get('name') or user.get('full_name')
                        })
                        if len(user_batch) >= USER_BATCH_SIZE:
                            self._batch_create_users(session, user_batch)
                            user_batch = []
                if user_batch:
                    self._batch_create_users(session, user_batch)

            # 2. Hosts & Relationships
            total_hosts = len(hosts_data)
            print(f"💾 Ingesting {total_hosts} hosts with relationships...")
            
            host_batch = []
            user_rel_batch = []
            
            # Grouped software structure: List of {hostname: str, software_list: []}
            software_grouped_batch = [] 

            progress_interval = 100 if total_hosts > 500 else 50 if total_hosts > 100 else 25

            for idx, host in enumerate(hosts_data):
                if (idx + 1) % progress_interval == 0 or (idx + 1) == total_hosts:
                    print(f"   Processing host {idx + 1}/{total_hosts}...")

                hostname = host.get('hostname')
                if not hostname:
                    continue

                # Host Data
                host_batch.append({
                    'hostname': hostname,
                    'os_version': host.get('os_version'),
                    'platform': host.get('platform'),
                    'ip': host.get('primary_ip'),
                    'last_seen': host.get('seen_time'),
                    'team_id': host.get('team_id'),
                    'team_name': host.get('team_name')
                })

                # User Relationships
                extracted_users = self._extract_user_identifiers(host)
                for uname in extracted_users:
                     # Simple lookup for enrichment
                     user = user_lookup.get(uname)
                     user_rel_batch.append({
                        'username': uname,
                        'email': user.get('email') if user else None,
                        'fullname': (user.get('name') or user.get('full_name')) if user else None,
                        'hostname': hostname
                    })

                # Software Data (Grouped)
                # `source` comes from osquery's `software` table union and tells us
                # which package channel the install came through (apps, programs,
                # deb_packages, rpm_packages, homebrew_packages, npm_packages,
                # vscode_extensions, chrome_extensions, ...). It is the cleanest
                # signal for separating "user-installed apps" (Shadow IT surface)
                # from "OS / language / extension transitive deps".
                software_list = host.get('software', [])
                if software_list:
                    cleaned_software = []
                    for s in software_list:
                        if s.get('name'):
                            cleaned_software.append({
                                'name': s.get('name'),
                                'version': s.get('version') or 'unknown',
                                'source': (s.get('source') or '').strip(),
                            })
                    if cleaned_software:
                        software_grouped_batch.append({
                            'hostname': hostname,
                            'software_list': cleaned_software
                        })

                # Flush Batches.
                # Ordering invariant: HOSTS MUST FLUSH BEFORE user/software rels in
                # the same iteration because the rel queries MATCH on Host (no
                # implicit creation). Always flush hosts first when ANY downstream
                # batch is ready.
                hosts_full = len(host_batch) >= HOST_BATCH_SIZE
                users_full = len(user_rel_batch) >= USER_BATCH_SIZE
                software_full = len(software_grouped_batch) >= 200

                if hosts_full or users_full or software_full:
                    if host_batch:
                        self._batch_create_hosts(session, host_batch)
                        host_batch = []

                if users_full:
                    self._batch_create_user_relationships(session, user_rel_batch)
                    user_rel_batch = []

                if software_full:
                    self._batch_create_software_grouped(session, software_grouped_batch)
                    software_grouped_batch = []

            # Final flush — hosts FIRST so the trailing rel batches can MATCH them.
            if host_batch:
                self._batch_create_hosts(session, host_batch)
            if user_rel_batch:
                self._batch_create_user_relationships(session, user_rel_batch)
            if software_grouped_batch:
                self._batch_create_software_grouped(session, software_grouped_batch)

            elapsed = time.time() - start_time
            print(f"✅ Ingestion completed in {elapsed:.2f} seconds")

    def print_stats(self):
        with self.driver.session() as session:
            counts = {}
            queries = {
                "hosts": "MATCH (h:Host) RETURN count(h) AS c",
                "users": "MATCH (u:User) RETURN count(u) AS c",
                "software": "MATCH (s:Software) RETURN count(s) AS c",
                "usesRels": "MATCH ()-[r:USES]->() RETURN count(r) AS c",
                "installedRels": "MATCH ()-[r:INSTALLED_ON]->() RETURN count(r) AS c"
            }
            for label, cypher in queries.items():
                rec = session.run(cypher).single()  # type: ignore[arg-type]
                counts[label] = rec["c"] if rec else 0
            print(f"Ingestion stats: Hosts={counts['hosts']} Users={counts['users']} Software={counts['software']} USES={counts['usesRels']} INSTALLED_ON={counts['installedRels']}")

    def _execute_with_retry(self, session, query, params, operation_name="operation"):
        """Execute a query with retry logic for transient errors."""
        for attempt in range(self.max_retries):
            try:
                session.run(query, **params)
                return True
            except TransientError:
                if attempt < self.max_retries - 1:
                    wait_time = 0.1 * (2 ** attempt)
                    time.sleep(wait_time)
                else:
                    print(f"   ⚠️  Warning: Failed to {operation_name} after {self.max_retries} attempts")
                    return False
            except Exception as e:
                print(f"   ⚠️  Warning: Failed to {operation_name}: {e}")
                return False
        return False

    def _batch_create_users(self, session, user_batch):
        """Batch create users using UNWIND."""
        if not user_batch:
            return

        query = """
            UNWIND $users AS user
            MERGE (u:User {username: user.username})
            SET u.email = user.email, u.fullname = user.fullname
        """
        self._execute_with_retry(session, query, {'users': user_batch}, "create user batch")

    def _batch_create_hosts(self, session, host_batch):
        """Batch create hosts using UNWIND."""
        if not host_batch:
            return

        query = """
            UNWIND $hosts AS host
            MERGE (h:Host {hostname: host.hostname})
            SET h.os_version = host.os_version,
                h.platform = host.platform,
                h.ip = host.ip,
                h.last_seen = host.last_seen,
                h.team_id = host.team_id,
                h.team_name = host.team_name
        """
        self._execute_with_retry(session, query, {'hosts': host_batch}, "create host batch")

    def _batch_create_user_relationships(self, session, user_rel_batch):
        """Batch create user-host relationships using UNWIND.

        Uses MATCH on Host to avoid creating ghost host nodes (with no platform/
        team metadata) when the host hasn't been ingested yet in this batch run.
        Hosts must be created via _batch_create_hosts before this is called.
        """
        if not user_rel_batch:
            return

        query = """
            UNWIND $rels AS rel
            MATCH (h:Host {hostname: rel.hostname})
            MERGE (u:User {username: rel.username})
            SET u.email = rel.email, u.fullname = rel.fullname
            MERGE (u)-[:USES]->(h)
        """
        self._execute_with_retry(session, query, {'rels': user_rel_batch}, "create user relationship batch")

    def _batch_create_software(self, session, software_batch):
        """Batch create software and relationships using UNWIND with retry logic."""
        if not software_batch:
            return

        # 1. Deduplicate software nodes to minimize MERGE/SET operations.
        # Key includes `source` so distinct install channels for the same
        # (name, version) (e.g., python3 from deb_packages on one host and from
        # homebrew_packages on another) all flow through and accumulate on the
        # node's `sources` list.
        unique_software_map = {}
        for sw in software_batch:
            key = (sw['name'], sw['version'], sw.get('source', ''))
            if key not in unique_software_map:
                unique_software_map[key] = sw

        unique_software_batch = list(unique_software_map.values())

        # 2. Efficiently update Software nodes and versions
        query_nodes = """
            UNWIND $software AS sw
            MERGE (s:Software {name: sw.name})
            ON CREATE SET s.versions = [sw.version],
                         s.first_version = sw.version,
                         s.last_version = sw.version,
                         s.sources = CASE
                             WHEN sw.source IS NULL OR sw.source = '' THEN []
                             ELSE [sw.source] END
            ON MATCH SET s.versions = CASE
                WHEN s.versions IS NULL THEN [sw.version]
                WHEN NOT sw.version IN s.versions THEN s.versions + [sw.version]
                ELSE s.versions END,
                s.last_version = sw.version,
                s.sources = CASE
                    WHEN sw.source IS NULL OR sw.source = '' THEN coalesce(s.sources, [])
                    WHEN s.sources IS NULL THEN [sw.source]
                    WHEN NOT sw.source IN s.sources THEN s.sources + [sw.source]
                    ELSE s.sources END
        """
        self._execute_with_retry(session, query_nodes, {'software': unique_software_batch}, "create software nodes")

        # 3. Create relationships using MATCH on both endpoints to avoid ghost hosts.
        # Hosts must be ingested via _batch_create_hosts before this runs.
        query_rels = """
            UNWIND $software AS sw
            MATCH (s:Software {name: sw.name})
            MATCH (h:Host {hostname: sw.hostname})
            MERGE (s)-[:INSTALLED_ON]->(h)
        """
        self._execute_with_retry(session, query_rels, {'software': software_batch}, "create software rels")

    def _extract_user_identifiers(self, host):
        """Extract user identifiers from host data.

        Only consider keys that are user identifiers. Do NOT fall back to host-level
        keys like 'name' or 'user' (which on Fleet often hold the host display name)
        because that pollutes the User node label with hostnames and creates spurious
        USES edges.
        """
        users_out = []
        raw_users = host.get('users')
        if isinstance(raw_users, list):
            for entry in raw_users:
                if isinstance(entry, dict):
                    cand = (
                        entry.get('username')
                        or entry.get('email')
                        or entry.get('display_name')
                    )
                    if cand:
                        users_out.append(cand)
                elif isinstance(entry, str):
                    users_out.append(entry)
        # Fallback ONLY to fields that are unambiguously user identifiers.
        for k in ('primary_user', 'owner'):
            v = host.get(k)
            if isinstance(v, str) and v:
                users_out.append(v)
        # Deduplicate while preserving order.
        seen = set()
        deduped = []
        for u in users_out:
            if u not in seen:
                seen.add(u)
                deduped.append(u)
        return deduped

    def _batch_create_software_grouped(self, session, software_grouped_batch):
        """
        Optimized batch creation of software grouped by host.
        Structure: [{'hostname': 'h1', 'software_list': [{'name': 's1', 'version': 'v1'}, ...]}, ...]
        """
        if not software_grouped_batch:
            return

        # 1. Flatten for Node Creation (Deduplicated globally for this batch)
        # We want to ensure all Software nodes exist before linking.
        
        unique_software_map = {}
        for entry in software_grouped_batch:
            for sw in entry['software_list']:
                key = (sw['name'], sw['version'], sw.get('source', ''))
                if key not in unique_software_map:
                    unique_software_map[key] = sw

        unique_software_list = list(unique_software_map.values())

        # 2. Create/Update Software Nodes
        query_nodes = """
            UNWIND $software AS sw
            MERGE (s:Software {name: sw.name})
            ON CREATE SET s.versions = [sw.version],
                          s.first_version = sw.version,
                          s.last_version = sw.version,
                          s.sources = CASE
                              WHEN sw.source IS NULL OR sw.source = '' THEN []
                              ELSE [sw.source] END
            ON MATCH SET s.versions = CASE
                WHEN s.versions IS NULL THEN [sw.version]
                WHEN NOT sw.version IN s.versions THEN s.versions + [sw.version]
                ELSE s.versions END,
                s.last_version = sw.version,
                s.sources = CASE
                    WHEN sw.source IS NULL OR sw.source = '' THEN coalesce(s.sources, [])
                    WHEN s.sources IS NULL THEN [sw.source]
                    WHEN NOT sw.source IN s.sources THEN s.sources + [sw.source]
                    ELSE s.sources END
        """
        self._execute_with_retry(session, query_nodes, {'software': unique_software_list}, "create software nodes")

        # 3. Create Links (Optimized Grouping)
        # Instead of matching Host for every software item, we Match Host ONCE per host entry
        query_rels = """
            UNWIND $batches AS batch
            MATCH (h:Host {hostname: batch.hostname})
            WITH h, batch
            UNWIND batch.software_list AS sw
            MATCH (s:Software {name: sw.name})
            MERGE (s)-[:INSTALLED_ON]->(h)
        """
        self._execute_with_retry(session, query_rels, {'batches': software_grouped_batch}, "create grouped software rels")
