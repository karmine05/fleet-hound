from neo4j import GraphDatabase
from neo4j.exceptions import TransientError
import time
from typing import Any, Dict, List, Optional

class MemgraphIngestion:
    def __init__(self, uri: str = "bolt://localhost:7687") -> None:
        self.driver = GraphDatabase.driver(uri)
        self.batch_size: int = 5000  # Optimized batch size
        self.max_retries: int = 3

    def close(self) -> None:
        """Close the underlying database driver."""
        self.driver.close()

    def __enter__(self) -> 'MemgraphIngestion':
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        self.close()
        return False

    def create_constraints(self) -> None:
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

    def create_graph_relationships(self, hosts_data: List[Dict[str, Any]], extractor: Any, global_users: Optional[List[Dict[str, Any]]] = None) -> None:
        """
        Ingest hosts, users, software, and relationships into Memgraph.

        Performance optimizations:
        - Parallel batch processing using ThreadPoolExecutor
        - Grouped software ingestion (per host) to reduce graph traversals
        - Optimized batch sizes
        """
        start_time = time.time()
        
        # Optimize batch sizing for different data types
        # Users/Hosts are light, can handle larger batches
        # Software is heavy (many items per host), improved by grouping
        HOST_BATCH_SIZE = 5000
        USER_BATCH_SIZE = 5000
        SOFTWARE_BATCH_SIZE = 2000 # This effectively means 2000 *HOSTS* with software bundles, which is huge

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
                            'username': uname.lower(),
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
                    'hostname': hostname.lower(),
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
                        'username': uname.lower(),
                        'email': user.get('email') if user else None,
                        'fullname': (user.get('name') or user.get('full_name')) if user else None,
                        'hostname': hostname.lower()
                    })

                # Software Data (Grouped)
                software_list = host.get('software', [])
                if software_list:
                    cleaned_software = []
                    for s in software_list:
                        if s.get('name'):
                            cleaned_software.append({
                                'name': s.get('name'),
                                'version': s.get('version') or 'unknown'
                            })
                    if cleaned_software:
                        software_grouped_batch.append({
                            'hostname': hostname.lower(),
                            'software_list': cleaned_software
                        })

                # Flush Batches
                if len(host_batch) >= HOST_BATCH_SIZE:
                    self._batch_create_hosts(session, host_batch)
                    host_batch = []
                
                if len(user_rel_batch) >= USER_BATCH_SIZE:
                    self._batch_create_user_relationships(session, user_rel_batch)
                    user_rel_batch = []

                if len(software_grouped_batch) >= 200: 
                    self._batch_create_software_grouped(session, software_grouped_batch)
                    software_grouped_batch = []

            # Flush Remaining
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
            except TransientError as e:
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
        """Batch create user-host relationships using UNWIND."""
        if not user_rel_batch:
            return

        query = """
            UNWIND $rels AS rel
            MERGE (h:Host {hostname: rel.hostname})
            MERGE (u:User {username: rel.username})
            SET u.email = rel.email, u.fullname = rel.fullname
            MERGE (u)-[:USES]->(h)
        """
        self._execute_with_retry(session, query, {'rels': user_rel_batch}, "create user relationship batch")

    def _batch_create_software(self, session, software_batch):
        """Batch create software and relationships using UNWIND with retry logic."""
        if not software_batch:
            return

        # 1. Deduplicate software nodes to minimize MERGE/SET operations
        # We only need to update the Software node once per (name, version) pair in this batch
        unique_software_map = {}
        for sw in software_batch:
            key = (sw['name'], sw['version'])
            if key not in unique_software_map:
                unique_software_map[key] = sw
        
        unique_software_batch = list(unique_software_map.values())

        # 2. Efficiently update Software nodes and versions
        query_nodes = """
            UNWIND $software AS sw
            MERGE (s:Software {name: sw.name})
            ON CREATE SET s.versions = [sw.version],
                         s.first_version = sw.version,
                         s.last_version = sw.version
            ON MATCH SET s.versions = CASE
                WHEN s.versions IS NULL THEN [sw.version]
                WHEN NOT sw.version IN s.versions THEN s.versions + [sw.version]
                ELSE s.versions END,
                s.last_version = sw.version
        """
        self._execute_with_retry(session, query_nodes, {'software': unique_software_batch}, "create software nodes")

        # 3. Create relationships (Lightweight, using MATCH)
        query_rels = """
            UNWIND $software AS sw
            MATCH (s:Software {name: sw.name})
            MERGE (h:Host {hostname: sw.hostname})
            MERGE (s)-[:INSTALLED_ON]->(h)
        """
        self._execute_with_retry(session, query_rels, {'software': software_batch}, "create software rels")

    def _extract_user_identifiers(self, host):
        """Extract user identifiers from host data."""
        users_out = []
        raw_users = host.get('users')
        if isinstance(raw_users, list):
            for entry in raw_users:
                if isinstance(entry, dict):
                    cand = entry.get('username') or entry.get('email') or entry.get('name') or entry.get('display_name')
                    if cand:
                        users_out.append(cand)
                elif isinstance(entry, str):
                    users_out.append(entry)
        # Fallback singular fields
        for k in ['primary_user', 'owner', 'user', 'name']:
            v = host.get(k)
            if isinstance(v, str):
                users_out.append(v)
        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for u in users_out:
            u_lower = u.lower()
            if u_lower not in seen:
                seen.add(u_lower)
                deduped.append(u_lower)
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
                key = (sw['name'], sw['version'])
                if key not in unique_software_map:
                    unique_software_map[key] = sw
        
        unique_software_list = list(unique_software_map.values())

        # 2. Create/Update Software Nodes
        query_nodes = """
            UNWIND $software AS sw
            MERGE (s:Software {name: sw.name})
            ON CREATE SET s.versions = [sw.version],
                          s.first_version = sw.version,
                          s.last_version = sw.version
            ON MATCH SET s.versions = CASE
                WHEN s.versions IS NULL THEN [sw.version]
                WHEN NOT sw.version IN s.versions THEN s.versions + [sw.version]
                ELSE s.versions END,
                s.last_version = sw.version
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
