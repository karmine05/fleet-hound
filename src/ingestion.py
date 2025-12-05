from neo4j import GraphDatabase
from neo4j.exceptions import TransientError
import time

class MemgraphIngestion:
    def __init__(self, uri="bolt://localhost:7687"):
        self.driver = GraphDatabase.driver(uri)
        self.batch_size = 1000  # Optimized batch size
        self.max_retries = 3

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
        - Batch processing for users, hosts, and software
        - Single UNWIND query instead of individual queries
        - Reduced database round-trips
        """
        start_time = time.time()

        with self.driver.session() as session:
            # Batch ingest all global users
            user_lookup = {}
            if global_users:
                print(f"💾 Ingesting {len(global_users)} users in batches...")
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

                        # Process in batches
                        if len(user_batch) >= self.batch_size:
                            self._batch_create_users(session, user_batch)
                            user_batch = []

                # Process remaining users
                if user_batch:
                    self._batch_create_users(session, user_batch)

                print(f"✅ Ingested {len(user_lookup)} users")
            # Batch ingest hosts and relationships
            total_hosts = len(hosts_data)
            print(f"💾 Ingesting {total_hosts} hosts with relationships...")

            host_batch = []
            user_rel_batch = []
            software_batch = []

            # Adjust progress interval based on dataset size
            progress_interval = 100 if total_hosts > 500 else 50 if total_hosts > 100 else 25

            for idx, host in enumerate(hosts_data):
                if (idx + 1) % progress_interval == 0 or (idx + 1) == total_hosts:
                    print(f"   Processing host {idx + 1}/{total_hosts}...")

                hostname = host.get('hostname')
                if not hostname:
                    continue

                # Collect host data
                host_batch.append({
                    'hostname': hostname,
                    'os_version': host.get('os_version'),
                    'platform': host.get('platform'),
                    'ip': host.get('primary_ip'),
                    'last_seen': host.get('seen_time'),
                    'team_id': host.get('team_id'),
                    'team_name': host.get('team_name')
                })

                # Extract users from host data (no additional API calls needed)
                extracted_users = self._extract_user_identifiers(host)
                for uname in extracted_users:
                    user = user_lookup.get(uname) if user_lookup else None
                    user_rel_batch.append({
                        'username': uname,
                        'email': user.get('email') if user else None,
                        'fullname': (user.get('name') or user.get('full_name')) if user else None,
                        'hostname': hostname
                    })

                # Collect software data (already populated from API)
                software_list = host.get('software', [])
                for software in software_list:
                    software_name = software.get('name')
                    if software_name:
                        software_batch.append({
                            'name': software_name,
                            'version': software.get('version') or 'unknown',
                            'hostname': hostname
                        })

                # Process batches when they reach batch_size
                if len(host_batch) >= self.batch_size:
                    self._batch_create_hosts(session, host_batch)
                    host_batch = []

                if len(user_rel_batch) >= self.batch_size:
                    self._batch_create_user_relationships(session, user_rel_batch)
                    user_rel_batch = []

                if len(software_batch) >= self.batch_size:
                    self._batch_create_software(session, software_batch)
                    software_batch = []

            # Process remaining batches
            print(f"   Finalizing remaining batches...")
            if host_batch:
                self._batch_create_hosts(session, host_batch)
                print(f"   ✓ Created {len(host_batch)} hosts")
            if user_rel_batch:
                self._batch_create_user_relationships(session, user_rel_batch)
                print(f"   ✓ Created {len(user_rel_batch)} user relationships")
            if software_batch:
                self._batch_create_software(session, software_batch)
                print(f"   ✓ Created {len(software_batch)} software relationships")

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
            if u not in seen:
                seen.add(u)
                deduped.append(u)
        return deduped
