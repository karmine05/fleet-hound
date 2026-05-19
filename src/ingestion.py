import base64
import gzip
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

from neo4j import GraphDatabase
from neo4j.exceptions import AuthError, ServiceUnavailable, TransientError


@dataclass
class LabelSyncStats:
    """Per-cycle label sync telemetry. Surfaced via ETLResult.

    `labels_unchanged` is the hash-skip count — these labels had a member-list
    hash match against the prior sync and emitted zero edge writes. `labels_resynced`
    is the dirty-path count — DETACH+re-MERGE happened. `labels_reaped` is the
    age-based orphan reap count from the end of the cycle. `orphan_members` is the
    total count of host_ids that appear in Fleet label membership but have no
    corresponding :Host node in the graph — these are the silent off-by-one gaps.
    """
    labels_seen: int = 0
    labels_unchanged: int = 0
    labels_resynced: int = 0
    labels_reaped: int = 0
    edges_created: int = 0
    edges_deleted: int = 0
    orphan_members: int = 0
    errors: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "labels_seen": self.labels_seen,
            "labels_unchanged": self.labels_unchanged,
            "labels_resynced": self.labels_resynced,
            "labels_reaped": self.labels_reaped,
            "edges_created": self.edges_created,
            "edges_deleted": self.edges_deleted,
            "orphan_members": self.orphan_members,
            "errors": list(self.errors),
        }


def compute_label_member_hash(fleet_host_ids) -> str:
    """sha256 of the canonical sorted host_id list.

    Hash on Fleet's stable numeric host id (NOT hostname). Hostnames are
    mutable in osquery; renames would otherwise churn the membership hash on
    every rename even when the actual host set is unchanged.
    """
    sorted_ids = sorted(int(h) for h in fleet_host_ids if h is not None)
    canonical = json.dumps(sorted_ids, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def encode_label_member_blob(fleet_host_ids) -> str:
    """Compact serialization of the member set for the per-host delta path.

    Stored on `Label.last_members_compressed`. Gzip-then-base64 so a 10k-host
    label's membership list lands at ~6KB instead of ~60KB raw JSON. Memgraph
    string properties handle this cleanly.
    """
    sorted_ids = sorted(int(h) for h in fleet_host_ids if h is not None)
    raw = json.dumps(sorted_ids, separators=(",", ":")).encode("utf-8")
    gz = gzip.compress(raw, compresslevel=6)
    return base64.b64encode(gz).decode("ascii")


def decode_label_member_blob(blob):
    """Inverse of encode_label_member_blob. Returns set[int] or None.

    Returns None on any decode failure (treats it as 'prior membership
    unknown') so callers fall back to the full-rewrite path safely.
    """
    if not blob:
        return None
    try:
        gz = base64.b64decode(blob)
        raw = gzip.decompress(gz)
        ids = json.loads(raw.decode("utf-8"))
        return set(int(x) for x in ids if x is not None)
    except Exception:
        return None


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
        """Create unique constraints + indexes on graph nodes.

        Host nodes MERGE on fleet_host_id — Fleet's stable numeric identifier.
        Hostname is a mutable display field updated via SET on every ingest.
        This eliminates case-variant duplicates (Fleet sometimes reports the
        same physical host with different hostname casings across cycles).

        Label nodes MERGE on fleet_id (stable across renames in Fleet); the
        name index accelerates `?labels=foo` URL→node resolution. An explicit
        hostname index keeps substring-search perf after the UNIQUE-on-hostname
        constraint was removed.
        """
        with self.driver.session() as session:
            # Drop the legacy hostname-UNIQUE constraint if present (idempotent
            # on fresh DBs). Required before swapping to fleet_host_id because
            # Memgraph rejects CREATE on a label that already has any UNIQUE.
            try:
                session.run("DROP CONSTRAINT ON (h:Host) ASSERT h.hostname IS UNIQUE;")
            except Exception:
                pass

            constraints = [
                "CREATE CONSTRAINT ON (u:User) ASSERT u.username IS UNIQUE;",
                "CREATE CONSTRAINT ON (h:Host) ASSERT h.fleet_host_id IS UNIQUE;",
                "CREATE CONSTRAINT ON (s:Software) ASSERT s.name IS UNIQUE;",
                "CREATE CONSTRAINT ON (l:Label) ASSERT l.fleet_id IS UNIQUE;",
            ]
            for constraint in constraints:
                try:
                    session.run(constraint)
                except Exception:
                    pass

            # UNIQUE on fleet_host_id implies a lookup index; no explicit index
            # needed for it. Keep an explicit hostname index for substring
            # search paths in webviz (search/filter queries).
            indexes = [
                "CREATE INDEX ON :Label(name);",
                "CREATE INDEX ON :Host(hostname);",
            ]
            for idx in indexes:
                try:
                    session.run(idx)
                except Exception:
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
        # Computed once per cycle so all host rows share the same freshness timestamp.
        now_iso = datetime.now(timezone.utc).isoformat()

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

            # Grouped software structure: List of {fleet_host_id: int, software_list: []}.
            # Keyed by Fleet's stable id; hostname carried only for diagnostic logs.
            software_grouped_batch = []

            progress_interval = 100 if total_hosts > 500 else 50 if total_hosts > 100 else 25

            skipped_no_id = 0
            skipped_no_hostname = 0

            for idx, host in enumerate(hosts_data):
                if (idx + 1) % progress_interval == 0 or (idx + 1) == total_hosts:
                    print(f"   Processing host {idx + 1}/{total_hosts}...")

                hostname = host.get('hostname')
                if not hostname:
                    skipped_no_hostname += 1
                    continue

                # fleet_host_id is the canonical identity for Host nodes (see
                # create_constraints docstring). Without it we cannot MERGE
                # safely — skip rather than create an orphan keyed by NULL.
                fleet_host_id = host.get('id')
                if fleet_host_id is None:
                    skipped_no_id += 1
                    continue

                # Host Data — fleet_host_id is the MERGE key; all other fields
                # (hostname included) are written via SET on every cycle.
                host_batch.append({
                    'hostname': hostname,
                    'fleet_host_id': fleet_host_id,
                    'os_version': host.get('os_version'),
                    'platform': host.get('platform'),
                    'ip': host.get('primary_ip'),
                    'last_seen': host.get('seen_time'),
                    'team_id': host.get('team_id'),
                    'team_name': host.get('team_name'),
                    'last_software_sync_iso': now_iso,
                })

                # User Relationships — match Host by fleet_host_id (stable).
                extracted_users = self._extract_user_identifiers(host)
                for uname in extracted_users:
                     # Simple lookup for enrichment
                     user = user_lookup.get(uname)
                     user_rel_batch.append({
                        'username': uname,
                        'email': user.get('email') if user else None,
                        'fullname': (user.get('name') or user.get('full_name')) if user else None,
                        'fleet_host_id': fleet_host_id
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
                            'fleet_host_id': fleet_host_id,
                            'software_list': cleaned_software
                        })

                # Flush Batches.
                # Ordering invariant: HOSTS MUST FLUSH BEFORE user/software rels in
                # the same iteration because the rel queries MATCH on Host by
                # fleet_host_id (no implicit creation). Always flush hosts first
                # when ANY downstream batch is ready.
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

            if skipped_no_id:
                print(f"   ⚠️  Skipped {skipped_no_id} host(s) with missing fleet id (cannot MERGE without identity).")
            if skipped_no_hostname:
                print(f"   ⚠️  Skipped {skipped_no_hostname} host(s) with missing hostname.")

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
        """Execute a query with retry logic for transient errors.

        Three error classes:
          - TransientError → retry with backoff (Memgraph signaled retry).
          - ServiceUnavailable / AuthError → propagate immediately. These are
            connection-level failures (Memgraph down, wrong creds). Swallowing
            them as warnings caused the May 2026 silent-watermark-advance bug
            where ETL "succeeded" with zero ingest writes and bumped the
            differential watermark, so the next cycle missed every host that
            wasn't recently changed.
          - Other Exception → warn + return False (legacy behavior for
            unexpected per-query failures that don't indicate a system-wide
            outage).
        """
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
            except (ServiceUnavailable, AuthError):
                # Connection-level failure. Re-raise so the ETL cycle aborts
                # without advancing the differential watermark in
                # `.state.json`. Caller (etl.run_etl) catches this in its
                # outer try/except and skips state.save() — guaranteeing the
                # next run will re-fetch everything from the prior watermark.
                raise
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
        """Batch create hosts using UNWIND.

        MERGE keyed by fleet_host_id (Fleet's stable numeric id, guaranteed
        non-null by the ingest-loop guard). Hostname is written via SET on
        every cycle so case-drift or rename in Fleet updates the display
        label without spawning a new node.
        """
        if not host_batch:
            return

        query = """
            UNWIND $hosts AS host
            MERGE (h:Host {fleet_host_id: host.fleet_host_id})
            SET h.hostname = host.hostname,
                h.os_version = host.os_version,
                h.platform = host.platform,
                h.ip = host.ip,
                h.last_seen = host.last_seen,
                h.team_id = host.team_id,
                h.team_name = host.team_name,
                h.last_software_sync_iso = host.last_software_sync_iso
        """
        self._execute_with_retry(session, query, {'hosts': host_batch}, "create host batch")

    def _batch_create_user_relationships(self, session, user_rel_batch):
        """Batch create user-host relationships using UNWIND.

        Matches Host by fleet_host_id (stable identity) to avoid creating
        ghost host nodes and to remain correct when hostname casing drifts
        between cycles. Hosts must be created via _batch_create_hosts before
        this is called.
        """
        if not user_rel_batch:
            return

        query = """
            UNWIND $rels AS rel
            MATCH (h:Host {fleet_host_id: rel.fleet_host_id})
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
        # Host MATCH is keyed by fleet_host_id (stable identity); hosts must be
        # ingested via _batch_create_hosts before this runs.
        query_rels = """
            UNWIND $software AS sw
            MATCH (s:Software {name: sw.name})
            MATCH (h:Host {fleet_host_id: sw.fleet_host_id})
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
        # MATCH Host ONCE per host entry, keyed by stable fleet_host_id.
        query_rels = """
            UNWIND $batches AS batch
            MATCH (h:Host {fleet_host_id: batch.fleet_host_id})
            WITH h, batch
            UNWIND batch.software_list AS sw
            MATCH (s:Software {name: sw.name})
            MERGE (s)-[:INSTALLED_ON]->(h)
        """
        self._execute_with_retry(session, query_rels, {'batches': software_grouped_batch}, "create grouped software rels")

        # 4. Orphan accounting: count entries whose fleet_host_id had no :Host
        # node at MATCH time (parity with label-orphan telemetry from 260519-j0t).
        # A single OPTIONAL MATCH against the same in-memory batch; no extra fan-out.
        orphan_query = """
            UNWIND $batches AS batch
            OPTIONAL MATCH (h:Host {fleet_host_id: batch.fleet_host_id})
            WITH batch, h
            WHERE h IS NULL
            RETURN count(batch) AS orphans
        """
        try:
            rec = session.run(orphan_query, batches=software_grouped_batch).single()
            orphans = int(rec["orphans"]) if rec and rec.get("orphans") is not None else 0
        except Exception:
            orphans = 0
        if orphans > 0:
            print(
                f"   ⚠️  host_software_orphans={orphans}"
                " (entries with fleet_host_id matching no :Host node"
                " — software dropped on the floor for those hosts this cycle)"
            )

    # ------------------------------------------------------------------
    # Label sync (added in v1.27 — see plan section 1A/1B/1D/4A)
    # ------------------------------------------------------------------
    #
    # Per-cycle data flow:
    #
    #   labels (list of dicts from /labels)
    #         │
    #         ▼
    #   _batch_merge_labels()  ── MERGE on fleet_id, SET name/description/etc.
    #         │
    #         ▼
    #   for each label:
    #       new_hash = sha256(sorted fleet_host_ids of current Fleet members)
    #       if new_hash == Label.last_member_hash:
    #           SET last_synced_iso ; status="ok"   ── HASH SKIP (zero edges)
    #       else:
    #           DETACH DELETE existing HAS_LABEL from this label
    #           MERGE HAS_LABEL for current member set
    #           SET last_member_hash = new_hash, last_synced_iso, status="ok"
    #         │
    #         ▼
    #   _reap_stale_labels()  ── 7-day age-based DETACH DELETE for labels
    #                           NOT in this cycle's payload (T2: option C)
    #
    # The hash key is fleet_host_id (stable), NOT hostname (mutable).
    # Recovery: graph wipe → no Label nodes → first cycle re-MERGEs everything
    # because every hash is missing → all labels treated as dirty. Self-healing.
    # ------------------------------------------------------------------

    def sync_labels_with_membership(self, labels, member_map, now_iso,
                                    reap_age_seconds: int = 604800):
        """Top-level label sync entry. Called by etl.run_etl after host ingest.

        Args:
            labels: list of label dicts from FleetGraphExtractor.extract_labels()
            member_map: {fleet_label_id: [fleet_host_id, ...]} from
                FleetGraphExtractor.extract_label_host_membership() per label
            now_iso: ISO 8601 UTC timestamp for last_synced_iso writes
            reap_age_seconds: orphan reap threshold; default 7 days per
                plan T2 (option C, age-based)

        Returns: LabelSyncStats summarizing the cycle.
        """
        stats = LabelSyncStats()
        if not labels:
            # Empty payload: don't touch the graph beyond age-based reaping.
            # Pure age-based reaping is robust to single-cycle empty responses
            # because labels synced within the last 7 days survive.
            with self.driver.session() as session:
                stats.labels_reaped = self._reap_stale_labels(
                    session, present_fleet_ids=[], now_iso=now_iso,
                    reap_age_seconds=reap_age_seconds,
                )
            return stats

        with self.driver.session() as session:
            self._batch_merge_labels(session, labels, now_iso)

            for lbl in labels:
                fleet_id = lbl.get('id')
                if fleet_id is None:
                    stats.errors.append(f"label without id: {lbl.get('name')!r}")
                    continue
                stats.labels_seen += 1
                member_ids = member_map.get(fleet_id, [])
                changed, edges_added, edges_removed, orphans_count = self._sync_single_label_membership(
                    session, fleet_id, member_ids, now_iso,
                )
                stats.orphan_members += orphans_count
                if changed:
                    stats.labels_resynced += 1
                    stats.edges_created += edges_added
                    stats.edges_deleted += edges_removed
                else:
                    stats.labels_unchanged += 1

            if stats.orphan_members > 0:
                logger.info(
                    "ingestion: label sync orphan summary — "
                    "orphan_members=%d (host ids in Fleet membership with no :Host node)",
                    stats.orphan_members,
                )

            present_ids = [
                lbl['id'] for lbl in labels if lbl.get('id') is not None
            ]
            stats.labels_reaped = self._reap_stale_labels(
                session, present_fleet_ids=present_ids, now_iso=now_iso,
                reap_age_seconds=reap_age_seconds,
            )
        return stats

    def _batch_merge_labels(self, session, labels, now_iso):
        """MERGE Label nodes on fleet_id; refresh metadata + last_synced_iso.

        Membership hash is NOT touched here — that's done in
        _sync_single_label_membership which compares old vs new and decides
        whether to re-MERGE edges. This call only handles Label entity props.
        """
        if not labels:
            return
        rows = []
        for lbl in labels:
            fleet_id = lbl.get('id')
            if fleet_id is None:
                continue
            rows.append({
                'fleet_id': fleet_id,
                'name': lbl.get('name'),
                'description': lbl.get('description') or '',
                'label_type': (lbl.get('label_type') or 'regular').lower(),
                'membership_type': (lbl.get('label_membership_type') or '').lower(),
                'query': lbl.get('query') or '',
                'host_count': lbl.get('host_count') or 0,
                'now_iso': now_iso,
            })
        query = """
            UNWIND $rows AS row
            MERGE (l:Label {fleet_id: row.fleet_id})
            SET l.name = row.name,
                l.description = row.description,
                l.label_type = row.label_type,
                l.membership_type = row.membership_type,
                l.query = row.query,
                l.host_count = row.host_count,
                l.last_synced_iso = row.now_iso,
                l.last_label_sync_status = 'ok',
                l.consecutive_failures = 0
        """
        self._execute_with_retry(session, query, {'rows': rows}, "merge label nodes")

    def _sync_single_label_membership(self, session, fleet_id, member_ids, now_iso):
        """Hash-skip + per-host symmetric diff (TODO-1, formerly hybrid C+B).

        Three paths:
          1. Hash match → drift check, then zero edge writes (skip entirely).
             Drift check: live count(HAS_LABEL) must equal len(member_ids).
             If they diverge, the persisted blob is "stale-correct" but the
             graph has lost (or never created) edges — fall through to the
             full-rewrite repair path. Without this check, drift is sticky:
             every subsequent cycle sees hash-match and never recovers.
          2. Hash mismatch + prior member blob present → per-host delta.
             Decode prior set; new set = current Fleet members; emit
             DELETEs for `prior - new` and MERGEs for `new - prior`.
             Edge churn is O(actual delta), not O(label size).
          3. Hash mismatch + no prior blob → full rewrite (legacy path).
             Hits on first sync after upgrade or after `Label.last_members_
             compressed` is missing for any reason. Self-healing: next
             cycle has the blob and the delta path takes over.

        Returns (changed, edges_added, edges_removed, orphans_count).
        """
        new_hash = compute_label_member_hash(member_ids)

        prior = session.run(
            "MATCH (l:Label {fleet_id: $fid}) "
            "RETURN l.last_member_hash AS h, l.last_members_compressed AS blob",
            fid=fleet_id,
        ).single()
        prior_hash = prior["h"] if prior else None
        prior_blob = prior["blob"] if prior else None

        expected_count = sum(1 for h in member_ids if h is not None)
        ids_list = sorted(int(h) for h in member_ids if h is not None)

        if prior_hash == new_hash:
            # Drift check before honoring the fast-path skip. Counts the
            # live HAS_LABEL edges from any Host to this Label; cheap because
            # Memgraph indexes Label.fleet_id and HAS_LABEL is a typed edge.
            count_rec = session.run(
                "MATCH (:Host)-[r:HAS_LABEL]->(:Label {fleet_id: $fid}) "
                "RETURN count(r) AS c",
                fid=fleet_id,
            ).single()
            live_edges = count_rec["c"] if count_rec else 0
            if live_edges == expected_count:
                # Hash match AND graph state consistent → safe to skip.
                # last_synced_iso already updated in _batch_merge_labels.
                # Still refresh orphan accounting cheaply so operators see
                # an up-to-date orphan_member_count without waiting for a
                # dirty cycle.
                orphan_rec = session.run(
                    """
                    MATCH (l:Label {fleet_id: $fid})
                    OPTIONAL MATCH (h:Host) WHERE h.fleet_host_id IN $ids
                    WITH l, collect(h.fleet_host_id) AS present
                    SET l.orphan_member_count = size([x IN $ids WHERE NOT x IN present]),
                        l.orphan_member_ids = [x IN $ids WHERE NOT x IN present][..50],
                        l.orphan_member_truncated = size([x IN $ids WHERE NOT x IN present]) > 50
                    RETURN l.orphan_member_count AS c
                    """,
                    fid=fleet_id, ids=ids_list,
                ).single()
                orphans_c = int(orphan_rec["c"]) if orphan_rec and orphan_rec["c"] is not None else 0
                return (False, 0, 0, orphans_c)
            # Drift detected: fall through to full-rewrite repair. Don't
            # trust the prior blob/hash because either the graph lost edges
            # since the last sync, or the prior cycle's MERGE silently
            # no-op'd for hosts that hadn't been ingested yet. The
            # full-rewrite path is idempotent and converges the graph.

        new_set = set(int(h) for h in member_ids if h is not None)
        new_blob = encode_label_member_blob(new_set)
        prior_set = decode_label_member_blob(prior_blob)

        # When the hash-match drift check fell through, the persisted blob
        # is stale-correct against truth but the graph diverges from it.
        # Forcing the full-rewrite path here repairs in one shot — delta
        # against `prior_set` would compute zero-diff and silently re-skip.
        if prior_hash == new_hash or prior_set is None:
            # No prior blob (first cycle after upgrade or decode failed),
            # or drift-repair: full rewrite. Next cycle has the blob and
            # the delta path takes over.
            edges_added, edges_removed, orphans_count = self._full_rewrite_label_membership(
                session, fleet_id, new_set,
            )
        else:
            edges_added, edges_removed, orphans_count = self._delta_apply_label_membership(
                session, fleet_id, prior_set, new_set,
            )

        # Persist the new hash + new blob atomically with the same SET.
        session.run(
            "MATCH (l:Label {fleet_id: $fid}) "
            "SET l.last_member_hash = $h, "
            "    l.last_members_compressed = $blob, "
            "    l.last_synced_iso = $now",
            fid=fleet_id, h=new_hash, blob=new_blob, now=now_iso,
        )

        return (True, edges_added, edges_removed, orphans_count)

    def _delta_apply_label_membership(self, session, fleet_id, prior_set, new_set):
        """Per-host symmetric diff. Emits only the delta edges.

        Computes orphan ids from the `added` set (hosts Fleet says are newly
        in the label but have no :Host node in the graph). For the unchanged
        carry-over set, orphan bookkeeping is maintained via the persisted
        `Label.orphan_member_ids` property — read current, union with new
        orphans from `added`, subtract any ids that NOW have a :Host node,
        then write back to keep the property accurate across supplement cycles.

        Returns (edges_added, edges_removed, orphans_count).
        """
        added = sorted(new_set - prior_set)
        removed = sorted(prior_set - new_set)

        if removed:
            self._execute_with_retry(
                session,
                """
                UNWIND $hids AS hid
                MATCH (h:Host {fleet_host_id: hid})-[r:HAS_LABEL]->(l:Label {fleet_id: $fid})
                DELETE r
                """,
                {"hids": removed, "fid": fleet_id},
                "delete HAS_LABEL edges (delta)",
            )

        if added:
            self._execute_with_retry(
                session,
                """
                UNWIND $hids AS hid
                MATCH (h:Host {fleet_host_id: hid})
                MATCH (l:Label {fleet_id: $fid})
                MERGE (h)-[:HAS_LABEL]->(l)
                """,
                {"hids": added, "fid": fleet_id},
                "merge HAS_LABEL edges (delta)",
            )

        # Compute orphans for the `added` set: which new ids have no :Host?
        new_orphan_candidates = added if added else []
        if new_orphan_candidates:
            present_rec = session.run(
                "MATCH (h:Host) WHERE h.fleet_host_id IN $ids "
                "RETURN collect(h.fleet_host_id) AS present",
                ids=new_orphan_candidates,
            ).single()
            present_ids = set(present_rec["present"]) if present_rec else set()
            new_orphans = sorted(set(new_orphan_candidates) - present_ids)
        else:
            new_orphans = []

        # Read existing persisted orphan ids, union with new, re-check
        # the full combined set against live :Host nodes so that ids
        # back-filled by a prior supplement cycle are removed automatically.
        existing_rec = session.run(
            "MATCH (l:Label {fleet_id: $fid}) "
            "RETURN coalesce(l.orphan_member_ids, []) AS oids",
            fid=fleet_id,
        ).single()
        existing_orphans = set(existing_rec["oids"]) if existing_rec else set()

        # Also remove any ids that left new_set (they're no longer members).
        candidate_orphans = (existing_orphans | set(new_orphans)) - set(removed)
        # Remove ids no longer in new_set at all.
        candidate_orphans &= new_set

        # Re-check all candidate orphans against live :Host nodes.
        if candidate_orphans:
            recheck_rec = session.run(
                "MATCH (h:Host) WHERE h.fleet_host_id IN $ids "
                "RETURN collect(h.fleet_host_id) AS present",
                ids=sorted(candidate_orphans),
            ).single()
            still_present = set(recheck_rec["present"]) if recheck_rec else set()
            final_orphans = sorted(candidate_orphans - still_present)
        else:
            final_orphans = []

        orphans_count = len(final_orphans)
        capped = final_orphans[:50]
        truncated = len(final_orphans) > 50
        session.run(
            "MATCH (l:Label {fleet_id: $fid}) "
            "SET l.orphan_member_count = $count, "
            "    l.orphan_member_ids = $ids, "
            "    l.orphan_member_truncated = $trunc",
            fid=fleet_id, count=orphans_count, ids=capped, trunc=truncated,
        )

        return (len(added), len(removed), orphans_count)

    def _full_rewrite_label_membership(self, session, fleet_id, new_set):
        """Legacy full-rewrite path (DETACH all + re-MERGE current).

        Used only when no prior member blob exists (first sync after upgrade
        or decode failure). Computes orphan ids (ids in new_set with no
        matching :Host node) via a pre-MERGE existence check and persists
        them on the :Label node. Returns (edges_added, edges_removed,
        orphans_count).
        """
        prior_edge_count_rec = session.run(
            "MATCH (:Host)-[r:HAS_LABEL]->(:Label {fleet_id: $fid}) "
            "RETURN count(r) AS c",
            fid=fleet_id,
        ).single()
        prior_edges = prior_edge_count_rec["c"] if prior_edge_count_rec else 0

        session.run(
            "MATCH (:Host)-[r:HAS_LABEL]->(:Label {fleet_id: $fid}) DELETE r",
            fid=fleet_id,
        )

        if new_set:
            sorted_ids = sorted(new_set)

            # Pre-MERGE existence check: find which ids have no :Host node.
            # One round-trip; cheap relative to the MERGE that follows.
            present_rec = session.run(
                "MATCH (h:Host) WHERE h.fleet_host_id IN $ids "
                "RETURN collect(h.fleet_host_id) AS present",
                ids=sorted_ids,
            ).single()
            present_ids = set(present_rec["present"]) if present_rec else set()
            orphan_ids = sorted(set(sorted_ids) - present_ids)
            orphans_count = len(orphan_ids)
            capped = orphan_ids[:50]
            truncated = len(orphan_ids) > 50

            # Persist orphan accounting on the Label node before MERGE.
            session.run(
                "MATCH (l:Label {fleet_id: $fid}) "
                "SET l.orphan_member_count = $count, "
                "    l.orphan_member_ids = $ids, "
                "    l.orphan_member_truncated = $trunc",
                fid=fleet_id, count=orphans_count, ids=capped, trunc=truncated,
            )

            self._execute_with_retry(
                session,
                """
                UNWIND $hids AS hid
                MATCH (h:Host {fleet_host_id: hid})
                MATCH (l:Label {fleet_id: $fid})
                MERGE (h)-[:HAS_LABEL]->(l)
                """,
                {"hids": sorted_ids, "fid": fleet_id},
                "re-merge HAS_LABEL edges (full rewrite fallback)",
            )
            # Count actual merged edges, not requested. If a Host node is
            # missing (member id present in Fleet but not yet ingested),
            # the MATCH drops that row and MERGE no-ops — counting len(ids)
            # would overcount and mask the gap.
            post_rec = session.run(
                "MATCH (:Host)-[r:HAS_LABEL]->(:Label {fleet_id: $fid}) "
                "RETURN count(r) AS c",
                fid=fleet_id,
            ).single()
            edges_added = post_rec["c"] if post_rec else 0
        else:
            orphans_count = 0
            # Clear orphan accounting when label has no members.
            session.run(
                "MATCH (l:Label {fleet_id: $fid}) "
                "SET l.orphan_member_count = 0, "
                "    l.orphan_member_ids = [], "
                "    l.orphan_member_truncated = false",
                fid=fleet_id,
            )
            edges_added = 0

        return (edges_added, prior_edges, orphans_count)

    def _reap_stale_labels(self, session, present_fleet_ids, now_iso,
                           reap_age_seconds: int = 604800):
        """Age-based DETACH DELETE for orphan Label nodes (plan T2 option C).

        A label is reaped when:
          - its fleet_id is NOT in `present_fleet_ids` (Fleet no longer
            returns it from /labels), AND
          - its `last_synced_iso` is older than `reap_age_seconds` ago.

        Pure age-based: tolerates transient empty-response cycles because a
        label synced in the last 7 days survives even if a single cycle
        returns it stale. The `present_fleet_ids` arg is empty-list-safe.
        """
        try:
            now_dt = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
        except ValueError:
            now_dt = datetime.now(timezone.utc)
        cutoff = (now_dt - timedelta(seconds=reap_age_seconds)).isoformat()
        present = list(present_fleet_ids)

        # Memgraph does not support Cypher 5's `count {(pattern)}` subquery
        # syntax. Split the count + delete into two queries within the same
        # session so the reap stat is accurate without the subquery.
        count_rec = session.run(
            "MATCH (l:Label) "
            "WHERE NOT l.fleet_id IN $present "
            "  AND l.last_synced_iso < $cutoff "
            "RETURN count(l) AS reaped",
            present=present, cutoff=cutoff,
        ).single()
        reaped = count_rec["reaped"] if count_rec else 0

        if reaped > 0:
            session.run(
                "MATCH (l:Label) "
                "WHERE NOT l.fleet_id IN $present "
                "  AND l.last_synced_iso < $cutoff "
                "DETACH DELETE l",
                present=present, cutoff=cutoff,
            )
        return reaped

    def mark_label_sync_failure(self, error_msg: str):
        """Record a global label-sync failure on every Label node.

        Called by etl.run_etl when /labels itself fails (no per-label data
        even available). Bumps consecutive_failures and flips status to
        `failed` so /api/labels surfaces freshness drift in the UI.
        Existing HAS_LABEL edges are NOT touched — last-known-good state
        is preserved per plan section 2B.
        """
        with self.driver.session() as session:
            session.run(
                "MATCH (l:Label) "
                "SET l.last_label_sync_status = 'failed', "
                "    l.consecutive_failures = coalesce(l.consecutive_failures, 0) + 1, "
                "    l.last_label_sync_error = $err",
                err=error_msg[:500],
            )
