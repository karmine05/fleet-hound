#!/usr/bin/env python3
"""Clear all data from Memgraph database AND remove host-side runtime state.

`clear_db.py` is the live-instance counterpart to `./stop.sh --purge`:
the stop script wipes the Docker volume (DB offline), this one talks to a
running Memgraph and drops every node, relationship, constraint, AND index,
then removes the host/bind-mount artifacts the OODA + ETL workers leave on
disk (`.state.json`, `.etl.lock`, `config/snapshots/`, `config/whitelist.json`).

Without the artifact sweep the next ETL/OODA cycle would resume from a
stale watermark or re-apply a stale whitelist — producing the "I cleared
the DB but it's still acting like the old one" surprise this script is
named to prevent.
"""

import argparse
import os
import shutil
import sys

from neo4j import GraphDatabase


# Default host-side artifact paths. Aligned with stop.sh --purge so the two
# scripts wipe the same set of files. Override individually via CLI flags if
# the deployment customized paths.
_DEFAULT_STATE_FILE = ".state.json"
_DEFAULT_ETL_LOCK = ".etl.lock"
_DEFAULT_SNAPSHOT_DIR = "config/snapshots"
_DEFAULT_WHITELIST_FILE = "config/whitelist.json"
_DEFAULT_CONTAINER_STATE_FILE = "config/.state.json"


def _parse_args():
    parser = argparse.ArgumentParser(description="Clear all data from a Memgraph instance AND wipe host-side runtime state (DESTRUCTIVE).")
    parser.add_argument(
        "--memgraph-uri",
        default=os.environ.get("MEMGRAPH_URI", "bolt://localhost:7687"),
        help="Memgraph Bolt URI (default: from MEMGRAPH_URI env or bolt://localhost:7687)",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip interactive confirmation prompt (dangerous).",
    )
    parser.add_argument(
        "--state-file",
        default=_DEFAULT_STATE_FILE,
        help=f"Path to host-side ETL state file (default: {_DEFAULT_STATE_FILE})",
    )
    parser.add_argument(
        "--etl-lock",
        default=_DEFAULT_ETL_LOCK,
        help=f"Path to host-side ETL lock file (default: {_DEFAULT_ETL_LOCK})",
    )
    parser.add_argument(
        "--snapshot-dir",
        default=_DEFAULT_SNAPSHOT_DIR,
        help=f"Path to ETL snapshot directory (default: {_DEFAULT_SNAPSHOT_DIR})",
    )
    parser.add_argument(
        "--whitelist-file",
        default=_DEFAULT_WHITELIST_FILE,
        help=f"Path to OODA whitelist file (default: {_DEFAULT_WHITELIST_FILE})",
    )
    parser.add_argument(
        "--container-state-file",
        default=_DEFAULT_CONTAINER_STATE_FILE,
        help=(
            "Path to container-side state file (bind-mounted via ./config). "
            f"Default: {_DEFAULT_CONTAINER_STATE_FILE}. Set to empty string to skip."
        ),
    )
    parser.add_argument(
        "--keep-schema",
        action="store_true",
        help="Drop nodes/edges only; preserve constraints + indexes.",
    )
    parser.add_argument(
        "--keep-files",
        action="store_true",
        help="Clear Memgraph only; preserve host-side state files.",
    )
    return parser.parse_args()


def _memgraph_auth():
    """Build (user, password) tuple from env (with _FILE indirection), or None."""
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
    return (user, pwd) if (user and pwd) else None


def _drop_all_constraints(session) -> int:
    """Enumerate every constraint via SHOW CONSTRAINT INFO and DROP it.

    Memgraph's `SHOW CONSTRAINT INFO` returns rows shaped roughly like
    {constraint type, label, properties}. The exact field names vary across
    Memgraph versions (`constraint type`/`constraint_type`, `properties`
    list vs single `property` string), so we coerce defensively. Falls back
    to a hardcoded list if SHOW isn't available on this Memgraph build.
    """
    dropped = 0
    try:
        rows = list(session.run("SHOW CONSTRAINT INFO"))
    except Exception:
        rows = []

    if rows:
        for r in rows:
            data = r.data() if hasattr(r, "data") else dict(r)
            ctype = (data.get("constraint type") or data.get("constraint_type") or data.get("type") or "").lower()
            label = data.get("label") or data.get("Label")
            props = data.get("properties") or data.get("property") or data.get("Properties")
            if isinstance(props, str):
                props_list = [props]
            elif isinstance(props, (list, tuple)):
                props_list = list(props)
            else:
                props_list = []
            if not (label and props_list):
                continue
            if "unique" in ctype:
                prop_str = ", ".join(f"n.{p}" for p in props_list)
                cypher = f"DROP CONSTRAINT ON (n:{label}) ASSERT {prop_str} IS UNIQUE;"
            elif "exist" in ctype:
                # Memgraph "exists" constraints are single-property.
                cypher = f"DROP CONSTRAINT ON (n:{label}) ASSERT EXISTS (n.{props_list[0]});"
            else:
                continue
            try:
                session.run(cypher).consume()
                dropped += 1
            except Exception as e:
                print(f"⚠️  Failed to drop constraint {cypher!r}: {e}")
        return dropped

    # Fallback: enumerate the constraints Fleet Hound is known to create.
    # Keep in sync with src/ingestion.py:create_constraints().
    fallback = [
        "DROP CONSTRAINT ON (u:User) ASSERT u.username IS UNIQUE;",
        "DROP CONSTRAINT ON (h:Host) ASSERT h.hostname IS UNIQUE;",  # legacy
        "DROP CONSTRAINT ON (h:Host) ASSERT h.fleet_host_id IS UNIQUE;",
        "DROP CONSTRAINT ON (s:Software) ASSERT s.name IS UNIQUE;",
        "DROP CONSTRAINT ON (l:Label) ASSERT l.fleet_id IS UNIQUE;",
    ]
    for cypher in fallback:
        try:
            session.run(cypher).consume()
            dropped += 1
        except Exception:
            pass
    return dropped


def _drop_all_indexes(session) -> int:
    """Enumerate every index via SHOW INDEX INFO and DROP it.

    Index INFO row shape (Memgraph 2.x): {index type, label, property, count}.
    `index type` is e.g. 'label' or 'label+property'. We DROP both kinds —
    `DROP INDEX ON :Label;` for label-only, `DROP INDEX ON :Label(prop);`
    for label+property. Falls back to the known Fleet Hound list if SHOW
    is unsupported.
    """
    dropped = 0
    try:
        rows = list(session.run("SHOW INDEX INFO"))
    except Exception:
        rows = []

    if rows:
        for r in rows:
            data = r.data() if hasattr(r, "data") else dict(r)
            label = data.get("label") or data.get("Label")
            prop = data.get("property") or data.get("Property")
            if not label:
                continue
            cypher = f"DROP INDEX ON :{label}({prop});" if prop else f"DROP INDEX ON :{label};"
            try:
                session.run(cypher).consume()
                dropped += 1
            except Exception as e:
                print(f"⚠️  Failed to drop index {cypher!r}: {e}")
        return dropped

    # Fallback: enumerate the indexes Fleet Hound is known to create.
    # Keep in sync with src/ingestion.py:create_constraints().
    fallback = [
        "DROP INDEX ON :Label(name);",
        "DROP INDEX ON :Host(hostname);",
    ]
    for cypher in fallback:
        try:
            session.run(cypher).consume()
            dropped += 1
        except Exception:
            pass
    return dropped


def clear_memgraph(memgraph_uri: str, *, assume_yes: bool, keep_schema: bool = False) -> None:
    """Clear all nodes, relationships, constraints, and indexes from Memgraph."""

    if not assume_yes:
        if not sys.stdin.isatty():
            print(
                "Refusing to clear database without confirmation in non-interactive mode. Use --yes to override.",
                file=sys.stderr,
            )
            raise SystemExit(2)

        confirm = input(
            "⚠️  This will DELETE ALL DATA in Memgraph AND wipe host-side runtime state. Type DELETE to continue (or anything else to abort): "
        ).strip()
        if confirm != "DELETE":
            print("Aborted.")
            return

    print(f"Connecting to Memgraph at {memgraph_uri}...")
    driver = None
    try:
        driver = GraphDatabase.driver(memgraph_uri, auth=_memgraph_auth())

        with driver.session() as session:
            print("Clearing all data from Memgraph...")
            # DETACH DELETE handles both nodes and their incident relationships;
            # no separate edge sweep is needed.
            session.run("MATCH (n) DETACH DELETE n").consume()

            if not keep_schema:
                print("Dropping all constraints...")
                n_constraints = _drop_all_constraints(session)
                print(f"  {n_constraints} constraint(s) dropped")

                print("Dropping all indexes...")
                n_indexes = _drop_all_indexes(session)
                print(f"  {n_indexes} index(es) dropped")
            else:
                print("Preserving constraints + indexes (--keep-schema)")

            # Verify database is empty
            result = session.run("MATCH (n) RETURN count(n) AS count").single()
            count = result["count"] if result else 0
            rel_result = session.run("MATCH ()-[r]->() RETURN count(r) AS count").single()
            rel_count = rel_result["count"] if rel_result else 0
            print(f"Database cleared. Remaining nodes: {count}, relationships: {rel_count}")
    finally:
        if driver is not None:
            driver.close()

    print("✅ Memgraph database cleared successfully!")


def _purge_path(path: str, label: str) -> bool:
    """Remove `path` (file or directory). Returns True on actual removal."""
    if not path or not os.path.exists(path):
        return False
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
        print(f"✅ {label} ({path}) removed")
        return True
    except OSError as e:
        print(f"⚠️  Failed to remove {label} ({path}): {e}")
        return False


def purge_host_state(
    *,
    state_file: str,
    etl_lock: str,
    snapshot_dir: str,
    whitelist_file: str,
    container_state_file: str,
) -> None:
    """Wipe host-side / bind-mount runtime state files.

    Match the set `stop.sh --purge` cleans so the two scripts converge on the
    same fully-reset state regardless of which one the operator runs.
    """
    print("Wiping host-side runtime state...")
    removed_any = False
    removed_any |= _purge_path(state_file, "ETL state")
    removed_any |= _purge_path(etl_lock, "ETL lock")
    removed_any |= _purge_path(snapshot_dir, "Snapshot dir")
    removed_any |= _purge_path(whitelist_file, "OODA whitelist")
    removed_any |= _purge_path(container_state_file, "Container state")
    if not removed_any:
        print("ℹ️  No host-side state artifacts to remove.")


if __name__ == "__main__":
    args = _parse_args()
    clear_memgraph(args.memgraph_uri, assume_yes=args.yes, keep_schema=args.keep_schema)
    if not args.keep_files:
        purge_host_state(
            state_file=args.state_file,
            etl_lock=args.etl_lock,
            snapshot_dir=args.snapshot_dir,
            whitelist_file=args.whitelist_file,
            container_state_file=args.container_state_file,
        )
    else:
        print("Preserving host-side state files (--keep-files)")
