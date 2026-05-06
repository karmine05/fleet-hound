#!/usr/bin/env python3
"""Clear all data from Memgraph database."""

import argparse
import os
import sys

from neo4j import GraphDatabase


def _parse_args():
    parser = argparse.ArgumentParser(description="Clear all data from a Memgraph instance (DESTRUCTIVE).")
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
        default=".state.json",
        help="Path to sync state file to remove after clearing (default: .state.json)",
    )
    return parser.parse_args()


def clear_memgraph(memgraph_uri: str, *, assume_yes: bool, state_file: str) -> None:
    """Clear all nodes and relationships from Memgraph."""

    if not assume_yes:
        if not sys.stdin.isatty():
            print(
                "Refusing to clear database without confirmation in non-interactive mode. Use --yes to override.",
                file=sys.stderr,
            )
            raise SystemExit(2)

        confirm = input(
            "⚠️  This will DELETE ALL DATA in Memgraph. Type DELETE to continue (or anything else to abort): "
        ).strip()
        if confirm != "DELETE":
            print("Aborted.")
            return

    print(f"Connecting to Memgraph at {memgraph_uri}...")
    driver = None
    try:
        # Pick up MEMGRAPH_USER/MEMGRAPH_PASSWORD (with _FILE) for authenticated instances.
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
        auth = (user, pwd) if (user and pwd) else None
        driver = GraphDatabase.driver(memgraph_uri, auth=auth)

        with driver.session() as session:
            print("Clearing all data from Memgraph...")
            session.run("MATCH (n) DETACH DELETE n")

            print("Dropping all constraints...")
            try:
                session.run("DROP CONSTRAINT ON (u:User) ASSERT u.username IS UNIQUE;")
            except Exception:
                pass
            try:
                session.run("DROP CONSTRAINT ON (h:Host) ASSERT h.hostname IS UNIQUE;")
            except Exception:
                pass
            try:
                session.run("DROP CONSTRAINT ON (s:Software) ASSERT s.name IS UNIQUE;")
            except Exception:
                pass

            # Verify database is empty
            result = session.run("MATCH (n) RETURN count(n) AS count")
            count = result.single()["count"]
            print(f"Database cleared. Remaining nodes: {count}")
    finally:
        if driver is not None:
            driver.close()

    print("✅ Memgraph database cleared successfully!")

    # Reset sync state
    if os.path.exists(state_file):
        try:
            os.remove(state_file)
            print(f"✅ Sync state ({state_file}) reset successfully!")
        except OSError as e:
            print(f"⚠️  Warning: Failed to delete {state_file}: {e}")
    else:
        print("ℹ️  No sync state found to reset.")

if __name__ == "__main__":
    args = _parse_args()
    clear_memgraph(args.memgraph_uri, assume_yes=args.yes, state_file=args.state_file)