#!/usr/bin/env python3
"""One-shot consolidation of fragmented :Software extension nodes.

If the same store ID (extension_key) was ever ingested under more than one
name (clean display name from one host, path-shaped name from another), the
name-keyed MERGE produced one node per name. This script folds each group
back into a single canonical node:

  * canonical name  = non-path-shaped, shortest, then lexicographic — the
                      exact same rule the ingestion path uses, so the two
                      can never disagree
  * versions        = union of all dups
  * scalar props    = coalesced (canonical node's value wins; dups fill gaps)
                      with last_version / first_version merged by version key
  * INSTALLED_ON    = edges re-pointed at the canonical node (MERGE per host,
                      existing edge values win, earliest first_seen kept)
  * dup nodes       = DETACH DELETE

Idempotent and re-runnable: with no fragments it does nothing. The
long-term fix (unique constraint on extension_key + keying MERGE on it)
supersedes this; keep the script around until that lands.

Usage:
    python3 consolidate_extensions.py [--uri bolt://localhost:7687] [--dry-run]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neo4j import GraphDatabase  # noqa: E402

from src.ingestion import _memgraph_auth, _is_pathy_name, _version_key  # noqa: E402

# Scalar props folded into the canonical node (canon wins, dup fills gaps).
COALESCE_PROPS = [
    "publisher", "publisher_reputable", "known_bad", "store_status",
    "store_url", "store_category", "display_name", "browser", "store",
    "extension_id", "manifest_version", "rating", "rating_count",
    "install_users", "latest_version", "risk_score", "risk_band",
    "capability_score", "trust_score", "threat_score", "exposure_score",
    "risk_signals_json", "kind", "is_builtin", "generated_cpe", "vendor",
    "signature_information_json", "vulnerabilities_json",
]


def pick_canonical(names):
    """Deterministic canonical name — must mirror ingestion exactly."""
    names = {str(n) for n in names if n}
    if not names:
        return None
    clean = [n for n in names if not _is_pathy_name(n)]
    pool = clean if clean else names
    return sorted(pool, key=lambda n: (len(n), n))[0]


def _merge_scalar_props(canon_p: dict, dup_p: dict) -> dict:
    """Return the SET-payload for the canonical node after absorbing one dup."""
    payload = {}
    for prop in COALESCE_PROPS:
        if canon_p.get(prop) is None and dup_p.get(prop) is not None:
            payload[prop] = dup_p[prop]
    # first/last version: min/max by version key, never demote.
    cands_lv = [v for v in (canon_p.get("last_version"), dup_p.get("last_version")) if v]
    if cands_lv and (not canon_p.get("last_version") or
                     max(cands_lv, key=_version_key) != canon_p.get("last_version")):
        payload["last_version"] = max(cands_lv, key=_version_key)
    cands_fv = [v for v in (canon_p.get("first_version"), dup_p.get("first_version")) if v]
    if cands_fv and (not canon_p.get("first_version") or
                     min(cands_fv, key=_version_key) != canon_p.get("first_version")):
        payload["first_version"] = min(cands_fv, key=_version_key)
    # seen stamps: ISO strings compare lexically.
    cands_fs = [v for v in (canon_p.get("first_seen"), dup_p.get("first_seen")) if v]
    if cands_fs:
        payload["first_seen"] = min(cands_fs)
    cands_ls = [v for v in (canon_p.get("last_seen"), dup_p.get("last_seen")) if v]
    if cands_ls:
        payload["last_seen"] = max(cands_ls)
    # vulnerability_count / max_cvss: worst observed wins.
    for prop, fn in (("vulnerability_count", max), ("max_cvss", max)):
        cands = [v for v in (canon_p.get(prop), dup_p.get(prop)) if v is not None]
        if cands and (canon_p.get(prop) is None or fn(cands) != canon_p.get(prop)):
            payload[prop] = fn(cands)
    return payload


def consolidate(driver, dry_run: bool) -> None:
    with driver.session() as s:
        keys = [r["k"] for r in s.run(
            "MATCH (x:Software) WHERE x.extension_key IS NOT NULL "
            "WITH x.extension_key AS k, count(*) AS c "
            "WHERE c > 1 RETURN k ORDER BY k"
        )]
        if not keys:
            print("no fragmented extension keys — nothing to do")
            return

        print(f"fragmented keys: {len(keys)}")
        for k in keys:
            nodes = [
                {"name": r["name"], "eid": r["eid"], "p": r["p"]}
                for r in s.run(
                    "MATCH (x:Software) WHERE x.extension_key = $k "
                    "RETURN x.name AS name, elementId(x) AS eid, properties(x) AS p",
                    k=k,
                )
            ]
            canon_name = pick_canonical(n["name"] for n in nodes)
            canon = next(n for n in nodes if n["name"] == canon_name)
            dups = [n for n in nodes if n["eid"] != canon["eid"]]
            print(f"\n{k}: {len(nodes)} nodes -> canonical {canon_name!r}")
            for d in dups:
                print(f"  absorb {d['name']!r}")

            if dry_run:
                continue

            # 1. Re-point every INSTALLED_ON edge at the canonical node.
            for d in dups:
                s.run("""
                    MATCH (dup:Software) WHERE elementId(dup) = $eid
                    MATCH (dup)-[r:INSTALLED_ON]->(h:Host)
                    MATCH (canon:Software {name: $canon})
                    MERGE (canon)-[nr:INSTALLED_ON]->(h)
                    ON CREATE SET
                        nr.first_seen = r.first_seen
                    SET nr.version = coalesce(nr.version, r.version),
                        nr.source = coalesce(nr.source, r.source),
                        nr.browser = coalesce(nr.browser, r.browser),
                        nr.extension_for = coalesce(nr.extension_for, r.extension_for),
                        nr.installed_path = coalesce(nr.installed_path, r.installed_path),
                        nr.last_seen = CASE
                            WHEN r.last_seen IS NOT NULL AND (nr.last_seen IS NULL OR r.last_seen > nr.last_seen)
                            THEN r.last_seen ELSE nr.last_seen END,
                        nr.first_seen = CASE
                            WHEN r.first_seen IS NOT NULL AND (nr.first_seen IS NULL OR r.first_seen < nr.first_seen)
                            THEN r.first_seen ELSE nr.first_seen END
                    DELETE r
                """, eid=d["eid"], canon=canon_name)

            # 2. Absorb versions + scalar props.
            for d in dups:
                s.run("""
                    MATCH (canon:Software {name: $canon}), (dup:Software)
                    WHERE elementId(dup) = $eid
                    WITH canon, dup
                    WHERE coalesce(dup.versions, []) <> []
                    SET canon.versions = coalesce(canon.versions, []) + [
                        v IN coalesce(dup.versions, []) WHERE NOT v IN coalesce(canon.versions, [])
                    ]
                """, eid=d["eid"], canon=canon_name)
                payload = _merge_scalar_props(canon["p"], d["p"])
                if payload:
                    s.run(
                        "MATCH (canon:Software {name: $canon}) SET canon += $props",
                        canon=canon_name, props=payload,
                    )
                    # canon["p"] is stale after each SET; refresh for the
                    # next dup's min/max comparisons.
                    canon["p"] = s.run(
                        "MATCH (x:Software {name: $canon}) RETURN properties(x) AS p",
                        canon=canon_name,
                    ).single()["p"]

            # 3. Delete the duplicates.
            for d in dups:
                s.run(
                    "MATCH (dup:Software) WHERE elementId(dup) = $eid DETACH DELETE dup",
                    eid=d["eid"],
                )

    if dry_run:
        print(f"\ndry-run: {len(keys)} key(s) would be consolidated — no changes made")
        return
    with driver.session() as s:
        left = s.run(
            "MATCH (x:Software) WHERE x.extension_key IS NOT NULL "
            "WITH x.extension_key AS k, count(*) AS c WHERE c > 1 RETURN count(k) AS n"
        ).single()["n"]
    print(f"\ndone — fragmented keys remaining: {left}")
    assert left == 0, "consolidation incomplete"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--uri", default=os.environ.get("MEMGRAPH_URI", "bolt://localhost:7687"))
    ap.add_argument("--dry-run", action="store_true", help="report only, change nothing")
    args = ap.parse_args()

    driver = GraphDatabase.driver(args.uri, auth=_memgraph_auth())
    try:
        consolidate(driver, dry_run=args.dry_run)
    finally:
        driver.close()


if __name__ == "__main__":
    main()
