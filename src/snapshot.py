"""Graph snapshot writer + diff for Fleet Hound.

Streams the full Memgraph graph (hosts, users, software, USES, INSTALLED_ON)
to a gzipped JSONL file per ETL run. Each node line carries a sha256 hash of
the canonical-JSON of its properties (excluding noisy churn fields like
last_seen / last_categorized) so cross-snapshot property drift can be detected
without diffing whole records.

File layout:
    <out_dir>/<ts>.jsonl.gz       gzipped node + edge stream
    <out_dir>/<ts>.meta.json      cached counts {hosts, users, software, edges}

The writer is read-only with respect to Memgraph and uses the same atomic
temp-then-rename pattern as save_state() in main.py / save_whitelist() in
webviz/app.py to avoid partial files on crash.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from neo4j import GraphDatabase

logger = logging.getLogger(__name__)

# Properties excluded from node hash. These churn on every ETL even when the
# logical node is unchanged, and including them would flood the property-drift
# diff with noise.
#
# For Label nodes (added in v1.27): last_synced_iso, last_label_sync_status,
# consecutive_failures, last_label_sync_error, and host_count all churn on
# every cycle independent of label-definition drift, so they go in the noisy
# set. last_member_hash is also noisy because it changes whenever membership
# changes — but membership churn is tracked through HAS_LABEL edge add/remove
# in the same snapshot, which is the right surface for that drift.
_NOISY_PROPS = {
    "last_seen",
    "last_categorized",
    "last_synced_iso",
    "last_label_sync_status",
    "consecutive_failures",
    "last_label_sync_error",
    "host_count",
    "last_member_hash",
    "last_members_compressed",
}

# Retention is age-driven, not count-driven. The drift/changelog UI lets an
# operator diff any two retained snapshots, so history must reach back far
# enough to answer "what changed last week" — not just the last few hours.
#
# The old count-only cap of 30 silently truncated history to ~15h at the
# default 30-min OODA cadence (30 snapshots × 30 min), which is why the UI
# only ever showed ~last-day data. We now keep snapshots up to RETAIN_DAYS old
# and only fall back to a count cap as a disk-bound safety valve for very high
# cadences. Both are env-overridable so ops can tune without a code change.
_RETAIN_DAYS_DEFAULT = int(os.environ.get("SNAPSHOT_RETAIN_DAYS", "30"))
# Safety cap on total retained files. Generous so age is the effective limit
# at any sane cadence (30 days @ 30-min cadence = 1440 files < 5000).
_RETAIN_DEFAULT = int(os.environ.get("SNAPSHOT_RETAIN_MAX", "5000"))


def _node_hash(props: dict) -> str:
    filtered = {k: v for k, v in props.items() if k not in _NOISY_PROPS}
    canonical = json.dumps(filtered, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _typed_id(kind: str, name) -> str:
    return f"{kind}_{name}"


def _coerce_props(record_keys, record) -> dict:
    """Memgraph returns Records; convert to a plain dict, skipping None values."""
    out = {}
    for key in record_keys:
        val = record.get(key)
        if val is None:
            continue
        out[key] = val
    return out


def _stream_graph(driver) -> Tuple[List[dict], List[dict], dict]:
    """Pull the full graph as (lines, edge_count_by_label_dict).

    Returns a tuple of (json_lines, counts) where json_lines are dicts ready
    to be JSON-encoded and counts is {hosts, users, software, labels, edges}.
    """
    lines: List[dict] = []
    counts = {"hosts": 0, "users": 0, "software": 0, "labels": 0, "edges": 0}

    with driver.session() as session:
        # --- Hosts ---
        # Node identity is keyed on fleet_host_id to match the live graph
        # endpoints (/api/graph, /api/correlate all use `host_<fleet_host_id>`).
        # Keying on the (mutable, non-unique) hostname would (a) collide two
        # distinct hosts that share a display name — now likely since the
        # display label is Fleet's "computer name" — silently dropping one
        # from the diff, and (b) break the changelog "View on graph" jump,
        # which posts the node id to /api/correlate (rejects non-fleet_host_id
        # ids). hostname stays in props so a rename surfaces as property drift.
        host_keys = ["hostname", "os_version", "platform", "ip", "last_seen",
                     "team_id", "team_name"]
        host_q = """
            MATCH (h:Host)
            RETURN h.fleet_host_id AS fleet_host_id, h.hostname AS hostname,
                   h.os_version AS os_version,
                   h.platform AS platform, h.ip AS ip,
                   h.last_seen AS last_seen, h.team_id AS team_id,
                   h.team_name AS team_name
        """
        for rec in session.run(host_q):
            fleet_host_id = rec["fleet_host_id"]
            if fleet_host_id is None:
                continue
            props = _coerce_props(host_keys, rec)
            lines.append({
                "type": "host",
                "id": _typed_id("host", fleet_host_id),
                "props": props,
                "hash": _node_hash(props),
            })
            counts["hosts"] += 1

        # --- Users ---
        user_keys = ["username", "email", "fullname"]
        user_q = """
            MATCH (u:User)
            RETURN u.username AS username, u.email AS email, u.fullname AS fullname
        """
        for rec in session.run(user_q):
            username = rec["username"]
            if not username:
                continue
            props = _coerce_props(user_keys, rec)
            lines.append({
                "type": "user",
                "id": _typed_id("user", username),
                "props": props,
                "hash": _node_hash(props),
            })
            counts["users"] += 1

        # --- Software ---
        sw_keys = ["name", "last_version", "category", "wikidata_description",
                   "last_categorized", "sources"]
        sw_q = """
            MATCH (s:Software)
            RETURN s.name AS name, s.last_version AS last_version,
                   s.category AS category,
                   s.wikidata_description AS wikidata_description,
                   s.last_categorized AS last_categorized,
                   s.sources AS sources
        """
        for rec in session.run(sw_q):
            name = rec["name"]
            if not name:
                continue
            props = _coerce_props(sw_keys, rec)
            lines.append({
                "type": "software",
                "id": _typed_id("software", name),
                "props": props,
                "hash": _node_hash(props),
            })
            counts["software"] += 1

        # --- Labels (added v1.27 — see plan section 1A) ---
        label_keys = ["fleet_id", "name", "description", "label_type",
                      "membership_type", "query"]
        label_q = """
            MATCH (l:Label)
            RETURN l.fleet_id AS fleet_id, l.name AS name,
                   l.description AS description,
                   l.label_type AS label_type,
                   l.membership_type AS membership_type,
                   l.query AS query
        """
        for rec in session.run(label_q):
            fleet_id = rec["fleet_id"]
            if fleet_id is None:
                continue
            props = _coerce_props(label_keys, rec)
            lines.append({
                "type": "label",
                "id": _typed_id("label", fleet_id),
                "props": props,
                "hash": _node_hash(props),
            })
            counts["labels"] += 1

        # --- Edges: HAS_LABEL (Host -> Label) ---
        # Host endpoint keyed on fleet_host_id to match the host node id above.
        has_label_q = """
            MATCH (h:Host)-[:HAS_LABEL]->(l:Label)
            RETURN h.fleet_host_id AS hfid, l.fleet_id AS lfid
        """
        for rec in session.run(has_label_q):
            if rec["hfid"] is None or rec["lfid"] is None:
                continue
            lines.append({
                "type": "edge",
                "label": "HAS_LABEL",
                "from": _typed_id("host", rec["hfid"]),
                "to": _typed_id("label", rec["lfid"]),
            })
            counts["edges"] += 1

        # --- Edges: USES (User -> Host) ---
        uses_q = """
            MATCH (u:User)-[:USES]->(h:Host)
            RETURN u.username AS uname, h.fleet_host_id AS hfid
        """
        for rec in session.run(uses_q):
            if not rec["uname"] or rec["hfid"] is None:
                continue
            lines.append({
                "type": "edge",
                "label": "USES",
                "from": _typed_id("user", rec["uname"]),
                "to": _typed_id("host", rec["hfid"]),
            })
            counts["edges"] += 1

        # --- Edges: INSTALLED_ON (Software -> Host) ---
        inst_q = """
            MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
            RETURN s.name AS sname, h.fleet_host_id AS hfid
        """
        for rec in session.run(inst_q):
            if not rec["sname"] or rec["hfid"] is None:
                continue
            lines.append({
                "type": "edge",
                "label": "INSTALLED_ON",
                "from": _typed_id("software", rec["sname"]),
                "to": _typed_id("host", rec["hfid"]),
            })
            counts["edges"] += 1

    return lines, counts


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _safe_ts(ts: str) -> str:
    """Sanitize a timestamp into a filename-safe slug. Keeps lexicographic order."""
    return ts.replace(":", "").replace(".", "-").replace("+", "p")


def write_snapshot(memgraph_uri: str, ts: str, out_dir: Path,
                   *, auth=None, retain: int = _RETAIN_DEFAULT,
                   retain_days: int = _RETAIN_DAYS_DEFAULT) -> Path:
    """Write a snapshot for the full graph state.

    Args:
        memgraph_uri: Bolt URI.
        ts: ISO timestamp string (becomes file slug).
        out_dir: directory to write into (created if missing).
        auth: optional (user, pwd) Bolt auth tuple.
        retain: hard cap on retained snapshot files (disk-bound safety valve).
            <= 0 disables the count cap.
        retain_days: keep snapshots written within this many days; older ones
            are pruned. <= 0 disables age-based pruning. This is the primary
            retention control — `retain` only kicks in when the file count
            still exceeds the cap after age pruning.

    Returns the path to the written .jsonl.gz file.
    """
    out_dir = Path(out_dir)
    slug = _safe_ts(ts)
    snap_path = out_dir / f"{slug}.jsonl.gz"
    meta_path = out_dir / f"{slug}.meta.json"

    driver = GraphDatabase.driver(memgraph_uri, auth=auth)
    try:
        lines, counts = _stream_graph(driver)
    finally:
        driver.close()

    buf = b""
    chunks = []
    for entry in lines:
        chunks.append(json.dumps(entry, separators=(",", ":"), default=str).encode("utf-8"))
    buf = b"\n".join(chunks)
    if buf:
        buf += b"\n"
    gz = gzip.compress(buf, compresslevel=6)

    _atomic_write_bytes(snap_path, gz)
    meta = {"ts": ts, **counts}
    _atomic_write_bytes(meta_path, json.dumps(meta, indent=2).encode("utf-8"))

    _prune_old(out_dir, retain=retain, retain_days=retain_days)

    logger.info(
        "snapshot written: %s (%d hosts, %d users, %d software, %d labels, %d edges)",
        snap_path, counts["hosts"], counts["users"],
        counts["software"], counts.get("labels", 0), counts["edges"],
    )
    return snap_path


def _drop_snapshot(out_dir: Path, gz_path: Path) -> None:
    """Unlink a snapshot's .jsonl.gz and its sibling .meta.json."""
    slug = gz_path.name.removesuffix(".jsonl.gz")
    meta_path = out_dir / f"{slug}.meta.json"
    for p in (gz_path, meta_path):
        try:
            p.unlink()
        except OSError:
            pass


def _prune_old(out_dir: Path, *, retain: int,
               retain_days: int = _RETAIN_DAYS_DEFAULT) -> None:
    """Prune snapshots: age horizon first, then a count cap as a safety valve.

    Age pruning uses file mtime (≈ write time, since each snapshot is written
    fresh and never rewritten). Slugs sort lexicographically by ISO ts, so the
    count-cap pass keeps the newest `retain` files.
    """
    try:
        gz = sorted(out_dir.glob("*.jsonl.gz"))
    except OSError:
        return

    # --- Age horizon (primary control) ---
    if retain_days > 0:
        cutoff = time.time() - (retain_days * 24 * 60 * 60)
        survivors = []
        for p in gz:
            try:
                mtime = p.stat().st_mtime
            except OSError:
                # Can't stat — keep it rather than risk deleting live data.
                survivors.append(p)
                continue
            if mtime < cutoff:
                _drop_snapshot(out_dir, p)
            else:
                survivors.append(p)
        gz = survivors

    # --- Count cap (disk-bound safety valve) ---
    if retain > 0 and len(gz) > retain:
        for old in gz[:-retain]:
            _drop_snapshot(out_dir, old)


def list_snapshots(out_dir: Path) -> List[dict]:
    """Return [{ts, slug, path, hosts, users, software, edges}] newest first."""
    out_dir = Path(out_dir)
    if not out_dir.is_dir():
        return []
    items = []
    for gz in sorted(out_dir.glob("*.jsonl.gz")):
        slug = gz.name.removesuffix(".jsonl.gz")
        meta_path = out_dir / f"{slug}.meta.json"
        meta = {}
        if meta_path.exists():
            try:
                with open(meta_path, "r", encoding="utf-8") as fh:
                    meta = json.load(fh)
            except (OSError, json.JSONDecodeError):
                meta = {}
        items.append({
            "ts": meta.get("ts", slug),
            "slug": slug,
            "path": str(gz),
            "hosts": int(meta.get("hosts", 0)),
            "users": int(meta.get("users", 0)),
            "software": int(meta.get("software", 0)),
            "labels": int(meta.get("labels", 0)),
            "edges": int(meta.get("edges", 0)),
        })
    items.sort(key=lambda x: x["ts"], reverse=True)
    return items


def _read_snapshot(path: Path) -> Tuple[Dict[str, dict], List[dict]]:
    """Return ({id: node_record}, [edge_record]) from a .jsonl.gz file."""
    nodes: Dict[str, dict] = {}
    edges: List[dict] = []
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("type") == "edge":
                edges.append(entry)
            else:
                nid = entry.get("id")
                if nid:
                    nodes[nid] = entry
    return nodes, edges


def _edge_key(edge: dict) -> str:
    return f"{edge.get('label', '')}::{edge.get('from', '')}::{edge.get('to', '')}"


def diff_snapshots(a_path: Path, b_path: Path) -> dict:
    """Compute diff a -> b. a is the older snapshot, b the newer.

    Returns:
        {
          "added":   {"hosts":[id..], "users":[..], "software":[..], "edges":[edge..]},
          "removed": {... same shape ...},
          "changed": [{id, type, props_changed: {prop: {old, new}}}]
        }
    """
    a_nodes, a_edges = _read_snapshot(Path(a_path))
    b_nodes, b_edges = _read_snapshot(Path(b_path))

    added: Dict[str, list] = {"hosts": [], "users": [], "software": [], "edges": []}
    removed: Dict[str, list] = {"hosts": [], "users": [], "software": [], "edges": []}
    changed: List[dict] = []

    for nid, entry in b_nodes.items():
        if nid not in a_nodes:
            bucket = entry.get("type", "") + "s"
            if bucket in added:
                added[bucket].append(nid)
        else:
            old = a_nodes[nid]
            if old.get("hash") != entry.get("hash"):
                old_props = old.get("props", {}) or {}
                new_props = entry.get("props", {}) or {}
                drift = {}
                keys = set(old_props.keys()) | set(new_props.keys())
                for k in keys:
                    if k in _NOISY_PROPS:
                        continue
                    if old_props.get(k) != new_props.get(k):
                        drift[k] = {"old": old_props.get(k), "new": new_props.get(k)}
                if drift:
                    changed.append({
                        "id": nid,
                        "type": entry.get("type"),
                        "props_changed": drift,
                    })

    for nid, entry in a_nodes.items():
        if nid not in b_nodes:
            bucket = entry.get("type", "") + "s"
            if bucket in removed:
                removed[bucket].append(nid)

    a_edge_keys = {_edge_key(e): e for e in a_edges}
    b_edge_keys = {_edge_key(e): e for e in b_edges}
    for k, e in b_edge_keys.items():
        if k not in a_edge_keys:
            added["edges"].append({"label": e["label"], "from": e["from"], "to": e["to"]})
    for k, e in a_edge_keys.items():
        if k not in b_edge_keys:
            removed["edges"].append({"label": e["label"], "from": e["from"], "to": e["to"]})

    return {"added": added, "removed": removed, "changed": changed}
