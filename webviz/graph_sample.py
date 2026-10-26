"""Degree-ranked graph sampling for the Overview constellation.

Pure functions only — no Flask, no Memgraph — so the sampling rules can be
unit-tested without a database. The dashboard asks for a small, balanced slice
of the graph to draw the hero diagram; drawing all 22k edges there would be
both slow and unreadable.
"""
from __future__ import annotations

from collections import Counter, defaultdict


def _degree_map(nodes: list[dict], links: list[dict]) -> dict[str, int]:
    degree: Counter = Counter()
    for link in links:
        src = link.get("source")
        dst = link.get("target")
        if src is not None:
            degree[src] += 1
        if dst is not None:
            degree[dst] += 1
    for node in nodes:
        nid = node.get("id")
        if nid is not None and nid not in degree:
            degree[nid] = 0
    return dict(degree)


def sample_graph(nodes: list[dict], links: list[dict], limit: int) -> tuple[list[dict], list[dict], dict]:
    """Keep roughly ``limit`` nodes, ranked by degree and balanced by type.

    Balance matters: a pure global top-N would return almost only hosts, and
    the constellation needs hosts, users and software to read as a fleet.
    The quota is split evenly across the types present, with leftover slots
    filled by global degree so a type with spare capacity absorbs the rest.

    Returns ``(nodes, links, meta)`` where ``meta`` reports the totals so the
    UI can caption the diagram honestly ("120 of 3,590 nodes").
    """
    total_nodes = len(nodes)
    total_links = len(links)
    limit = max(1, int(limit))

    if total_nodes <= limit:
        return nodes, links, {
            "sample": False,
            "total_nodes": total_nodes,
            "total_links": total_links,
        }

    degree = _degree_map(nodes, links)

    buckets: dict[str, list[dict]] = defaultdict(list)
    for node in nodes:
        buckets[node.get("type") or "unknown"].append(node)
    for bucket in buckets.values():
        bucket.sort(key=lambda n: (-degree.get(n.get("id"), 0), str(n.get("id"))))

    types = sorted(buckets, key=lambda t: -len(buckets[t]))
    quota = max(1, limit // len(types))

    kept: list[dict] = []
    for t in types:
        kept.extend(buckets[t][:quota])

    if len(kept) < limit:
        chosen = {n.get("id") for n in kept}
        remainder = sorted(
            (n for n in nodes if n.get("id") not in chosen),
            key=lambda n: (-degree.get(n.get("id"), 0), str(n.get("id"))),
        )
        kept.extend(remainder[: limit - len(kept)])

    kept_ids = {n.get("id") for n in kept}
    kept_links = [
        link for link in links
        if link.get("source") in kept_ids and link.get("target") in kept_ids
    ]

    return kept, kept_links, {
        "sample": True,
        "total_nodes": total_nodes,
        "total_links": total_links,
    }
