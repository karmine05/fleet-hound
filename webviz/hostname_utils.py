"""Shared hostname-collision disambiguation for graph payloads.

Fleet enrolls physical machines under their OS hostname. The Fleet
default is a collision: an un-renamed Mac is ``mac.lan`` and a freshly
imaged one is often ``hostname.local``. A single team can therefore have
four DISTINCT hosts all named ``mac.lan``.

Every endpoint that builds a node list keyed on ``fleet_host_id`` had
independently re-implemented the same two-step rule:

  1. count how many records in the batch share each hostname,
  2. render ``"<hostname> #<fleet_host_id>"`` only when the count is > 1.

This module is that rule, once. Endpoints call :func:`hostname_counts`
over their raw record list and :func:`disambiguated_display_name` per
node. Both are pure and testable without a database.

Records are expected to expose a ``hostname`` key (Cypher rows aliased
``AS hostname`` or dicts built from them). A ``None`` hostname is
counted as ``None`` — a null-hint bucket, never a collision with real
names — and :func:`disambiguated_display_name` returns the raw (possibly
``None``) value for it.
"""
from __future__ import annotations

from typing import Mapping, Optional, Sequence


def hostname_counts(records: Sequence[Mapping[str, object]]) -> dict:
    """Count how many records in a batch carry each hostname.

    Args:
        records: Host records (dicts or Cypher row mappings) each exposing
            a ``hostname`` key.

    Returns:
        ``{hostname: count}``. A ``None`` hostname accumulates under the
        ``None`` key (a null bucket, deliberately excluded from
        disambiguation by :func:`disambiguated_display_name`).
    """
    counts: dict = {}
    for record in records:
        hostname = record["hostname"]
        counts[hostname] = counts.get(hostname, 0) + 1
    return counts


def disambiguated_display_name(hostname: Optional[str],
                               fleet_host_id: object,
                               counts: Mapping[str, int]) -> object:
    """Display label for one host node in a graph payload.

    Colliding hostnames (``counts[hostname] > 1``) get a stable
    ``"hostname #<fleet_host_id>"`` suffix so ``mac.lan #1229`` and
    ``mac.lan #1367`` read as two machines. Unique hostnames render
    bare. ``None`` hostnames are returned untouched.
    """
    if hostname and counts.get(hostname, 0) > 1:
        return f"{hostname} #{fleet_host_id}"
    return hostname
