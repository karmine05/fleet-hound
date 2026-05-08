"""Host-filter Cypher composer (plan section 2A).

Single helper that handles `?team=`, `?platform=`, and multi-label
`?labels=A,B&label_op=AND|OR` query parameters uniformly. Replaces ~20
duplicated `if team_filter != 'all': query += "AND ..."` sites previously
spread across 6 endpoints in webviz/app.py.

API
---

    fragment, params = apply_host_filters(request.args, host_var="h")

`fragment` is a Cypher fragment that ALWAYS begins with " AND " or is the
empty string. It is meant to be appended to an existing WHERE clause. The
caller's typical pattern:

    cypher = f"MATCH (h:Host) WHERE 1=1{fragment} RETURN ..."
    session.run(cypher, **caller_params, **params)

`params` keys are namespaced with the prefix `_flt_` to avoid collision
with caller-supplied parameter names (plan section R6).

Multi-label semantics
---------------------

Both AND and OR use a single size-comprehension pattern that traverses
HAS_LABEL once per row, eliminating the cartesian-product risk that
multiple MATCH clauses would carry:

    AND: size([(h)-[:HAS_LABEL]->(_l:Label) WHERE _l.name IN $names | _l]) = size($names)
    OR:  size([(h)-[:HAS_LABEL]->(_l:Label) WHERE _l.name IN $names | _l]) >= 1

Predictable plan, single traversal, no risk of inflating row count.

Security
--------

`label_op` is whitelist-validated against {"AND", "OR"} (case-insensitive
on input, normalized to upper). Anything else raises FilterValidationError
which the caller turns into HTTP 400. Label NAMES, team_id, and platform
are bound as Cypher parameters — never string-concatenated — so Cypher
injection on those fields is defended at the parametrization layer.
"""
from __future__ import annotations

from typing import Iterable, Mapping, Tuple


_ALLOWED_LABEL_OPS = frozenset({"AND", "OR"})


class FilterValidationError(ValueError):
    """Raised when a query-string filter value is malformed.

    Caller (Flask endpoint) should catch and return HTTP 400 with the
    error message. Message is safe to surface to clients — it never echoes
    the offending value back beyond the parameter name.
    """


def _split_labels(raw: str) -> list:
    """Split a comma-separated `?labels=A,B,C` value into a clean list.

    Drops empty segments (e.g., trailing commas) and leading/trailing
    whitespace per segment. Preserves order for predictable Cypher param
    binding (sorted comparisons happen elsewhere if needed).
    """
    if not raw:
        return []
    return [seg.strip() for seg in raw.split(",") if seg.strip()]


def apply_host_filters(args: Mapping, host_var: str = "h",
                        label_only: bool = False) -> Tuple[str, dict]:
    """Compose Cypher filter fragment + params from request query args.

    Args:
        args: A mapping (typically Flask `request.args`) supporting `.get()`.
        host_var: The Cypher variable bound to the Host node in the caller's
            query (default "h" — change if caller uses a different alias).
        label_only: When True, ONLY emit the label-filter clause (skip
            team/platform). Used by endpoints that already have inline
            team/platform handling and want to bolt on label scoping
            additively without re-implementing their existing filter
            shape. New endpoints should leave this False and use the
            helper for all three filter dimensions.

    Returns:
        (fragment, params): fragment always starts with " AND " or is empty.
        params keys are prefixed with `_flt_`.

    Raises:
        FilterValidationError: if `?label_op` is set to anything other than
            AND/OR (case-insensitive).
    """
    parts: list = []
    params: dict = {}

    if not label_only:
        team = (args.get("team") or "").strip()
        if team and team.lower() != "all":
            parts.append(f"toString({host_var}.team_id) = $_flt_team")
            params["_flt_team"] = team

        platform = (args.get("platform") or "").strip().lower()
        if platform and platform != "all":
            # Mirrors the pre-refactor semantics: case-insensitive substring
            # match so a stored `platform = 'darwin 14.5'` still matches
            # `?platform=darwin`. Endpoints relied on this fuzziness; exact
            # match would break the regression contract.
            parts.append(
                f"toLower({host_var}.platform) CONTAINS toLower($_flt_platform)"
            )
            params["_flt_platform"] = platform

    labels_raw = args.get("labels") or ""
    if labels_raw and labels_raw.strip().lower() != "all":
        names = _split_labels(labels_raw)
        if names:
            label_op_raw = (args.get("label_op") or "AND").strip().upper()
            if label_op_raw not in _ALLOWED_LABEL_OPS:
                raise FilterValidationError(
                    "label_op must be one of: AND, OR (case-insensitive)"
                )
            comparator = "=" if label_op_raw == "AND" else ">="
            rhs = "size($_flt_labels)" if label_op_raw == "AND" else "1"
            parts.append(
                f"size([({host_var})-[:HAS_LABEL]->(_l:Label) "
                f"WHERE _l.name IN $_flt_labels | _l]) {comparator} {rhs}"
            )
            params["_flt_labels"] = names

    if not parts:
        return ("", params)
    fragment = " AND " + " AND ".join(parts)
    return (fragment, params)


def apply_label_filter(args: Mapping, host_var: str = "h") -> Tuple[str, dict]:
    """Convenience: label-only filter fragment.

    Equivalent to apply_host_filters(args, host_var, label_only=True).
    Documented as a separate function so call sites in webviz/app.py read
    clearly: "I'm bolting label support onto an existing endpoint, not
    refactoring its team/platform logic."
    """
    return apply_host_filters(args, host_var=host_var, label_only=True)


def merge_filter_params(caller_params: dict, filter_params: dict) -> dict:
    """Defensive helper that merges caller params with filter params.

    Raises if a caller-supplied key starts with the reserved `_flt_` prefix
    (which would collide with the filter helper's namespace). This exists
    so callers don't accidentally shadow filter params and silently break
    the filter binding.
    """
    for k in caller_params:
        if k.startswith("_flt_"):
            raise FilterValidationError(
                f"Caller param '{k}' uses the reserved _flt_ prefix"
            )
    out = dict(caller_params)
    out.update(filter_params)
    return out


# ---------------------------------------------------------------------------
# Composite scoping (TODO-2): JSON boolean-expression filter language.
# ---------------------------------------------------------------------------
#
# Generalizes apply_host_filters to accept arbitrary boolean expressions
# across team / platform / label dimensions. Goal: queries like
#   (team=5 OR team=7) AND label="Shadow IT" AND NOT platform=darwin
#
# The expression is structured JSON (NOT a parsed string DSL) — eliminates
# Cypher injection vectors at the schema layer. Every leaf value lands in
# Cypher params, never in the query string.
#
# Schema (recursive):
#   Node:    {"op": "AND"|"OR", "children": [<expr>, ...]}
#            {"op": "NOT", "child": <expr>}
#   Leaf:    {"team": "<id>"}            — toString(h.team_id) = $id
#            {"platform": "<name>"}      — toLower(h.platform) CONTAINS toLower($name)
#            {"label": "<name>"}         — host has HAS_LABEL to Label{name}
#
# Validation:
#   - Operators whitelisted to {AND, OR, NOT}
#   - Leaf fields whitelisted to {team, platform, label}
#   - Max recursion depth 6 (defense against pathological nesting)
#   - All values bound as Cypher params; no string interpolation
# ---------------------------------------------------------------------------

_COMPOSITE_ALLOWED_OPS = frozenset({"AND", "OR", "NOT"})
_COMPOSITE_ALLOWED_LEAVES = frozenset({"team", "platform", "label"})
_COMPOSITE_MAX_DEPTH = 6


def apply_composite_filter(expr, host_var: str = "h") -> Tuple[str, dict]:
    """Walk a JSON boolean expression tree → (cypher_fragment, params).

    Args:
        expr: Parsed JSON dict (use json.loads on raw input first).
        host_var: Host node alias in the caller's MATCH.

    Returns:
        (fragment, params): fragment ALWAYS starts with " AND " or is empty.
        Designed to drop into the same `WHERE 1=1<frag>` pattern as
        apply_host_filters. Empty expr (or expr == {}) returns ("", {}).
        params keys are prefixed with `_flt_` and counter-suffixed for
        uniqueness across leaf reuse.

    Raises:
        FilterValidationError on schema violations, unknown ops/fields,
        depth overflow, or empty children lists.
    """
    if expr is None or expr == {}:
        return ("", {})
    if not isinstance(expr, dict):
        raise FilterValidationError("expr must be a JSON object")
    params: dict = {}
    counter = [0]
    body = _composite_node(expr, host_var, params, counter, depth=0)
    return (" AND " + body, params)


def _composite_node(node, host_var: str, params: dict, counter: list, depth: int) -> str:
    if depth > _COMPOSITE_MAX_DEPTH:
        raise FilterValidationError(
            f"expr exceeds max depth {_COMPOSITE_MAX_DEPTH}"
        )
    if not isinstance(node, dict):
        raise FilterValidationError("expr node must be an object")

    # Operator node
    if "op" in node:
        op_raw = node["op"]
        if not isinstance(op_raw, str):
            raise FilterValidationError("op must be a string")
        op = op_raw.upper()
        if op not in _COMPOSITE_ALLOWED_OPS:
            raise FilterValidationError(
                f"op must be one of {sorted(_COMPOSITE_ALLOWED_OPS)}"
            )

        if op == "NOT":
            child = node.get("child")
            if child is None:
                raise FilterValidationError("NOT requires a 'child' field")
            inner = _composite_node(child, host_var, params, counter, depth + 1)
            return f"NOT ({inner})"

        children = node.get("children")
        if not isinstance(children, list) or len(children) == 0:
            raise FilterValidationError(
                f"{op} requires a non-empty 'children' list"
            )
        rendered = [
            _composite_node(c, host_var, params, counter, depth + 1)
            for c in children
        ]
        joiner = " AND " if op == "AND" else " OR "
        return "(" + joiner.join(rendered) + ")"

    # Leaf node — exactly one of the allowed leaf fields must be set.
    leaf_fields = [k for k in node.keys() if k in _COMPOSITE_ALLOWED_LEAVES]
    if len(leaf_fields) == 0:
        raise FilterValidationError(
            f"leaf must contain exactly one of {sorted(_COMPOSITE_ALLOWED_LEAVES)}"
        )
    if len(leaf_fields) > 1:
        raise FilterValidationError(
            f"leaf must contain exactly one field; got {sorted(leaf_fields)}"
        )
    field = leaf_fields[0]
    value = node[field]
    if value is None or (isinstance(value, str) and value == ""):
        raise FilterValidationError(f"{field} value cannot be empty")

    counter[0] += 1
    key = f"_flt_{field}_{counter[0]}"
    if field == "team":
        params[key] = str(value)
        return f"toString({host_var}.team_id) = ${key}"
    if field == "platform":
        params[key] = str(value).lower()
        return f"toLower({host_var}.platform) CONTAINS toLower(${key})"
    # label
    params[key] = str(value)
    return (
        f"size([({host_var})-[:HAS_LABEL]->(_l:Label) "
        f"WHERE _l.name = ${key} | _l]) >= 1"
    )
