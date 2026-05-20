"""Enrich Software nodes in Memgraph with Wikidata categories/description.

Production-grade defenses against Wikidata's flaky free SPARQL endpoint:
- defensive network timeouts + rate-limit handling
- safe SPARQL literal escaping
- graph-side failure cache: track per-software attempt count + last-try
  timestamp so we don't re-hit Wikidata for names it already 404'd on
  (the May 2026 fix for the timeout storm — Wikidata is unreliable enough
  that retrying every cycle wastes 90%+ of the call budget on names with
  zero entries)
- adaptive backoff: when consecutive failures pile up, pause longer between
  attempts so we don't keep getting rate-limited
- ensures DB driver is closed
"""

import argparse
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

import requests
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, SessionExpired, TransientError

logger = logging.getLogger(__name__)

# Shadow IT filter primitives. Enrichment only targets software that COULD
# plausibly be Shadow IT — never OS plumbing, dev-language transitive deps,
# CUDA stacks, or browser extensions. Pre-2026-05-07 the candidate query
# selected ANY uncategorized software, which meant every ETL cycle hammered
# Wikidata with 250 lookups for items it had zero chance of finding (NVIDIA
# Container, libnvblas12, Microsoft Visual C++ ..., etc).
from src.shadow_it_filter import (
    USER_APP_SOURCES,
    compute_per_platform_thresholds,
    get_outlier_pct,
    has_user_app_source,
    is_system_package,
)
from src.software_catalog import catalog_size as _catalog_size
from src.software_catalog import lookup as catalog_lookup


# Load environment variables (simplified loader)
def load_env(env_path='.env'):
    """Minimal .env loader. Strips inline comments — supports lines like:
        FOO=bar         # explanation
    and quoted values with comments after the close quote.
    """
    env_vars = {}
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' not in line:
                    continue
                k, v = line.split('=', 1)
                v = v.strip()
                # Quoted-value parsing: allow `KEY="value with # in it"`.
                # Anything OUTSIDE the quotes after the close quote is a
                # trailing comment.
                if v and v[0] in ('"', "'"):
                    quote = v[0]
                    end = v.find(quote, 1)
                    if end != -1:
                        v = v[1:end]
                    else:
                        v = v[1:]
                else:
                    # Unquoted: strip trailing inline comment.
                    if '#' in v:
                        v = v.split('#', 1)[0]
                    v = v.strip()
                env_vars[k.strip()] = v
    return env_vars

ENV = load_env()
MEMGRAPH_URI = os.environ.get('MEMGRAPH_URI') or ENV.get('MEMGRAPH_URI', 'bolt://localhost:7687')
USER_AGENT = 'FleetHoundSoftwareCategorizer/1.0 (https://github.com/fleethound)'

# Wikipedia REST API — much more reliable than Wikidata SPARQL. Returns
# title + description + extract for any encyclopedia entry. ~100-300ms typical
# response, generous rate limits, and excellent uptime.
WIKIPEDIA_REST_URL = "https://en.wikipedia.org/api/rest_v1/page/summary/{title}"

# Failure-cache cooldown. After a software fails enrichment (HTTP 404 / no
# entry), don't re-query for this many days. Reduces wasted API calls every
# ETL cycle for the long tail of software Wikipedia doesn't cover.
def _read_env_int(key: str, default: int) -> int:
    """Read an int from env or .env. Strips inline comments and falls back
    to default on any parse failure (so a malformed .env line doesn't
    crash startup)."""
    raw = (os.environ.get(key) or ENV.get(key) or "").strip()
    if not raw:
        return default
    # Defense in depth: even after load_env's comment-strip, the raw os.environ
    # value could carry whitespace/comments if the user exported it directly.
    if '#' in raw:
        raw = raw.split('#', 1)[0].strip()
    try:
        return int(raw)
    except ValueError:
        logger.warning("env var %s=%r is not a valid int; using default=%d", key, raw, default)
        return default


ENRICH_FAILURE_COOLDOWN_DAYS = _read_env_int('ENRICH_FAILURE_COOLDOWN_DAYS', 7)

# Adaptive backoff thresholds. After this many consecutive timeouts/errors
# on Wikipedia, increase the inter-request sleep so we stop hammering. Resets
# on the first success.
ADAPTIVE_BACKOFF_TRIGGER = 5
ADAPTIVE_BACKOFF_SECONDS = 5.0


class EnrichResult:
    """Three-state outcome from any enrichment lookup (catalog or Wikipedia)."""
    HIT = "hit"              # found categories + description
    MISS = "miss"            # query succeeded but no entry exists (Wikipedia 404)
    TRANSIENT = "transient"  # network timeout / 5xx — try again next cycle


# Heuristic: turn a Wikipedia description/extract into a category list.
# Wikipedia REST returns natural-language descriptions; we keyword-match into
# our 12-category taxonomy (matches the curated catalog above). This keeps
# the schema consistent — every enriched Software gets a `category` array
# even when the source was Wikipedia rather than the local catalog.
_KEYWORD_TO_CATEGORY = [
    (("password manager",), ["Security Tool", "Password Manager"]),
    (("vpn", "virtual private network"), ["Privacy Tool", "VPN"]),
    (("antivirus", "anti-virus", "endpoint detection"), ["Security Tool", "Antivirus"]),
    (("encryption tool", "cryptographic"), ["Security Tool"]),
    (("ssh client", "telnet client"), ["Remote Access", "SSH Client"]),
    (("remote desktop", "remote control software"), ["Remote Access", "Remote Desktop"]),
    (("web browser", "browser"), ["Browser"]),
    (("instant messaging", "messaging app", "messenger"), ["Communication", "Messaging"]),
    (("video conferencing", "video call", "video chat"), ["Communication", "Video Conferencing"]),
    (("voice chat", "voice over ip", "voip"), ["Communication", "Voice Chat"]),
    (("team collaboration",), ["Communication", "Team Chat"]),
    (("note-taking", "note taking"), ["Productivity", "Notes"]),
    (("task management", "to-do list", "todo"), ["Productivity", "Task Management"]),
    (("project management", "kanban"), ["Productivity", "Project Management"]),
    (("office suite", "word processor", "spreadsheet"), ["Productivity", "Office Suite"]),
    (("pdf reader", "pdf viewer"), ["Productivity", "PDF Reader"]),
    (("source-code editor", "code editor", "text editor for code"), ["Developer Tool", "Editor"]),
    (("integrated development environment", "ide"), ["Developer Tool", "IDE"]),
    (("api client", "api testing"), ["Developer Tool", "API Client"]),
    (("git", "version control"), ["Developer Tool", "Version Control"]),
    (("database client", "database manager", "sql client"), ["Developer Tool", "Database Client"]),
    (("container runtime", "containerization"), ["Developer Tool", "Container Runtime"]),
    (("javascript runtime",), ["Developer Tool", "Runtime"]),
    (("file archiver", "archive manager"), ["Utility", "Archive Manager"]),
    (("ftp client", "sftp client"), ["Utility", "FTP Client"]),
    (("bittorrent client",), ["Utility", "BitTorrent"]),
    (("clipboard manager",), ["Utility", "Clipboard"]),
    (("window manager",), ["Utility", "Window Manager"]),
    (("application launcher",), ["Utility", "Launcher"]),
    (("cloud storage", "file hosting"), ["Cloud Storage"]),
    (("media player",), ["Media Player"]),
    (("music streaming",), ["Media", "Music Streaming"]),
    (("video editor", "video editing"), ["Media", "Video Editor"]),
    (("audio editor", "digital audio workstation"), ["Media", "Audio Editor"]),
    (("streaming software", "broadcast software"), ["Media", "Streaming"]),
    (("video transcoder", "video converter"), ["Media", "Video Encoder"]),
    (("vector graphics", "vector editor"), ["Design", "Vector Editor"]),
    (("raster graphics", "image editor", "image editing"), ["Design", "Image Editor"]),
    (("3d modeling", "3d modelling", "3d graphics"), ["Design", "3D Modeling"]),
    (("interface design", "ui design", "ux design"), ["Design", "UI Design"]),
    (("digital painting",), ["Design", "Image Editor"]),
    (("cryptocurrency wallet", "crypto wallet"), ["Crypto", "Wallet"]),
    (("digital wallet",), ["Crypto", "Wallet"]),
]


def _keyword_match(keyword: str, text: str) -> bool:
    """Word-boundary match. Prevents 'ide' matching 'consider' and 'git'
    matching 'digital'. Multi-word keywords are matched as a contiguous
    phrase with word boundaries on each end."""
    import re as _re
    pattern = r"\b" + _re.escape(keyword) + r"\b"
    return bool(_re.search(pattern, text))


def infer_categories_from_description(description: str, extract: str = "") -> List[str]:
    """Map a Wikipedia description/extract into our category taxonomy.

    Uses word-boundary matching so short keywords like 'ide', 'git', 'vpn',
    'ssh' don't false-match inside longer words ('consider', 'digital',
    'description').
    """
    text = " ".join(s for s in (description or "", extract or "") if s).lower()
    if not text:
        return ["Application"]
    matched = []
    for keywords, cats in _KEYWORD_TO_CATEGORY:
        if any(_keyword_match(k, text) for k in keywords):
            for c in cats:
                if c not in matched:
                    matched.append(c)
    return matched if matched else ["Application"]


def get_software_info(software_name: str, http: requests.Session) -> Tuple[str, Optional[Tuple[List[str], Optional[str]]]]:
    """Resolve software metadata via the catalog → Wikipedia chain.

    Returns (status, payload):
      HIT       → payload is (categories, description); persist to graph
      MISS      → payload is None; mark as 'tried, no entry' for cooldown
      TRANSIENT → payload is None; don't burn the MISS cooldown — retry next cycle
    """
    # Stage 1: local catalog. O(1) for the common ~100 Shadow IT apps.
    cached = catalog_lookup(software_name)
    if cached is not None:
        return EnrichResult.HIT, cached

    # Stage 2: Wikipedia REST API. Far more reliable than Wikidata SPARQL.
    title = requests.utils.quote(software_name.strip(), safe='')
    url = WIKIPEDIA_REST_URL.format(title=title)
    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'application/json',
    }
    try:
        response = http.get(url, headers=headers, timeout=10)
    except (requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.ChunkedEncodingError) as e:
        logger.warning("wikipedia transient error name=%r: %s", software_name, e)
        return EnrichResult.TRANSIENT, None
    except Exception as e:
        logger.warning("wikipedia unexpected error name=%r: %s", software_name, e)
        return EnrichResult.TRANSIENT, None

    if response.status_code == 404:
        # Not in Wikipedia — definite miss; cache to skip future cycles.
        return EnrichResult.MISS, None
    if response.status_code == 429:
        retry_after = response.headers.get('Retry-After')
        wait_s = int(retry_after) if (retry_after and retry_after.isdigit()) else 30
        logger.warning("rate limited by wikipedia; waiting %ds", wait_s)
        time.sleep(wait_s)
        return EnrichResult.TRANSIENT, None
    if response.status_code >= 500:
        return EnrichResult.TRANSIENT, None
    if response.status_code != 200:
        # 4xx other than 404/429 — treat as MISS (won't get better with retry).
        return EnrichResult.MISS, None

    try:
        data = response.json()
    except ValueError:
        return EnrichResult.TRANSIENT, None

    page_type = data.get('type', '')
    if page_type == 'disambiguation':
        # Disambig pages aren't useful. Mark MISS so we stop trying — if
        # the operator wants a specific entry they can hand-curate.
        return EnrichResult.MISS, None

    description = data.get('description') or ''
    extract = data.get('extract') or ''
    if not description and not extract:
        return EnrichResult.MISS, None

    categories = infer_categories_from_description(description, extract)
    short_extract = extract.split('. ')[0] if extract else description
    return EnrichResult.HIT, (categories, short_extract or description)

def run_query_with_retry(session, query, params, max_retries=3):
    for attempt in range(max_retries):
        try:
            session.run(query, **params)
            return True
        except (TransientError, ServiceUnavailable, SessionExpired) as e:
            if attempt < max_retries - 1:
                wait_time = 0.5 * (2 ** attempt)
                time.sleep(wait_time)
            else:
                logger.warning("query failed after %d attempts: %s", max_retries, e)
                return False
    return False

def _memgraph_auth():
    """Resolve MEMGRAPH_USER/MEMGRAPH_PASSWORD (with _FILE indirection) to a Bolt auth tuple."""
    user = os.environ.get("MEMGRAPH_USER", "").strip() or ENV.get("MEMGRAPH_USER", "").strip()
    pwd_file = os.environ.get("MEMGRAPH_PASSWORD_FILE", "").strip() or ENV.get("MEMGRAPH_PASSWORD_FILE", "").strip()
    pwd = ""
    if pwd_file:
        try:
            with open(pwd_file, "r", encoding="utf-8") as fh:
                pwd = fh.read().strip()
        except OSError:
            pwd = ""
    if not pwd:
        pwd = os.environ.get("MEMGRAPH_PASSWORD", "").strip() or ENV.get("MEMGRAPH_PASSWORD", "").strip()
    if user and pwd:
        return (user, pwd)
    return None


def run_categorization(memgraph_uri: str = MEMGRAPH_URI, limit: Optional[int] = 500, target_names=None):
    logger.info("connecting to memgraph uri=%s", memgraph_uri)
    driver = None
    try:
        driver = GraphDatabase.driver(memgraph_uri, auth=_memgraph_auth())
        with driver.session() as session:
            # Test connection
            session.run("RETURN 1")
    except Exception as e:
        if driver is not None:
            driver.close()
        logger.error("could not connect to memgraph: %s", e)
        return

    if target_names:
        preview = ", ".join(target_names[:5]) + ("..." if len(target_names) > 5 else "")
        logger.info("fetching specific software items=%s", preview)
        software_list = target_names
    else:
        # Per-platform Shadow IT outlier scoping (May 2026 — user request).
        # Three-stage filter:
        #   1. Per-platform threshold: software is a candidate ONLY when its
        #      host_count within ITS platform is ≤ max(2, plat_hosts × pct).
        #      pct comes from SHADOW_IT_OUTLIER_PCT env (default 3%).
        #      Per-platform avoids over-flagging rare software on small
        #      platforms and under-flagging on large ones.
        #   2. Source filter: only software whose `sources` intersects
        #      USER_APP_SOURCES (apps/programs/homebrew/chocolatey).
        #   3. Name-pattern filter: surviving names through is_system_package()
        #      to catch Linux distro packages that don't expose a clean
        #      `sources` value but match the OS-plumbing regex.
        # The candidate count drops by 90%+ vs the pre-2026-05-07 query that
        # selected ANY uncategorized software ordered by host_count ASC.
        outlier_pct = get_outlier_pct()
        with driver.session() as session:
            thresholds = compute_per_platform_thresholds(session, outlier_pct)
        limit_label = f"{limit} max" if limit else "ALL"
        logger.info(
            "fetching shadow-IT candidates outlier_pct=%d%% min=2 user_app_sources_only limit=%s",
            int(outlier_pct * 100), limit_label,
        )
        if not thresholds:
            logger.info("no platforms detected; skipping")
            software_list = []
        else:
            thresholds_str = ", ".join(f"{p}={t}" for p, t in sorted(thresholds.items()))
            logger.info("per-platform thresholds %s", thresholds_str)

            # Per-platform query: pull all uncategorized user-app software
            # whose count of hosts ON THAT PLATFORM is at or below threshold.
            # Aggregate across platforms by name (a software name can appear
            # under multiple platforms with different counts; treat the
            # smallest count as authoritative for ordering).
            #
            # Failure-cache filter (May 2026): exclude software that failed
            # enrichment within the last ENRICH_FAILURE_COOLDOWN_DAYS. Without
            # this gate, every ETL cycle re-asks Wikipedia for the same long
            # tail of names that will never have entries. Skip them for a
            # week, then try once more.
            cutoff_iso = (
                datetime.now(timezone.utc)
                - timedelta(days=ENRICH_FAILURE_COOLDOWN_DAYS)
            ).isoformat()
            by_name = {}
            with driver.session() as session:
                for platform, threshold in thresholds.items():
                    result = session.run(
                        """
                        MATCH (s:Software)-[:INSTALLED_ON]->(h:Host {platform: $platform})
                        WHERE s.category IS NULL
                          AND any(src IN coalesce(s.sources, []) WHERE src IN $user_app_sources)
                          AND (s.last_categorization_attempt_iso IS NULL
                               OR s.last_categorization_attempt_iso < $cutoff_iso)
                        WITH s.name AS name,
                             coalesce(s.sources, []) AS sources,
                             coalesce(s.category, []) AS db_categories,
                             count(DISTINCT h) AS host_count
                        WHERE host_count <= $threshold
                        RETURN name, sources, db_categories, host_count
                        ORDER BY host_count ASC
                        """,
                        platform=platform,
                        threshold=threshold,
                        user_app_sources=list(USER_APP_SOURCES),
                        cutoff_iso=cutoff_iso,
                    )
                    for rec in result:
                        name = rec["name"]
                        # Take the lowest host_count across platforms so the
                        # global ordering still surfaces rarest items first.
                        cur = by_name.get(name)
                        if cur is None or rec["host_count"] < cur["host_count"]:
                            by_name[name] = {
                                "name": name,
                                "sources": rec["sources"],
                                "db_categories": rec["db_categories"],
                                "host_count": rec["host_count"],
                                "platform": platform,
                            }

            # Stage 3 — drop system packages that slipped through the source
            # filter (Linux distro packages, MS update bundles, NVIDIA CUDA
            # components). Sort by host_count ASC so rarest items go first.
            sorted_candidates = sorted(
                by_name.values(),
                key=lambda c: c["host_count"],
            )
            software_list = []
            skipped = 0
            for c in sorted_candidates:
                if is_system_package(c["name"], c["db_categories"], c["sources"]):
                    skipped += 1
                    continue
                software_list.append(c["name"])
                if limit and len(software_list) >= limit:
                    break
            logger.info(
                "candidates outliers=%d after_system_filter=%d system_skipped=%d",
                len(by_name), len(software_list), skipped,
            )

    if not software_list:
        logger.info("no software to process")
        return

    total = len(software_list)
    logger.info(
        "processing items=%d catalog_size=%d (unknowns fall through to wikipedia REST)",
        total, _catalog_size(),
    )

    processed = 0
    updated = 0          # successful HIT (catalog or Wikipedia)
    cached_misses = 0    # MISS persisted to graph for cooldown
    transient_skips = 0  # transient errors — no cooldown burn
    catalog_hits = 0     # resolved without any network call
    consecutive_failures = 0
    base_sleep = 0.2

    http = requests.Session()
    log_every = max(1, total // 10)  # ~10 progress lines for any input size
    try:
        with driver.session() as session:
            logger.info("enrichment starting total=%d", total)

            for name in software_list:
                # Catalog hit doesn't even need to mark an attempt — it's
                # synthetic enrichment, not a query.
                catalog_payload = catalog_lookup(name)
                if catalog_payload is not None:
                    cats, desc = catalog_payload
                    success = run_query_with_retry(
                        session,
                        """
                            MATCH (s:Software {name: $name})
                            SET s.category = $category,
                                s.wikidata_description = $desc,
                                s.last_categorized = datetime(),
                                s.last_categorization_attempt_iso = $now_iso,
                                s.categorization_attempts = coalesce(s.categorization_attempts, 0) + 1,
                                s.categorization_source = 'catalog'
                        """,
                        {
                            'name': name, 'category': cats, 'desc': desc,
                            'now_iso': datetime.now(timezone.utc).isoformat(),
                        },
                    )
                    if success:
                        updated += 1
                        catalog_hits += 1
                    consecutive_failures = 0
                    processed += 1
                    if processed % log_every == 0 or processed == total:
                        logger.info(
                            "enriching progress=%d/%d updated=%d catalog=%d",
                            processed, total, updated, catalog_hits,
                        )
                    continue  # no sleep — local lookup costs nothing

                # Stage 2: Wikipedia REST.
                status, payload = get_software_info(name, http)
                now_iso = datetime.now(timezone.utc).isoformat()

                if status == EnrichResult.HIT and payload is not None:
                    cats, desc = payload
                    success = run_query_with_retry(
                        session,
                        """
                            MATCH (s:Software {name: $name})
                            SET s.category = $category,
                                s.wikidata_description = $desc,
                                s.last_categorized = datetime(),
                                s.last_categorization_attempt_iso = $now_iso,
                                s.categorization_attempts = coalesce(s.categorization_attempts, 0) + 1,
                                s.categorization_source = 'wikipedia'
                        """,
                        {'name': name, 'category': cats, 'desc': desc, 'now_iso': now_iso},
                    )
                    if success:
                        updated += 1
                    consecutive_failures = 0

                elif status == EnrichResult.MISS:
                    # Mark attempt so the failure-cache filter excludes this
                    # name from the next ENRICH_FAILURE_COOLDOWN_DAYS cycles.
                    run_query_with_retry(
                        session,
                        """
                            MATCH (s:Software {name: $name})
                            SET s.last_categorization_attempt_iso = $now_iso,
                                s.categorization_attempts = coalesce(s.categorization_attempts, 0) + 1
                        """,
                        {'name': name, 'now_iso': now_iso},
                    )
                    cached_misses += 1
                    consecutive_failures = 0  # MISS isn't a failure to back off on

                else:  # TRANSIENT
                    transient_skips += 1
                    consecutive_failures += 1

                processed += 1
                if processed % log_every == 0 or processed == total:
                    logger.info(
                        "enriching progress=%d/%d hits=%d miss_cached=%d transient=%d",
                        processed, total, updated, cached_misses, transient_skips,
                    )

                # Adaptive backoff. After ADAPTIVE_BACKOFF_TRIGGER consecutive
                # transient failures, sleep longer between requests so we stop
                # hammering an already-struggling endpoint.
                sleep_s = (
                    ADAPTIVE_BACKOFF_SECONDS
                    if consecutive_failures >= ADAPTIVE_BACKOFF_TRIGGER
                    else base_sleep
                )
                time.sleep(sleep_s)
    finally:
        http.close()
        if driver is not None:
            driver.close()

    logger.info(
        "enrichment finished hits=%d catalog=%d wikipedia=%d miss_cached=%d cooldown_days=%d transient=%d",
        updated, catalog_hits, updated - catalog_hits,
        cached_misses, ENRICH_FAILURE_COOLDOWN_DAYS, transient_skips,
    )

if __name__ == "__main__":
    # Stand-alone invocation: set up logging since main.py's basicConfig didn't run.
    # When called from src/etl.py (importing run_categorization), this block is skipped
    # and the inherited root logger config from main.py applies.
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s %(levelname)-7s %(name)s | %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%S',
        )
    parser = argparse.ArgumentParser(description="Enrich software nodes with Wikidata categories.")
    parser.add_argument('--memgraph-uri', default=MEMGRAPH_URI, help="Memgraph Bolt URI (default: from MEMGRAPH_URI or .env)")
    parser.add_argument('--limit', type=int, default=500, help="Maximum items to process (default: 500, use 0 for ALL)")
    parser.add_argument('--names', help="Comma-separated list of specific software names to enrich")
    args = parser.parse_args()
    
    name_list = [n.strip() for n in args.names.split(',')] if args.names else None
    run_categorization(memgraph_uri=args.memgraph_uri, limit=None if args.limit == 0 else args.limit, target_names=name_list)
