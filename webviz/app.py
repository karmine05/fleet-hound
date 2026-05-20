import atexit
import hmac
import ipaddress
import json
import logging
import os
import re
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from neo4j import GraphDatabase
from neo4j.exceptions import AuthError, ClientError, ServiceUnavailable, TransientError

# Host-filter helper (plan section 2A). Single source of truth for the
# `?team=`, `?platform=`, `?labels=A,B&label_op=AND|OR` query-string contract
# previously duplicated across ~6 endpoints. New scoping endpoints should
# import from here rather than recreate the if-platform-then-AND pattern.
from webviz.host_filters import (
    FilterValidationError,
    apply_composite_filter,
    apply_host_filters,
    apply_label_filter,
    merge_filter_params,
)

# Shadow IT filter primitives (shared with categorize_software.py).
# Pre-2026-05-07 these lived inline in this file; extracting to
# src/shadow_it_filter.py let categorize_software.py reuse the same rules
# for enrichment-candidate selection (so Wikidata stops getting hammered
# with system-package lookups it has zero chance of resolving).
from src.shadow_it_filter import (
    DEV_LANGUAGE_SOURCES as _DEV_LANGUAGE_SOURCES,
    EXTENSION_SOURCES as _EXTENSION_SOURCES,
    MIN_OUTLIER_HOSTS as _MIN_OUTLIER_HOSTS,
    SYSTEM_CATEGORY_TOKENS as _SYSTEM_CATEGORY_TOKENS,
    SYSTEM_PACKAGE_RE as _SYSTEM_PACKAGE_RE,
    USER_APP_SOURCES as _USER_APP_SOURCES,
    compute_per_platform_thresholds as _compute_per_platform_thresholds,
    get_outlier_pct as _get_outlier_pct,
    has_user_app_source as _has_user_app_source,  # noqa: F401  (used by future endpoints)
    is_non_app_source as _is_non_app_source,
    is_system_package as _is_system_package,
)

# /app on the container has webviz/, src/, categorize_software.py side by side
# (Dockerfile copies them all). Make /app importable for `from src.snapshot import …`
# and the webviz/ dir importable for bare `from enrich_worker import …` / `ooda_worker`.
_WEBVIZ_DIR = os.path.dirname(os.path.abspath(__file__))
_APP_DIR = os.path.dirname(_WEBVIZ_DIR)
sys.path.insert(0, _APP_DIR)
sys.path.insert(0, _WEBVIZ_DIR)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static')


# ----------------------------------------------------------------------------
# Configuration helpers
# ----------------------------------------------------------------------------
def _resolve_secret(name: str, default: str = "") -> str:
    """Resolve a secret from <NAME>_FILE first, then <NAME>, both whitespace-trimmed.

    Lets operators mount Docker / Kubernetes secrets as files without committing
    plaintext values to env. Both branches trim trailing newlines so a token
    copy-pasted into an env var still compares cleanly against bearer headers.
    """
    file_var = name + "_FILE"
    file_path = os.environ.get(file_var, "").strip()
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                value = fh.read().strip()
                if value:
                    return value
        except OSError as exc:
            logger.warning("Failed to read %s=%s: %s", file_var, file_path, exc)
    return os.environ.get(name, default).strip()


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


# ----------------------------------------------------------------------------
# Memgraph + auth configuration
# ----------------------------------------------------------------------------
MEMGRAPH_URI = os.environ.get("MEMGRAPH_URI", "bolt://memgraph:7687").strip()
MEMGRAPH_USER = _resolve_secret("MEMGRAPH_USER")
MEMGRAPH_PASSWORD = _resolve_secret("MEMGRAPH_PASSWORD")

# Only include raw backend error details in API responses if explicitly enabled.
# Keeps safer defaults for "production-ready" usage while still allowing debugging.
DEBUG_ERROR_DETAILS = _bool_env("WEBVIZ_DEBUG_ERRORS", False)

# API auth posture. Three knobs:
#   WEBVIZ_API_TOKEN              required header value for /api/* (in Authorization
#                                 or X-Api-Token). When set, every API call must
#                                 present it.
#   WEBVIZ_REQUIRE_AUTH=true      refuse to start unless WEBVIZ_API_TOKEN is set.
#   WEBVIZ_ALLOW_ANONYMOUS_READ   when token is unset, opt in to anonymous GETs
#                                 from any client. POST/PUT/DELETE always require
#                                 a token (defense against drive-by writes / CSRF).
# /api/health and / are always reachable so containers and browsers can load.
WEBVIZ_API_TOKEN = _resolve_secret("WEBVIZ_API_TOKEN")
WEBVIZ_REQUIRE_AUTH = _bool_env("WEBVIZ_REQUIRE_AUTH", False)
WEBVIZ_ALLOW_ANONYMOUS_READ = _bool_env("WEBVIZ_ALLOW_ANONYMOUS_READ", False)

if WEBVIZ_REQUIRE_AUTH and not WEBVIZ_API_TOKEN:
    raise SystemExit(
        "WEBVIZ_REQUIRE_AUTH=true but WEBVIZ_API_TOKEN/WEBVIZ_API_TOKEN_FILE is unset. "
        "Set the token or unset WEBVIZ_REQUIRE_AUTH."
    )
if not WEBVIZ_API_TOKEN:
    if WEBVIZ_ALLOW_ANONYMOUS_READ:
        logger.warning(
            "WEBVIZ_API_TOKEN is unset and WEBVIZ_ALLOW_ANONYMOUS_READ=true: "
            "anyone with network access can read /api/* GETs. POST/PUT/DELETE still "
            "require a token. Front this with an authenticated reverse proxy in production."
        )
    else:
        logger.warning(
            "WEBVIZ_API_TOKEN is unset. /api/* GET requests are restricted to loopback "
            "clients. Set WEBVIZ_API_TOKEN for remote access, or "
            "WEBVIZ_ALLOW_ANONYMOUS_READ=true behind a trusted proxy."
        )

# Routes always accessible (no auth required).
PUBLIC_PATHS = {"/api/health", "/"}

# Configuration for persistence
WHITELIST_FILE = '/app/config/whitelist.json'
AUDIT_FILE = '/app/config/audit.log'
SNAPSHOT_DIR = '/app/config/snapshots'

# Enricher worker tunables (read once at import time).
ENRICHER_ENABLED = _bool_env("ENRICHER_ENABLED", True)
try:
    ENRICHER_INTERVAL_SEC = int(os.environ.get("ENRICHER_INTERVAL_SEC", "300"))
except ValueError:
    ENRICHER_INTERVAL_SEC = 300
try:
    ENRICHER_BATCH_SIZE = int(os.environ.get("ENRICHER_BATCH_SIZE", "25"))
except ValueError:
    ENRICHER_BATCH_SIZE = 25
ENRICHER_LOCK_PATH = os.environ.get("ENRICHER_LOCK_PATH", "/tmp/fleet-hound-enricher.lock")
ENRICHER_TRIGGER_PATH = os.environ.get("ENRICHER_TRIGGER_PATH", "/tmp/fleet-hound-enricher.trigger")
# Status file lives under /app/config (the bind-mounted volume) so all 4
# gunicorn workers see the same view AND items_categorized_total survives
# container restarts.
ENRICHER_STATUS_PATH = os.environ.get("ENRICHER_STATUS_PATH", "/app/config/enricher_status.json")
# Manual /api/enricher/trigger rate limit (seconds between accepted triggers).
# Enforced cross-worker via trigger-file mtime.
ENRICHER_MANUAL_TRIGGER_COOLDOWN = 30.0

# OODA supervisor tunables (read once at import time).
OODA_ENABLED = _bool_env("OODA_ENABLED", False)
try:
    OODA_INTERVAL_SEC = int(os.environ.get("OODA_INTERVAL_SEC", "1800"))
except ValueError:
    OODA_INTERVAL_SEC = 1800
try:
    # Run a full-scan ETL every N delta cycles. 0 disables periodic full-scans.
    OODA_FULL_SCAN_EVERY = int(os.environ.get("OODA_FULL_SCAN_EVERY", "24"))
except ValueError:
    OODA_FULL_SCAN_EVERY = 24
OODA_LOCK_PATH = os.environ.get("OODA_LOCK_PATH", "/tmp/fleet-hound-ooda.lock")
OODA_TRIGGER_PATH = os.environ.get("OODA_TRIGGER_PATH", "/tmp/fleet-hound-ooda.trigger")
OODA_STATUS_PATH = os.environ.get("OODA_STATUS_PATH", "/app/config/ooda_status.json")
OODA_CYCLES_PATH = os.environ.get("OODA_CYCLES_PATH", "/app/config/ooda_cycles.jsonl")
OODA_FINDINGS_PATH = os.environ.get("OODA_FINDINGS_PATH", "/app/config/ooda_findings.json")
# State watermark and snapshot dir live under the bind-mounted /app/config so
# they survive restarts AND are writable under the read_only rootfs.
OODA_STATE_PATH = os.environ.get("OODA_STATE_PATH", "/app/config/.state.json")
OODA_SNAPSHOT_DIR = os.environ.get("OODA_SNAPSHOT_DIR", SNAPSHOT_DIR)
OODA_MANUAL_TRIGGER_COOLDOWN = 60.0

# Loud refusal-to-stay-silent when the long-running OODA supervisor is wired up
# to talk to Fleet with TLS verification disabled. INSECURE is a legitimate
# self-signed-cert / dev escape hatch for one-shot host ETL, but inside a
# container that polls Fleet every OODA_INTERVAL_SEC for the lifetime of the
# process it represents a sustained MITM exposure window. Surface it at boot
# so an operator who flipped INSECURE for a one-time debug session and forgot
# notices in their stack logs.
if _bool_env("INSECURE", False) and OODA_ENABLED:
    logger.warning(
        "INSECURE=true with OODA_ENABLED=true: the supervisor will talk to "
        "FLEET_URL with TLS verification DISABLED on every cycle. This is a "
        "sustained MITM-exposure posture, not a one-shot dev override. Unset "
        "INSECURE in production and front Fleet with a valid TLS cert."
    )

# ---------------------------------------------------------------------------
# Shadow IT classification helpers
#
# Shadow IT = end-user-installed software that bypasses IT/security review:
# personal communication apps, unsanctioned file-sync, remote-access tools,
# privacy/anonymity tools, and crypto miners. It is NOT OS-managed system
# libraries, kernel headers, language toolchain packages, or transitive
# dependencies pulled in by the package manager. Treating those as Shadow IT
# generates pure noise (libreadline8, python3.12-dev, tzdata-legacy, etc.).
#
# These helpers are used by /api/shadow-it to filter the candidate set before
# running outlier / high-risk / version-sprawl detection.
# ---------------------------------------------------------------------------

# Shadow IT filter primitives now live in src/shadow_it_filter.py and are
# imported above as _SYSTEM_PACKAGE_RE / _SYSTEM_CATEGORY_TOKENS /
# _DEV_LANGUAGE_SOURCES / _EXTENSION_SOURCES / _USER_APP_SOURCES /
# _is_non_app_source / _is_system_package. Single source of truth shared
# with categorize_software.py.


def _word_match(pattern: str, text_lower: str) -> bool:
    """Match a keyword against text using non-alphanumeric word boundaries.
    `'line' in 'libreadline8'` returns True (substring match) — that is the
    bug. This helper enforces that 'line' only matches the standalone word
    'line', not 'readline'/'pipeline'/'command-line'. Multi-word patterns
    like 'tor browser' are supported."""
    if not pattern or not text_lower:
        return False
    return re.search(
        r"(?<![a-z0-9])" + re.escape(pattern) + r"(?![a-z0-9])",
        text_lower,
    ) is not None


def load_whitelist():
    """Load authorized software list"""
    if not os.path.exists(WHITELIST_FILE):
        return []
    try:
        with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing whitelist JSON (corrupted file?): {e}")
        return []
    except Exception as e:
        logger.error(f"Error loading whitelist: {e}")
        return []

def save_whitelist(whitelist):
    """Save authorized software list"""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(WHITELIST_FILE), exist_ok=True)
        # Atomic write to avoid partial/corrupted JSON on crash.
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode='w',
                encoding='utf-8',
                delete=False,
                dir=os.path.dirname(WHITELIST_FILE),
                prefix=os.path.basename(WHITELIST_FILE) + '.',
                suffix='.tmp',
            ) as f:
                tmp_path = f.name
                json.dump(whitelist, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
            os.replace(tmp_path, WHITELIST_FILE)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
    except Exception as e:
        logger.error(f"Error saving whitelist: {e}")

def audit_log(action, details):
    """Log actions to audit file"""
    try:
        os.makedirs(os.path.dirname(AUDIT_FILE), exist_ok=True)
        # Keep one action per line (avoid newlines in user-controlled details).
        safe_details = (details or "").replace("\n", "\\n").replace("\r", "\\r")
        with open(AUDIT_FILE, 'a', encoding='utf-8') as f:
            timestamp = datetime.now(timezone.utc).isoformat()
            f.write(f"{timestamp} - {action} - {safe_details}\n")
    except Exception as e:
        logger.error(f"Error writing audit log: {e}")


# ----------------------------------------------------------------------------
# Memgraph driver lifecycle
# ----------------------------------------------------------------------------
# The driver is created lazily, after Gunicorn has already forked workers, so
# every worker gets its own Bolt connection pool (sharing one across forked
# processes corrupts pool state). _get_driver() retries transparently when the
# DB is unreachable; _reset_driver() lets request handlers force a fresh
# connection on a transient failure mid-request.
_driver = None
_driver_lock = threading.Lock()
_DRIVER_INIT_RETRIES = 5
_DRIVER_INIT_BACKOFF_SEC = 2.0


def _build_auth():
    if MEMGRAPH_USER and MEMGRAPH_PASSWORD:
        return (MEMGRAPH_USER, MEMGRAPH_PASSWORD)
    return None


def _get_driver():
    """Return a connected driver, lazily creating one on first use.

    Returns None when Memgraph is unreachable after the bounded retry budget;
    callers should treat that as a 503/500 condition.
    """
    global _driver
    if _driver is not None:
        return _driver
    with _driver_lock:
        if _driver is not None:
            return _driver
        auth = _build_auth()
        last_err = None
        for attempt in range(1, _DRIVER_INIT_RETRIES + 1):
            try:
                drv = GraphDatabase.driver(MEMGRAPH_URI, auth=auth)
                with drv.session() as session:
                    session.run("RETURN 1").consume()
                logger.info("Connected to Memgraph at %s", MEMGRAPH_URI)
                _driver = drv
                return _driver
            except AuthError as exc:
                logger.error("Memgraph auth failed: %s", exc)
                return None
            except Exception as exc:
                last_err = exc
                if attempt < _DRIVER_INIT_RETRIES:
                    logger.warning(
                        "Memgraph connect attempt %d/%d failed (%s), retrying in %.1fs",
                        attempt, _DRIVER_INIT_RETRIES, exc, _DRIVER_INIT_BACKOFF_SEC,
                    )
                    time.sleep(_DRIVER_INIT_BACKOFF_SEC)
        logger.error("Failed to connect to Memgraph after %d attempts: %s",
                     _DRIVER_INIT_RETRIES, last_err)
        return None


def _reset_driver():
    """Drop the cached driver so the next _get_driver() call rebuilds it."""
    global _driver
    with _driver_lock:
        if _driver is not None:
            try:
                _driver.close()
            except Exception:
                pass
            _driver = None


@atexit.register
def _close_memgraph_driver():
    """Best-effort cleanup at process exit."""
    _reset_driver()


# Backwards-compatible shim: existing handlers do `if not driver: ...`. We expose
# `driver` as a property-like accessor that resolves through _get_driver().
class _DriverProxy:
    def __bool__(self):
        return _get_driver() is not None

    def session(self, *args, **kwargs):
        drv = _get_driver()
        if drv is None:
            raise ServiceUnavailable("Memgraph driver is not connected")
        return drv.session(*args, **kwargs)


driver = _DriverProxy()


# ----------------------------------------------------------------------------
# Auth + safety middleware
# ----------------------------------------------------------------------------
_LOOPBACK_NETS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)


def _is_loopback(addr: str) -> bool:
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in _LOOPBACK_NETS)


def _client_ip() -> str:
    return (request.remote_addr or "").strip()


def _extract_token_from_request() -> str:
    auth_header = request.headers.get("Authorization", "").strip()
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return request.headers.get("X-Api-Token", "").strip()


_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@app.before_request
def _enforce_auth():
    path = request.path or ""
    # Always allow the healthcheck and the static index entry-point.
    if path in PUBLIC_PATHS:
        return None
    if not path.startswith("/api/"):
        return None

    is_write = request.method in _STATE_CHANGING_METHODS

    if WEBVIZ_API_TOKEN:
        supplied = _extract_token_from_request()
        if not supplied or not hmac.compare_digest(supplied, WEBVIZ_API_TOKEN):
            return jsonify({"error": "Unauthorized"}), 401
        return None

    # Token unconfigured. State-changing routes are always denied without a token —
    # this is the CSRF / drive-by-write defense (anyone could otherwise POST to
    # /api/authorize-software from a browser they happen to load on the LAN).
    if is_write:
        return jsonify({
            "error": "Unauthorized",
            "message": "Set WEBVIZ_API_TOKEN to enable state-changing API calls.",
        }), 401

    # GETs: loopback always OK, others require explicit anonymous-read opt-in.
    if _is_loopback(_client_ip()):
        return None
    if WEBVIZ_ALLOW_ANONYMOUS_READ:
        return None
    return jsonify({
        "error": "Unauthorized",
        "message": "Set WEBVIZ_API_TOKEN, or WEBVIZ_ALLOW_ANONYMOUS_READ=true for read-only access.",
    }), 401


@app.after_request
def _security_headers(response):
    # Conservative defaults safe for an SPA that serves a single inline-JS HTML.
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    return response


# ----------------------------------------------------------------------------
# ReDoS guard for /api/search?mode=regex
# ----------------------------------------------------------------------------
# Belt + suspenders. We refuse obviously catastrophic patterns BEFORE forwarding
# to Memgraph and we cap the input length tighter than the wildcard mode. The
# ultimate safety net is memgraph.conf's --query-execution-timeout-sec.
_MAX_REGEX_LEN = 100
# Heuristic ReDoS blocklist. Targets the canonical catastrophic-backtracking
# shapes; we accept some false positives in exchange for not having to run a
# regex pattern in a sandbox. The Memgraph query timeout is the safety net.
_REDOS_BLOCKLIST = (
    re.compile(r"[+*?]\s*\)\s*[+*?]"),         # nested quantifier — (a+)+, (a*)*
    re.compile(r"\(.+\)\s*\{\d+,?\d*\}\s*[+*]"),  # quantified group with outer * / +
    re.compile(r"(?:\.\*){2,}"),               # consecutive greedy .*
    re.compile(r"(?:\.\+){2,}"),               # consecutive greedy .+
)


def _validate_user_regex(pattern: str) -> tuple[bool, str]:
    if pattern is None:
        return False, "regex required"
    if len(pattern) > _MAX_REGEX_LEN:
        return False, f"regex pattern must be <= {_MAX_REGEX_LEN} chars"
    for blocked in _REDOS_BLOCKLIST:
        if blocked.search(pattern):
            return False, "regex pattern rejected for safety (potential ReDoS)"
    try:
        re.compile(pattern)
    except re.error as exc:
        return False, f"invalid regex: {exc}"
    return True, ""

@app.route("/api/hosts")
def get_hosts():
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    with driver.session() as session:
        result = session.run("MATCH (h:Host) RETURN h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform, h.ip AS ip, h.last_seen AS last_seen")
        return jsonify([r.data() for r in result])

@app.route("/api/users")
def get_users():
    """Get users per host - only users that are connected to hosts"""
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    with driver.session() as session:
        result = session.run("""
            MATCH (u:User)-[:USES]->(h:Host) 
            RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname, 
                   h.hostname AS hostname, h.platform AS platform
            ORDER BY h.hostname, u.username
        """)
        users = [r.data() for r in result]
        # Filter out any users that don't have proper host connections
        filtered_users = [user for user in users if user.get('hostname')]
        return jsonify(filtered_users)

@app.route("/api/software")
def get_software():
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    with driver.session() as session:
        result = session.run("MATCH (s:Software) RETURN s.name AS name, s.versions AS versions, s.last_version AS last_version")
        return jsonify([r.data() for r in result])

@app.route("/api/teams")
def get_teams():
    """Get all unique teams from hosts."""
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    with driver.session() as session:
        result = session.run("""
            MATCH (h:Host)
            WHERE h.team_id IS NOT NULL
            RETURN DISTINCT h.team_id AS team_id, h.team_name AS team_name
            ORDER BY h.team_name
        """)
        teams = [{"id": str(r['team_id']), "name": r['team_name']} for r in result]
        return jsonify(teams)

@app.route("/api/platforms")
def get_platforms():
    """Get all unique platforms from hosts."""
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    with driver.session() as session:
        result = session.run("""
            MATCH (h:Host)
            WHERE h.platform IS NOT NULL AND h.platform <> ""
            RETURN DISTINCT h.platform AS platform
            ORDER BY h.platform
        """)
        platforms = [r['platform'] for r in result]
        return jsonify(platforms)


@app.route("/api/labels")
def get_labels():
    """List Fleet labels (user-defined + functional builtins) for scoping.

    Plan section 1A/1E/2B. Powers the UI multi-select widget and any
    consumer that needs to know:
      - which labels exist in this graph
      - how many hosts each one currently scopes
      - how fresh the label sync is, per-label

    Response schema (one entry per label):
        {
          "fleet_id": int,
          "name": str,
          "description": str | "",
          "label_type": "regular" | "builtin",
          "membership_type": "dynamic" | "manual" | "",
          "host_count": int,           # live count from graph (HAS_LABEL edges)
          "last_synced_iso": str,
          "last_label_sync_status": "ok" | "stale" | "failed",
          "consecutive_failures": int,
          "orphan_member_count": int,  # host ids in Fleet membership with no :Host node
          "orphan_member_ids": list[int],  # up to 50 orphan host ids
          "orphan_member_truncated": bool, # true when >50 orphans exist
        }

    Notes:
      - The osquery `query` field that defines a dynamic label is NOT
        included by default. It can be large and is rarely needed for the
        scoping UX. Pass `?include_query=true` to retrieve it.
      - host_count comes from the live graph (count of HAS_LABEL edges),
        not from Fleet's metadata. This catches drift between Fleet's
        cached counter and what's actually in our graph.
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    include_query = request.args.get("include_query", "").strip().lower() == "true"

    try:
        with driver.session() as session:
            result = session.run(
                """
                MATCH (l:Label)
                OPTIONAL MATCH (l)<-[r:HAS_LABEL]-(:Host)
                WITH l, count(r) AS live_host_count
                RETURN l.fleet_id AS fleet_id,
                       l.name AS name,
                       coalesce(l.description, '') AS description,
                       coalesce(l.label_type, 'regular') AS label_type,
                       coalesce(l.membership_type, '') AS membership_type,
                       live_host_count AS host_count,
                       coalesce(l.last_synced_iso, '') AS last_synced_iso,
                       coalesce(l.last_label_sync_status, 'unknown') AS last_label_sync_status,
                       coalesce(l.consecutive_failures, 0) AS consecutive_failures,
                       l.query AS query,
                       coalesce(l.orphan_member_count, 0) AS orphan_member_count,
                       coalesce(l.orphan_member_ids, []) AS orphan_member_ids,
                       coalesce(l.orphan_member_truncated, false) AS orphan_member_truncated
                ORDER BY l.name
"""
            )
            payload = []
            for r in result:
                entry = {
                    "fleet_id": r["fleet_id"],
                    "name": r["name"],
                    "description": r["description"],
                    "label_type": r["label_type"],
                    "membership_type": r["membership_type"],
                    "host_count": int(r["host_count"]) if r["host_count"] is not None else 0,
                    "last_synced_iso": r["last_synced_iso"],
                    "last_label_sync_status": r["last_label_sync_status"],
                    "consecutive_failures": int(r["consecutive_failures"] or 0),
                    "orphan_member_count": int(r["orphan_member_count"] or 0),
                    "orphan_member_ids": list(r["orphan_member_ids"] or []),
                    "orphan_member_truncated": bool(r["orphan_member_truncated"]),
                }
                if include_query and r["query"]:
                    entry["query"] = r["query"]
                payload.append(entry)
            return jsonify(payload)
    except (TransientError, ServiceUnavailable) as exc:
        logger.warning("/api/labels transient: %s", exc)
        return jsonify({
            "error": "Database transient error",
            "message": "Memgraph is unreachable. Retry in a moment.",
        }), 503
    except Exception as exc:
        logger.error("/api/labels failed: %s", exc, exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/labels/scope-count")
def get_label_scope_count():
    """Pre-flight host count for a candidate label scope.

    Drives the zero-host empty-state UX in the label widget (plan-design-review
    Pass 2 finding 2A). On every chip toggle the UI fires this endpoint with
    the candidate scope; on count == 0 the widget surfaces the "Switch to OR
    (matches N hosts)" CTA with a pre-computed alternative count.

    Query params: same shape as /api/search etc.
        ?labels=A,B&label_op=AND|OR  → count of hosts in scope
        ?team=N&platform=X           → optional, filters the count
        ?include_alt=true            → also return alternative count for
                                       the OPPOSITE label_op (so the UI can
                                       render "Switch to OR (matches N)" without
                                       a second round-trip)

    Response:
        {
          "count": int,
          "labels": [...],         # echoed for client-side state alignment
          "label_op": "AND"|"OR",
          "alt_count": int|null,   # only when ?include_alt=true
          "alt_label_op": "OR"|"AND"|null
        }
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    # TODO-2: composite scoping. When `?expr=<json>` is provided, route
    # through apply_composite_filter for arbitrary boolean expressions over
    # team/platform/labels. Otherwise fall back to the flat-AND
    # apply_host_filters path. The expr param is the opt-in — no separate
    # feature flag needed.
    expr_raw = (request.args.get("expr") or "").strip()
    if expr_raw:
        try:
            expr_obj = json.loads(expr_raw)
        except (ValueError, TypeError) as exc:
            return jsonify({
                "error": "Invalid expr",
                "message": f"expr must be valid JSON: {exc}",
            }), 400
        try:
            flt_fragment, flt_params = apply_composite_filter(expr_obj)
        except FilterValidationError as exc:
            return jsonify({"error": "Invalid filter", "message": str(exc)}), 400
    else:
        try:
            flt_fragment, flt_params = apply_host_filters(request.args)
        except FilterValidationError as exc:
            return jsonify({"error": "Invalid filter", "message": str(exc)}), 400

    include_alt = request.args.get("include_alt", "").strip().lower() == "true"
    labels_csv = (request.args.get("labels") or "").strip()
    label_names = [s.strip() for s in labels_csv.split(",") if s.strip()] if labels_csv else []
    label_op = (request.args.get("label_op") or "AND").strip().upper()
    if label_op not in ("AND", "OR"):
        # Unreachable when apply_host_filters validates label_op, but defense
        # in depth in case the helper signature changes later.
        return jsonify({"error": "Invalid label_op"}), 400

    try:
        with driver.session() as session:
            count_query = (
                "MATCH (h:Host) WHERE 1=1" + flt_fragment + " RETURN count(h) AS c"
            )
            rec = session.run(count_query, **flt_params).single()
            count = int(rec["c"]) if rec and rec["c"] is not None else 0

            payload = {
                "count": count,
                "labels": label_names,
                "label_op": label_op,
                "alt_count": None,
                "alt_label_op": None,
            }

            if include_alt and label_names and len(label_names) >= 2:
                # Compute the count under the OPPOSITE op so the UI's
                # "Switch to OR (matches N hosts)" CTA can pre-render without
                # a second fetch. Only meaningful when ≥2 labels are selected
                # (with one label, AND and OR are equivalent).
                alt_op = "OR" if label_op == "AND" else "AND"
                alt_args = dict(request.args)
                alt_args["label_op"] = alt_op
                alt_fragment, alt_params = apply_host_filters(alt_args)
                alt_query = (
                    "MATCH (h:Host) WHERE 1=1" + alt_fragment + " RETURN count(h) AS c"
                )
                alt_rec = session.run(alt_query, **alt_params).single()
                payload["alt_count"] = (
                    int(alt_rec["c"]) if alt_rec and alt_rec["c"] is not None else 0
                )
                payload["alt_label_op"] = alt_op

            return jsonify(payload)
    except (TransientError, ServiceUnavailable) as exc:
        logger.warning("/api/labels/scope-count transient: %s", exc)
        return jsonify({
            "error": "Database transient error",
            "message": "Memgraph is unreachable. Retry in a moment.",
        }), 503
    except Exception as exc:
        logger.error("/api/labels/scope-count failed: %s", exc, exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/search")
def search_all():
    """Universal search endpoint for all node types (hosts, users, software).

    Query parameters:
    - q: search term (optional - if empty, returns ALL nodes of specified type)
    - type: node type filter ('all', 'host', 'user', 'software') - default 'all'
    - platform: platform filter ('all', 'ubuntu', 'darwin', 'windows') - default 'all'

    Returns full relationship graph with matching nodes and their connections.
    """
    search_term = request.args.get('q', '').strip()
    node_type = request.args.get('type', 'all').strip().lower()
    platform_filter = request.args.get('platform', 'all').strip().lower()
    team_filter = request.args.get('team', 'all').strip()

    # Label scoping (plan section 1E + 2A): bolted on additively via the
    # apply_label_filter helper so existing team/platform logic stays intact.
    # The label fragment always starts with " AND " or is empty; appending
    # it after the existing inline team/platform AND chain is safe.
    try:
        label_flt_fragment, label_flt_params = apply_label_filter(request.args)
    except FilterValidationError as exc:
        return jsonify({"error": "Invalid filter", "message": str(exc)}), 400

    # Advanced search parameters
    search_mode = request.args.get('mode', 'wildcard').strip().lower()  # wildcard, exact, regex
    case_sensitive = request.args.get('case', 'false').strip().lower() == 'true'

    # Validate key inputs BEFORE touching the database so callers get a 400 even
    # when Memgraph is down — and so a malicious regex never reaches the DB.
    allowed_node_types = {'all', 'host', 'user', 'software'}
    if node_type not in allowed_node_types:
        return jsonify({
            "error": "Invalid node type",
            "message": f"type must be one of {sorted(allowed_node_types)}",
        }), 400

    allowed_search_modes = {'wildcard', 'exact', 'regex'}
    if search_mode not in allowed_search_modes:
        return jsonify({
            "error": "Invalid search mode",
            "message": f"mode must be one of {sorted(allowed_search_modes)}",
        }), 400

    # Basic input size guardrails (avoid pathological queries / regex)
    if len(search_term) > 200:
        return jsonify({
            "error": "Search term too long",
            "message": "q must be <= 200 characters",
        }), 400

    # ReDoS guard: when caller asked for regex mode, validate the pattern up-front
    # so catastrophic-backtracking patterns never reach Memgraph.
    if search_mode == "regex" and search_term:
        ok, msg = _validate_user_regex(search_term)
        if not ok:
            return jsonify({"error": "Invalid regex", "message": msg}), 400

    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    # Limit parameter
    try:
        limit_param = int(request.args.get('limit', 0))
    except ValueError:
        limit_param = 0
    
    # Default limits
    cypher_limit = limit_param if limit_param > 0 else 100
    display_limit = limit_param if limit_param > 0 else 10


    # Helper function to generate search condition based on mode
    def get_search_condition(property_name, term_param_name):
        if search_mode == 'exact':
            if case_sensitive:
                return f"{property_name} = ${term_param_name}"
            return f"toLower({property_name}) = toLower(${term_param_name})"

        if search_mode == 'regex':
            # Regex match using =~. For case-insensitive regex we match against a lowercased property.
            if case_sensitive:
                return f"{property_name} =~ ${term_param_name}"
            return f"toLower({property_name}) =~ ${term_param_name}_lower"

        # wildcard (default): substring match
        if case_sensitive:
            return f"{property_name} CONTAINS ${term_param_name}"
        return f"toLower({property_name}) CONTAINS toLower(${term_param_name})"
    

    # Prepare search logging
    if search_term:
        logger.info(f"Search: '{search_term}' (mode: {search_mode}, case: {case_sensitive}, type: {node_type})")
    else:
        logger.info(f"Search: ALL (type: {node_type}, limit: {limit_param})")

    with driver.session() as session:
        nodes = []
        node_ids = set()

        # Search/load hosts
        if node_type in ['all', 'host']:
            if search_term:
                # Search hosts by hostname or OS version
                host_condition = get_search_condition('h.hostname', 'search_term')
                os_condition = get_search_condition('h.os_version', 'search_term')
                
                host_query = f"""
                    MATCH (h:Host)
                    WHERE ({host_condition} OR {os_condition})
                """
                if platform_filter != 'all':
                    host_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                if team_filter != 'all':
                    host_query += " AND toString(h.team_id) = $team_id"
                host_query += label_flt_fragment
                host_query += " RETURN DISTINCT h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform, h.team_name AS team_name"
                # Apply limit to search results too if requested
                if limit_param > 0:
                    host_query += f" LIMIT {cypher_limit}"

                params = {'search_term': search_term}
                if search_mode == 'regex' and not case_sensitive:
                    params['search_term_lower'] = search_term.lower()
                if platform_filter != 'all':
                    params['platform'] = platform_filter
                if team_filter != 'all':
                    params['team_id'] = team_filter
                params.update(label_flt_params)
                host_result = session.run(host_query, **params)
            else:
                # No search term: return ALL hosts (with optional platform and team filters)
                host_query = "MATCH (h:Host) WHERE 1=1"
                params = {}

                if platform_filter != 'all':
                    host_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                    params['platform'] = platform_filter
                if team_filter != 'all':
                    host_query += " AND toString(h.team_id) = $team_id"
                    params['team_id'] = team_filter
                host_query += label_flt_fragment
                params.update(label_flt_params)

                host_query += " RETURN DISTINCT h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform, h.team_name AS team_name"
                # Apply default limit if no term
                host_query += f" LIMIT {cypher_limit}"

                host_result = session.run(host_query, **params)

            for record in host_result:
                host_id = f"host_{record['hostname']}"
                team_info = f" - Team: {record.get('team_name', 'No team')}" if record.get('team_name') else ""
                nodes.append({
                    "id": host_id,
                    "name": record['hostname'],
                    "type": "host",
                    "details": f"{record['os_version'] or ''} ({record['platform'] or ''}){team_info}"
                })
                node_ids.add(host_id)

        # Search/load users
        if node_type in ['all', 'user']:
            if search_term:
                # Search users by username, email, or fullname
                # Search users by username, email, or fullname
                username_cond = get_search_condition('u.username', 'search_term')
                email_cond = get_search_condition('u.email', 'search_term')
                fullname_cond = get_search_condition('u.fullname', 'search_term')
                
                user_query = f"""
                    MATCH (u:User)-[:USES]->(h:Host)
                    WHERE ({username_cond} OR {email_cond} OR {fullname_cond})
                """
                params = {'search_term': search_term}
                if search_mode == 'regex' and not case_sensitive:
                    params['search_term_lower'] = search_term.lower()

                if platform_filter != 'all':
                    user_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                    params['platform'] = platform_filter
                if team_filter != 'all':
                    user_query += " AND toString(h.team_id) = $team_id"
                    params['team_id'] = team_filter
                user_query += label_flt_fragment
                params.update(label_flt_params)

                user_query += " RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname"
                if limit_param > 0:
                    user_query += f" LIMIT {cypher_limit}"

                user_result = session.run(user_query, **params)
            else:
                # No search term: return ALL users (with optional platform and team filters)
                user_query = "MATCH (u:User)-[:USES]->(h:Host) WHERE 1=1"
                params = {}

                if platform_filter != 'all':
                    user_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                    params['platform'] = platform_filter
                if team_filter != 'all':
                    user_query += " AND toString(h.team_id) = $team_id"
                    params['team_id'] = team_filter
                user_query += label_flt_fragment
                params.update(label_flt_params)

                user_query += " RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname"
                user_query += f" LIMIT {cypher_limit}"

                user_result = session.run(user_query, **params)

            for record in user_result:
                user_id = f"user_{record['username']}"
                if user_id not in node_ids:
                    nodes.append({
                        "id": user_id,
                        "name": record['username'],
                        "type": "user",
                        "details": record['email'] or record['fullname'] or ''
                    })
                    node_ids.add(user_id)

        # Search/load software
        if node_type in ['all', 'software']:
            if search_term:
                # Search software by name
                software_cond = get_search_condition('s.name', 'search_term')
                
                software_query = f"""
                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                    WHERE {software_cond}
                """
                params = {'search_term': search_term}
                if search_mode == 'regex' and not case_sensitive:
                    params['search_term_lower'] = search_term.lower()

                if platform_filter != 'all':
                    software_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                    params['platform'] = platform_filter
                if team_filter != 'all':
                    software_query += " AND toString(h.team_id) = $team_id"
                    params['team_id'] = team_filter
                software_query += label_flt_fragment
                params.update(label_flt_params)

                software_query += """
                    WITH s, COUNT(DISTINCT h) as host_count
                    RETURN s.name AS name, s.last_version AS last_version, s.category AS category, s.wikidata_description AS description, host_count
                """
                if limit_param > 0:
                    software_query += f" LIMIT {cypher_limit}"

                software_result = session.run(software_query, **params)
            else:
                # No search term: return top 100 software by host count (with optional platform and team filters)
                software_query = """
                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                    WHERE 1=1
                """
                params = {}

                if platform_filter != 'all':
                    software_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                    params['platform'] = platform_filter
                if team_filter != 'all':
                    software_query += " AND toString(h.team_id) = $team_id"
                    params['team_id'] = team_filter
                software_query += label_flt_fragment
                params.update(label_flt_params)

                software_query += f"""
                    WITH s.name AS name, s.last_version AS last_version, s.category AS category, s.wikidata_description AS description, COUNT(DISTINCT h) AS host_count
                    ORDER BY host_count DESC
                    LIMIT {cypher_limit}
                    RETURN name, last_version, category, description, host_count
                """
                software_result = session.run(software_query, **params)

            # Limit to 10 unique software items for visualization ONLY when showing "ALL" (no search term)
            # When user searches for specific software, show ALL matching results
            software_count = 0
            for record in software_result:
                software_id = f"software_{record['name']}"
                if software_id not in node_ids:
                    # Only apply limit when there's no search term (the "ALL" case)
                    if not search_term and software_count >= display_limit:
                        break
                    nodes.append({
                        "id": software_id,
                        "name": record['name'],
                        "type": "software",
                        "category": record.get('category'),
                        "description": record.get('description'),
                        "details": f"Latest: {record['last_version'] or 'unknown'} (on {record.get('host_count', 0)} hosts)"
                    })
                    node_ids.add(software_id)
                    software_count += 1

        # If we loaded software or users, we need to also load their connected hosts
        # to ensure we have complete relationships
        software_ids_loaded = [nid for nid in node_ids if nid.startswith('software_')]
        user_ids_loaded = [nid for nid in node_ids if nid.startswith('user_')]

        if software_ids_loaded and (node_type == 'software' or node_type == 'all'):
            # Load hosts connected to the software we loaded
            software_names = [sid.replace('software_', '') for sid in software_ids_loaded]
            host_query = """
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE s.name IN $software_names
            """
            params = {'software_names': software_names}

            if platform_filter != 'all':
                host_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                params['platform'] = platform_filter
            if team_filter != 'all':
                host_query += " AND toString(h.team_id) = $team_id"
                params['team_id'] = team_filter

            host_query += " RETURN DISTINCT h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform, h.team_name AS team_name"

            host_result = session.run(host_query, **params)
            for record in host_result:
                host_id = f"host_{record['hostname']}"
                if host_id not in node_ids:
                    team_info = f" - Team: {record.get('team_name', 'No team')}" if record.get('team_name') else ""
                    nodes.append({
                        "id": host_id,
                        "name": record['hostname'],
                        "type": "host",
                        "details": f"{record['os_version'] or ''} ({record['platform'] or ''}){team_info}"
                    })
                    node_ids.add(host_id)

        if user_ids_loaded and (node_type == 'user' or node_type == 'all'):
            # Load hosts connected to the users we loaded
            usernames = [uid.replace('user_', '') for uid in user_ids_loaded]
            host_query = """
                MATCH (u:User)-[:USES]->(h:Host)
                WHERE u.username IN $usernames
            """
            params = {'usernames': usernames}

            if platform_filter != 'all':
                host_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                params['platform'] = platform_filter
            if team_filter != 'all':
                host_query += " AND toString(h.team_id) = $team_id"
                params['team_id'] = team_filter

            host_query += " RETURN DISTINCT h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform, h.team_name AS team_name"

            host_result = session.run(host_query, **params)
            for record in host_result:
                host_id = f"host_{record['hostname']}"
                if host_id not in node_ids:
                    team_info = f" - Team: {record.get('team_name', 'No team')}" if record.get('team_name') else ""
                    nodes.append({
                        "id": host_id,
                        "name": record['hostname'],
                        "type": "host",
                        "details": f"{record['os_version'] or ''} ({record['platform'] or ''}){team_info}"
                    })
                    node_ids.add(host_id)

        # Now get all relationships between the loaded nodes
        links = []

        # Get user-host relationships
        if node_ids:
            user_host_query = """
                MATCH (u:User)-[:USES]->(h:Host)
                WHERE $user_filter OR $host_filter
                RETURN DISTINCT u.username AS username, h.hostname AS hostname
            """
            # Build filter conditions
            user_ids_list = [nid.replace('user_', '') for nid in node_ids if nid.startswith('user_')]
            host_ids_list = [nid.replace('host_', '') for nid in node_ids if nid.startswith('host_')]

            if user_ids_list or host_ids_list:
                user_host_query = """
                    MATCH (u:User)-[:USES]->(h:Host)
                """
                conditions = []
                params = {}

                if user_ids_list:
                    conditions.append("u.username IN $user_list")
                    params['user_list'] = user_ids_list
                if host_ids_list:
                    conditions.append("h.hostname IN $host_list")
                    params['host_list'] = host_ids_list

                if conditions:
                    user_host_query += " WHERE " + " OR ".join(conditions)

                # Apply team filter to relationships to prevent cross-team contamination
                if team_filter != 'all':
                    if conditions:
                        user_host_query += " AND toString(h.team_id) = $team_id"
                    else:
                        user_host_query += " WHERE toString(h.team_id) = $team_id"
                    params['team_id'] = team_filter

                # Apply platform filter to relationships
                if platform_filter != 'all':
                    if conditions or team_filter != 'all':
                        user_host_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                    else:
                        user_host_query += " WHERE toLower(h.platform) CONTAINS toLower($platform)"
                    params['platform'] = platform_filter

                user_host_query += " RETURN DISTINCT u.username AS username, h.hostname AS hostname"

                user_host_result = session.run(user_host_query, **params)

                for record in user_host_result:
                    source_id = f"user_{record['username']}"
                    target_id = f"host_{record['hostname']}"
                    if source_id in node_ids and target_id in node_ids:
                        links.append({
                            "source": source_id,
                            "target": target_id,
                            "type": "uses"
                        })

        # Get software-host relationships
        if node_ids:
            software_ids_list = [nid.replace('software_', '') for nid in node_ids if nid.startswith('software_')]
            host_ids_list = [nid.replace('host_', '') for nid in node_ids if nid.startswith('host_')]

            if software_ids_list or host_ids_list:
                software_host_query = """
                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                """
                conditions = []
                params = {}

                if software_ids_list:
                    conditions.append("s.name IN $software_list")
                    params['software_list'] = software_ids_list
                if host_ids_list:
                    conditions.append("h.hostname IN $host_list")
                    params['host_list'] = host_ids_list

                if conditions:
                    software_host_query += " WHERE " + " OR ".join(conditions)

                # Apply team filter to relationships to prevent cross-team contamination
                if team_filter != 'all':
                    if conditions:
                        software_host_query += " AND toString(h.team_id) = $team_id"
                    else:
                        software_host_query += " WHERE toString(h.team_id) = $team_id"
                    params['team_id'] = team_filter

                # Apply platform filter to relationships
                if platform_filter != 'all':
                    if conditions or team_filter != 'all':
                        software_host_query += " AND toLower(h.platform) CONTAINS toLower($platform)"
                    else:
                        software_host_query += " WHERE toLower(h.platform) CONTAINS toLower($platform)"
                    params['platform'] = platform_filter

                software_host_query += " RETURN DISTINCT s.name AS software_name, h.hostname AS hostname"

                software_host_result = session.run(software_host_query, **params)

                for record in software_host_result:
                    source_id = f"software_{record['software_name']}"
                    target_id = f"host_{record['hostname']}"
                    if source_id in node_ids and target_id in node_ids:
                        links.append({
                            "source": source_id,
                            "target": target_id,
                            "type": "installed"
                        })

        search_desc = f"'{search_term}'" if search_term else "ALL"
        logger.info(f"Search {search_desc} (type: {node_type}, platform: {platform_filter}): Returning {len(nodes)} nodes and {len(links)} links")

        return jsonify({
            "nodes": nodes,
            "links": links,
            "search_term": search_term,
            "node_type": node_type,
            "platform_filter": platform_filter,
            "node_count": len(nodes),
            "link_count": len(links)
        })

@app.route("/api/search/software")
def search_software():
    """Legacy endpoint - redirects to new universal search endpoint.

    Kept for backward compatibility with existing frontend code.
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    search_term = request.args.get('q', '').strip()
    platform_filter = request.args.get('platform', 'all').strip().lower()

    with driver.session() as session:
        nodes = []
        node_ids = set()

        # Search for ALL software matching the search term (case-insensitive, partial match)
        # If search_term is empty, return ALL software
        if search_term:
            software_query = """
                MATCH (s:Software)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                RETURN DISTINCT s.name AS name, s.last_version AS last_version
                ORDER BY s.name
            """
            software_result = session.run(software_query, search_term=search_term)
        else:
            # No search term: return top 100 software by host count
            # Apply platform filter if specified to reduce data
            if platform_filter != 'all':
                software_query = """
                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                    WHERE toLower(h.platform) CONTAINS toLower($platform)
                    WITH s.name AS name, s.last_version AS last_version, COUNT(DISTINCT h) AS host_count
                    ORDER BY host_count DESC
                    LIMIT 100
                    RETURN name, last_version, host_count
                """
                software_result = session.run(software_query, platform=platform_filter)
            else:
                software_query = """
                    MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                    WITH s.name AS name, s.last_version AS last_version, COUNT(DISTINCT h) AS host_count
                    ORDER BY host_count DESC
                    LIMIT 100
                    RETURN name, last_version, host_count
                """
                software_result = session.run(software_query)

        software_list = [record for record in software_result]

        if not software_list:
            msg = f"No software found matching '{search_term}'" if search_term else "No software found"
            return jsonify({"nodes": [], "links": [], "message": msg}), 200

        # Add matching software nodes - limit to 10 unique items ONLY when showing "ALL" (no search term)
        # When user searches for specific software, show ALL matching results
        software_count = 0
        for record in software_list:
            # Only apply limit when there's no search term (the "ALL" case)
            if not search_term and software_count >= 10:
                break
            software_id = f"software_{record['name']}"
            nodes.append({
                "id": software_id,
                "name": record['name'],
                "type": "software",
                "details": f"Latest: {record['last_version'] or 'unknown'} (on {record.get('host_count', 0)} hosts)"
            })
            node_ids.add(software_id)
            software_count += 1

        # Get ALL hosts that have any of the matching software, with optional platform filter
        if platform_filter == 'all':
            host_result = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                RETURN DISTINCT h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform
            """, search_term=search_term)
        else:
            host_result = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                  AND toLower(h.platform) CONTAINS toLower($platform)
                RETURN DISTINCT h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform
            """, search_term=search_term, platform=platform_filter)

        for record in host_result:
            host_id = f"host_{record['hostname']}"
            if host_id not in node_ids:
                nodes.append({
                    "id": host_id,
                    "name": record['hostname'],
                    "type": "host",
                    "details": f"{record['os_version'] or ''} ({record['platform'] or ''})"
                })
                node_ids.add(host_id)

        # Get users connected to these hosts (with platform filter if applicable)
        if platform_filter == 'all':
            user_result = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname
            """, search_term=search_term)
        else:
            user_result = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                  AND toLower(h.platform) CONTAINS toLower($platform)
                RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname
            """, search_term=search_term, platform=platform_filter)

        for record in user_result:
            user_id = f"user_{record['username']}"
            if user_id not in node_ids:
                nodes.append({
                    "id": user_id,
                    "name": record['username'],
                    "type": "user",
                    "details": record['email'] or record['fullname'] or ''
                })
                node_ids.add(user_id)

        # Get all relationships
        links = []

        # Software-Host relationships (with platform filter if applicable)
        if platform_filter == 'all':
            software_host_links = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                RETURN s.name AS software_name, h.hostname AS hostname
            """, search_term=search_term)
        else:
            software_host_links = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                  AND toLower(h.platform) CONTAINS toLower($platform)
                RETURN s.name AS software_name, h.hostname AS hostname
            """, search_term=search_term, platform=platform_filter)

        for record in software_host_links:
            source_id = f"software_{record['software_name']}"
            target_id = f"host_{record['hostname']}"
            if source_id in node_ids and target_id in node_ids:
                links.append({
                    "source": source_id,
                    "target": target_id,
                    "type": "installed"
                })

        # User-Host relationships (for hosts that have the matching software, with platform filter)
        if platform_filter == 'all':
            user_host_links = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                RETURN DISTINCT u.username AS username, h.hostname AS hostname
            """, search_term=search_term)
        else:
            user_host_links = session.run("""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
                WHERE toLower(s.name) CONTAINS toLower($search_term)
                  AND toLower(h.platform) CONTAINS toLower($platform)
                RETURN DISTINCT u.username AS username, h.hostname AS hostname
            """, search_term=search_term, platform=platform_filter)

        for record in user_host_links:
            source_id = f"user_{record['username']}"
            target_id = f"host_{record['hostname']}"
            if source_id in node_ids and target_id in node_ids:
                links.append({
                    "source": source_id,
                    "target": target_id,
                    "type": "uses"
                })

        search_desc = f"'{search_term}'" if search_term else "ALL"
        logger.info(f"Software search {search_desc} (platform: {platform_filter}): Found {len(software_list)} software, returning {len(nodes)} nodes and {len(links)} links")
        return jsonify({
            "nodes": nodes,
            "links": links,
            "search_term": search_term,
            "platform_filter": platform_filter,
            "software_count": len(software_list)
        })

@app.route("/api/blast-radius")
def get_blast_radius():
    """Calculate blast radius metrics for a given node type and ID.
    
    Query parameters:
    - type: 'user' or 'software'
    - id: The specific ID (username or software name)
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    node_type = request.args.get('type')
    node_id = request.args.get('id')
    team_filter = request.args.get('team', 'all')
    ignore_defaults = request.args.get('ignore_defaults', 'false').lower() == 'true'

    if not node_type or not node_id:
        return jsonify({"error": "Missing type or id parameter"}), 400

    allowed_types = {'user', 'software'}
    if node_type not in allowed_types:
        return jsonify({
            "error": "Invalid type",
            "message": f"type must be one of {sorted(allowed_types)}",
        }), 400

    if len(node_id) > 300:
        return jsonify({
            "error": "Invalid id",
            "message": "id must be <= 300 characters",
        }), 400

    # Software name lookup is case-insensitive against a graph that now
    # stores names lowercase (see ingestion case-dedupe). Users (USES edge
    # endpoints) stay case-sensitive because usernames are exact identifiers.
    if node_type == 'software':
        node_id = node_id.strip().lower()

    # Label scoping (plan 1E): bolted on additively. label_clause is merged
    # alongside team_clause into every Cypher query that filters on hosts.
    try:
        label_flt_fragment, label_flt_params = apply_label_filter(request.args)
    except FilterValidationError as exc:
        return jsonify({"error": "Invalid filter", "message": str(exc)}), 400

    with driver.session() as session:
        metrics = {
            "host_reach": 0,
            "user_impact": 0,
            "lateral_movement": 0,
            "platform_diversity": 0
        }

        details = {
            "hosts": [],
            "users": [],
            "teams": [],
            "platforms": []
        }

        # Prepare team + label filter clauses. team_clause uses the legacy
        # inline pattern; label_clause comes from apply_label_filter so it
        # supports multi-label AND/OR semantics. Both inject into the same
        # WHERE chain via f-string interpolation below.
        team_clause = ""
        label_clause = label_flt_fragment
        params = {"id": node_id}

        if team_filter != 'all':
            team_clause = "AND toString(h.team_id) = $team_id"
            params["team_id"] = team_filter

        params.update(label_flt_params)

        # Common logic for finding impacted users on compromised hosts
        # This is where we apply the ignore_defaults filter
        user_exclusion_clause = "AND u.username <> $id" if node_type == 'user' else ""
        
        # Handle exclusions (dynamic list from frontend preferred)
        excluded_users_param = request.args.get('excluded_users', '')
        
        if excluded_users_param:
            # Frontend provided specific list
            excluded_users = [u.strip() for u in excluded_users_param.split(',') if u.strip()]
            if len(excluded_users) > 1000:
                return jsonify({
                    "error": "excluded_users too large",
                    "message": "excluded_users must contain <= 1000 usernames",
                }), 400
            if excluded_users:
                user_exclusion_clause += " AND NOT u.username IN $defaults"
                params['defaults'] = excluded_users
        elif ignore_defaults:
            # Fallback for backward compatibility
            default_accounts = ['root', 'Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount']
            user_exclusion_clause += " AND NOT u.username IN $defaults"
            params['defaults'] = default_accounts

        if node_type == 'user':
            # For a User, blast radius is:
            # 1. Hosts they have access to
            # 2. Other Users on those hosts (lateral movement potential)
            
            # Find hosts accessed by this user (filtered by team)
            host_query = f"""
                MATCH (u:User {{username: $id}})-[:USES]->(h:Host)
                WHERE 1=1 {team_clause} {label_clause}
                RETURN collect(DISTINCT h) as hosts
            """
            result = session.run(host_query, **params)
            _h_rec = result.single()
            hosts = (_h_rec['hosts'] if _h_rec else []) or []
            metrics['host_reach'] = len(hosts)
            details['hosts'] = [h['hostname'] for h in hosts]
            details['platforms'] = list(set([h['platform'] for h in hosts if h.get('platform')]))
            metrics['platform_diversity'] = len(details['platforms'])
            
            # Teams involved
            teams = set()
            for h in hosts:
                if h.get('team_name'):
                    teams.add(h['team_name'])
            # We don't use 'Team Impact' metric anymore, but we keep details
            # metrics['team_impact'] = len(teams) 
            details['teams'] = list(teams)

            # Potential impacted users (people who use the same machines)
            if hosts:
                host_names = [h['hostname'] for h in hosts]
                # Note: We don't filter impacted users by team, we see ALL users on the affected hosts
                # because if a host is compromised, all users on it are at risk regardless of their team.
                # However, the HOSTS themselves were filtered by the team earlier.
                
                user_query = f"""
                    MATCH (u:User)-[:USES]->(h:Host)
                    WHERE h.hostname IN $hostnames {user_exclusion_clause}
                    RETURN collect(DISTINCT u.username) as users
                """
                # Update params with hostnames for this query
                query_params = {**params, "hostnames": host_names}
                
                user_res = session.run(user_query, **query_params)
                user_rec = user_res.single()
                impacted_users = (user_rec['users'] if user_rec else []) or []
                metrics['user_impact'] = len(impacted_users)
                details['users'] = impacted_users

        elif node_type == 'software':
            # For Software, blast radius is:
            # 1. Hosts installed on
            # 2. Users on those hosts
            #
            # Two-step query because the previous one-step COLLECT version
            # returned 0 rows when the team/label scope produced no matching
            # hosts — and `result.single()` was None, crashing on
            # `record['hosts']`. Splitting the metadata fetch from the host
            # set lets us render an empty-blast-radius result cleanly when
            # the operator scopes to a label this software isn't in.
            sw_meta = session.run(
                "MATCH (s:Software {name: $id}) "
                "RETURN s.category AS category, "
                "       s.wikidata_description AS description LIMIT 1",
                id=node_id,
            ).single()
            if sw_meta is None:
                metrics['category'] = None
                metrics['description'] = None
            else:
                metrics['category'] = sw_meta['category']
                metrics['description'] = sw_meta['description']

            host_query = f"""
                MATCH (s:Software {{name: $id}})-[:INSTALLED_ON]->(h:Host)
                WHERE 1=1 {team_clause} {label_clause}
                RETURN collect(DISTINCT h) AS hosts
            """
            host_rec = session.run(host_query, **params).single()
            hosts = (host_rec['hosts'] if host_rec else []) or []
            
            metrics['host_reach'] = len(hosts)
            details['hosts'] = [h['hostname'] for h in hosts]
            details['platforms'] = list(set([h['platform'] for h in hosts if h.get('platform')]))
            metrics['platform_diversity'] = len(details['platforms'])
            
            # Teams involved
            teams = set()
            for h in hosts:
                if h.get('team_name'):
                    teams.add(h['team_name'])
            details['teams'] = list(teams)
            
            # Impacted users
            if hosts:
                host_names = [h['hostname'] for h in hosts]
                
                user_query = f"""
                    MATCH (u:User)-[:USES]->(h:Host)
                    WHERE h.hostname IN $hostnames {user_exclusion_clause}
                    RETURN collect(DISTINCT u.username) as users
                """
                query_params = {**params, "hostnames": host_names}
                
                user_res = session.run(user_query, **query_params)
                user_rec = user_res.single()
                impacted_users = (user_rec['users'] if user_rec else []) or []
                metrics['user_impact'] = len(impacted_users)
                details['users'] = impacted_users
        
        # Calculate Lateral Movement Potential (Threat Hunting Metric)
        # Definition: Count of UNIQUE hosts accessible by the 'impacted_users', EXCLUDING the originally affected hosts.
        # This represents "Where can they go next?"
        
        lateral_hosts = []
        metrics['lateral_movement'] = 0
        
        if details['users'] and len(details['users']) > 0:
            # We have impacted users. Find where they can go.
            # Avoid re-scanning original hosts.
            original_host_names = details['hosts']
            
            lateral_res = session.run("""
                MATCH (u:User)-[:USES]->(h:Host)
                WHERE u.username IN $users 
                  AND NOT h.hostname IN $original_hosts
                RETURN collect(DISTINCT h.hostname) as lateral_hosts
            """, users=details['users'], original_hosts=original_host_names)
            
            _lat_rec = lateral_res.single()
            lateral_hosts = (_lat_rec['lateral_hosts'] if _lat_rec else []) or []
            metrics['lateral_movement'] = len(lateral_hosts)
            
        # Add lateral hosts count to details for potential display (though we might not list them all if too many)
        # details['lateral_hosts'] = lateral_hosts 

        # Calculate normalized scores (0-100) for radar chart
        # Key Change: Use GLOBAL totals for "Team Impact" and others to avoid skewing.
        # If we select a team, the impact is 1 team. 1/TotalTeams is small, but accurate.
        # This prevents "100% Team Impact" when filtering by a single team.

        # Fetch Global Totals (ignoring filters)
        global_totals = session.run("""
            MATCH (h:Host)
            WITH count(h) as total_hosts
            MATCH (u:User)
            WITH total_hosts, count(u) as total_users
            MATCH (t:Team)
            RETURN total_hosts, total_users, count(t) as total_teams
        """).single()
        
        # When normalizing:
        # - Host/User Reach: Normalize against the SCOPE (if I filter by team, 50% of THAT team impacted is high impact).
        # - Team Impact: Normalize against GLOBAL (impacting 1 team out of 20 is "Low" organizational spread).
        
        # Let's refine based on user feedback "shouldn't skew the team to become max".
        # This implies they want Team Impact to be relative to the Whole Org.
        
        global_total_teams = global_totals['total_teams'] if global_totals else 1
        
        # For Host/User, do we normalize against TEAM totals or GLOBAL totals?
        # If I want to see "How bad is this for the team?", I should use Team Totals.
        # If I want to see "How bad is this for the company?", I use Global.
        # Given the "drill down" nature, Team Totals for hosts/users makes sense (saturation of the team).
        # BUT Team Impact must be Global.
        
        # Calculate scoped totals (for Host/User normalization - saturation of the filtered scope)
        if team_filter != 'all':
            scoped_totals = session.run("""
                MATCH (h:Host) WHERE toString(h.team_id) = $team_id
                WITH count(h) as total_hosts
                OPTIONAL MATCH (u:User)-[:USES]->(h:Host) WHERE toString(h.team_id) = $team_id
                RETURN total_hosts, count(DISTINCT u) as total_users
            """, team_id=team_filter).single()
        else:
            scoped_totals = global_totals # Same as global if no filter
            
        total_hosts = scoped_totals['total_hosts'] if scoped_totals else 1
        total_users = scoped_totals['total_users'] if scoped_totals else 1
        
        # Prevent division by zero
        total_hosts = max(total_hosts, 1)
        total_users = max(total_users, 1)
        
        # Normalization for Lateral Movement:
        # Relative to total hosts in the scope? Or Global?
        # Lateral movement usually implies moving ANYWHERE in the org preferably.
        # But if we are scoped to a team, maybe "Lateral movement within team"?
        # If I filter by team, I want to see impact ON THAT TEAM.
        # So lateral movement should probably be filtered by team if a filter is active?
        # My lateral query didn't filter by team.
        # Let's adjust lateral query to respect team filter if present?
        # Actually, lateral movement often crosses team boundaries (that's the danger).
        # So "Lateral Potential" should probably be GLOBAL (where can they go in the whole org?).
        # Let's stick to Global potential for Lateral Move, normalized against GLOBAL total hosts.
        
        global_total_hosts = global_totals['total_hosts'] if global_totals else 1
        global_total_hosts = max(global_total_hosts, 1)

        scores = {
            "Host Reach": min(int((metrics['host_reach'] / total_hosts) * 100), 100),
            "User Impact": min(int((metrics['user_impact'] / total_users) * 100), 100),
            # New Metric: Lateral Movement (Normalized against GLOBAL hosts usually, or maybe scoped?)
            # Let's Use Global Hosts to show "Access to X% of the entire fleet"
            "Lateral Movement": min(int((metrics['lateral_movement'] / global_total_hosts) * 100), 100),
            "Platform Diversity": min(int((metrics['platform_diversity'] / 3) * 100), 100)
        }
        
        return jsonify({
            "metrics": metrics,
            "scores": scores,
            "details": details,
            "scope": {
                "team_filter": team_filter,
                "totals": {
                    "hosts": total_hosts,
                    "users": total_users,
                    "teams": global_total_teams
                }
            }
        })

@app.route("/api/graph")
def get_graph_data():
    """Get graph data formatted for D3.js force layout"""
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500
    
    with driver.session() as session:
        # Get all nodes (only those with relationships)
        nodes = []

        # Host nodes - only hosts that have users connected
        host_result = session.run("""
            MATCH (h:Host)<-[:USES]-(u:User)
            RETURN DISTINCT h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform
        """)
        for record in host_result:
            nodes.append({
                "id": f"host_{record['hostname']}",
                "name": record['hostname'],
                "type": "host",
                "details": f"{record['os_version'] or ''} ({record['platform'] or ''})"
            })

        # User nodes (only those connected to hosts)
        user_result = session.run("""
            MATCH (u:User)-[:USES]->(h:Host)
            RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname
        """)
        for record in user_result:
            nodes.append({
                "id": f"user_{record['username']}",
                "name": record['username'],
                "type": "user",
                "details": record['email'] or record['fullname'] or ''
            })
        
        # Get ONLY user-host relationships for clean initial view
        links = []
        rel_result = session.run("""
            MATCH (u:User)-[r:USES]->(h:Host)
            RETURN 'uses' AS type, u.username AS from_name, h.hostname AS to_host
        """)
        
        for record in rel_result:
            source_id = f"user_{record['from_name']}"
            target_id = f"host_{record['to_host']}"
            
            links.append({
                "source": source_id,
                "target": target_id,
                "type": record['type']
            })
        
        return jsonify({"nodes": nodes, "links": links})

@app.route("/api/graph/full")
def get_full_graph_data():
    """Get scoped graph data including software for expansion.

    Supports the same scoping params as /api/search and /api/shadow-it:
        ?team=<id>           — filter Hosts by team_id
        ?platform=<name>     — filter Hosts by platform substring
        ?labels=A,B          — filter Hosts by HAS_LABEL membership
        ?label_op=AND|OR     — multi-label semantics (default AND)
        ?expr=<json>         — composite boolean expression (alternative)

    Filtering applies at the Host level. Users and Software cascade: only
    surfaces if connected to at least one Host that survived filtering. This
    ensures the graph shows only entities ACTUALLY in the selected scope —
    no orphan apps that aren't part of the chosen labels.
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    # Parse scoping filters once. Apply the same fragment to every host-anchored
    # query (Hosts, Users via h, Software via h) so the cascade is consistent.
    expr_raw = (request.args.get("expr") or "").strip()
    if expr_raw:
        try:
            expr_obj = json.loads(expr_raw)
        except (ValueError, TypeError) as exc:
            return jsonify({
                "error": "Invalid expr",
                "message": f"expr must be valid JSON: {exc}",
            }), 400
        try:
            flt_fragment, flt_params = apply_composite_filter(expr_obj)
        except FilterValidationError as exc:
            return jsonify({"error": "Invalid filter", "message": str(exc)}), 400
    else:
        try:
            flt_fragment, flt_params = apply_host_filters(request.args)
        except FilterValidationError as exc:
            return jsonify({"error": "Invalid filter", "message": str(exc)}), 400

    try:
        with driver.session() as session:
            # Get all nodes including software (only connected nodes)
            nodes = []
            node_ids = set()  # Track node IDs to ensure links are valid

            # Host nodes — only hosts with relationships (users or software).
            # `flt_fragment` always begins with " AND " or is empty, so it
            # appends cleanly after the existing connected-host predicate.
            host_query = (
                "MATCH (h:Host) "
                "WHERE (EXISTS((h)<-[:USES]-(:User)) OR EXISTS((h)<-[:INSTALLED_ON]-(:Software)))"
                + flt_fragment +
                " RETURN h.fleet_host_id AS fleet_host_id, "
                "        h.hostname AS hostname, h.os_version AS os_version, "
                "        h.platform AS platform, h.team_id AS team_id, "
                "        h.team_name AS team_name"
            )
            host_result = session.run(host_query, **flt_params)
            for record in host_result:
                # Node id is keyed on fleet_host_id (stable, unique). hostname
                # carries the current display label. This eliminates duplicate
                # nodes when Fleet reports the same host with different casing.
                node_id = f"host_{record['fleet_host_id']}"
                node_obj = {
                    "id": node_id,
                    "name": record['hostname'],
                    "type": "host",
                    "details": f"{record['os_version'] or ''} ({record['platform'] or ''})",
                }
                if record['team_id'] is not None:
                    node_obj['team_id'] = record['team_id']
                if record['team_name']:
                    node_obj['team_name'] = record['team_name']
                nodes.append(node_obj)
                node_ids.add(node_id)

            # User nodes — only those connected to a host that survived the
            # filter. Without this cascade, the graph would include users from
            # hosts the operator just scoped OUT.
            user_query = (
                "MATCH (u:User)-[:USES]->(h:Host) "
                "WHERE 1=1" + flt_fragment +
                " RETURN DISTINCT u.username AS username, u.email AS email, "
                "        u.fullname AS fullname"
            )
            user_result = session.run(user_query, **flt_params)
            for record in user_result:
                node_id = f"user_{record['username']}"
                nodes.append({
                    "id": node_id,
                    "name": record['username'],
                    "type": "user",
                    "details": record['email'] or record['fullname'] or ''
                })
                node_ids.add(node_id)

            # Software nodes — top 50 by host_count WITHIN the filtered scope.
            # The host_count we report is the in-scope count, not the global
            # count, so the badge ("on N hosts") matches what the operator
            # actually sees in the graph.
            software_query = (
                "MATCH (s:Software)-[:INSTALLED_ON]->(h:Host) "
                "WHERE 1=1" + flt_fragment +
                " WITH s, COUNT(DISTINCT h) AS host_count "
                "ORDER BY host_count DESC "
                "LIMIT 50 "
                "RETURN s.name AS name, s.last_version AS last_version, "
                "        s.category AS category, "
                "        s.wikidata_description AS description, "
                "        host_count"
            )
            software_result = session.run(software_query, **flt_params)
            for record in software_result:
                node_id = f"software_{record['name']}"
                node_obj = {
                    "id": node_id,
                    "name": record['name'],
                    "type": "software",
                    "details": f"Latest: {record['last_version'] or 'unknown'} (on {record['host_count']} hosts)",
                }
                if record['category']:
                    node_obj['category'] = record['category']
                if record['description']:
                    node_obj['description'] = record['description']
                nodes.append(node_obj)
                node_ids.add(node_id)

            # Get relationships - only for nodes that exist
            links = []

            # User-Host relationships — target keyed on fleet_host_id to match
            # the node ids emitted above.
            rel_result = session.run("""
                MATCH (u:User)-[r:USES]->(h:Host)
                RETURN 'uses' AS type, u.username AS from_name,
                       h.fleet_host_id AS to_host_id
            """)
            for record in rel_result:
                source_id = f"user_{record['from_name']}"
                target_id = f"host_{record['to_host_id']}"

                # Only add link if both nodes exist
                if source_id in node_ids and target_id in node_ids:
                    links.append({
                        "source": source_id,
                        "target": target_id,
                        "type": record['type']
                    })

            # Software-Host relationships (only for loaded software nodes)
            # Build list of software names we've loaded to filter the query
            software_names = [node['name'] for node in nodes if node['type'] == 'software']

            if software_names:
                # Query only relationships for the software we've loaded
                # This is much more memory efficient than loading all relationships
                software_rel_result = session.run("""
                    MATCH (s:Software)-[r:INSTALLED_ON]->(h:Host)
                    WHERE s.name IN $software_names
                    RETURN 'installed' AS type, s.name AS from_name,
                           h.fleet_host_id AS to_host_id
                """, software_names=software_names)

                added_software_links = 0
                for record in software_rel_result:
                    source_id = f"software_{record['from_name']}"
                    target_id = f"host_{record['to_host_id']}"

                    # Only add link if both nodes exist
                    if source_id in node_ids and target_id in node_ids:
                        links.append({
                            "source": source_id,
                            "target": target_id,
                            "type": record['type']
                        })
                        added_software_links += 1

                logger.info(f"Software links: {added_software_links} added")

            logger.info(f"Full graph API: Returning {len(nodes)} nodes and {len(links)} links")
            return jsonify({"nodes": nodes, "links": links})

    except TransientError as e:
        error_msg = str(e)
        if "Memory limit exceeded" in error_msg:
            logger.error(f"Memory limit exceeded while loading full graph: {error_msg}")
            payload = {
                "error": "Dataset too large for available memory",
                "message": "The dataset is too large to load all at once. Try increasing Memgraph's memory limit in docker-compose.yml or use the filtered view instead.",
            }
            if DEBUG_ERROR_DETAILS:
                payload["details"] = error_msg
            return jsonify(payload), 507  # HTTP 507 Insufficient Storage
        else:
            logger.error(f"Transient error in get_full_graph_data: {error_msg}")
            payload = {"error": "Database transient error"}
            if DEBUG_ERROR_DETAILS:
                payload["details"] = error_msg
            return jsonify(payload), 503

    except Exception as e:
        logger.error(f"Unexpected error in get_full_graph_data: {e}", exc_info=True)
        payload = {"error": "Internal server error"}
        if DEBUG_ERROR_DETAILS:
            payload["details"] = str(e)
        return jsonify(payload), 500

@app.route("/api/software/<software_name>/hosts")
def get_software_hosts(software_name):
    """Get ALL hosts that have a specific software installed.

    Software names are stored lowercase in the graph (see
    src/ingestion.py — name is normalized at ingest to collapse the
    "Ollama" / "ollama" / "OLLAMA" case-variant duplicates Fleet
    exposes from heterogeneous osquery sources). Lowercase the URL
    param before MATCH so a request for `/api/software/Ollama/hosts`
    resolves to the same node as `/api/software/ollama/hosts`.
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    software_name = (software_name or "").strip().lower()
    if not software_name:
        return jsonify({"error": "Software name required"}), 400

    with driver.session() as session:
        # Check if software exists
        software_check = session.run(
            "MATCH (s:Software {name: $name}) RETURN s.name AS name, s.last_version AS last_version",
            name=software_name
        )
        software_data = software_check.single()
        if not software_data:
            return jsonify({"error": "Software not found"}), 404
        
        nodes = []
        node_ids = set()
        
        # Add the software node
        software_id = f"software_{software_name}"
        nodes.append({
            "id": software_id,
            "name": software_name,
            "type": "software",
            "details": f"Latest: {software_data['last_version'] or 'unknown'}"
        })
        node_ids.add(software_id)
        
        # Get ALL hosts that have this software
        host_result = session.run("""
            MATCH (s:Software {name: $name})-[:INSTALLED_ON]->(h:Host)
            RETURN h.hostname AS hostname, h.os_version AS os_version, h.platform AS platform
        """, name=software_name)
        
        for record in host_result:
            host_id = f"host_{record['hostname']}"
            nodes.append({
                "id": host_id,
                "name": record['hostname'],
                "type": "host",
                "details": f"{record['os_version'] or ''} ({record['platform'] or ''})"
            })
            node_ids.add(host_id)
        
        # Get users connected to these hosts
        user_result = session.run("""
            MATCH (s:Software {name: $name})-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
            RETURN DISTINCT u.username AS username, u.email AS email, u.fullname AS fullname
        """, name=software_name)
        
        for record in user_result:
            user_id = f"user_{record['username']}"
            nodes.append({
                "id": user_id,
                "name": record['username'],
                "type": "user",
                "details": record['email'] or record['fullname'] or ''
            })
            node_ids.add(user_id)
        
        # Get ALL relationships
        links = []
        
        # Software-Host relationships
        software_host_links = session.run("""
            MATCH (s:Software {name: $name})-[:INSTALLED_ON]->(h:Host)
            RETURN h.hostname AS hostname
        """, name=software_name)
        
        for record in software_host_links:
            target_id = f"host_{record['hostname']}"
            if target_id in node_ids:
                links.append({
                    "source": software_id,
                    "target": target_id,
                    "type": "installed"
                })
        
        # User-Host relationships (for hosts that have this software)
        user_host_links = session.run("""
            MATCH (s:Software {name: $name})-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
            RETURN u.username AS username, h.hostname AS hostname
        """, name=software_name)
        
        for record in user_host_links:
            source_id = f"user_{record['username']}"
            target_id = f"host_{record['hostname']}"
            if source_id in node_ids and target_id in node_ids:
                links.append({
                    "source": source_id,
                    "target": target_id,
                    "type": "uses"
                })
        
        logger.info(f"Software {software_name}: Returning {len(nodes)} nodes and {len(links)} links")
        return jsonify({"nodes": nodes, "links": links})

@app.route("/api/host/<hostname>/software")
def get_host_software(hostname):
    """Get ALL software installed on a specific host.

    Looks the host up by case-insensitive hostname so that the side panel
    still resolves when the URL casing differs from the surviving canonical
    casing in the graph (e.g. an old bookmark, a copy-pasted link, or two
    Fleet hosts whose names differ only in case). Once we have the host we
    pivot to its fleet_host_id (stable id) for all subsequent rel lookups
    to guarantee we follow edges of exactly one logical machine.
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    with driver.session() as session:
        # Case-insensitive host lookup. LIMIT 1 because, in the rare event
        # two enrolled Fleet hosts share a lowercased hostname, we pick the
        # one with the most recent activity to populate the side panel.
        host_result = session.run(
            "MATCH (h:Host) "
            "WHERE toLower(h.hostname) = toLower($hostname) "
            "RETURN h.fleet_host_id AS fleet_host_id, h.hostname AS hostname, "
            "       h.os_version AS os_version, h.platform AS platform "
            "ORDER BY h.last_seen DESC LIMIT 1",
            hostname=hostname
        )
        host_data = host_result.single()
        if not host_data:
            return jsonify({"error": "Host not found"}), 404

        fleet_host_id = host_data['fleet_host_id']
        canonical_hostname = host_data['hostname']

        nodes = []
        node_ids = set()

        # Add the host node — id keyed on fleet_host_id, name shows the
        # canonical (most-recently-ingested) hostname casing.
        host_id = f"host_{fleet_host_id}"
        nodes.append({
            "id": host_id,
            "name": canonical_hostname,
            "type": "host",
            "details": f"{host_data['os_version'] or ''} ({host_data['platform'] or ''})"
        })
        node_ids.add(host_id)

        # Get ALL users connected to this host — match by fleet_host_id.
        user_result = session.run("""
            MATCH (u:User)-[:USES]->(h:Host {fleet_host_id: $fleet_host_id})
            RETURN u.username AS username, u.email AS email, u.fullname AS fullname
        """, fleet_host_id=fleet_host_id)

        for record in user_result:
            user_id = f"user_{record['username']}"
            nodes.append({
                "id": user_id,
                "name": record['username'],
                "type": "user",
                "details": record['email'] or record['fullname'] or ''
            })
            node_ids.add(user_id)

        # Get ALL software installed on this host
        software_result = session.run("""
            MATCH (s:Software)-[:INSTALLED_ON]->(h:Host {fleet_host_id: $fleet_host_id})
            RETURN s.name AS name, s.last_version AS last_version
            ORDER BY s.name
        """, fleet_host_id=fleet_host_id)

        for record in software_result:
            software_id = f"software_{record['name']}"
            nodes.append({
                "id": software_id,
                "name": record['name'],
                "type": "software",
                "details": f"Latest: {record['last_version'] or 'unknown'}"
            })
            node_ids.add(software_id)

        # Get ALL relationships for this host
        links = []

        # User-Host relationships
        user_links = session.run("""
            MATCH (u:User)-[:USES]->(h:Host {fleet_host_id: $fleet_host_id})
            RETURN u.username AS username
        """, fleet_host_id=fleet_host_id)

        for record in user_links:
            source_id = f"user_{record['username']}"
            if source_id in node_ids:
                links.append({
                    "source": source_id,
                    "target": host_id,
                    "type": "uses"
                })

        # Software-Host relationships
        software_links = session.run("""
            MATCH (s:Software)-[:INSTALLED_ON]->(h:Host {fleet_host_id: $fleet_host_id})
            RETURN s.name AS name
        """, fleet_host_id=fleet_host_id)

        for record in software_links:
            source_id = f"software_{record['name']}"
            if source_id in node_ids:
                links.append({
                    "source": source_id,
                    "target": host_id,
                    "type": "installed"
                })

        logger.info(f"Host {canonical_hostname} (id={fleet_host_id}): Returning {len(nodes)} nodes and {len(links)} links")
        return jsonify({"nodes": nodes, "links": links})

@app.route("/api/meta")
def get_meta():
    """Lightweight summary used by the dashboard's top-bar pill.

    Returns total host / user / software counts. Cheap query — uses node-label
    counts which Memgraph keeps O(1)-ish in IN_MEMORY_TRANSACTIONAL mode.
    """
    if not driver:
        return jsonify({"hosts": 0, "users": 0, "software": 0, "connected": False}), 200
    try:
        with driver.session() as session:
            result = session.run("""
                MATCH (h:Host) WITH count(h) AS hosts
                OPTIONAL MATCH (u:User)-[:USES]->(:Host) WITH hosts, count(DISTINCT u) AS users
                OPTIONAL MATCH (s:Software) RETURN hosts, users, count(s) AS software
            """).single()
        if not result:
            return jsonify({"hosts": 0, "users": 0, "software": 0, "connected": True}), 200
        return jsonify({
            "hosts": result["hosts"] or 0,
            "users": result["users"] or 0,
            "software": result["software"] or 0,
            "connected": True,
        }), 200
    except Exception as exc:  # noqa: BLE001
        logger.warning("meta query failed: %s", exc)
        return jsonify({"hosts": 0, "users": 0, "software": 0, "connected": False}), 200


@app.route("/api/health")
def health_check():
    """Health check endpoint for monitoring.

    Doubles as the autonomy bootstrap: the Docker healthcheck hits this
    every 30s, so the enricher and OODA supervisor boot on the first
    healthcheck after startup without requiring an operator request.
    """
    _ensure_enricher_started()
    _ensure_ooda_started()
    if not driver:
        return jsonify({
            "status": "unhealthy",
            "database": "disconnected"
        }), 503

    try:
        with driver.session() as session:
            result = session.run("RETURN 1")
            result.single()
        return jsonify({
            "status": "healthy",
            "database": "connected",
            "memgraph_uri": MEMGRAPH_URI
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        payload = {
            "status": "unhealthy",
            "database": "error",
        }
        if DEBUG_ERROR_DETAILS:
            payload["error"] = str(e)
        return jsonify(payload), 503

@app.route("/api/authorize-software", methods=['POST'])
def authorize_software():
    """Authorize a software (whitelist it)"""
    try:
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"error": "Invalid JSON body"}), 400

        software_name = (data.get('software_name') or '').strip()
        
        if not software_name:
            return jsonify({"error": "Software name required"}), 400

        if len(software_name) > 500:
            return jsonify({
                "error": "Software name too long",
                "message": "software_name must be <= 500 characters",
            }), 400
            
        whitelist = load_whitelist()
        if software_name not in whitelist:
            whitelist.append(software_name)
            save_whitelist(whitelist)
            audit_log("AUTHORIZE", f"Authorized software: {software_name}")
            logger.info(f"Authorized software: {software_name}")
            
        return jsonify({"status": "success", "message": f"{software_name} authorized"}), 200
    except Exception as e:
        logger.error(f"Error authorizing software: {e}", exc_info=True)
        payload = {"error": "Internal server error"}
        if DEBUG_ERROR_DETAILS:
            payload["details"] = str(e)
        return jsonify(payload), 500

@app.route("/api/shadow-it")
def get_shadow_it():
    """Detect Shadow IT - unauthorized or risky software installations.
    
    Query parameters:
    - team: team filter ('all' or team_id)
    - platform: platform filter ('all', 'windows', 'darwin', 'ubuntu')
    - risk: risk level filter ('all', 'high', 'medium', 'low')
    - detection_type: detection type filter ('all', 'outlier', 'high_risk', 'version_sprawl')
    
    Returns Shadow IT detections with risk scores and recommendations.
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    team_filter = request.args.get('team', 'all')
    platform_filter = request.args.get('platform', 'all').lower()
    risk_filter = request.args.get('risk', 'all').lower()
    detection_type_filter = request.args.get('detection_type', 'all').lower()
    host_count_filter = request.args.get('host_count', 'all')  # New filter
    user_count_filter = request.args.get('user_count', 'all')  # New filter
    software_type_filter = request.args.get('software_type', 'all')  # New filter

    # Label scoping (plan 1E): bolted on additively. label_flt_fragment
    # is appended to each detection query's WHERE chain alongside team_clause
    # and platform_clause; label_flt_params merge into filter_params.
    try:
        label_flt_fragment, label_flt_params = apply_label_filter(request.args)
    except FilterValidationError as exc:
        return jsonify({"error": "Invalid filter", "message": str(exc)}), 400
    
    # Software type detection patterns
    def detect_software_type(software_name):
        """Detect the type of software based on name patterns"""
        name_lower = software_name.lower()
        
        # Browser Extensions
        if any(x in name_lower for x in ['-extension', 'chrome extension', 'firefox addon', 'safari extension', 'edge extension']):
            return 'Browser Extension'
        
        # VSCode Extensions  
        if any(x in name_lower for x in ['vscode-', '.vscode', 'code-extension']):
            return 'VSCode Extension'
        
        # Package Managers
        if name_lower.startswith('npm:') or name_lower.startswith('@'):
            return 'npm Package'
        if name_lower.startswith('pip:') or name_lower.startswith('python-'):
            return 'Python Package'
        if name_lower.startswith('gem:'):
            return 'Ruby Gem'
        
        # Operating System Components
        if any(x in name_lower for x in ['microsoft', 'windows', 'macos', 'darwin', 'linux', 'ubuntu']):
            return 'OS Component'
        
        # Development Tools
        if any(x in name_lower for x in ['git', 'node', 'python', 'java', 'docker', 'kubernetes']):
            return 'Developer Tool'
        
        # Default
        return 'Application'
    
    # High-risk Shadow IT patterns. Curated list of specific brand/binary names
    # that are end-user-installable and bypass IT review. All matches are
    # word-boundary, not substring (see _word_match).
    #
    # Deliberately excluded:
    #   * Generic terms ('line', 'voip', 'vpn', 'remote desktop',
    #     'instant messaging', 'videotelephony', 'cryptocurrency', 'bitcoin',
    #     'anonymizing proxy', 'file sharing', 'penetration testing').
    #     These match either OS components (readline -> 'line', RDP -> 'remote
    #     desktop') or are too broad to drive a security action.
    #   * Sanctioned dual-use dev/security tools (docker, virtualbox, vmware,
    #     wireshark, burp suite, metasploit, nmap, aircrack). These are
    #     legitimate engineering tools; an outlier check on non-engineering
    #     teams is the right signal, not a blanket high-risk flag.
    HIGH_RISK_PATTERNS = {
        # Personal remote-access tools — data exfil risk, bypasses jump-host policy.
        'Remote Access Tools': [
            'teamviewer', 'anydesk', 'chrome remote desktop', 'logmein',
            'gotomypc', 'remotepc', 'splashtop', 'realvnc', 'tightvnc',
            'ultravnc', 'screenconnect', 'connectwise control', 'parsec',
        ],
        # Personal file-sync — DLP bypass, exfil risk.
        'File Sharing': [
            'dropbox', 'wetransfer', 'mega', 'sync.com', 'tresorit', 'pcloud',
            'bittorrent', 'utorrent', 'qbittorrent', 'transmission',
            'deluge', 'vuze', 'frostwire', 'limewire',
        ],
        # Personal messaging — bypasses corporate IM/DLP.
        'Communication Apps': [
            'telegram', 'telegram desktop',
            'signal', 'signal desktop',
            'whatsapp', 'whatsapp desktop',
            'discord', 'wechat', 'viber', 'kik messenger', 'qq', 'skype',
        ],
        # Crypto miners — almost always shadow IT or compromise indicator.
        'Cryptocurrency Mining': [
            'nicehash', 'cgminer', 'ethminer', 'xmrig', 'phoenixminer',
            'claymore miner', 'minergate', 'bfgminer', 'sgminer', 'lolminer',
            't-rex miner', 'gminer', 'teamredminer',
        ],
        # Privacy / anonymity / personal VPNs (specific brands only — generic
        # 'vpn' catches enterprise VPN clients).
        'Tor/Privacy Tools': [
            'tor browser', 'tails', 'proxifier', 'psiphon', 'tunnelbear',
            'nordvpn', 'expressvpn', 'protonvpn', 'mullvad', 'surfshark',
            'private internet access', 'cyberghost', 'ipvanish',
            'hotspot shield',
        ],
    }
    
    
    with driver.session() as session:
        # Per-platform outlier thresholds. SHADOW_IT_OUTLIER_PCT (env, default
        # 3%) controls the percentage. Per-platform avoids the global-threshold
        # bug where a software on 1 of 10 Linux servers and a software on 1 of
        # 100 Windows hosts would both count the same toward outlier scoring,
        # even though the first is a much stronger signal.
        outlier_pct = _get_outlier_pct()
        platform_thresholds = _compute_per_platform_thresholds(session, outlier_pct)

        # The detection queries below operate on a single composite scope
        # (team_clause + platform_clause + label_clause). Use the MOST
        # restrictive matching threshold across the platforms in scope:
        #   - platform_filter set: use that platform's threshold
        #   - platform_filter='all': use max threshold across platforms (so
        #     software has to be rare on every platform it appears on, not
        #     just one)
        # Falls back to a global-style computation if the platform map is
        # empty (no hosts ingested yet).
        if platform_thresholds:
            if platform_filter and platform_filter != 'all':
                # Best-effort lookup; Fleet platforms are stored as strings
                # like "darwin", "windows", "ubuntu", "rhel". Match
                # case-insensitively with substring rules to mirror the
                # frontend's behavior.
                pf_lower = platform_filter.lower()
                matched = [
                    t for p, t in platform_thresholds.items()
                    if p and pf_lower in p.lower()
                ]
                OUTLIER_THRESHOLD = (
                    max(matched) if matched else max(platform_thresholds.values())
                )
            else:
                OUTLIER_THRESHOLD = max(platform_thresholds.values())
        else:
            total_hosts_count = (
                session.run("MATCH (h:Host) RETURN count(h) AS count")
                .single()['count'] or 1
            )
            OUTLIER_THRESHOLD = max(_MIN_OUTLIER_HOSTS, int(total_hosts_count * outlier_pct))

        detections = []
        detection_id_counter = 1
        
        # Load whitelist
        whitelist = load_whitelist()
        
        # Build team and platform filters
        team_clause = ""
        platform_clause = ""
        whitelist_clause = ""
        # label_clause is the apply_label_filter fragment renamed for visual
        # parity with the other inline clauses. Always begins with " AND " or
        # is empty; injects into the same `WHERE 1=1 {team_clause} ...` chain.
        label_clause = label_flt_fragment
        filter_params = {}

        if team_filter != 'all':
            team_clause = "AND toString(h.team_id) = $team_id"
            filter_params['team_id'] = team_filter

        if platform_filter != 'all':
            platform_clause = "AND toLower(h.platform) CONTAINS toLower($platform)"
            filter_params['platform'] = platform_filter

        if whitelist:
            whitelist_clause = "AND NOT s.name IN $whitelist"
            filter_params['whitelist'] = whitelist

        filter_params.update(label_flt_params)
        
        # ===== DETECTION 1: Outlier Software (installed on very few hosts) =====
        if detection_type_filter in ['all', 'outlier']:
            outlier_query = f"""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE 1=1 {team_clause} {platform_clause} {whitelist_clause} {label_clause}
                WITH s.name AS software_name, s.last_version AS version,
                     s.category AS db_category, s.wikidata_description AS db_desc,
                     s.sources AS db_sources,
                     COUNT(DISTINCT h) AS host_count,
                     COLLECT(DISTINCT h.hostname) AS hosts,
                     COLLECT(DISTINCT h.platform) AS platforms
                WHERE host_count <= $outlier_threshold
                RETURN software_name, version, host_count, hosts, platforms,
                       db_category, db_desc, db_sources
                ORDER BY host_count ASC, software_name ASC
            """
            
            # Add outlier_threshold to filter_params
            filter_params['outlier_threshold'] = OUTLIER_THRESHOLD
            
            result = session.run(outlier_query, **filter_params)
            for record in result:
                # Skip OS-managed system packages, dev-language transitive deps,
                # and browser/IDE extensions — none are user-chosen apps. The
                # `sources` field carries the osquery install channel
                # (apps, programs, deb_packages, npm_packages, vscode_extensions
                # ...) and is the strongest signal.
                if _is_system_package(
                    record['software_name'],
                    record.get('db_category') or [],
                    record.get('db_sources') or [],
                ):
                    continue

                # Get users on affected hosts
                users_query = """
                    MATCH (s:Software {name: $software_name})-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
                    RETURN COLLECT(DISTINCT u.username) AS users
                """
                users_result = session.run(users_query, software_name=record['software_name'])
                users_record = users_result.single()
                users = users_record['users'] if users_record else []

                # Risk level based on install count
                risk_level = "high" if record['host_count'] == 1 else "medium"
                
                # Apply host count filter
                if host_count_filter != 'all':
                    if host_count_filter == '1' and record['host_count'] != 1 or host_count_filter == '2' and record['host_count'] != 2 or host_count_filter == '3+' and record['host_count'] < 3:
                        continue
                
                # Apply user count filter
                user_count = len(users)
                if user_count_filter != 'all':
                    if user_count_filter == '1' and user_count != 1 or user_count_filter == '2' and user_count != 2 or user_count_filter == '3+' and user_count < 3:
                        continue
                
                # Detect software type
                software_type = detect_software_type(record['software_name'])

                # Apply software type filter
                if software_type_filter != 'all' and software_type != software_type_filter:
                    continue
                
                if risk_filter == 'all' or risk_filter == risk_level:
                    detections.append({
                        "id": f"outlier_{detection_id_counter}",
                        "software_name": record['software_name'],
                        "software_type": software_type,
                        "risk_level": risk_level,
                        "category": "Outlier Software",
                        "db_category": record.get('db_category'),
                        "wikidata_description": record.get('db_desc'),
                        "detection_type": "outlier",
                        "host_count": record['host_count'],
                        "affected_hosts": record['hosts'],
                        "affected_users": users,
                        "platforms": record['platforms'],
                        "version": record['version'] or "Unknown",
                        "recommendation": f"Verify if this software is authorized. Found on only {record['host_count']} host(s). Consider removing if unauthorized.",
                        "details": f"Installed on {record['host_count']} host(s) only - unusual for enterprise software",
                        "risk_reason": f"Risk is {risk_level.upper()} because this software is installed on only {record['host_count']} host(s) (<{OUTLIER_THRESHOLD} threshold).",
                    })
                    detection_id_counter += 1
        
        # ===== DETECTION 2: High-Risk Category Software =====
        if detection_type_filter in ['all', 'high_risk']:
            # Get all software
            all_software_query = f"""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE 1=1 {team_clause} {platform_clause} {whitelist_clause} {label_clause}
                WITH s.name AS software_name, s.last_version AS version,
                     s.category AS db_category, s.wikidata_description AS db_desc,
                     s.sources AS db_sources,
                     COUNT(DISTINCT h) AS host_count,
                     COLLECT(DISTINCT h.hostname) AS hosts,
                     COLLECT(DISTINCT h.platform) AS platforms
                RETURN software_name, version, host_count, hosts, platforms,
                       db_category, db_desc, db_sources
            """
            
            result = session.run(all_software_query, **filter_params)

            for record in result:
                software_lower = record['software_name'].lower()
                db_categories = record.get('db_category') or []
                db_sources = record.get('db_sources') or []

                # Skip OS-managed system packages, dev-language transitive deps,
                # and browser/IDE extensions outright — none of these are
                # Shadow IT regardless of name overlap with high-risk patterns.
                if _is_system_package(record['software_name'], db_categories, db_sources):
                    continue

                matched_category = None

                # 1. Wikidata category-based matching first (highest signal:
                # the enrichment job has already classified the software).
                for db_cat in db_categories:
                    db_cat_lower = db_cat.lower()
                    for category, patterns in HIGH_RISK_PATTERNS.items():
                        if _word_match(category.lower(), db_cat_lower) or any(
                            _word_match(p, db_cat_lower) for p in patterns
                        ):
                            matched_category = category
                            break
                    if matched_category:
                        break

                # 2. Fallback: word-boundary match on software name. Plain
                # substring match is unsafe (libreadline8 -> 'line').
                if not matched_category:
                    for category, patterns in HIGH_RISK_PATTERNS.items():
                        for pattern in patterns:
                            if _word_match(pattern, software_lower):
                                matched_category = category
                                break
                        if matched_category:
                            break

                if matched_category:
                    # Get users on affected hosts
                    users_query = """
                        MATCH (s:Software {name: $software_name})-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
                        RETURN COLLECT(DISTINCT u.username) AS users
                    """
                    users_result = session.run(users_query, software_name=record['software_name'])
                    users_record = users_result.single()
                    users = users_record['users'] if users_record else []
                    
                    # All high-risk category detections are high risk
                    risk_level = "high"
                    
                    # Apply host count filter
                    if host_count_filter != 'all':
                        if host_count_filter == '1' and record['host_count'] != 1 or host_count_filter == '2' and record['host_count'] != 2 or host_count_filter == '3+' and record['host_count'] < 3:
                            continue
                    
                    # Apply user count filter
                    user_count = len(users)
                    if user_count_filter != 'all':
                        if user_count_filter == '1' and user_count != 1 or user_count_filter == '2' and user_count != 2 or user_count_filter == '3+' and user_count < 3:
                            continue
                    
                    # Detect software type
                    software_type = detect_software_type(record['software_name'])
                    
                    # Apply software type filter
                    if software_type_filter != 'all' and software_type != software_type_filter:
                        continue
                    
                    if risk_filter == 'all' or risk_filter == risk_level:
                        # Category-specific recommendations. Keys must match
                        # HIGH_RISK_PATTERNS exactly.
                        recommendations = {
                            'Remote Access Tools': "Verify authorization. Remote access tools can be used for data exfiltration. Replace with approved enterprise solution.",
                            'File Sharing': "Verify authorization. File sharing apps may lead to data leakage. Use approved enterprise file sharing.",
                            'Communication Apps': "Verify authorization. Unofficial communication apps may bypass DLP policies. Use approved enterprise messaging.",
                            'Cryptocurrency Mining': "CRITICAL: Remove immediately. Cryptocurrency miners consume resources and may indicate compromise.",
                            'Tor/Privacy Tools': "CRITICAL: Investigate immediately. Privacy/anonymity tools may indicate malicious activity or policy violation.",
                        }
                        
                        detections.append({
                            "id": f"highrisk_{detection_id_counter}",
                            "software_name": record['software_name'],
                            "software_type": software_type,
                            "risk_level": risk_level,
                            "category": matched_category,
                            "detection_type": "high_risk",
                            "host_count": record['host_count'],
                            "affected_hosts": record['hosts'],
                            "affected_users": users,
                            "platforms": record['platforms'],
                            "version": record['version'] or "Unknown",
                            "recommendation": recommendations.get(matched_category, "Review and verify authorization"),
                            "details": f"High-risk category: {matched_category}",
                            "risk_reason": f"Risk is HIGH because '{record['software_name']}' matches the '{matched_category}' category, which is flagged for security review."
                        })
                        detection_id_counter += 1
        
        # ===== DETECTION 3: Version Sprawl (multiple versions of same software) =====
        if detection_type_filter in ['all', 'version_sprawl']:
            version_sprawl_query = f"""
                MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
                WHERE s.last_version IS NOT NULL
                  AND s.last_version <> ''
                  {team_clause} {platform_clause} {whitelist_clause} {label_clause}
                WITH s.name AS software_name,
                     s.category AS db_category,
                     s.sources AS db_sources,
                     COUNT(DISTINCT s.last_version) AS version_count,
                     COLLECT(DISTINCT s.last_version) AS versions,
                     COUNT(DISTINCT h) AS host_count,
                     COLLECT(DISTINCT h.hostname) AS hosts
                WHERE version_count > 2
                RETURN software_name, db_category, db_sources, version_count, versions, host_count, hosts
                ORDER BY version_count DESC
                LIMIT 20
            """

            result = session.run(version_sprawl_query, **filter_params)
            for record in result:
                # System packages, dev-language deps, and extensions routinely
                # show many versions across distro releases / lockfile drift —
                # that's package-manager state, not Shadow IT.
                if _is_system_package(
                    record['software_name'],
                    record.get('db_category') or [],
                    record.get('db_sources') or [],
                ):
                    continue

                # Get users on affected hosts
                users_query = """
                    MATCH (s:Software {name: $software_name})-[:INSTALLED_ON]->(h:Host)<-[:USES]-(u:User)
                    RETURN COLLECT(DISTINCT u.username) AS users
                """
                users_result = session.run(users_query, software_name=record['software_name'])
                users_record = users_result.single()
                users = users_record['users'] if users_record else []
                
                # Risk level based on version count
                if record['version_count'] > 5:
                    risk_level = "high"
                elif record['version_count'] > 3:
                    risk_level = "medium"
                else:
                    risk_level = "low"
                
                # Apply host count filter
                if host_count_filter != 'all':
                    if host_count_filter == '1' and record['host_count'] != 1 or host_count_filter == '2' and record['host_count'] != 2 or host_count_filter == '3+' and record['host_count'] < 3:
                        continue
                
                # Apply user count filter
                user_count = len(users)
                if user_count_filter != 'all':
                    if user_count_filter == '1' and user_count != 1 or user_count_filter == '2' and user_count != 2 or user_count_filter == '3+' and user_count < 3:
                        continue
                
                # Detect software type
                software_type = detect_software_type(record['software_name'])

                # Apply software type filter
                if software_type_filter != 'all' and software_type != software_type_filter:
                    continue
                
                if risk_filter == 'all' or risk_filter == risk_level:
                    detections.append({
                        "id": f"sprawl_{detection_id_counter}",
                        "software_name": record['software_name'],
                        "software_type": software_type,
                        "risk_level": risk_level,
                        "category": "Version Management",
                        "detection_type": "version_sprawl",
                        "host_count": record['host_count'],
                        "affected_hosts": record['hosts'],
                        "affected_users": users,
                        "platforms": [],
                        "version": f"{record['version_count']} versions: {', '.join(record['versions'][:3])}{'...' if len(record['versions']) > 3 else ''}",
                        "recommendation": f"Standardize software versions across fleet. Currently running {record['version_count']} different versions.",
                        "details": f"Version sprawl detected - {record['version_count']} different versions installed",
                        "risk_reason": f"Risk is {risk_level.upper()} because there are {record['version_count']} distinct versions installed, indicating poor patch management."
                    })
                    detection_id_counter += 1
        
        # ===== Calculate Summary Metrics =====
        summary = {
            "total_detections": len(detections),
            "high_risk": len([d for d in detections if d['risk_level'] == 'high']),
            "medium_risk": len([d for d in detections if d['risk_level'] == 'medium']),
            "low_risk": len([d for d in detections if d['risk_level'] == 'low']),
            "affected_hosts": len(set([host for d in detections for host in d['affected_hosts']])),
            "affected_users": len(set([user for d in detections for user in d['affected_users']])),
        }
        
        # Calculate category distribution
        risk_distribution = {}
        for detection in detections:
            category = detection['category']
            risk_distribution[category] = risk_distribution.get(category, 0) + 1
        
        logger.info(f"Shadow IT scan (team: {team_filter}, platform: {platform_filter}): {summary['total_detections']} detections")
        
        return jsonify({
            "summary": summary,
            "detections": detections,
            "risk_distribution": risk_distribution,
            "filters": {
                "team": team_filter,
                "platform": platform_filter,
                "risk": risk_filter,
                "detection_type": detection_type_filter
            }
        })

_TYPED_ID_RE = re.compile(r"^(host|user|software)_(.+)$")


def _resolve_typed_id(typed_id: str):
    """Parse `host_<hostname>` / `user_<username>` / `software_<name>` into (kind, name).

    Returns (None, None) on bad input.
    """
    if not typed_id or len(typed_id) > 400:
        return None, None
    m = _TYPED_ID_RE.match(typed_id)
    if not m:
        return None, None
    return m.group(1), m.group(2)


def _node_label_for_kind(kind: str) -> str:
    return {"host": "Host", "user": "User", "software": "Software"}[kind]


def _key_prop_for_kind(kind: str) -> str:
    return {"host": "hostname", "user": "username", "software": "name"}[kind]


def _serialize_graph_node(record_obj):
    """Map a Memgraph node object to the same node shape as /api/graph/full."""
    labels = list(record_obj.labels) if hasattr(record_obj, "labels") else []
    props = dict(record_obj) if record_obj else {}

    if "Host" in labels:
        hostname = props.get("hostname")
        if not hostname:
            return None
        node = {
            "id": f"host_{hostname}",
            "name": hostname,
            "type": "host",
            "details": f"{props.get('os_version') or ''} ({props.get('platform') or ''})",
        }
        if props.get("team_id") is not None:
            node["team_id"] = props.get("team_id")
        if props.get("team_name"):
            node["team_name"] = props.get("team_name")
        return node
    if "User" in labels:
        username = props.get("username")
        if not username:
            return None
        return {
            "id": f"user_{username}",
            "name": username,
            "type": "user",
            "details": props.get("email") or props.get("fullname") or "",
        }
    if "Software" in labels:
        name = props.get("name")
        if not name:
            return None
        node = {
            "id": f"software_{name}",
            "name": name,
            "type": "software",
            "details": f"Latest: {props.get('last_version') or 'unknown'}",
        }
        if props.get("category"):
            node["category"] = props["category"]
        if props.get("wikidata_description"):
            node["description"] = props["wikidata_description"]
        return node
    return None


def _link_type_for_rel(rel_type: str) -> str:
    return {"USES": "uses", "INSTALLED_ON": "installed"}.get(rel_type, rel_type.lower())


@app.route("/api/path")
def get_path():
    """Shortest path between two typed-id nodes via USES / INSTALLED_ON edges.

    Query: from=<typed-id>&to=<typed-id>&max_hops=<1..6>
    Returns: {nodes, links, ordered_ids}
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    from_id = request.args.get("from", "").strip()
    to_id = request.args.get("to", "").strip()
    try:
        max_hops = int(request.args.get("max_hops", 4))
    except ValueError:
        max_hops = 4
    if max_hops < 1 or max_hops > 6:
        return jsonify({"error": "max_hops must be between 1 and 6"}), 400

    a_kind, a_name = _resolve_typed_id(from_id)
    b_kind, b_name = _resolve_typed_id(to_id)
    if not a_kind or not b_kind:
        return jsonify({"error": "Invalid typed id; expected <type>_<name>"}), 400

    # Identity case: same node both endpoints. Skip the DB roundtrip and return
    # a degenerate "path" containing just that node so the client can render it.
    if from_id == to_id:
        a_label = _node_label_for_kind(a_kind)
        a_key = _key_prop_for_kind(a_kind)
        try:
            with driver.session() as session:
                rec = session.run(
                    f"MATCH (n:{a_label} {{{a_key}: $name}}) RETURN n LIMIT 1",
                    name=a_name,
                ).single()
        except Exception as exc:
            logger.error("path identity lookup failed: %s", exc)
            return jsonify({"error": "Internal server error"}), 500
        if not rec:
            return jsonify({"error": "Node not found"}), 404
        node_obj = _serialize_graph_node(rec["n"])
        if not node_obj:
            return jsonify({"error": "Node not found"}), 404
        return jsonify({
            "nodes": [node_obj],
            "links": [],
            "ordered_ids": [node_obj["id"]],
        })

    a_label = _node_label_for_kind(a_kind)
    b_label = _node_label_for_kind(b_kind)
    a_key = _key_prop_for_kind(a_kind)
    b_key = _key_prop_for_kind(b_kind)

    # Strategy 1: Memgraph BFS extension — fastest, returns shortest path natively.
    # Strategy 2: Standard variable-length pattern with manual ORDER BY length(p).
    #             Used when the BFS syntax is rejected by older Memgraph versions.
    cypher_bfs = (
        f"MATCH (a:{a_label} {{{a_key}: $aname}}), (b:{b_label} {{{b_key}: $bname}}) "
        f"MATCH p = (a)-[:USES|INSTALLED_ON *BFS 1..{max_hops}]-(b) "
        f"RETURN nodes(p) AS ns, relationships(p) AS rs LIMIT 1"
    )
    cypher_varlen = (
        f"MATCH (a:{a_label} {{{a_key}: $aname}}), (b:{b_label} {{{b_key}: $bname}}) "
        f"MATCH p = (a)-[:USES|INSTALLED_ON *1..{max_hops}]-(b) "
        f"RETURN nodes(p) AS ns, relationships(p) AS rs "
        f"ORDER BY length(p) ASC LIMIT 1"
    )

    rec = None
    strategy_used = None
    try:
        with driver.session() as session:
            rec = session.run(cypher_bfs, aname=a_name, bname=b_name).single()
        strategy_used = "bfs"
    except TransientError as exc:
        logger.warning("path BFS transient: %s", exc)
        return jsonify({"error": "Database transient error"}), 503
    except ClientError as exc:
        logger.info("path BFS syntax not supported, falling back to variable-length: %s", exc)
        try:
            with driver.session() as session:
                rec = session.run(cypher_varlen, aname=a_name, bname=b_name).single()
            strategy_used = "varlen"
        except (TransientError, ClientError) as exc2:
            logger.warning("path varlen failed: %s", exc2)
            return jsonify({"error": "Database transient error"}), 503
        except Exception as exc2:
            logger.error("path varlen unexpected error: %s", exc2, exc_info=True)
            return jsonify({"error": "Path query failed"}), 500
    except Exception as exc:
        logger.error("path query unexpected error: %s", exc, exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

    if not rec:
        logger.info("path: no path between %s and %s within %d hops (strategy=%s)",
                    from_id, to_id, max_hops, strategy_used or "?")
        return jsonify({"nodes": [], "links": [], "ordered_ids": []})

    logger.info("path: %s -> %s (strategy=%s)", from_id, to_id, strategy_used)

    nodes_raw = rec["ns"] or []
    rels_raw = rec["rs"] or []

    nodes = []
    seen_ids = set()
    ordered_ids = []
    for n in nodes_raw:
        node_obj = _serialize_graph_node(n)
        if not node_obj:
            continue
        ordered_ids.append(node_obj["id"])
        if node_obj["id"] not in seen_ids:
            nodes.append(node_obj)
            seen_ids.add(node_obj["id"])

    links = []
    for idx, r in enumerate(rels_raw):
        if idx >= len(ordered_ids) - 1:
            break
        links.append({
            "source": ordered_ids[idx],
            "target": ordered_ids[idx + 1],
            "type": _link_type_for_rel(r.type if hasattr(r, "type") else "USES"),
        })

    return jsonify({"nodes": nodes, "links": links, "ordered_ids": ordered_ids})


@app.route("/api/correlate")
def get_correlate():
    """Ego network for a typed-id node.

    Query: id=<typed-id>&depth=<1..3>
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    typed_id = request.args.get("id", "").strip()
    try:
        depth = int(request.args.get("depth", 2))
    except ValueError:
        depth = 2
    if depth < 1 or depth > 3:
        return jsonify({"error": "depth must be between 1 and 3"}), 400

    kind, name = _resolve_typed_id(typed_id)
    if not kind:
        return jsonify({"error": "Invalid typed id; expected <type>_<name>"}), 400

    label = _node_label_for_kind(kind)
    key = _key_prop_for_kind(kind)

    cypher = (
        f"MATCH (n:{label} {{{key}: $name}})-[r:USES|INSTALLED_ON *1..{depth}]-(m) "
        f"RETURN n, m, r"
    )

    try:
        with driver.session() as session:
            recs = list(session.run(cypher, name=name))
    except TransientError as exc:
        logger.warning("correlate transient: %s", exc)
        return jsonify({"error": "Database transient error"}), 503
    except Exception as exc:
        logger.error("correlate failed: %s", exc)
        return jsonify({"error": "Correlate query failed"}), 500

    nodes_by_id = {}
    link_keys = set()
    links = []

    for rec in recs:
        for graph_node in (rec.get("n"), rec.get("m")):
            obj = _serialize_graph_node(graph_node)
            if obj:
                nodes_by_id[obj["id"]] = obj
        rels = rec.get("r") or []
        # Walk the relationship list — each rel has start_node / end_node / type.
        for r in rels:
            try:
                start_obj = _serialize_graph_node(r.start_node)
                end_obj = _serialize_graph_node(r.end_node)
            except AttributeError:
                continue
            if not start_obj or not end_obj:
                continue
            nodes_by_id[start_obj["id"]] = start_obj
            nodes_by_id[end_obj["id"]] = end_obj
            # USES edges always go user -> host, INSTALLED_ON go software -> host.
            # Normalise direction for the frontend.
            if r.type == "USES":
                src, tgt = (start_obj, end_obj) if start_obj["type"] == "user" else (end_obj, start_obj)
            elif r.type == "INSTALLED_ON":
                src, tgt = (start_obj, end_obj) if start_obj["type"] == "software" else (end_obj, start_obj)
            else:
                src, tgt = start_obj, end_obj
            key_str = f"{r.type}::{src['id']}::{tgt['id']}"
            if key_str in link_keys:
                continue
            link_keys.add(key_str)
            links.append({
                "source": src["id"],
                "target": tgt["id"],
                "type": _link_type_for_rel(r.type),
            })

    return jsonify({"nodes": list(nodes_by_id.values()), "links": links})


@app.route("/api/snapshots")
def list_snapshots_route():
    """List available graph snapshots (newest first)."""
    try:
        from src.snapshot import list_snapshots as _ls
    except Exception as exc:
        logger.error("snapshot module unavailable: %s", exc)
        return jsonify([])
    items = _ls(Path(SNAPSHOT_DIR))
    # Caller doesn't need the absolute path; expose ts + counts.
    return jsonify([
        {
            "ts": item["ts"],
            "slug": item["slug"],
            "hosts": item["hosts"],
            "users": item["users"],
            "software": item["software"],
            "edges": item["edges"],
        }
        for item in items
    ])


def _resolve_snapshot_path(token: str):
    """Map a `ts` or `slug` from a query param to an on-disk path. Returns None if missing."""
    if not token:
        return None
    safe = re.sub(r"[^A-Za-z0-9._\-]", "", token)[:100]
    if not safe:
        return None
    candidate = Path(SNAPSHOT_DIR) / f"{safe}.jsonl.gz"
    if candidate.is_file():
        return candidate
    # Fall back to a ts -> slug match against list_snapshots metadata.
    try:
        from src.snapshot import list_snapshots as _ls
    except Exception:
        return None
    for item in _ls(Path(SNAPSHOT_DIR)):
        if item["ts"] == token or item["slug"] == token:
            p = Path(item["path"])
            if p.is_file():
                return p
    return None


@app.route("/api/diff")
def get_diff():
    """Diff between two snapshots: ?from=<ts>&to=<ts>."""
    a_token = request.args.get("from", "").strip()
    b_token = request.args.get("to", "").strip()
    if not a_token or not b_token:
        return jsonify({"error": "from and to are required"}), 400

    a_path = _resolve_snapshot_path(a_token)
    b_path = _resolve_snapshot_path(b_token)
    if not a_path or not b_path:
        return jsonify({"error": "snapshot not found"}), 404

    try:
        from src.snapshot import diff_snapshots as _diff
    except Exception as exc:
        logger.error("snapshot module unavailable: %s", exc)
        return jsonify({"error": "snapshot subsystem unavailable"}), 500

    try:
        result = _diff(a_path, b_path)
    except Exception as exc:
        logger.error("diff failed: %s", exc, exc_info=True)
        return jsonify({"error": "Diff failed", "message": str(exc) if DEBUG_ERROR_DETAILS else None}), 500
    return jsonify(result)


# ----------------------------------------------------------------------------
# Continuous enrichment worker
# ----------------------------------------------------------------------------
# Each gunicorn worker tries to claim the lock at boot. Only the holder runs
# the enrichment loop. Other workers fall through. Status is mirrored to a
# JSON file under /app/config and triggers travel via a tmpfs file mtime, so
# the four worker views are coherent regardless of which one handles a given
# /api request.
_ENRICHER_STOP = None
_ENRICHER_INIT_DONE = False
_ENRICHER_INIT_LOCK = threading.Lock()


def _ensure_enricher_started():
    """Start the enricher on first /api request. Idempotent."""
    global _ENRICHER_STOP, _ENRICHER_INIT_DONE
    if _ENRICHER_INIT_DONE:
        return
    with _ENRICHER_INIT_LOCK:
        if _ENRICHER_INIT_DONE:
            return
        try:
            from enrich_worker import start_worker
        except Exception as exc:
            logger.error("enricher import failed: %s", exc)
            _ENRICHER_INIT_DONE = True
            return
        try:
            _, stop_evt = start_worker(
                _get_driver,
                interval_sec=ENRICHER_INTERVAL_SEC,
                batch_size=ENRICHER_BATCH_SIZE,
                lock_path=ENRICHER_LOCK_PATH,
                trigger_path=ENRICHER_TRIGGER_PATH,
                status_path=ENRICHER_STATUS_PATH,
                enabled=ENRICHER_ENABLED,
            )
            _ENRICHER_STOP = stop_evt
        except Exception as exc:
            logger.error("enricher start failed: %s", exc, exc_info=True)
        _ENRICHER_INIT_DONE = True


@app.route("/api/enricher/status")
def enricher_status():
    _ensure_enricher_started()
    try:
        from enrich_worker import read_status, queue_remaining as _qr
        snap = read_status(ENRICHER_STATUS_PATH)
        # Override `enabled` with the live config so a status file written
        # in a previous run can't claim the worker is enabled when the env
        # has flipped it off.
        snap["enabled"] = ENRICHER_ENABLED
        snap["queue_remaining"] = _qr(_get_driver)
    except Exception as exc:
        logger.error("enricher status failed: %s", exc)
        snap = {
            "enabled": ENRICHER_ENABLED, "running": False,
            "last_tick_iso": None, "items_categorized_total": 0,
            "last_error": str(exc) if DEBUG_ERROR_DETAILS else None,
            "queue_remaining": 0,
        }
    return jsonify(snap)


@app.route("/api/enricher/trigger", methods=["POST"])
def enricher_trigger():
    _ensure_enricher_started()
    if not ENRICHER_ENABLED:
        return jsonify({"error": "Enricher disabled"}), 503
    try:
        from enrich_worker import fire_trigger
    except Exception as exc:
        logger.error("enricher import failed at trigger time: %s", exc)
        return jsonify({"error": "Enricher unavailable"}), 503
    fired, retry_after = fire_trigger(ENRICHER_TRIGGER_PATH,
                                      cooldown_sec=ENRICHER_MANUAL_TRIGGER_COOLDOWN)
    if not fired:
        return jsonify({
            "error": "Rate limited",
            "retry_after_sec": int(retry_after),
        }), 429
    return ("", 204)


@atexit.register
def _stop_enricher():
    if _ENRICHER_STOP is not None:
        try:
            _ENRICHER_STOP.set()
        except Exception:
            pass


# ----------------------------------------------------------------------------
# OODA supervisor — Observe → Orient → Decide → Act
# ----------------------------------------------------------------------------
# One worker holds the OODA lock and drives the cycle; others fall through.
# Status, cycles, and findings are mirrored to /app/config so all workers
# can serve the same view via /api/ooda/*.
_OODA_STOP = None
_OODA_INIT_DONE = False
_OODA_INIT_LOCK = threading.Lock()


def _ensure_ooda_started():
    """Start the OODA supervisor on first /api request. Idempotent."""
    global _OODA_STOP, _OODA_INIT_DONE
    if _OODA_INIT_DONE:
        return
    with _OODA_INIT_LOCK:
        if _OODA_INIT_DONE:
            return
        try:
            from ooda_worker import start_worker as _ooda_start
        except Exception as exc:
            logger.error("ooda import failed: %s", exc)
            _OODA_INIT_DONE = True
            return
        try:
            _, stop_evt = _ooda_start(
                _get_driver,
                interval_sec=OODA_INTERVAL_SEC,
                full_scan_every=OODA_FULL_SCAN_EVERY,
                state_path=OODA_STATE_PATH,
                snapshot_dir=OODA_SNAPSHOT_DIR,
                lock_path=OODA_LOCK_PATH,
                trigger_path=OODA_TRIGGER_PATH,
                status_path=OODA_STATUS_PATH,
                cycles_path=OODA_CYCLES_PATH,
                findings_path=OODA_FINDINGS_PATH,
                enricher_trigger_path=ENRICHER_TRIGGER_PATH,
                audit_log_path=AUDIT_FILE,
                enabled=OODA_ENABLED,
            )
            _OODA_STOP = stop_evt
        except Exception as exc:
            logger.error("ooda start failed: %s", exc, exc_info=True)
        _OODA_INIT_DONE = True


@app.route("/api/ooda/status")
def ooda_status():
    _ensure_ooda_started()
    try:
        from ooda_worker import read_status
        snap = read_status(OODA_STATUS_PATH)
        # Override `enabled` with the live config so a stale status file
        # cannot claim the worker is enabled when env has flipped it off.
        snap["enabled"] = OODA_ENABLED
        snap["interval_sec"] = OODA_INTERVAL_SEC
        snap["full_scan_every"] = OODA_FULL_SCAN_EVERY
    except Exception as exc:
        logger.error("ooda status failed: %s", exc)
        snap = {
            "enabled": OODA_ENABLED, "running": False,
            "next_cycle_id": 1, "last_phase": None,
            "last_error": str(exc) if DEBUG_ERROR_DETAILS else None,
            "cycles_total": 0, "cycles_failed": 0, "last_cycle": None,
            "interval_sec": OODA_INTERVAL_SEC,
            "full_scan_every": OODA_FULL_SCAN_EVERY,
        }
    return jsonify(snap)


@app.route("/api/ooda/trigger", methods=["POST"])
def ooda_trigger():
    _ensure_ooda_started()
    if not OODA_ENABLED:
        return jsonify({"error": "OODA disabled"}), 503
    try:
        from ooda_worker import fire_trigger as _fire
    except Exception as exc:
        logger.error("ooda import failed at trigger time: %s", exc)
        return jsonify({"error": "OODA unavailable"}), 503
    fired, retry_after = _fire(OODA_TRIGGER_PATH,
                               cooldown_sec=OODA_MANUAL_TRIGGER_COOLDOWN)
    if not fired:
        return jsonify({"error": "Rate limited",
                        "retry_after_sec": int(retry_after)}), 429
    audit_log("ooda_trigger", "manual cycle requested")
    return ("", 204)


@app.route("/api/ooda/findings")
def ooda_findings():
    _ensure_ooda_started()
    try:
        from ooda_worker import read_findings
        return jsonify(read_findings(OODA_FINDINGS_PATH))
    except Exception as exc:
        logger.error("ooda findings failed: %s", exc)
        return jsonify({"error": "Findings unavailable",
                        "message": str(exc) if DEBUG_ERROR_DETAILS else "internal error"}), 500


@app.route("/api/ooda/cycles")
def ooda_cycles():
    _ensure_ooda_started()
    try:
        limit = int(request.args.get("limit", 20))
    except ValueError:
        limit = 20
    limit = max(1, min(limit, 100))
    try:
        from ooda_worker import read_cycles
        return jsonify(read_cycles(OODA_CYCLES_PATH, limit=limit))
    except Exception as exc:
        logger.error("ooda cycles failed: %s", exc)
        return jsonify({"error": "Cycles unavailable",
                        "message": str(exc) if DEBUG_ERROR_DETAILS else "internal error"}), 500


@atexit.register
def _stop_ooda():
    if _OODA_STOP is not None:
        try:
            _OODA_STOP.set()
        except Exception:
            pass


@app.route("/api/relationships")
def get_relationships():
    """List all USES + INSTALLED_ON edges. Bounded so a multi-million-edge fleet
    can't OOM the response. Use the per-entity endpoints for full traversals.
    """
    if not driver:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        limit = int(request.args.get("limit", 5000))
    except ValueError:
        limit = 5000
    limit = max(1, min(limit, 10000))

    half = max(1, limit // 2)
    rows = []
    with driver.session() as session:
        uses = session.run(
            """
            MATCH (u:User)-[:USES]->(h:Host)
            RETURN 'USES' AS type, u.username AS from_name, h.hostname AS to_host
            LIMIT $limit
            """,
            limit=half,
        )
        rows.extend(r.data() for r in uses)
        installed = session.run(
            """
            MATCH (s:Software)-[:INSTALLED_ON]->(h:Host)
            RETURN 'INSTALLED_ON' AS type, s.name AS from_name, h.hostname AS to_host
            LIMIT $limit
            """,
            limit=limit - half,
        )
        rows.extend(r.data() for r in installed)
    return jsonify(rows)

@app.route("/")
def index():
    """Serve the main web interface"""
    response = send_from_directory(app.static_folder, "index.html")
    # Prevent caching to ensure fresh code is always loaded
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(ClientError)
def handle_database_error(error):
    """Handle database client errors (e.g. invalid regex)"""
    logger.error(f"Database error: {error}")
    # Return 400 Bad Request for client errors (like bad regex)
    return jsonify({
        "error": "Database error", 
        "message": str(error),
        "code": "BAD_REQUEST"
    }), 400

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal error: {error}")
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    debug_mode = os.environ.get("DEBUG", "False").lower() == "true"
    # Default the dev server to loopback so a misconfigured machine doesn't expose
    # the dashboard to the LAN. Production runs under Gunicorn (see Dockerfile)
    # which binds 0.0.0.0 explicitly.
    bind_host = os.environ.get("WEBVIZ_BIND_HOST", "127.0.0.1")

    logger.info(f"Starting Fleet Hound Web Dashboard on {bind_host}:{port}")
    logger.info(f"Debug mode: {debug_mode}")
    logger.info(f"Memgraph URI: {MEMGRAPH_URI}")

    app.run(host=bind_host, port=port, debug=debug_mode)
