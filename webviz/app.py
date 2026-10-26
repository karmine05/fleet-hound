import atexit
import functools
import hashlib
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
from webviz.hostname_utils import (
    disambiguated_display_name,
    # Aliased so call sites can keep their local `hostname_counts` variable
    # name without shadowing the helper.
    hostname_counts as _hostname_counts,
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
    SHADOW_IT_SOURCES as _SHADOW_IT_SOURCES,  # noqa: F401  (used by future endpoints)
    SYSTEM_CATEGORY_TOKENS as _SYSTEM_CATEGORY_TOKENS,
    SYSTEM_PACKAGE_RE as _SYSTEM_PACKAGE_RE,
    USER_APP_SOURCES as _USER_APP_SOURCES,
    classify_extension_type as _classify_extension_type,
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

# When run as `python webviz/app.py` this module is `__main__`, and the route
# blueprints below do `from webviz.app import ...`. Without this, they'd load a
# SECOND copy of app.py (module `webviz.app`), giving them a different driver
# singleton and worker state than the serving `__main__` app. Registering the
# module here makes that import resolve to this exact module object in every
# launch mode (dev `python app.py`, gunicorn `webviz.app:app`, tests).
if __name__ == "__main__":
    import importlib as _importlib
    _importlib.import_module("webviz")  # ensure the namespace package is importable
    sys.modules["webviz.app"] = sys.modules[__name__]

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
SNAPSHOT_DIR = os.environ.get("SNAPSHOT_DIR", "/app/config/snapshots")

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
try:
    ENRICHER_PARALLELISM = int(os.environ.get("ENRICHER_PARALLELISM", "4"))
except ValueError:
    ENRICHER_PARALLELISM = 4
ENRICHER_LOCK_PATH = os.environ.get("ENRICHER_LOCK_PATH", "/tmp/fleet-hound-enricher.lock")
ENRICHER_TRIGGER_PATH = os.environ.get("ENRICHER_TRIGGER_PATH", "/tmp/fleet-hound-enricher.trigger")
# Status file lives under /app/config (the bind-mounted volume) so all
# gunicorn workers see the same view AND items_categorized_total survives
# container restarts.
ENRICHER_STATUS_PATH = os.environ.get("ENRICHER_STATUS_PATH", "/app/config/enricher_status.json")
# Manual /api/enricher/trigger rate limit (seconds between accepted triggers).
# Enforced cross-worker via trigger-file mtime.
ENRICHER_MANUAL_TRIGGER_COOLDOWN = 30.0

# Browser-extension intel worker tunables. Same leader-elected pattern as the
# enricher; defaults to enabled because the feature is read-only and every
# network source is cached/degradable. Interval defaults to 6h (store metadata
# TTL is 24h; the worker only re-fetches when the watermark is stale).
EXTENSION_WORKER_ENABLED = _bool_env("EXTENSION_WORKER_ENABLED", True)
try:
    EXTENSION_WORKER_INTERVAL_SEC = int(os.environ.get("EXTENSION_WORKER_INTERVAL_SEC", "21600"))
except ValueError:
    EXTENSION_WORKER_INTERVAL_SEC = 21600
try:
    EXTENSION_WORKER_BATCH_SIZE = int(os.environ.get("EXTENSION_WORKER_BATCH_SIZE", "50"))
except ValueError:
    EXTENSION_WORKER_BATCH_SIZE = 50
try:
    EXTENSION_WORKER_PARALLELISM = int(os.environ.get("EXTENSION_WORKER_PARALLELISM", "4"))
except ValueError:
    EXTENSION_WORKER_PARALLELISM = 4
EXTENSION_WORKER_LOCK_PATH = os.environ.get(
    "EXTENSION_WORKER_LOCK_PATH", "/tmp/fleet-hound-extensions.lock"
)
EXTENSION_WORKER_TRIGGER_PATH = os.environ.get(
    "EXTENSION_WORKER_TRIGGER_PATH", "/tmp/fleet-hound-extensions.trigger"
)
EXTENSION_WORKER_STATUS_PATH = os.environ.get(
    "EXTENSION_WORKER_STATUS_PATH", "/app/config/extension_status.json"
)
EXTENSION_CACHE_DIR = os.environ.get(
    "EXTENSION_CACHE_DIR", "/app/config/extension_cache"
)
EXTENSION_MANUAL_TRIGGER_COOLDOWN = 30.0

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
    return _word_re(pattern).search(text_lower) is not None


@functools.lru_cache(maxsize=2048)
def _word_re(pattern: str) -> "re.Pattern":
    # Shadow IT calls _word_match ~10^5 times per request; compile once.
    return re.compile(r"(?<![a-z0-9])" + re.escape(pattern) + r"(?![a-z0-9])")


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


def _is_loopback_host(host: str) -> bool:
    hostname = host or ""
    if not hostname.endswith("]"):  # strip :port, but not from a bare "[::1]"
        hostname = hostname.rsplit(":", 1)[0]
    hostname = hostname.strip("[]").lower()
    return hostname == "localhost" or _is_loopback(hostname)


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
        # Hash both sides so compare_digest never raises on unequal lengths
        # (a short token used to 500 instead of 401).
        if not hmac.compare_digest(
            hashlib.sha256(supplied.encode("utf-8")).digest(),
            hashlib.sha256(WEBVIZ_API_TOKEN.encode("utf-8")).digest(),
        ):
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
    # Host check blocks DNS rebinding and local tunnels/proxies (which connect
    # from 127.0.0.1 but carry a public Host header).
    if _is_loopback(_client_ip()) and _is_loopback_host(request.host):
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

def _bounded_limit(default: int = 5000, hard_cap: int = 20000) -> int:
    try:
        limit = int(request.args.get("limit", default))
    except (TypeError, ValueError):
        limit = default
    return max(1, min(limit, hard_cap))


def _normalize_whitelist(entries) -> list:
    """Lowercased unique whitelist entries, preserving first-seen order."""
    seen = set()
    out = []
    for raw in entries or []:
        item = str(raw or "").strip().lower()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _whitelist_clause(alias: str = "s") -> str:
    """Exclude software whose name or display_name is on the whitelist.

    Operators authorize by the title they see (LastPass, Grammarly). After
    extension_key identity, that title lives in display_name while `name`
    is `ext:<store>:<id>`. Matching either keeps authorize working.
    """
    return (
        f"AND NOT (toLower({alias}.name) IN $whitelist "
        f"OR toLower(coalesce({alias}.display_name, '')) IN $whitelist)"
    )


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
    every 30s, so the enricher / OODA / extension workers boot on the first
    healthcheck after startup without requiring an operator request. They
    only boot once the DB probe succeeds — a worker started against an
    unreachable Memgraph would burn its leader election and first cycle on
    guaranteed failures.
    """
    if not driver:
        return jsonify({
            "status": "unhealthy",
            "database": "disconnected"
        }), 503

    try:
        with driver.session() as session:
            result = session.run("RETURN 1")
            result.single()
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        payload = {
            "status": "unhealthy",
            "database": "error",
        }
        if DEBUG_ERROR_DETAILS:
            payload["error"] = str(e)
        return jsonify(payload), 503

    _ensure_enricher_started()
    _ensure_ooda_started()
    _ensure_extension_worker_started()
    return jsonify({
        "status": "healthy",
        "database": "connected",
    }), 200

@app.route("/api/authorize-software", methods=['POST'])
def authorize_software():
    """Authorize a software (whitelist it)"""
    try:
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"error": "Invalid JSON body"}), 400

        software_name = (data.get('software_name') or '').strip().lower()
        
        if not software_name:
            return jsonify({"error": "Software name required"}), 400

        if len(software_name) > 500:
            return jsonify({
                "error": "Software name too long",
                "message": "software_name must be <= 500 characters",
            }), 400
            
        whitelist = _normalize_whitelist(load_whitelist())
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


# ----------------------------------------------------------------------------
# Continuous enrichment worker
# ----------------------------------------------------------------------------
# Each gunicorn worker tries to claim the lock at boot. Only the holder runs
# the enrichment loop. Other workers fall through. Status is mirrored to a
# JSON file under /app/config and triggers travel via a tmpfs file mtime, so
# the worker views are coherent regardless of which one handles a given
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
                parallelism=ENRICHER_PARALLELISM,
                lock_path=ENRICHER_LOCK_PATH,
                trigger_path=ENRICHER_TRIGGER_PATH,
                status_path=ENRICHER_STATUS_PATH,
                enabled=ENRICHER_ENABLED,
            )
            _ENRICHER_STOP = stop_evt
        except Exception as exc:
            logger.error("enricher start failed: %s", exc, exc_info=True)
        _ENRICHER_INIT_DONE = True


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


@atexit.register
def _stop_ooda():
    if _OODA_STOP is not None:
        try:
            _OODA_STOP.set()
        except Exception:
            pass


# ----------------------------------------------------------------------------
# Browser-extension inventory + risk
# ----------------------------------------------------------------------------
# Read-only view over the fields ingestion now preserves plus the scores written
# by extension_worker. Grouping is by `extension_key` (ext:<store>:<id>) because
# one canonical extension can exist as several :Software nodes when Fleet
# reports different install paths/versions.

_EXTENSION_STOP = None
_EXTENSION_INIT_DONE = False
_EXTENSION_INIT_LOCK = threading.Lock()


def _ensure_extension_worker_started():
    """Start the extension worker on first /api request. Idempotent."""
    global _EXTENSION_STOP, _EXTENSION_INIT_DONE
    if _EXTENSION_INIT_DONE:
        return
    with _EXTENSION_INIT_LOCK:
        if _EXTENSION_INIT_DONE:
            return
        try:
            from extension_worker import start_worker
        except Exception as exc:
            logger.error("extension worker import failed: %s", exc)
            _EXTENSION_INIT_DONE = True
            return
        try:
            _, stop_evt = start_worker(
                _get_driver,
                interval_sec=EXTENSION_WORKER_INTERVAL_SEC,
                batch_size=EXTENSION_WORKER_BATCH_SIZE,
                parallelism=EXTENSION_WORKER_PARALLELISM,
                lock_path=EXTENSION_WORKER_LOCK_PATH,
                trigger_path=EXTENSION_WORKER_TRIGGER_PATH,
                status_path=EXTENSION_WORKER_STATUS_PATH,
                cache_dir=EXTENSION_CACHE_DIR,
                enabled=EXTENSION_WORKER_ENABLED,
            )
            _EXTENSION_STOP = stop_evt
        except Exception as exc:
            logger.error("extension worker start failed: %s", exc, exc_info=True)
        _EXTENSION_INIT_DONE = True


@atexit.register
def _stop_extension_worker():
    if _EXTENSION_STOP is not None:
        try:
            _EXTENSION_STOP.set()
        except Exception:
            pass


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
    """Handle database client errors (e.g. invalid regex)."""
    logger.error("Database error: %s", error)
    payload = {
        "error": "Database error",
        "code": "BAD_REQUEST",
    }
    if DEBUG_ERROR_DETAILS:
        payload["message"] = str(error)
    else:
        payload["message"] = "invalid query"
    return jsonify(payload), 400

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal error: {error}")
    return jsonify({"error": "Internal server error"}), 500

# ---------------------------------------------------------------------------
# Route blueprints (Phase 5). Endpoints live in webviz/routes/*; this file keeps
# the app, auth middleware, driver singleton, worker lifecycle, /api/meta and
# /api/health, the index route and the error handlers. Registration is at the
# very bottom so every name the blueprints import (driver, logger, helpers, the
# worker interval constants and _ensure_*_started) is already bound.
# ---------------------------------------------------------------------------
from webviz.routes import (
    blast_radius as _bp_blast_radius,
    entities as _bp_entities,
    graph as _bp_graph,
    labels as _bp_labels,
    search as _bp_search,
    shadow_it as _bp_shadow_it,
    traversal as _bp_traversal,
    workers as _bp_workers,
)

app.register_blueprint(_bp_entities.bp)
app.register_blueprint(_bp_labels.bp)
app.register_blueprint(_bp_search.bp)
app.register_blueprint(_bp_blast_radius.bp)
app.register_blueprint(_bp_graph.bp)
app.register_blueprint(_bp_shadow_it.bp)
app.register_blueprint(_bp_traversal.bp)
app.register_blueprint(_bp_workers.bp)

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
