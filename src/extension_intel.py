"""Browser-extension identity, store metadata, and risk scoring.

Pure stdlib. No Flask, no Neo4j, no paid/account sources.

Sources used (all verified anonymous):
  * Chrome update2 + CRX manifest   (clients2.google.com / storage.googleapis.com)
  * Edge product-details JSON       (microsoftedge.microsoft.com)
  * Firefox AMO add-on API          (addons.mozilla.org)
  * Mozilla add-on blocklist        (firefox.settings.services.mozilla.com)

The module is deliberately defensive: a dead network or a changed store response
must degrade to a local, explainable score instead of failing ingestion.
"""

from __future__ import annotations

import functools
import hashlib
import html
import io
import json
import logging
import math
import os
import re
import threading
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

BROWSER_EXTENSION_SOURCES = frozenset({
    "chrome_extensions", "firefox_addons", "safari_extensions", "ie_extensions",
})
CHROMIUM_STORES = frozenset({"chrome", "edge", "brave", "opera", "vivaldi", "chromium"})

# Chrome/Edge component extensions. Path heuristics cover the long tail; these
# IDs cover builds where Fleet does not return an installed path.
CHROMIUM_BUILTIN_IDS = frozenset({
    "aohghmighlieiainnegkcijnfilokake",  # Google Docs
    "aapocclcgogkmnckokdopfmhonfmgoek",  # Google Slides
    "felcaaldnbdncclmgdcncolpebgiejap",  # Google Sheets
    "ghbmnnjooekpmoecnnnilnnbdlolhkhi",  # Google Docs Offline
    "nmmhkkegccagdldgiimedpiccmgmieda",  # Chrome Web Store payments
    "mhjfbmdgcfjbbpaeojofohoefgiehjai",  # Chrome PDF viewer
    "nkeimhogjdpnpccoofpliimaahmaaome",  # Chrome component (legacy)
    "pkedcjkdefgpdelpbcmbmeomcjbeemfm",  # Chrome Media Router
})
FIREFOX_BUILTIN_SUFFIXES = ("@mozilla.org", "@mozilla.com")

_EXT_ID_RE = re.compile(r"\b([a-p]{32})\b", re.IGNORECASE)
_FIREFOX_GUID_RE = re.compile(r"^(\{[0-9a-f-]{36}\}|[^@\s]+@[^@\s]+)$", re.IGNORECASE)


def _clean_str(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _infer_store(source: str, browser: str, extension_for: str,
                 installed_paths) -> str:
    src = source.lower()
    if src == "firefox_addons":
        return "firefox"
    if src == "safari_extensions":
        return "safari"
    if src == "ie_extensions":
        return "edge"
    if src != "chrome_extensions":
        return "unknown"

    b = f"{browser} {extension_for}".lower()
    for candidate in ("edge", "brave", "opera", "vivaldi", "chromium"):
        if candidate in b:
            return "edge" if candidate == "edge" else candidate
    # The install path is more reliable than osquery's `extension_for` on
    # Windows, where Edge can report `chrome`.
    for path in installed_paths or []:
        p = str(path).lower()
        if "microsoft\\edge" in p or "microsoft edge.app" in p:
            return "edge"
        if "brave" in p:
            return "brave"
        if "opera" in p:
            return "opera"
        if "vivaldi" in p:
            return "vivaldi"
    return "chrome"


def _infer_extension_id(source: str, name: str, display_name: str,
                        installed_paths) -> str:
    for candidate in (name, display_name, *(installed_paths or [])):
        c = _clean_str(candidate)
        if not c:
            continue
        if source in ("chrome_extensions", "ie_extensions"):
            m = _EXT_ID_RE.search(c)
            if m:
                return m.group(1).lower()
        if source == "firefox_addons" and _FIREFOX_GUID_RE.match(c):
            return c
        if source == "safari_extensions" and c.count(".") >= 2 and " " not in c:
            return c
    return ""


def derive_extension_identity(software: dict) -> dict | None:
    """Return additive extension fields for a Fleet software row.

    Returns None for non-browser-extension sources. Never raises: malformed
    Fleet rows fall back to a name-derived key so they still appear in the
    inventory instead of disappearing.
    """
    if not isinstance(software, dict):
        return None
    source = _clean_str(software.get("source")).lower()
    if source not in BROWSER_EXTENSION_SOURCES:
        return None

    name = _clean_str(software.get("name"))
    display_name = _clean_str(software.get("display_name"))
    browser = _clean_str(software.get("browser")).lower()
    extension_for = _clean_str(software.get("extension_for")).lower()
    installed_paths = software.get("installed_paths")
    if not isinstance(installed_paths, list):
        installed_paths = [installed_paths] if installed_paths else []
    installed_paths = [str(p) for p in installed_paths if p]

    store = _infer_store(source, browser, extension_for, installed_paths)
    ext_id = _clean_str(software.get("extension_id")) or _infer_extension_id(
        source, name, display_name, installed_paths
    )
    if ext_id:
        # Lowercase: ingestion lowercases Software.name, and name == extension_key
        # for extensions, so a mixed-case key would churn nodes every cycle.
        extension_key = f"ext:{store}:{ext_id}".lower()
    else:
        # Stable fallback for malformed data. The store lookup is skipped, but
        # the inventory row still exists and can be reviewed.
        digest = hashlib.sha1((name or display_name).encode("utf-8")).hexdigest()[:16]
        extension_key = f"ext:{store}:name:{digest}"

    return {
        "kind": "browser_extension",
        "store": store,
        "extension_id": ext_id or None,
        "extension_key": extension_key,
        "browser": browser or None,
        "extension_for": extension_for or None,
        "display_name": display_name or name or None,
        "installed_paths": installed_paths[:10] or None,
        "installed_path": installed_paths[0] if installed_paths else None,
        "is_builtin": is_browser_builtin({
            "store": store,
            "extension_id": ext_id,
            "installed_paths": installed_paths,
        }),
    }


def is_browser_builtin(record: dict) -> bool:
    """True for vendor-shipped/component extensions that must never be flagged."""
    store = _clean_str(record.get("store")).lower()
    ext_id = _clean_str(record.get("extension_id")).lower()
    if store == "firefox" and ext_id.lower().endswith(FIREFOX_BUILTIN_SUFFIXES):
        return True
    if store in ("chrome", "edge", "brave", "opera", "vivaldi", "chromium"):
        if ext_id in CHROMIUM_BUILTIN_IDS:
            return True
    paths = record.get("installed_paths") or []
    if isinstance(paths, str):
        paths = [paths]
    for path in paths:
        p = str(path).lower().replace("/", "\\")
        if store == "chrome" and "\\google\\chrome\\application\\" in p:
            return True
        if store == "edge" and "\\microsoft\\edge\\application\\" in p:
            return True
        if store in ("brave", "opera", "vivaldi") and "\\application\\" in p:
            return True
        if store == "firefox" and ("\\browser\\features\\" in p or "/browser/features/" in p):
            return True
        if store == "safari" and ("\\contents\\plugins\\" in p or "\\contents\\library\\" in p):
            return True
    return False


# ---------------------------------------------------------------------------
# Name anomalies / publisher reputation
# ---------------------------------------------------------------------------

# Brands worth impersonating. Keep this list focused: every extra brand is a
# new false-positive source for legitimate look-alike names.
_BRANDS = (
    "adguard", "adblock", "ublock", "lastpass", "bitwarden", "1password",
    "dashlane", "grammarly", "honey", "paypal", "metamask", "phantom",
    "rabby", "ledger", "trezor", "keeper", "norton", "mcafee", "avast",
    "avg", "malwarebytes", "kaspersky", "eset", "bitdefender", "sophos",
    "cloudflare", "google", "microsoft", "mozilla", "adobe", "apple",
    "amazon", "netflix", "spotify", "slack", "zoom", "notion", "evernote",
    "pocket", "darkreader", "ghostery", "privacybadger", "tampermonkey",
)


# Cyrillic/Greek characters that render like Latin letters. Used only to raise
# a signal, never to block.
_HOMOGLYPHS = set("абвгдеёжзийклмнопрстуфхцчшщъыьэюяαβγδεζηθικλμνξοπρστυφχψω")


def _normalise_name(value: str) -> str:
    value = unicodedata.normalize("NFKC", value or "").casefold()
    value = value.replace("0", "o").replace("1", "l").replace("rn", "m")
    return re.sub(r"[^a-z0-9]+", "", value)


# Same mapping as the names they are compared with ("1password" -> "lpassword").
_NORMALISED_BRANDS = tuple(dict.fromkeys(_normalise_name(b) for b in _BRANDS))

# Trailing legal/corporate words dropped before comparing publisher names, so
# "Google LLC" / "Meta Platforms, Inc." / "Avast Software s.r.o." match.
_PUBLISHER_SUFFIXES = frozenset({
    "inc", "llc", "ltd", "limited", "corp", "corporation", "co", "company",
    "gmbh", "ag", "sa", "srl", "sro", "bv", "plc", "pty", "software", "systems",
    "security", "technologies", "platforms", "labs", "lab",
    # Store author names often append these (AMO: "1Password Devs").
    "devs", "dev", "developers", "developer", "team",
})


def _edit_distance_at_most_one(a: str, b: str) -> bool:
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        if len(diffs) <= 1:
            return True
        # A single adjacent transposition ("adgaurd" -> "adguard") is the most
        # common brand typo; Levenshtein distance 2 but worth flagging.
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
            i, j = diffs
            return a[i] == b[j] and a[j] == b[i]
        return False
    if len(a) > len(b):
        a, b = b, a
    i = j = 0
    skipped = False
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
            continue
        if skipped:
            return False
        skipped = True
        j += 1
    return True


def name_anomaly_signals(name: str, display_name: str = "", *,
                         store: str = "") -> tuple[list[dict], int]:
    """Heuristic malformed/typosquat detection.

    Deliberately conservative: a hit is a review signal, not a verdict.
    """
    display = (display_name or name or "").strip()
    signals: list[dict] = []
    penalty = 0

    def add(code: str, weight: int, detail: str):
        nonlocal penalty
        signals.append({"code": code, "weight": weight, "detail": detail})
        penalty += weight

    if not display:
        add("missing-name", 12, "extension has no name or display name")
        return signals, min(penalty, 35)

    if re.search(r"[\\/]|\.crx$|\.xpi$", display):
        add("path-as-name", 12, f"name looks like an install path: {display[:120]}")
    if any(ch in _HOMOGLYPHS for ch in display.casefold()):
        add("mixed-script-name", 20, "name contains Cyrillic/Greek characters that mimic Latin")
    if re.search(r"[\x00-\x1f\x7f]", display):
        add("control-characters", 15, "name contains control characters")
    if len(display) > 80:
        add("oversized-name", 6, f"name is {len(display)} characters")
    if display.count(".") >= 4 and " " not in display and not display.endswith("@"):
        add("dotted-identifier-name", 4, "name looks like a reverse-DNS identifier")

    compact = _normalise_name(display)
    # The exact brand spelling ("1Password") is the brand itself, not a
    # typosquat; only look-alikes ("1Passw0rd", "adgaurd") are flagged.
    exact = re.sub(r"[^a-z0-9]+", "", unicodedata.normalize("NFKC", display).casefold())
    if len(compact) >= 5 and exact not in _BRANDS:
        for brand in _NORMALISED_BRANDS:
            if _edit_distance_at_most_one(compact, brand):
                add("typosquat-brand", 18,
                    f"name is one edit away from the '{brand}' brand")
                break
            if compact.startswith(brand) and len(compact) - len(brand) <= 2:
                suffix = compact[len(brand):]
                if suffix in {"x", "pro", "plus", "app", "ex", "official"}:
                    add("brand-affix", 8,
                        f"name appends '{suffix}' to the '{brand}' brand")
                    break

    return signals, min(penalty, 35)


def _normalise_publisher(value) -> str:
    words = re.sub(r"[^\w\s]+", "", unicodedata.normalize("NFKC", _clean_str(value))
                   .casefold()).split()
    while len(words) > 1 and words[-1] in _PUBLISHER_SUFFIXES:
        words.pop()
    return " ".join(words)


# Known-good publishers live in a data file (config/known_publishers.json) so
# operators can add or change entries without a code change or rebuild.
_KNOWN_PUBLISHERS_CANDIDATES = (
    "/app/config/known_publishers.json",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "config", "known_publishers.json"),
)
_CWS_PUBLISHER_ID_RE = re.compile(r"u[0-9a-f]{32}")
_known_publishers_cache: dict = {"key": None, "names": frozenset(), "chrome_ids": frozenset(),
                                 "amo_ids": frozenset(), "edge_ext_ids": frozenset()}
_known_publishers_lock = threading.Lock()


def _known_publishers_path() -> str | None:
    env = os.environ.get("KNOWN_PUBLISHERS_FILE", "").strip()
    if env:
        return env
    return next((p for p in _KNOWN_PUBLISHERS_CANDIDATES if os.path.exists(p)), None)


def _parse_known_publishers(doc) -> tuple[frozenset, frozenset, frozenset, frozenset]:
    names, chrome_ids, amo_ids, edge_ext_ids = set(), set(), set(), set()
    entries = doc.get("publishers") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        raise ValueError("expected an object with a 'publishers' list")
    for idx, entry in enumerate(entries):
        try:
            if not isinstance(entry, dict) or not _clean_str(entry.get("name")):
                raise ValueError("missing name")
            datetime.fromisoformat(_clean_str(entry.get("added_at")).replace("Z", "+00:00"))
            ids = entry.get("chrome_publisher_ids") or []
            bad = [i for i in ids if not (isinstance(i, str) and _CWS_PUBLISHER_ID_RE.fullmatch(i))]
            if bad:
                raise ValueError(f"invalid chrome_publisher_ids {bad}")
            authors = entry.get("amo_author_ids") or []
            bad = [i for i in authors if not (isinstance(i, int) and not isinstance(i, bool) and i > 0)]
            if bad:
                raise ValueError(f"invalid amo_author_ids {bad}")
            edge_exts = entry.get("edge_extension_ids") or []
            bad = [i for i in edge_exts
                   if not (isinstance(i, str) and _CHROME_EXTENSION_ID_RE.fullmatch(i))]
            if bad:
                raise ValueError(f"invalid edge_extension_ids {bad}")
        except (ValueError, TypeError) as exc:
            logger.warning("known_publishers: skipping entry %d (%s): %s",
                           idx, (entry or {}).get("name") if isinstance(entry, dict) else entry, exc)
            continue
        # Only explicit match_names are name-trusted; `name` is a label. Entries
        # verified by Chrome ID alone must not become trusted names elsewhere.
        for n in entry.get("match_names") or []:
            if _normalise_publisher(n):
                names.add(_normalise_publisher(n))
        chrome_ids.update(ids)
        amo_ids.update(authors)
        edge_ext_ids.update(edge_exts)
    return frozenset(names), frozenset(chrome_ids), frozenset(amo_ids), frozenset(edge_ext_ids)


def known_publishers() -> tuple[frozenset, frozenset, frozenset, frozenset]:
    """(normalized names, Chrome publisher IDs, AMO author IDs, Edge extension IDs).

    Reloaded when the file changes.

    A missing or unreadable file trusts nobody (logged), never a built-in default.
    """
    path = _known_publishers_path()
    try:
        key = (path, os.path.getmtime(path)) if path else None
    except OSError:
        key = None
    with _known_publishers_lock:
        c = _known_publishers_cache
        if key is not None and key == c["key"]:
            return c["names"], c["chrome_ids"], c["amo_ids"], c["edge_ext_ids"]
        names, chrome_ids, amo_ids, edge_ext_ids = (frozenset(),) * 4
        if key is None:
            logger.warning("known_publishers: file not found (%s); no publisher is trusted",
                           path or "config/known_publishers.json")
        else:
            try:
                with open(path, encoding="utf-8") as fh:
                    names, chrome_ids, amo_ids, edge_ext_ids = _parse_known_publishers(json.load(fh))
                logger.info("known_publishers: loaded %d names, %d Chrome publisher IDs, "
                            "%d AMO author IDs, %d Edge extension IDs from %s",
                            len(names), len(chrome_ids), len(amo_ids), len(edge_ext_ids), path)
            except (OSError, ValueError) as exc:
                logger.warning("known_publishers: cannot load %s (%s); no publisher is trusted",
                               path, exc)
        c.update(key=key, names=names, chrome_ids=chrome_ids, amo_ids=amo_ids,
                 edge_ext_ids=edge_ext_ids)
        return names, chrome_ids, amo_ids, edge_ext_ids


# Browser-managed store directories, anchored at the user's home. Paths are
# matched whole (fullmatch) after normalizing "\\" to "/", so an unpacked
# extension placed in some other ".../Extensions/<id>/<ver>" does not pass.
_HOME = r"(?:/Users/[^/]+|/home/[^/]+|/root|[a-z]:/Users/[^/]+)"
_CHROMIUM_ROOTS = (
    # macOS
    r"Library/Application Support/(?:Google/Chrome(?: Beta| Canary| Dev)?|Chromium"
    r"|Microsoft Edge(?: Beta| Dev| Canary)?|BraveSoftware/Brave-Browser(?:-Beta|-Nightly)?"
    r"|Vivaldi|com\.operasoftware\.Opera|Arc/User Data|Comet|Dia/User Data)"
    # Linux
    r"|\.config/(?:google-chrome(?:-beta|-unstable)?|chromium|microsoft-edge(?:-beta|-dev)?"
    r"|BraveSoftware/Brave-Browser(?:-Beta|-Nightly)?|vivaldi|opera)"
    r"|snap/chromium/common/chromium"
    # Windows
    r"|AppData/Local/(?:Google/Chrome(?: Beta| Dev| SxS)?|Chromium"
    r"|Microsoft/Edge(?: Beta| Dev| SxS)?|BraveSoftware/Brave-Browser(?:-Beta|-Nightly)?"
    r"|Vivaldi)/User Data"
    r"|AppData/Roaming/Opera Software/Opera Stable"
)
_FIREFOX_ROOTS = (
    r"Library/Application Support/Firefox/Profiles|\.mozilla/firefox"
    r"|snap/firefox/common/\.mozilla/firefox|\.var/app/org\.mozilla\.firefox/\.mozilla/firefox"
    r"|AppData/Roaming/Mozilla/Firefox/Profiles"
)


def _store_path_re(store: str, extension_id: str):
    eid = re.escape(extension_id)
    if store == "firefox":
        tail = rf"(?:{_FIREFOX_ROOTS})/[^/]+/extensions/{eid}\.xpi"
    else:  # Chromium family + Edge; Opera has no profile segment
        tail = rf"(?:{_CHROMIUM_ROOTS})(?:/[^/]+)?/Extensions/{eid}/[^/]+/?"
    return re.compile(rf"{_HOME}/{tail}", re.IGNORECASE)


def store_install_verified(store, extension_id, installs) -> bool:
    """True when every host install of the extension is a store install.

    Store-ID trust is about the listing, not the installed copy: an unpacked
    extension can claim a listed ID by copying its manifest `key`. Store
    installs live in the browser's managed directory under the user's
    profile; unpacked ones load from anywhere else. `installs` is a list of
    {"path", "platform"} (one per host install; bare path strings accepted).
    Fails closed: needs at least one install whose path positively matches a
    store directory. A missing path counts against trust, except on ChromeOS
    hosts (platform "chrome"), whose agent never reports extension paths;
    those are tolerated but never count as evidence, so a ChromeOS-only
    extension is unverifiable and gets no publisher trust.

    Residual: a local user who copies an unpacked extension INTO the real
    profile directory still passes; osquery's from_webstore would close
    that, but Fleet's software inventory does not expose it.
    """
    if not extension_id or not installs:
        return False
    pattern = _store_path_re(store, extension_id)
    verified = 0
    for item in installs:
        path, platform = (item.get("path"), item.get("platform")) if isinstance(item, dict) else (item, None)
        path = (path or "").strip().replace("\\", "/")
        if not path:
            if platform == "chrome":
                continue
            return False
        if not pattern.fullmatch(path):
            return False
        verified += 1
    return verified > 0


def publisher_is_reputable(*values) -> bool:
    """True when a store-sourced developer/publisher NAME is a known publisher.

    Safari only; Chrome-family, Firefox and Edge trust is by store ID
    (chrome_publisher_is_reputable / amo_author_is_reputable /
    edge_extension_is_reputable). Callers pass store fields only: Fleet's
    host-reported `vendor` is attacker-influenced. Normalized equality, not a
    word search, so "Box Hill Scams" / "Meta Tools" do not match "box" / "meta".
    """
    names, _, _, _ = known_publishers()
    return any(_normalise_publisher(v) in names for v in values if v)


def chrome_publisher_is_reputable(publisher_id) -> bool:
    """Chrome Web Store trust is by immutable publisher ID, never display name."""
    _, chrome_ids, _, _ = known_publishers()
    return bool(publisher_id) and publisher_id in chrome_ids


def amo_author_is_reputable(author_ids) -> bool:
    """Firefox trust is by immutable AMO author user ID, never display name."""
    _, _, amo_ids, _ = known_publishers()
    return any(isinstance(i, int) and i in amo_ids for i in author_ids or [])


def edge_extension_is_reputable(extension_id, store_status) -> bool:
    """Edge exposes no publisher ID, so trust is per listed extension ID, and
    only while the Edge store reports that ID as a public listing. Whether the
    installed copy came from the store is checked separately
    (store_install_verified)."""
    _, _, _, edge_ext_ids = known_publishers()
    return store_status == "public" and bool(extension_id) and extension_id in edge_ext_ids


# ---------------------------------------------------------------------------
# Permission / capability analysis
# ---------------------------------------------------------------------------

_PERMISSION_WEIGHTS = {
    "debugger": 25,
    "nativeMessaging": 20,
    "proxy": 20,
    "userScripts": 15,
    "cookies": 15,
    "webRequest": 15,
    "declarativeNetRequest": 15,
    "management": 15,
    "scripting": 12,
    "clipboardRead": 12,
    "tabCapture": 10,
    "history": 8,
    "identity": 8,
    "downloads": 6,
    "offscreen": 6,
    "activeTab": 2,
    "storage": 1,
    "contextMenus": 1,
    "alarms": 1,
    "notifications": 1,
    "sidePanel": 1,
}

_ALL_URLS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}
_HOST_PATTERN_RE = re.compile(r"^(<all_urls>|\*://|[a-z]+://)", re.IGNORECASE)


def _as_string_list(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if isinstance(v, (str, int))]
    return []


def _permission_sets(meta: dict, record: dict) -> tuple[set[str], set[str], set[str], set[str]]:
    raw_perms = _as_string_list(meta.get("permissions") or record.get("permissions"))
    raw_hosts = _as_string_list(meta.get("host_permissions") or record.get("host_permissions"))
    matches = _as_string_list(
        meta.get("content_script_matches") or record.get("content_script_matches")
    )
    raw_optional = _as_string_list(
        meta.get("optional_permissions") or record.get("optional_permissions")
    )
    perms: set[str] = set()
    hosts: set[str] = set(raw_hosts)
    for p in raw_perms:
        (hosts if _HOST_PATTERN_RE.match(p) else perms).add(p)
    optional = {p for p in raw_optional if not _HOST_PATTERN_RE.match(p)} - perms
    return perms, hosts, set(matches), optional


def _capability(perms: set[str], hosts: set[str], matches: set[str],
                optional: set[str] = frozenset()) -> tuple[int, list[dict]]:
    score = 0
    signals: list[dict] = []
    for perm in sorted(perms):
        weight = _PERMISSION_WEIGHTS.get(perm, 0)
        if weight:
            score += weight
            signals.append({
                "code": f"permission:{perm}",
                "weight": weight,
                "detail": f"requests the '{perm}' permission",
            })
    # Optional permissions are granted at runtime, so half weight, and their
    # total never exceeds what the required permissions contribute.
    budget = score
    for perm in sorted(optional):
        weight = min(round(_PERMISSION_WEIGHTS.get(perm, 0) * 0.5), budget)
        if weight > 0:
            budget -= weight
            score += weight
            signals.append({
                "code": f"optional-permission:{perm}",
                "weight": weight,
                "detail": f"may request the '{perm}' permission at runtime",
            })
    if hosts & _ALL_URLS:
        score += 20
        signals.append({
            "code": "broad-host-access",
            "weight": 20,
            "detail": "host permissions include <all_urls> or an equivalent wildcard",
        })
    elif hosts:
        weight = min(10, len(hosts) * 2)
        score += weight
        signals.append({
            "code": "host-access",
            "weight": weight,
            "detail": f"requests access to {len(hosts)} host pattern(s)",
        })
    if matches & _ALL_URLS:
        score += 10
        signals.append({
            "code": "content-script-all-urls",
            "weight": 10,
            "detail": "content script runs on every page",
        })
    elif matches:
        score += 5
        signals.append({
            "code": "content-script",
            "weight": 5,
            "detail": f"injects a content script into {len(matches)} pattern(s)",
        })
    # Content scripts reach page content too, so only discount when neither exists.
    if not hosts and not matches:
        score = round(score * 0.6)
    return min(100, score), signals


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

_BANDS = ((75, "critical"), (50, "high"), (25, "medium"), (0, "low"))


def risk_band(score: int) -> str:
    for threshold, band in _BANDS:
        if score >= threshold:
            return band
    return "low"


def _as_int(value):
    try:
        if value is None or value == "":
            return None
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _as_float(value):
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_iso(value):
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (TypeError, ValueError):
        return None


def _trust_score(meta: dict, record: dict, *, reputable: bool) -> tuple[int, list[dict]]:
    status = _clean_str(meta.get("status") or record.get("store_status") or "unknown").lower()
    signals: list[dict] = []
    score = 0

    if status == "public":
        score += 25
        signals.append({"code": "store-listed", "weight": 0,
                        "detail": "listed in a public extension store"})
    elif status == "unlisted":
        score += 5
        signals.append({"code": "store-unlisted", "weight": 0,
                        "detail": "unlisted or self-distributed"})
    elif status == "unknown":
        score += 8
        signals.append({"code": "store-status-unknown", "weight": 0,
                        "detail": "store metadata unavailable"})
    # not_found/removed deliberately score 0.

    if reputable:
        score += 20
        signals.append({"code": "reputable-publisher", "weight": 0,
                        "detail": "publisher matches a known vendor"})
    if meta.get("developer_verified") is True:
        score += 10
        signals.append({"code": "verified-developer", "weight": 0,
                        "detail": "store marks the developer as verified"})
    elif meta.get("established_publisher") is True:
        score += 10
        signals.append({"code": "established-publisher", "weight": 0,
                        "detail": "store: verified website owner with no history of violations"})
    if meta.get("featured") is True:
        score += 5
        signals.append({"code": "store-featured", "weight": 0,
                        "detail": "featured / recommended by the store"})

    mv = _as_int(meta.get("manifest_version"))
    if mv == 3:
        score += 8
        signals.append({"code": "manifest-v3", "weight": 0,
                        "detail": "uses Manifest V3"})

    updated = _parse_iso(meta.get("updated_at"))
    if updated:
        age_days = (datetime.now(timezone.utc) - updated).days
        if age_days <= 365:
            score += 10
        elif age_days <= 730:
            score += 4
        signals.append({"code": "store-updated", "weight": 0,
                        "detail": f"last store update {max(age_days, 0)} days ago"})

    users = _as_int(meta.get("users"))
    if users and users > 0:
        score += min(12, int(4 * math.log10(users + 1)))
        signals.append({"code": "install-popularity", "weight": 0,
                        "detail": f"{users:,} store installs"})

    rating = _as_float(meta.get("rating"))
    rating_count = _as_int(meta.get("rating_count"))
    if rating is not None and rating >= 4.0 and (rating_count or 0) >= 100:
        score += 5
        signals.append({"code": "store-rating", "weight": 0,
                        "detail": f"rated {rating:.1f} from {rating_count:,} ratings"})

    if meta.get("crx_hash_verified") is True:
        score += 5
        signals.append({"code": "crx-hash-verified", "weight": 0,
                        "detail": "CRX SHA-256 matches the update manifest"})

    return min(100, score), signals


def _threat_score(meta: dict, record: dict, blocklist_entry: dict | None) -> tuple[int, list[dict]]:
    signals: list[dict] = []
    threat = 0
    status = _clean_str(meta.get("status") or record.get("store_status")).lower()

    if blocklist_entry:
        threat = 100
        why = _clean_str(blocklist_entry.get("why")) or "blocked by Mozilla"
        signals.append({"code": "mozilla-blocklist", "weight": 100, "detail": why})
    elif status in ("removed", "disabled"):
        threat = max(threat, 45)
        signals.append({"code": "removed-from-store", "weight": 45,
                        "detail": "extension is no longer available in its store"})
    elif status in ("not_found", "sideloaded"):
        threat = max(threat, 20)
        signals.append({"code": "not-in-store", "weight": 20,
                        "detail": "extension ID was not found in the expected public store"})
    elif status == "unlisted":
        threat = max(threat, 10)
        signals.append({"code": "unlisted", "weight": 10,
                        "detail": "unlisted or self-distributed extension"})

    # Stores keep abuse reports private; a low rating from many reviewers is
    # the closest public complaint signal.
    rating = _as_float(meta.get("rating"))
    rating_count = _as_int(meta.get("rating_count")) or 0
    if rating is not None and rating < 2.5 and rating_count >= 50:
        threat = max(threat, 15)
        signals.append({"code": "poor-public-reputation", "weight": 15,
                        "detail": f"rated {rating:.1f}/5 by {rating_count:,} reviewers"})

    # Never fail open: a package we could not inspect (store serves none, or
    # it exceeds our download cap, which an attacker can pad past) has an
    # unknown capability score, so it must not look clean.
    if meta.get("manifest_unavailable") and not meta.get("manifest_error"):
        threat = max(threat, 15)
        signals.append({"code": "manifest-uninspected", "weight": 15,
                        "detail": str(meta["manifest_unavailable"])[:200]})

    if meta.get("manifest_error"):
        threat = max(threat, 30)
        signals.append({"code": "manifest-unparseable", "weight": 30,
                        "detail": str(meta["manifest_error"])[:200]})

    max_cvss = _as_float(record.get("max_cvss"))
    if max_cvss is None:
        vulns = record.get("vulnerabilities")
        if isinstance(vulns, list):
            scores = [_as_float(v.get("cvss_score")) for v in vulns if isinstance(v, dict)]
            scores = [s for s in scores if s is not None]
            max_cvss = max(scores) if scores else None
    if max_cvss is not None:
        if max_cvss >= 9:
            threat = max(threat, 35)
            signals.append({"code": "critical-cve", "weight": 35,
                            "detail": f"Fleet reports a CVSS {max_cvss:.1f} vulnerability"})
        elif max_cvss >= 7:
            threat = max(threat, 25)
            signals.append({"code": "high-cve", "weight": 25,
                            "detail": f"Fleet reports a CVSS {max_cvss:.1f} vulnerability"})
        elif max_cvss > 0:
            threat = max(threat, 10)
            signals.append({"code": "known-cve", "weight": 10,
                            "detail": f"Fleet reports a CVSS {max_cvss:.1f} vulnerability"})

    return min(100, threat), signals


def _exposure_score(host_count: int, version_count: int) -> int:
    score = min(60, round(15 * math.log10(max(host_count, 0) + 1)))
    if version_count > 2:
        score += 10
    return min(100, score)


def analyze_extension(record: dict, *, blocklist_entry: dict | None = None,
                      fleet_host_count: int | None = None) -> dict:
    """Compute an explainable 0-100 risk score for one extension identity.

    `record` accepts flattened Fleet properties plus an optional `store_meta`
    map from `fetch_store_metadata()`. The function is deterministic and does
    not perform I/O, which keeps it cheap enough to run on every API request
    if needed.
    """
    meta = record.get("store_meta") if isinstance(record.get("store_meta"), dict) else {}
    store = _clean_str(record.get("store") or meta.get("store") or "unknown").lower()
    extension_id = _clean_str(record.get("extension_id"))
    name = _clean_str(record.get("name"))
    display_name = _clean_str(record.get("display_name"))
    installed_paths = record.get("installed_paths") or []
    if isinstance(installed_paths, str):
        installed_paths = [installed_paths]

    builtin = bool(record.get("is_builtin")) or is_browser_builtin({
        "store": store,
        "extension_id": extension_id,
        "installed_paths": installed_paths,
    })

    if builtin:
        return {
            "risk_score": 0,
            "risk_band": "low",
            "capability_score": 0,
            "trust_score": 100,
            "threat_score": 0,
            "exposure_score": 0,
            "risk_signals": [{
                "code": "browser-builtin",
                "weight": 0,
                "detail": "vendor-shipped/component extension; never auto-flagged",
            }],
            "store_status": "builtin",
            "is_builtin": True,
            "publisher_reputable": True,
            "known_bad": False,
            "install_users": None,
            "manifest_version": None,
            "permissions": [],
            "host_permissions": [],
            "content_script_matches": [],
            "latest_version": None,
            "store_url": None,
            "publisher": None,
            "category": None,
            "rating": None,
            "rating_count": None,
            "updated_at": None,
            "intel_error": None,
        }

    perms, hosts, matches, optional = _permission_sets(meta, record)
    capability, cap_signals = _capability(perms, hosts, matches, optional)
    signals = list(cap_signals)

    publisher = _clean_str(
        meta.get("developer") or meta.get("publisher") or record.get("vendor")
    )
    if meta.get("store") == "chrome":
        reputable = chrome_publisher_is_reputable(meta.get("publisher_id"))
    elif meta.get("store") == "firefox":
        reputable = amo_author_is_reputable(meta.get("author_ids"))
    elif meta.get("store") == "edge":
        reputable = edge_extension_is_reputable(record.get("extension_id"), meta.get("status"))
    else:
        reputable = publisher_is_reputable(meta.get("developer"), meta.get("publisher"))
    sideload_signal = None
    if reputable and meta.get("store") in ("chrome", "firefox", "edge"):
        if not store_install_verified(meta.get("store"), record.get("extension_id"),
                                      record.get("installs")):
            reputable = False
            sideload_signal = {"code": "not-store-install", "weight": 0,
                               "detail": "publisher is known, but not every host install is in the "
                                         "browser's store directory (unpacked or unreported path); "
                                         "publisher trust not applied"}
    trust, trust_signals = _trust_score(meta, record, reputable=reputable)
    if sideload_signal:
        trust_signals.append(sideload_signal)
    threat, threat_signals = _threat_score(meta, record, blocklist_entry)
    signals.extend(threat_signals)

    host_count = _as_int(record.get("host_count")) or 0
    versions = record.get("versions") or []
    exposure = _exposure_score(host_count, len(versions) if isinstance(versions, list) else 0)

    name_signals, name_penalty = name_anomaly_signals(
        name, display_name, store=store
    )
    signals.extend(name_signals)

    users = _as_int(meta.get("users"))
    if users is None:
        users = _as_int(record.get("install_users"))

    rarity_penalty = 0
    if users is not None and users < 1000:
        if reputable:
            signals.append({
                "code": "low-installs-reputable-publisher",
                "weight": 0,
                "detail": f"only {users:,} installs, but the publisher is known",
            })
        elif users < 100:
            rarity_penalty += 8
            signals.append({"code": "very-low-installs", "weight": 8,
                            "detail": f"only {users:,} store installs"})
        else:
            rarity_penalty += 4
            signals.append({"code": "low-installs", "weight": 4,
                            "detail": f"only {users:,} store installs"})

    if host_count <= 1:
        rarity_penalty += 4
        signals.append({"code": "single-host", "weight": 4,
                        "detail": "installed on at most one host in this fleet"})
    elif fleet_host_count and fleet_host_count >= 10:
        ratio = host_count / max(fleet_host_count, 1)
        if ratio < 0.03:
            rarity_penalty += 3
            signals.append({"code": "rare-in-fleet", "weight": 3,
                            "detail": f"installed on {host_count}/{fleet_host_count} hosts"})

    risk = round(
        0.35 * capability
        + 0.25 * (100 - trust)
        + 0.25 * threat
        + 0.15 * exposure
        + name_penalty
        + rarity_penalty
    )

    status = _clean_str(meta.get("status") or record.get("store_status") or "unknown").lower()
    known_bad = bool(blocklist_entry)
    if known_bad:
        # A blocklisted extension is never "low" regardless of popularity.
        risk = max(risk, 85)
        if users is not None and users >= 100_000:
            risk = max(risk, 96)
            signals.append({
                "code": "known-bad-at-scale",
                "weight": 30,
                "detail": f"blocked extension with {users:,} installs",
            })
        elif users is not None and users >= 10_000:
            risk = max(risk, 92)
            signals.append({
                "code": "known-bad-popular",
                "weight": 20,
                "detail": f"blocked extension with {users:,} installs",
            })
    elif status == "removed":
        risk = max(risk, 60)
    elif status == "not_found" and name_penalty >= 18:
        risk = max(risk, 55)

    risk = max(0, min(100, risk))
    signals.extend(trust_signals)
    signals.sort(key=lambda s: abs(int(s.get("weight") or 0)), reverse=True)

    return {
        "risk_score": risk,
        "risk_band": risk_band(risk),
        "capability_score": capability,
        "trust_score": trust,
        "threat_score": threat,
        "exposure_score": exposure,
        "risk_signals": signals,
        "store_status": status,
        "is_builtin": False,
        "publisher_reputable": reputable,
        "known_bad": known_bad,
        "install_users": users,
        "manifest_version": _as_int(meta.get("manifest_version")),
        "permissions": sorted(perms),
        "host_permissions": sorted(hosts),
        "content_script_matches": sorted(matches),
        "latest_version": _clean_str(meta.get("version")) or None,
        "store_url": _clean_str(meta.get("url")) or None,
        "publisher": publisher or None,
        "category": _clean_str(meta.get("category")) or None,
        "rating": _as_float(meta.get("rating")),
        "rating_count": _as_int(meta.get("rating_count")),
        "updated_at": _clean_str(meta.get("updated_at")) or None,
        "featured": meta.get("featured") if isinstance(meta.get("featured"), bool) else None,
        "established_publisher": meta.get("established_publisher") is True or None,
        "developer_verified": meta.get("developer_verified") if isinstance(meta.get("developer_verified"), bool) else None,
        "developer_email": _clean_str(meta.get("developer_email")) or None,
        "developer_website": _clean_str(meta.get("developer_website")) or None,
        "trader": meta.get("trader") if isinstance(meta.get("trader"), bool) else None,
        "privacy_disclosure": _clean_str(meta.get("privacy_disclosure")) or None,
        "privacy_policy_url": _clean_str(meta.get("privacy_policy_url")) or None,
        "intel_error": _clean_str(meta.get("error")) or None,
    }


# ---------------------------------------------------------------------------
# Anonymous HTTP client
# ---------------------------------------------------------------------------

_USER_AGENT = "fleet-hound-extension-intel/1.0 (+https://github.com/)"
_MAX_HTTP_BYTES = 8 * 1024 * 1024
_CHROME_HOSTS = frozenset({
    "clients2.google.com",          # update2 endpoint
    "storage.googleapis.com",       # CRX CDN (verified 2026-10)
    "clients2.googleusercontent.com",  # CRX CDN (codebase target)
    "redirector.gvt1.com",          # CRX CDN redirector
    "edgedl.me.gvt1.com",           # CRX CDN edge download host
    "chromewebstore.google.com",    # detail page (publisher name)
})
_EDGE_HOSTS = frozenset({"microsoftedge.microsoft.com"})
_AMO_HOSTS = frozenset({"addons.mozilla.org"})
_MOZILLA_HOSTS = frozenset({"firefox.settings.services.mozilla.com"})


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts):
        self.allowed_hosts = frozenset(allowed_hosts)
        super().__init__()

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        host = (urllib.parse.urlparse(newurl).hostname or "").lower()
        if host not in self.allowed_hosts:
            raise urllib.error.URLError(f"redirect to non-allowlisted host: {host}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpClient:
    """Minimal urllib wrapper with size caps and host allowlisting."""

    def __init__(self, timeout: float = 12.0):
        self.timeout = timeout

    def get(self, url: str, *, allowed_hosts, max_bytes: int = _MAX_HTTP_BYTES):
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        if host not in allowed_hosts:
            return 0, {}, b"", f"host not allowlisted: {host}"
        opener = urllib.request.build_opener(_SafeRedirectHandler(allowed_hosts))
        req = urllib.request.Request(url, headers={
            "User-Agent": _USER_AGENT,
            "Accept": "*/*",
        })
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                final_host = (urllib.parse.urlparse(resp.geturl()).hostname or "").lower()
                if final_host not in allowed_hosts:
                    return 0, {}, b"", f"redirected to non-allowlisted host: {final_host}"
                body = resp.read(max_bytes + 1)
                if len(body) > max_bytes:
                    return resp.status, dict(resp.headers), body[:max_bytes], "response too large"
                return resp.status, dict(resp.headers), body, None
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(max_bytes + 1)
            except Exception:
                body = b""
            return exc.code, dict(exc.headers or {}), body, None
        except Exception as exc:
            return 0, {}, b"", str(exc)


# ---------------------------------------------------------------------------
# Store adapters
# ---------------------------------------------------------------------------

def _json_loads(body: bytes):
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except (TypeError, ValueError):
        return None


def _header(headers: dict, name: str) -> str:
    name = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == name:
            return _clean_str(value)
    return ""


def _mark_rate_limited(meta: dict, status: int, headers: dict) -> bool:
    """Flag 429 / 503+Retry-After so the worker trips its per-store breaker.

    `error` is set so the result is never cached; `rate_limited` tells the
    worker to leave the item unstamped for the next cycle.
    """
    if status == 429 or (status == 503 and _header(headers, "Retry-After")):
        meta["error"] = f"{meta.get('store')} store HTTP {status} (rate limited)"
        meta["rate_limited"] = True
        return True
    return False


def _first(data: dict, *keys):
    for key in keys:
        value = data.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _localised_name(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("en-US", "en", "en_GB"):
            if isinstance(value.get(key), str):
                return value[key]
        for candidate in value.values():
            if isinstance(candidate, str) and candidate:
                return candidate
    return ""


def _manifest_from_meta(meta: dict) -> dict:
    manifest = _first(meta, "manifest", "manifest_json", "manifestJson")
    if isinstance(manifest, str):
        try:
            manifest = json.loads(manifest)
        except ValueError:
            return {}
    return manifest if isinstance(manifest, dict) else {}


def _manifest_fields(meta: dict) -> dict:
    manifest = _manifest_from_meta(meta)
    if not manifest:
        return {}
    content_matches = []
    for cs in manifest.get("content_scripts") or []:
        if isinstance(cs, dict):
            content_matches.extend(_as_string_list(cs.get("matches")))
    return {
        "name": _clean_str(manifest.get("name")) or None,
        "version": _clean_str(manifest.get("version")) or None,
        "manifest_version": _as_int(manifest.get("manifest_version")),
        "permissions": _as_string_list(manifest.get("permissions")),
        "optional_permissions": _as_string_list(manifest.get("optional_permissions")),
        "host_permissions": _as_string_list(manifest.get("host_permissions")),
        "content_script_matches": content_matches,
        "update_url": _clean_str(manifest.get("update_url")) or None,
        "homepage_url": _clean_str(manifest.get("homepage_url")) or None,
    }


_MAX_MANIFEST_BYTES = 1024 * 1024


def _parse_crx(data: bytes) -> dict:
    """Return manifest.json from a CRX2/CRX3 or plain ZIP payload."""
    if not data:
        raise ValueError("empty CRX payload")
    zip_bytes = data
    if data[:4] == b"Cr24":
        if len(data) < 12:
            raise ValueError("truncated CRX header")
        version = int.from_bytes(data[4:8], "little")
        if version == 3:
            header_len = int.from_bytes(data[8:12], "little")
            zip_bytes = data[12 + header_len:]
        elif version == 2:
            if len(data) < 16:
                raise ValueError("truncated CRX2 header")
            pubkey_len = int.from_bytes(data[8:12], "little")
            sig_len = int.from_bytes(data[12:16], "little")
            zip_bytes = data[16 + pubkey_len + sig_len:]
        else:
            raise ValueError(f"unsupported CRX version {version}")
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as exc:
        raise ValueError(f"CRX payload is not a ZIP: {exc}") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > 5000:
            raise ValueError("CRX contains too many files")
        # Only manifest.json is ever decompressed, so cap that entry, not the
        # archive: real extensions (Bitwarden) exceed 80 MB uncompressed. The
        # bounded read holds even if the entry under-reports its size.
        try:
            with zf.open("manifest.json") as fh:
                raw = fh.read(_MAX_MANIFEST_BYTES + 1)
        except KeyError as exc:
            raise ValueError("CRX has no manifest.json") from exc
        if len(raw) > _MAX_MANIFEST_BYTES:
            raise ValueError("manifest.json exceeds 1 MB")
        manifest = json.loads(raw.decode("utf-8-sig", errors="replace"))
        if not isinstance(manifest, dict):
            raise ValueError("manifest.json is not an object")
        return manifest


# Publisher link on a Chrome Web Store detail page:
#   <a ... data-publisher-id="u<32 hex>" ...>AgileBits Inc</a>
# Bounded quantifiers keep this linear on the ~1 MB untrusted page.
_CWS_PUBLISHER_RE = re.compile(
    rb'data-publisher-id="(u[0-9a-f]{32})"[^>]{0,400}>([^<]{1,150})</a>'
)
_CHROME_EXTENSION_ID_RE = re.compile(r"[a-p]{32}")


def _chrome_publisher(page: bytes) -> tuple[str, str] | None:
    """(publisher_id, display name), or None unless exactly one publisher ID appears.

    A listing has one publisher link; more than one distinct ID means the
    markup changed or the page embeds another publisher, so trust nothing.
    """
    matches = _CWS_PUBLISHER_RE.findall(page)
    if len({pid for pid, _ in matches}) != 1:
        return None
    pid, raw = matches[0]
    name = html.unescape(raw.decode("utf-8", "replace")).strip()
    return pid.decode("ascii"), name or pid.decode("ascii")


# Every pattern below needs literal markup (`<`, `>`, `"`). Developer-written
# text (name, description) is HTML-escaped on the page, so it can never
# satisfy one — free-text matching would let a description fake a badge.
_CWS_WEBSITE_RE = re.compile(
    r'<a href="(https?://[^"\s]{1,300})"[^>]{0,500}>'
    r'(?:<svg[^>]{0,300}>(?:<path[^>]{0,3000}/>){0,5}</svg>)?\s{0,5}Website</a>'
)
_CWS_USERS_RE = re.compile(
    r'href="\./category/extensions/[^"]{1,100}"[^>]{0,300}>([^<]{1,80})</a>([\d,]{1,15})\+? users?</div>'
)
_CWS_RATING_RE = re.compile(r'aria-label="Average rating ([0-5](?:\.\d{1,2})?) out of 5')
_CWS_RATING_COUNT_RE = re.compile(r'<p[^>]{0,100}>([\d,.]{1,12})(K?) ratings?</p>')
_CWS_ESTABLISHED_RE = re.compile(
    r'aria-label="(?:Created by the owner of the listed website\. )?'
    r'The publisher has a good record with no history of violations\.'
)
# The Featured badge's tooltip link; Google shows it only on Featured items.
_CWS_FEATURED_RE = re.compile(
    r'aria-label="Follows recommended practices for Chrome extensions\.'
)
_CWS_UPDATED_RE = re.compile(r'>Updated</div><div>([^<]{1,40})</div>')
_CWS_EMAIL_RE = re.compile(
    r'> Email (?:<svg[^>]{0,300}>(?:<path[^>]{0,3000}/>){0,5}</svg>){0,3}</summary>'
    r'<div[^>]{0,100}>([^<]{1,320})</div>'
)
_CWS_TRADER_RE = re.compile(r'>(Trader|Non-trader)</div><div>This developer ')
_CWS_PRIVACY_RE = re.compile(r'</svg><span>(The developer has disclosed that it [^<.]{1,160})')
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}$")


def _chrome_listing(page: bytes) -> dict:
    """Store-listing facts from a Chrome Web Store detail page (fetched with hl=en).

    Fields anchor on store markup and English labels, not the rotating
    minified class names. Parsing stops at the "Related" carousel so another
    listing's facts can never be attributed to this one. Missing fields are
    omitted.
    """
    text = page.decode("utf-8", "replace")
    cut = text.find(">Related<")
    if cut > 0:
        text = text[:cut]
    out: dict = {}
    m = _CWS_USERS_RE.search(text)
    if m:
        out["category"] = html.unescape(m.group(1)).strip()
        out["users"] = int(m.group(2).replace(",", ""))
    else:
        m = re.search(r'href="\./category/extensions/[^"]{1,100}"[^>]{0,300}>([^<]{1,80})</a>', text)
        if m:
            out["category"] = html.unescape(m.group(1)).strip()
    m = _CWS_RATING_RE.search(text)
    if m:
        out["rating"] = float(m.group(1))
    m = _CWS_RATING_COUNT_RE.search(text)
    if m:
        n = float(m.group(1).replace(",", ""))
        out["rating_count"] = int(n * 1000 if m.group(2) else n)
    if _CWS_FEATURED_RE.search(text):
        out["featured"] = True
    if _CWS_ESTABLISHED_RE.search(text):
        out["established_publisher"] = True
    m = _CWS_UPDATED_RE.search(text)
    if m:
        try:
            out["updated_at"] = datetime.strptime(m.group(1).strip(), "%B %d, %Y").replace(
                tzinfo=timezone.utc).isoformat()
        except ValueError:
            pass
    m = _CWS_WEBSITE_RE.search(text)
    if m:
        out["developer_website"] = html.unescape(m.group(1))
    m = _CWS_EMAIL_RE.search(text)
    if m:
        email = html.unescape(m.group(1)).strip()
        if _EMAIL_RE.match(email):
            out["developer_email"] = email
    m = _CWS_TRADER_RE.search(text)
    if m:
        out["trader"] = m.group(1) == "Trader"
    m = _CWS_PRIVACY_RE.search(text)
    if m:
        out["privacy_disclosure"] = html.unescape(m.group(1)).strip()
    return out


def fetch_chrome_metadata(extension_id: str, *, client: HttpClient | None = None) -> dict:
    client = client or HttpClient()
    # Host-reported ID: only a real Chrome ID may reach a store URL path.
    if not _CHROME_EXTENSION_ID_RE.fullmatch(extension_id or ""):
        return {"store": "chrome", "status": "unknown", "error": "invalid chrome extension id"}
    meta = {"store": "chrome", "status": "unknown", "url": (
        "https://chromewebstore.google.com/detail/" + urllib.parse.quote(extension_id, safe="")
    )}
    query = urllib.parse.quote(f"id={extension_id}&uc", safe="")
    # Far-future Chrome version: update2 answers "noupdate" (no codebase) when
    # the item's minimum_chrome_version exceeds prodversion, and a pinned real
    # version goes stale as vendors raise their minimum.
    url = (
        "https://clients2.google.com/service/update2/crx"
        f"?response=updatecheck&prodversion=999.0&acceptformat=crx2,crx3&x={query}"
    )
    status, headers, body, error = client.get(url, allowed_hosts=_CHROME_HOSTS, max_bytes=1_000_000)
    if _mark_rate_limited(meta, status, headers):
        return meta
    if error and status == 0:
        meta["error"] = error
        return meta
    if status != 200 or not body:
        meta["error"] = f"update2 HTTP {status}"
        return meta

    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(body)
        updatecheck = None
        for elem in root.iter():
            if elem.tag.rsplit("}", 1)[-1] == "updatecheck":
                updatecheck = elem
                break
        if updatecheck is None:
            meta["status"] = "not_found"
            meta["error"] = "update2 returned no updatecheck element"
            return meta
        check_status = (updatecheck.get("status") or "").lower()
        if check_status.startswith("error-unknownapplication") or check_status.startswith("error"):
            meta["status"] = "not_found"
            meta["error"] = check_status
            return meta
        meta.update({
            "status": "public",
            "version": updatecheck.get("version"),
            "url": meta["url"],
        })
        # update2 carries no developer field; the detail page does. Without it
        # no Chrome-family extension can ever count as a reputable publisher.
        # hl=en: the listing parser anchors on English labels.
        dstatus, dheaders, dbody, _ = client.get(
            meta["url"] + "?hl=en", allowed_hosts=_CHROME_HOSTS, max_bytes=2 * 1024 * 1024
        )
        if _mark_rate_limited(meta, dstatus, dheaders):
            return meta
        if dstatus == 200 and dbody:
            publisher = _chrome_publisher(dbody)
            if publisher:
                meta["publisher_id"], meta["publisher"] = publisher
            meta.update(_chrome_listing(dbody))
        codebase = updatecheck.get("codebase") or ""
        expected_hash = (updatecheck.get("hash_sha256") or "").lower()
        if not codebase:
            # "noupdate": Google serves no package for this ID (e.g. MV2 items
            # Chrome no longer runs). Nothing was parsed, so nothing is suspect.
            meta["manifest_unavailable"] = f"update2 status {check_status or 'missing'}, no codebase"
            return meta
        cstatus, _, crx, cerr = client.get(
            codebase, allowed_hosts=_CHROME_HOSTS, max_bytes=50 * 1024 * 1024
        )
        if cstatus == 200 and cerr == "response too large":
            # Our download cap, not a bad package (ad blockers bundle >50 MB of
            # filter lists). A truncated ZIP has no central directory to read.
            meta["manifest_unavailable"] = "CRX exceeds 50 MB download cap"
            return meta
        if cstatus != 200 or not crx:
            meta["manifest_error"] = cerr or f"CRX HTTP {cstatus}"
            return meta
        actual_hash = hashlib.sha256(crx).hexdigest()
        if expected_hash:
            meta["crx_hash_verified"] = actual_hash == expected_hash
            if not meta["crx_hash_verified"]:
                meta["manifest_error"] = "CRX SHA-256 does not match update2"
        try:
            manifest = _parse_crx(crx)
        except ValueError as exc:
            meta["manifest_error"] = str(exc)
            return meta
        fields = _manifest_fields({"manifest": manifest})
        for key, value in fields.items():
            if value not in (None, [], ""):
                meta[key] = value
        return meta
    except Exception as exc:
        meta["error"] = f"update2 parse failed: {exc}"
        return meta


def fetch_edge_metadata(extension_id: str, *, client: HttpClient | None = None) -> dict:
    client = client or HttpClient()
    meta = {"store": "edge", "status": "unknown", "url": (
        f"https://microsoftedge.microsoft.com/addons/detail/{extension_id}"
    )}
    url = f"https://microsoftedge.microsoft.com/addons/getproductdetailsbycrxid/{extension_id}"
    status, headers, body, error = client.get(url, allowed_hosts=_EDGE_HOSTS, max_bytes=2_000_000)
    if _mark_rate_limited(meta, status, headers):
        return meta
    if status == 404:
        meta["status"] = "not_found"
        meta["error"] = "edge detail returned 404"
        return meta
    data = _json_loads(body) if body else None
    if status != 200 or data is None:
        meta["error"] = error or f"edge detail HTTP {status}"
        return meta
    if not data:
        meta["status"] = "not_found"
        meta["error"] = "edge detail returned an empty object"
        return meta

    manifest_fields = _manifest_fields(data)
    developer = _first(data, "developer", "developerName", "publisher", "publisherName")
    verified = _first(data, "developerVerified", "isDeveloperVerified", "verified")
    if isinstance(developer, dict):
        verified = developer.get("verified", verified)
        developer = _first(developer, "name", "displayName", "publisherName")
    updated = _first(data, "lastUpdateDate", "lastUpdated", "updateDate")
    if isinstance(updated, (int, float)) and updated > 0:  # live API returns epoch seconds
        updated = datetime.fromtimestamp(updated, timezone.utc).isoformat()
    featured = data.get("isBadgedAsFeatured")
    meta.update({
        "status": "public",
        "name": _clean_str(_first(data, "name", "extensionName")) or manifest_fields.get("name"),
        "version": _clean_str(_first(data, "version", "latestVersion")) or manifest_fields.get("version"),
        "users": _as_int(_first(data, "activeInstallCount", "users", "userCount", "installCount")),
        "rating": _as_float(_first(data, "rating", "averageRating")),
        "rating_count": _as_int(_first(data, "ratingCount", "ratingsCount", "rating_count")),
        "developer": _clean_str(developer) or None,
        "developer_verified": bool(verified) if verified is not None else None,
        "developer_website": _clean_str(data.get("publisherWebsiteUri")) or None,
        "featured": featured if isinstance(featured, bool) else None,
        "category": _clean_str(_first(data, "category", "categories")) or None,
        "updated_at": _clean_str(updated) or None,
        "privacy_policy_url": _clean_str(_first(data, "privacyUrl", "privacyPolicyUrl", "privacyPolicy")) or None,
    })
    for key, value in manifest_fields.items():
        if value not in (None, [], ""):
            meta[key] = value
    return meta


def fetch_amo_metadata(guid: str, *, client: HttpClient | None = None) -> dict:
    client = client or HttpClient()
    meta = {"store": "firefox", "status": "unknown", "url": (
        f"https://addons.mozilla.org/firefox/addon/{urllib.parse.quote(guid, safe='')}/"
    )}
    url = f"https://addons.mozilla.org/api/v5/addons/addon/{urllib.parse.quote(guid, safe='')}/"
    status, headers, body, error = client.get(url, allowed_hosts=_AMO_HOSTS, max_bytes=2_000_000)
    if _mark_rate_limited(meta, status, headers):
        return meta
    if status == 401:
        meta["status"] = "unlisted"
        meta["error"] = "AMO returned 401 (unlisted or self-distributed)"
        return meta
    if status == 404:
        meta["status"] = "not_found"
        meta["error"] = "AMO returned 404 (built-in or unknown GUID)"
        return meta
    data = _json_loads(body) if body else None
    if status != 200 or not isinstance(data, dict):
        meta["error"] = error or f"AMO HTTP {status}"
        return meta

    current = data.get("current_version") if isinstance(data.get("current_version"), dict) else {}
    file_info = current.get("file") if isinstance(current.get("file"), dict) else {}
    authors = data.get("authors") if isinstance(data.get("authors"), list) else []
    # Numeric AMO user IDs are immutable; author display names are not.
    meta["author_ids"] = [a["id"] for a in authors
                          if isinstance(a, dict) and isinstance(a.get("id"), int) and a["id"] > 0]
    developer = ""
    if authors and isinstance(authors[0], dict):
        developer = _first(authors[0], "name", "username") or ""
    ratings = data.get("ratings") if isinstance(data.get("ratings"), dict) else {}
    status_text = _clean_str(data.get("status")).lower()
    if status_text in ("public", "listed"):
        meta_status = "public"
    elif status_text in ("unlisted", "self"):
        meta_status = "unlisted"
    elif status_text in ("disabled", "removed", "deleted"):
        meta_status = "removed"
    else:
        meta_status = "public"
    if data.get("is_disabled") is True:
        meta_status = "removed"
    promoted = data.get("promoted") if isinstance(data.get("promoted"), list) else []
    categories = [p.get("category") for p in promoted if isinstance(p, dict)]
    email = _clean_str(_localised_name(data.get("support_email")))
    homepage = data.get("homepage")
    if isinstance(homepage, dict) and "url" in homepage:  # v5: {"url": {locale: url}, ...}
        homepage = homepage["url"]

    permissions = _as_string_list(
        file_info.get("permissions") or current.get("permissions") or data.get("permissions")
    )
    host_permissions = _as_string_list(
        file_info.get("host_permissions") or current.get("host_permissions")
        or data.get("host_permissions")
    )
    optional = _as_string_list(
        file_info.get("optional_permissions") or current.get("optional_permissions")
        or data.get("optional_permissions")
    )
    content_matches = _as_string_list(
        current.get("content_script_matches") or data.get("content_script_matches")
    )
    meta.update({
        "status": meta_status,
        "name": _localised_name(data.get("name")) or None,
        "version": _clean_str(current.get("version")) or None,
        "users": _as_int(data.get("average_daily_users") or data.get("weekly_downloads")),
        "rating": _as_float(ratings.get("average")),
        "rating_count": _as_int(ratings.get("count")),
        "developer": _clean_str(developer) or None,
        "category": _clean_str(data.get("category") or next(iter(
            data.get("categories") if isinstance(data.get("categories"), list) else []), None)) or None,
        "updated_at": _clean_str(current.get("created")) or _clean_str(data.get("last_updated")) or None,
        "manifest_version": _as_int(current.get("manifest_version")),
        "permissions": permissions,
        "host_permissions": host_permissions,
        "optional_permissions": optional,
        "content_script_matches": content_matches,
        "crx_hash_verified": None,
        # Mozilla's "recommended"/"line" programs include a manual code review.
        "featured": any(c in ("recommended", "line") for c in categories),
        "developer_email": email if _EMAIL_RE.match(email) else None,
        "developer_website": _clean_str(_localised_name(homepage)) or None,
        "privacy_policy_url": (meta["url"] + "privacy/") if data.get("has_privacy_policy") else None,
        "created_at": _clean_str(data.get("created")) or None,
    })
    return meta


def fetch_store_metadata(store: str, extension_id: str, *,
                         client: HttpClient | None = None) -> dict:
    """Dispatch to the anonymous adapter for `store`. Never raises."""
    store = _clean_str(store).lower()
    extension_id = _clean_str(extension_id)
    if not extension_id:
        return {"store": store, "status": "unknown", "error": "missing extension id"}
    try:
        if store in ("chrome", "brave", "opera", "vivaldi", "chromium"):
            return fetch_chrome_metadata(extension_id, client=client)
        if store == "edge":
            return fetch_edge_metadata(extension_id, client=client)
        if store == "firefox":
            return fetch_amo_metadata(extension_id, client=client)
        return {"store": store, "status": "unknown",
                "error": f"no anonymous metadata adapter for store '{store}'"}
    except Exception as exc:
        logger.warning("extension metadata fetch failed store=%s id=%s: %s",
                       store, extension_id, exc)
        return {"store": store, "status": "unknown", "error": str(exc)}


def fetch_mozilla_blocklist(*, client: HttpClient | None = None) -> dict:
    """Return {guid: record} from the Mozilla add-on blocklist. Never raises."""
    client = client or HttpClient()
    url = (
        "https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/"
        "collections/addons/records"
    )
    records: dict[str, dict] = {}
    seen_urls = set()
    for _ in range(20):
        if not url or url in seen_urls:
            break
        seen_urls.add(url)
        status, headers, body, error = client.get(
            url, allowed_hosts=_MOZILLA_HOSTS, max_bytes=8 * 1024 * 1024
        )
        if status != 200 or not body:
            logger.warning("mozilla blocklist fetch failed: %s", error or status)
            break
        payload = _json_loads(body)
        if not isinstance(payload, dict):
            break
        for record in payload.get("data") or []:
            if isinstance(record, dict) and record.get("guid"):
                guid = str(record["guid"])
                prior = records.get(guid)
                if prior is not None:
                    # Mozilla files separate records per blocked version range
                    # for one GUID; keep every range, not just the last record.
                    record = {**record, "versionRange": list(prior.get("versionRange") or [])
                              + list(record.get("versionRange") or [])}
                records[guid] = record
        # Kinto paginates via the Next-Page header; `next` kept as a fallback.
        url = _header(headers, "Next-Page") or payload.get("next")
    return records


@functools.lru_cache(maxsize=4096)
def _guid_regex(guid: str):
    """Compile a `/pattern/` blocklist GUID once. None for plain/invalid GUIDs."""
    if len(guid) < 3 or not guid.startswith("/") or not guid.endswith("/"):
        return None
    try:
        return re.compile(guid[1:-1])
    except re.error:
        return None


def _version_key(version: str) -> list[tuple]:
    # Per dot part: numeric prefix, then "no suffix" sorts after a suffix
    # (1.0a < 1.0, like Mozilla pre-releases), then the suffix as a string.
    key = []
    for part in str(version).strip().split("."):
        if part == "*":  # "1.2.*" = any 1.2.x
            key.append((math.inf, True, ""))
            continue
        m = re.match(r"(\d*)(.*)", part)
        key.append((int(m.group(1) or 0), not m.group(2), m.group(2)))
    return key


def compare_versions(a: str, b: str) -> int:
    ka, kb = _version_key(a), _version_key(b)
    pad = (0, True, "")
    n = max(len(ka), len(kb))
    ka += [pad] * (n - len(ka))
    kb += [pad] * (n - len(kb))
    return (ka > kb) - (ka < kb)


def _version_blocked(entry: dict, versions) -> bool:
    ranges = [r for r in entry.get("versionRange") or [] if isinstance(r, dict)]
    known = [v for v in versions or () if _clean_str(v)]
    if not ranges or not known:
        return True  # no range = every version; unknown installed version fails closed
    for rng in ranges:
        lo = _clean_str(rng.get("minVersion")) or "*"
        hi = _clean_str(rng.get("maxVersion")) or "*"
        for v in known:
            if (lo == "*" or compare_versions(v, lo) >= 0) and \
                    (hi == "*" or compare_versions(v, hi) <= 0):
                return True
    return False


def match_blocklist(blocklist: dict, extension_id: str, versions=()) -> dict | None:
    """Return the blocklist record covering `extension_id` at any of `versions`.

    `blocklist` is the raw {guid: record} map from fetch_mozilla_blocklist()
    (JSON-cacheable). GUIDs may be exact IDs or `/regex/` patterns; regexes
    are compiled lazily and memoised. Empty `versions` fails closed.
    """
    extension_id = _clean_str(extension_id)
    if not extension_id or not blocklist:
        return None
    entry = blocklist.get(extension_id)
    if isinstance(entry, dict) and _version_blocked(entry, versions):
        return entry
    for guid, entry in blocklist.items():
        rx = _guid_regex(guid) if guid.startswith("/") else None
        if rx and isinstance(entry, dict) and rx.search(extension_id) \
                and _version_blocked(entry, versions):
            return entry
    return None


# ---------------------------------------------------------------------------
# Graph-facing helpers
# ---------------------------------------------------------------------------

def summarize_vulnerabilities(vulnerabilities) -> tuple[str, int, float | None]:
    """Return (json, count, max_cvss) suitable for Memgraph scalar properties."""
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        return "[]", 0, None
    cleaned = []
    max_cvss = None
    for vuln in vulnerabilities[:50]:
        if not isinstance(vuln, dict):
            continue
        cvss = _as_float(
            vuln.get("cvss_score") or vuln.get("cvss") or vuln.get("cvss_v3_score")
        )
        if cvss is not None:
            max_cvss = cvss if max_cvss is None else max(max_cvss, cvss)
        cleaned.append({
            "cve": _clean_str(vuln.get("cve") or vuln.get("cve_id")) or None,
            "cvss_score": cvss,
            "epss_probability": _as_float(vuln.get("epss_probability")),
            "details": _clean_str(vuln.get("details"))[:500] or None,
            "created_at": _clean_str(vuln.get("created_at")) or None,
        })
    try:
        encoded = json.dumps(cleaned, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        encoded = "[]"
    return encoded[:20_000], len(vulnerabilities), max_cvss


def signals_json(signals) -> str:
    try:
        return json.dumps(signals or [], separators=(",", ":"), default=str)[:20_000]
    except (TypeError, ValueError):
        return "[]"


# ---------------------------------------------------------------------------
# Self-check: `python3 src/extension_intel.py`
# ---------------------------------------------------------------------------

def _self_check() -> None:
    import tempfile
    # Self-check uses its own publisher fixture, independent of the operator list.
    fixture = {"publishers": [
        {"name": "Google", "match_names": ["Google", "Google Ireland"], "added_at": "2026-10-26T00:00:00Z",
         "chrome_publisher_ids": ["udcdd80226b381e8c9845d3e7861f0e71"]},
        {"name": "Meta", "match_names": ["Meta"], "added_at": "2026-10-26T00:00:00Z"},
        {"name": "Mozilla", "match_names": ["Mozilla"], "added_at": "2026-10-26T00:00:00Z",
         "amo_author_ids": [101]},
        {"name": "Bad Amo", "added_at": "2026-10-26T00:00:00Z", "amo_author_ids": ["101"]},  # skipped
        {"name": "Microsoft", "match_names": ["Microsoft"], "added_at": "2026-10-26T00:00:00Z",
         "edge_extension_ids": ["jmjflgjpcpepeafmmgdpfkogkghcpiha"]},
        {"name": "AdGuard", "match_names": ["AdGuard"], "added_at": "2026-10-26T00:00:00Z"},
        {"name": "1Password", "match_names": ["1Password", "AgileBits"], "added_at": "2026-10-26T00:00:00Z",
         "chrome_publisher_ids": ["udb847e9815e2e1626d9ddb346d722811"]},
        {"name": "DuckDuckGo", "match_names": ["DuckDuckGo", "Duck Duck Go"], "added_at": "2026-10-26T00:00:00Z"},
        {"name": "No Timestamp"},                                                   # skipped
        {"name": "Bad Id", "added_at": "2026-10-26T00:00:00Z", "chrome_publisher_ids": ["x"]},  # skipped
    ]}
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(fixture, tmp)
    tmp.close()
    os.environ["KNOWN_PUBLISHERS_FILE"] = tmp.name
    assert not publisher_is_reputable("No Timestamp") and not publisher_is_reputable("Bad Id")
    fixture["publishers"].append({"name": "ChromeOnly", "added_at": "2026-10-26T00:00:00Z",
                                  "chrome_publisher_ids": ["u" + "2" * 32]})
    with open(tmp.name, "w") as fh:
        json.dump(fixture, fh)
    os.utime(tmp.name, (os.path.getmtime(tmp.name) + 2,) * 2)
    assert not publisher_is_reputable("ChromeOnly"), "Chrome-ID-only entry must not trust its name"
    assert chrome_publisher_is_reputable("u" + "2" * 32)

    builtin = analyze_extension({
        "store": "chrome", "extension_id": "ghbmnnjooekpmoecnnnilnnbdlolhkhi",
        "name": "google docs offline", "host_count": 32,
    })
    assert builtin["risk_score"] == 0 and builtin["risk_band"] == "low", builtin

    bad = analyze_extension({
        "store": "edge", "extension_id": "pdffkfellgipmhklpdmokmckkkfcopbh",
        "name": "adguard adblocker", "host_count": 3,
        "store_meta": {"status": "public", "users": 11_548_306,
                       "developer": "AdGuard Software Ltd"},
    }, blocklist_entry={"why": "malicious"})
    assert bad["risk_score"] >= 95 and bad["risk_band"] == "critical", bad

    tiny_unknown = analyze_extension({
        "store": "firefox", "extension_id": "agent@example.com",
        "name": "agent bridge", "host_count": 1,
        "store_meta": {"status": "public", "users": 12, "developer": "unknown"},
    })
    assert tiny_unknown["risk_band"] in ("medium", "high"), tiny_unknown

    tiny_known = analyze_extension({
        "store": "firefox", "extension_id": "{ce9f4b1f-24b8-4e9a-9051-b9e472b1b2f2}",
        "name": "clear browsing data", "host_count": 1,
        "installs": ["/home/a/.mozilla/firefox/p.default/extensions/"
                          "{ce9f4b1f-24b8-4e9a-9051-b9e472b1b2f2}.xpi"],
        "store_meta": {"store": "firefox", "status": "public", "users": 41_759,
                       "developer": "Mozilla", "author_ids": [101]},
    })
    assert tiny_known["risk_band"] in ("low", "medium"), tiny_known
    assert any(s["code"] == "reputable-publisher" for s in tiny_known["risk_signals"])
    # Firefox trust is by AMO author ID: the right name with another ID is not trusted.
    amo_spoof = analyze_extension({
        "store": "firefox", "extension_id": "spoof@example.com", "name": "x", "host_count": 1,
        "store_meta": {"store": "firefox", "status": "public", "developer": "Mozilla",
                       "author_ids": [999]},
    })
    assert amo_spoof["publisher_reputable"] is False, "AMO name match without ID must not be trusted"
    assert not publisher_is_reputable("Bad Amo"), "string author IDs are rejected"
    # Edge: listed extension ID + public listing; the developer name alone earns nothing.
    edge_meta = {"store": "edge", "status": "public", "developer": "Microsoft Corporation"}
    edge_path = ["/Users/a/Library/Application Support/Microsoft Edge/Default/Extensions/"
                 "jmjflgjpcpepeafmmgdpfkogkghcpiha/1.0_0"]
    listed = analyze_extension({"store": "edge", "extension_id": "jmjflgjpcpepeafmmgdpfkogkghcpiha",
                                "name": "x", "host_count": 1, "store_meta": edge_meta,
                                "installs": edge_path})
    other = analyze_extension({"store": "edge", "extension_id": "b" * 32, "name": "x",
                               "host_count": 1, "store_meta": edge_meta})
    gone = analyze_extension({"store": "edge", "extension_id": "jmjflgjpcpepeafmmgdpfkogkghcpiha",
                              "name": "x", "host_count": 1, "installs": edge_path,
                              "store_meta": {**edge_meta, "status": "not_found"}})
    assert listed["publisher_reputable"] and not other["publisher_reputable"]
    assert not gone["publisher_reputable"], "listed ID no longer on the store is not trusted"
    # An unpacked copy claiming the listed ID (manifest `key`) loses store trust.
    sideloaded = analyze_extension({"store": "edge", "extension_id": "jmjflgjpcpepeafmmgdpfkogkghcpiha",
                                    "name": "x", "host_count": 2, "store_meta": edge_meta,
                                    "installs": edge_path + ["/Users/b/dev/copy/dist"]})
    assert not sideloaded["publisher_reputable"]
    assert any(s["code"] == "not-store-install" for s in sideloaded["risk_signals"])
    eid = "jmjflgjpcpepeafmmgdpfkogkghcpiha"
    assert store_install_verified("chrome", eid, [
        f"C:\\Users\\a\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\{eid}\\1_0",
        {"path": None, "platform": "chrome"}])                       # ChromeOS: no path reported
    for bad in ([f"/tmp/x/Extensions/{eid}/1.0"],                    # store-shaped, wrong root
                [f"/Users/a/evil/Google/Chrome/Default/Extensions/{eid}/1.0"],
                [f"/Users/a/Library/Application Support/Google/Chrome/Default/Extensions/{eid}/1/../../x"],
                [{"path": None, "platform": "darwin"}], [],          # missing path fails closed
                [{"path": None, "platform": "chrome"}]):              # ChromeOS-only: no evidence
        assert not store_install_verified("chrome", eid, bad), bad

    typo = analyze_extension({
        "store": "chrome", "extension_id": "a" * 32,
        "name": "adgaurd", "host_count": 1,
        "store_meta": {"status": "public", "users": 50, "developer": "someone"},
    })
    assert any(s["code"] == "typosquat-brand" for s in typo["risk_signals"]), typo

    # Brand list is normalised like names: the real brand is not its own typosquat.
    assert not name_anomaly_signals("1Password")[0]
    assert any(s["code"] == "typosquat-brand" for s in name_anomaly_signals("1Passw0rd")[0])
    assert any(s["code"] == "typosquat-brand" for s in name_anomaly_signals("G00gle")[0])

    # Reputation: store fields only, exact normalised names only.
    vendor_only = analyze_extension({
        "store": "chrome", "extension_id": "b" * 32, "name": "helper",
        "vendor": "Google", "host_count": 1, "store_meta": {"status": "public"},
    })
    assert vendor_only["publisher_reputable"] is False, vendor_only
    assert not publisher_is_reputable("Box Hill Scams")
    assert not publisher_is_reputable("Meta Tools")
    assert publisher_is_reputable("Google LLC") and publisher_is_reputable("Meta Platforms, Inc.")
    assert publisher_is_reputable("AdGuard Software Ltd")

    # Capability: content-script matches cancel the "no host permissions" discount.
    no_hosts, _ = _capability({"cookies"}, set(), set())
    with_cs, _ = _capability({"cookies"}, set(), {"https://example.com/*"})
    assert no_hosts == round(15 * 0.6) and with_cs == 15 + 5, (no_hosts, with_cs)
    opt, opt_signals = _capability({"storage"}, {"https://a/*"}, set(), {"debugger"})
    assert opt == 1 + 1 + 2, (opt, opt_signals)  # optional capped at required total
    opt, _ = _capability({"cookies"}, {"https://a/*"}, set(), {"debugger"})
    assert opt == 15 + 12 + 2, opt

    # Mozilla blocklist: regex GUIDs, versionRange, unknown version fails closed.
    blocklist = {
        "/^((evil@a\\.com)|(\\{0000-bad\\}))$/": {"why": "regex", "versionRange": []},
        "old@b.com": {"why": "old only", "versionRange": [
            {"minVersion": "0", "maxVersion": "1.2.*"},
            {"minVersion": "2.0b1", "maxVersion": "2.0"},
        ]},
        "all@c.com": {"why": "all", "versionRange": [{"minVersion": "0", "maxVersion": "*"}]},
    }
    assert match_blocklist(blocklist, "evil@a.com")["why"] == "regex"
    assert match_blocklist(blocklist, "{0000-bad}", ["9"])["why"] == "regex"
    assert match_blocklist(blocklist, "evil@a.comx") is None
    assert match_blocklist(blocklist, "old@b.com", ["1.1"])["why"] == "old only"
    assert match_blocklist(blocklist, "old@b.com", ["1.2.9"]) is not None
    assert match_blocklist(blocklist, "old@b.com", ["1.10"]) is None
    assert match_blocklist(blocklist, "old@b.com", ["2.0a1"]) is None
    assert match_blocklist(blocklist, "old@b.com", ["2.0b3"]) is not None
    assert match_blocklist(blocklist, "old@b.com", ["3.0"]) is None
    assert match_blocklist(blocklist, "old@b.com", ["3.0", "1.0"]) is not None
    assert match_blocklist(blocklist, "old@b.com", []) is not None  # fail closed
    assert match_blocklist(blocklist, "all@c.com", ["99.1"]) is not None
    assert match_blocklist(blocklist, "nobody@d.com", ["1"]) is None
    json.loads(json.dumps(blocklist))  # raw map stays cacheable
    assert compare_versions("1.10", "1.9") == 1 and compare_versions("1.0", "1.0.0") == 0

    # Adapters: Edge 404 is not_found; 429 / 503+Retry-After flag the breaker;
    # blocklist follows the Next-Page header.
    class _Fake:
        def __init__(self, *responses):
            self.responses = list(responses)

        def get(self, url, **_):
            return self.responses.pop(0)

    edge_404 = fetch_edge_metadata("x" * 32, client=_Fake((404, {}, b'{"name":"x"}', None)))
    assert edge_404["status"] == "not_found", edge_404
    edge_ok = fetch_edge_metadata("x" * 32, client=_Fake((200, {}, b'{"name":"x"}', None)))
    assert edge_ok["status"] == "public" and not edge_ok.get("error"), edge_ok
    edge_500 = fetch_edge_metadata("x" * 32, client=_Fake((500, {}, b'{"name":"x"}', None)))
    assert edge_500["status"] == "unknown" and edge_500.get("error"), edge_500
    amo_429 = fetch_amo_metadata("a@b", client=_Fake((429, {}, b"", None)))
    assert amo_429.get("rate_limited") and amo_429.get("error"), amo_429
    chrome_503 = fetch_chrome_metadata("a" * 32, client=_Fake((503, {"retry-after": "60"}, b"", None)))
    assert chrome_503.get("rate_limited"), chrome_503
    paged = fetch_mozilla_blocklist(client=_Fake(
        (200, {"Next-Page": "https://firefox.settings.services.mozilla.com/p2"},
         b'{"data":[{"guid":"a@b"}]}', None),
        (200, {}, b'{"data":[{"guid":"c@d"}]}', None),
    ))
    assert set(paged) == {"a@b", "c@d"}, paged

    json_blob, count, max_cvss = summarize_vulnerabilities([
        {"cve": "CVE-2024-0001", "cvss_score": 8.8},
        {"cve": "CVE-2024-0002", "cvss_score": 5.1},
    ])
    assert count == 2 and max_cvss == 8.8 and "CVE-2024-0001" in json_blob
    assert publisher_is_reputable("1Password Devs"), "AMO author suffix"
    assert publisher_is_reputable("AgileBits Inc") and publisher_is_reputable("Duck Duck Go, Inc.")
    assert publisher_is_reputable("Google Ireland, Ltd.") and not publisher_is_reputable("eyeo GmbH")
    page = (b'<a class="x" href="./publisher/agilebits-inc/u1" data-publisher-id='
            b'"udb847e9815e2e1626d9ddb346d722811" jslog="1">AgileBits &amp; Co</a>')
    assert _chrome_publisher(page) == ("udb847e9815e2e1626d9ddb346d722811", "AgileBits & Co")
    two = page + page.replace(b"udb847e9815e2e1626d9ddb346d722811", b"u" + b"0" * 32)
    assert _chrome_publisher(two) is None, "two distinct publisher IDs -> trust nothing"
    # Chrome trust is by ID: a lookalike name with another ID is not reputable.
    assert chrome_publisher_is_reputable("udb847e9815e2e1626d9ddb346d722811")
    assert not chrome_publisher_is_reputable("u" + "0" * 32) and not chrome_publisher_is_reputable(None)
    chrome_meta = {"store": "chrome", "status": "public", "publisher": "AgileBits Inc",
                   "publisher_id": "u" + "1" * 32}
    spoof = analyze_extension({"store": "chrome", "extension_id": "a" * 32, "name": "x",
                               "host_count": 1, "store_meta": chrome_meta})
    assert spoof["publisher_reputable"] is False, "Chrome name match without ID must not be trusted"
    # Host-reported IDs never reach a store URL unless they are real Chrome IDs.
    class _NoNet:
        def get(self, *a, **k):
            raise AssertionError("network call for invalid id")
    assert fetch_chrome_metadata("../publisher/x", client=_NoNet())["error"] == "invalid chrome extension id"
    # Edits to the file are picked up without a restart (mtime change).
    fixture["publishers"].append({"name": "Late Addition", "match_names": ["Late Addition"], "added_at": "2026-10-27T00:00:00Z"})
    with open(tmp.name, "w") as fh:
        json.dump(fixture, fh)
    os.utime(tmp.name, (os.path.getmtime(tmp.name) + 5,) * 2)
    assert publisher_is_reputable("Late Addition Inc")
    assert _chrome_publisher(b"<html>no publisher link</html>") is None
    assert not publisher_is_reputable("Totally Not 1Password Devs")
    os.unlink(tmp.name)

    # Chrome listing: labels anchor fields; the Related carousel is ignored.
    page = (
        '<a aria-label="Follows recommended practices for Chrome extensions. Learn more.">x</a>'
        '<span>Featured</span><span aria-label="Average rating 3.9 out of 5 stars."></span>'
        '<a href="./detail/x/reviews"><p class="q">1.2K ratings</p></a>'
        '<a class="g" href="./category/extensions/productivity/workflow" x="1">'
        'Workflow &amp; Planning</a>100,000 users</div>'
        '<div class="QDHp8e">Updated</div><div>September 22, 2026</div>'
        '<a href="https://noscript.net" rel="ugc"><svg w="1"><path d="M1 2z"/></svg> Website</a>'
        '<summary class="m"><svg w="1"><path d="M1 2z"/></svg> Email <svg w="1"><path d="M1z"/></svg>'
        '</summary><div class="N">info@hackademix.net</div></details>'
        '<div class="QDHp8e">Non-trader</div><div>This developer has not identified itself</div>'
        '<path d="M1z"/></svg><span>The developer has disclosed that it will not collect or use your data. More</span>'
        '<a aria-label="Created by the owner of the listed website. The publisher has a good record'
        ' with no history of violations. Learn more.">x</a>'
        '<h2>Related</h2><span aria-label="Average rating 1.0 out of 5 stars."></span>9 users'
    ).encode()
    listing = _chrome_listing(page)
    assert listing == {
        "users": 100_000, "rating": 3.9, "rating_count": 1200, "featured": True,
        "established_publisher": True, "updated_at": "2026-09-22T00:00:00+00:00",
        "category": "Workflow & Planning", "developer_website": "https://noscript.net",
        "developer_email": "info@hackademix.net", "trader": False,
        "privacy_disclosure": "The developer has disclosed that it will not collect or use your data",
    }, listing
    class _NoUpdate:
        def __init__(self):
            self.urls = []

        def get(self, url, **_):
            self.urls.append(url)
            if "update2" in url:
                return 200, {}, (b'<gupdate xmlns="http://www.google.com/update2/response"><app>'
                                 b'<updatecheck status="noupdate"/></app></gupdate>'), None
            return 404, {}, b"", None
    def _zip(files):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for n, data in files.items():
                z.writestr(n, data)
        return buf.getvalue()
    # Large archives parse (only the manifest is read); a huge manifest does not.
    big = _zip({"manifest.json": '{"manifest_version": 3}', "blob.bin": b"\0" * (40 << 20)})
    assert _parse_crx(big) == {"manifest_version": 3}
    try:
        _parse_crx(_zip({"manifest.json": b" " * (_MAX_MANIFEST_BYTES + 10) + b"{}"}))
        raise AssertionError("oversized manifest accepted")
    except ValueError as exc:
        assert "exceeds 1 MB" in str(exc)

    class _HugeCrx(_NoUpdate):
        def get(self, url, **_):
            if "update2" in url:
                return 200, {}, (b'<gupdate><app><updatecheck status="ok" version="1" '
                                 b'codebase="https://clients2.googleusercontent.com/x.crx"/></app></gupdate>'), None
            if url.endswith(".crx"):
                return 200, {}, b"Cr24\x03\x00\x00\x00", "response too large"
            return 404, {}, b"", None
    huge = fetch_chrome_metadata("c" * 32, client=_HugeCrx())
    assert "manifest_error" not in huge and "50 MB" in huge["manifest_unavailable"], huge

    nu = _NoUpdate()
    served_none = fetch_chrome_metadata("c" * 32, client=nu)
    assert "prodversion=999.0" in nu.urls[0], nu.urls
    assert served_none["status"] == "public" and "manifest_error" not in served_none, served_none
    nu_result = analyze_extension({"store": "chrome", "extension_id": "c" * 32, "name": "x",
                                   "host_count": 1, "store_meta": served_none})
    assert not any(s["code"] == "manifest-unparseable" for s in nu_result["risk_signals"]), nu_result
    # Uninspected must not fail open: it carries its own non-zero signal.
    assert any(s["code"] == "manifest-uninspected" for s in nu_result["risk_signals"]), nu_result
    assert nu_result["threat_score"] >= 15 and huge.get("crx_hash_verified") is None

    assert _chrome_listing(b"<h2>Related</h2>5 users<div>Featured</div>") == {}
    assert _chrome_listing(b'<a aria-label="The publisher has a good record with no history'
                           b' of violations. Learn more.">') == {"established_publisher": True}
    # A developer-written description is HTML-escaped: quoting every badge
    # phrase and label in it must yield nothing.
    spoof = html.escape(
        'Featured\n10,000,000 users\n5,000 ratings\nUpdated September 1, 2026\nTrader\n'
        'Email x@y.com\nThe developer has disclosed that it will not collect\n'
        'aria-label="Created by the owner of the listed website. The publisher has a good record'
        ' with no history of violations." aria-label="Follows recommended practices for Chrome'
        ' extensions." </svg><span>The developer has disclosed that it is safe'
    )
    assert _chrome_listing(f'<div class="desc">{spoof}</div>'.encode()) == {}
    listed_chrome = analyze_extension({"store": "chrome", "extension_id": "c" * 32, "name": "x",
                                       "host_count": 1, "store_meta": {"status": "public", **listing}})
    codes = {s["code"] for s in listed_chrome["risk_signals"]}
    assert {"store-featured", "established-publisher", "install-popularity"} <= codes, codes
    assert listed_chrome["developer_email"] == "info@hackademix.net" and listed_chrome["featured"] is True
    panned = analyze_extension({"store": "chrome", "extension_id": "c" * 32, "name": "x", "host_count": 1,
                                "store_meta": {"status": "public", "rating": 1.8, "rating_count": 400}})
    assert any(s["code"] == "poor-public-reputation" for s in panned["risk_signals"]), panned
    assert panned["threat_score"] >= 15
    print("extension_intel self-check: OK")


if __name__ == "__main__":
    _self_check()
