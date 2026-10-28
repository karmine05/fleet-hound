"""Browser-extension identity, store metadata, and risk scoring.

Pure stdlib. No Flask, no Neo4j, no paid/account sources.

Sources used (all verified anonymous):
  * Chrome Web Store listing RPC     (chromewebstore.google.com batchexecute "xY2Ddd";
                                     undocumented internal RPC, Google has no public
                                     read API: the Chrome Web Store API is publisher-only)
  * Chrome update2 + CRX manifest   (clients2.google.com / storage.googleapis.com),
                                     only for items the listing RPC does not serve
  * Edge product-details JSON       (microsoftedge.microsoft.com)
  * Firefox AMO add-on API          (addons.mozilla.org)
  * Opera add-ons listing page + CRX (addons.opera.com; no public API, the
                                     listing HTML is parsed)
  * Apple iTunes lookup API         (itunes.apple.com; Safari extensions, by
                                     the containing app's bundle ID)
  * Mozilla add-on blocklist        (firefox.settings.services.mozilla.com)

The module is deliberately defensive: a dead network or a changed store response
must degrade to a local, explainable score instead of failing ingestion.
"""

from __future__ import annotations

import csv
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


# osquery reports only Safari extensions bundled in a top-level /Applications app.
_SAFARI_APPEX_RE = re.compile(r"(/Applications/[^/]+\.app)/Contents/PlugIns/[^/]+\.appex/?")


def safari_containing_app(path) -> str | None:
    """`/Applications/X.app` for a Safari `.appex` path, else None."""
    m = _SAFARI_APPEX_RE.fullmatch(_clean_str(path))
    return m.group(1) if m else None


def with_safari_app(ext: dict, apps: dict) -> dict:
    """Bind a Safari extension to its containing app.

    `apps`: {app path: (bundle ID, team ID or None)} from the same host's
    Fleet `apps` rows. Safari extensions carry no ID, so when the app is known
    the identity becomes `<app bundle ID>/<appex name>`: extensions of
    different apps never share a node (and its App Store lookup).
    """
    path = ext.get("installed_path") or ""
    bundle, team = apps.get(safari_containing_app(path)) or (None, None)
    if ext.get("store") != "safari" or not bundle:
        return ext
    ext_id = f"{bundle}/{path.rstrip('/').rsplit('/', 1)[-1]}"
    return {**ext, "extension_id": ext_id, "extension_key": f"ext:safari:{ext_id}".lower(),
            "app_bundle_id": bundle, "app_team_id": team or None}


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


# Built-in (component) extension install roots per store, matched against the
# lowercased path with "/" -> "\\". Windows: Program Files or the per-user
# AppData\\Local install; macOS: the app bundle under /Applications.
_WIN_ROOT = r"[a-z]:\\(?:program files(?: \(x86\))?|users\\[^\\]+\\appdata\\local)\\"
_BUILTIN_PATH_RES = {
    "chrome": re.compile(_WIN_ROOT + r"google\\chrome\\application\\"),
    "edge": re.compile(_WIN_ROOT + r"microsoft\\edge\\application\\"),
    "brave": re.compile(_WIN_ROOT + r"bravesoftware\\brave-browser\\application\\"),
    "vivaldi": re.compile(_WIN_ROOT + r"vivaldi\\application\\"),
    "firefox": re.compile(r"(?:" + _WIN_ROOT + r"mozilla firefox\\"
                          r"|\\applications\\firefox\.app\\contents\\resources\\"
                          r"|\\usr\\lib(?:64)?\\firefox(?:-esr)?\\)browser\\features\\"),
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
        # Anchored at the browser's install root: a host-reported path is
        # attacker-influenced, so "...\\application\\" elsewhere is not built-in.
        rx = _BUILTIN_PATH_RES.get(store)
        if rx and rx.match(p):
            return True
        # Every App Store Safari extension lives in its app's Contents/PlugIns,
        # so only extensions bundled with Safari itself or the OS are built-in.
        if store == "safari" and p.startswith(("\\applications\\safari.app\\", "\\system\\")):
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
                         store: str = "", vouched: bool = False) -> tuple[list[dict], int]:
    """Heuristic malformed/typosquat detection.

    Deliberately conservative: a hit is a review signal, not a verdict.
    `vouched`: the store vouches for the publisher of a verified store
    install, so a brand look-alike name ("Motion", "Rocket") is a real
    product, not an impersonation; the brand checks are skipped.
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
    hit = None
    if len(compact) >= 5 and exact not in _BRANDS:
        for brand in _NORMALISED_BRANDS:
            if _edit_distance_at_most_one(compact, brand):
                hit = ("typosquat-brand", 18, f"name is one edit away from the '{brand}' brand")
                break
            if compact.startswith(brand) and len(compact) - len(brand) <= 2:
                suffix = compact[len(brand):]
                if suffix in {"x", "pro", "plus", "app", "ex", "official"}:
                    hit = ("brand-affix", 8, f"name appends '{suffix}' to the '{brand}' brand")
                    break
    if hit and vouched:
        signals.append({"code": "brand-lookalike-vouched", "weight": 0,
                        "detail": hit[2] + ", but the store vouches for this publisher; "
                                  "not penalised"})
    elif hit:
        add(*hit)

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
    if store == "safari":  # App Store or not, the extension lives in its app bundle
        return _SAFARI_APPEX_RE
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
    # Safari extensions carry no ID of their own (see safari_containing_app).
    if (not extension_id and store != "safari") or not installs:
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

    Safari only (App Store seller name); Chrome-family, Firefox and Edge trust is by store ID
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

# Chrome Web Store data-collection disclosure codes (see _CWS_PRIVACY_LABELS)
# that matter for exfiltration risk. Capped in total: a disclosure is honest
# self-reporting, a review signal rather than a verdict.
_PRIVACY_WEIGHTS = {4: 4, 3: 3, 5: 3, 1: 2, 7: 2}
_PRIVACY_CAP = 8

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
                optional: set[str] = frozenset(),
                privacy_codes=()) -> tuple[int, list[dict]]:
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
    declared = sorted({c for c in privacy_codes or () if type(c) is int and c in _PRIVACY_WEIGHTS})
    if declared:
        weight = min(_PRIVACY_CAP, sum(_PRIVACY_WEIGHTS[c] for c in declared))
        score += weight
        signals.append({
            "code": "declared-data-collection",
            "weight": weight,
            "detail": "developer declares it collects: "
                      + ", ".join(_CWS_PRIVACY_LABELS[c] for c in declared),
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
        signals.append({"code": "store-listed", "weight": -25,
                        "detail": "listed in a public extension store"})
    elif status == "unlisted":
        score += 5
        signals.append({"code": "store-unlisted", "weight": -5,
                        "detail": "unlisted or self-distributed, but the store still serves it"})
    elif status == "unknown":
        score += 8
        signals.append({"code": "store-status-unknown", "weight": -8,
                        "detail": "store metadata unavailable"})
    # not_found/removed deliberately score 0.

    if reputable:
        score += 20
        signals.append({"code": "reputable-publisher", "weight": -20,
                        "detail": "publisher matches a known vendor"})
    if meta.get("developer_verified") is True:
        score += 10
        signals.append({"code": "verified-developer", "weight": -10,
                        "detail": "store marks the developer as verified"})
    elif meta.get("established_publisher") is True:
        score += 10
        signals.append({"code": "established-publisher", "weight": -10,
                        "detail": "store: verified website owner with no history of violations"})
    if meta.get("featured") is True:
        score += 5
        signals.append({"code": "store-featured", "weight": -5,
                        "detail": "featured / recommended by the store"})

    mv = _as_int(meta.get("manifest_version"))
    if mv == 3:
        score += 8
        signals.append({"code": "manifest-v3", "weight": -8,
                        "detail": "uses Manifest V3"})

    updated = _parse_iso(meta.get("updated_at"))
    if updated:
        age_days = (datetime.now(timezone.utc) - updated).days
        points = 10 if age_days <= 365 else 4 if age_days <= 730 else 0
        score += points
        signals.append({"code": "store-updated", "weight": -points,
                        "detail": f"last store update {max(age_days, 0)} days ago"})

    users = _as_int(meta.get("users"))
    if users and users > 0:
        points = min(12, int(4 * math.log10(users + 1)))
        score += points
        signals.append({"code": "install-popularity", "weight": -points,
                        "detail": f"{users:,} store installs"})

    rating = _as_float(meta.get("rating"))
    rating_count = _as_int(meta.get("rating_count"))
    if rating is not None and rating >= 4.0 and (rating_count or 0) >= 100:
        score += 5
        signals.append({"code": "store-rating", "weight": -5,
                        "detail": f"rated {rating:.1f} from {rating_count:,} ratings"})

    if meta.get("crx_hash_verified") is True:
        score += 5
        signals.append({"code": "crx-hash-verified", "weight": -5,
                        "detail": "package SHA-256 matches the store's published hash"})

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
    elif status == "off_store":
        signals.append({"code": "not-in-app-store", "weight": 0,
                        "detail": "containing app is not in the Mac App Store "
                                  "(direct download or sideloaded)"})

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


# Bump on any change to analyze_extension() output: the worker fingerprints
# its inputs with this, and a new value re-scores every extension once.
SCORER_VERSION = 10


def analyze_extension(record: dict, *, blocklist_entry: dict | None = None,
                      feed_hits: list[dict] | None = None,
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

    # Recomputed, not read from the node: ingestion sets is_builtin only when a
    # host is re-ingested, so a stored flag lags behind built-in rule changes.
    builtin = is_browser_builtin({
        "store": store,
        "extension_id": extension_id,
        "installed_paths": installed_paths,
    })

    # A blocklist or threat-feed hit always gets scored, even for a built-in
    # ID or path (an ID suffix or vendor-looking path is host-reported).
    # shortcut: built-in path rules are substring matches, not anchored install
    # roots; anchor them if host-reported paths become an attack surface.
    if builtin and not blocklist_entry and not feed_hits:
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
            "store_name": None,
            "store_url": None,
            "publisher": None,
            "category": None,
            "rating": None,
            "rating_count": None,
            "updated_at": None,
            "intel_error": None,
        }

    perms, hosts, matches, optional = _permission_sets(meta, record)
    capability, cap_signals = _capability(perms, hosts, matches, optional,
                                          meta.get("privacy_codes") or ())
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
    elif meta.get("store") == "safari":
        # The bundle ID is host-reported; an unsigned app can claim any. Seller
        # trust needs the containing app signed with an Apple team ID.
        reputable = publisher_is_reputable(meta.get("developer")) and bool(record.get("app_team_id"))
    else:
        # Opera exposes only a developer username; names are display-only.
        reputable = False
    sideload_signal = None
    if reputable and meta.get("store") in ("chrome", "firefox", "edge", "safari"):
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
    for hit in feed_hits or []:
        threat = max(threat, int(hit.get("threat") or 0))
        detail = f"{hit.get('feed')}: {hit.get('reason')}"
        if hit.get("date"):
            detail += f" (listed {hit['date']})"
        if hit.get("source"):
            detail += f" — {hit['source']}"
        threat_signals.append({"code": f"threat-feed:{hit.get('feed')}",
                               "weight": int(hit.get("threat") or 0), "detail": detail[:400]})
    threat = min(100, threat)
    signals.extend(threat_signals)

    host_count = _as_int(record.get("host_count")) or 0
    versions = record.get("versions") or []
    exposure = _exposure_score(host_count, len(versions) if isinstance(versions, list) else 0)

    # Vouched: a known publisher ID (reputable already requires a verified
    # store install), or a store badge on a listing with >= 100k users. A badge
    # alone proves a clean record, not brand identity, so a small badged
    # publisher naming itself "Bitwardn" keeps the typosquat penalty.
    vouched = reputable or (
        (meta.get("developer_verified") is True or meta.get("established_publisher") is True)
        and (_as_int(meta.get("users")) or 0) >= 100_000
        and store_install_verified(store, extension_id, record.get("installs")))
    name_signals, name_penalty = name_anomaly_signals(
        name, display_name, store=store, vouched=vouched
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
    known_bad = bool(blocklist_entry) or any(
        h.get("severity") == "malicious" for h in feed_hits or [])
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
    elif feed_hits:
        # Listed by an open threat feed: adware/hijacking is "high" outright;
        # an unexplained takedown ranks with a store removal.
        risk = max(risk, 70 if any(h.get("severity") == "unwanted" for h in feed_hits) else 60)
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
        # Stays True for a threat-listed built-in, so the flag matches ingestion.
        "is_builtin": builtin,
        "publisher_reputable": reputable,
        "known_bad": known_bad,
        "install_users": users,
        "manifest_version": _as_int(meta.get("manifest_version")),
        "permissions": sorted(perms),
        "host_permissions": sorted(hosts),
        "content_script_matches": sorted(matches),
        "latest_version": _clean_str(meta.get("version")) or None,
        "store_name": None if _clean_str(meta.get("name")).startswith("__MSG_")
        else _clean_str(meta.get("name")) or None,
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
    "chromewebstore.google.com",    # listing RPC (batchexecute)
})
_EDGE_HOSTS = frozenset({"microsoftedge.microsoft.com"})
_AMO_HOSTS = frozenset({"addons.mozilla.org"})
_MOZILLA_HOSTS = frozenset({"firefox.settings.services.mozilla.com"})
_OPERA_HOSTS = frozenset({"addons.opera.com"})
_APPLE_HOSTS = frozenset({"itunes.apple.com"})


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

    def get(self, url: str, *, allowed_hosts, max_bytes: int = _MAX_HTTP_BYTES,
            headers: dict | None = None):
        """`headers`: extra request headers, e.g. If-None-Match for a conditional GET."""
        return self._request(url, None, allowed_hosts, max_bytes, headers)

    def post(self, url: str, form: dict, *, allowed_hosts, max_bytes: int = _MAX_HTTP_BYTES):
        """POST `form` url-encoded; same allowlist, redirect guard, cap and return shape as get()."""
        return self._request(url, urllib.parse.urlencode(form).encode(), allowed_hosts, max_bytes)

    def _request(self, url: str, data: bytes | None, allowed_hosts, max_bytes: int,
                 extra_headers: dict | None = None):
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        if host not in allowed_hosts:
            return 0, {}, b"", f"host not allowlisted: {host}"
        opener = urllib.request.build_opener(_SafeRedirectHandler(allowed_hosts))
        headers = {**(extra_headers or {}), "User-Agent": _USER_AGENT, "Accept": "*/*"}
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded;charset=UTF-8"
        req = urllib.request.Request(url, data=data, headers=headers)
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


_CHROME_EXTENSION_ID_RE = re.compile(r"[a-p]{32}")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}$")

# Chrome Web Store listing facts come from the store front end's own
# batchexecute RPC. It is undocumented and internal: Google offers no public
# read API (the Chrome Web Store API is publisher-only). Payload indices were
# mapped against rendered detail pages on 2026-10-27; a payload whose shape or
# ID does not match is rejected whole rather than half-read.
_CWS_RPC_ID = "xY2Ddd"
_CWS_RPC_URL = ("https://chromewebstore.google.com/_/ChromeWebStoreConsumerFeUi/data/"
                f"batchexecute?rpcids={_CWS_RPC_ID}&hl=en&rt=c")
# About 50 KB of response per listing: 40 keeps one POST far below the 8 MB cap.
_CWS_RPC_BATCH = 40
# shortcut: the payload carries only the category slug; these labels were
# verified on live pages. Other slugs are shown raw; add pairs once confirmed.
_CWS_CATEGORY_LABELS = {
    "make_chrome_yours/accessibility": "Accessibility",
    "make_chrome_yours/privacy": "Privacy & Security",
    "productivity/communication": "Communication",
    "productivity/developer": "Developer Tools",
    "productivity/education": "Education",
    "productivity/tools": "Tools",
    "productivity/workflow": "Workflow & Planning",
}
_CWS_PRIVACY_LABELS = {
    1: "personally identifiable information", 3: "financial and payment information",
    4: "authentication information", 5: "personal communications", 6: "location",
    7: "web history", 8: "user activity", 9: "website content",
}


def _at(value, *path):
    for index in path:
        if not isinstance(value, list) or index >= len(value):
            return None
        value = value[index]
    return value


def _http_url(value) -> str | None:
    value = _clean_str(value)
    parsed = urllib.parse.urlparse(value)
    return value if parsed.scheme in ("http", "https") and parsed.hostname else None


def _parse_cws_rpc(body: bytes) -> dict:
    """{tag: (payload JSON string or None, error code or None)} from a
    batchexecute response.

    Chunks are length-prefixed lines; only lines that parse as a JSON list
    hold envelopes. Envelopes arrive in any order, so map them by tag. A null
    payload carries a gRPC-style code in env[5]: 5 for an ID the store never
    had, 7 for a removed item, others for bad input or transient failures.
    """
    text = body.decode("utf-8", "replace")
    if not text.startswith(")]}'"):
        raise ValueError("listing RPC response lacks the )]}' prefix")
    out = {}
    for line in text[4:].splitlines():
        try:
            chunk = json.loads(line)
        except (ValueError, RecursionError):
            continue
        for env in chunk if isinstance(chunk, list) else ():
            if (isinstance(env, list) and len(env) > 6 and env[0] == "wrb.fr"
                    and env[1] == _CWS_RPC_ID and isinstance(env[6], str)):
                code = _at(env, 5, 0)
                out[env[6]] = (env[2], code if type(code) is int else None)
    return out


def _cws_listing(extension_id: str, payload: str) -> dict:
    """Listing and manifest fields from one RPC payload. Raises ValueError on schema drift."""
    data = json.loads(payload)
    item, dev = _at(data, 0), _at(data, 10)
    if _at(item, 0) != extension_id or not isinstance(dev, list):
        raise ValueError("payload id or shape does not match the request")
    manifest = _at(item, 18)
    manifest = json.loads(manifest) if isinstance(manifest, str) else None
    if not isinstance(manifest, dict):
        raise ValueError("payload has no manifest object")

    out: dict = {"status": "public"}
    for key, value in _manifest_fields({"manifest": manifest}).items():
        if value not in (None, [], ""):
            out[key] = value
    # Store display name; the manifest name is often an unresolved __MSG_ key.
    if _clean_str(_at(item, 2)):
        out["name"] = _clean_str(item[2])
    if isinstance(_at(data, 13), str) and data[13]:
        out["version"] = data[13]
    users, rating, rating_count = _at(item, 14), _at(item, 3), _at(item, 4)
    if type(users) is int and users >= 0:
        out["users"] = users
    if type(rating) in (int, float) and 0 <= rating <= 5:
        out["rating"] = round(float(rating), 1)
    if type(rating_count) is int and rating_count >= 0:
        out["rating_count"] = rating_count
    slug = _at(item, 11, 0)
    if isinstance(slug, str) and slug:
        out["category"] = _CWS_CATEGORY_LABELS.get(slug, slug)
    out["featured"] = _at(item, 9) is True
    # [0][8] and [0][15] tracked the "good record" badge on every listing probed
    # (2026-10-27); Google's own items show "developed by Google" instead.
    if _at(item, 8) is True and _at(item, 15) is True:
        out["established_publisher"] = True
    updated = _at(data, 14, 0)
    if type(updated) in (int, float) and 0 < updated < 32_503_680_000:  # before year 3000
        out["updated_at"] = datetime.fromtimestamp(updated, timezone.utc).isoformat()
    website = _clean_str(_at(item, 7))
    if website and "://" not in website:
        website = "https://" + website  # the store renders bare hosts as https links
    website = _http_url(website)
    if website:
        out["developer_website"] = website
    email = _clean_str(_at(dev, 0))
    if _EMAIL_RE.match(email):
        out["developer_email"] = email
    # Trader is a boolean here but 1 in the page's own blob: test truthiness.
    out["trader"] = bool(_at(dev, 3))
    codes = _at(data, 7)
    if codes is None:
        out["privacy_disclosure"] = "The developer has disclosed that it will not collect or use your data"
    elif isinstance(codes, list) and all(type(c) is int for c in codes):
        out["privacy_codes"] = codes
        out["privacy_disclosure"] = "The developer has disclosed that it collects or uses: " + ", ".join(
            _CWS_PRIVACY_LABELS.get(c, f"data category {c}") for c in codes)
    privacy_url = _http_url(_at(data, 33))
    if privacy_url:
        out["privacy_policy_url"] = privacy_url
    publisher_id = _at(dev, 10)
    if isinstance(publisher_id, str) and _CWS_PUBLISHER_ID_RE.fullmatch(publisher_id):
        out["publisher_id"] = publisher_id
    # [10][5] is the name the store shows; [10][7] is the trader's legal
    # name, null for non-traders.
    publisher = _clean_str(_at(dev, 5)) or _clean_str(_at(dev, 7))
    if publisher:
        out["publisher"] = publisher
    return out


def _chrome_detail_url(extension_id: str) -> str:
    return "https://chromewebstore.google.com/detail/" + urllib.parse.quote(extension_id, safe="")


def fetch_chrome_listings(extension_ids, *, client: HttpClient | None = None) -> dict[str, dict]:
    """{id: listing meta} from the Chrome Web Store listing RPC. Never raises.

    Invalid IDs are dropped before any request. A listed item gets status
    "public" with listing and manifest fields. A removed item (code 7) gets
    "removed". An ID the RPC does not know (code 5) gets status "unlisted"
    plus `listing_missing`, and update2 tells unlisted from never published.
    Any other per-envelope error is an error, never a missing listing.
    """
    client = client or HttpClient()
    ids = list(dict.fromkeys(
        i for i in extension_ids if isinstance(i, str) and _CHROME_EXTENSION_ID_RE.fullmatch(i)
    ))
    out: dict[str, dict] = {}
    limited: dict = {"store": "chrome"}
    for start in range(0, len(ids), _CWS_RPC_BATCH):
        chunk = ids[start:start + _CWS_RPC_BATCH]
        payloads = None
        if limited.get("rate_limited"):
            # Rate limited on an earlier chunk: mark the rest without asking again.
            for eid in chunk:
                out[eid] = {"store": "chrome", "status": "unknown",
                            "url": _chrome_detail_url(eid), **limited}
            continue
        freq = json.dumps([[[_CWS_RPC_ID, json.dumps([eid]), None, str(n)]
                            for n, eid in enumerate(chunk, 1)]], separators=(",", ":"))
        status, headers, body, error = client.post(_CWS_RPC_URL, {"f.req": freq},
                                                   allowed_hosts=_CHROME_HOSTS)
        limited = {"store": "chrome"}
        _mark_rate_limited(limited, status, headers)
        if not limited.get("rate_limited"):
            try:
                if status != 200 or error:
                    raise ValueError(error or f"listing RPC HTTP {status}")
                payloads = _parse_cws_rpc(body)
            except (ValueError, RecursionError) as exc:
                limited["error"] = str(exc)
        for n, eid in enumerate(chunk, 1):
            meta = {"store": "chrome", "status": "unknown", "url": _chrome_detail_url(eid)}
            tag = str(n)
            if payloads is None:
                meta.update(limited)
            elif tag not in payloads:
                meta["error"] = "listing RPC returned no envelope for this id"
            elif payloads[tag][0] is not None:
                try:
                    meta.update(_cws_listing(eid, payloads[tag][0]))
                except Exception as exc:  # noqa: BLE001 — one odd payload must not fail the batch
                    meta["error"] = f"listing RPC schema drift: {exc}"
            elif payloads[tag][1] == 5:
                meta.update(status="unlisted", listing_missing=True)
            elif payloads[tag][1] == 7:
                meta["status"] = "removed"
            elif payloads[tag][1] == 8:
                meta.update(rate_limited=True, error="listing RPC code 8 (resource exhausted)")
            else:
                meta["error"] = f"listing RPC error code {payloads[tag][1]}"
            out[eid] = meta
    return out


def fetch_chrome_metadata(extension_id: str, *, client: HttpClient | None = None,
                          listing: dict | None = None, manifest_for=None) -> dict:
    """`listing`: this ID's fetch_chrome_listings() result when the caller
    already batched it. `manifest_for(version)`: cached manifest fields for an
    immutable version, which skip the CRX download."""
    client = client or HttpClient()
    # Host-reported ID: only a real Chrome ID may reach a store URL or body.
    if not _CHROME_EXTENSION_ID_RE.fullmatch(extension_id or ""):
        return {"store": "chrome", "status": "unknown", "error": "invalid chrome extension id"}
    meta = dict(listing) if listing is not None else \
        fetch_chrome_listings([extension_id], client=client)[extension_id]
    if not meta.pop("listing_missing", False):
        return meta  # listed (manifest came with it), rate limited, or failed
    # The listing RPC serves only listed items. update2 still answers for
    # unlisted ones, which install by direct link and are a real malware
    # vector, so their package is fetched and inspected.
    meta["status"] = "unknown"
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
            "status": "unlisted",
            "version": updatecheck.get("version"),
        })
        cached = manifest_for(meta["version"]) if manifest_for and meta["version"] else None
        if cached:
            meta.update(cached)
            return meta
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


def fetch_amo_metadata(guid: str, *, client: HttpClient | None = None,
                       manifest_for=None) -> dict:
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
    cached = manifest_for(meta["version"]) if manifest_for and meta["version"] else None
    if cached:
        # A version's package never changes: reuse its parsed manifest, skip the XPI.
        for key, value in cached.items():
            if value not in (None, [], "") and not meta.get(key):
                meta[key] = value
        return meta
    _amo_package_manifest(meta, file_info, client)
    return meta


def _amo_package_manifest(meta: dict, file_info: dict, client: HttpClient) -> None:
    """Fill manifest fields the AMO API omits (MV, content scripts) from the signed XPI."""
    url = _clean_str(file_info.get("url"))
    if (urllib.parse.urlparse(url).hostname or "").lower() not in _AMO_HOSTS:
        meta["manifest_unavailable"] = "AMO lists no downloadable package"
        return
    if (_as_int(file_info.get("size")) or 0) > 50 * 1024 * 1024:
        meta["manifest_unavailable"] = "XPI exceeds 50 MB download cap"
        return
    status, _, xpi, error = client.get(url, allowed_hosts=_AMO_HOSTS, max_bytes=50 * 1024 * 1024)
    if status == 200 and error == "response too large":
        meta["manifest_unavailable"] = "XPI exceeds 50 MB download cap"
        return
    if status != 200 or not xpi:
        meta["manifest_unavailable"] = error or f"XPI HTTP {status}"
        return
    expected = _clean_str(file_info.get("hash")).lower()
    if expected.startswith("sha256:"):
        meta["crx_hash_verified"] = hashlib.sha256(xpi).hexdigest() == expected[7:]
        if not meta["crx_hash_verified"]:
            meta["manifest_error"] = "XPI SHA-256 does not match AMO"
            return
    try:
        manifest = _parse_crx(xpi)
    except ValueError as exc:
        meta["manifest_error"] = str(exc)
        return
    for key, value in _manifest_fields({"manifest": manifest}).items():
        # The API's permission lists stay authoritative; the package adds what it lacks.
        if value not in (None, [], "") and not meta.get(key):
            meta[key] = value


_OPERA_SLUG_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,100}")
_MONTHS = {m: i for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}


def _html_text(fragment: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", fragment or ""))).strip()


def _opera_date(text: str) -> str | None:
    """'Sept. 18, 2026' (the page's Django "N j, Y") as ISO, else None."""
    m = re.fullmatch(r"([A-Za-z]+)\.?\s+(\d{1,2}),\s+(\d{4})", text)
    month = _MONTHS.get(m.group(1)[:3].lower()) if m else None
    try:
        return datetime(int(m.group(3)), month, int(m.group(2)), tzinfo=timezone.utc).isoformat() \
            if month else None
    except ValueError:
        return None


def _opera_listing(extension_id: str, page: str) -> dict:
    """Listing fields from an addons.opera.com detail page. Raises ValueError on drift."""
    def meta_prop(name):
        m = re.search(r'<meta property="%s" content="([^"]*)"' % re.escape(name), page)
        return html.unescape(m.group(1)).strip() if m else ""

    if meta_prop("aoc:app_id") != extension_id:
        raise ValueError("listing page id does not match the request")
    slug = meta_prop("aoc:slug")
    if not _OPERA_SLUG_RE.fullmatch(slug):
        raise ValueError("listing page has no valid slug")
    out = {"status": "public", "slug": slug,
           "url": f"https://addons.opera.com/en/extensions/details/{slug}/"}
    name = meta_prop("og:title")
    if name:
        out["name"] = name
    m = re.search(r'class="h-byline".*?developer=[^"]*"[^>]*>(.*?)</a>', page, re.S)
    if m and _html_text(m.group(1)):
        out["developer"] = _html_text(m.group(1))
    m = re.search(r'id="rating-value">\s*([0-9.]+)\s*<', page)
    if m and 0 <= float(m.group(1)) <= 5:
        out["rating"] = round(float(m.group(1)), 1)
    m = re.search(r'id="rating-count"[^>]*>\s*([0-9,]+)\s*<', page)  # related items repeat reviewCount
    if m:
        out["rating_count"] = int(m.group(1).replace(",", ""))
    about = {_html_text(k): _html_text(v)
             for k, v in re.findall(r"<dt>(.*?)</dt>\s*<dd[^>]*>(.*?)</dd>", page, re.S)}
    if re.fullmatch(r"[0-9,]+", about.get("Downloads", "")):
        out["users"] = int(about["Downloads"].replace(",", ""))  # total downloads, not active users
    if about.get("Category"):
        out["category"] = about["Category"]
    if about.get("Version"):
        out["version"] = about["Version"]
    updated = _opera_date(about.get("Last update", ""))
    if updated:
        out["updated_at"] = updated
    website = _http_url(about.get("Support page"))
    if website:
        out["developer_website"] = website
    return out


def fetch_opera_metadata(extension_id: str, *, client: HttpClient | None = None,
                         manifest_for=None) -> dict:
    """addons.opera.com has no API: `details/app_id/<id>/` redirects to the
    listing page (404 for an ID the store does not list), and the CRX comes
    from `download/<slug>/`."""
    client = client or HttpClient()
    if not _CHROME_EXTENSION_ID_RE.fullmatch(extension_id or ""):
        return {"store": "opera", "status": "unknown", "error": "invalid opera extension id"}
    meta = {"store": "opera", "status": "unknown"}
    url = f"https://addons.opera.com/en/extensions/details/app_id/{extension_id}/"
    status, headers, body, error = client.get(url, allowed_hosts=_OPERA_HOSTS, max_bytes=2_000_000)
    if _mark_rate_limited(meta, status, headers):
        return meta
    if status == 404:
        meta["status"] = "not_found"
        meta["error"] = "Opera add-ons returned 404"
        return meta
    if status != 200 or not body:
        meta["error"] = error or f"Opera add-ons HTTP {status}"
        return meta
    try:
        meta.update(_opera_listing(extension_id, body.decode("utf-8", "replace")))
    except ValueError as exc:
        meta["error"] = f"Opera listing parse failed: {exc}"
        return meta
    cached = manifest_for(meta["version"]) if manifest_for and meta.get("version") else None
    if cached:
        meta.update(cached)
        return meta
    cstatus, cheaders, crx, cerr = client.get(
        f"https://addons.opera.com/extensions/download/{meta['slug']}/",
        allowed_hosts=_OPERA_HOSTS, max_bytes=50 * 1024 * 1024)
    if _mark_rate_limited(meta, cstatus, cheaders):
        return meta
    if cstatus == 0 or cstatus >= 500:
        # Transient (Opera resets bursts): an uncached "unknown" retries next
        # cycle instead of caching a manifest_error for weeks.
        return {"store": "opera", "status": "unknown", "error": f"Opera CRX: {cerr or cstatus}"}
    if cstatus == 200 and cerr == "response too large":
        meta["manifest_unavailable"] = "CRX exceeds 50 MB download cap"
        return meta
    if cstatus != 200 or not crx:
        meta["manifest_error"] = cerr or f"CRX HTTP {cstatus}"
        return meta
    try:
        manifest = _parse_crx(crx)
    except ValueError as exc:
        meta["manifest_error"] = str(exc)
        return meta
    for key, value in _manifest_fields({"manifest": manifest}).items():
        # The listing's store name and version stay authoritative.
        if value not in (None, [], "") and not meta.get(key):
            meta[key] = value
    return meta


_BUNDLE_ID_RE = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")


def fetch_safari_metadata(bundle_id: str, *, client: HttpClient | None = None) -> dict:
    """Mac App Store listing of the app that bundles a Safari extension.

    `bundle_id` is the containing app's CFBundleIdentifier (Fleet `apps` row
    at the extension's app path). The App Store serves no package, so the
    manifest is never inspected. Residual: the bundle ID is host-reported, so
    a non-App-Store app that claims a listed app's bundle ID inherits that
    listing.
    """
    client = client or HttpClient()
    bundle_id = _clean_str(bundle_id)
    if len(bundle_id) > 255 or not _BUNDLE_ID_RE.fullmatch(bundle_id):
        return {"store": "safari", "status": "unknown", "error": "invalid app bundle id"}
    meta = {"store": "safari", "status": "unknown"}
    url = ("https://itunes.apple.com/lookup?entity=macSoftware&bundleId="
           + urllib.parse.quote(bundle_id, safe=""))
    status, headers, body, error = client.get(url, allowed_hosts=_APPLE_HOSTS, max_bytes=1_000_000)
    if _mark_rate_limited(meta, status, headers):
        return meta
    data = _json_loads(body) if body else None
    if status != 200 or not isinstance(data, dict) or not isinstance(data.get("results"), list):
        meta["error"] = error or f"iTunes lookup HTTP {status}"
        return meta
    app = next((r for r in data["results"] if isinstance(r, dict)
                and _clean_str(r.get("bundleId")).lower() == bundle_id.lower()), None)
    if app is None:
        # Developer ID (notarized) distribution outside the App Store is a normal
        # Safari channel, unlike an off-store Chrome item: not "not_found".
        meta["status"] = "off_store"
        return meta
    rating_count = _as_int(app.get("userRatingCount")) or 0
    rating = _as_float(app.get("averageUserRating"))
    meta.update({
        "status": "public",
        "name": _clean_str(app.get("trackName")) or None,
        "version": _clean_str(app.get("version")) or None,
        "developer": _clean_str(app.get("sellerName")) or _clean_str(app.get("artistName")) or None,
        # The lookup reports 0 for "no ratings"; only a counted rating means anything.
        "rating": rating if rating_count > 0 and rating is not None and 0 <= rating <= 5 else None,
        "rating_count": rating_count or None,
        "category": _clean_str(app.get("primaryGenreName")) or None,
        "updated_at": _clean_str(app.get("currentVersionReleaseDate")) or None,
        "created_at": _clean_str(app.get("releaseDate")) or None,
        "url": _http_url(app.get("trackViewUrl")),
        "developer_website": _http_url(app.get("sellerUrl")),
        "manifest_unavailable": "the App Store serves no inspectable extension package",
    })
    return meta


def fetch_store_metadata(store: str, extension_id: str, *,
                         client: HttpClient | None = None, manifest_for=None) -> dict:
    """Dispatch to the anonymous adapter for `store`. Never raises.

    `manifest_for(version)` returns cached manifest fields for that version or
    None; a hit skips the package download (CRX or XPI)."""
    store = _clean_str(store).lower()
    extension_id = _clean_str(extension_id)
    if not extension_id:
        return {"store": store, "status": "unknown", "error": "missing extension id"}
    try:
        if store in ("chrome", "brave", "vivaldi", "chromium"):
            return fetch_chrome_metadata(extension_id, client=client, manifest_for=manifest_for)
        if store == "opera":
            meta = fetch_opera_metadata(extension_id, client=client, manifest_for=manifest_for)
            # Opera also installs from the Chrome Web Store ("Install Chrome
            # Extensions"), so any Opera miss or failure asks the CWS; a CWS
            # miss or failure keeps Opera's own answer.
            if meta.get("status") != "public" and not meta.get("rate_limited"):
                chrome = fetch_chrome_metadata(extension_id, client=client,
                                               manifest_for=manifest_for)
                if chrome.get("status") not in ("not_found", "unknown"):
                    chrome["resolved_from"] = "opera"
                    return chrome
            return meta
        if store == "safari":
            # `extension_id` here is the containing app's bundle ID (the worker's lookup ID).
            return fetch_safari_metadata(extension_id, client=client)
        if store == "edge":
            meta = fetch_edge_metadata(extension_id, client=client)
            # Edge installs from the Chrome Web Store too; an ID Edge's store
            # does not know is usually a CWS item, not an unknown sideload.
            if meta.get("status") == "not_found" and _CHROME_EXTENSION_ID_RE.fullmatch(extension_id):
                chrome = fetch_chrome_metadata(extension_id, client=client,
                                               manifest_for=manifest_for)
                # Only update2's own "unknown application" confirms Edge's miss;
                # an unlisted, removed or failed Chrome answer must not cache as not_found.
                if chrome.get("status") != "not_found":
                    chrome["resolved_from"] = "edge"
                    return chrome
            return meta
        if store == "firefox":
            return fetch_amo_metadata(extension_id, client=client, manifest_for=manifest_for)
        return {"store": store, "status": "unknown",
                "error": f"no anonymous metadata adapter for store '{store}'"}
    except Exception as exc:
        logger.warning("extension metadata fetch failed store=%s id=%s: %s",
                       store, extension_id, exc)
        return {"store": store, "status": "unknown", "error": str(exc)}


# Returned by a conditional fetch when the server answers 304: the caller's
# cached copy is still current.
NOT_MODIFIED = object()


def _conditional_headers(validators: dict | None) -> dict | None:
    etag = _clean_str((validators or {}).get("etag"))
    return {"If-None-Match": etag} if etag else None


def fetch_mozilla_blocklist(*, client: HttpClient | None = None,
                            validators: dict | None = None):
    """Return {guid: record} from the Mozilla add-on blocklist. Never raises.

    Returns {} unless every page was read: a partial list must never be
    cached as the whole blocklist. `validators` ({"etag": ...}) makes the
    first request conditional; a 304 returns NOT_MODIFIED, and a full read
    stores the new ETag back into `validators`.
    """
    client = client or HttpClient()
    url = (
        "https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/"
        "collections/addons/records"
    )
    records: dict[str, dict] = {}
    seen_urls = set()
    etag = None
    for page in range(20):
        if not url or url in seen_urls:
            break
        seen_urls.add(url)
        status, headers, body, error = client.get(
            url, allowed_hosts=_MOZILLA_HOSTS, max_bytes=8 * 1024 * 1024,
            headers=_conditional_headers(validators) if page == 0 else None,
        )
        if page == 0 and status == 304:
            return NOT_MODIFIED
        if status != 200 or not body or error:
            logger.warning("mozilla blocklist page %d failed: %s; discarding partial list",
                           page + 1, error or status)
            return {}
        payload = _json_loads(body)
        if not isinstance(payload, dict):
            logger.warning("mozilla blocklist page %d is not JSON; discarding partial list", page + 1)
            return {}
        if page == 0:
            etag = _header(headers, "ETag") or None
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
    if url and url not in seen_urls:
        logger.warning("mozilla blocklist has more than 20 pages; discarding partial list")
        return {}
    if validators is not None and etag:
        validators["etag"] = etag
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

# ---------------------------------------------------------------------------
# Open threat feeds (config/extension_threat_feeds.json)
# ---------------------------------------------------------------------------

# Feed definitions live in a data file so a new open-source feed is a data
# edit, not a code change. Every extension is matched against every feed.
_THREAT_FEEDS_CANDIDATES = (
    "/app/config/extension_threat_feeds.json",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "config", "extension_threat_feeds.json"),
)
_FEED_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,40}")
_FEED_PLATFORMS = {"chromium": CHROMIUM_STORES, "firefox": frozenset({"firefox"})}
_FEED_MAX_ROWS = 200_000
# Reason keywords -> (severity, threat). Matched as substrings of the
# lowercased reason; first tier that matches wins.
_FEED_SEVERITY = (
    ("malicious", 100, ("malware", "spyware", "phish", "steal", "credential", "backdoor",
                        "trojan", "ransom", "keylog", "exfiltrat", "cryptojack", "miner",
                        "malicious", "rat ")),
    ("unwanted", 70, ("adware", "hijack", "bundl", "suspicious", "fraud", "scam",
                      "affiliate", "injection", "tracking")),
)


def _threat_feeds_path() -> str | None:
    env = os.environ.get("EXTENSION_THREAT_FEEDS_FILE", "").strip()
    if env:
        return env
    return next((p for p in _THREAT_FEEDS_CANDIDATES if os.path.exists(p)), None)


def load_threat_feeds() -> list[dict]:
    """Validated feed definitions. Bad entries are skipped with a warning."""
    path = _threat_feeds_path()
    if not path:
        logger.error("threat feeds: no extension_threat_feeds.json found; no feed matching")
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        logger.error("threat feeds: cannot read %s: %s", path, exc)
        return []
    feeds = []
    for i, raw in enumerate(doc.get("feeds") or [] if isinstance(doc, dict) else []):
        try:
            if not isinstance(raw, dict):
                raise ValueError("entry is not an object")
            name = _clean_str(raw.get("name"))
            if not _FEED_NAME_RE.fullmatch(name):
                raise ValueError(f"invalid name {name!r}")
            url = _clean_str(raw.get("url"))
            parsed = urllib.parse.urlparse(url)
            host = (parsed.hostname or "").lower()
            if parsed.scheme != "https" or not host or "." not in host \
                    or re.fullmatch(r"[\d.]+|\[?[0-9a-f:]+\]?", host) or host.endswith(".local"):
                raise ValueError("url must be https on a public hostname")
            if raw.get("format") != "csv":
                raise ValueError("format must be 'csv'")
            platform = raw.get("platform")
            if platform not in _FEED_PLATFORMS:
                raise ValueError(f"platform must be one of {sorted(_FEED_PLATFORMS)}")
            id_field = _clean_str(raw.get("id_field"))
            if not id_field:
                raise ValueError("id_field is required")
            datetime.fromisoformat(_clean_str(raw.get("added_at")).replace("Z", "+00:00"))
            feeds.append({
                "name": name, "url": url, "host": host, "platform": platform,
                "id_field": id_field,
                "reason_field": _clean_str(raw.get("reason_field")) or None,
                "source_field": _clean_str(raw.get("source_field")) or None,
                "date_field": _clean_str(raw.get("date_field")) or None,
                "default_reason": _clean_str(raw.get("default_reason")) or "listed by threat feed",
            })
        except (ValueError, TypeError) as exc:
            logger.warning("threat feeds: skipping entry %d: %s", i, exc)
    return feeds


def _feed_id_ok(platform: str, ext_id: str) -> bool:
    if platform == "chromium":
        return bool(_CHROME_EXTENSION_ID_RE.fullmatch(ext_id))
    return bool(_FIREFOX_GUID_RE.match(ext_id))


def fetch_threat_feed(feed: dict, *, client: HttpClient | None = None,
                      validators: dict | None = None):
    """Return {extension_id_lower: {reason, source, date}} or None on failure. Never raises.

    `validators` ({"etag": ...}) makes the request conditional: a 304 returns
    NOT_MODIFIED, and a 200 stores the new ETag back into `validators`.
    """
    client = client or HttpClient(timeout=30.0)
    status, headers, body, error = client.get(feed["url"], allowed_hosts={feed["host"]},
                                              max_bytes=32 * 1024 * 1024,
                                              headers=_conditional_headers(validators))
    if status == 304:
        return NOT_MODIFIED
    if status != 200 or not body or error:
        logger.warning("threat feed %s fetch failed: %s", feed["name"], error or f"HTTP {status}")
        return None
    entries: dict[str, dict] = {}
    try:
        reader = csv.DictReader(io.StringIO(body.decode("utf-8-sig", errors="replace")))
        if feed["id_field"] not in (reader.fieldnames or []):
            logger.warning("threat feed %s: column %r missing", feed["name"], feed["id_field"])
            return None
        for n, row in enumerate(reader):
            if n >= _FEED_MAX_ROWS:
                break
            ext_id = _clean_str(row.get(feed["id_field"])).lower()
            if not _feed_id_ok(feed["platform"], ext_id):
                continue
            entries[ext_id] = {
                "reason": (_clean_str(row.get(feed["reason_field"] or "")) or feed["default_reason"])[:120],
                "source": _clean_str(row.get(feed["source_field"] or ""))[:300] or None,
                "date": _clean_str(row.get(feed["date_field"] or ""))[:40] or None,
            }
    except (csv.Error, ValueError) as exc:
        logger.warning("threat feed %s parse failed: %s", feed["name"], exc)
        return None
    if validators is not None and _header(headers, "ETag"):
        validators["etag"] = _header(headers, "ETag")
    return entries


def classify_feed_reason(reason: str) -> tuple[str, int]:
    """(severity, threat score) for a feed's free-text listing reason."""
    text = f"{_clean_str(reason).lower()} "
    for severity, threat, keywords in _FEED_SEVERITY:
        if any(k in text for k in keywords):
            return severity, threat
    return "listed", 45  # policy violation / removed for an unstated reason


def match_threat_feeds(feed_index: dict, store: str, extension_id: str) -> list[dict]:
    """Hits for one extension. `feed_index` is {feed_name: {"platform", "entries"}}."""
    ext_id = _clean_str(extension_id).lower()
    if not ext_id:
        return []
    hits = []
    for name, feed in sorted((feed_index or {}).items()):
        if store not in _FEED_PLATFORMS.get(feed.get("platform"), ()):
            continue
        entry = (feed.get("entries") or {}).get(ext_id)
        if entry:
            severity, threat = classify_feed_reason(entry.get("reason"))
            hits.append({"feed": name, **entry, "severity": severity, "threat": threat})
    return hits


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

        def post(self, url, form, **_):
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
    # A failed later page discards the partial list instead of returning page 1 only.
    partial = fetch_mozilla_blocklist(client=_Fake(
        (200, {"Next-Page": "https://firefox.settings.services.mozilla.com/p2"},
         b'{"data":[{"guid":"a@b"}]}', None),
        (502, {}, b"", None),
    ))
    assert partial == {}, partial

    # Conditional GET: the ETag goes out as If-None-Match; 304 means "use the cache".
    class _Cond:
        def __init__(self, *responses):
            self.responses, self.sent = list(responses), []

        def get(self, url, *, headers=None, **_):
            self.sent.append(headers)
            return self.responses.pop(0)

    val = {}
    cond = _Cond((200, {"ETag": '"v1"'}, b'{"data":[{"guid":"a@b"}]}', None))
    assert set(fetch_mozilla_blocklist(client=cond, validators=val)) == {"a@b"} and val == {"etag": '"v1"'}
    assert cond.sent == [None], cond.sent
    cond = _Cond((304, {}, b"", None))
    assert fetch_mozilla_blocklist(client=cond, validators=val) is NOT_MODIFIED
    assert cond.sent == [{"If-None-Match": '"v1"'}], cond.sent

    json_blob, count, max_cvss = summarize_vulnerabilities([
        {"cve": "CVE-2024-0001", "cvss_score": 8.8},
        {"cve": "CVE-2024-0002", "cvss_score": 5.1},
    ])
    assert count == 2 and max_cvss == 8.8 and "CVE-2024-0001" in json_blob
    assert publisher_is_reputable("1Password Devs"), "AMO author suffix"
    assert publisher_is_reputable("AgileBits Inc") and publisher_is_reputable("Duck Duck Go, Inc.")
    assert publisher_is_reputable("Google Ireland, Ltd.") and not publisher_is_reputable("eyeo GmbH")
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
        post = get
    assert fetch_chrome_metadata("../publisher/x", client=_NoNet())["error"] == "invalid chrome extension id"
    # Edits to the file are picked up without a restart (mtime change).
    fixture["publishers"].append({"name": "Late Addition", "match_names": ["Late Addition"], "added_at": "2026-10-27T00:00:00Z"})
    with open(tmp.name, "w") as fh:
        json.dump(fixture, fh)
    os.utime(tmp.name, (os.path.getmtime(tmp.name) + 5,) * 2)
    assert publisher_is_reputable("Late Addition Inc")
    assert not publisher_is_reputable("Totally Not 1Password Devs")
    # Safari: the App Store lists the containing app, looked up by its bundle ID.
    assert safari_containing_app("/Applications/Wipr.app/Contents/PlugIns/Wipr Extra.appex") == \
        "/Applications/Wipr.app"
    assert safari_containing_app("/Users/a/Applications/X.app/Contents/PlugIns/X.appex") is None

    class _Itunes:
        def __init__(self, results, status=200):
            self.results, self.status, self.urls = results, status, []

        def get(self, url, **_):
            self.urls.append(url)
            return self.status, {}, json.dumps({"resultCount": len(self.results),
                                                "results": self.results}).encode(), None
    app = {"bundleId": "com.1password.safari", "trackName": "1Password for Safari",
           "sellerName": "AgileBits Inc.", "version": "8.12.42", "averageUserRating": 0,
           "userRatingCount": 0, "currentVersionReleaseDate": "2026-10-22T16:41:31Z",
           "primaryGenreName": "Utilities", "sellerUrl": "https://1password.com",
           "trackViewUrl": "https://apps.apple.com/us/app/id1569813296?mt=12"}
    itunes = _Itunes([app])
    sm = fetch_store_metadata("safari", "com.1password.safari", client=itunes)
    assert sm["status"] == "public" and sm["developer"] == "AgileBits Inc." and sm["rating"] is None, sm
    assert "bundleId=com.1password.safari" in itunes.urls[0] and sm["manifest_unavailable"], itunes.urls
    other = fetch_safari_metadata("com.evil.app", client=_Itunes([app]))      # answer for another app
    assert other["status"] == "off_store", other
    off = analyze_extension({"store": "safari", "name": "x", "host_count": 2, "store_meta": other})
    assert off["threat_score"] == 0 and any(s["code"] == "not-in-app-store" for s in off["risk_signals"])
    apps = {"/Applications/W.app": ("site.w", "TEAM1")}
    ext = derive_extension_identity({"source": "safari_extensions", "name": "Wipr Extra",
                                     "installed_paths": ["/Applications/W.app/Contents/PlugIns/X.appex"]})
    bound = with_safari_app(ext, apps)
    assert bound["extension_key"] == "ext:safari:site.w/x.appex" and bound["app_team_id"] == "TEAM1", bound
    assert with_safari_app(ext, {}) == ext
    assert fetch_safari_metadata("../x", client=_Itunes([app]))["error"] == "invalid app bundle id"
    assert fetch_safari_metadata("com.a.b", client=_Itunes([], status=500))["status"] == "unknown"
    appex = "/Applications/1Password for Safari.app/Contents/PlugIns/1Password.appex"
    sr = analyze_extension({"store": "safari", "name": "1Password", "host_count": 3, "app_team_id": "2BUA8C4S2C",
                            "installs": [{"path": appex, "platform": "darwin"}], "store_meta": sm})
    assert sr["publisher_reputable"] and sr["store_status"] == "public", sr
    assert not analyze_extension({"store": "safari", "name": "1Password", "host_count": 3,   # unsigned app
                                  "installs": [{"path": appex, "platform": "darwin"}],
                                  "store_meta": sm})["publisher_reputable"]
    assert any(s["code"] == "manifest-uninspected" for s in sr["risk_signals"]), sr
    moved = analyze_extension({"store": "safari", "name": "1Password", "host_count": 3, "app_team_id": "T",
                               "installs": [{"path": "/tmp/1Password.appex", "platform": "darwin"}],
                               "store_meta": sm})
    assert not moved["publisher_reputable"] and any(
        s["code"] == "not-store-install" for s in moved["risk_signals"]), moved

    os.unlink(tmp.name)

    # Chrome listing RPC: envelopes map by tag, null payload = not served,
    # a payload for another ID is drift (no partial data), bad IDs never sent.
    def _cws_payload(eid, email="dev@example.org"):
        item = [None] * 20
        item[0], item[2], item[3], item[4], item[7], item[9] = eid, "Ex", 4.26, 1234, "example.org", True
        item[8] = item[15] = True
        item[11], item[14] = ["productivity/workflow", None, 4], 100_000
        item[18] = json.dumps({"manifest_version": 3, "name": "__MSG_extName__", "version": "2.1",
                               "permissions": ["tabs"], "content_scripts": [{"matches": ["<all_urls>"]}]})
        dev = [None] * 11
        dev[0], dev[3], dev[5], dev[7], dev[10] = email, 1, "Example", "Example Ltd", "u" + "1" * 32
        payload = [None] * 34
        payload[0], payload[7], payload[10], payload[13] = item, [1, 6], dev, "2.1"
        payload[14], payload[33] = [1_790_000_000, 0], "https://example.org/privacy"
        return payload

    def _rpc_body(*envelopes):
        lines = [")]}'", ""]
        for tag, payload, *code in envelopes:
            chunk = json.dumps([["wrb.fr", _CWS_RPC_ID, payload if payload is None else json.dumps(payload),
                                 None, None, code or [5], tag]])
            lines += [str(len(chunk)), chunk]
        return "\n".join(lines).encode()

    class _Rpc:
        def __init__(self, *responses):
            self.responses, self.forms, self.urls = list(responses), [], []

        def post(self, url, form, *, allowed_hosts, **_):
            assert allowed_hosts == _CHROME_HOSTS and url == _CWS_RPC_URL
            self.forms.append(form["f.req"])
            return self.responses.pop(0)

        def get(self, url, **_):
            self.urls.append(url)
            return self.responses.pop(0)

    a_id, b_id, c_id = "a" * 32, "b" * 32, "c" * 32
    rpc = _Rpc((200, {}, _rpc_body(("3", _cws_payload("d" * 32)), ("1", _cws_payload(a_id)),
                                   ("2", None)), None))
    listings = fetch_chrome_listings([a_id, "../x", b_id, a_id, c_id], client=rpc)
    assert len(rpc.forms) == 1 and "../x" not in rpc.forms[0] and rpc.forms[0].count(a_id) == 1, rpc.forms
    assert set(listings) == {a_id, b_id, c_id}, listings
    hit = listings[a_id]
    assert hit == {
        "store": "chrome", "status": "public", "url": "https://chromewebstore.google.com/detail/" + a_id,
        "name": "Ex", "version": "2.1", "manifest_version": 3, "permissions": ["tabs"],
        "content_script_matches": ["<all_urls>"], "users": 100_000, "rating": 4.3, "rating_count": 1234,
        "category": "Workflow & Planning", "featured": True, "updated_at": "2026-09-21T14:13:20+00:00",
        "developer_website": "https://example.org", "developer_email": "dev@example.org", "trader": True,
        "privacy_codes": [1, 6], "privacy_disclosure": "The developer has disclosed that it collects or uses: "
                              "personally identifiable information, location",
        "privacy_policy_url": "https://example.org/privacy", "publisher_id": "u" + "1" * 32,
        "publisher": "Example", "established_publisher": True,
    }, hit
    assert listings[b_id]["status"] == "unlisted" and listings[b_id]["listing_missing"], listings[b_id]
    drift = listings[c_id]
    assert drift["status"] == "unknown" and "schema drift" in drift["error"] and "users" not in drift, drift
    # Null payloads: removed (7) is a takedown, transient codes are errors, not "unlisted".
    odd = _cws_payload(c_id)
    odd[14] = [1e20]
    odd[0][14] = 2 ** 70
    nontrader = _cws_payload("d" * 32)
    nontrader[10][5], nontrader[10][7], nontrader[0][8] = "Solo Dev", None, None
    coded = fetch_chrome_listings([a_id, b_id, c_id, "d" * 32, "e" * 32], client=_Rpc((200, {}, _rpc_body(
        ("1", None, 7), ("2", None, 14), ("3", odd), ("4", nontrader), ("5", None, 8)), None)))
    assert coded[a_id]["status"] == "removed" and "listing_missing" not in coded[a_id], coded[a_id]
    assert coded[b_id]["status"] == "unknown" and "code 14" in coded[b_id]["error"], coded[b_id]
    assert coded[c_id]["status"] == "public" and "updated_at" not in coded[c_id], coded[c_id]
    assert coded["d" * 32]["publisher"] == "Solo Dev" and "established_publisher" not in coded["d" * 32]
    assert coded["e" * 32]["rate_limited"], coded["e" * 32]
    deep = b")]}'\n" + b"[" * 100_000
    assert fetch_chrome_listings([a_id], client=_Rpc((200, {}, deep, None)))[a_id]["error"]
    bad_mail = fetch_chrome_listings([a_id], client=_Rpc(
        (200, {}, _rpc_body(("1", _cws_payload(a_id, email="x@y"))), None)))[a_id]
    assert "developer_email" not in bad_mail and bad_mail["status"] == "public", bad_mail
    limited = fetch_chrome_listings([a_id, b_id], client=_Rpc((429, {}, b"", None)))
    assert all(m["rate_limited"] and m["error"] for m in limited.values()), limited
    # After a 429 the later chunks are marked, not posted (_Rpc has one response).
    many = ["".join("abcdefghijklmnop"[(n >> (4 * k)) & 15] for k in range(32))
            for n in range(_CWS_RPC_BATCH + 1)]
    rpc = _Rpc((429, {}, b"", None))
    limited = fetch_chrome_listings(many, client=rpc)
    assert len(rpc.forms) == 1 and len(limited) == len(many), (len(rpc.forms), len(limited))
    assert all(m["rate_limited"] for m in limited.values())
    assert fetch_chrome_listings(["nope"], client=_NoNet()) == {}
    # A cached manifest for the update2 version skips the CRX download.
    rpc = _Rpc((200, {}, b'<gupdate><app><updatecheck status="ok" version="1.2" '
                          b'codebase="https://clients2.googleusercontent.com/x.crx"/></app></gupdate>',
                None))
    cached_mv = fetch_chrome_metadata(b_id, client=rpc, listing={
        "store": "chrome", "status": "unlisted", "listing_missing": True},
        manifest_for=lambda v: {"manifest_version": 3, "crx_hash_verified": True} if v == "1.2" else None)
    assert cached_mv["manifest_version"] == 3 and cached_mv["status"] == "unlisted", cached_mv
    assert rpc.forms == [] and len(rpc.urls) == 1 and "update2" in rpc.urls[0], rpc.urls
    # Listed: the manifest came with the listing, so no update2 and no CRX.
    rpc = _Rpc((200, {}, _rpc_body(("1", _cws_payload(a_id))), None))
    assert fetch_chrome_metadata(a_id, client=rpc)["status"] == "public" and rpc.urls == []
    gone = fetch_chrome_metadata(b_id, client=_Rpc((200, {}, _rpc_body(("1", None)), None), (
        200, {}, b'<gupdate><app><updatecheck status="error-unknownApplication"/></app></gupdate>', None)))
    assert gone["status"] == "not_found" and "listing_missing" not in gone, gone
    listing = hit

    class _NoUpdate:
        def __init__(self):
            self.urls = []

        def post(self, url, form, **_):
            return 200, {}, _rpc_body(("1", None)), None

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

    # Threat feeds: parse, classify, scope by platform, score.
    feed_tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump({"feeds": [
        {"name": "t", "url": "https://feeds.example.org/x.csv", "format": "csv", "platform": "chromium",
         "id_field": "id", "reason_field": "why", "added_at": "2026-10-27T00:00:00Z"},
        {"name": "lan", "url": "https://192.168.1.5/x.csv", "format": "csv", "platform": "chromium",
         "id_field": "id", "added_at": "2026-10-27T00:00:00Z"},                    # skipped: IP host
        {"name": "plain", "url": "http://feeds.example.org/x.csv", "format": "csv", "platform": "chromium",
         "id_field": "id", "added_at": "2026-10-27T00:00:00Z"},                    # skipped: not https
        {"name": "nodate", "url": "https://feeds.example.org/x.csv", "format": "csv",
         "platform": "chromium", "id_field": "id"},                                # skipped: no added_at
    ]}, feed_tmp)
    feed_tmp.close()
    os.environ["EXTENSION_THREAT_FEEDS_FILE"] = feed_tmp.name
    feeds = load_threat_feeds()
    os.unlink(feed_tmp.name)
    assert [f["name"] for f in feeds] == ["t"], feeds

    class _FeedClient:
        def get(self, url, *, allowed_hosts, **_):
            assert allowed_hosts == {"feeds.example.org"}
            return 200, {}, ("﻿id,why\n" + "a" * 32 + ",Malware\n" + "b" * 32 + ",Adware\n"
                             + "c" * 32 + ",Policy Violation\nnot-an-id,Malware\n").encode(), None
    entries = fetch_threat_feed(feeds[0], client=_FeedClient())
    assert set(entries) == {"a" * 32, "b" * 32, "c" * 32}, entries
    fval = {"etag": '"f1"'}
    fcond = _Cond((304, {}, b"", None))
    assert fetch_threat_feed(feeds[0], client=fcond, validators=fval) is NOT_MODIFIED
    assert fcond.sent == [{"If-None-Match": '"f1"'}], fcond.sent
    index = {"t": {"platform": "chromium", "entries": entries}}
    assert match_threat_feeds(index, "firefox", "a" * 32) == []          # platform-scoped
    assert match_threat_feeds(index, "vivaldi", "A" * 32)[0]["severity"] == "malicious"
    assert classify_feed_reason("Adware")[0] == "unwanted"
    assert classify_feed_reason("Policy Violation") == ("listed", 45)
    for ext_id, floor, bad in (("a" * 32, 85, True), ("b" * 32, 70, False), ("c" * 32, 60, False)):
        r = analyze_extension({"store": "edge", "extension_id": ext_id, "name": "x", "host_count": 1,
                               "store_meta": {"status": "public", "users": 50}},
                              feed_hits=match_threat_feeds(index, "edge", ext_id))
        assert r["risk_score"] >= floor and r["known_bad"] is bad, (ext_id, r["risk_score"], r["known_bad"])
        assert any(s["code"] == "threat-feed:t" for s in r["risk_signals"]), r

    # Edge falls back to the Chrome Web Store for IDs Edge's store does not know.
    class _EdgeMiss(_NoUpdate):
        def get(self, url, **_):
            if "microsoftedge" in url:
                return 404, {}, b"", None
            return super().get(url)

        def post(self, url, form, **_):
            return 200, {}, _rpc_body(("1", _cws_payload("d" * 32))), None
    via = fetch_store_metadata("edge", "d" * 32, client=_EdgeMiss())
    assert via["store"] == "chrome" and via["resolved_from"] == "edge", via

    class _EdgeMissRpcDown(_EdgeMiss):
        def post(self, url, form, **_):
            return 500, {}, b"", None
    down = fetch_store_metadata("edge", "d" * 32, client=_EdgeMissRpcDown())
    assert down["status"] == "unknown" and down["error"], down  # not a cacheable not_found

    # AMO: manifest_version and content scripts come from the signed XPI.
    xpi = _zip({"manifest.json": json.dumps({"manifest_version": 2, "content_scripts": [
        {"matches": ["<all_urls>"], "js": ["c.js"]}]})})

    class _Amo:
        def __init__(self, digest):
            self.digest = digest

        def get(self, url, *, allowed_hosts, **_):
            assert allowed_hosts == _AMO_HOSTS
            if url.endswith(".xpi"):
                return 200, {}, xpi, None
            return 200, {}, json.dumps({"status": "public", "current_version": {"version": "1", "file": {
                "url": "https://addons.mozilla.org/firefox/downloads/file/1/x.xpi",
                "hash": "sha256:" + self.digest, "size": len(xpi), "permissions": ["tabs"]}}}).encode(), None
    amo = fetch_amo_metadata("x@y.org", client=_Amo(hashlib.sha256(xpi).hexdigest()))
    assert amo["manifest_version"] == 2 and amo["content_script_matches"] == ["<all_urls>"], amo
    assert amo["permissions"] == ["tabs"] and amo["crx_hash_verified"] is True, amo
    tampered = fetch_amo_metadata("x@y.org", client=_Amo("0" * 64))
    assert tampered["manifest_error"] == "XPI SHA-256 does not match AMO", tampered

    nu = _NoUpdate()
    served_none = fetch_chrome_metadata("c" * 32, client=nu)
    assert "prodversion=999.0" in nu.urls[0], nu.urls
    assert served_none["status"] == "unlisted" and "manifest_error" not in served_none, served_none
    nu_result = analyze_extension({"store": "chrome", "extension_id": "c" * 32, "name": "x",
                                   "host_count": 1, "store_meta": served_none})
    assert not any(s["code"] == "manifest-unparseable" for s in nu_result["risk_signals"]), nu_result
    # Uninspected must not fail open: it carries its own non-zero signal.
    assert any(s["code"] == "manifest-uninspected" for s in nu_result["risk_signals"]), nu_result
    assert nu_result["threat_score"] >= 15 and huge.get("crx_hash_verified") is None

    listed_chrome = analyze_extension({"store": "chrome", "extension_id": "c" * 32, "name": "x",
                                       "host_count": 1, "store_meta": {"status": "public", **listing}})
    codes = {s["code"] for s in listed_chrome["risk_signals"]}
    assert {"store-featured", "install-popularity", "manifest-v3"} <= codes, codes
    assert listed_chrome["developer_email"] == "dev@example.org" and listed_chrome["featured"] is True
    panned = analyze_extension({"store": "chrome", "extension_id": "c" * 32, "name": "x", "host_count": 1,
                                "store_meta": {"status": "public", "rating": 1.8, "rating_count": 400}})
    assert any(s["code"] == "poor-public-reputation" for s in panned["risk_signals"]), panned
    assert panned["threat_score"] >= 15

    # Built-in ID/path never hides a blocklist or feed hit; the flag survives.
    fx_builtin = {"store": "firefox", "extension_id": "evil@mozilla.org", "name": "x",
                  "host_count": 3, "versions": ["1.0"]}
    stale = analyze_extension({"store": "safari", "is_builtin": True, "name": "Clipper", "host_count": 1,
                               "installed_paths": ["/Applications/C.app/Contents/PlugIns/C.appex"]})
    assert not stale["is_builtin"] and stale["risk_score"] > 0, stale
    assert analyze_extension(fx_builtin)["risk_score"] == 0
    flagged = analyze_extension(fx_builtin, blocklist_entry={"guid": "evil@mozilla.org"})
    assert flagged["risk_score"] >= 85 and flagged["known_bad"] and flagged["is_builtin"], flagged
    fed = analyze_extension(fx_builtin, feed_hits=[{"feed": "f", "reason": "adware", "severity": "unwanted",
                                                    "threat": 70}])
    assert fed["risk_score"] >= 70 and not fed["known_bad"], fed
    # Safari: only Safari.app / system extensions are built-in, not App Store app extensions.
    assert not is_browser_builtin({"store": "safari", "extension_id": "com.x.ext", "installed_paths":
                                   ["/Applications/X.app/Contents/PlugIns/X Extension.appex"]})
    assert is_browser_builtin({"store": "safari", "extension_id": "com.apple.y", "installed_paths":
                               ["/Applications/Safari.app/Contents/PlugIns/Y.appex"]})
    assert not is_browser_builtin({"store": "safari", "extension_id": "com.x.z", "installed_paths":
                                   ["/Users/a/Downloads/Safari.app/Contents/PlugIns/Z.appex"]})
    for store, path, want in [
        ("chrome", r"C:\Program Files\Google\Chrome\Application\120.0\resources\x", True),
        ("chrome", r"C:\Users\a\AppData\Local\Google\Chrome\Application\120.0\x", True),
        ("chrome", r"C:\Users\a\Desktop\Google\Chrome\Application\x", False),
        ("brave", r"C:\Users\x\Desktop\application\evil", False),
        ("vivaldi", r"C:\Program Files\Vivaldi\Application\6.0\x", True),
        ("edge", r"C:\Program Files (x86)\Microsoft\Edge\Application\156.0\BHO\x.dll", True),
        ("firefox", "/Applications/Firefox.app/Contents/Resources/browser/features/a.xpi", True),
        ("firefox", r"C:\Program Files\Mozilla Firefox\browser\features\a.xpi", True),
        ("firefox", "/tmp/browser/features/a.xpi", False),
    ]:
        got = is_browser_builtin({"store": store, "extension_id": "x", "installed_paths": [path]})
        assert got is want, (store, path, got)

    # Typosquat: a store-vouched publisher's look-alike name is not penalised.
    assert name_anomaly_signals("Motion")[1] == 18
    sig, pen = name_anomaly_signals("Motion", vouched=True)
    assert pen == 0 and sig[0]["code"] == "brand-lookalike-vouched", sig
    assert name_anomaly_signals("Bitwardn", vouched=False)[1] == 18
    home = "/Users/a/Library/Application Support/Google/Chrome/Default/Extensions/"
    badge = {"status": "public", "established_publisher": True, "users": 500_000}
    ok_installs = [{"path": home + "e" * 32 + "/1.0_0", "platform": "darwin"}]
    ok = analyze_extension({"store": "chrome", "extension_id": "e" * 32, "name": "Motion", "host_count": 2,
                            "installs": ok_installs,
                            "store_meta": badge})
    assert not any(s["code"] == "typosquat-brand" for s in ok["risk_signals"]), ok
    unpacked = analyze_extension({"store": "chrome", "extension_id": "e" * 32, "name": "Motion",
                                  "host_count": 2, "installs": [{"path": "/tmp/x", "platform": "darwin"}],
                                  "store_meta": badge})
    assert any(s["code"] == "typosquat-brand" for s in unpacked["risk_signals"]), unpacked
    small = analyze_extension({"store": "chrome", "extension_id": "e" * 32, "name": "Bitwardn",
                               "host_count": 2, "installs": ok_installs,
                               "store_meta": {**badge, "users": 5_000}})
    assert any(s["code"] == "typosquat-brand" for s in small["risk_signals"]), small

    # Declared data collection adds capability (capped), only for weighted codes.
    cap0, _ = _capability(set(), {"https://a.com/*"}, set())
    cap1, sig1 = _capability(set(), {"https://a.com/*"}, set(), privacy_codes=[4, 3, 5, 6])
    assert cap1 - cap0 == _PRIVACY_CAP and sig1[-1]["code"] == "declared-data-collection", sig1
    assert _capability(set(), set(), set(), privacy_codes=[6, 9])[0] == 0

    # Trust signals carry negative weights equal to the trust points they add.
    trust, tsig = _trust_score({"status": "public", "manifest_version": 3, "featured": True}, {},
                               reputable=False)
    assert trust == -sum(s["weight"] for s in tsig) == 38, (trust, tsig)
    utrust, usig = _trust_score({"status": "unlisted"}, {}, reputable=False)
    assert utrust == -sum(s["weight"] for s in usig) == 5, (utrust, usig)
    # Opera: addons.opera.com first (HTML listing + CRX), then the Chrome Web Store.
    oid = "k" * 32
    page = (f'<meta property="aoc:app_id" content="{oid}" /><meta property="aoc:slug" content="ublock" />'
            '<meta property="og:title" content="uBlock Origin" /><h2 class="h-byline" itemprop="brand">'
            'by <a href="/en/search/?developer=gorhill" itemprop="name">gorhill</a></h2>'
            '<span class="rating" id="rating-value">4.8</span>'
            '<span id="rating-count" itemprop="reviewCount">5,530</span>'
            '<span class="total" itemprop="reviewCount">319</span>'
            '<dt>Downloads</dt><dd>15,508,453</dd><dt>Category</dt><dd><a href="/c/">Privacy &amp; '
            'Security</a></dd><dt>Version</dt><dd>1.75.0</dd><dt>Last update</dt><dd>Sept. 18, 2026</dd>')
    ocrx = _zip({"manifest.json": json.dumps({"manifest_version": 3, "name": "__MSG_n__",
                                              "permissions": ["cookies"]})})

    class _Opera:
        def __init__(self, page, status=200):
            self.page, self.status, self.urls = page, status, []

        def get(self, url, **_):
            self.urls.append(url)
            if "/download/" in url:
                return 200, {}, ocrx, None
            return self.status, {}, self.page.encode(), None
    class _OperaCrxDown(_Opera):
        def get(self, url, **_):
            if "/download/" in url:
                return 0, {}, b"", "Connection reset by peer"
            return super().get(url)
    down_o = fetch_opera_metadata(oid, client=_OperaCrxDown(page))
    assert down_o["status"] == "unknown" and down_o["error"], down_o   # not cached
    om = fetch_store_metadata("opera", oid, client=_Opera(page))
    assert (om["store"], om["status"], om["developer"], om["users"], om["rating_count"]) == \
        ("opera", "public", "gorhill", 15_508_453, 5_530), om
    assert om["name"] == "uBlock Origin" and om["manifest_version"] == 3 and om["permissions"] == ["cookies"], om
    assert om["updated_at"].startswith("2026-09-18") and om["category"] == "Privacy & Security", om
    assert om["url"] == "https://addons.opera.com/en/extensions/details/ublock/", om
    cached_o = _Opera(page)
    fetch_opera_metadata(oid, client=cached_o, manifest_for=lambda v: {"manifest_version": 2})
    assert not any("/download/" in u for u in cached_o.urls), cached_o.urls  # cached version: no CRX
    wrong = fetch_opera_metadata(oid, client=_Opera(page.replace(oid, "j" * 32)))
    assert wrong["status"] == "unknown" and "does not match" in wrong["error"], wrong
    assert not analyze_extension({"store": "opera", "extension_id": oid, "name": "x", "host_count": 1,
                                  "store_meta": {**om, "developer": "AgileBits"}})["publisher_reputable"]

    class _OperaMiss(_Opera):
        def post(self, url, form, **_):
            return 200, {}, _rpc_body(("1", _cws_payload(oid))), None
    ovia = fetch_store_metadata("opera", oid, client=_OperaMiss("", status=404))
    assert ovia["store"] == "chrome" and ovia["resolved_from"] == "opera", ovia
    class _Unknown(_NoUpdate):
        def get(self, url, **_):
            if "update2" in url:
                return 200, {}, (b'<gupdate xmlns="http://www.google.com/update2/response"><app>'
                                 b'<updatecheck status="error-unknownApplication"/></app></gupdate>'), None
            return 404, {}, b"", None
    onone = fetch_store_metadata("opera", oid, client=_Unknown())
    assert onone["store"] == "opera" and onone["status"] == "not_found", onone
    print("extension_intel self-check: OK")


if __name__ == "__main__":
    _self_check()
