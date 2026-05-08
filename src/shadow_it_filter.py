"""Shared Shadow IT filtering primitives.

Single source of truth for "is this software a Shadow-IT candidate?" Used by:
  - webviz/app.py — runtime detection in /api/shadow-it
  - categorize_software.py — candidate selection for Wikidata enrichment

The contract: a Shadow IT candidate is software the USER actively chose to
install (`apps`/`programs`/`homebrew_packages`/`chocolatey_packages`),
installed on a small fraction of the platform's hosts (the "outlier"
threshold, configurable via SHADOW_IT_OUTLIER_PCT env var, default 3%),
and not OS plumbing / dev-language transitive deps / browser extensions.

Per-platform threshold rationale: a piece of software installed on 1 of 10
Linux servers means something very different than 1 of 100 Windows
workstations. Computing the threshold globally would over-flag rare
software on small platforms and under-flag rare software on large
platforms. Per-platform is the right scope.
"""
from __future__ import annotations

import os
import re

# Names that are almost always installed by the OS package manager as
# transitive deps or platform components — never user-chosen Shadow IT.
SYSTEM_PACKAGE_RE = re.compile(
    r"^("
    # Library packages (lib*, *-dev, *-doc, *-data, *-common, *-headers, *-dbg, *-dbgsym)
    r"lib[a-z0-9].*"
    r"|.*-(dev|dbg|dbgsym|doc|docs|data|common|headers|src|source|locale|locales|man|examples|utils|runtime|core|base|tiny|minimal)"
    # Linux kernel / firmware / boot
    r"|linux-(image|headers|libc|modules|tools|cloud|generic|signed|firmware|base|hwe|aws|azure|gcp|oracle|kvm|raspi|ibm|nvidia)([-.].*)?"
    r"|kernel(-.*)?|firmware-.*|grub[-.].*|systemd([-.].*)?|initramfs.*|initrd.*"
    # Package manager / distro plumbing
    r"|debconf.*|dpkg.*|apt(-.*)?|aptitude.*|yum.*|dnf.*|rpm(-.*)?|alien.*|snapd.*|flatpak.*"
    # Locale / timezone / console
    r"|tzdata(-.*)?|locales(-.*)?|language-pack(-.*)?|console-(setup|data)(-.*)?"
    # Language runtimes shipped as distro packages
    r"|python3?(-.*|\.[0-9]+(-.*)?)?"
    r"|perl(-.*|-base|-modules.*)?"
    r"|ruby[0-9.]*(-.*)?|gem-.*"
    r"|golang(-.*)?"
    # Toolchain
    r"|gcc(-.*)?|g\+\+(-.*)?|clang(-.*)?|llvm(-.*)?|binutils(-.*)?|make.*|cmake.*"
    r"|automake.*|autoconf.*|libtool.*|pkg-config.*"
    # Desktop / X11 / fonts
    r"|gnome-.*|kde-.*|xfce4-.*|cinnamon-.*|mate-.*|x11-.*|xorg-.*|xserver-.*"
    r"|fonts-.*|gtk[0-9.-]*|qt[0-9.-]*"
    # Crypto / certs / shells
    r"|openssl.*|ca-certificates.*|gnupg.*|gpg.*|gpgv.*|gnupg2.*"
    # Core utils
    r"|ucf|sensible-utils|lsb-.*|base-(files|passwd)|coreutils|util-linux.*"
    r"|findutils|grep|sed|gawk|tar|gzip|xz-utils|bzip2|zstd|file|less|nano"
    r"|vim-(common|tiny|runtime)|bash|dash|zsh|tmux|screen"
    # Network plumbing
    r"|cups(-.*)?|samba.*|smbclient.*|nfs-.*|rpcbind.*|netbase|iproute2|iputils-.*"
    # CUDA / NVIDIA / GPU dev stacks (added 2026-05-07 — these flooded the
    # enrichment queue with non-Shadow-IT candidates that Wikidata never has).
    # Match space-separated names too: "NVIDIA Container", "CUDART Runtime",
    # "CUDA Profiler Tools" — the boundary is `[\s\-_.]` so we catch every
    # variant osquery surfaces.
    r"|cuda([\s\-_.].*)?|cudart([\s\-_.].*)?|cccl([\s\-_.].*)?"
    r"|cupti([\s\-_.].*)?|nccl([\s\-_.].*)?|cusparse([\s\-_.].*)?"
    r"|cusolver([\s\-_.].*)?|cublas([\s\-_.].*)?|cudnn([\s\-_.].*)?"
    r"|nvjpeg([\s\-_.].*)?|nvrtc([\s\-_.].*)?|nvprune([\s\-_.].*)?"
    r"|nvidia([\s\-_.].*)?"
    r"|nvvm([\s\-_.].*)?|nvcc|npp([\s\-_.].*)?|visual profiler.*|nsight.*"
    r"|libnv(idia|jpeg|cu.*|nccl.*|rtc.*|pti.*|blas.*|toolkit.*)?(-.*)?"
    r"|libcu(blas.*|dnn.*|fft.*|rand.*|solver.*|sparse.*|pti.*|tensor.*|nvrtc.*)(-.*)?"
    r"|libnpp.*|libnvrtc.*"
    # Windows OS-plumbing names that aren't user apps
    r"|microsoft visual c\+\+ [0-9]+.*"
    r"|microsoft \.net.*"
    r"|update for microsoft .*"
    r"|security update for microsoft .*"
    r"|definition update for microsoft .*"
    r"|microsoft\.(aad.*|bingsearch|bingweather|bioenrollment|webpimageextension|"
    r"|windowscalculator|skydrive.*|onedrive.*|content.*|asyncfile.*|heif.*|"
    r"|outlook.*|webp.*|xaml.*|ui\..*|xboxgamebar.*|gamebar.*|xbox.*|cortana|"
    r"|wallet.*|getstarted.*|getstarted|store.*|edge.*|edgecore.*|onenote.*)"
    r"|windows sdk.*|windows .*sdk.*|application verifier.*|wdagutilityaccount|defaultaccount"
    r"|game bar|xbox game bar|mecab-.*"
    # Hardware drivers that appear with vendor-prefix + underscore variants
    r"|mlnx_.*|mellanox.*|msi development tools.*|msi dev.*"
    # Python distribution components — "Python 3.X.Y Standard Library (64-bit)",
    # "Python 3.X.Y Test Suite (64-bit)", "Python 3.X.Y Documentation (64-bit)",
    # "Python 3.X.Y Utility Scripts (64-bit)", "Python 3.X.Y pip Bootstrap (64-bit)",
    # "Python 3.X.Y Tcl/Tk Support (64-bit)", "Python 3.X.Y Core Interpreter (64-bit)",
    # "Python 3.X.Y Executables (64-bit)", "Python 3.X.Y Development Libraries (64-bit)"
    r"|python\s+[0-9][\s.0-9].*"
    # Windows SDK variants (long-tail names that don't match the simpler 'windows sdk.*')
    r"|windows software development kit.*|windows app certification kit.*"
    r"|wptx?(64|86)?(\s|\-|_).*|wpt(x64|x86).*|application verifier.*"
    r"|winrt intellisense.*|winrt[\s\-_].*"
    # Microsoft platform components / store-app projections
    r"|microsoft\.(ppiprojection|.*projection|mpeg[0-9]+.*|.*videoextension|"
    r"|cloud.*|content.*|ngc.*|powerautomatedesktop.*|paint|xboxapp.*|copilot.*|"
    r"|todo.*|whiteboard.*|skype.*|teams.*|stickynotes.*|alarmclock.*|"
    r"|maps.*|messaging.*|people.*|moviesandtv|getstarted.*|getstarted)"
    # Microsoft Visual C++ all version variants (v14, v17, etc)
    r"|microsoft visual c\+\+ v?[0-9]+.*"
    # Visual Studio variants (Community, Enterprise, Professional, BuildTools)
    r"|visual studio (community|enterprise|professional|build tools|installer|tools).*"
    r"|visual studio [0-9]+.*"
    # WD / SSD / hardware vendor SKUs that appear in inventory but never in Wikidata
    r"|wd[\s\-_].*|seagate[\s\-_].*|verbatim[\s\-_].*"
    # Placeholder display names from broken installers
    r"|\$\{\{?arpdisplayname\}?\}\$?|\$\{\{[^}]+\}\}.*"
    # Generic Windows Store app prefixes
    r"|windowsstore.*|appsforwindows10.*|microsoftstore.*"
    # Generic SDK / redistributables (catch-all for the long tail)
    r"|.*\bsdk\b.*redistributables?.*|sdk\s+(arm|x86|x64).*"
    r"|.*redistributables?(\s|\-).*|.*\bredistributable\b.*"
    r"|microsoft update health tools|microsoft msi development tools|microsoft msi development tools.*"
    r"|microsoft .net native runtime package.*|universal crt redistributable"
    r"|outlook for windows|microsoft office shared.*|microsoft yourphone"
    r"|microsoft\.zune.*|microsoft\.mspaint|microsoft msync.*"
    r"|microsoft 365 - en-us|cortana"
    # Visual Studio / SDK installer artifacts
    r"|vs_.*|virtio-win-driver-installer.*"
    # Other obviously-not-Shadow-IT
    r"|udk package|verbatim_.*|wd_.*|wd p[0-9]+ .*|m-audio .*|"
    r"|ene_.*|ctadvisor|realtek.*|intel\(r\) .*|amd .*|c5e2524a-.*"
    r"|microsoft\.windows\..*"
    r")$",
    re.IGNORECASE,
)

# Wikidata category tokens that indicate "this is OS plumbing, not an app".
SYSTEM_CATEGORY_TOKENS = (
    "software library", "shared library", "system library",
    "free software library", "kernel module", "device driver",
    "header file", "package manager package", "metapackage",
    "init system", "system component", "operating system component",
)

# osquery `software` table source values.
DEV_LANGUAGE_SOURCES = frozenset({
    "npm_packages", "python_packages", "gem_packages", "cargo_packages",
    "pkg_packages", "portage_packages",
})
EXTENSION_SOURCES = frozenset({
    "chrome_extensions", "firefox_addons", "safari_extensions",
    "ie_extensions", "vscode_extensions", "atom_packages",
})
# Sources that ARE the primary user-installable app surface — apps the user
# actively chose to install. These are the highest-signal Shadow IT candidates
# AND the only sources that should drive Wikidata enrichment.
USER_APP_SOURCES = frozenset({
    "apps",                  # macOS .app bundles
    "programs",              # Windows installed programs
    "homebrew_packages",     # macOS user-installed
    "chocolatey_packages",   # Windows user-installed
})


def is_non_app_source(sources) -> bool:
    """True if every recorded source is a dev-language package manager or
    a browser/IDE extension — i.e. not a user-installed app."""
    if not sources:
        return False
    src_set = {s.lower().strip() for s in sources if isinstance(s, str) and s.strip()}
    if not src_set:
        return False
    return src_set.issubset(DEV_LANGUAGE_SOURCES | EXTENSION_SOURCES)


def has_user_app_source(sources) -> bool:
    """True if at least one recorded source is a user-installable-app channel
    (apps, programs, homebrew_packages, chocolatey_packages)."""
    if not sources:
        return False
    src_set = {s.lower().strip() for s in sources if isinstance(s, str) and s.strip()}
    return bool(src_set & USER_APP_SOURCES)


# ---------------------------------------------------------------------------
# Outlier threshold — configurable via SHADOW_IT_OUTLIER_PCT env var
# ---------------------------------------------------------------------------

# Software is considered an "outlier" (Shadow IT candidate) when it appears
# on no more than this fraction of a platform's hosts. 3% is the published
# default; ops can override per-deployment via the env variable.
DEFAULT_OUTLIER_PCT = 0.03
MIN_OUTLIER_HOSTS = 2  # always allow at least 2 hosts as the floor


def get_outlier_pct(env_var: str = "SHADOW_IT_OUTLIER_PCT") -> float:
    """Read the outlier-threshold percentage from environment.

    Expected as a decimal fraction (0.03 = 3%) — NOT as a whole percentage.
    Falls back to DEFAULT_OUTLIER_PCT on missing / unparseable / out-of-range
    values. Range gate: 0 < pct < 1 (5% would be 0.05, not 5).
    """
    raw = (os.environ.get(env_var) or "").strip()
    if not raw:
        return DEFAULT_OUTLIER_PCT
    # Strip inline comments — `.env` files commonly carry trailing comments
    # after a value (`FOO=0.03  # 3%`). Without this, that whole tail ends
    # up in `raw` and the float() call below fails.
    if "#" in raw:
        raw = raw.split("#", 1)[0].strip()
    if not raw:
        return DEFAULT_OUTLIER_PCT
    try:
        pct = float(raw)
    except ValueError:
        return DEFAULT_OUTLIER_PCT
    if pct <= 0 or pct >= 1:
        return DEFAULT_OUTLIER_PCT
    return pct


def compute_per_platform_thresholds(session, pct: float = None) -> dict:
    """Return {platform: outlier_threshold_int} for every distinct
    Host.platform value in the graph.

    `outlier_threshold_int = max(MIN_OUTLIER_HOSTS, int(plat_hosts * pct))`

    A piece of software installed on > threshold hosts of that platform is
    NOT considered an outlier under this scope. Used by both /api/shadow-it
    (runtime detection) and categorize_software.py (enrichment candidate
    selection) so the two stay aligned.
    """
    if pct is None:
        pct = get_outlier_pct()
    out = {}
    result = session.run(
        "MATCH (h:Host) "
        "WHERE h.platform IS NOT NULL AND h.platform <> '' "
        "RETURN h.platform AS platform, count(h) AS total"
    )
    for rec in result:
        platform = rec["platform"]
        total = int(rec["total"] or 0)
        out[platform] = max(MIN_OUTLIER_HOSTS, int(total * pct))
    return out


def is_system_package(name: str, db_categories=None, sources=None) -> bool:
    """True if a Software node represents OS plumbing, dev-language transitive
    deps, or a browser/IDE extension — anything NOT a user-chosen end-user app.

    Used by /api/shadow-it to suppress false positives AND by
    categorize_software.py to skip enrichment of items that are never going
    to be Shadow IT anyway (the May 2026 fix that stopped Wikidata from
    being hammered by 250 system-package lookups per ETL cycle).
    """
    if not name:
        return False
    if is_non_app_source(sources):
        return True
    if SYSTEM_PACKAGE_RE.match(name.lower().strip()):
        return True
    if db_categories:
        cat_text = " ".join(c.lower() for c in db_categories if isinstance(c, str))
        if any(tok in cat_text for tok in SYSTEM_CATEGORY_TOKENS):
            return True
    return False
