"""Curated catalog of common Shadow IT applications.

Hand-maintained mapping of software-name → (categories, description). Used as
the FIRST stop in enrichment so the most common Shadow IT apps resolve in
microseconds with zero network calls. Only software not in this catalog
falls through to Wikipedia REST.

Lookup is case-insensitive on a normalized name (strip version suffixes,
parenthetical platform tags). Patterns are a tradeoff: too broad and we
mis-classify, too narrow and we miss the common-case apps Wikipedia would
also tell us about.

Maintenance protocol: when an app appears in the enrichment queue often
enough to be noticed (e.g., the user explicitly asks "why does Slack keep
hitting Wikipedia?"), add it here. Keep entries terse — one descriptive
line; let categories carry the structure.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

# Catalog format: { normalized_key: (categories_list, description) }
# Keys are lowercase, no version, no parenthetical platform tags.
_CATALOG = {
    # === Communication ===
    "slack": (["Communication", "Team Chat"], "Workplace messaging and collaboration platform."),
    "discord": (["Communication", "Voice Chat"], "Voice, video, and text chat for communities."),
    "zoom": (["Communication", "Video Conferencing"], "Video conferencing and online meeting platform."),
    "microsoft teams": (["Communication", "Team Chat"], "Microsoft's workplace chat and meetings platform."),
    "telegram desktop": (["Communication", "Messaging"], "Cloud-based instant messaging app."),
    "signal": (["Communication", "Messaging"], "End-to-end encrypted messaging app."),
    "whatsapp": (["Communication", "Messaging"], "End-to-end encrypted messaging app."),
    "skype": (["Communication", "Video Conferencing"], "Voice, video, and instant messaging."),

    # === Productivity / Notes ===
    "notion": (["Productivity", "Notes"], "All-in-one workspace for notes, docs, and project management."),
    "obsidian": (["Productivity", "Notes"], "Markdown-based knowledge base and note-taking app."),
    "evernote": (["Productivity", "Notes"], "Note-taking and organization app."),
    "trello": (["Productivity", "Project Management"], "Kanban-style project management."),
    "todoist": (["Productivity", "Task Management"], "Personal and team task manager."),

    # === Security / Password Managers ===
    "1password": (["Security Tool", "Password Manager"], "Cross-platform password manager."),
    "bitwarden": (["Security Tool", "Password Manager"], "Open-source password manager."),
    "keepassxc": (["Security Tool", "Password Manager"], "Cross-platform community port of KeePass."),
    "keepass": (["Security Tool", "Password Manager"], "Free open-source password manager."),
    "lastpass": (["Security Tool", "Password Manager"], "Cloud password manager."),
    "dashlane": (["Security Tool", "Password Manager"], "Password manager and digital wallet."),
    "nordpass": (["Security Tool", "Password Manager"], "NordVPN's password manager."),

    # === Remote Access ===
    "anydesk": (["Remote Access", "Remote Desktop"], "Remote desktop software."),
    "teamviewer": (["Remote Access", "Remote Desktop"], "Remote control and desktop sharing."),
    "putty": (["Remote Access", "SSH Client"], "Free SSH and telnet client for Windows."),
    "windows terminal": (["Developer Tool", "Terminal"], "Microsoft's modern terminal app."),
    "tabby": (["Remote Access", "Terminal"], "Modern terminal with SSH support."),
    "mremoteng": (["Remote Access", "Connection Manager"], "Multi-protocol remote connection manager."),

    # === Browsers ===
    "google chrome": (["Browser"], "Google's web browser based on Chromium."),
    "mozilla firefox": (["Browser"], "Open-source web browser by Mozilla."),
    "firefox": (["Browser"], "Open-source web browser by Mozilla."),
    "brave browser": (["Browser", "Privacy Tool"], "Privacy-focused browser based on Chromium."),
    "brave": (["Browser", "Privacy Tool"], "Privacy-focused browser based on Chromium."),
    "vivaldi": (["Browser"], "Customizable web browser."),
    "opera": (["Browser"], "Web browser developed by Opera Software."),

    # === Developer Tools ===
    "visual studio code": (["Developer Tool", "IDE"], "Microsoft's free source-code editor."),
    "sublime text": (["Developer Tool", "Editor"], "Sophisticated text editor for code."),
    "atom": (["Developer Tool", "Editor"], "Hackable text editor (deprecated by GitHub)."),
    "intellij idea": (["Developer Tool", "IDE"], "JetBrains IDE for Java and JVM languages."),
    "pycharm": (["Developer Tool", "IDE"], "JetBrains IDE for Python."),
    "webstorm": (["Developer Tool", "IDE"], "JetBrains IDE for JavaScript/TypeScript."),
    "goland": (["Developer Tool", "IDE"], "JetBrains IDE for Go."),
    "android studio": (["Developer Tool", "IDE"], "Google's IDE for Android app development."),
    "xcode": (["Developer Tool", "IDE"], "Apple's IDE for macOS/iOS development."),
    "github desktop": (["Developer Tool", "Git Client"], "GitHub's desktop Git client."),
    "sourcetree": (["Developer Tool", "Git Client"], "Atlassian's free Git GUI client."),
    "gitkraken": (["Developer Tool", "Git Client"], "Cross-platform Git GUI."),
    "postman": (["Developer Tool", "API Client"], "API development and testing platform."),
    "insomnia": (["Developer Tool", "API Client"], "Open-source API design and testing tool."),
    "docker desktop": (["Developer Tool", "Container Runtime"], "Docker container runtime for desktop OSes."),
    "podman desktop": (["Developer Tool", "Container Runtime"], "Container runtime alternative to Docker."),
    "nodejs": (["Developer Tool", "Runtime"], "JavaScript runtime built on Chrome's V8 engine."),
    "node.js": (["Developer Tool", "Runtime"], "JavaScript runtime built on Chrome's V8 engine."),
    "git": (["Developer Tool", "Version Control"], "Distributed version control system."),

    # === Utilities ===
    "7-zip": (["Utility", "Archive Manager"], "Open-source file archiver."),
    "winrar": (["Utility", "Archive Manager"], "Windows archive manager."),
    "the unarchiver": (["Utility", "Archive Manager"], "macOS archive utility."),
    "rectangle": (["Utility", "Window Manager"], "macOS window manager (free)."),
    "magnet": (["Utility", "Window Manager"], "macOS window manager (paid)."),
    "alfred": (["Utility", "Launcher"], "macOS productivity launcher."),
    "raycast": (["Utility", "Launcher"], "Modern macOS launcher with extensions."),
    "powertoys": (["Utility", "Productivity"], "Microsoft's free productivity utilities for Windows."),
    "ditto": (["Utility", "Clipboard"], "Windows clipboard manager."),

    # === Cloud Storage ===
    "dropbox": (["Cloud Storage"], "File hosting and synchronization service."),
    "google drive": (["Cloud Storage"], "Google's cloud file storage."),
    "onedrive": (["Cloud Storage"], "Microsoft's cloud file storage."),
    "icloud drive": (["Cloud Storage"], "Apple's cloud file storage."),
    "box": (["Cloud Storage"], "Enterprise cloud storage and collaboration."),

    # === Media ===
    "vlc media player": (["Media Player"], "Free open-source cross-platform media player."),
    "vlc": (["Media Player"], "Free open-source cross-platform media player."),
    "spotify": (["Media", "Music Streaming"], "Music streaming service."),
    "obs studio": (["Media", "Streaming"], "Free open-source streaming and recording software."),
    "obs": (["Media", "Streaming"], "Free open-source streaming and recording software."),
    "audacity": (["Media", "Audio Editor"], "Free open-source audio editor."),
    "handbrake": (["Media", "Video Encoder"], "Open-source video transcoder."),

    # === Design ===
    "figma": (["Design", "UI Design"], "Collaborative interface design tool."),
    "sketch": (["Design", "UI Design"], "macOS interface design app."),
    "adobe photoshop": (["Design", "Image Editor"], "Adobe's raster graphics editor."),
    "adobe illustrator": (["Design", "Vector Editor"], "Adobe's vector graphics editor."),
    "gimp": (["Design", "Image Editor"], "Free open-source raster graphics editor."),
    "inkscape": (["Design", "Vector Editor"], "Free open-source vector graphics editor."),
    "blender": (["Design", "3D Modeling"], "Free open-source 3D creation suite."),
    "krita": (["Design", "Image Editor"], "Free open-source digital painting app."),

    # === Privacy / VPN ===
    "nordvpn": (["Privacy Tool", "VPN"], "Commercial VPN service."),
    "expressvpn": (["Privacy Tool", "VPN"], "Commercial VPN service."),
    "protonvpn": (["Privacy Tool", "VPN"], "Privacy-focused VPN by Proton."),
    "mullvad vpn": (["Privacy Tool", "VPN"], "Privacy-focused VPN."),
    "tunnelblick": (["Privacy Tool", "VPN"], "Free OpenVPN client for macOS."),
    "openvpn connect": (["Privacy Tool", "VPN"], "OpenVPN's official client."),
    "wireguard": (["Privacy Tool", "VPN"], "Modern open-source VPN protocol."),
    "tor browser": (["Privacy Tool", "Browser"], "Browser routing traffic through the Tor network."),

    # === Crypto / Wallets — high-signal Shadow IT ===
    "exodus": (["Crypto", "Wallet"], "Multi-cryptocurrency wallet."),
    "ledger live": (["Crypto", "Wallet"], "Companion app for Ledger hardware wallets."),
    "metamask": (["Crypto", "Wallet"], "Ethereum-compatible browser wallet."),

    # === Office / PDF ===
    "libreoffice": (["Productivity", "Office Suite"], "Free open-source office suite."),
    "openoffice": (["Productivity", "Office Suite"], "Apache's open-source office suite."),
    "adobe acrobat reader": (["Productivity", "PDF Reader"], "Adobe's free PDF reader."),
    "adobe acrobat reader dc": (["Productivity", "PDF Reader"], "Adobe's free PDF reader."),
    "foxit reader": (["Productivity", "PDF Reader"], "PDF reader and editor."),

    # === File transfer ===
    "filezilla": (["Utility", "FTP Client"], "Free FTP/SFTP client."),
    "cyberduck": (["Utility", "FTP Client"], "Free FTP/SFTP/cloud-storage browser for macOS/Windows."),
    "transmission": (["Utility", "BitTorrent"], "Free open-source BitTorrent client."),
    "qbittorrent": (["Utility", "BitTorrent"], "Free open-source BitTorrent client."),

    # === Database ===
    "dbeaver": (["Developer Tool", "Database Client"], "Universal database manager."),
    "tableplus": (["Developer Tool", "Database Client"], "Modern native GUI tool for relational databases."),
    "datagrip": (["Developer Tool", "Database Client"], "JetBrains database IDE."),
}


# Patterns for stripping common version / platform suffixes before lookup.
# Order matters — more specific patterns first.
_NORMALIZE_PATTERNS = [
    re.compile(r"\s+release\s+[0-9.]+.*$", re.IGNORECASE),  # "PuTTY release 0.83 (64-bit)"
    re.compile(r"\s+[0-9]+\.[0-9.]+.*$"),                   # "Slack 4.39.95"
    re.compile(r"\s*\([^)]*\)\s*$"),                        # "(64-bit)" / "(x64)"
    re.compile(r"\s+(x64|x86|arm64|amd64|i386|i686).*$", re.IGNORECASE),
    re.compile(r"\s+(64|32)-bit.*$", re.IGNORECASE),
    re.compile(r"\s+v?[0-9]+(\.[0-9]+)+.*$"),               # "v1.2.3.4"
]


def _normalize(name: str) -> str:
    """Strip version + platform suffixes for catalog lookup."""
    n = (name or "").strip().lower()
    prev = None
    while n != prev:
        prev = n
        for pat in _NORMALIZE_PATTERNS:
            n = pat.sub("", n).strip()
    return n


def lookup(software_name: str) -> Optional[Tuple[List[str], Optional[str]]]:
    """Return (categories, description) for a known app, or None."""
    if not software_name:
        return None
    key = _normalize(software_name)
    if key in _CATALOG:
        cats, desc = _CATALOG[key]
        return list(cats), desc
    return None


def catalog_size() -> int:
    """Number of curated entries — surfaced for diagnostics."""
    return len(_CATALOG)
