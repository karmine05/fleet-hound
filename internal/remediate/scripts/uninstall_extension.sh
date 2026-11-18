#!/bin/sh
# Fleet Hound: remove one browser extension from this host (macOS and Linux).
# One generic script: the server fills in the three parameters below per run
# and sends it as a one-off Fleet script. Nothing is saved in Fleet.
#
# The host supplies everything else: OS, user homes, browser data roots and
# profiles are discovered here, so the same script serves every extension.
EXT_ID='__EXT_ID__'
EXT_STORE='__EXT_STORE__'
BLOCK='__BLOCK__'
# Path prefix for tests only; always empty in production.
ROOT=''

OS=$(uname -s)
LOG=$(mktemp) || exit 1
ERR=$(mktemp) || exit 1
trap 'rm -f "$LOG" "$ERR"' EXIT
BLOCK_STATE='not_requested'

# One home directory per line: real users plus root.
homes() {
    if [ "$OS" = "Darwin" ]; then
        for h in "$ROOT"/Users/*; do
            [ -d "$h" ] && [ "${h##*/}" != "Shared" ] && printf '%s\n' "$h"
        done
        [ -d "$ROOT/var/root" ] && printf '%s\n' "$ROOT/var/root"
    else
        awk -F: '($3 >= 1000 || $3 == 0) && $6 != "" {print $6}' "$ROOT/etc/passwd" | sort -u |
            while IFS= read -r h; do
                [ -d "$ROOT$h" ] && printf '%s\n' "$ROOT$h"
            done
    fi
}

# Chromium-family data roots for EXT_STORE, relative to a home directory.
chromium_roots() {
    if [ "$OS" = "Darwin" ]; then
        p='Library/Application Support'
        case "$EXT_STORE" in
        chrome) printf '%s\n' "$p/Google/Chrome" "$p/Google/Chrome Beta" "$p/Google/Chrome Dev" "$p/Google/Chrome Canary" ;;
        edge) printf '%s\n' "$p/Microsoft Edge" "$p/Microsoft Edge Beta" "$p/Microsoft Edge Dev" "$p/Microsoft Edge Canary" ;;
        brave) printf '%s\n' "$p/BraveSoftware/Brave-Browser" "$p/BraveSoftware/Brave-Browser-Beta" "$p/BraveSoftware/Brave-Browser-Nightly" ;;
        chromium) printf '%s\n' "$p/Chromium" ;;
        opera) printf '%s\n' "$p/com.operasoftware.Opera" "$p/com.operasoftware.OperaGX" ;;
        vivaldi) printf '%s\n' "$p/Vivaldi" ;;
        esac
    else
        case "$EXT_STORE" in
        chrome) printf '%s\n' .config/google-chrome .config/google-chrome-beta .config/google-chrome-unstable ;;
        edge) printf '%s\n' .config/microsoft-edge .config/microsoft-edge-beta .config/microsoft-edge-dev ;;
        brave) printf '%s\n' .config/BraveSoftware/Brave-Browser .config/BraveSoftware/Brave-Browser-Beta .config/BraveSoftware/Brave-Browser-Nightly ;;
        chromium) printf '%s\n' .config/chromium snap/chromium/common/chromium ;;
        opera) printf '%s\n' .config/opera ;;
        vivaldi) printf '%s\n' .config/vivaldi ;;
        esac
    fi
}

# Firefox profile parents, relative to a home directory.
firefox_roots() {
    if [ "$OS" = "Darwin" ]; then
        printf '%s\n' 'Library/Application Support/Firefox/Profiles'
    else
        printf '%s\n' .mozilla/firefox snap/firefox/common/.mozilla/firefox
    fi
}

# These folders belong to users and this script runs as root, so a planted
# link must never steer a delete. True when no directory between home ($1) and
# the target ($2) is a symbolic link.
no_link_parents() {
    p=$(dirname "$2")
    while [ "$p" != "$1" ] && [ "$p" != "/" ] && [ "$p" != "." ]; do
        [ -L "$p" ] && return 1
        p=$(dirname "$p")
    done
    return 0
}

# remove_path HOME TARGET. A target that is itself a link is unlinked, never
# followed; rm -rf does not follow links inside the tree.
remove_path() {
    [ -e "$2" ] || [ -L "$2" ] || return 0
    if ! no_link_parents "$1" "$2"; then
        echo "skipped (symbolic link in path): $2"
        return 0
    fi
    set -- "$2"
    if [ -L "$1" ]; then
        rm -f -- "$1" && printf '%s\n' "$1" >>"$LOG" && echo "removed link: $1" && return 0
        printf '%s\n' "$1" >>"$ERR"
        echo "FAILED to remove: $1"
        return 0
    fi
    if rm -rf -- "$1"; then
        printf '%s\n' "$1" >>"$LOG"
        echo "removed: $1"
    else
        printf '%s\n' "$1" >>"$ERR"
        echo "FAILED to remove: $1"
    fi
}

remove_chromium() {
    homes | while IFS= read -r home; do
        chromium_roots | while IFS= read -r rel; do
            base="$home/$rel"
            [ -d "$base" ] && [ ! -L "$base" ] || continue
            # Every profile (Default, Profile 1, ...) plus a profile-less root.
            for dir in "$base"/*/Extensions/"$EXT_ID" "$base"/Extensions/"$EXT_ID"; do
                remove_path "$home" "$dir"
            done
        done
    done
}

remove_firefox() {
    homes | while IFS= read -r home; do
        firefox_roots | while IFS= read -r rel; do
            for prof in "$home/$rel"/*; do
                [ -d "$prof/extensions" ] || continue
                remove_path "$home" "$prof/extensions/$EXT_ID.xpi"
                remove_path "$home" "$prof/extensions/$EXT_ID"
            done
        done
    done
}

# Linux managed-policy directories for EXT_STORE.
chromium_policy_dirs() {
    case "$EXT_STORE" in
    chrome) printf '%s\n' /etc/opt/chrome/policies/managed ;;
    edge) printf '%s\n' /etc/opt/edge/policies/managed ;;
    brave) printf '%s\n' /etc/brave/policies/managed ;;
    chromium)
        printf '%s\n' /etc/chromium/policies/managed
        [ -d "$ROOT/etc/chromium-browser" ] && printf '%s\n' /etc/chromium-browser/policies/managed
        ;;
    esac
}

# Chromium reads every *.json in the managed directory, but the same policy in
# two files is undefined, so all removed IDs live in one file this script owns
# and nothing is written when another file already sets ExtensionSettings.
block_chromium() {
    dirs=$(chromium_policy_dirs)
    if [ -z "$dirs" ]; then
        BLOCK_STATE="unsupported_store"
        return
    fi
    BLOCK_STATE='written'
    for d in $dirs; do
        dir="$ROOT$d"
        own="$dir/fleet-hound-removed-extensions.json"
        mkdir -p "$dir" || { BLOCK_STATE='failed'; continue; }
        other=$(grep -l '"ExtensionSettings"' "$dir"/*.json 2>/dev/null | grep -v -F "$own" | head -n 1)
        if [ -n "$other" ]; then
            echo "block skipped: $other already sets ExtensionSettings; add $EXT_ID there"
            BLOCK_STATE='skipped_existing_policy'
            continue
        fi
        ids=$({ [ -f "$own" ] && grep -o '[a-p]\{32\}' "$own"; printf '%s\n' "$EXT_ID"; } | sort -u)
        {
            printf '{"ExtensionSettings":{'
            sep=''
            for id in $ids; do
                printf '%s"%s":{"installation_mode":"removed"}' "$sep" "$id"
                sep=','
            done
            printf '}}\n'
        } >"$own.tmp" && chmod 644 "$own.tmp" && mv "$own.tmp" "$own" || { BLOCK_STATE='failed'; continue; }
        echo "policy written: $own"
    done
}

# Firefox has one policies.json. A missing file is created; an existing one is
# merged with python3, and left alone when python3 is absent.
block_firefox() {
    dir="$ROOT/etc/firefox/policies"
    file="$dir/policies.json"
    mkdir -p "$dir" || { BLOCK_STATE='failed'; return; }
    if [ ! -f "$file" ]; then
        printf '{"policies":{"ExtensionSettings":{"%s":{"installation_mode":"blocked"}}}}\n' "$EXT_ID" >"$file" &&
            chmod 644 "$file" && BLOCK_STATE='written' || BLOCK_STATE='failed'
    elif command -v python3 >/dev/null 2>&1; then
        python3 - "$file" "$EXT_ID" <<'PY' && BLOCK_STATE='written' || BLOCK_STATE='failed'
import json, os, sys
path, ext = sys.argv[1], sys.argv[2]
with open(path) as f:
    doc = json.load(f)
if not isinstance(doc, dict):
    sys.exit("policies.json is not a JSON object")
settings = doc.setdefault("policies", {}).setdefault("ExtensionSettings", {})
settings[ext] = {"installation_mode": "blocked"}
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(doc, f, indent=2)
os.chmod(tmp, 0o644)
os.replace(tmp, path)
PY
    else
        echo "block skipped: $file exists and python3 is not available to merge it"
        BLOCK_STATE='skipped_existing_policy'
        return
    fi
    [ "$BLOCK_STATE" = 'written' ] && echo "policy written: $file"
}

case "$EXT_STORE" in
firefox) remove_firefox ;;
chrome | edge | brave | chromium | opera | vivaldi) remove_chromium ;;
*)
    echo "FH_RESULT=error"
    echo "unsupported store: $EXT_STORE"
    exit 2
    ;;
esac

if [ "$BLOCK" = "1" ]; then
    if [ "$OS" = "Darwin" ]; then
        # A mandatory browser policy on macOS needs a configuration profile.
        BLOCK_STATE='unsupported_on_macos'
    elif [ "$EXT_STORE" = "firefox" ]; then
        block_firefox
    else
        block_chromium
    fi
fi

removed=$(wc -l <"$LOG" | tr -d ' ')
failed=$(wc -l <"$ERR" | tr -d ' ')
echo "FH_REMOVED=$removed"
echo "FH_BLOCK=$BLOCK_STATE"
if [ "$failed" -gt 0 ]; then
    echo "FH_RESULT=error"
    exit 1
fi
if [ "$removed" -gt 0 ]; then
    echo "FH_RESULT=removed"
else
    echo "FH_RESULT=not_found"
fi
exit 0
