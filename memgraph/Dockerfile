# Memgraph 3.14.0 (newest release on 2026-10-27), pinned by digest, with the
# Python packages its MAGE query modules use patched where upstream lags.
# The engine is unchanged, so the existing memgraph-data volume stays valid.
# Drop a pin below once a Memgraph release ships that version or newer.
FROM memgraph/memgraph:3.14.0@sha256:a732421217951066e42f5749111bc3d0c7b51b12c756be04850d4dafa84cc05e

# certifi 2026.7.22 trusts emSign roots whose intermediate CA keys were
# compromised (GHSA-6q48-6c7w-9gw2, CRITICAL). 2026.10.23 matches the webviz
# lock. --break-system-packages: Ubuntu 24.04 (PEP 668) refuses --user
# installs without it; this touches only the memgraph user's site-packages.
RUN python3 -m pip install --user --no-cache-dir --no-deps --break-system-packages \
        certifi==2026.10.23 \
 && python3 -c "import certifi; assert certifi.__version__ == '2026.10.23', certifi.__version__"
