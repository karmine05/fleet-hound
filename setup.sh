#!/usr/bin/env bash
# Fleet Hound setup script.
#
# Creates a virtual environment and installs Python dependencies.
#
# Usage:
#   ./setup.sh              # create venv + install deps
#   ./setup.sh --recreate   # remove existing venv and recreate

set -euo pipefail

cd "$(dirname "$0")"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}ℹ️  $*${NC}"; }
ok()    { echo -e "${GREEN}✅ $*${NC}"; }
warn()  { echo -e "${YELLOW}⚠️  $*${NC}"; }
fail()  { echo -e "${RED}❌ $*${NC}"; }

echo "🩸 Fleet Hound Setup"
echo "=============================================="

# Check Python
if ! command -v python3 &>/dev/null; then
    fail "Python 3 is not installed."; exit 1
fi
info "Python $(python3 --version) found"

# Handle --recreate
if [[ "${1:-}" == "--recreate" ]]; then
    if [[ -d venv ]]; then
        info "Removing existing venv..."
        rm -rf venv
        ok "Removed venv"
    fi
fi

# Create venv if not exists
if [[ ! -d venv ]]; then
    info "Creating virtual environment..."
    python3 -m venv venv
    ok "Virtual environment created"
else
    info "Virtual environment exists"
fi

# Activate and install
info "Activating virtual environment..."
source venv/bin/activate

info "Installing dependencies from requirements.txt..."
if [[ ! -f requirements.txt ]]; then
    fail "requirements.txt not found"
fi

pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt

ok "Dependencies installed"

echo
echo "=============================================="
ok "Setup complete!"
echo "=============================================="
echo "To activate the virtual environment:"
echo "  source venv/bin/activate  # macOS/Linux"
echo "  venv\\Scripts\\activate     # Windows"
echo
echo "Then run:"
echo "  ./start.sh"
echo "  python3 main.py --full-scan"
echo
