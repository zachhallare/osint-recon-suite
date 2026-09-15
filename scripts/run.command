#!/usr/bin/env bash
# =============================================================================
#  scripts/run.command — OSINT Recon Suite macOS Finder double-click launcher
# =============================================================================
#
#  HOW TO USE:
#    Open Finder, navigate to osint-recon-suite/scripts/, and double-click
#    run.command. Terminal opens automatically and walks you through setup.
#
#  FIRST-TIME SETUP (one-time only):
#    chmod +x scripts/run.command scripts/run.sh scripts/uninstall.sh scripts/uninstall.command
#
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

info()  { echo -e "  ${GRN}[+]${RST} $*"; }
warn()  { echo -e "  ${YLW}[!]${RST} $*"; }
error() { echo -e "  ${RED}[✗]${RST} $*" >&2; }
step()  { echo -e "  ${CYN}[→]${RST} $*"; }

# ── Locate repo root (one level above scripts/) ───────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

clear
echo ""
echo -e "${CYN}${BLD}╔══════════════════════════════════════════════════════╗${RST}"
echo -e "${CYN}${BLD}║       OSINT Recon Suite  — macOS Launcher            ║${RST}"
echo -e "${CYN}${BLD}╚══════════════════════════════════════════════════════╝${RST}"
echo ""
info "Repository: $REPO_DIR"
echo ""

# ── Python detection ──────────────────────────────────────────────────────────
PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        MAJOR=$("$candidate" -c "import sys; print(sys.version_info.major)" 2>/dev/null || true)
        MINOR=$("$candidate" -c "import sys; print(sys.version_info.minor)" 2>/dev/null || true)
        if [[ "$MAJOR" -ge 3 && "$MINOR" -ge 11 ]]; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    error "Python 3.11 or higher is required but was not found."
    echo ""
    echo "  Install Python from https://www.python.org/downloads/"
    echo "  Or with Homebrew:  brew install python"
    echo ""
    echo "  Press Enter to close this window."
    read -r
    exit 1
fi

info "Python: $("$PYTHON" --version)"

# ── Virtual environment ───────────────────────────────────────────────────────
VENV_DIR="$REPO_DIR/venv"

if [[ ! -d "$VENV_DIR" ]]; then
    step "Creating virtual environment at venv/ ..."
    "$PYTHON" -m venv "$VENV_DIR"
    info "Virtual environment created."
else
    info "Virtual environment found — skipping creation."
fi

# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

# ── Install / update dependencies ────────────────────────────────────────────
STAMP_FILE="$VENV_DIR/.install_stamp"
REQ_FILE="$REPO_DIR/requirements.txt"

if [[ ! -f "$STAMP_FILE" ]] || [[ "$REQ_FILE" -nt "$STAMP_FILE" ]]; then
    step "Installing / updating dependencies ..."
    pip install --upgrade pip --quiet
    pip install -r "$REQ_FILE" --quiet
    touch "$STAMP_FILE"
    info "Dependencies installed."
else
    info "Dependencies are up to date."
fi

echo ""
mkdir -p "$REPO_DIR/data" "$REPO_DIR/reports"

# ── Interactive prompts ───────────────────────────────────────────────────────
echo -e "${BLD}  -- Scan Configuration ----------------------------------------${RST}"
echo ""

while true; do
    read -rp "  Enter the target domain (e.g. example.com): " TARGET
    TARGET="${TARGET// /}"
    [[ -n "$TARGET" ]] && break
    warn "Domain cannot be empty. Please try again."
done

echo ""
echo "  Select scan mode:"
echo "    [1] Live scan   — real HTTP/DNS requests (default)"
echo "    [2] Mock mode   — no network calls; pipeline test only"
echo ""
read -rp "  Your choice [1/2, default=1]: " MODE_CHOICE
MODE_CHOICE="${MODE_CHOICE:-1}"

echo ""
echo "  Show interactive confirmation before scanning?"
echo "    [1] Yes (recommended, default)"
echo "    [2] No  — start immediately"
echo ""
read -rp "  Your choice [1/2, default=1]: " CONFIRM_CHOICE
CONFIRM_CHOICE="${CONFIRM_CHOICE:-1}"

ARGS=("$TARGET")
[[ "$MODE_CHOICE" == "2" ]] && ARGS+=("--mock")
[[ "$CONFIRM_CHOICE" == "2" ]] && ARGS+=("--no-confirm")

# ── Launch ────────────────────────────────────────────────────────────────────
echo ""
info "Running: python main.py ${ARGS[*]}"
echo ""

"$PYTHON" "$REPO_DIR/main.py" "${ARGS[@]}"
EXIT_CODE=$?

echo ""
if [[ $EXIT_CODE -eq 0 ]]; then
    info "Scan complete! Open the report from the reports/ folder."
    info "Tip:  open $REPO_DIR/reports/*.html"
else
    error "Scan exited with code $EXIT_CODE."
fi

echo ""
echo "  Press Enter to close this Terminal window."
read -r
exit $EXIT_CODE
