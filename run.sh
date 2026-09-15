#!/usr/bin/env bash
# =============================================================================
#  run.sh — OSINT Recon Suite bootstrap launcher (Linux / macOS)
# =============================================================================
#
#  Usage:
#    ./run.sh                          # interactive: prompts for target & mode
#    ./run.sh example.com              # live scan with confirmation prompt
#    ./run.sh example.com --mock       # mock mode (no network calls)
#    ./run.sh example.com --no-confirm # skip confirmation prompt
#
#  The script will:
#    1. Locate the repository root (the directory containing this script)
#    2. Create a Python virtual environment (venv/) if one does not exist
#    3. Install / upgrade dependencies from requirements.txt if needed
#    4. Prompt interactively for a target and mode when no arguments are given
#    5. Launch main.py, passing through any CLI arguments you provided
#
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

banner() {
    echo ""
    echo -e "${CYN}${BLD}╔══════════════════════════════════════════════════╗${RST}"
    echo -e "${CYN}${BLD}║          OSINT Recon Suite  — run.sh             ║${RST}"
    echo -e "${CYN}${BLD}╚══════════════════════════════════════════════════╝${RST}"
    echo ""
}

info()  { echo -e "  ${GRN}[+]${RST} $*"; }
warn()  { echo -e "  ${YLW}[!]${RST} $*"; }
error() { echo -e "  ${RED}[✗]${RST} $*" >&2; }
step()  { echo -e "  ${CYN}[→]${RST} $*"; }

# ── Locate repo root ──────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

banner

# ── Python detection ──────────────────────────────────────────────────────────
PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        VER=$("$candidate" -c "import sys; print(sys.version_info[:2])" 2>/dev/null || true)
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
    echo "  Install Python 3.11+ from https://www.python.org/downloads/"
    echo "  Or via your package manager:"
    echo "    Debian/Ubuntu/Kali:  sudo apt install python3"
    echo "    macOS (Homebrew):    brew install python"
    echo ""
    exit 1
fi

info "Using Python: $("$PYTHON" --version)"

# ── Virtual environment ───────────────────────────────────────────────────────
VENV_DIR="$SCRIPT_DIR/venv"

if [[ ! -d "$VENV_DIR" ]]; then
    step "Creating virtual environment at venv/ ..."
    "$PYTHON" -m venv "$VENV_DIR"
    info "Virtual environment created."
else
    info "Virtual environment already exists — skipping creation."
fi

# Activate venv
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

# ── Install / update dependencies ────────────────────────────────────────────
STAMP_FILE="$VENV_DIR/.install_stamp"
REQ_FILE="$SCRIPT_DIR/requirements.txt"

needs_install=0

if [[ ! -f "$STAMP_FILE" ]]; then
    needs_install=1
elif [[ "$REQ_FILE" -nt "$STAMP_FILE" ]]; then
    warn "requirements.txt has changed since last install — reinstalling ..."
    needs_install=1
fi

if [[ "$needs_install" -eq 1 ]]; then
    step "Installing dependencies from requirements.txt ..."
    pip install --upgrade pip --quiet
    pip install -r "$REQ_FILE" --quiet
    touch "$STAMP_FILE"
    info "Dependencies installed."
else
    info "Dependencies are up to date."
fi

echo ""

# ── Ensure data/ and reports/ directories exist ───────────────────────────────
mkdir -p "$SCRIPT_DIR/data" "$SCRIPT_DIR/reports"

# ── Argument handling / interactive prompt ────────────────────────────────────
if [[ $# -eq 0 ]]; then
    # No arguments supplied — enter interactive mode
    echo -e "${BLD}  No arguments detected. Entering interactive setup.${RST}"
    echo ""

    # Target domain
    while true; do
        read -rp "  Enter the target domain to scan (e.g. example.com): " TARGET
        TARGET="${TARGET// /}"  # strip whitespace
        if [[ -n "$TARGET" ]]; then
            break
        fi
        warn "Target cannot be empty. Please enter a domain name."
    done

    # Scan mode
    echo ""
    echo "  Select scan mode:"
    echo "    [1] Live scan      — makes real HTTP/DNS requests (default)"
    echo "    [2] Mock mode      -- no network calls; safe for testing the pipeline"
    echo ""
    read -rp "  Your choice [1/2, default=1]: " MODE_CHOICE
    MODE_CHOICE="${MODE_CHOICE:-1}"

    # Confirmation
    echo ""
    echo "  Run confirmation prompt:"
    echo "    [1] Yes — show the interactive target confirmation before scanning (default)"
    echo "    [2] No  — skip confirmation (useful for scripted/automated runs)"
    echo ""
    read -rp "  Your choice [1/2, default=1]: " CONFIRM_CHOICE
    CONFIRM_CHOICE="${CONFIRM_CHOICE:-1}"

    # Build argument list
    ARGS=("$TARGET")
    if [[ "$MODE_CHOICE" == "2" ]]; then
        ARGS+=("--mock")
    fi
    if [[ "$CONFIRM_CHOICE" == "2" ]]; then
        ARGS+=("--no-confirm")
    fi
else
    # Arguments supplied — pass them through verbatim
    ARGS=("$@")
fi

# ── Launch ────────────────────────────────────────────────────────────────────
echo ""
info "Launching OSINT Recon Suite ..."
echo -e "  ${YLW}Command:${RST} python main.py ${ARGS[*]}"
echo ""

"$PYTHON" "$SCRIPT_DIR/main.py" "${ARGS[@]}"
EXIT_CODE=$?

echo ""
if [[ $EXIT_CODE -eq 0 ]]; then
    info "Scan completed successfully."
    info "Open the generated report in reports/ with your browser."
else
    error "Scan exited with code $EXIT_CODE."
fi

exit $EXIT_CODE
