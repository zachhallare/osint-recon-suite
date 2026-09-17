#!/usr/bin/env bash
# Run the suite on Linux or macOS.
# Examples:
#   ./scripts/run.sh
#   ./scripts/run.sh example.com
#   ./scripts/run.sh example.com --mock
#   ./scripts/run.sh example.com --no-confirm

set -euo pipefail

RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

banner() {
    echo ""
    echo -e "${CYN}${BLD}OSINT Recon Suite${RST}"
    echo ""
}

info()  { echo -e "  ${GRN}[+]${RST} $*"; }
warn()  { echo -e "  ${YLW}[!]${RST} $*"; }
error() { echo -e "  ${RED}[x]${RST} $*" >&2; }
step()  { echo -e "  ${CYN}[>]${RST} $*"; }

# Go to repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

banner

# Find Python 3.11 or newer
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
    echo "  Install Python 3.11+ from https://www.python.org/downloads/"
    echo "  Or via your package manager:"
    echo "    Debian/Ubuntu/Kali:  sudo apt install python3"
    echo "    macOS (Homebrew):    brew install python"
    echo ""
    exit 1
fi

info "Using Python: $("$PYTHON" --version)"

# Set up virtual environment
VENV_DIR="$REPO_DIR/venv"

if [[ ! -d "$VENV_DIR" ]]; then
    step "Creating virtual environment at venv/ ..."
    "$PYTHON" -m venv "$VENV_DIR"
    info "Virtual environment created."
else
    info "Virtual environment already exists, skipping creation."
fi

# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

# Install or update dependencies
STAMP_FILE="$VENV_DIR/.install_stamp"
REQ_FILE="$REPO_DIR/requirements.txt"

needs_install=0
[[ ! -f "$STAMP_FILE" ]] && needs_install=1
if [[ "$REQ_FILE" -nt "$STAMP_FILE" ]]; then
    warn "requirements.txt changed, reinstalling ..."
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
mkdir -p "$REPO_DIR/data" "$REPO_DIR/reports"

# Prompt for inputs if no arguments were passed
if [[ $# -eq 0 ]]; then
    echo -e "${BLD}  No arguments detected. Entering interactive setup.${RST}"
    echo ""

    while true; do
        read -rp "  Enter the target domain to scan (e.g. example.com): " TARGET
        TARGET="${TARGET// /}"
        [[ -n "$TARGET" ]] && break
        warn "Target cannot be empty. Please enter a domain name."
    done

    echo ""
    echo "  Select scan mode:"
    echo "    [1] Live scan      - makes real HTTP/DNS requests (default)"
    echo "    [2] Mock mode      - no network calls, safe for testing the pipeline"
    echo ""
    read -rp "  Your choice [1/2, default=1]: " MODE_CHOICE
    MODE_CHOICE="${MODE_CHOICE:-1}"

    echo ""
    echo "  Show interactive confirmation before scanning?"
    echo "    [1] Yes (default)"
    echo "    [2] No  - start immediately (scripted/automated runs)"
    echo ""
    read -rp "  Your choice [1/2, default=1]: " CONFIRM_CHOICE
    CONFIRM_CHOICE="${CONFIRM_CHOICE:-1}"

    ARGS=("$TARGET")
    [[ "$MODE_CHOICE" == "2" ]] && ARGS+=("--mock")
    [[ "$CONFIRM_CHOICE" == "2" ]] && ARGS+=("--no-confirm")
else
    ARGS=("$@")
fi

# Run the scanner
echo ""
info "Launching OSINT Recon Suite ..."
echo -e "  ${YLW}Command:${RST} python main.py ${ARGS[*]}"
echo ""

"$VENV_DIR/bin/python" "$REPO_DIR/main.py" "${ARGS[@]}"
EXIT_CODE=$?

echo ""
if [[ $EXIT_CODE -eq 0 ]]; then
    info "Scan completed successfully."
    info "Open the generated report in reports/ with your browser."
else
    error "Scan exited with code $EXIT_CODE."
fi

exit $EXIT_CODE
