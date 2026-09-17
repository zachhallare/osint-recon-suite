#!/usr/bin/env bash
# Uninstaller for OSINT Recon Suite on Linux or macOS.
# Cleans scan data or removes the repository.

set -euo pipefail

RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

info()    { echo -e "  ${GRN}[+]${RST} $*"; }
warn()    { echo -e "  ${YLW}[!]${RST} $*"; }
error()   { echo -e "  ${RED}[x]${RST} $*" >&2; }
success() { echo -e "  ${GRN}${BLD}[v]${RST} $*"; }
deleted() { echo -e "  ${RED}[-]${RST} Removed: $*"; }

# Go to repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

clear
echo ""
echo -e "${RED}${BLD}OSINT Recon Suite Uninstaller${RST}"
echo ""
echo -e "  Repository path: ${BLD}${REPO_DIR}${RST}"
echo ""
echo -e "${BLD}  Choose an option:${RST}"
echo ""
echo "  [1]  Clean scan data only"
echo "       Removes: HTML reports, SQLite database, log files, __pycache__,"
echo "       .pytest_cache, and downloaded file cache."
echo "       Keeps:   source code, virtual environment, requirements.txt."
echo ""
echo "  [2]  Full removal (uninstall everything)"
echo "       Removes: ALL of the above PLUS the virtual environment and the"
echo "       entire repository directory."
echo "       WARNING: This action is permanent."
echo ""
echo "  [q]  Quit - make no changes"
echo ""
read -rp "  Your choice [1 / 2 / q]: " CHOICE
echo ""

clean_scan_data() {
    echo -e "  ${CYN}Cleaning scan data${RST}"
    echo ""

    local removed=0

    if compgen -G "${REPO_DIR}/reports/*.html" &>/dev/null; then
        rm -f "${REPO_DIR}/reports/"*.html
        deleted "reports/*.html"
        (( removed++ )) || true
    else
        info "reports/*.html - nothing to remove."
    fi

    for f in "${REPO_DIR}/data/osint.db" \
              "${REPO_DIR}/data/osint.db-wal" \
              "${REPO_DIR}/data/osint.db-shm"; do
        if [[ -f "$f" ]]; then
            rm -f "$f"
            deleted "$f"
            (( removed++ )) || true
        fi
    done
    [[ $removed -eq 0 ]] && info "data/osint.db* - nothing to remove."

    if [[ -f "${REPO_DIR}/osint_recon.log" ]]; then
        rm -f "${REPO_DIR}/osint_recon.log"
        deleted "osint_recon.log"
    else
        info "osint_recon.log - nothing to remove."
    fi

    if [[ -f "${REPO_DIR}/.env" ]]; then
        warn ".env file detected (may contain API keys)."
        read -rp "  Remove .env as well? [y/N]: " RM_ENV
        if [[ "${RM_ENV,,}" == "y" ]]; then
            rm -f "${REPO_DIR}/.env"
            deleted ".env"
        else
            info ".env kept."
        fi
    fi

    local cache_count
    cache_count=$(find "${REPO_DIR}" -type d -name "__pycache__" | wc -l)
    if [[ "$cache_count" -gt 0 ]]; then
        find "${REPO_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
        deleted "__pycache__ directories ($cache_count found)"
    else
        info "__pycache__ - nothing to remove."
    fi

    if [[ -d "${REPO_DIR}/.pytest_cache" ]]; then
        rm -rf "${REPO_DIR}/.pytest_cache"
        deleted ".pytest_cache/"
    else
        info ".pytest_cache - nothing to remove."
    fi

    [[ -f "${REPO_DIR}/venv/.install_stamp" ]] && rm -f "${REPO_DIR}/venv/.install_stamp"

    echo ""
    success "Scan data cleaned. Source code and virtual environment are intact."
}

full_removal() {
    echo ""
    echo -e "${RED}${BLD}  FULL REMOVAL WARNING  ${RST}"
    echo ""
    echo "  This will permanently delete:"
    echo "    * All scan reports, database, and logs"
    echo "    * The Python virtual environment (venv/)"
    echo "    * The entire repository directory:"
    echo -e "      ${BLD}${REPO_DIR}${RST}"
    echo ""
    echo -e "  ${YLW}Type exactly  yes  and press Enter to confirm:${RST}"
    read -rp "  Confirmation: " CONFIRM

    if [[ "$CONFIRM" != "yes" ]]; then
        echo ""
        warn "Aborted - no files were deleted."
        exit 0
    fi

    echo ""
    [[ -n "${VIRTUAL_ENV:-}" ]] && { info "Deactivating venv ..."; deactivate 2>/dev/null || true; }

    clean_scan_data

    echo ""
    echo -e "  ${CYN}Removing virtual environment${RST}"
    echo ""
    if [[ -d "${REPO_DIR}/venv" ]]; then
        rm -rf "${REPO_DIR}/venv"
        deleted "venv/"
    else
        info "venv/ - nothing to remove."
    fi

    echo ""
    echo -e "  ${CYN}Removing repository directory${RST}"
    echo ""
    PARENT_DIR="$(dirname "${REPO_DIR}")"
    REPO_NAME="$(basename "${REPO_DIR}")"
    info "Navigating to: $PARENT_DIR"
    cd "$PARENT_DIR"
    info "Deleting: $REPO_NAME"
    rm -rf "$REPO_NAME"

    echo ""
    success "OSINT Recon Suite has been completely removed."
    echo ""
    info "Reinstall at any time:"
    echo "    git clone https://github.com/zachhallare/osint-recon-suite.git"
    echo ""
}
case "${CHOICE,,}" in
    1)  clean_scan_data ;;
    2)  full_removal ;;
    q|"")
        info "No changes made. Exiting."
        exit 0
        ;;
    *)
        error "Invalid choice: '$CHOICE'. Please enter 1, 2, or q."
        exit 1
        ;;
esac

echo ""
exit 0
