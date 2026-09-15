#!/usr/bin/env bash
# =============================================================================
#  uninstall.sh — OSINT Recon Suite safe uninstaller (Linux / macOS)
# =============================================================================
#
#  MENU:
#    Option 1 — Clean scan data only (reports, database, logs, caches)
#               The application and its dependencies remain intact.
#
#    Option 2 — Full removal (scan data + virtualenv + entire repository)
#               Leaves nothing behind on the filesystem.
#
#  SAFETY GUARANTEES:
#    - Confirms the repository path before any deletion.
#    - Option 2 requires explicit typed confirmation ("yes") before removing
#      the repository directory.
#    - All rm operations are path-qualified; no $HOME or / wildcards used.
#    - Script exits immediately on any unexpected error (set -euo pipefail).
#
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

info()    { echo -e "  ${GRN}[+]${RST} $*"; }
warn()    { echo -e "  ${YLW}[!]${RST} $*"; }
error()   { echo -e "  ${RED}[✗]${RST} $*" >&2; }
success() { echo -e "  ${GRN}${BLD}[✓]${RST} $*"; }
deleted() { echo -e "  ${RED}[-]${RST} Removed: $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

clear
echo ""
echo -e "${RED}${BLD}╔══════════════════════════════════════════════════════╗${RST}"
echo -e "${RED}${BLD}║       OSINT Recon Suite  — Uninstaller               ║${RST}"
echo -e "${RED}${BLD}╚══════════════════════════════════════════════════════╝${RST}"
echo ""
echo -e "  Repository path: ${BLD}${SCRIPT_DIR}${RST}"
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
echo "       ⚠  This action is IRREVERSIBLE."
echo ""
echo "  [q]  Quit — make no changes"
echo ""
read -rp "  Your choice [1 / 2 / q]: " CHOICE
echo ""

# ─────────────────────────────────────────────────────────────────────────────
clean_scan_data() {
    echo -e "  ${CYN}── Cleaning scan data ──────────────────────────────${RST}"
    echo ""

    local removed=0

    # HTML reports
    if compgen -G "${SCRIPT_DIR}/reports/*.html" &>/dev/null; then
        rm -f "${SCRIPT_DIR}/reports/"*.html
        deleted "reports/*.html"
        (( removed++ )) || true
    else
        info "reports/*.html — nothing to remove."
    fi

    # SQLite database and WAL/SHM files
    for f in "${SCRIPT_DIR}/data/osint.db" \
              "${SCRIPT_DIR}/data/osint.db-wal" \
              "${SCRIPT_DIR}/data/osint.db-shm"; do
        if [[ -f "$f" ]]; then
            rm -f "$f"
            deleted "$f"
            (( removed++ )) || true
        fi
    done
    if [[ $removed -eq 0 ]]; then
        info "data/osint.db* — nothing to remove."
    fi

    # Runtime log
    if [[ -f "${SCRIPT_DIR}/osint_recon.log" ]]; then
        rm -f "${SCRIPT_DIR}/osint_recon.log"
        deleted "osint_recon.log"
    else
        info "osint_recon.log — nothing to remove."
    fi

    # .env (optional, only if user explicitly wants it gone)
    if [[ -f "${SCRIPT_DIR}/.env" ]]; then
        warn ".env file detected (may contain API keys)."
        read -rp "  Remove .env as well? [y/N]: " RM_ENV
        if [[ "${RM_ENV,,}" == "y" ]]; then
            rm -f "${SCRIPT_DIR}/.env"
            deleted ".env"
        else
            info ".env kept."
        fi
    fi

    # __pycache__ directories
    local cache_count
    cache_count=$(find "${SCRIPT_DIR}" -type d -name "__pycache__" | wc -l)
    if [[ "$cache_count" -gt 0 ]]; then
        find "${SCRIPT_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
        deleted "__pycache__ directories ($cache_count found)"
    else
        info "__pycache__ — nothing to remove."
    fi

    # pytest cache
    if [[ -d "${SCRIPT_DIR}/.pytest_cache" ]]; then
        rm -rf "${SCRIPT_DIR}/.pytest_cache"
        deleted ".pytest_cache/"
    else
        info ".pytest_cache — nothing to remove."
    fi

    # venv install stamp (so next run.sh reinstalls fresh)
    if [[ -f "${SCRIPT_DIR}/venv/.install_stamp" ]]; then
        rm -f "${SCRIPT_DIR}/venv/.install_stamp"
        deleted "venv/.install_stamp"
    fi

    echo ""
    success "Scan data cleaned. Source code and virtual environment are intact."
}

# ─────────────────────────────────────────────────────────────────────────────
full_removal() {
    echo ""
    echo -e "${RED}${BLD}  ⚠  FULL REMOVAL WARNING  ⚠${RST}"
    echo ""
    echo "  This will permanently delete:"
    echo "    • All scan reports, database, and logs"
    echo "    • The Python virtual environment (venv/)"
    echo "    • The entire repository directory:"
    echo -e "      ${BLD}${SCRIPT_DIR}${RST}"
    echo ""
    echo "  This action CANNOT be undone."
    echo ""
    echo -e "  ${YLW}Type exactly  yes  and press Enter to confirm, or anything else to abort:${RST}"
    read -rp "  Confirmation: " CONFIRM

    if [[ "$CONFIRM" != "yes" ]]; then
        echo ""
        warn "Aborted — no files were deleted."
        exit 0
    fi

    echo ""

    # Deactivate venv if active
    if [[ -n "${VIRTUAL_ENV:-}" ]]; then
        info "Deactivating virtual environment ..."
        # shellcheck disable=SC1090
        deactivate 2>/dev/null || true
    fi

    # Step 1 — clean scan data first
    clean_scan_data

    # Step 2 — remove virtual environment
    echo ""
    echo -e "  ${CYN}── Removing virtual environment ─────────────────────${RST}"
    echo ""
    if [[ -d "${SCRIPT_DIR}/venv" ]]; then
        rm -rf "${SCRIPT_DIR}/venv"
        deleted "venv/"
    else
        info "venv/ — nothing to remove."
    fi

    # Step 3 — navigate out and remove the repository
    echo ""
    echo -e "  ${CYN}── Removing repository directory ─────────────────────${RST}"
    echo ""
    PARENT_DIR="$(dirname "${SCRIPT_DIR}")"
    REPO_NAME="$(basename "${SCRIPT_DIR}")"

    info "Navigating to parent directory: $PARENT_DIR"
    cd "$PARENT_DIR"

    info "Deleting repository: $REPO_NAME"
    rm -rf "$REPO_NAME"

    echo ""
    success "OSINT Recon Suite has been completely removed from this system."
    echo ""
    info "If you cloned from GitHub, you can reinstall at any time with:"
    echo "    git clone https://github.com/zachhallare/osint-recon-suite.git"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
case "${CHOICE,,}" in
    1)  clean_scan_data ;;
    2)  full_removal ;;
    q|"")
        info "No changes made. Exiting."
        exit 0
        ;;
    *)
        error "Invalid choice: '$CHOICE'. Please re-run and enter 1, 2, or q."
        exit 1
        ;;
esac

echo ""
exit 0
