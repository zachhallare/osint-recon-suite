@echo off
:: =============================================================================
::  scripts\uninstall.bat — OSINT Recon Suite safe uninstaller (Windows)
:: =============================================================================
::
::  MENU:
::    Option 1 — Clean scan data only (reports, DB, logs, __pycache__, caches)
::    Option 2 — Full removal (scan data + virtualenv + entire repository)
::               Requires typing YES to confirm before deleting anything.
::
:: =============================================================================
setlocal EnableDelayedExpansion

:: ── Locate repo root (one level above scripts\) ───────────────────────────────
cd /d "%~dp0.."
set "REPO_DIR=%CD%"

cls
echo.
echo  ================================================
echo    OSINT Recon Suite  ^|  Uninstaller
echo  ================================================
echo.
echo  Repository path: !REPO_DIR!
echo.
echo  Choose an option:
echo.
echo    [1]  Clean scan data only
echo         Removes: HTML reports, SQLite database, log files,
echo                  __pycache__, .pytest_cache, and downloaded cache.
echo         Keeps:   source code, virtual environment, requirements.txt.
echo.
echo    [2]  Full removal (uninstall everything)
echo         Removes: all of the above PLUS the virtual environment
echo                  and the ENTIRE repository directory.
echo         WARNING: This action is IRREVERSIBLE.
echo.
echo    [Q]  Quit -- make no changes
echo.
set "CHOICE="
set /p "CHOICE=  Your choice [1 / 2 / Q]: "
echo.

if /i "!CHOICE!"=="1" goto :opt_clean
if /i "!CHOICE!"=="2" goto :opt_full
if /i "!CHOICE!"=="q" goto :opt_quit
if    "!CHOICE!"==""  goto :opt_quit
echo  [ERROR] Invalid choice. Please re-run and enter 1, 2, or Q.
pause
exit /b 1

:: =============================================================================
:opt_clean
:: =============================================================================
call :clean_scan_data
echo.
echo  [OK] Scan data cleaned. Source code and virtual environment are intact.
echo.
pause
exit /b 0

:: =============================================================================
:opt_full
:: =============================================================================
echo.
echo  ================================================
echo    WARNING: FULL REMOVAL
echo  ================================================
echo.
echo  This will permanently delete:
echo    * All scan reports, database, and logs
echo    * The Python virtual environment (venv\)
echo    * The entire repository directory:
echo        !REPO_DIR!
echo.
echo  This action CANNOT be undone.
echo.
set "CONFIRM="
set /p "CONFIRM=  Type YES (in full) to confirm, or anything else to abort: "
echo.

if /i "!CONFIRM!" neq "yes" (
    echo  Aborted -- no files were deleted.
    pause
    exit /b 0
)

call :clean_scan_data

echo.
echo  [->] Removing virtual environment ...
if exist "!REPO_DIR!\venv\" (
    rmdir /s /q "!REPO_DIR!\venv"
    echo  [-] Removed: venv\
) else (
    echo  [+] venv\ -- nothing to remove.
)

echo.
echo  [->] Removing repository directory ...
call deactivate 2>nul || true

for %%F in ("!REPO_DIR!") do set "PARENT=%%~dpF"
set "PARENT=!PARENT:~0,-1!"
for %%F in ("!REPO_DIR!") do set "REPO_FOLDER=%%~nxF"

cd /d "!PARENT!"
rmdir /s /q "!REPO_DIR!" 2>nul
if !errorlevel! neq 0 (
    echo  [!] Could not remove the directory. Close any open files and try again.
    pause
    exit /b 1
)
echo  [-] Removed: !REPO_DIR!
echo.
echo  [OK] OSINT Recon Suite has been completely removed.
echo.
echo  To reinstall:
echo    git clone https://github.com/zachhallare/osint-recon-suite.git
echo.
pause
exit /b 0

:: =============================================================================
:opt_quit
:: =============================================================================
echo  No changes made. Exiting.
pause
exit /b 0

:: =============================================================================
:: Subroutine: clean_scan_data
:: =============================================================================
:clean_scan_data
echo  [->] Cleaning scan data ...
echo.

if exist "!REPO_DIR!\reports\*.html" (
    del /q "!REPO_DIR!\reports\*.html"
    echo  [-] Removed: reports\*.html
) else (
    echo  [+] reports\*.html -- nothing to remove.
)

set "DB_REMOVED=0"
for %%F in ("!REPO_DIR!\data\osint.db" "!REPO_DIR!\data\osint.db-wal" "!REPO_DIR!\data\osint.db-shm") do (
    if exist "%%F" (
        del /q "%%F"
        echo  [-] Removed: %%F
        set "DB_REMOVED=1"
    )
)
if "!DB_REMOVED!"=="0" echo  [+] data\osint.db* -- nothing to remove.

if exist "!REPO_DIR!\osint_recon.log" (
    del /q "!REPO_DIR!\osint_recon.log"
    echo  [-] Removed: osint_recon.log
) else (
    echo  [+] osint_recon.log -- nothing to remove.
)

if exist "!REPO_DIR!\.env" (
    echo.
    echo  [!] .env file detected (may contain API keys).
    set "RM_ENV="
    set /p "RM_ENV=  Remove .env as well? [y/N]: "
    if /i "!RM_ENV!"=="y" (
        del /q "!REPO_DIR!\.env"
        echo  [-] Removed: .env
    ) else (
        echo  [+] .env kept.
    )
)

set "CACHE_COUNT=0"
for /r "!REPO_DIR!" %%D in (.) do (
    if exist "%%D\__pycache__\" (
        rmdir /s /q "%%D\__pycache__" 2>nul
        set /a CACHE_COUNT+=1
    )
)
if !CACHE_COUNT! gtr 0 (
    echo  [-] Removed !CACHE_COUNT! __pycache__ director(ies).
) else (
    echo  [+] __pycache__ -- nothing to remove.
)

if exist "!REPO_DIR!\.pytest_cache\" (
    rmdir /s /q "!REPO_DIR!\.pytest_cache"
    echo  [-] Removed: .pytest_cache\
) else (
    echo  [+] .pytest_cache\ -- nothing to remove.
)

if exist "!REPO_DIR!\venv\.install_stamp" (
    del /q "!REPO_DIR!\venv\.install_stamp"
)

goto :eof
