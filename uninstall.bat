@echo off
:: =============================================================================
::  uninstall.bat — OSINT Recon Suite safe uninstaller (Windows)
:: =============================================================================
::
::  MENU:
::    Option 1 — Clean scan data only
::               Removes: HTML reports, SQLite database, log files, __pycache__,
::                        .pytest_cache, downloaded file cache.
::               Keeps:   source code, virtual environment, requirements.txt.
::
::    Option 2 — Full removal (uninstall everything)
::               Removes: ALL of the above PLUS the virtual environment and the
::               entire repository directory.
::               Requires typed confirmation before deleting.
::
::  SAFETY:
::    - All paths are qualified with the script directory; no wildcard root ops.
::    - Option 2 requires you to type YES (case-insensitive) to proceed.
::    - The script confirms the directory path before any destructive action.
::
:: =============================================================================
setlocal EnableDelayedExpansion

:: Change to the directory containing uninstall.bat
cd /d "%~dp0"
set "REPO_DIR=%~dp0"
:: Strip trailing backslash for clean display
set "REPO_DIR_CLEAN=%REPO_DIR:~0,-1%"

cls
echo.
echo  ================================================
echo    OSINT Recon Suite  ^|  Uninstaller
echo  ================================================
echo.
echo  Repository path: %REPO_DIR_CLEAN%
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

:: Normalise to uppercase for comparison
for %%C in (!CHOICE!) do set "CHOICE_UPPER=%%C"
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
echo        %REPO_DIR_CLEAN%
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

:: Step 1 — clean scan data
call :clean_scan_data

:: Step 2 — remove virtual environment
echo.
echo  [->] Removing virtual environment ...
if exist "%REPO_DIR%venv\" (
    rmdir /s /q "%REPO_DIR%venv"
    echo  [-] Removed: venv\
) else (
    echo  [+] venv\ -- nothing to remove.
)

:: Step 3 — remove the repository directory
echo.
echo  [->] Removing repository directory ...

:: Deactivate if inside a venv (ignore errors)
call deactivate 2>nul || true

:: Navigate to parent
set "PARENT=%REPO_DIR_CLEAN%"
for %%F in ("!PARENT!") do set "PARENT=%%~dpF"
set "PARENT=!PARENT:~0,-1!"

:: Get the folder name only
for %%F in ("!REPO_DIR_CLEAN!") do set "REPO_FOLDER=%%~nxF"

cd /d "!PARENT!"
rmdir /s /q "!REPO_DIR_CLEAN!" 2>nul
if !errorlevel! neq 0 (
    echo  [!] Could not remove the directory while a file inside it is in use.
    echo      Close any open files or applications referencing the folder and try again.
    pause
    exit /b 1
)
echo  [-] Removed: !REPO_DIR_CLEAN!
echo.
echo  [OK] OSINT Recon Suite has been completely removed from this system.
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

:: HTML reports
if exist "%REPO_DIR%reports\*.html" (
    del /q "%REPO_DIR%reports\*.html"
    echo  [-] Removed: reports\*.html
) else (
    echo  [+] reports\*.html -- nothing to remove.
)

:: SQLite database and WAL / SHM files
set "DB_REMOVED=0"
for %%F in ("%REPO_DIR%data\osint.db" "%REPO_DIR%data\osint.db-wal" "%REPO_DIR%data\osint.db-shm") do (
    if exist "%%F" (
        del /q "%%F"
        echo  [-] Removed: %%F
        set "DB_REMOVED=1"
    )
)
if "!DB_REMOVED!"=="0" echo  [+] data\osint.db* -- nothing to remove.

:: Runtime log
if exist "%REPO_DIR%osint_recon.log" (
    del /q "%REPO_DIR%osint_recon.log"
    echo  [-] Removed: osint_recon.log
) else (
    echo  [+] osint_recon.log -- nothing to remove.
)

:: .env file (ask)
if exist "%REPO_DIR%.env" (
    echo.
    echo  [!] .env file detected (may contain API keys).
    set "RM_ENV="
    set /p "RM_ENV=  Remove .env as well? [y/N]: "
    if /i "!RM_ENV!"=="y" (
        del /q "%REPO_DIR%.env"
        echo  [-] Removed: .env
    ) else (
        echo  [+] .env kept.
    )
)

:: __pycache__ directories (recursive)
set "CACHE_COUNT=0"
for /r "%REPO_DIR%" %%D in (.) do (
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

:: pytest cache
if exist "%REPO_DIR%.pytest_cache\" (
    rmdir /s /q "%REPO_DIR%.pytest_cache"
    echo  [-] Removed: .pytest_cache\
) else (
    echo  [+] .pytest_cache\ -- nothing to remove.
)

:: venv install stamp (so next run.bat reinstalls fresh)
if exist "%REPO_DIR%venv\.install_stamp" (
    del /q "%REPO_DIR%venv\.install_stamp"
)

goto :eof
