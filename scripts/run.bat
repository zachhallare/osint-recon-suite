@echo off
:: =============================================================================
::  scripts\run.bat — OSINT Recon Suite bootstrap launcher (Windows)
:: =============================================================================
::
::  Usage (double-click in Explorer, or run from CMD / PowerShell):
::    scripts\run.bat                        — interactive prompts
::    scripts\run.bat example.com            — live scan
::    scripts\run.bat example.com --mock     — mock mode (no network calls)
::    scripts\run.bat example.com --no-confirm
::
:: =============================================================================
setlocal EnableDelayedExpansion

:: ── Locate repo root (one level above this script) ───────────────────────────
cd /d "%~dp0.."
set "REPO_DIR=%CD%"

echo.
echo  ================================================
echo    OSINT Recon Suite  ^|  Windows Launcher
echo  ================================================
echo.

:: ── Python detection ──────────────────────────────────────────────────────────
set "PYTHON="
for %%C in (python python3) do (
    if "!PYTHON!"=="" (
        where %%C >nul 2>&1
        if !errorlevel! == 0 (
            for /f "delims=" %%V in ('%%C -c "import sys; print(sys.version_info.major)" 2^>nul') do set "PY_MAJOR=%%V"
            for /f "delims=" %%V in ('%%C -c "import sys; print(sys.version_info.minor)" 2^>nul') do set "PY_MINOR=%%V"
            if !PY_MAJOR! GEQ 3 (
                if !PY_MINOR! GEQ 11 (
                    set "PYTHON=%%C"
                )
            )
        )
    )
)

if "!PYTHON!"=="" (
    echo  [ERROR] Python 3.11 or higher is required but was not found.
    echo.
    echo  Install Python from:  https://www.python.org/downloads/
    echo  Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

for /f "delims=" %%V in ('!PYTHON! --version 2^>^&1') do echo  [+] Using !PYTHON!: %%V

:: ── Virtual environment ───────────────────────────────────────────────────────
set "VENV_DIR=!REPO_DIR!\venv"

if not exist "!VENV_DIR!\" (
    echo  [->] Creating virtual environment at venv\ ...
    !PYTHON! -m venv "!VENV_DIR!"
    if !errorlevel! neq 0 (
        echo  [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo  [+] Virtual environment created.
) else (
    echo  [+] Virtual environment already exists — skipping creation.
)

:: ── Activate venv ─────────────────────────────────────────────────────────────
call "!VENV_DIR!\Scripts\activate.bat"
if !errorlevel! neq 0 (
    echo  [ERROR] Failed to activate virtual environment.
    pause
    exit /b 1
)

:: ── Install / update dependencies ────────────────────────────────────────────
set "STAMP_FILE=!VENV_DIR!\.install_stamp"
set "REQ_FILE=!REPO_DIR!\requirements.txt"
set "NEEDS_INSTALL=0"

if not exist "!STAMP_FILE!" set "NEEDS_INSTALL=1"

if "!NEEDS_INSTALL!"=="1" (
    echo  [->] Installing dependencies from requirements.txt ...
    pip install --upgrade pip --quiet
    pip install -r "!REQ_FILE!" --quiet
    if !errorlevel! neq 0 (
        echo  [ERROR] pip install failed. Check your network connection.
        pause
        exit /b 1
    )
    type nul > "!STAMP_FILE!"
    echo  [+] Dependencies installed successfully.
) else (
    echo  [+] Dependencies are up to date.
)

echo.

:: ── Ensure data\ and reports\ exist ──────────────────────────────────────────
if not exist "!REPO_DIR!\data\" mkdir "!REPO_DIR!\data"
if not exist "!REPO_DIR!\reports\" mkdir "!REPO_DIR!\reports"

:: ── Argument handling / interactive prompt ────────────────────────────────────
set "USER_ARGS=%*"

if "!USER_ARGS!"=="" (
    echo  No arguments detected. Entering interactive setup.
    echo.

    :ask_target
    set "TARGET="
    set /p "TARGET=  Enter the target domain to scan (e.g. example.com): "
    if "!TARGET!"=="" (
        echo  [!] Target cannot be empty.
        goto ask_target
    )

    echo.
    echo  Select scan mode:
    echo    [1] Live scan   — makes real HTTP/DNS requests (default)
    echo    [2] Mock mode   — no network calls; safe pipeline test
    echo.
    set "MODE_CHOICE=1"
    set /p "MODE_CHOICE=  Your choice [1/2, default=1]: "
    if "!MODE_CHOICE!"=="" set "MODE_CHOICE=1"

    echo.
    echo  Show interactive confirmation before scanning?
    echo    [1] Yes (default)
    echo    [2] No  — skip confirmation
    echo.
    set "CONFIRM_CHOICE=1"
    set /p "CONFIRM_CHOICE=  Your choice [1/2, default=1]: "
    if "!CONFIRM_CHOICE!"=="" set "CONFIRM_CHOICE=1"

    set "ARGS=!TARGET!"
    if "!MODE_CHOICE!"=="2" set "ARGS=!ARGS! --mock"
    if "!CONFIRM_CHOICE!"=="2" set "ARGS=!ARGS! --no-confirm"
) else (
    set "ARGS=!USER_ARGS!"
)

:: ── Launch ────────────────────────────────────────────────────────────────────
echo.
echo  [+] Launching OSINT Recon Suite ...
echo  [->] Command: python main.py !ARGS!
echo.

"!VENV_DIR!\Scripts\python.exe" "!REPO_DIR!\main.py" !ARGS!
set "EXIT_CODE=!errorlevel!"

echo.
if "!EXIT_CODE!"=="0" (
    echo  [+] Scan completed successfully.
    echo  [+] Open the generated HTML report from the reports\ folder.
) else (
    echo  [ERROR] Scan exited with code !EXIT_CODE!.
)

echo.
pause
exit /b !EXIT_CODE!
