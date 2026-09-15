@echo off
:: =============================================================================
::  run.bat — OSINT Recon Suite bootstrap launcher (Windows)
:: =============================================================================
::
::  Usage (double-click or run from CMD / PowerShell):
::    run.bat                        — interactive: prompts for target & mode
::    run.bat example.com            — live scan with confirmation prompt
::    run.bat example.com --mock     — mock mode (no network calls)
::    run.bat example.com --no-confirm
::
::  The script will:
::    1. Locate the repository root (where run.bat lives)
::    2. Create a Python virtual environment (venv\) if one does not exist
::    3. Install / upgrade dependencies from requirements.txt if needed
::    4. Prompt interactively for target and mode when no args are given
::    5. Launch main.py, passing through any CLI arguments you provided
::
:: =============================================================================
setlocal EnableDelayedExpansion

:: Change to the directory containing run.bat
cd /d "%~dp0"

:: ── Banner ────────────────────────────────────────────────────────────────────
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
set "VENV_DIR=%~dp0venv"

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
set "REQ_FILE=%~dp0requirements.txt"
set "NEEDS_INSTALL=0"

if not exist "!STAMP_FILE!" set "NEEDS_INSTALL=1"

:: Check if requirements.txt is newer than stamp (basic check)
if "!NEEDS_INSTALL!"=="0" (
    for /f %%A in ('forfiles /p "%~dp0" /m "requirements.txt" /c "cmd /c echo @fdate @ftime" 2^>nul') do set "REQ_DATE=%%A"
    for /f %%A in ('forfiles /p "!VENV_DIR!" /m ".install_stamp" /c "cmd /c echo @fdate @ftime" 2^>nul') do set "STAMP_DATE=%%A"
    if "!REQ_DATE!" gtr "!STAMP_DATE!" set "NEEDS_INSTALL=1"
)

if "!NEEDS_INSTALL!"=="1" (
    echo  [->] Installing dependencies from requirements.txt ...
    pip install --upgrade pip --quiet
    pip install -r "!REQ_FILE!" --quiet
    if !errorlevel! neq 0 (
        echo  [ERROR] pip install failed. Check your network connection and requirements.txt.
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
if not exist "%~dp0data\" mkdir "%~dp0data"
if not exist "%~dp0reports\" mkdir "%~dp0reports"

:: ── Argument handling / interactive prompt ────────────────────────────────────
set "USER_ARGS=%*"

if "!USER_ARGS!"=="" (
    :: No arguments — interactive mode
    echo  No arguments detected. Entering interactive setup.
    echo.

    :: Target domain
    :ask_target
    set "TARGET="
    set /p "TARGET=  Enter the target domain to scan (e.g. example.com): "
    if "!TARGET!"=="" (
        echo  [!] Target cannot be empty. Please enter a domain name.
        goto ask_target
    )

    :: Scan mode
    echo.
    echo  Select scan mode:
    echo    [1] Live scan   — makes real HTTP/DNS requests (default)
    echo    [2] Mock mode   — no network calls; safe pipeline test
    echo.
    set "MODE_CHOICE=1"
    set /p "MODE_CHOICE=  Your choice [1/2, default=1]: "
    if "!MODE_CHOICE!"=="" set "MODE_CHOICE=1"

    :: Confirmation prompt
    echo.
    echo  Show interactive confirmation before scanning?
    echo    [1] Yes — show confirmation prompt (default)
    echo    [2] No  — skip confirmation (automated/scripted use)
    echo.
    set "CONFIRM_CHOICE=1"
    set /p "CONFIRM_CHOICE=  Your choice [1/2, default=1]: "
    if "!CONFIRM_CHOICE!"=="" set "CONFIRM_CHOICE=1"

    :: Build argument string
    set "ARGS=!TARGET!"
    if "!MODE_CHOICE!"=="2" set "ARGS=!ARGS! --mock"
    if "!CONFIRM_CHOICE!"=="2" set "ARGS=!ARGS! --no-confirm"
) else (
    :: Arguments supplied — pass through verbatim
    set "ARGS=!USER_ARGS!"
)

:: ── Launch ────────────────────────────────────────────────────────────────────
echo.
echo  [+] Launching OSINT Recon Suite ...
echo  [->] Command: python main.py !ARGS!
echo.

!PYTHON! "%~dp0main.py" !ARGS!
set "EXIT_CODE=!errorlevel!"

echo.
if "!EXIT_CODE!"=="0" (
    echo  [+] Scan completed successfully.
    echo  [+] Open the generated HTML report from the reports\ folder.
) else (
    echo  [ERROR] Scan exited with code !EXIT_CODE!. Check the output above.
)

echo.
pause
exit /b !EXIT_CODE!
