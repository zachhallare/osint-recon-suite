# How to Run OSINT Recon Suite

A complete step-by-step guide to installing, configuring, and running the **OSINT Recon Suite** across different operating systems, with dedicated instructions for **Kali Linux**.

---

## Table of Contents
1. [Compatibility Overview](#compatibility-overview)
2. [Kali Linux Setup & Execution](#kali-linux-setup--execution)
3. [Other Linux Distributions (Debian, Ubuntu, Arch, Fedora)](#other-linux-distributions)
4. [macOS Setup & Execution](#macos-setup--execution)
5. [Windows Setup & Execution](#windows-setup--execution)
6. [CLI Usage & Scan Modes](#cli-usage--scan-modes)
7. [Viewing the HTML Report](#viewing-the-html-report)
8. [Running Automated Tests](#running-automated-tests)
9. [Troubleshooting & Kali Linux FAQ](#troubleshooting--kali-linux-faq)
10. [Safely Cleaning Up & Uninstalling](#safely-cleaning-up--uninstalling)

---

## Compatibility Overview

| Platform | Supported? | Python Version | Notes |
|----------|------------|----------------|-------|
| **Kali Linux** | **Yes (Fully Supported)** | 3.11+ | Ideal environment; requires `python3-venv` and system `whois` |
| **Debian / Ubuntu** | **Yes** | 3.11+ | Standard virtualenv setup |
| **Arch Linux / Fedora** | **Yes** | 3.11+ | Standard virtualenv setup |
| **macOS** | **Yes** | 3.11+ | Intel & Apple Silicon (M1/M2/M3) supported |
| **Windows 10/11** | **Yes** | 3.11+ | Native PowerShell / CMD supported |

> **Note on Architecture:** The suite uses pure-Python libraries (such as `pypdf`, `python-docx`, `dnspython`, `httpx`) and pre-built wheels (`Pillow`), meaning **no C compiler or system development toolchains are required**.

---

## Kali Linux Setup & Execution

Kali Linux (rolling releases based on Debian 12+) enforces **PEP 668** (*externally managed environments*), which means running `pip install` globally without a virtual environment will produce an error. Always use a Python virtual environment.

### 1. Install System Prerequisites
Open a terminal in Kali and ensure `python3`, `python3-venv`, `git`, and the system `whois` utility are installed:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip whois git
```

*(Note: `python-whois` invokes the system `whois` binary on Linux; having the package installed ensures WHOIS lookups succeed reliably).*

### 2. Clone or Navigate to the Repository
```bash
# If cloning from GitHub:
git clone https://github.com/zachhallare/osint-recon-suite.git
cd osint-recon-suite

# Or navigate to your existing project directory:
cd /path/to/osint-recon-suite
```

### 3. Create and Activate Virtual Environment
```bash
# Create a local virtual environment named 'venv'
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate
```
*(Your terminal prompt will now show `(venv)`).*

### 4. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 5. Run the Tool

#### Safe Test (Mock Mode - No Network Requests):
```bash
python3 main.py example.com --mock
```

#### Live Recon Scan (Interactive confirmation prompt):
```bash
python3 main.py targetdomain.com
```

#### Live Recon Scan (Unattended / Scripted):
```bash
python3 main.py targetdomain.com --no-confirm
```

---

## Other Linux Distributions

### Ubuntu / Debian / Linux Mint
```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip whois git
cd osint-recon-suite
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 main.py example.com
```

### Arch Linux / Manjaro
```bash
sudo pacman -Syu python python-pip whois git
cd osint-recon-suite
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py example.com
```

### Fedora / RHEL
```bash
sudo dnf install -y python3 python3-pip whois git
cd osint-recon-suite
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 main.py example.com
```

---

## macOS Setup & Execution

1. Ensure Python 3.11+ is installed (via [python.org](https://www.python.org/) or `brew install python whois`).
2. Open Terminal and run:

```bash
cd osint-recon-suite
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 main.py example.com
```

---

## Windows Setup & Execution

1. Open PowerShell or Command Prompt.
2. Navigate to the repository:

```powershell
cd osint-recon-suite

# Create virtual environment
python -m venv venv

# Activate in PowerShell:
.\venv\Scripts\Activate.ps1
# (If execution policy error occurs, run: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass)

# Or activate in CMD:
venv\Scripts\activate.bat

# Install dependencies:
pip install -r requirements.txt

# Run:
python main.py example.com
```

---

## CLI Usage & Scan Modes

### Command Syntax
```bash
python main.py <target> [flags]
```

### Available Options
| Flag | Description | Default |
|------|-------------|---------|
| `target` | Domain name or hostname to scan (e.g. `example.com`) | *Required* |
| `--mock` | Run mock module only; exercises orchestrator, database, and HTML reporting with zero network activity | `False` |
| `--no-confirm` | Bypass the interactive target confirmation prompt (useful in CI pipelines or bash scripts) | `False` |
| `--db PATH` | Custom SQLite database file location | `data/osint.db` |
| `--output DIR`| Output directory where the HTML risk report will be written | `reports/` |
| `-h`, `--help` | Show command line help message and exit | — |

### Examples

```bash
# 1. Quick test to verify complete pipeline without making any external calls:
python main.py example.com --mock

# 2. Standard scan on an authorized domain:
python main.py mycompany.com

# 3. Automated scan saving to a specific report folder:
python main.py mycompany.com --no-confirm --output /tmp/recon_reports/

# 4. Use an isolated database file:
python main.py mycompany.com --db /tmp/custom_scan.db
```

---

## Viewing the HTML Report

The suite generates a self-contained, interactive HTML report styled in dark mode with zero external CDN dependencies:
```
reports/<target>_run<id>_<timestamp>.html
```

### On Desktop (Kali Linux / Ubuntu / Debian / macOS / Windows)
Open the generated report directly in your default browser:

- **Kali Linux / Ubuntu (CLI):**
  ```bash
  xdg-open reports/*.html
  # or specifically with Firefox:
  firefox reports/*.html &
  ```
- **macOS:**
  ```bash
  open reports/*.html
  ```
- **Windows:**
  ```powershell
  start reports/*.html
  ```

### On Headless Servers, Remote Kali VPS, or WSL
If you are running Kali in a headless cloud server or over SSH without X11 forwarding:

1. **Serve reports locally over Python's built-in HTTP server:**
   ```bash
   python3 -m http.server 8080 --directory reports
   ```
   Then open `http://<your-server-ip>:8080` in your host browser.

2. **Or copy the file to your local machine via SCP:**
   ```bash
   scp kali@remote-ip:~/osint-recon-suite/reports/*.html ./
   ```

---

## Running Automated Tests

The repository includes a comprehensive test suite (140+ unit and integration tests) that mocks all network endpoints to run fast and fully offline.

To run the tests:
```bash
# Ensure virtual environment is active
pytest
```

To run with verbose output:
```bash
pytest -v
```

---

## Troubleshooting & Kali Linux FAQ

### 1. `error: externally-managed-environment` on Kali
**Cause:** Debian/Kali follows PEP 668 to prevent `pip` from breaking OS packages.  
**Fix:** Always create and activate a virtual environment (`python3 -m venv venv && source venv/bin/activate`) before running `pip install`.

### 2. `whois: command not found` or WHOIS timeout errors
**Cause:** `python-whois` calls the system `whois` command under Linux. If the system package is missing, queries may fail.  
**Fix:** Install the system package:
```bash
sudo apt install -y whois
```

### 3. Do I need to run this as `root` / `sudo`?
**No.** Running security tools as `root` when not needed is an antipattern. This tool performs passive network requests (DNS, HTTP/HTTPS, public APIs) on non-privileged unreserved ports. Running as your standard `kali` user is recommended and avoids file permission issues in `data/` and `reports/`.

### 4. Can I add custom API keys (e.g., full Shodan or GitHub token)?
**Yes.** While the suite requires no paid API keys for MVP operation, you can configure optional tokens via a `.env` file in the project root:
```ini
# .env (gitignored)
GITHUB_TOKEN=ghp_yourTokenHere
SHODAN_API_KEY=yourShodanKeyHere
```

### 5. `sqlite3.OperationalError: unable to open database file`
**Cause:** The target `data/` directory does not exist or lacks write permissions.  
**Fix:** Ensure the directory exists or run from the repository root:
```bash
mkdir -p data reports
```

---

## Safely Cleaning Up & Uninstalling

Depending on whether you want to reset scan artifacts, clean sensitive OSINT data, or completely remove the suite from your system, follow the appropriate method below.

### Method 1: Clean Up Scan Data & Reports Only (Keep the Code & Venv)
If you want to keep the application ready for future runs but wipe all past scan findings, logs, and sensitive client reports:

#### Linux / Kali Linux / macOS:
```bash
# Remove all generated HTML reports
rm -rf reports/*.html

# Remove the SQLite database and write-ahead logs
rm -rf data/osint.db*

# Remove runtime execution logs and test caches
rm -f osint_recon.log
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
rm -rf .pytest_cache
```

#### Windows (PowerShell):
```powershell
# Remove generated HTML reports
Remove-Item -Force reports\*.html -ErrorAction SilentlyContinue

# Remove SQLite database and write-ahead logs
Remove-Item -Force data\osint.db* -ErrorAction SilentlyContinue

# Remove runtime log and caches
Remove-Item -Force osint_recon.log -ErrorAction SilentlyContinue
Get-ChildItem -Path . -Filter "__pycache__" -Recurse -Directory | Remove-Item -Recurse -Force
Remove-Item -Recurse -Force .pytest_cache -ErrorAction SilentlyContinue
```

---

### Method 2: Remove Virtual Environment (Reset Dependencies)
If you want to free disk space or recreate dependencies from scratch:

#### Linux / Kali Linux / macOS:
```bash
# Deactivate the virtual environment if active
deactivate 2>/dev/null

# Remove the virtual environment folder
rm -rf venv/
```

#### Windows (PowerShell):
```powershell
# Deactivate the virtual environment if active
deactivate

# Remove the virtual environment folder
Remove-Item -Recurse -Force venv
```

---

### Method 3: Complete & Safe Deletion of the Repository
To completely remove the repository, all scanned artifacts, database records, API secrets (`.env`), and virtual environments with zero leftover files:

#### Linux / Kali Linux / macOS:
```bash
# 1. Deactivate virtual environment
deactivate 2>/dev/null

# 2. Navigate out of the project directory
cd ..

# 3. Securely delete or remove the entire project directory
rm -rf osint-recon-suite
```

> **Pro-Tip for Security Assessments (Kali Linux Secure Shred):**  
> If your scan contained sensitive client data or confidential targets that require compliance-grade sanitization before deleting the folder, securely overwrite the database and reports first using `shred`:
> ```bash
> # Securely overwrite files with random bytes and delete them
> shred -u -z -n 3 data/osint.db* reports/*.html osint_recon.log .env 2>/dev/null
> cd .. && rm -rf osint-recon-suite
> ```

#### Windows (PowerShell):
```powershell
# 1. Deactivate virtual environment
deactivate

# 2. Navigate to parent folder
cd ..

# 3. Completely delete the directory
Remove-Item -Recurse -Force osint-recon-suite
```

