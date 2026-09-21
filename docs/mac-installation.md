# How to Run OSINT Recon Suite on Mac

a complete guide to installing configuring and running the tool on mac

## Recommended Install using pipx

pipx is the easiest way to install the tool globally

option one one-liner
```bash
pipx install git+https://github.com/zachhallare/osint-recon-suite.git
```

option two from clone
```bash
git clone https://github.com/zachhallare/osint-recon-suite.git
cd osint-recon-suite
pipx install .
```

after installing you can run `recon-suite` from anywhere

## Alternative Install using Standalone Scripts

if you do not want to use pipx the included scripts will automatically create a virtual environment and install dependencies

```bash
git clone https://github.com/zachhallare/osint-recon-suite.git
cd osint-recon-suite
chmod +x scripts/run.command scripts/uninstall.command
./scripts/run.command
```
you can also double click the run.command file in finder

## Manual Virtual Environment Install

if you want to set it up manually yourself

```bash
git clone https://github.com/zachhallare/osint-recon-suite.git
cd osint-recon-suite
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 main.py example.com
```

## CLI Usage and Scan Modes

### Command Syntax
```bash
recon-suite <target> [flags]
```

### Available Options
| Flag | Description | Default |
|------|-------------|---------|
| `target` | Domain name or hostname to scan | Required |
| `--mock` | Run mock module only with zero network activity | False |
| `--no-confirm` | Bypass interactive confirmation prompt | False |
| `--html` | Force HTML risk report generation without prompting | None |
| `--no-html` | Skip HTML report generation | None |
| `--db PATH` | Custom SQLite database file location | data/osint.db |
| `--output DIR`| Output directory where the HTML risk report will be written | reports/ |
| `-h`, `--help` | Show command line help message and exit | |

### Scan Authorization Audit Trail

to prevent accidental scanning every run records how it was authorized

| Authorization Status | Trigger | Description |
|----------------------|---------|-------------|
| INTERACTIVE | Standard CLI invocation | Operator confirmed target authorization |
| BYPASSED | `--no-confirm` flag | Confirmation prompt was skipped |
| MOCK | `--mock` flag | Synthetic test scan with zero external network calls |

### Examples

```bash
# quick test with no network calls
recon-suite example.com --mock

# standard interactive scan
recon-suite mycompany.com

# automated scan saving to a specific folder
recon-suite mycompany.com --no-confirm --html --output /tmp/recon_reports/
```

## Viewing the HTML Report

the suite generates a self-contained html report in the reports directory

open the report directly in your browser

```bash
open reports/*.html
```

if you are on a remote server you can serve the reports locally
```bash
python3 -m http.server 8080 --directory reports
```

## Running Automated Tests

the repository includes an offline test suite

```bash
pytest
```

## Troubleshooting

1 whois command not found
install the system whois package using homebrew

2 can i add custom api keys like full shodan or github token or the have i been pwned key
yes you can add optional tokens using an env file in the project root like this
GITHUB_TOKEN=ghp_yourTokenHere
SHODAN_API_KEY=yourShodanKeyHere
HIBP_API_KEY=yourHIBPKeyHere

## Uninstalling

if you installed with pipx run
```bash
pipx uninstall osint-recon-suite
```

if you used the standalone scripts run the uninstaller
```bash
./scripts/uninstall.command
```
you can also double click the uninstall.command file in finder
