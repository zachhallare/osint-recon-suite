# OSINT Recon Suite

A modular, passive OSINT reconnaissance tool.  Given a target domain or entity, it gathers public intelligence from multiple sources and produces a single HTML risk/profile report.

> **Ethical use only.** Only scan domains you own or have explicit written permission to test.  
> This tool performs **passive reconnaissance only** and never attempts exploitation.

---

## Features (MVP)

| Module | Source | Status |
|--------|--------|--------|
| Orchestrator + Report Shell | Internal | ✅ Done (Step 1) |
| WHOIS / DNS Recon | python-whois, dnspython | 🔜 Step 2 |
| Subdomain Enumerator | crt.sh public API | 🔜 Step 3 |
| Company Attack Surface Mapper | Public search | 🔜 Step 4 |
| Document Exposure Scanner | Google dorks (passive) | 🔜 Step 5 |
| Metadata Extractor | pypdf, python-docx, Pillow | 🔜 Step 5 |
| Social Media OSINT Collector | Public APIs | 🔜 Step 6 |

---

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/zachhallare/osint-recon-suite.git
cd osint-recon-suite

# 2. Create and activate a virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

If you plan to add paid API sources later, create a `.env` file (it is gitignored):

```bash
# .env
# SHODAN_API_KEY=your_key_here
```

---

## Usage

```bash
# Full suite run (confirms target before any network calls)
python main.py example.com

# Mock mode — no network calls, useful for testing the pipeline
python main.py example.com --mock

# Skip the confirmation prompt (use in automated/CI environments)
python main.py example.com --no-confirm

# Custom DB and output paths
python main.py example.com --db data/mydb.db --output reports/
```

The HTML report is saved to `reports/<target>_run<id>_<timestamp>.html`.

---

## Running Tests

```bash
python -m pytest tests/ -v
```

Tests use saved fixture data — no live network calls are required.

---

## Project Structure

```
osint-recon-suite/
├── main.py                        # CLI entry point
├── requirements.txt
├── pytest.ini
├── osint_recon/
│   ├── models.py                  # Shared dataclasses (Finding, ModuleResult, ScanResult)
│   ├── base_module.py             # Abstract base every module inherits
│   ├── orchestrator.py            # Pipeline driver + target confirmation
│   ├── database.py                # SQLite persistence (targets, scan_runs, findings)
│   ├── reporter.py                # Jinja2 → HTML report generator
│   ├── templates/
│   │   └── report.html.j2         # Dark-mode HTML report template
│   └── modules/
│       ├── mock_module.py          # Fake module for pipeline testing
│       └── ...                    # Real modules added here (Steps 2–6)
├── tests/
│   ├── conftest.py
│   ├── test_models.py
│   ├── test_base_module.py
│   ├── test_database.py
│   └── test_reporter.py
└── data/                          # SQLite DB (gitignored)
    └── osint.db
```

---

## Database Schema

```sql
targets    (id, name, domain, created_at)
scan_runs  (id, target_id, started_at, completed_at, status)
findings   (id, scan_run_id, module_name, finding_type, value,
             risk_level, extra_json, discovered_at)
```

SQLite — no server required.  Indexed on `scan_run_id` and `module_name`.

---

## Adding a New Module

1. Create `osint_recon/modules/my_module.py`
2. Subclass `BaseModule`, set `MODULE_NAME`, implement `async def _run(self, target: str) -> list[Finding]`
3. Add the module to the list in `main.py`
4. Write a unit test in `tests/` against saved fixture data

```python
from osint_recon.base_module import BaseModule
from osint_recon.models import Finding, RiskLevel

class MyModule(BaseModule):
    MODULE_NAME = "my_module"

    async def _run(self, target: str) -> list[Finding]:
        # ... do passive recon ...
        return [Finding(
            module_name=self.MODULE_NAME,
            finding_type="example",
            value="discovered value",
            risk_level=RiskLevel.LOW,
        )]
```

---

## Definition of Done (per module)

- [ ] Module runs standalone and returns structured data (not just printed text)
- [ ] Module handles a failed/empty response without crashing the orchestrator
- [ ] Module's output appears correctly in the final HTML report
- [ ] Module has at least one test run against a real target with results manually verified

---

*Resume framing: "Built a modular OSINT recon tool (mini-Spiderfoot) that aggregates WHOIS, subdomain, document exposure, and metadata leakage into a single automated risk report."*