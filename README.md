# OSINT Recon Suite

## Tool Name
**OSINT Recon Suite** — a modular, passive open-source intelligence (OSINT) reconnaissance tool.

---

## Description
OSINT Recon Suite is a command-line Python application that automates the passive recon phase of a security assessment. Given a single target (domain name or entity), it queries multiple public sources — WHOIS registries, DNS resolvers, certificate transparency logs, Shodan's free InternetDB, and web-accessible file paths — and consolidates all findings into a single, professional HTML risk report.

Think of it as a lightweight, personal [Spiderfoot](https://github.com/smicallef/spiderfoot) you can run locally, understand end-to-end, and extend one module at a time.

---

## Purpose
- **Automate** the manual OSINT phase: WHOIS/DNS lookups, subdomain discovery, attack surface mapping, exposed document scanning, and metadata leakage — all in one command.
- **Produce** a single consolidated output (HTML report) that reads like an actual recon deliverable, not raw terminal output.
- **Enable** module-level isolation — each recon module can run independently or as part of the full suite.
- **Serve as a portfolio project** demonstrating security tooling, modular Python architecture, and professional reporting.

---

## Features

### Implemented (MVP Critical Path)

| Step | Module | What It Does | Status |
|------|--------|--------------|--------|
| 1 | Orchestrator + Report Shell | Drives the pipeline; dark-mode HTML reports with risk stat cards | ✅ Complete |
| 2 | WHOIS / DNS Recon | WHOIS + A/AAAA/MX/NS/TXT/CNAME/SOA; flags email leakage, near-expiry, SPF/DMARC/DKIM | ✅ Complete |
| 3 | Subdomain Enumerator | Certificate Transparency via crt.sh; async DNS validation; keyword risk classifier | ✅ Complete |
| 4 | Company Attack Surface Mapper | Shodan InternetDB (open ports, CVEs, CPEs); IP geo + ASN; shared-hosting detection; MX/NS tech fingerprinting | ✅ Complete |
| 5a | Document Exposure Scanner | Probes 60+ sensitive paths (.git, .env, DB dumps, config, logs, deployment files); concurrent HEAD requests; deduplication | ✅ Complete |
| 5b | Metadata Extractor | Downloads discovered documents; extracts PDF author/creator/producer, Office author/company/username, image GPS coordinates (HIGH risk), EXIF software/artist | ✅ Complete |
| 6 | Social Media OSINT Collector | Public profile enumeration | 🔜 Next |

### Core Architecture
- **Modular**: Each recon module inherits `BaseModule` — it cannot crash the orchestrator even if it fails completely.
- **Persistent**: All findings stored in a local SQLite database with composite indexes.
- **Safe by design**: Interactive confirmation prompt before any network calls. All APIs are public and free.
- **Async-ready**: Subdomain DNS, document scanner, and metadata extractor run concurrent requests within configurable semaphore limits.

---

## System Requirements

| Requirement | Version |
|-------------|---------|
| Python | 3.11 or higher (tested on 3.13.7) |
| Operating System | Windows 10/11, macOS 12+, Linux (Ubuntu 20.04+) |
| Network | Internet access for live scans; none required for `--mock` mode or tests |
| Disk | ~50 MB for dependencies + database + downloaded document cache |

> **Note:** No paid API keys required for the MVP.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/zachhallare/osint-recon-suite.git
cd osint-recon-suite

# 2. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # macOS / Linux

# 3. Install dependencies
pip install -r requirements.txt
```

Optionally create a `.env` file for future paid API sources (gitignored):

```bash
# .env  — never commit this file
# SHODAN_API_KEY=your_key_here
```

---

## Usage

```bash
# Full suite run — confirmation prompt before any network calls
python main.py yourdomain.com

# Mock mode — no network calls; full pipeline smoke-test
python main.py yourdomain.com --mock

# Skip confirmation prompt
python main.py yourdomain.com --no-confirm

# Custom paths
python main.py yourdomain.com --db data/mydb.db --output reports/
```

Report saved to: `reports/<target>_run<id>_<timestamp>.html` — open in any browser.

### Example session

```
11:07:00  INFO  orchestrator — Modules: [whois_dns, subdomain, company_mapper,
                                          document_scanner, metadata_extractor]
11:07:01  INFO  base_module  — [whois_dns]          Finished — 9 finding(s) in 1.21s
11:07:04  INFO  base_module  — [subdomain]           Finished — 14 finding(s) in 3.04s
11:07:07  INFO  base_module  — [company_mapper]      Finished — 12 finding(s) in 2.87s
11:07:10  INFO  base_module  — [document_scanner]    Finished — 4 finding(s) in 3.11s
11:07:12  INFO  base_module  — [metadata_extractor]  Finished — 6 finding(s) in 2.04s

  [OK]  Report saved:  reports\example_com_run5_20260915_110700.html
  [**]  Findings:      45
  [t]   Duration:      12.3s
```

---

## Testing Environment

| Component | Details |
|-----------|---------|
| Test runner | pytest 9.1.1 |
| Async support | anyio 4.11.0 (asyncio backend) |
| Network isolation | All HTTP/DNS calls mocked; real pypdf/python-docx/Pillow used against in-memory blobs |
| Fixture storage | `tests/fixtures/` — saved API responses |
| Python version | 3.13.7 (Windows) |

```bash
python -m pytest tests/ -v
```

### Test Coverage (as of Step 5)

| Test File | Tests | What's Covered |
|-----------|-------|----------------|
| `test_models.py` | 7 | Finding, ModuleResult, ScanResult dataclasses |
| `test_base_module.py` | 3 | Error isolation, timing, status contracts |
| `test_database.py` | 6 | SQLite lifecycle |
| `test_reporter.py` | 6 | HTML structure, risk badges |
| `test_whois_dns_module.py` | 17 | WHOIS parsing, DNS records, expiry risk |
| `test_subdomain_module.py` | 21 | crt.sh parsing, SAN multi-value, keyword classification |
| `test_company_mapper_module.py` | 26 | Shodan, ipapi.co, reverse IP, fingerprinting |
| `test_document_scanner_module.py` | 12 | HEAD probing, size limits, risk levels, deduplication |
| `test_metadata_extractor_module.py` | 15 | PDF/Office/image parsing, GPS conversion, download guard |
| **Total** | **113** | |

---

## Sample Output

The HTML report is a self-contained dark-mode page with:
- **Hero header** — target, scan ID, start time, duration
- **Risk stat cards** — High / Medium / Low / Info at a glance
- **Per-module tables** — type, value (monospace), risk badge, timestamp
- **Collapsible extra data** — expand any finding for raw JSON metadata
- **Error modules** — failures show error text in red; report always completes

### Step 5 finding examples

```
[document_scanner] ✓ success · 3.11s
  git_exposure     https://example.com/.git/HEAD        HIGH   ← Source code!
  env_file         https://example.com/.env             HIGH   ← Secrets!
  php_info         https://example.com/phpinfo.php      medium
  robots_txt       https://example.com/robots.txt       info

[metadata_extractor] ✓ success · 2.04s
  pdf_author       Jane Smith                           medium ← PII
  office_company   ACME Internal                        low
  office_last_m    jdoe                                 medium ← username
  image_gps        51.507400, -0.127800                 HIGH   ← Location!
  image_software   Adobe Photoshop CC 2022              low
  pdf_creator      Microsoft Word 2019                  low
```

---

## Limitations

- **Passive only** — never sends exploit traffic, attempts authentication, or bypasses rate limits.
- **Document scanner** — only checks for known sensitive paths; novel or renamed sensitive files will not be found. False negatives are expected.
- **False positive rate** — a path returning HTTP 200 may serve a custom 404 page. The TRD goal of keeping false positives low is partially addressed by checking `Content-Length` and `Content-Type`; full body validation is a post-MVP enhancement.
- **Metadata extractor** — only analyses files with recognised extensions (PDF, DOCX, XLSX, JPEG, PNG, TIFF). Unusual content types require the file to have a matching URL extension.
- **Rate limiting** — document scanner fires up to 15 concurrent HEAD requests. Targets with aggressive WAFs may block or rate-limit this. The semaphore limit is configurable.
- **PyMuPDF** — uses `pypdf` (pure-Python) instead; no VS2019 compiler required.
- **No GUI** — CLI-only. A local web dashboard is post-MVP.

---

## Future Improvements

> Strictly post-MVP per `implementation.md § Future Enhancements`.

- Risk scoring — rank findings instead of listing flat
- CLI module flags — `--only document_scanner` for partial scans
- Diff-based scanning — highlight only what changed since last `scan_run`
- Breach-check module — flag emails in known breach databases
- Local web dashboard — browse historical scans in browser

---

## Ethical Disclaimer

**This tool is for passive, authorised reconnaissance only.**

- Only scan domains or infrastructure you **own** or have **explicit written permission** to test.
- The document scanner sends real HTTP HEAD requests to the target domain — ensure you have permission before running it against any target.
- Never attempts exploitation, authentication bypass, rate-limit evasion, or CAPTCHA circumvention.
- Misuse may violate computer fraud laws (CFAA in the US, Computer Misuse Act in the UK, etc.).
- The built-in confirmation prompt is intentional.

---

## Group Members and Roles

| Name | Role | Responsibilities |
|------|------|-----------------|
| Zach Hallare | Lead Developer & Security Architect | Architecture design, all module development, database schema, report generation, testing strategy |

*This is a solo portfolio project.*

---

## Original Contribution

| Contribution | Description |
|--------------|-------------|
| **Modular error-isolation architecture** | `BaseModule` ABC structurally enforces typed `FAILED` results without propagation. |
| **Unified data model** | `Finding → ModuleResult → ScanResult` typed contract between modules and report layer. |
| **Longitudinal SQLite schema** | 3-table schema with composite indexes, designed for future diff-based scanning. |
| **Professional HTML report template** | Self-contained dark-mode report with risk stat cards, collapsible JSON metadata, monospace values. |
| **WHOIS expiry risk classification** | Flags domains expiring within 60 days as HIGH (hijack vector). |
| **TXT record intelligence** | Auto-categorises SPF, DMARC, DKIM, vendor verification tokens. |
| **Async subdomain enumeration** | `asyncio.gather` + semaphore for fast crt.sh validation. |
| **Sensitive subdomain keyword classifier** | 50-keyword dictionary auto-elevates admin/vpn/dev/git/jenkins subdomains to MEDIUM. |
| **Shodan InternetDB port risk engine** | HIGH/MEDIUM/LOW port classification without a paid API key. |
| **Technology stack fingerprinting** | Detects email + DNS provider purely from MX/NS records. |
| **Shared hosting detection** | Flags IPs hosting multiple domains as wider blast radius. |
| **60-path document exposure scanner** | Concurrent async HEAD probing for .git, .env, DB dumps, config, deployment, log files; deduplicates across HTTP/HTTPS; enforces TRD size and timeout limits. |
| **PDF metadata extraction** | Extracts author, creator, producer, dates from PDF XMP/Info dicts using pypdf. |
| **Office metadata extraction** | Extracts author, last-modified-by (internal username), company, revision from DOCX/XLSX. |
| **Image EXIF + GPS extraction** | Extracts GPS coordinates (HIGH risk — physical location leakage), camera make/model, software, artist from JPEG/PNG/TIFF EXIF via Pillow; converts DMS to decimal degrees. |
| **Offline test suite** | All 113 tests run without network calls; real pypdf/docx/Pillow used against in-memory synthetic blobs. |

---

## Project Structure

```
osint-recon-suite/
├── main.py
├── requirements.txt
├── pytest.ini
├── .gitignore
├── implementation.md
├── README.md
│
├── osint_recon/
│   ├── models.py
│   ├── base_module.py
│   ├── orchestrator.py
│   ├── database.py
│   ├── reporter.py
│   ├── templates/
│   │   └── report.html.j2
│   └── modules/
│       ├── mock_module.py
│       ├── whois_dns_module.py          Step 2
│       ├── subdomain_module.py          Step 3
│       ├── company_mapper_module.py     Step 4
│       ├── document_scanner_module.py   Step 5a ← NEW
│       └── metadata_extractor_module.py Step 5b ← NEW
│
└── tests/
    ├── conftest.py
    ├── fixtures/
    │   ├── whois_example_com.json
    │   ├── crtsh_example_com.json
    │   ├── shodan_internetdb_93_184_216_34.json
    │   └── ipapi_93_184_216_34.json
    ├── test_models.py
    ├── test_base_module.py
    ├── test_database.py
    ├── test_reporter.py
    ├── test_whois_dns_module.py
    ├── test_subdomain_module.py
    ├── test_company_mapper_module.py
    ├── test_document_scanner_module.py   Step 5a ← NEW
    └── test_metadata_extractor_module.py Step 5b ← NEW
```