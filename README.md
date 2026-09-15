# OSINT Recon Suite

## Tool Name
**OSINT Recon Suite** — a modular, passive open-source intelligence (OSINT) reconnaissance tool.

---

## Description
OSINT Recon Suite is a command-line Python application that automates the passive recon phase of a security assessment. Given a single target (domain name or entity), it queries multiple public sources — WHOIS registries, DNS resolvers, certificate transparency logs, and more — and consolidates all findings into a single, professional HTML risk report.

Think of it as a lightweight, personal [Spiderfoot](https://github.com/smicallef/spiderfoot) you can run locally, understand end-to-end, and extend one module at a time.

---

## Purpose
- **Automate** the manual OSINT phase: WHOIS/DNS lookups, subdomain discovery, exposed document discovery, and metadata leakage — all in one command.
- **Produce** a single consolidated output (HTML report) that reads like an actual recon deliverable, not raw terminal output.
- **Enable** module-level isolation — each recon module can run independently or as part of the full suite.
- **Serve as a portfolio project** demonstrating security tooling, modular Python architecture, and professional reporting.

---

## Features

### Implemented (MVP Critical Path)

| Step | Module | What It Does | Status |
|------|--------|--------------|--------|
| 1 | Orchestrator + Report Shell | Drives the pipeline; generates dark-mode HTML reports with risk-tiered stat cards | ✅ Complete |
| 2 | WHOIS / DNS Recon | WHOIS lookup + A/AAAA/MX/NS/TXT/CNAME/SOA records; flags email leakage, near-expiry domains, SPF/DMARC/DKIM records | ✅ Complete |
| 3 | Subdomain Enumerator | Certificate Transparency via crt.sh; async DNS validation of live subdomains; keyword-based risk classification (dev, admin, vpn, etc.) | ✅ Complete |
| 4 | Company Attack Surface Mapper | Public search for exposed infrastructure | 🔜 Next |
| 5 | Document Exposure Scanner + Metadata Extractor | Google dorks for exposed files; PDF/Office/image EXIF metadata extraction | 🔜 Planned |
| 6 | Social Media OSINT Collector | Public profile enumeration | 🔜 Planned |

### Core Architecture
- **Modular**: Each recon module inherits `BaseModule` — it cannot crash the orchestrator even if it fails completely.
- **Persistent**: All findings stored in a local SQLite database, indexed for fast per-scan queries. Enables longitudinal comparison (was this subdomain there last week?).
- **Safe by design**: Interactive confirmation prompt before any network calls. Explicit allowlist-ready architecture.
- **Report-first**: The Jinja2 HTML report template was built before any real modules — every module plugs into a proven output pipeline.
- **Async-ready**: Subdomain DNS validation runs up to 20 concurrent queries via `asyncio.Semaphore`.

---

## System Requirements

| Requirement | Version |
|-------------|---------|
| Python | 3.11 or higher (tested on 3.13.7) |
| Operating System | Windows 10/11, macOS 12+, Linux (Ubuntu 20.04+) |
| Network | Internet access for live scans; none required for `--mock` mode or tests |
| Disk | ~50 MB for dependencies + database growth over time |

> **Note:** No paid API keys are required for the MVP. All sources are free and public.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/zachhallare/osint-recon-suite.git
cd osint-recon-suite

# 2. Create and activate a virtual environment (recommended)
python -m venv venv

# Windows:
venv\Scripts\activate

# macOS / Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

If you intend to add paid API sources later (e.g., Shodan), create a `.env` file in the project root (it is `.gitignore`d and will never be committed):

```bash
# .env  — never commit this file
# SHODAN_API_KEY=your_key_here
```

---

## Usage

```bash
# Full suite run — prompts you to confirm the target before any network calls
python main.py yourdomain.com

# Mock mode — no network calls; exercises the full pipeline with fake data
python main.py yourdomain.com --mock

# Skip the interactive confirmation prompt (useful for CI or scripted runs)
python main.py yourdomain.com --no-confirm

# Custom database and output paths
python main.py yourdomain.com --db data/mydb.db --output reports/
```

The HTML report is saved to:
```
reports/<target>_run<scan_id>_<timestamp>.html
```

Open it in any browser — no server required.

### Example session

```
10:53:20  INFO  main — Starting OSINT Recon Suite
10:53:20  INFO  orchestrator — Modules enabled: ['whois_dns', 'subdomain']
10:53:21  INFO  base_module — [whois_dns] Finished — 9 finding(s) in 1.21s
10:53:24  INFO  base_module — [subdomain] Finished — 14 finding(s) in 3.04s
10:53:24  INFO  reporter — Report written to: reports\example_com_run3_20260915_105320.html

  [OK]  Report saved:  reports\example_com_run3_20260915_105320.html
  [**]  Findings:      23
  [t]   Duration:      4.3s
```

---

## Testing Environment

| Component | Details |
|-----------|---------|
| Test runner | pytest 9.1.1 |
| Async support | anyio 4.11.0 (asyncio backend) |
| Network isolation | All network calls mocked via `unittest.mock` and `httpx` fakes |
| Fixture storage | `tests/fixtures/` — saved API/WHOIS responses for reproducibility |
| Python version | 3.13.7 (Windows) |

```bash
# Run the full test suite
python -m pytest tests/ -v
```

All tests run **offline** — no live DNS, WHOIS, crt.sh, or API calls are made during testing.  
Real-target validation is performed manually against a domain you control, per the Definition of Done in `implementation.md`.

### Test Coverage (as of Step 3)

| Test File | Tests | What's Covered |
|-----------|-------|----------------|
| `test_models.py` | 7 | Finding, ModuleResult, ScanResult dataclasses |
| `test_base_module.py` | 3 | Error isolation, timing, status contracts |
| `test_database.py` | 6 | SQLite upsert, scan run lifecycle, finding persistence |
| `test_reporter.py` | 6 | HTML structure, risk badges, error module display |
| `test_whois_dns_module.py` | 17 | WHOIS parsing, DNS record types, email leakage, expiry risk, NXDOMAIN, timeouts |
| `test_subdomain_module.py` | 21 | crt.sh parsing, SAN multi-value, wildcard detection, keyword classification, DNS live/dead, HTTP errors, full async run |
| **Total** | **60** | |

---

## Sample Output

The HTML report is a self-contained dark-mode page with:

- **Hero header** — target name, scan ID, start time, total duration
- **Risk summary cards** — count of High / Medium / Low / Info findings at a glance
- **Per-module tables** — each finding shows: type, value (monospace), risk badge, discovery timestamp
- **Collapsible extra data** — click "extra data" on any row to expand the raw JSON metadata
- **Error modules** — modules that failed show their error message in red rather than crashing the report

### Report layout (Step 3 example)

```
┌──────────────────────────────────────────────────────────────────┐
│  OSINT Recon Suite  ·  Recon Report — example.com               │
│  Scan #3  ·  2026-09-15 10:53 UTC  ·  Duration: 4.3s            │
├──────────┬──────────┬──────────┬──────────┬──────────────────────┤
│ Findings │  High    │  Medium  │   Low    │   Info               │
│   23     │    0     │    5     │    1     │   17                 │
├──────────────────────────────────────────────────────────────────┤
│ [whois_dns] ✓ success · 1.21s                                   │
│   whois_registrar      IANA                          info        │
│   whois_email_exposed  admin@example.com             medium ▼   │
│   dns_a                93.184.216.34                 info        │
│   dns_txt              v=spf1 include:…              info        │
│   …                                                              │
├──────────────────────────────────────────────────────────────────┤
│ [subdomain] ✓ success · 3.04s                                   │
│   subdomain  *.example.com        low    {wildcard: true}  ▼   │
│   subdomain  admin.example.com    medium {keywords:[admin]} ▼   │
│   subdomain  dev.example.com      medium {keywords:[dev]}   ▼   │
│   subdomain  vpn.example.com      medium {keywords:[vpn]}   ▼   │
│   subdomain  www.example.com      info   {live: true}       ▼   │
│   …                                                              │
└──────────────────────────────────────────────────────────────────┘
```

---

## Limitations

- **Passive only** — this tool never sends exploit traffic, attempts authentication, bypasses rate limits, or touches anything beyond public data. This is by design and will not change.
- **Rate limiting** — public sources (crt.sh, WHOIS servers) may throttle repeated queries. Basic timeout handling is in place per module; exponential backoff is on the roadmap for production use.
- **WHOIS privacy redaction** — many modern domain registrations use WHOIS privacy services; registrant name/email fields may return redacted or proxy values.
- **DNS propagation** — DNS results reflect the resolver's current view; recently changed records may not be visible yet.
- **crt.sh coverage** — Certificate Transparency only returns subdomains where a TLS certificate was issued. Subdomains using self-signed certs, internal-only names, or IP-based access will not appear.
- **Module count** — the MVP targets 7 modules. Scope is intentionally fixed; see `implementation.md` Anti-Goals.
- **PyMuPDF** — the full metadata extractor (Module 5) uses `pypdf` rather than `PyMuPDF` because the latter requires Visual Studio 2019 build tools on Windows. PDF support is fully functional; advanced rendering features are not needed for metadata extraction.
- **No GUI** — the tool is CLI-only. A local web dashboard is listed as a post-MVP enhancement.

---

## Future Improvements

> These items are documented in `implementation.md § Future Enhancements` and are **strictly post-MVP**. None will be implemented until all 7 MVP modules are complete and Zach has explicitly approved proceeding.

- **Risk scoring** — rank findings by severity instead of listing flat (exposed .git = high, subdomain = medium)
- **CLI module flags** — `--only whois_dns,subdomain` for faster partial scans once all modules are stable
- **Diff-based scanning** — compare today's scan against the last `scan_run`, highlight only what changed (new subdomain, newly exposed file)
- **Breach-check module** — query a public breach database API to flag emails tied to the target
- **Local web dashboard** — browse historical scans in a browser instead of opening individual HTML files

---

## Ethical Disclaimer

**This tool is for passive, authorised reconnaissance only.**

- Only scan domains, entities, or infrastructure that you **own** or have **explicit written permission** to test.
- This tool is designed for practice on your own domains, authorised penetration testing engagements, or clearly public test targets.
- The tool never attempts active exploitation, authentication bypass, rate-limit evasion, or CAPTCHA circumvention.
- Misuse of this tool against targets you do not have permission to test may violate computer fraud laws in your jurisdiction (e.g., CFAA in the US, Computer Misuse Act in the UK).
- The built-in confirmation prompt is intentional and should not be routinely bypassed with `--no-confirm` in production use.

---

## Group Members and Roles

| Name | Role | Responsibilities |
|------|------|-----------------|
| Zach Hallare | Lead Developer & Security Architect | Architecture design, all module development, database schema, report generation, testing strategy |

*This is a solo portfolio project.*

---

## Original Contribution

This tool was designed and built from scratch as an original portfolio project. The following elements represent novel or non-trivial contributions:

| Contribution | Description |
|--------------|-------------|
| **Modular error-isolation architecture** | `BaseModule` ABC enforces that any crashing module produces a typed `FAILED` result rather than propagating — this contract is tested and structurally enforced, not just documented. |
| **Unified data model** | `Finding → ModuleResult → ScanResult` hierarchy provides a clean, typed contract between modules and the reporting layer. Any future module gets logging, timing, and error handling for free. |
| **Longitudinal SQLite schema** | Three-table schema (`targets`, `scan_runs`, `findings`) with composite indexes designed for future diff-based scanning — not just point-in-time queries. |
| **Professional HTML report template** | Self-contained dark-mode report with risk-tiered stat cards, per-module finding tables, collapsible extra-data JSON, and monospace value display. No external runtime required to open. |
| **WHOIS expiry risk classification** | Automatically flags domains expiring within 60 days as `HIGH` risk (potential hijack vector) and within 180 days as `MEDIUM`. |
| **TXT record intelligence** | Automatically categorises SPF, DMARC, DKIM, and vendor verification tokens (Google, Microsoft, Atlassian, Stripe) from raw TXT records. |
| **Async subdomain enumeration** | Subdomain DNS validation uses `asyncio.gather` + a configurable semaphore (default: 20 concurrent queries) to keep the full crt.sh result set validation fast even for domains with hundreds of subdomains. |
| **Sensitive subdomain keyword classifier** | 50-keyword dictionary (admin, vpn, dev, git, jenkins, phpmyadmin, s3, etc.) auto-elevates matching subdomains to MEDIUM risk regardless of live/dead status. |
| **Multi-value SAN parsing** | Correctly parses crt.sh's newline-joined Subject Alternative Name fields, deduplicates across all certificate entries, and strips wildcard prefixes for canonical lookup while preserving the original value. |
| **Offline test suite** | All 63 tests run without any network calls using `unittest.mock`, async fakes, and saved fixture files — enabling fast, reproducible CI without live API dependencies. |

---

## Project Structure

```
osint-recon-suite/
├── main.py                            CLI entry point
├── requirements.txt                   Python dependencies
├── pytest.ini                         Test configuration
├── .gitignore                         Excludes .env, data/, reports/, logs
├── implementation.md                  PRD, TRD, schema, and critical path spec
├── README.md                          This file
│
├── osint_recon/
│   ├── models.py                      Shared dataclasses (Finding, ModuleResult, ScanResult)
│   ├── base_module.py                 Abstract base — auto error isolation + timing
│   ├── orchestrator.py                Pipeline driver + TRD confirmation prompt
│   ├── database.py                    SQLite persistence (3-table schema)
│   ├── reporter.py                    Jinja2 → HTML report generator
│   ├── templates/
│   │   └── report.html.j2             Dark-mode HTML report template
│   └── modules/
│       ├── mock_module.py             Fake module for pipeline smoke-testing
│       ├── whois_dns_module.py        Step 2: WHOIS + DNS recon
│       └── subdomain_module.py        Step 3: crt.sh subdomain enumeration ← NEW
│
└── tests/
    ├── conftest.py                    anyio backend fixture
    ├── fixtures/
    │   ├── whois_example_com.json     Saved WHOIS response for offline tests
    │   └── crtsh_example_com.json     Saved crt.sh response for offline tests ← NEW
    ├── test_models.py
    ├── test_base_module.py
    ├── test_database.py
    ├── test_reporter.py
    ├── test_whois_dns_module.py
    └── test_subdomain_module.py       Step 3 tests (21 tests, all offline) ← NEW
```