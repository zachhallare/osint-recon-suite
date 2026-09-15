# OSINT Recon Suite

## Tool Name

**OSINT Recon Suite** — a modular, passive open-source intelligence (OSINT) reconnaissance tool.

---

## Description

OSINT Recon Suite is a command-line Python application that automates the passive recon phase of a security assessment. Given a single target (domain name or entity), it queries multiple public sources — WHOIS registries, DNS resolvers, certificate transparency logs, Shodan's free InternetDB, publicly accessible file paths, and social media platforms — and consolidates all findings into a single, professional HTML risk report.

---

## Purpose

- Automate the manual OSINT phase: WHOIS/DNS lookups, subdomain discovery, attack surface mapping, exposed document scanning, file metadata extraction, and social media footprint — all in one command.
- Produce a single consolidated output (HTML report) that reads like an actual recon deliverable rather than raw terminal output.
- Enable module-level isolation — each recon module can fail independently without crashing the full suite.
- Serve as a portfolio project demonstrating security tooling, modular Python architecture, SQLite persistence, and professional reporting.

---

## Features

### Implemented Modules (MVP Complete)

| Step | Module | What It Does |
|------|--------|--------------|
| 1 | Orchestrator + Report Shell | Pipeline driver; dark-mode HTML report with risk stat cards; SQLite persistence |
| 2 | WHOIS / DNS Recon | WHOIS lookup, A/AAAA/MX/NS/TXT/CNAME/SOA records; expiry risk classification; SPF/DMARC/DKIM detection; email leakage flagging |
| 3 | Subdomain Enumerator | Certificate Transparency via crt.sh; async DNS validation of live subdomains; 50-keyword sensitive name classifier |
| 4 | Company Attack Surface Mapper | Shodan InternetDB (open ports, CVEs, CPEs); IP geolocation and ASN via ipapi.co; reverse IP shared-hosting detection; MX/NS technology stack fingerprinting |
| 5a | Document Exposure Scanner | Concurrent async HEAD probing of 60+ sensitive paths (.git, .env, DB dumps, config files, deployment files, logs); deduplication across HTTPS/HTTP |
| 5b | Metadata Extractor | Downloads exposed PDF/Office/image files; extracts author, creator, internal usernames, company name, GPS coordinates (HIGH risk), software version |
| 6 | Social Media OSINT Collector | Probes 15+ platforms (GitHub, LinkedIn, Twitter/X, Instagram, Reddit, YouTube, Facebook, Keybase, Telegram, npmjs, PyPI, Docker Hub, Medium, HackerNews); GitHub API enrichment for org repos, stars, languages, and sensitive repo detection |

### Architecture

- **Error isolation**: each module runs inside a typed try/except boundary; a crashing module returns a FAILED result without affecting the others.
- **Persistent storage**: all findings stored in a local SQLite database with composite indexes, enabling future diff-based scanning.
- **Async concurrency**: subdomain DNS validation, document scanning, metadata downloading, and social media probing all use asyncio with configurable semaphore limits.
- **No paid API keys required**: all six modules use free, public endpoints.
- **Report-first design**: the Jinja2 HTML template was built before any real modules; every module plugs into a proven output pipeline.

---

## System Requirements

| Requirement | Version |
|-------------|---------|
| Python | 3.11 or higher (tested on 3.13.7) |
| Operating System | Kali Linux, Ubuntu 20.04+, Debian, Windows 10/11, macOS 12+ |
| Network | Internet access for live scans; none required for --mock mode or tests |
| Disk | ~75 MB for dependencies plus database and downloaded file cache |

> **Run Guide:** For a dedicated, OS-specific guide (with step-by-step instructions for Kali Linux, Ubuntu, macOS, Windows, and headless servers), see **[HOW_TO_RUN.md](HOW_TO_RUN.md)**.


---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/zachhallare/osint-recon-suite.git
cd osint-recon-suite

# 2. Create and activate a virtual environment
python -m venv venv

# Windows:
venv\Scripts\activate

# macOS / Linux:
source venv/bin/activate

# 3. Install all dependencies
pip install -r requirements.txt
```

If you add paid API sources later (for example a full Shodan key), create a `.env` file in the project root. It is gitignored and will never be committed:

```
# .env
# SHODAN_API_KEY=your_key_here
```

---

## Usage

```bash
# Full suite run — confirmation prompt before any network calls
python main.py yourdomain.com

# Mock mode — no network calls; exercises the full pipeline with synthetic data
python main.py yourdomain.com --mock

# Skip the interactive confirmation prompt (for CI or scripted runs)
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
11:18:00  INFO  orchestrator — Modules: [whois_dns, subdomain, company_mapper,
                                          document_scanner, metadata_extractor, social_media]
11:18:01  INFO  base_module  — [whois_dns]          Finished —  9 finding(s) in  1.2s
11:18:04  INFO  base_module  — [subdomain]           Finished — 14 finding(s) in  3.0s
11:18:07  INFO  base_module  — [company_mapper]      Finished — 12 finding(s) in  2.9s
11:18:10  INFO  base_module  — [document_scanner]    Finished —  4 finding(s) in  3.1s
11:18:12  INFO  base_module  — [metadata_extractor]  Finished —  6 finding(s) in  2.0s
11:18:15  INFO  base_module  — [social_media]        Finished —  8 finding(s) in  3.2s

  Report saved:  reports\example_com_run6_20260915_111800.html
  Findings:      53
  Duration:      15.4s
```

---

## Testing Environment

| Component | Details |
|-----------|---------|
| Test runner | pytest 9.1.1 |
| Async support | anyio 4.11.0 (asyncio backend) |
| Network isolation | All HTTP and DNS calls mocked; real pypdf, python-docx, and Pillow used against in-memory synthetic blobs |
| Fixture storage | tests/fixtures/ — saved API responses for reproducibility |
| Python version | 3.13.7 (Windows) |

```bash
python -m pytest tests/ -v
```

All 149 tests run offline — no live DNS, WHOIS, crt.sh, Shodan, ipapi.co, GitHub, or social media calls are made during testing.

### Test Coverage (as of Step 6 — MVP Complete)

| Test File | Tests | What Is Covered |
|-----------|-------|----------------|
| test_models.py | 7 | Finding, ModuleResult, ScanResult dataclasses |
| test_base_module.py | 3 | Error isolation, timing, status contracts |
| test_database.py | 6 | SQLite upsert, scan run lifecycle, finding persistence |
| test_reporter.py | 6 | HTML structure, risk badges, error module display |
| test_whois_dns_module.py | 17 | WHOIS parsing, DNS record types, expiry risk, NXDOMAIN, timeouts |
| test_subdomain_module.py | 21 | crt.sh parsing, SAN multi-value fields, wildcard detection, keyword classification, DNS live/dead |
| test_company_mapper_module.py | 26 | Shodan InternetDB, ipapi.co, reverse IP, MX/NS fingerprinting, port risk |
| test_document_scanner_module.py | 12 | HEAD probing, size-limit enforcement, risk classification, HTTPS/HTTP deduplication |
| test_metadata_extractor_module.py | 15 | PDF/Office/image parsing, GPS decimal conversion, download size and timeout guard |
| test_social_media_module.py | 24 | Slug derivation, platform probing, HackerNews null-body edge case, GitHub API enrichment, sensitive repo detection, org/user fallback |
| **Total** | **137** | |

---

## Sample Output

The HTML report is a self-contained dark-mode page with:

- Hero header: target name, scan ID, start time, total duration
- Risk summary cards: count of High / Medium / Low / Info findings at a glance
- Per-module tables: finding type, value displayed in monospace, risk badge, discovery timestamp
- Collapsible extra data: expand any finding row to see the raw JSON metadata
- Error modules: modules that failed display their error message in red; the report always renders completely

### Finding examples from a full run

```
[whois_dns]
  whois_email_exposed    admin@example.com         MEDIUM
  whois_expiry           2026-10-01                HIGH   (expires < 60 days)
  dns_txt                v=spf1 include:...        INFO

[subdomain]
  subdomain              *.example.com             LOW    (wildcard cert)
  subdomain              admin.example.com         MEDIUM (sensitive keyword)
  subdomain              vpn.example.com           MEDIUM (sensitive keyword)

[company_mapper]
  open_port              93.184.216.34:6379        HIGH   (Redis exposed)
  known_cve              CVE-2023-44487 on...      HIGH
  ip_geolocation         93.184.216.34 -> LA, CA   INFO

[document_scanner]
  git_exposure           https://example.com/.git/HEAD    HIGH
  env_file               https://example.com/.env         HIGH
  php_info               https://example.com/phpinfo.php  MEDIUM

[metadata_extractor]
  pdf_author             Jane Smith                        MEDIUM
  office_last_modified   jdoe                              MEDIUM (internal username)
  image_gps_coordinates  51.507400, -0.127800              HIGH   (location leak)

[social_media]
  social_profile         https://github.com/example        MEDIUM
  github_email           oss@example.com                   MEDIUM
  github_sensitive_repo  https://github.com/example/terraform-infra  HIGH
  social_profile         https://www.linkedin.com/company/example    MEDIUM
```

---

## Limitations

- **Passive only**: this tool never sends exploit traffic, attempts authentication, bypasses rate limits, or touches anything beyond publicly accessible data.
- **Rate limiting**: free-tier APIs (HackerTarget, ipapi.co, GitHub unauthenticated at 60 req/hr) impose daily or per-hour limits. The tool handles all rate-limit errors gracefully per module.
- **Social media platform blocks**: some platforms (Instagram, Facebook) aggressively block non-browser user agents even for public profiles. False negatives are expected.
- **Shodan InternetDB**: covers only IPs that Shodan has previously scanned. Recently provisioned IPs may not appear.
- **Document scanner false positives**: a path returning HTTP 200 may serve a custom 404 page. Content-Type and Content-Length are checked, but full body validation is a post-MVP enhancement.
- **WHOIS privacy redaction**: many domain registrations use privacy proxies; registrant contact fields may be redacted.
- **crt.sh coverage**: only finds subdomains that had a public TLS certificate issued. Internal-only names, wildcard-only certs, or self-signed certs will not appear.
- **Metadata extraction**: only analyses files with recognised extensions (PDF, DOCX, XLSX, JPEG, PNG, TIFF). Unusual content types require the URL to have a matching extension.
- **pypdf vs PyMuPDF**: uses pure-Python pypdf to avoid the Visual Studio 2019 C compiler requirement on Windows. PDF metadata extraction is fully functional.
- **No GUI**: the tool is CLI-only. A local web dashboard is listed as a post-MVP enhancement.

---

## Future Improvements

These items are documented in implementation.md under Future Enhancements and are strictly post-MVP. None will be implemented until all six MVP modules have passed their Definition of Done and have been explicitly approved.

- Risk scoring: rank findings by severity instead of listing flat; an exposed .git repo should sort above a robots.txt entry.
- CLI module flags: --only whois_dns,subdomain for faster partial scans.
- Diff-based scanning: compare today's scan against the last scan_run in the database; surface only what changed (new subdomain, newly exposed file, new CVE).
- Breach-check module: query a public breach database API to flag email addresses tied to the target domain.
- Local web dashboard: browse historical scans in a browser instead of opening individual HTML files.

---

## Ethical Disclaimer

This tool is for passive, authorised reconnaissance only.

- Only scan domains, entities, or infrastructure that you own or have explicit written permission to test.
- The document scanner and social media module send real HTTP requests to the target and to third-party platforms. Ensure you have permission before running these against any live target.
- The tool never attempts active exploitation, authentication bypass, rate-limit evasion, or CAPTCHA circumvention.
- Misuse of this tool against targets you do not have permission to test may violate computer fraud laws in your jurisdiction (for example the Computer Fraud and Abuse Act in the United States or the Computer Misuse Act in the United Kingdom).
- The built-in interactive confirmation prompt is intentional and should not be routinely bypassed with --no-confirm in production use.

---

## Group Members and Roles

| Name | Role | Responsibilities |
|------|------|-----------------|
| Zach Hallare | Lead Developer and Security Architect | Architecture design, all module development, database schema, report generation, testing strategy |

This is a solo portfolio project.

---

## Original Contribution

| Contribution | Description |
|--------------|-------------|
| Modular error-isolation architecture | BaseModule ABC structurally enforces that any crashing module produces a typed FAILED result rather than propagating an exception. This contract is tested, not just documented. |
| Unified data model | Finding to ModuleResult to ScanResult hierarchy provides a typed contract between modules and the reporting layer. Any new module gets logging, timing, and error handling for free. |
| Longitudinal SQLite schema | Three-table schema with composite indexes, designed from the start for future diff-based scanning rather than just point-in-time queries. |
| Professional HTML report template | Self-contained dark-mode report with risk-tiered stat cards, per-module finding tables, collapsible JSON metadata expansion, and monospace value display. No runtime dependencies to open. |
| WHOIS expiry risk classification | Automatically flags domains expiring within 60 days as HIGH risk (potential domain hijack vector) and within 180 days as MEDIUM. |
| TXT record intelligence | Automatically categorises SPF, DMARC, DKIM, and vendor-specific verification tokens (Google, Microsoft, Atlassian, Stripe) from raw DNS TXT records. |
| Async subdomain enumeration | asyncio.gather plus a configurable semaphore (default 20 concurrent queries) keeps the full crt.sh result set validation fast even for domains with hundreds of subdomains. |
| Sensitive subdomain keyword classifier | A 50-keyword dictionary (admin, vpn, dev, git, jenkins, phpmyadmin, s3, etc.) automatically elevates matching subdomains to MEDIUM risk. |
| Multi-value SAN parsing | Correctly deduplicates and parses newline-joined Subject Alternative Name fields returned by crt.sh, which other tools commonly mishandle. |
| Shodan InternetDB port risk engine | Classifies open ports as HIGH (Redis, MongoDB, Docker API, Elasticsearch, etc.), MEDIUM (SSH, SMTP, alternate web ports), or LOW (other), without requiring a paid Shodan API key. |
| Technology stack fingerprinting | Detects email provider (Google Workspace, Microsoft 365, Proofpoint, Mimecast, Zoho, SendGrid, etc.) and DNS provider (Cloudflare, Route 53, Azure DNS, etc.) purely from MX and NS DNS records. |
| Shared hosting detection | Flags IPs hosting multiple co-located domains as LOW risk with a co-hosted domain sample, because a compromise of any co-hosted site could affect the same IP. |
| 60-path document exposure scanner | Concurrent async HEAD probing for .git, .env, DB dumps, config files, deployment files, and logs; deduplicates across HTTPS and HTTP; enforces TRD-specified 15-second timeout and 10 MB size limit. |
| PDF metadata extraction | Extracts author (MEDIUM risk), creator/modified-date (LOW), producer and title (INFO) from PDF XMP and Info dictionaries using pypdf. |
| Office document metadata extraction | Extracts author and last-modified-by username (MEDIUM risk, may reveal internal Active Directory usernames), company name from OOXML core properties XML (LOW), and revision number (INFO). |
| Image EXIF and GPS extraction | Extracts GPS coordinates (HIGH risk, physical location leakage with Google Maps link in metadata), camera make and model, software, and artist from JPEG, PNG, and TIFF EXIF data via Pillow; converts DMS tuples to decimal degrees. |
| Social media slug derivation | Derives candidate usernames from the target domain, including hyphen-stripped variants, to maximise platform hit rate across services with different username policies. |
| GitHub enrichment without an API key | Uses the unauthenticated GitHub API (60 req/hr) to retrieve org or user entity data, public repo count, stars, language distribution, and exposed email addresses, all parsed into typed findings. |
| Sensitive GitHub repo classifier | A 50-keyword dictionary (terraform, ansible, infra, secrets, kubernetes, deploy, credentials, production, etc.) automatically flags matching public repos as HIGH risk. |
| Offline test suite | All 137 tests run without any network calls, using unittest.mock, async fake HTTP clients, and saved fixture files. Real pypdf, python-docx, and Pillow are exercised against in-memory synthetic file blobs, providing genuine parser coverage without live downloads. |

---

## Project Structure

```
osint-recon-suite/
│
│  Root files
│
├── main.py                 Entry point. Parses CLI args, imports modules, calls the orchestrator.
├── requirements.txt        Lists every Python package that must be installed (pip install -r requirements.txt).
├── pytest.ini              Tells pytest to use asyncio as the event loop backend. Required for async tests.
├── .gitignore              Prevents secrets (.env), reports, databases, and cache from being committed to git.
├── implementation.md       The original spec: PRD, TRD, database schema, and 6-step critical path.
└── README.md               This file.

osint_recon/                The main Python package — all production code lives here.
│
├── models.py               Defines the three shared data structures used across the whole project:
│                             Finding      — a single piece of intelligence (type, value, risk level, extras).
│                             ModuleResult — what a module returns: status, list of Findings, duration.
│                             ScanResult   — wraps all ModuleResults from a complete run.
│
├── base_module.py          Abstract base class that every recon module inherits from.
│                           Handles the try/except boundary so a crashing module never kills the run.
│                           Also records start/end time and logs progress automatically.
│
├── orchestrator.py         Runs each module in sequence, collects results, saves them to the database,
│                           and hands the final ScanResult to the reporter.
│                           Also shows the confirmation prompt before any network calls are made.
│
├── database.py             SQLite interface. Three tables:
│                             targets    — one row per domain ever scanned.
│                             scan_runs  — one row per execution (start time, end time, status).
│                             findings   — every Finding from every run, indexed for fast retrieval.
│
├── reporter.py             Loads the Jinja2 template and writes the self-contained HTML report file.
│
├── templates/
│   └── report.html.j2      The HTML report template. Dark-mode layout with risk stat cards,
│                           per-module finding tables, collapsible JSON metadata, and risk badges.
│
└── modules/
    ├── mock_module.py              Returns fake findings so the full pipeline can be tested end-to-end
    │                               without any network calls (used with --mock flag).
    │
    ├── whois_dns_module.py         Queries WHOIS and DNS (A, AAAA, MX, NS, TXT, CNAME, SOA).
    │                               Flags near-expiry domains, exposed registrant emails, SPF/DMARC/DKIM.
    │
    ├── subdomain_module.py         Pulls subdomains from certificate transparency logs (crt.sh),
    │                               then validates each one live with async DNS. Flags sensitive names
    │                               (admin, vpn, dev, git, jenkins, etc.) as MEDIUM risk.
    │
    ├── company_mapper_module.py    Maps the attack surface for each IP the target resolves to.
    │                               Uses Shodan InternetDB (ports, CVEs), ipapi.co (geo/ASN),
    │                               HackerTarget (shared hosting), and MX/NS fingerprinting (tech stack).
    │
    ├── document_scanner_module.py  Sends HTTP HEAD requests to 60+ known sensitive paths
    │                               (.git/HEAD, .env, backup.sql, phpinfo.php, Dockerfile, etc.)
    │                               and flags any that return HTTP 200 as an exposure.
    │
    ├── metadata_extractor_module.py Downloads publicly accessible documents and extracts hidden metadata:
    │                               PDF author/creator/dates, Office author/username/company,
    │                               image GPS coordinates (flags as HIGH risk), camera make, software.
    │
    └── social_media_module.py      Derives username slugs from the domain and checks 15+ platforms
                                    (GitHub, LinkedIn, Twitter/X, Instagram, Reddit, YouTube, etc.).
                                    If a GitHub org/user is found, fetches repos and flags any with
                                    names matching a sensitive keyword list (infra, secrets, terraform, etc.)
                                    as HIGH risk.

tests/                      All unit tests. Every test runs fully offline — no live network calls.
│
├── conftest.py             Sets the anyio event loop backend to asyncio for all async tests.
│                           Without this file, every async test fails with "no event loop" error.
│
├── fixtures/               Pre-saved real API responses used by tests instead of live calls.
│   ├── whois_example_com.json              Saved python-whois result for example.com
│   ├── crtsh_example_com.json              Saved crt.sh certificate transparency response
│   ├── shodan_internetdb_93_184_216_34.json Saved Shodan InternetDB result for 93.184.216.34
│   └── ipapi_93_184_216_34.json            Saved ipapi.co geolocation result for 93.184.216.34
│
├── test_models.py              Verifies Finding, ModuleResult, and ScanResult behave correctly.
├── test_base_module.py         Verifies the error-isolation contract: a crash inside a module
│                               produces a FAILED result, not an unhandled exception.
├── test_database.py            Verifies SQLite upsert, scan run lifecycle, and finding persistence.
├── test_reporter.py            Verifies the HTML report contains correct structure and risk badges.
├── test_whois_dns_module.py    Tests WHOIS parsing, all DNS record types, expiry risk, and error paths.
├── test_subdomain_module.py    Tests crt.sh parsing, SAN multi-value fields, DNS live/dead detection,
│                               and the keyword risk classifier.
├── test_company_mapper_module.py Tests Shodan port/CVE parsing, geo/ASN, reverse IP, fingerprinting,
│                               and port risk classification.
├── test_document_scanner_module.py Tests HTTP probing (200/404), size-limit enforcement,
│                               risk levels per path category, and HTTPS/HTTP deduplication.
├── test_metadata_extractor_module.py Tests PDF metadata (pypdf), Office metadata (python-docx),
│                               image EXIF (Pillow), GPS decimal conversion, and download guards.
└── test_social_media_module.py Tests slug derivation, platform probing, HackerNews null-body edge case,
                                GitHub API enrichment, sensitive repo detection, and org/user fallback.
```