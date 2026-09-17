# Project Structure

```
osint-recon-suite/
│
│  Root files
│
├── main.py                 Entry point. Parses CLI args, imports modules, calls the orchestrator.
├── requirements.txt        All Python dependencies (pip install -r requirements.txt).
├── pytest.ini              Configures pytest to use asyncio backend. Required for async tests.
├── .gitignore              Excludes secrets (.env), reports, databases, and caches from git.
├── README.md               Project overview and quickstart.
│
│  scripts/                 Launchers and uninstallers — kept out of the repo root.
│
├── scripts/
│   ├── run.sh              Bootstrap launcher for Linux and macOS.
│   ├── run.command         macOS Finder double-click launcher (opens Terminal automatically).
│   ├── run.bat             Windows double-click or CMD/PowerShell launcher.
│   ├── uninstall.sh        Interactive uninstaller for Linux and macOS.
│   ├── uninstall.command   macOS Finder double-click uninstaller.
│   └── uninstall.bat       Windows interactive uninstaller.
│
│  docs/                    All documentation — kept out of the repo root.
│
└── docs/
    ├── cover.jpg                    README hero banner image.
    ├── how-to-run.md                Full OS-specific setup guide.
    ├── features.md                  Module list, architecture, sample output, limitations.
    ├── testing.md                   Test coverage table and how to run tests.
    ├── original-contribution.md     Novel design decisions and implementations.
    └── project-structure.md         This file.


osint_recon/                The main Python package.
│
├── models.py               Shared data structures & enums:
│                             Finding            — one piece of intelligence (type, value, risk, extras).
│                             ModuleResult       — what a module returns: status, findings, duration.
│                             ScanResult         — wraps all ModuleResults from a complete run.
│                             ConfirmationMethod — INTERACTIVE, BYPASSED, or MOCK authorization enum.
│
├── base_module.py          Abstract base class all recon modules inherit from.
│                           Handles try/except boundary, timing, and logging automatically.
│
├── console.py              Rich terminal UI utilities: stylized banner, animated progress bars,
│                           streamlined findings summary table, and scan footer with auth badge.
│
├── orchestrator.py         Runs each module in sequence, persists results, triggers the reporter.
│                           Shows the confirmation prompt before any network calls are made.
│
├── database.py             SQLite interface — three tables:
│                             targets    — one row per domain scanned.
│                             scan_runs  — one row per execution (including confirmation_method audit trail).
│                             findings   — every Finding from every run.
│
├── reporter.py             Loads the Jinja2 template and writes the self-contained HTML report.
│
├── templates/
│   └── report.html.j2      Dark-mode HTML report template with risk cards, collapsible rows, and auth badge.
│
└── modules/
    ├── mock_module.py                Returns synthetic findings for offline pipeline testing.
    ├── whois_dns_module.py           WHOIS + DNS recon (A, AAAA, MX, NS, TXT, CNAME, SOA).
    ├── subdomain_module.py           crt.sh CT log enumeration + async DNS validation.
    ├── company_mapper_module.py      Shodan InternetDB, ipapi.co, shared hosting, tech stack.
    ├── document_scanner_module.py    HEAD probing of 60+ sensitive paths.
    ├── metadata_extractor_module.py  PDF/Office/image metadata extraction.
    └── social_media_module.py        15+ platform probing + GitHub API enrichment.


tests/                      All unit tests — fully offline, no live network calls.
│
├── conftest.py             Configures anyio asyncio backend for all async tests.
├── fixtures/               Pre-saved real API responses used instead of live calls.
│   ├── whois_example_com.json
│   ├── crtsh_example_com.json
│   ├── shodan_internetdb_93_184_216_34.json
│   └── ipapi_93_184_216_34.json
│
├── test_models.py
├── test_base_module.py
├── test_database.py
├── test_confirmation_audit.py
├── test_reporter.py
├── test_whois_dns_module.py
├── test_subdomain_module.py
├── test_company_mapper_module.py
├── test_document_scanner_module.py
├── test_metadata_extractor_module.py
└── test_social_media_module.py
```
