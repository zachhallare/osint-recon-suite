# Features & Architecture

## Implemented Modules (MVP Complete)

| Step | Module | What It Does |
|------|--------|--------------|
| 1 | Orchestrator + Report Shell | Pipeline driver; dark-mode HTML report with risk stat cards; SQLite persistence |
| 2 | WHOIS / DNS Recon | WHOIS lookup, A/AAAA/MX/NS/TXT/CNAME/SOA records; expiry risk classification; SPF/DMARC/DKIM detection; email leakage flagging |
| 3 | Subdomain Enumerator | Certificate Transparency via crt.sh; async DNS validation of live subdomains; 50-keyword sensitive name classifier |
| 4 | Company Attack Surface Mapper | Shodan InternetDB (open ports, CVEs, CPEs); IP geolocation and ASN via ipapi.co; reverse IP shared-hosting detection; MX/NS technology stack fingerprinting |
| 5a | Document Exposure Scanner | Concurrent async HEAD probing of 60+ sensitive paths (.git, .env, DB dumps, config files, deployment files, logs); deduplication across HTTPS/HTTP |
| 5b | Metadata Extractor | Downloads exposed PDF/Office/image files; extracts author, creator, internal usernames, company name, GPS coordinates (HIGH risk), software version |
| 6 | Social Media OSINT Collector | Probes 15+ platforms (GitHub, LinkedIn, Twitter/X, Instagram, Reddit, YouTube, Facebook, Keybase, Telegram, npmjs, PyPI, Docker Hub, Medium, HackerNews); GitHub API enrichment for org repos, stars, languages, and sensitive repo detection |

---

## Architecture

- **Error isolation**: each module runs inside a typed try/except boundary; a crashing module returns a FAILED result without affecting the others.
- **Persistent storage**: all findings stored in a local SQLite database with composite indexes, enabling future diff-based scanning.
- **Authorization audit trail**: every scan records how it was initiated (`interactive`, `bypassed`, or `mock`) into SQLite `scan_runs.confirmation_method`. Unattended runs via `--no-confirm` leave a clear forensic log, while `--mock` runs are safely distinguished from live engagements.
- **Streamlined Rich terminal UI**: animated progress indicators show active module execution without terminal clutter; scan completion displays a concise findings summary table and execution footer with color-coded authorization status.
- **Flexible reporting pipeline**: interactive prompt or explicit CLI flags (`--html`, `--no-html`) allow operators to choose between rapid CLI-only triage and full HTML report generation.
- **Async concurrency**: subdomain DNS validation, document scanning, metadata downloading, and social media probing all use asyncio with configurable semaphore limits.
- **No paid API keys required**: all six modules use free, public endpoints.
- **Report-first design**: the Jinja2 HTML template was built before any real modules; every module plugs into a proven output pipeline.

---

## Sample Output

The HTML report is a self-contained dark-mode page with:

- Hero header: target name, scan ID, start time, total duration, and styled **Authorization Badge** (`INTERACTIVE`, `BYPASSED`, or `MOCK`)
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
- **Shodan InternetDB data freshness**: queries Shodan's free InternetDB API, which acts as a passive historical cache. Open ports and vulnerabilities reflect past scan observations and may be stale or have false negatives compared to active network port scans.
- **crt.sh availability**: relies on public Certificate Transparency logs via crt.sh. The service can experience intermittent rate limiting (HTTP 429) or latency during peak usage, and only exposes domains with issued public TLS certificates.
- **Document scanner false positives**: a path returning HTTP 200 may serve a custom 404 page. Content-Type and Content-Length are checked, but full body validation is a post-MVP enhancement.
- **WHOIS privacy redaction**: many domain registrations use privacy proxies; registrant contact fields may be redacted.
- **Metadata extraction**: only analyses files with recognised extensions (PDF, DOCX, XLSX, JPEG, PNG, TIFF). Unusual content types require the URL to have a matching extension.
- **pypdf vs PyMuPDF**: uses pure-Python pypdf to avoid the Visual Studio 2019 C compiler requirement on Windows. PDF metadata extraction is fully functional.
- **No GUI**: the tool is CLI-only with an interactive Rich interface and standalone HTML reports. A local web dashboard is listed as a post-MVP enhancement.
