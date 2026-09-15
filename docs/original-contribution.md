# Original Contributions

This document catalogues the novel design decisions and implementations in OSINT Recon Suite that go beyond assembling existing libraries.

| Contribution | Description |
|--------------|-------------|
| Modular error-isolation architecture | BaseModule ABC structurally enforces that any crashing module produces a typed FAILED result rather than propagating an exception. This contract is tested, not just documented. |
| Unified data model | Finding → ModuleResult → ScanResult hierarchy provides a typed contract between modules and the reporting layer. Any new module gets logging, timing, and error handling for free. |
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
