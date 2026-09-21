# Original Contributions

This file highlights the custom work and design choices in OSINT Recon Suite that go beyond just connecting existing libraries.

- **Modular error isolation**: The base module is set up so that if any module crashes it returns a failed status instead of breaking the whole program. This contract is heavily tested.
- **Unified data model**: Findings flow directly into module results and then into scan results. This means any new module automatically gets logging, timing, and error handling built in.
- **Longitudinal SQLite schema**: The database uses three tables and was designed from the start to handle diff-based scanning over time instead of just single point-in-time checks.
- **Professional HTML report**: The tool generates a standalone dark-mode report with risk stat cards, per-module finding tables, a JSON viewer, and monospace formatting. You do not need any external dependencies to open it.
- **WHOIS expiry risk classification**: The tool automatically flags domains expiring within 60 days as high risk and within 180 days as medium risk to catch potential hijack vectors.
- **TXT record intelligence**: It automatically pulls and categorizes SPF, DMARC, DKIM, and vendor tokens directly from raw DNS TXT records.
- **Async subdomain enumeration**: Using asyncio gather with a custom limit keeps the crt.sh scraping fast even for targets with hundreds of subdomains.
- **Sensitive subdomain keyword classifier**: A custom dictionary of 50 keywords automatically elevates matching subdomains to medium risk.
- **60-path document exposure scanner**: It uses concurrent async HEAD probes to find exposed logs, databases, and config files while deduplicating across HTTP and HTTPS and enforcing a strict size limit.
- **PDF metadata extraction**: It extracts author, creator, and timestamp metadata from PDF files using pypdf and assigns risk levels accordingly.
- **Office document metadata extraction**: It pulls author and revision data from OOXML core properties which can sometimes leak internal Active Directory usernames.
- **Image EXIF and GPS extraction**: It extracts GPS coordinates, camera models, and software from image EXIF data and converts them to decimal degrees.
- **Social media slug derivation**: It generates potential usernames from the target domain including stripped variants to maximize the hit rate across different platforms.
- **GitHub enrichment without an API key**: It hits the unauthenticated GitHub API to pull repository stats, language data, and exposed emails, and parses them into typed findings.
- **Sensitive GitHub repo classifier**: A 50-keyword dictionary automatically flags public repos matching words like terraform or secrets as high risk.
- **Offline test suite**: All 162 tests run entirely offline without network calls by using fake async clients and saved files. This tests the actual parsers safely against in-memory synthetic file blobs.
- **Scan authorization audit trail**: Every single scan logs exactly how it was authorized into the database. This shows up in the terminal and the final report so you always have a clear record.
- **Dual-tier operational interface**: The tool provides a fast terminal interface for quick checks and a detailed HTML report for full audits covering both use cases.
