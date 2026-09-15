# Testing

## Running the Tests

```bash
# Ensure virtual environment is active first
python -m pytest tests/ -v
```

All tests run **fully offline** — no live DNS, WHOIS, crt.sh, Shodan, ipapi.co, GitHub, or social media calls are made during testing.

---

## Testing Environment

| Component | Details |
|-----------|---------|
| Test runner | pytest 8.2.2 |
| Async support | anyio / pytest-asyncio (asyncio backend) |
| Network isolation | All HTTP and DNS calls mocked; real pypdf, python-docx, and Pillow used against in-memory synthetic blobs |
| Fixture storage | `tests/fixtures/` — saved API responses for reproducibility |
| Python version | 3.13.7 (Windows) |

---

## Test Coverage (MVP Complete — 137 tests)

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
