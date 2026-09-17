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

## Test Coverage (162 tests)

| Test File | Tests | What Is Covered |
|-----------|-------|----------------|
| test_models.py | 8 | Finding, ModuleResult, ScanResult dataclasses, ConfirmationMethod enum |
| test_base_module.py | 4 | Error isolation, timing, status contracts |
| test_database.py | 6 | SQLite upsert, scan run lifecycle, finding persistence |
| test_confirmation_audit.py | 16 | CLI flag derivation, --mock vs --no-confirm precedence, confirmation_method DB persistence, legacy schema migration |
| test_reporter.py | 6 | HTML structure, risk badges, error module display, auth badge rendering |
| test_whois_dns_module.py | 19 | WHOIS parsing, DNS record types, expiry risk, NXDOMAIN, timeouts, date normalization |
| test_subdomain_module.py | 21 | crt.sh parsing, SAN multi-value fields, wildcard detection, keyword classification, DNS live/dead |
| test_company_mapper_module.py | 26 | Shodan InternetDB, ipapi.co, reverse IP, MX/NS fingerprinting, port risk |
| test_document_scanner_module.py | 12 | HEAD probing, size-limit enforcement, risk classification, HTTPS/HTTP deduplication |
| test_metadata_extractor_module.py | 23 | PDF/Office/image parsing, GPS decimal conversion, download size and timeout guard, extension detection |
| test_social_media_module.py | 21 | Slug derivation, platform probing, HackerNews null-body edge case, GitHub API enrichment, sensitive repo detection, org/user fallback |
| **Total** | **162** | |
