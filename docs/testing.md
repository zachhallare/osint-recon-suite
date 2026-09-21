# Testing

## Running the Tests

First make sure your virtual environment is active. Then run `pytest tests` in the terminal.

> All tests run fully offline so no live network calls are ever made during testing.

## Testing Environment

- **Test framework**: The tests use pytest and anyio for async support.
- **Network isolation**: All HTTP and DNS calls are mocked out.
- **Parser testing**: Real parsers like pypdf and Pillow are tested against fake files generated in memory.
- **Reproducibility**: We use saved API responses in the fixtures folder to make tests perfectly reproducible.

## Test Coverage (202 tests total)

- **test_models.py**: Covers finding, module result, scan result, and confirmation method classes.
- **test_base_module.py**: Covers error isolation, timing, and status contracts.
- **test_database.py**: Covers SQLite inserts, the scan run lifecycle, and finding persistence.
- **test_confirmation_audit.py**: Covers command-line flags and database persistence for the audit trail.
- **test_reporter.py**: Covers HTML structure, risk badges, error displays, and authorization badges.
- **test_whois_dns_module.py**: Covers parsing, record types, expiry risk, timeouts, and date formatting.
- **test_subdomain_module.py**: Covers crt.sh parsing, wildcard detection, keyword classification, and DNS checks.
- **test_company_mapper_module.py**: Covers Shodan, ipapi, reverse IP, fingerprinting, and port risks.
- **test_document_scanner_module.py**: Covers HEAD probing, size limits, risk classification, and deduplication.
- **test_metadata_extractor_module.py**: Covers PDF, Office, and image parsing, GPS conversion, and extension detection.
- **test_social_media_module.py**: Covers slug derivation, platform probing, the GitHub API, and repo detection.
- **test_breach_module.py**: Covers missing API keys, rate limiting, and risk scoring.
- **test_cli.py**: Covers argument parsing, the interactive menu, mock mode, and flag combinations.
- **test_orchestrator.py**: Covers module concurrency, error isolation, finding diffs, and partial scans.
- **test_resolvers.py**: Covers target resolution, company to domain mapping, and ambiguity errors.
- **test_scoring.py**: Covers base risk mapping, port risks, breach date scoring, and CVE escalation.
