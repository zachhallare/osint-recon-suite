# Features and Architecture

## Implemented Modules

1. **Orchestrator and report shell**
   Drives the pipeline, generates the dark-mode HTML report, and handles the SQLite database.
2. **WHOIS and DNS recon**
   Runs WHOIS lookups, pulls DNS records, flags expiry risks, detects SPF, DMARC, DKIM, and finds exposed emails.
3. **Subdomain enumerator**
   Pulls Certificate Transparency logs from crt.sh, validates live subdomains asynchronously, and flags sensitive keywords.
4. **Company attack surface mapper**
   Uses Shodan InternetDB for open ports and CVEs, grabs IP geolocation from ipapi.co, and fingerprints MX and NS servers.
5. **Document exposure scanner**
   Concurrently probes over 60 sensitive paths like git folders and env files while deduplicating requests and enforcing size limits.
6. **Metadata extractor**
   Downloads exposed PDF, Office, and image files to extract authors, internal usernames, software versions, and GPS coordinates.
7. **Social media OSINT collector**
   Probes over 15 platforms to find profiles and hits the unauthenticated GitHub API to find organization repos and flag sensitive code.
8. **Breach check**
   Passively collects emails found during the scan and checks them against the Have I Been Pwned API.

## Architecture

- **Error isolation**: Each module runs inside a safe boundary so if one crashes it just returns a failed result without stopping the scan.
- **Persistent storage**: All findings go into a local SQLite database designed for future diff-based scanning.
- **Authorization audit trail**: Every scan records how it was started so you know exactly if it was interactive, bypassed, or just a mock test run.
- **Streamlined terminal interface**: Animated progress bars show you what is running without cluttering the screen and give you a clean summary at the end.
- **Flexible reporting**: You can choose between quick terminal output or generating a full HTML report using command-line flags.
- **Async concurrency**: Network requests like DNS validation and document downloading all run concurrently to save time.
- **No paid API keys required**: The first seven modules use completely free public endpoints. Only the optional breach check module requires an API key.
- **Report-first design**: The HTML output template was built before any of the modules so every module plugs perfectly into a proven system.

## Sample Output

The HTML report is a self-contained dark-mode page that you can open anywhere without needing a server.
- It includes a header with the scan details and the authorization status.
- It shows risk summary cards counting high, medium, low, and info findings.
- Every module gets its own table showing the finding type, value, risk level, and timestamp.
- You can click on any finding to see the raw JSON data behind it.
- If a module fails its error message is shown clearly in red.

## Limitations

- This tool is strictly passive and never sends exploit traffic or bypasses rate limits.
- Free-tier APIs have usage limits so you might see errors if you run it too much.
- Some social media platforms block non-browser requests so false negatives happen.
- Shodan InternetDB data is historical and might not perfectly match a live port scan right now.
- crt.sh can sometimes be slow or rate limit you during busy times.
- A document path might return a successful status code but actually serve a custom error page.
- Domain registrations often hide behind privacy proxies so WHOIS data might be redacted.
- Metadata extraction only works on known file extensions.
- There is no GUI right now it is strictly a command-line tool with HTML reports.
