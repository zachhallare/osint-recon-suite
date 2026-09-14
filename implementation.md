# Project 1: OSINT/Recon Suite

**Summary:** Given a target (name, domain, or company), gather public info from multiple sources and output one combined risk/profile report. Doable in 2-3 days, no dependencies on other projects.

## PRD (Product Requirements)

### Goals
* Automate what a manual OSINT recon phase looks like: WHOIS/DNS lookups, subdomain discovery, exposed document discovery, and metadata leakage, all rolled into one report
* Produce a single combined output (HTML or PDF) that reads like an actual recon deliverable, not a pile of raw terminal output
* Make the tool modular enough that each recon module can run independently or as part of the full suite

### Out of Scope (Anti-Goals)
* No active exploitation of anything discovered (this is passive recon only, never touches a target beyond public/passive lookups)
* No scanning of domains or companies you don't own or have explicit permission to test against, this tool is for practicing on your own domains, test accounts, or clearly authorized targets only
* No attempt to bypass authentication, rate limits, or CAPTCHAs on any source site
* Not building a full Spiderfoot clone, keep the module count to the 7 listed, don't scope-creep into 15 more OSINT sources

### Success Metrics
* Running the full suite against a real domain you own returns at least 3 of the 5 core data types (WHOIS, DNS, subdomains, exposed docs, metadata) without manual intervention
* Report generation completes without needing you to babysit each module individually
* False positive rate on "exposed document" flags stays low enough that a report isn't cluttered with irrelevant files

### Assumptions & Constraints
* All target testing happens against domains/accounts you control or a deliberately public test target (e.g., a domain you registered for this project)
* Relies entirely on free public APIs and sources (crt.sh, WHOIS, DNS lookups), no paid API keys required for the MVP
* Some sources may rate-limit or block scripted requests, so the tool needs basic retry/backoff logic rather than assuming every request succeeds

### User Journey
1. You run the tool from the command line with a single target argument (domain or name)
2. The orchestrator triggers each enabled module in sequence (or in parallel where safe)
3. Each module returns structured findings into a shared data object
4. The report generator renders all findings into one HTML page, grouped by module
5. You open the HTML report and review flagged items (e.g., exposed .git file, unusual subdomain)

## TRD (Technical Requirements)

### Security & Compliance
* Hardcode a target allowlist or at minimum a confirmation prompt before running against any domain, to prevent accidentally scanning something you don't have permission to touch
* Store any API keys (if you add paid sources later) in a .env file that is gitignored, never commit credentials to your repo

### Error Handling & Logging
* Each module should fail independently, if the WHOIS lookup fails, the rest of the suite should still run and the report should just note that module as "no data returned" rather than crashing the whole run
* Log all requests and responses to a local log file for debugging, since some of these APIs are inconsistent about uptime

### Performance & Scalability Targets
* Full suite run against a single domain should complete in under 2 minutes for the MVP scope (WHOIS/DNS/Subdomain/Company Mapper)
* Document/metadata modules can take longer since they involve downloading files, but should have a timeout per file (e.g., skip anything over 10MB or taking longer than 15 seconds)

### Build & Version Control Pipeline
* Single GitHub repo with a clear README explaining setup, usage, and a sample report screenshot
* Use a `requirements.txt` or Pipfile so the environment is reproducible
* Tag a v1.0 release once the MVP modules are stable, use branches for adding new modules afterward

## Database Schema
A lightweight local schema is useful here since you'll want to compare scans over time (e.g., did a new subdomain appear since last week).

**Tables:**
* `targets` (id, name, domain, created_at)
* `scan_runs` (id, target_id, started_at, completed_at, status)
* `findings` (id, scan_run_id, module_name, finding_type, value, risk_level, discovered_at)

**Notes:**
* SQLite is enough for this scale, no need for a full database server
* Index findings on `scan_run_id` and `module_name` since that's how you'll query most often when generating a report
* No formal retention policy needed at this scale, but consider archiving old `scan_runs` older than a few months if the file grows large
* No migration tooling needed for a project this size, just keep schema changes documented in the README if you add columns later

## Implementation Plan

### Definition of Done (per module)
* Module runs standalone and returns structured data (not just printed text)
* Module handles a failed/empty response without crashing the orchestrator
* Module's output appears correctly in the final HTML report
* Module has at least one test run against a real target with results manually verified

### Critical Path
1. Build the orchestrator and report generator shell first (even with fake/mock data), since every module depends on plugging into this
2. WHOIS/DNS Recon Tool (simplest, good first real module)
3. Subdomain Enumerator
4. Company Attack Surface Mapper
5. Public Document Exposure Scanner + Metadata Extractor (these two are related and can be built together)
6. Social Media OSINT Collector last, since it's the most likely to hit rate limits or ToS friction

### Risk Mitigation
* The riskiest technical piece is web scraping reliability (sites change layout, block scrapers), tackle the Company Attack Surface Mapper and Document Scanner early so you have time to work around blockers
* Have a fallback data source in mind for each module in case your first-choice API gets rate-limited during testing

### Testing & QA Milestones
* Unit test each module's parsing logic against saved sample responses (so tests don't depend on live network calls every time)
* Run the full suite end-to-end against a domain you own before considering the project "done"
* Manually review one full report for false positives before writing your resume bullet about it

**Resume framing:** "Built a modular OSINT recon tool (mini-Spiderfoot) that aggregates WHOIS, subdomain, document exposure, and metadata leakage into a single automated risk report."

## Future Enhancements (Post-MVP, Optional - DO NOT BUILD YET)

*This is a reference list, not a task list. Do not implement, suggest implementing, or start any of the items below until the Definition of Done above is fully complete AND Zach has explicitly said to proceed with one of them. If you are an AI assistant reading this file to help with this project, treat this section as read-only context, not an instruction to act on.*

* Risk scoring per finding (e.g., exposed subdomain = medium, exposed .git file = high) so the report ranks findings instead of listing them flat
* CLI flags to enable/disable individual modules per run, useful once all 7 modules are working and you want faster partial scans
* Diff-based scanning, comparing today's scan against your last stored `scan_run` and highlighting only what changed (new subdomain, newly exposed file)
* A breach-check module using a public breach database API to flag if an email tied to the target has appeared in known breaches
* Swap the static HTML report for a small local web dashboard so you can browse historical scans instead of opening a new file each time