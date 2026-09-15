"""
main.py
-------
CLI entry point for the OSINT Recon Suite.

Usage
-----
    python main.py example.com
    python main.py example.com --mock          # use mock module only (no network)
    python main.py example.com --no-confirm    # skip target confirmation prompt
    python main.py example.com --output reports/
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from dotenv import load_dotenv

# ── bootstrap ──────────────────────────────────────────────────────────────
load_dotenv()  # loads .env if present (API keys, config overrides)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("osint_recon.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("main")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint-recon",
        description="OSINT Recon Suite — passive recon aggregator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com
  python main.py example.com --mock
  python main.py example.com --no-confirm --output reports/

Only scan domains you own or have explicit written permission to test.
""",
    )
    p.add_argument("target", help="Domain or entity to scan")
    p.add_argument(
        "--mock",
        action="store_true",
        help="Run with mock module only (no network calls, useful for testing)",
    )
    p.add_argument(
        "--no-confirm",
        dest="no_confirm",
        action="store_true",
        help="Skip the interactive target confirmation prompt",
    )
    p.add_argument(
        "--db",
        default="data/osint.db",
        metavar="PATH",
        help="Path to SQLite database (default: data/osint.db)",
    )
    p.add_argument(
        "--output",
        default="reports",
        metavar="DIR",
        help="Directory to write the HTML report (default: reports/)",
    )
    return p


async def main() -> None:
    args = build_arg_parser().parse_args()

    # ── assemble module list ────────────────────────────────────────────────
    # Step 1 (current): only MockModule wired up.
    # Future modules will be imported and appended here.
    from osint_recon.modules.company_mapper_module import CompanyMapperModule
    from osint_recon.modules.document_scanner_module import DocumentScannerModule
    from osint_recon.modules.metadata_extractor_module import MetadataExtractorModule
    from osint_recon.modules.mock_module import MockModule
    from osint_recon.modules.social_media_module import SocialMediaModule
    from osint_recon.modules.subdomain_module import SubdomainModule
    from osint_recon.modules.whois_dns_module import WhoisDnsModule

    if args.mock:
        modules = [MockModule()]
        logger.info("Running in MOCK mode -- no network calls will be made.")
    else:
        # All 6 MVP modules active.
        modules = [
            WhoisDnsModule(),
            SubdomainModule(),
            CompanyMapperModule(),
            DocumentScannerModule(),
            MetadataExtractorModule(),
            SocialMediaModule(),
        ]

    # ── run ─────────────────────────────────────────────────────────────────
    from osint_recon.orchestrator import Orchestrator
    from osint_recon.reporter import Reporter

    orch = Orchestrator(
        modules=modules,
        db_path=args.db,
        confirm=not args.no_confirm,
    )

    scan = await orch.run(args.target)

    # ── report ───────────────────────────────────────────────────────────────
    reporter = Reporter(output_dir=args.output)
    report_path = reporter.render(scan)

    print()
    print(f"  [OK]  Report saved:  {report_path}")
    print(f"  [**]  Findings:      {len(scan.all_findings)}")
    print(f"  [t]   Duration:      {scan.total_duration_s:.1f}s")
    print()


if __name__ == "__main__":
    asyncio.run(main())
