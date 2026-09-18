"""CLI entry point for scanning domains."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Only log to file -- Rich owns the terminal.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s - %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.FileHandler("osint_recon.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("main")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint-recon",
        description="OSINT Recon Suite -- passive recon aggregator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com
  python main.py example.com --mock
  python main.py example.com --no-confirm --html --output reports/

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

    # HTML report flags -- mutually exclusive.
    html_group = p.add_mutually_exclusive_group()
    html_group.add_argument(
        "--html",
        dest="html",
        action="store_true",
        default=None,
        help="Generate an HTML report without prompting",
    )
    html_group.add_argument(
        "--no-html",
        dest="html",
        action="store_false",
        help="Skip HTML report generation entirely",
    )
    return p


async def main() -> None:
    args = build_arg_parser().parse_args()

    from osint_recon.console import (
        ask_html_prompt,
        make_progress,
        print_banner,
        print_findings_summary,
        print_scan_footer,
    )

    print_banner()

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
        modules = [
            WhoisDnsModule(),
            SubdomainModule(),
            CompanyMapperModule(),
            DocumentScannerModule(),
            MetadataExtractorModule(),
            SocialMediaModule(),
        ]

    from osint_recon.orchestrator import Orchestrator
    from osint_recon.reporter import Reporter
    from osint_recon.models import ConfirmationMethod

    orch = Orchestrator(
        modules=modules,
        db_path=args.db,
        confirm=not args.no_confirm,
    )

    # Determine how this scan was authorized for the audit trail.
    # --mock always wins over --no-confirm. A mock run makes zero real network
    # calls, so labelling it BYPASSED would be misleading -- the confirmation
    # prompt is meaningless when no target is actually contacted.
    if args.mock:
        confirmation = ConfirmationMethod.MOCK
    elif args.no_confirm:
        confirmation = ConfirmationMethod.BYPASSED
    else:
        confirmation = ConfirmationMethod.INTERACTIVE

    # Run modules inside an animated progress bar.
    with make_progress() as progress:
        scan = await orch.run(
            args.target,
            progress=progress,
            confirmation_method=confirmation,
        )

    print_findings_summary(scan)

    # Decide whether to generate the HTML report.
    generate_html: bool
    if args.html is True:
        generate_html = True
    elif args.html is False:
        generate_html = False
    elif args.no_confirm:
        # Non-interactive mode -- skip prompt, no report unless --html passed.
        generate_html = False
    else:
        generate_html = ask_html_prompt()

    report_path: Path | None = None
    if generate_html:
        reporter = Reporter(output_dir=args.output)
        report_path = reporter.render(scan)

    print_scan_footer(scan, report_path)


if __name__ == "__main__":
    asyncio.run(main())
