"""Rich-powered terminal UI helpers for the recon suite."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

if TYPE_CHECKING:
    from osint_recon.models import ScanResult

# Single shared console instance so all output lands on the same stream.
# Force UTF-8 so box-drawing characters work on Windows regardless of the
# active code page (avoids cp1252 UnicodeEncodeError).
console = Console(highlight=False, file=open(sys.stdout.fileno(), mode="w", encoding="utf-8", buffering=1, closefd=False))

# Brand colors
_GREEN = "#39ff14"
_CYAN = "#00d4ff"
_DIM = "#4a5a74"
_RED = "#ff3e3e"
_ORANGE = "#ff8c00"
_YELLOW = "#fbbf24"

_BANNER_ART = r"""
 ██████╗ ███████╗██╗███╗   ██╗████████╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║   ██║███████╗██║██╔██╗ ██║   ██║       ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║   ██║╚════██║██║██║╚██╗██║   ██║       ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚██████╔╝███████║██║██║ ╚████║   ██║       ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

  ███████╗██╗   ██╗██╗████████╗███████╗
  ██╔════╝██║   ██║██║╚══██╔══╝██╔════╝
  ███████╗██║   ██║██║   ██║   █████╗
  ╚════██║██║   ██║██║   ██║   ██╔══╝
  ███████║╚██████╔╝██║   ██║   ███████╗
  ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝
"""

_TAGLINE = "passive recon  |  no active probing  |  authorised targets only"


def print_banner() -> None:
    """Print the startup ASCII banner with neon green styling."""
    art = Text(_BANNER_ART, style=f"bold {_GREEN}", justify="center")
    tagline = Text.from_markup(f"[{_DIM}]{_TAGLINE}[/{_DIM}]")
    panel = Panel(
        art,
        subtitle=tagline,
        border_style=_CYAN,
        padding=(0, 2),
    )
    console.print(panel)
    console.print()


def make_progress() -> Progress:
    """Return a configured Progress bar for the module loop.

    The bar shows: spinner, module name, elapsed time, a progress bar,
    and an M/N counter. It clears on exit so the terminal stays clean.
    """
    return Progress(
        SpinnerColumn(spinner_name="dots", style=f"bold {_GREEN}"),
        TextColumn("[bold]{task.description}"),
        BarColumn(
            bar_width=36,
            style=_DIM,
            complete_style=_GREEN,
            finished_style=_CYAN,
        ),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


def print_findings_summary(scan: ScanResult) -> None:
    """Print a table of HIGH/MEDIUM findings plus a count of lower-severity ones."""
    findings = scan.all_findings
    hi_med = [f for f in findings if f.risk_level.value in ("high", "medium")]
    low_info_count = len(findings) - len(hi_med)

    console.print(Rule(f"[bold {_CYAN}]Findings Summary[/]", style=_DIM))
    console.print()

    if not findings:
        console.print(f"  [{_DIM}]No findings returned.[/{_DIM}]")
        for res in scan.results:
            if getattr(res, "source_status", None) in ("crtsh_failed_fallback_used", "all_sources_failed"):
                console.print(f"  [{_ORANGE}]Warning: {res.module_name} source status: {res.source_status}[/{_ORANGE}]")
        console.print()
        return

    if hi_med:
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style=f"bold {_CYAN}",
            border_style=_DIM,
            pad_edge=False,
            expand=False,
        )
        table.add_column("Module", style=f"dim {_CYAN}", no_wrap=True, min_width=12)
        table.add_column("Type", style="bold white", no_wrap=True, min_width=16)
        table.add_column("Value", style="white", min_width=30)
        table.add_column("Risk", justify="center", no_wrap=True, min_width=8)

        disclaimers = set()
        
        for f in hi_med:
            risk_style = (
                f"bold {_RED}" if f.risk_level.value == "high" else f"bold {_ORANGE}"
            )
            val_str = f.value[:80] + ("..." if len(f.value) > 80 else "")
            if f.extra and f.extra.get("disclaimer"):
                disclaimers.add(f.extra["disclaimer"])

            table.add_row(
                f.module_name,
                f.finding_type,
                val_str,
                Text(f.risk_level.value.upper(), style=risk_style),
            )

        console.print(table)
        
        if disclaimers:
            console.print()
            for d in disclaimers:
                console.print(f"  [{_ORANGE}]⚠ {d}[/{_ORANGE}]")
    else:
        console.print(
            f"  [{_GREEN}]No HIGH or MEDIUM findings.[/{_GREEN}]"
            f"  [{_DIM}](All findings are LOW / INFO)[/{_DIM}]"
        )

    if low_info_count:
        console.print(
            f"\n  [{_DIM}]+{low_info_count} LOW / INFO finding(s) — see HTML report for details[/{_DIM}]"
        )
        
    for res in scan.results:
        if getattr(res, "source_status", None) in ("crtsh_failed_fallback_used", "all_sources_failed"):
            console.print(f"\n  [{_ORANGE}]⚠ Warning: {res.module_name} source status: {res.source_status}[/{_ORANGE}]")

    console.print()


def print_scan_footer(
    scan: ScanResult,
    report_path: Path | None = None,
) -> None:
    """Print the final stat block after scanning is done."""
    stats = [
        _stat_cell("Findings", str(len(scan.all_findings)), _GREEN),
        _stat_cell("Modules", str(len(scan.results)), _CYAN),
        _stat_cell("Duration", f"{scan.total_duration_s:.1f}s", _YELLOW),
    ]

    console.print(Columns(stats, equal=False, expand=False))
    console.print()

    # Show the audit trail status with appropriate styling.
    method = scan.confirmation_method.value
    if method == "interactive":
        auth_style = f"bold {_GREEN}"
        auth_label = "INTERACTIVE"
    elif method == "bypassed":
        auth_style = f"bold {_ORANGE}"
        auth_label = "BYPASSED (--no-confirm)"
    else:  # mock
        auth_style = f"bold {_CYAN}"
        auth_label = "MOCK (no network calls)"

    console.print(
        f"  [{_DIM}]Authorization[/{_DIM}]  [{auth_style}]{auth_label}[/{auth_style}]"
    )

    if report_path:
        console.print(
            f"  [{_CYAN}]Report saved[/{_CYAN}]  [{_GREEN}]{report_path}[/{_GREEN}]"
        )
    else:
        console.print(f"  [{_DIM}]No HTML report generated.[/{_DIM}]")

    console.print()


def _stat_cell(label: str, value: str, color: str) -> Panel:
    """Build a single small stat panel for the footer row."""
    content = Text.assemble(
        (value + "\n", f"bold {color}"),
        (label, _DIM),
    )
    return Panel(content, border_style=_DIM, padding=(0, 2), expand=False)


def confirm_target(target: str) -> bool:
    """Ask the user to confirm the scan target using a Rich prompt."""
    console.print()
    console.print(
        Panel(
            f"[bold white]Target:[/bold white]  [{_GREEN}]{target}[/{_GREEN}]\n\n"
            f"[{_DIM}]Only scan domains or entities you own or have explicit\n"
            f"written permission to test. This tool performs passive\n"
            f"reconnaissance only.[/{_DIM}]",
            title=f"[bold {_RED}]  WARNING  [/bold {_RED}]",
            border_style=_RED,
            padding=(1, 3),
        )
    )
    return Confirm.ask("  Confirm scan?", console=console, default=False)


def ask_html_prompt() -> bool:
    """Ask the user if they want to generate an HTML report."""
    return Confirm.ask(
        f"\n  [{_CYAN}]Generate HTML report?[/{_CYAN}]",
        console=console,
        default=True,
    )
