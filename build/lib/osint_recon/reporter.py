"""Renders scan results to an HTML report using Jinja2."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

_UTC = timezone.utc

from jinja2 import Environment, FileSystemLoader, select_autoescape

from osint_recon.models import ModuleStatus, RiskLevel, ScanResult

logger = logging.getLogger(__name__)

# Template directory relative to this file
_TEMPLATES_DIR = Path(__file__).parent / "templates"


class Reporter:
    """Generates an HTML report from a completed ScanResult."""

    def __init__(self, output_dir: str | Path = "reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html"]),
        )
        # Expose enums and helpers to templates
        self._env.globals["RiskLevel"] = RiskLevel
        self._env.globals["ModuleStatus"] = ModuleStatus
        self._env.globals["now"] = lambda: datetime.now(_UTC)

    def render(self, scan: ScanResult) -> Path:
        """Render the HTML report to disk and return the file path."""
        template = self._env.get_template("report.html.j2")

        # Compute summary stats for the template
        findings_by_module = {}
        for result in scan.results:
            findings_by_module[result.module_name] = result

        risk_counts = {level: 0 for level in RiskLevel}
        for finding in scan.all_findings:
            risk_counts[finding.risk_level] += 1

        html = template.render(
            scan=scan,
            findings_by_module=findings_by_module,
            risk_counts=risk_counts,
            generated_at=datetime.now(_UTC),
        )

        # Build safe filename
        safe_target = scan.target.replace(".", "_").replace("/", "_")
        date_str = scan.started_at.strftime("%Y%m%d_%H%M%S")
        filename = f"{safe_target}_run{scan.scan_run_id}_{date_str}.html"
        out_path = self.output_dir / filename

        out_path.write_text(html, encoding="utf-8")
        logger.info("Report written to: %s", out_path)
        return out_path
