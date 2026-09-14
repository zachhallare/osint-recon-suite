"""
osint_recon/models.py
---------------------
Shared data contracts used by every module and the orchestrator.
Modules return a ModuleResult; the orchestrator assembles a ScanResult.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

_UTC = timezone.utc


class RiskLevel(str, Enum):
    """Severity classification for individual findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ModuleStatus(str, Enum):
    """Outcome of a module run."""
    SUCCESS = "success"
    PARTIAL = "partial"   # some findings, but errors occurred
    FAILED = "failed"     # module returned no data (network/API failure)
    SKIPPED = "skipped"   # module was disabled for this run


@dataclass
class Finding:
    """
    A single discrete piece of intelligence discovered by a module.

    Attributes
    ----------
    module_name  : Name of the module that produced this finding.
    finding_type : Category label (e.g. "dns_record", "subdomain", "exposed_file").
    value        : The raw discovered value.
    risk_level   : Severity classification.
    extra        : Optional freeform dict for module-specific extra data.
    discovered_at: UTC timestamp of discovery.
    """
    module_name: str
    finding_type: str
    value: str
    risk_level: RiskLevel = RiskLevel.INFO
    extra: dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=lambda: datetime.now(_UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "finding_type": self.finding_type,
            "value": self.value,
            "risk_level": self.risk_level.value,
            "extra": self.extra,
            "discovered_at": self.discovered_at.isoformat(),
        }


@dataclass
class ModuleResult:
    """
    Complete output of one module run.

    Attributes
    ----------
    module_name : Unique identifier matching the module class.
    status      : Outcome of the run.
    findings    : List of Finding objects (empty on failure).
    error       : Human-readable error message if status != SUCCESS.
    duration_s  : Wall-clock seconds the module took to run.
    """
    module_name: str
    status: ModuleStatus
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "status": self.status.value,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "duration_s": round(self.duration_s, 3),
        }


@dataclass
class ScanResult:
    """
    Top-level container produced by the orchestrator after a full suite run.

    Attributes
    ----------
    target      : The domain or entity that was scanned.
    scan_run_id : DB primary key of the scan_runs row for this execution.
    started_at  : UTC timestamp when the orchestrator started.
    completed_at: UTC timestamp when all modules finished.
    results     : Ordered list of ModuleResult objects.
    """
    target: str
    scan_run_id: int
    started_at: datetime
    completed_at: datetime | None = None
    results: list[ModuleResult] = field(default_factory=list)

    @property
    def all_findings(self) -> list[Finding]:
        """Flatten findings across all modules into a single list."""
        return [f for r in self.results for f in r.findings]

    @property
    def total_duration_s(self) -> float:
        if self.completed_at is None:
            return 0.0
        return (self.completed_at - self.started_at).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scan_run_id": self.scan_run_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_duration_s": round(self.total_duration_s, 3),
            "results": [r.to_dict() for r in self.results],
        }
