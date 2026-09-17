"""Data models for scan findings and results."""

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
    PARTIAL = "partial"   # Some findings returned with errors
    FAILED = "failed"     # Module failed without data
    SKIPPED = "skipped"   # Module was disabled for this run


@dataclass
class Finding:
    """Single finding discovered by a recon module."""
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
    """Outcome and findings from a single module run."""
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
    """Overall scan results across all modules."""
    target: str
    scan_run_id: int
    started_at: datetime
    completed_at: datetime | None = None
    results: list[ModuleResult] = field(default_factory=list)

    @property
    def all_findings(self) -> list[Finding]:
        """Flatten all module findings into a single list."""
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
