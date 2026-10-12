"""Audit-domain models.

Pydantic v2 models shared by the scanners, the compliance evaluator and the
report generators. These are deliberately independent from the catalog models
in :mod:`ens_audit.catalog.models`; the only link is that ``measure_codes``
reference catalog measure codes as plain strings.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    """Return the current timezone-aware UTC timestamp."""
    return datetime.now(UTC)


class Verdict(str, Enum):
    """Outcome of assessing a single ENS measure."""

    CUMPLE = "cumple"
    NO_CUMPLE = "no_cumple"
    PARCIAL = "parcial"
    NO_APLICA = "no_aplica"
    NO_EVALUABLE = "no_evaluable"


class EvidenceKind(str, Enum):
    """Nature of a piece of evidence."""

    FILE_LINE = "file_line"
    CONFIG = "config"
    NOTE = "note"


class Severity(str, Enum):
    """Severity of a finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Evidence(BaseModel):
    """A pointer to the evidence backing a finding or an assessment."""

    kind: EvidenceKind
    location: str
    detail: str = ""


class Finding(BaseModel):
    """A scanner finding, linked to the ENS measure(s) it concerns."""

    id: str
    severity: Severity
    message: str
    measure_codes: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    scanner: str | None = None

    @property
    def code(self) -> str:
        """Alias of :attr:`id` for callers that refer to a finding code."""
        return self.id


class CheckEvidence(BaseModel):
    """Positive evidence that a scanner examined a measure and found it clean.

    Absence of findings is not evidence of compliance, so a scanner must record
    explicitly what it checked. ``covers_all`` states whether the check covers
    *every* applicable requirement of the measure: only then can a clean result
    raise the measure to ``cumple`` (otherwise the verdict is ``parcial``).
    """

    scanner: str
    measure_codes: list[str]
    checked: str
    scope: str
    result: str = "pass"
    observed_at: datetime = Field(default_factory=_utcnow)
    covers_all: bool = False
    evidence: list[Evidence] = Field(default_factory=list)


class ScanReport(BaseModel):
    """Result of running one or more scanners against a target."""

    target: str
    findings: list[Finding] = Field(default_factory=list)
    scanners: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=_utcnow)
    evidence: list[CheckEvidence] = Field(default_factory=list)
    scanner_status: dict[str, str] = Field(default_factory=dict)


class Assessment(BaseModel):
    """A manual/qualitative assessment of a single measure."""

    measure_code: str
    verdict: Verdict
    notes: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class MeasureVerdict(BaseModel):
    """The consolidated verdict for a measure in a compliance report."""

    measure_code: str
    verdict: Verdict
    evidence: list[Evidence] = Field(default_factory=list)
    rationale: str = ""


class ComplianceSummary(BaseModel):
    """Aggregate counts of verdicts across the assessed measures.

    Two distinct ratios are exposed (see the R1 verdict-reliability revision):

    * ``compliance_pct`` = ``cumple / applicable`` -- how much of what applies
      is explicitly verified as compliant.
    * ``coverage_pct`` = ``(applicable - no_evaluable) / applicable`` -- how
      much of what applies has *any* evidence (i.e. is not ``no_evaluable``).
    """

    total: int = 0
    cumple: int = 0
    no_cumple: int = 0
    parcial: int = 0
    no_aplica: int = 0
    no_evaluable: int = 0
    applicable: int = 0
    compliance_pct: float = 0.0
    coverage_pct: float = 0.0

    @classmethod
    def from_verdicts(cls, verdicts: list[MeasureVerdict]) -> ComplianceSummary:
        """Build a summary by counting a list of measure verdicts."""
        summary = cls(total=len(verdicts))
        for measure_verdict in verdicts:
            setattr(
                summary,
                measure_verdict.verdict.value,
                getattr(summary, measure_verdict.verdict.value) + 1,
            )
        summary.applicable = summary.total - summary.no_aplica
        if summary.applicable:
            summary.compliance_pct = round(
                100 * summary.cumple / summary.applicable, 2
            )
            summary.coverage_pct = round(
                100 * (summary.applicable - summary.no_evaluable) / summary.applicable,
                2,
            )
        return summary


class ComplianceReport(BaseModel):
    """Per-measure compliance verdicts plus aggregate metadata."""

    # System category code (e.g. "BASICA"/"MEDIA"/"ALTA"); kept as a plain
    # string to avoid coupling the audit domain to the catalog models.
    category: str
    verdicts: list[MeasureVerdict] = Field(default_factory=list)
    summary: ComplianceSummary = Field(default_factory=ComplianceSummary)
    metadata: dict[str, Any] = Field(default_factory=dict)
