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


class Method(str, Enum):
    """How a piece of evidence was obtained.

    One of the three independent axes (method / confidence / scope) the audit
    model never conflates. ``HEURISTIC`` is pattern-based detection;
    ``VERIFIED`` is confirmation by a tool or an explicit rule.
    """

    HEURISTIC = "heuristic"
    VERIFIED = "verified"


class Confidence(str, Enum):
    """Confidence in a piece of evidence.

    Independent from both the method and the scope: a verified piece of evidence
    can still be low-confidence, and vice versa.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EvidenceState(str, Enum):
    """Epistemic state of the evidence behind a measure verdict.

    Deliberately distinguishes *not checked* from *checked and found clean* and
    from *demonstrated compliance* (and its opposite):

    * ``no_aplica`` -- the measure is not applicable to the system.
    * ``no_comprobado`` -- no coverage (no scanner examined it, or the scanner
      failed/was skipped). Absence of evidence is never compliance.
    * ``no_detectado`` -- it was checked and **nothing was found**; this is
      strictly "clean", and it is **not** proof of compliance, hence it maps to
      ``parcial``.
    * ``riesgo_detectado`` -- the only signals found were non-demonstrated
      risk findings (e.g. a detected CVE or an unpinned dependency). Such a
      signal does not demonstrate non-compliance, so it maps to ``parcial`` and
      is surfaced separately as a risk; it is distinct from ``no_detectado``
      (where nothing was found).
    * ``no_concluyente`` -- a manual (human) judgement that is not itself a
      demonstrated outcome, e.g. a manual ``parcial`` assessment. A human
      partial judgement is neither *checked and found clean* (``no_detectado``)
      nor a machine-detected risk (``riesgo_detectado``), so it gets its own
      neutral state.
    * ``cumplimiento_demostrado`` -- sufficient positive evidence exists.
    * ``incumplimiento_demostrado`` -- an applicable requirement is
      demonstrably not met.
    """

    NO_APLICA = "no_aplica"
    NO_COMPROBADO = "no_comprobado"
    NO_DETECTADO = "no_detectado"
    RIESGO_DETECTADO = "riesgo_detectado"
    NO_CONCLUYENTE = "no_concluyente"
    CUMPLIMIENTO_DEMOSTRADO = "cumplimiento_demostrado"
    INCUMPLIMIENTO_DEMOSTRADO = "incumplimiento_demostrado"


#: Maps an :class:`EvidenceState` to the :class:`ComplianceSummary` counter it
#: increments. ``NO_APLICA`` has no counter: it duplicates the ``no_aplica``
#: verdict count.
_EVIDENCE_STATE_COUNT_FIELDS: dict[EvidenceState, str] = {
    EvidenceState.NO_COMPROBADO: "no_comprobado",
    EvidenceState.NO_DETECTADO: "no_detectado",
    EvidenceState.RIESGO_DETECTADO: "riesgo_detectado",
    EvidenceState.NO_CONCLUYENTE: "no_concluyente",
    EvidenceState.CUMPLIMIENTO_DEMOSTRADO: "cumplimiento_demostrado",
    EvidenceState.INCUMPLIMIENTO_DEMOSTRADO: "incumplimiento_demostrado",
}


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
    # -- traceability (independent axes; never conflated) ---------------------
    #: Tool that produced the finding (the scanner id by default).
    tool: str | None = None
    #: Version of the producing tool, when known.
    tool_version: str | None = None
    #: Detection method (heuristic pattern vs explicit verification).
    method: Method = Method.HEURISTIC
    #: Confidence in the finding.
    confidence: Confidence = Confidence.MEDIUM
    #: ENS requirement ids of the measures this finding concerns.
    requirement_refs: list[str] = Field(default_factory=list)
    #: ENS refuerzo ids this finding concerns.
    refuerzo_refs: list[str] = Field(default_factory=list)
    #: Whether the finding *demonstrates* non-compliance of an applicable
    #: requirement. A mere risk signal (e.g. a detected CVE, an unpinned
    #: dependency) must set this to ``False``: it must never force NO_CUMPLE.
    demonstrates: bool = True

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
    #: Rule kind that was evaluated (a key of
    #: :data:`ens_audit.checks.mapping.MEASURE_MAP`). It lets the renderers show
    #: a localized description instead of the scanner-authored English
    #: ``checked`` text; ``None`` for hand-authored evidence without a rule kind.
    kind: str | None = None
    scope: str
    result: str = "pass"
    observed_at: datetime = Field(default_factory=_utcnow)
    covers_all: bool = False
    evidence: list[Evidence] = Field(default_factory=list)
    # -- traceability (independent axes; never conflated) ---------------------
    #: Tool that produced the evidence (the scanner id by default).
    tool: str | None = None
    #: Version of the producing tool, when known.
    tool_version: str | None = None
    #: Detection method (heuristic pattern vs explicit verification).
    method: Method = Method.HEURISTIC
    #: Confidence in the evidence.
    confidence: Confidence = Confidence.MEDIUM
    #: ENS requirement ids this evidence concerns.
    requirement_refs: list[str] = Field(default_factory=list)
    #: ENS refuerzo ids this evidence concerns.
    refuerzo_refs: list[str] = Field(default_factory=list)


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
    #: Epistemic state of the evidence backing this verdict (see
    #: :class:`EvidenceState`). Kept on a separate axis from ``verdict``.
    evidence_state: EvidenceState
    evidence: list[Evidence] = Field(default_factory=list)
    rationale: str = ""
    #: ENS requirement ids the evidence behind this verdict concerns.
    requirement_refs: list[str] = Field(default_factory=list)
    #: ENS refuerzo ids the evidence behind this verdict concerns.
    refuerzo_refs: list[str] = Field(default_factory=list)


class ComplianceSummary(BaseModel):
    """Aggregate counts of verdicts across the assessed measures.

    Two distinct ratios are exposed (see the R1 verdict-reliability revision):

    * ``compliance_pct`` = ``cumple / applicable`` -- how much of what applies
      is explicitly verified as compliant.
    * ``coverage_pct`` = ``(applicable - no_evaluable) / applicable`` -- how
      much of what applies has *any* evidence (i.e. is not ``no_evaluable``).

    The ``evidence_state`` counts sit on an orthogonal axis to the ``verdict``
    counts: they distinguish *not checked* (``no_comprobado``) from *checked and
    clean* (``no_detectado``) from a non-demonstrated *risk* (``riesgo_detectado``)
    from a neutral manual judgement (``no_concluyente``) from *demonstrated*
    compliance / non-compliance.
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
    #: Counts by :class:`EvidenceState` (the ``no_aplica`` state is already
    #: represented by the ``no_aplica`` verdict count and is not duplicated).
    no_comprobado: int = 0
    no_detectado: int = 0
    riesgo_detectado: int = 0
    no_concluyente: int = 0
    cumplimiento_demostrado: int = 0
    incumplimiento_demostrado: int = 0

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
            field = _EVIDENCE_STATE_COUNT_FIELDS.get(measure_verdict.evidence_state)
            if field is not None:
                setattr(summary, field, getattr(summary, field) + 1)
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
