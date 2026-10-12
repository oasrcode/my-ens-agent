"""Compliance evaluator: consolidate scan findings and manual assessments.

This module turns a :class:`~ens_audit.catalog.models.Catalog`, an optional
:class:`~ens_audit.models.ScanReport` (deterministic scanner output) and an
optional set of :class:`~ens_audit.models.Assessment` (qualitative, human
judgements) into a :class:`~ens_audit.models.ComplianceReport` with **exactly
one** :class:`~ens_audit.models.MeasureVerdict` per ENS measure in the catalog
(the RD 311/2022 Anexo II catalog has 73 base measures).

The fundamental rule is: **absence of findings is not evidence of compliance.**
``CUMPLE`` is never reachable by default -- it requires explicit positive
verification.

Verdict precedence (first matching rule wins)
---------------------------------------------
1. **Explicit assessment.** If an :class:`Assessment` exists for the measure its
   verdict, notes and evidence are used verbatim. A human decision overrides
   everything else, including applicability.
2. **Applicability.** When ``categoria`` is supplied, measures that are not
   applicable to that category are reported as ``NO_APLICA``. Applicability is
   resolved with :func:`~ens_audit.catalog.applicability.compute_applicability`.
   Because the evaluator only receives a category (and no per-dimension levels),
   applicability is resolved against a *uniform* dimension valuation derived
   from the category -- ``BASICA`` -> all dimensions ``BAJO``, ``MEDIA`` ->
   ``MEDIO``, ``ALTA`` -> ``ALTO``. This yields the documented upper-bound counts
   (52 / 68 / 73 applicable measures).
3. **Failure signals.** A finding is a *failure signal* unless its severity is
   ``INFO``. Any failure finding makes the measure ``NO_CUMPLE``: **failures
   dominate**, and a failure from one scanner is never downgraded to ``PARCIAL``
   by positive evidence from another. Positive signals for a failed measure are
   excluded globally before the verdict is resolved, so a confirmed failure
   always wins (a scanner cannot certify as clean a measure another check
   flagged).
4. **Positive signals only.** A positive signal is any :class:`CheckEvidence`
   whose ``result`` is ``pass`` (the evidence-based replacement for "a scanner
   ran and found it clean") plus any ``INFO`` finding (legacy). -> ``CUMPLE``
   **only if** some positive :class:`CheckEvidence` has ``covers_all=True`` (it
   verifies *every* applicable requirement of the measure). Otherwise ->
   ``PARCIAL``: a clean scanner check is not proof that the whole measure is
   satisfied.
5. **No failure and no positive signal.** -> ``NO_EVALUABLE``, whether or not
   some scanner claimed coverage. Absence of evidence is never compliance.

Positive signals are ``CheckEvidence`` entries grouped by their
``measure_codes`` with ``result == "pass"`` (from ``scan_report.evidence``) plus
any ``severity == INFO`` findings. Every measure code that produced a failure
finding (in any scanner) is subtracted globally from the positive signals, so a
failure is never masked by another scanner's clean check. *Coverage* is exactly
the presence of a surviving positive signal: a measure a scanner ran over and
found clean has ``CheckEvidence`` -> ``PARCIAL``, while a measure no scanner
examined (or whose scanner failed and emitted nothing) has none ->
``NO_EVALUABLE``.

The no-automated-evidence heuristic
-----------------------------------
A scanner cannot produce machine-checkable evidence for measures whose
requirements are met by documents, management processes or physical controls.
The set below is deliberately **explicit and conservative** (each pattern is
prefixed with a comment explaining why it is non-automatable). It no longer
changes the verdict -- a measure with no evidence is always ``NO_EVALUABLE`` --
it only enriches the ``NO_EVALUABLE`` rationale.

* ``org.*``    -- organizational marco: security policy, norms, procedures and
  the authorization process are documents.
* ``op.pl.1``  -- risk analysis is a documented management activity.
* ``op.cont.*`` -- continuity: impact analysis, continuity plan, periodic drills
  and alternative means are documented/organizational.
* ``mp.if.*``  -- facilities and physical infrastructure (zoning, access,
  power, fire, flood, equipment movement log).
* ``mp.eq.*``  -- physical protection of workstations and equipment.
* ``mp.per.*`` -- personnel management: duties, awareness and training.
* ``mp.info.2`` -- information classification is an organizational decision.
* ``mp.si.1``  -- media marking is a physical/organizational control.

A measure in this set that *does* have an assessment or scanner findings is
still evaluated normally (rules 1 and 3 take precedence).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from .catalog.applicability import compute_applicability
from .catalog.models import Catalog, Categoria, Dimension, Nivel
from .models import (
    Assessment,
    CheckEvidence,
    ComplianceReport,
    ComplianceSummary,
    Evidence,
    Finding,
    MeasureVerdict,
    ScanReport,
    Severity,
    Verdict,
)

__all__ = ["evaluate_compliance"]

#: Measure-code patterns that no deterministic scanner can evaluate. Used only
#: to enrich the ``NO_EVALUABLE`` rationale; the verdict is ``NO_EVALUABLE``
#: regardless (see the module docstring).
_NO_AUTOMATED_EVIDENCE_PATTERNS: tuple[str, ...] = (
    r"^org\.",  # organizational marco: documents and management processes
    r"^op\.pl\.1$",  # risk analysis (documented management activity)
    r"^op\.cont\.",  # service continuity plans and drills
    r"^mp\.if\.",  # physical facilities and infrastructure
    r"^mp\.eq\.",  # physical protection of equipment and workstations
    r"^mp\.per\.",  # personnel duties, awareness and training
    r"^mp\.info\.2$",  # information classification (organizational decision)
    r"^mp\.si\.1$",  # media marking (physical/organizational control)
)
_NO_AUTOMATED_EVIDENCE_RE = re.compile(
    "|".join(f"(?:{pattern})" for pattern in _NO_AUTOMATED_EVIDENCE_PATTERNS)
)

#: Uniform dimension level used when only a category is available.
_LEVEL_FOR_CATEGORY: dict[Categoria, Nivel] = {
    Categoria.BASICA: Nivel.BAJO,
    Categoria.MEDIA: Nivel.MEDIO,
    Categoria.ALTA: Nivel.ALTO,
}


def _coerce_category(categoria: Categoria | str | None) -> Categoria | None:
    """Normalize a category given as an enum member or a raw string."""
    if categoria is None or isinstance(categoria, Categoria):
        return categoria
    return Categoria(categoria)


def _has_no_automated_evidence(code: str) -> bool:
    """Whether the measure code matches the non-automatable heuristic set."""
    return _NO_AUTOMATED_EVIDENCE_RE.match(code) is not None


def _levels_for_category(categoria: Categoria) -> dict[Dimension, Nivel]:
    """Return a uniform dimension valuation for the given category."""
    level = _LEVEL_FOR_CATEGORY[categoria]
    return {dimension: level for dimension in Dimension}


def _applicable_codes(catalog: Catalog, categoria: Categoria | None) -> set[str]:
    """Return the measure codes applicable under ``categoria``.

    Without a category every catalog measure is considered applicable.
    """
    if categoria is None:
        return set(catalog.medidas)
    result = compute_applicability(
        catalog, _levels_for_category(categoria), categoria
    )
    return set(result.measure_codes())


def _index_assessments(
    assessments: Sequence[Assessment] | Mapping[str, Assessment] | None,
) -> dict[str, Assessment]:
    """Index assessments by measure code, accepting a sequence or a mapping."""
    if assessments is None:
        return {}
    if isinstance(assessments, Mapping):
        return {str(code): assessment for code, assessment in assessments.items()}
    return {assessment.measure_code: assessment for assessment in assessments}


def _group_findings(scan_report: ScanReport | None) -> dict[str, list[Finding]]:
    """Group findings by every measure code they reference."""
    grouped: dict[str, list[Finding]] = {}
    if scan_report is None:
        return grouped
    for finding in scan_report.findings:
        for code in finding.measure_codes:
            grouped.setdefault(code, []).append(finding)
    return grouped


def _is_failure(finding: Finding) -> bool:
    """Whether a finding signals non-compliance.

    Convention: ``INFO`` findings are positive/informational signals; every
    other severity is a failure signal.
    """
    return finding.severity is not Severity.INFO


def _failed_codes(scan_report: ScanReport | None) -> set[str]:
    """Return every measure code that produced a failure finding.

    The set spans *all* scanners: a failure recorded by one scanner must veto
    the positive evidence another scanner emitted for the same measure, so the
    subtraction is global rather than per scanner.
    """
    if scan_report is None:
        return set()
    return {
        code
        for finding in scan_report.findings
        if _is_failure(finding)
        for code in finding.measure_codes
    }


def _group_check_evidence(
    scan_report: ScanReport | None,
    failed_codes: set[str],
) -> dict[str, list[CheckEvidence]]:
    """Group positive check evidence by every measure code it references.

    Only ``result == "pass"`` entries are positive signals; any other result is
    ignored (it neither supports compliance nor signals a failure). Measure
    codes in ``failed_codes`` are excluded so a failure confirmed by a scanner
    is never certified clean by another one (failure dominance).
    """
    grouped: dict[str, list[CheckEvidence]] = {}
    if scan_report is None:
        return grouped
    for check in scan_report.evidence:
        if check.result != "pass":
            continue
        for code in check.measure_codes:
            if code in failed_codes:
                continue
            grouped.setdefault(code, []).append(check)
    return grouped


def _collect_evidence(findings: Sequence[Finding]) -> list[Evidence]:
    """Flatten the evidence of the given findings, preserving order."""
    evidence: list[Evidence] = []
    for finding in findings:
        evidence.extend(finding.evidence)
    return evidence


def _collect_check_evidence(checks: Sequence[CheckEvidence]) -> list[Evidence]:
    """Flatten the evidence attached to the given positive checks."""
    evidence: list[Evidence] = []
    for check in checks:
        evidence.extend(check.evidence)
    return evidence


def _verdict_for_measure(
    code: str,
    *,
    applicable: bool,
    category_label: str,
    assessment: Assessment | None,
    findings: list[Finding],
    check_evidence: list[CheckEvidence],
) -> MeasureVerdict:
    """Resolve the verdict of a single measure following the precedence rules."""
    if assessment is not None:
        return MeasureVerdict(
            measure_code=code,
            verdict=assessment.verdict,
            evidence=list(assessment.evidence),
            rationale=assessment.notes or "Explicit manual assessment.",
        )

    if not applicable:
        return MeasureVerdict(
            measure_code=code,
            verdict=Verdict.NO_APLICA,
            rationale=f"Measure not applicable to category {category_label}.",
        )

    failures = [finding for finding in findings if _is_failure(finding)]
    if failures:
        # Failure dominance: a confirmed failure always wins. Positive signals
        # for this measure were already excluded globally (``failed_codes``), so
        # no clean check from another scanner can downgrade it to ``PARCIAL``.
        return MeasureVerdict(
            measure_code=code,
            verdict=Verdict.NO_CUMPLE,
            evidence=_collect_evidence(failures),
            rationale=f"{len(failures)} failing scanner finding(s) for this measure.",
        )

    info_findings = [finding for finding in findings if not _is_failure(finding)]
    positive_count = len(info_findings) + len(check_evidence)
    has_positive = positive_count > 0

    if has_positive:
        positive_evidence = _collect_check_evidence(
            check_evidence
        ) + _collect_evidence(info_findings)
        if any(check.covers_all for check in check_evidence):
            return MeasureVerdict(
                measure_code=code,
                verdict=Verdict.CUMPLE,
                evidence=positive_evidence,
                rationale=(
                    "Explicit scanner check covers all applicable requirements "
                    "of this measure."
                ),
            )
        return MeasureVerdict(
            measure_code=code,
            verdict=Verdict.PARCIAL,
            evidence=positive_evidence,
            rationale=f"{positive_count} passing scanner signal(s) for this measure.",
        )

    if _has_no_automated_evidence(code):
        rationale = (
            "Documentary/organizational or physical measure with no automated "
            "evidence and no manual assessment."
        )
    else:
        rationale = (
            "No coverage and no manual assessment: absence of evidence is not "
            "evidence of compliance."
        )
    return MeasureVerdict(
        measure_code=code,
        verdict=Verdict.NO_EVALUABLE,
        rationale=rationale,
    )


def evaluate_compliance(
    catalog: Catalog,
    scan_report: ScanReport | None = None,
    assessments: Sequence[Assessment] | Mapping[str, Assessment] | None = None,
    categoria: Categoria | str | None = None,
) -> ComplianceReport:
    """Evaluate every catalog measure and build a compliance report.

    :param catalog: parsed ENS catalog (the source of the 73 measures).
    :param scan_report: optional scanner output; its findings are aggregated
        through their ``measure_codes``.
    :param assessments: optional manual assessments, as a sequence or a mapping
        of measure code to :class:`Assessment`. An explicit assessment always
        wins over scan-derived verdicts.
    :param categoria: optional system category; when given, measures not
        applicable to it are reported as ``NO_APLICA``.
    :returns: a :class:`ComplianceReport` with one verdict per catalog measure,
        the aggregate summary and metadata (including the compliance and
        coverage percentages over applicable measures, the serialized positive
        evidence and each scanner's execution status).
    """
    category = _coerce_category(categoria)
    category_label = category.value if category is not None else ""
    applicable = _applicable_codes(catalog, category)
    assessments_by_code = _index_assessments(assessments)
    findings_by_code = _group_findings(scan_report)
    check_evidence_by_code = _group_check_evidence(
        scan_report, _failed_codes(scan_report)
    )

    verdicts: list[MeasureVerdict] = [
        _verdict_for_measure(
            code,
            applicable=code in applicable,
            category_label=category_label,
            assessment=assessments_by_code.get(code),
            findings=findings_by_code.get(code, []),
            check_evidence=check_evidence_by_code.get(code, []),
        )
        for code in catalog.measure_codes()
    ]

    summary = ComplianceSummary.from_verdicts(verdicts)
    metadata: dict[str, Any] = {
        "catalog_norma": catalog.norma,
        "catalog_version": catalog.version,
        "catalog_uuid": catalog.uuid,
        "category": category_label,
        "target": scan_report.target if scan_report is not None else None,
        "scanners": list(scan_report.scanners) if scan_report is not None else [],
        "finding_count": len(scan_report.findings) if scan_report is not None else 0,
        "evidence": (
            [item.model_dump(mode="json") for item in scan_report.evidence]
            if scan_report is not None
            else []
        ),
        "scanner_status": (
            dict(scan_report.scanner_status) if scan_report is not None else {}
        ),
        "assessment_count": len(assessments_by_code),
        "applicable": summary.applicable,
        "compliance_pct": summary.compliance_pct,
        "coverage_pct": summary.coverage_pct,
    }

    return ComplianceReport(
        category=category_label,
        verdicts=verdicts,
        summary=summary,
        metadata=metadata,
    )
