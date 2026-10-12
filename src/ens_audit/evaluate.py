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
   everything else, including applicability. The ``evidence_state`` is derived
   from the verdict (``cumple`` -> ``cumplimiento_demostrado``, ``no_cumple`` ->
   ``incumplimiento_demostrado``, ``parcial`` -> ``no_concluyente``, and so on).
2. **Applicability.** When ``categoria`` is supplied, measures that are not
   applicable to that category are reported as ``NO_APLICA``
   (``evidence_state=no_aplica``). Applicability is resolved with
   :func:`~ens_audit.catalog.applicability.compute_applicability`.
3. **Demonstrated failures.** A finding that *demonstrates* non-compliance of an
   applicable requirement (``demonstrates=True`` and severity is not ``INFO``)
   makes the measure ``NO_CUMPLE`` (``incumplimiento_demostrado``): demonstrated
   failures dominate, and positive evidence for the measure is excluded globally
   beforehand, so no scanner can certify as clean a measure another one proved
   non-compliant.
4. **Non-demonstrated signals (risks).** A finding whose ``demonstrates`` is
   ``False`` (e.g. a detected CVE, an unpinned dependency) does **not** force
   ``NO_CUMPLE``. It caps the measure at ``PARCIAL`` (``riesgo_detectado``) and
   is surfaced separately as a risk. ``no_detectado`` is reserved strictly for
   "checked and found nothing", never for a detected risk.
5. **Positive signals only.** A positive signal is any :class:`CheckEvidence`
   with ``result == "pass"`` plus any ``INFO`` finding. If a positive check has
   ``covers_all=True`` (it verifies *every* applicable requirement) the measure
   is ``CUMPLE`` (``cumplimiento_demostrado``); otherwise it is ``PARCIAL``
   (``no_detectado``), because a clean check is not proof the whole measure is
   satisfied.
6. **No failure and no positive signal.** -> ``NO_EVALUABLE``
   (``no_comprobado``), whether or not some scanner claimed coverage. Absence of
   evidence is never compliance; a missing/failed/skipped scanner reduces
   coverage and can never be read as compliance.

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
from .catalog.models import Catalog, Categoria, Dimension, Medida, Nivel
from .models import (
    Assessment,
    CheckEvidence,
    ComplianceReport,
    ComplianceSummary,
    Evidence,
    EvidenceState,
    Finding,
    MeasureVerdict,
    ScanReport,
    Severity,
    Verdict,
)

__all__ = ["evaluate_compliance"]

#: Epistemic evidence state implied by an explicit assessment verdict.
_ASSESSMENT_EVIDENCE_STATE: dict[Verdict, EvidenceState] = {
    Verdict.CUMPLE: EvidenceState.CUMPLIMIENTO_DEMOSTRADO,
    Verdict.NO_CUMPLE: EvidenceState.INCUMPLIMIENTO_DEMOSTRADO,
    Verdict.PARCIAL: EvidenceState.NO_CONCLUYENTE,
    Verdict.NO_APLICA: EvidenceState.NO_APLICA,
    Verdict.NO_EVALUABLE: EvidenceState.NO_COMPROBADO,
}

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

#: Accepted aliases for the five security dimensions (name and single letter).
_DIMENSION_ALIASES: dict[str, Dimension] = {
    "confidencialidad": Dimension.CONFIDENCIALIDAD,
    "c": Dimension.CONFIDENCIALIDAD,
    "integridad": Dimension.INTEGRIDAD,
    "i": Dimension.INTEGRIDAD,
    "disponibilidad": Dimension.DISPONIBILIDAD,
    "d": Dimension.DISPONIBILIDAD,
    "autenticidad": Dimension.AUTENTICIDAD,
    "a": Dimension.AUTENTICIDAD,
    "trazabilidad": Dimension.TRAZABILIDAD,
    "t": Dimension.TRAZABILIDAD,
}


def _coerce_category(categoria: Categoria | str | None) -> Categoria | None:
    """Normalize a category given as an enum member or a raw string."""
    if categoria is None or isinstance(categoria, Categoria):
        return categoria
    return Categoria(categoria)


def _coerce_dimensions(
    dimensiones: Mapping[Any, Any],
) -> dict[Dimension, Nivel]:
    """Normalize a per-dimension level mapping into enum-keyed form.

    Keys accept a :class:`~ens_audit.catalog.models.Dimension` member or a raw
    string naming it (``Confidencialidad``) or its single letter (``C``/``I``/
    ``D``/``A``/``T``), case-insensitively. Values accept a
    :class:`~ens_audit.catalog.models.Nivel` member or ``BAJO``/``MEDIO``/
    ``ALTO``, case-insensitively.
    """
    levels: dict[Dimension, Nivel] = {}
    for raw_key, raw_value in dimensiones.items():
        if isinstance(raw_key, Dimension):
            dimension = raw_key
        else:
            dimension = _DIMENSION_ALIASES.get(str(raw_key).strip().lower())
            if dimension is None:
                raise ValueError(
                    f"Unknown dimension {raw_key!r}; use one of "
                    "Confidencialidad, Integridad, Disponibilidad, Autenticidad, "
                    "Trazabilidad (or C/I/D/A/T)."
                )
        if isinstance(raw_value, Nivel):
            level = raw_value
        else:
            try:
                level = Nivel(str(raw_value).strip().upper())
            except ValueError as exc:
                raise ValueError(
                    f"Unknown level {raw_value!r} for {raw_key!r}; use BAJO, "
                    "MEDIO or ALTO."
                ) from exc
        levels[dimension] = level
    return levels


def _has_no_automated_evidence(code: str) -> bool:
    """Whether the measure code matches the non-automatable heuristic set."""
    return _NO_AUTOMATED_EVIDENCE_RE.match(code) is not None


def _levels_for_category(categoria: Categoria) -> dict[Dimension, Nivel]:
    """Return a uniform dimension valuation for the given category."""
    level = _LEVEL_FOR_CATEGORY[categoria]
    return {dimension: level for dimension in Dimension}


def _resolve_applicability(
    catalog: Catalog,
    categoria: Categoria | None,
    dimensiones: Mapping[Any, Any] | None,
) -> tuple[set[str], dict[str, list[str]], dict[str, str], Categoria | None]:
    """Resolve applicable codes, activated refuerzos, levels and category.

    When ``dimensiones`` is given, applicability (and the derived category plus
    the activated refuerzos) is computed from the per-dimension valuation via
    :func:`~ens_audit.catalog.applicability.compute_applicability`. Otherwise
    the historical uniform valuation for ``categoria`` is used as a fallback.
    Without either, every catalog measure is considered applicable.

    :returns: a ``(applicable_codes, refuerzos_by_code, level_labels,
        resolved_category)`` tuple. ``level_labels`` maps each explicitly valued
        dimension to its level and is empty when only a category (or nothing)
        was supplied; ``resolved_category`` is ``categoria`` when it was given
        (it acts as an override), otherwise the category derived from the
        valuation.
    """
    levels: dict[Dimension, Nivel] | None = None
    if dimensiones is not None:
        levels = _coerce_dimensions(dimensiones)
    elif categoria is not None:
        levels = _levels_for_category(categoria)

    if levels is None:
        return set(catalog.medidas), {}, {}, categoria

    result = compute_applicability(catalog, levels, categoria)
    refuerzos_by_code = {
        item.medida.code: [refuerzo.id for refuerzo in item.refuerzos]
        for item in result.medidas
        if item.refuerzos
    }
    # The categorical fallback is a synthetic uniform valuation and must not be
    # reported as a real per-dimension valuation.
    level_labels = (
        {dimension.value: level.value for dimension, level in levels.items()}
        if dimensiones is not None
        else {}
    )
    return set(result.measure_codes()), refuerzos_by_code, level_labels, result.categoria


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


def _is_demonstrated_failure(finding: Finding) -> bool:
    """Whether a finding demonstrates non-compliance of an applicable measure.

    Only such findings force ``NO_CUMPLE``. A finding that merely signals a risk
    (``demonstrates=False``, e.g. a detected CVE or an unpinned dependency) does
    **not** demonstrate non-compliance. ``INFO`` findings are positive signals.
    """
    return finding.demonstrates and finding.severity is not Severity.INFO


def _is_positive_signal(finding: Finding) -> bool:
    """Whether an ``INFO`` finding is a (legacy) positive signal."""
    return finding.demonstrates and finding.severity is Severity.INFO


def _is_risk(finding: Finding) -> bool:
    """Whether a finding is a non-demonstrated risk signal (never NO_CUMPLE).

    An ``INFO`` finding is a positive signal, not a failure, so it is excluded
    even when ``demonstrates`` is ``False``: it must not cap a measure at
    ``PARCIAL``/``riesgo_detectado``.
    """
    return not finding.demonstrates and finding.severity is not Severity.INFO


def _failed_codes(scan_report: ScanReport | None) -> set[str]:
    """Return every measure code that produced a *demonstrated* failure finding.

    The set spans *all* scanners: a demonstrated failure recorded by one scanner
    must veto the positive evidence another scanner emitted for the same measure,
    so the subtraction is global rather than per scanner. Non-demonstrated risk
    signals are deliberately **not** included: they cap the measure at
    ``PARCIAL`` but must not cancel positive evidence.
    """
    if scan_report is None:
        return set()
    return {
        code
        for finding in scan_report.findings
        if _is_demonstrated_failure(finding)
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


def _collect_refs(
    items: Sequence[Finding | CheckEvidence],
) -> tuple[list[str], list[str]]:
    """Aggregate the requirement/refuerzo refs of the given sources, sorted."""
    requirements = {ref for item in items for ref in item.requirement_refs}
    refuerzos = {ref for item in items for ref in item.refuerzo_refs}
    return sorted(requirements), sorted(refuerzos)


def _requisitos_by_measure(catalog: Catalog) -> dict[str, list[str]]:
    """Return the requirement ids of every catalog measure, keyed by code."""
    return {
        code: [requisito.id for requisito in medida.requisitos]
        for code, medida in catalog.medidas.items()
    }


def _catalog_requirement_refs(
    medida: Medida | None, activated_refuerzos: Sequence[str]
) -> list[str]:
    """Derive the requirement ids a measure carries from the catalog.

    The ids are the measure's own requisitos plus those of every *activated*
    refuerzo (looked up in the measure's refuerzo list). The result is sorted
    and empty when the measure is unknown.
    """
    if medida is None:
        return []
    refs = {requisito.id for requisito in medida.requisitos}
    if activated_refuerzos:
        by_id = {refuerzo.id: refuerzo for refuerzo in medida.refuerzos}
        for refuerzo_id in activated_refuerzos:
            refuerzo = by_id.get(refuerzo_id)
            if refuerzo is not None:
                refs.update(requisito.id for requisito in refuerzo.requisitos)
    return sorted(refs)


def _derive_requirement_refs(
    explicit_refs: Sequence[str],
    measure_codes: Sequence[str],
    requisitos_by_code: Mapping[str, Sequence[str]],
) -> list[str]:
    """Return a source's requirement refs, deriving them from the catalog.

    When the source already carries explicit refs they are preserved verbatim;
    otherwise the union of the requisitos of its ``measure_codes`` is used, so
    the requirement link of the traceability chain is never empty for a mapped
    source.
    """
    if explicit_refs:
        return list(explicit_refs)
    return sorted(
        {ref for code in measure_codes for ref in requisitos_by_code.get(code, ())}
    )


def _evidence_to_dict(item: Evidence) -> dict[str, str]:
    """Serialize one evidence pointer to a stable dictionary."""
    kind = item.kind.value if hasattr(item.kind, "value") else item.kind
    return {
        "kind": str(kind),
        "location": item.location,
        "detail": item.detail,
    }


def _finding_to_dict(
    finding: Finding, requisitos_by_code: Mapping[str, Sequence[str]]
) -> dict[str, Any]:
    """Serialize a finding into the traceability/risk metadata shape.

    ``requirement_refs`` is filled from the catalog when the finding does not
    carry explicit refs, so every mapped finding keeps the requirement link of
    the traceability chain.
    """
    return {
        "id": finding.id,
        "severity": finding.severity.value,
        "message": finding.message,
        "measure_codes": list(finding.measure_codes),
        "scanner": finding.scanner,
        "tool": finding.tool,
        "tool_version": finding.tool_version,
        "method": finding.method.value,
        "confidence": finding.confidence.value,
        "demonstrates": finding.demonstrates,
        "requirement_refs": _derive_requirement_refs(
            finding.requirement_refs, finding.measure_codes, requisitos_by_code
        ),
        "refuerzo_refs": list(finding.refuerzo_refs),
        "evidence": [_evidence_to_dict(item) for item in finding.evidence],
    }


def _check_to_dict(
    check: CheckEvidence, requisitos_by_code: Mapping[str, Sequence[str]]
) -> dict[str, Any]:
    """Serialize a positive check into the traceability metadata shape.

    As with findings, an empty ``requirement_refs`` is derived from the catalog
    so the requirement link is present.
    """
    return {
        "scanner": check.scanner,
        "tool": check.tool,
        "tool_version": check.tool_version,
        "method": check.method.value,
        "confidence": check.confidence.value,
        "kind": check.kind,
        "checked": check.checked,
        "scope": check.scope,
        "result": check.result,
        "covers_all": check.covers_all,
        "measure_codes": list(check.measure_codes),
        "requirement_refs": _derive_requirement_refs(
            check.requirement_refs, check.measure_codes, requisitos_by_code
        ),
        "refuerzo_refs": list(check.refuerzo_refs),
        "evidence": [_evidence_to_dict(item) for item in check.evidence],
    }


def _risk_items(
    scan_report: ScanReport | None,
    requisitos_by_code: Mapping[str, Sequence[str]],
) -> list[dict[str, Any]]:
    """Return the non-demonstrated findings (risk signals), serialized."""
    if scan_report is None:
        return []
    return [
        _finding_to_dict(finding, requisitos_by_code)
        for finding in scan_report.findings
        if _is_risk(finding)
    ]


def _traceability_items(
    scan_report: ScanReport | None,
    requisitos_by_code: Mapping[str, Sequence[str]],
) -> dict[str, list[dict[str, Any]]]:
    """Map each measure code to the chain of sources that speak to it.

    Each entry preserves the traceability chain
    ``measure -> requirement/refuerzo -> tool(+version) -> method -> evidence``,
    so the renderers can surface it without re-deriving it.
    """
    trace: dict[str, list[dict[str, Any]]] = {}
    if scan_report is None:
        return trace
    for finding in scan_report.findings:
        entry = _finding_to_dict(finding, requisitos_by_code)
        for code in finding.measure_codes:
            trace.setdefault(code, []).append(entry)
    for check in scan_report.evidence:
        entry = _check_to_dict(check, requisitos_by_code)
        for code in check.measure_codes:
            trace.setdefault(code, []).append(entry)
    return trace


def _verdict_for_measure(
    code: str,
    *,
    applicable: bool,
    category_label: str,
    assessment: Assessment | None,
    findings: list[Finding],
    check_evidence: list[CheckEvidence],
    activated_refuerzos: list[str],
    catalog_requirement_refs: list[str],
) -> MeasureVerdict:
    """Resolve the verdict of a single measure following the precedence rules.

    ``activated_refuerzos`` are the refuerzos the applicability engine activated
    for this measure (empty when no per-dimension valuation was resolved). They
    are merged into the verdict's ``refuerzo_refs`` alongside any refuerzo
    referenced by the evidence, so the activated scope is never lost.

    ``catalog_requirement_refs`` are the requirement ids derived from the
    catalog (the measure's own requisitos plus those of its activated
    refuerzos). They are the requirement link of the traceability chain and are
    merged with any requirement refs carried explicitly by the evidence, so the
    link is never empty for an applicable measure.
    """
    if assessment is not None:
        # A manual ``no_aplica`` verdict removes the measure from scope, so it
        # carries no activated refuerzos nor requirement refs; any other verdict
        # keeps the refuerzos the applicability engine activated for this
        # measure and the measure's catalog requirement ids.
        not_applicable = assessment.verdict is Verdict.NO_APLICA
        return MeasureVerdict(
            measure_code=code,
            verdict=assessment.verdict,
            evidence_state=_ASSESSMENT_EVIDENCE_STATE[assessment.verdict],
            evidence=list(assessment.evidence),
            rationale=assessment.notes or "Explicit manual assessment.",
            requirement_refs=(
                [] if not_applicable else list(catalog_requirement_refs)
            ),
            refuerzo_refs=[] if not_applicable else list(activated_refuerzos),
        )

    if not applicable:
        return MeasureVerdict(
            measure_code=code,
            verdict=Verdict.NO_APLICA,
            evidence_state=EvidenceState.NO_APLICA,
            rationale=f"Measure not applicable to category {category_label}.",
        )

    evidence_requirements, evidence_refuerzos = _collect_refs(
        [*findings, *check_evidence]
    )
    requirement_refs = sorted(
        set(catalog_requirement_refs) | set(evidence_requirements)
    )
    refuerzo_refs = sorted(set(activated_refuerzos) | set(evidence_refuerzos))

    demonstrated = [
        finding for finding in findings if _is_demonstrated_failure(finding)
    ]
    if demonstrated:
        # Demonstrated non-compliance dominates everything else. Positive
        # evidence for this measure was already excluded globally
        # (``_failed_codes``), so no clean check can downgrade it.
        return MeasureVerdict(
            measure_code=code,
            verdict=Verdict.NO_CUMPLE,
            evidence_state=EvidenceState.INCUMPLIMIENTO_DEMOSTRADO,
            evidence=_collect_evidence(demonstrated),
            rationale=(
                f"{len(demonstrated)} demonstrated non-compliance finding(s) "
                "for this measure."
            ),
            requirement_refs=requirement_refs,
            refuerzo_refs=refuerzo_refs,
        )

    risks = [finding for finding in findings if _is_risk(finding)]
    if risks:
        # A non-demonstrated signal (a risk) caps the measure at PARCIAL: it may
        # not force NO_CUMPLE, and it may not be read as compliance either. Its
        # evidence state is ``riesgo_detectado`` -- distinct from ``no_detectado``
        # (which means "checked and found nothing"). The signals are surfaced
        # separately as risks in the report.
        return MeasureVerdict(
            measure_code=code,
            verdict=Verdict.PARCIAL,
            evidence_state=EvidenceState.RIESGO_DETECTADO,
            evidence=_collect_evidence(risks),
            rationale=(
                f"{len(risks)} non-demonstrated risk signal(s) for this measure."
            ),
            requirement_refs=requirement_refs,
            refuerzo_refs=refuerzo_refs,
        )

    positive_findings = [
        finding for finding in findings if _is_positive_signal(finding)
    ]
    positive_count = len(positive_findings) + len(check_evidence)

    if positive_count > 0:
        positive_evidence = _collect_check_evidence(
            check_evidence
        ) + _collect_evidence(positive_findings)
        if any(check.covers_all for check in check_evidence):
            return MeasureVerdict(
                measure_code=code,
                verdict=Verdict.CUMPLE,
                evidence_state=EvidenceState.CUMPLIMIENTO_DEMOSTRADO,
                evidence=positive_evidence,
                rationale=(
                    "Explicit scanner check covers all applicable requirements "
                    "of this measure."
                ),
                requirement_refs=requirement_refs,
                refuerzo_refs=refuerzo_refs,
            )
        return MeasureVerdict(
            measure_code=code,
            verdict=Verdict.PARCIAL,
            evidence_state=EvidenceState.NO_DETECTADO,
            evidence=positive_evidence,
            rationale=f"{positive_count} passing scanner signal(s) for this measure.",
            requirement_refs=requirement_refs,
            refuerzo_refs=refuerzo_refs,
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
        evidence_state=EvidenceState.NO_COMPROBADO,
        rationale=rationale,
        requirement_refs=requirement_refs,
        refuerzo_refs=refuerzo_refs,
    )


def evaluate_compliance(
    catalog: Catalog,
    scan_report: ScanReport | None = None,
    assessments: Sequence[Assessment] | Mapping[str, Assessment] | None = None,
    categoria: Categoria | str | None = None,
    dimensiones: Mapping[Any, Any] | None = None,
) -> ComplianceReport:
    """Evaluate every catalog measure and build a compliance report.

    :param catalog: parsed ENS catalog (the source of the 73 measures).
    :param scan_report: optional scanner output; its findings are aggregated
        through their ``measure_codes``.
    :param assessments: optional manual assessments, as a sequence or a mapping
        of measure code to :class:`Assessment`. An explicit assessment always
        wins over scan-derived verdicts.
    :param categoria: optional system category; when given, measures not
        applicable to it are reported as ``NO_APLICA``. When ``dimensiones`` is
        also given, ``categoria`` acts as an override of the derived category.
    :param dimensiones: optional per-dimension valuation mapping each security
        dimension (name or ``C``/``I``/``D``/``A``/``T``) to its level
        (``BAJO``/``MEDIO``/``ALTO``). When given, applicability, the derived
        category and the activated refuerzos are resolved through
        :func:`~ens_audit.catalog.applicability.compute_applicability`; when
        absent the historical ``categoria``-only uniform valuation is used.
    :returns: a :class:`ComplianceReport` with one verdict per catalog measure,
        the aggregate summary and metadata (including the compliance and
        coverage percentages over applicable measures, the dimension valuation,
        the derived category, the activated refuerzos, the serialized positive
        evidence and each scanner's execution status).
    """
    category = _coerce_category(categoria)
    applicable, refuerzos_by_code, dimension_labels, resolved_category = (
        _resolve_applicability(catalog, category, dimensiones)
    )
    category = category or resolved_category
    category_label = category.value if category is not None else ""
    assessments_by_code = _index_assessments(assessments)
    findings_by_code = _group_findings(scan_report)
    check_evidence_by_code = _group_check_evidence(
        scan_report, _failed_codes(scan_report)
    )
    requisitos_by_code = _requisitos_by_measure(catalog)
    catalog_refs_by_code = {
        code: _catalog_requirement_refs(
            catalog.medidas.get(code), refuerzos_by_code.get(code, [])
        )
        for code in catalog.measure_codes()
    }

    verdicts: list[MeasureVerdict] = [
        _verdict_for_measure(
            code,
            applicable=code in applicable,
            category_label=category_label,
            assessment=assessments_by_code.get(code),
            findings=findings_by_code.get(code, []),
            check_evidence=check_evidence_by_code.get(code, []),
            activated_refuerzos=refuerzos_by_code.get(code, []),
            catalog_requirement_refs=catalog_refs_by_code.get(code, []),
        )
        for code in catalog.measure_codes()
    ]

    summary = ComplianceSummary.from_verdicts(verdicts)
    metadata: dict[str, Any] = {
        "catalog_norma": catalog.norma,
        "catalog_version": catalog.version,
        "catalog_uuid": catalog.uuid,
        "category": category_label,
        # Per-dimension valuation used to derive applicability (empty when only a
        # category was supplied).
        "dimensions": dimension_labels,
        # Activated refuerzos per applicable measure: measure -> [refuerzo id].
        "refuerzos": refuerzos_by_code,
        "target": scan_report.target if scan_report is not None else None,
        "scanners": list(scan_report.scanners) if scan_report is not None else [],
        "finding_count": len(scan_report.findings) if scan_report is not None else 0,
        "evidence": (
            [
                {
                    **item.model_dump(mode="json"),
                    # Fill the requirement link when the scanner did not set it,
                    # mirroring the risk/traceability serialization.
                    "requirement_refs": _derive_requirement_refs(
                        item.requirement_refs,
                        item.measure_codes,
                        requisitos_by_code,
                    ),
                }
                for item in scan_report.evidence
            ]
            if scan_report is not None
            else []
        ),
        "scanner_status": (
            dict(scan_report.scanner_status) if scan_report is not None else {}
        ),
        # Non-demonstrated findings: risk signals that must be reviewed but do
        # not demonstrate non-compliance of an applicable requirement.
        "risks": _risk_items(scan_report, requisitos_by_code),
        # Traceability chain per measure: measure -> requirement/refuerzo ->
        # tool(+version) -> method -> evidence.
        "traceability": _traceability_items(scan_report, requisitos_by_code),
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
