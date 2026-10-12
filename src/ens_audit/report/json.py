"""JSON renderer for a :class:`~ens_audit.models.ComplianceReport`.

Produces a stable, versioned document (``schema_version``) intended for
machine consumption. The ordering of ``verdicts`` follows catalog order when a
catalog is supplied, so consecutive renders of the same inputs differ only in
``generated_at``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from ..catalog.models import Catalog
from ..models import ComplianceReport, Evidence, MeasureVerdict
from . import (
    activated_refuerzos,
    dimension_levels,
    positive_evidence_items,
    risk_items,
    scanner_status_items,
    traceability_map,
)

__all__ = ["render_json", "write_json"]

#: Current JSON schema version of the rendered document.
SCHEMA_VERSION = "1.6"


def _ordered_verdicts(
    report: ComplianceReport, catalog: Catalog | None
) -> list[MeasureVerdict]:
    """Return the report verdicts in catalog order when a catalog is given."""
    if catalog is None:
        return list(report.verdicts)
    by_code = {v.measure_code: v for v in report.verdicts}
    ordered = [by_code[code] for code in catalog.measure_codes() if code in by_code]
    seen = {v.measure_code for v in ordered}
    ordered.extend(v for v in report.verdicts if v.measure_code not in seen)
    return ordered


def _evidence_to_dict(evidence: Evidence) -> dict[str, str]:
    """Serialize a single evidence item to a stable dictionary."""
    kind = evidence.kind.value if hasattr(evidence.kind, "value") else evidence.kind
    return {
        "kind": str(kind),
        "location": evidence.location,
        "detail": evidence.detail,
    }


def _summary_value(
    summary: object, metadata: dict[str, object], key: str
) -> object:
    """Return a summary attribute, falling back to ``metadata`` when absent."""
    value = getattr(summary, key, None)
    if value is None:
        return metadata.get(key)
    return value


def _summary_to_dict(report: ComplianceReport) -> dict[str, object]:
    """Serialize the aggregate verdict counts plus both derived ratios.

    ``report.summary`` is the authoritative source: the applicable count and
    both ratios are read from it, and the equivalent ``metadata`` keys are used
    only as a fallback when the summary does not carry a value (so a hand-built
    report whose metadata is richer still renders consistently).
    """
    summary = report.summary
    metadata = report.metadata or {}
    return {
        "total": summary.total,
        "cumple": summary.cumple,
        "no_cumple": summary.no_cumple,
        "parcial": summary.parcial,
        "no_aplica": summary.no_aplica,
        "no_evaluable": summary.no_evaluable,
        "applicable": _summary_value(summary, metadata, "applicable"),
        "compliance_pct": _summary_value(summary, metadata, "compliance_pct"),
        "coverage_pct": _summary_value(summary, metadata, "coverage_pct"),
        # Epistemic evidence-state counts (orthogonal to the verdict counts).
        "no_comprobado": summary.no_comprobado,
        "no_detectado": summary.no_detectado,
        "riesgo_detectado": summary.riesgo_detectado,
        "no_concluyente": summary.no_concluyente,
        "cumplimiento_demostrado": summary.cumplimiento_demostrado,
        "incumplimiento_demostrado": summary.incumplimiento_demostrado,
    }


def build_document(
    report: ComplianceReport, catalog: Catalog | None = None
) -> dict[str, object]:
    """Build the JSON-serializable document for ``report``."""
    trace = traceability_map(report)
    verdicts: list[dict[str, object]] = []
    for verdict in _ordered_verdicts(report, catalog):
        medida = catalog.medidas.get(verdict.measure_code) if catalog else None
        verdicts.append(
            {
                "code": verdict.measure_code,
                "name": medida.name if medida is not None else "",
                "verdict": verdict.verdict.value,
                "evidence_state": verdict.evidence_state.value,
                "requirement_refs": list(verdict.requirement_refs),
                "refuerzo_refs": list(verdict.refuerzo_refs),
                "traceability": trace.get(verdict.measure_code, []),
                "evidence": [
                    _evidence_to_dict(evidence) for evidence in verdict.evidence
                ],
                "rationale": verdict.rationale,
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "category": report.category,
        # Per-dimension valuation used to derive applicability (empty when only a
        # category was supplied) and the refuerzos it activated per measure.
        "dimensions": dict(dimension_levels(report)),
        "refuerzos": activated_refuerzos(report),
        "summary": _summary_to_dict(report),
        "evidence": positive_evidence_items(report),
        "risks": risk_items(report),
        "scanner_status": scanner_status_items(report),
        "verdicts": verdicts,
    }


def render_json(
    report: ComplianceReport,
    catalog: Catalog | None = None,
    indent: int = 2,
) -> str:
    """Render a compliance report as a versioned JSON string.

    :param report: the consolidated compliance report.
    :param catalog: optional catalog used to enrich each verdict with the
        measure name and to impose a deterministic (catalog) ordering.
    :param indent: JSON indentation width.
    :returns: the JSON document as a string.
    """
    document = build_document(report, catalog=catalog)
    return json.dumps(document, indent=indent, ensure_ascii=False)


def write_json(
    report: ComplianceReport,
    path: str | Path,
    catalog: Catalog | None = None,
    indent: int = 2,
) -> Path:
    """Render ``report`` as JSON and write it to ``path``.

    :returns: the :class:`pathlib.Path` written to.
    """
    destination = Path(path)
    destination.write_text(
        render_json(report, catalog=catalog, indent=indent) + "\n",
        encoding="utf-8",
    )
    return destination
