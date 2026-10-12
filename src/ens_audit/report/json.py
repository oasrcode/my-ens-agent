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

__all__ = ["render_json", "write_json"]

#: Current JSON schema version of the rendered document.
SCHEMA_VERSION = "1.0"


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


def _summary_to_dict(report: ComplianceReport) -> dict[str, object]:
    """Serialize the aggregate verdict counts plus derived compliance ratio."""
    summary = report.summary
    return {
        "total": summary.total,
        "cumple": summary.cumple,
        "no_cumple": summary.no_cumple,
        "parcial": summary.parcial,
        "no_aplica": summary.no_aplica,
        "no_evaluable": summary.no_evaluable,
        "applicable": report.metadata.get("applicable", 0),
        "compliance_pct": report.metadata.get("compliance_pct", 0.0),
    }


def build_document(
    report: ComplianceReport, catalog: Catalog | None = None
) -> dict[str, object]:
    """Build the JSON-serializable document for ``report``."""
    verdicts: list[dict[str, object]] = []
    for verdict in _ordered_verdicts(report, catalog):
        medida = catalog.medidas.get(verdict.measure_code) if catalog else None
        verdicts.append(
            {
                "code": verdict.measure_code,
                "name": medida.name if medida is not None else "",
                "verdict": verdict.verdict.value,
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
        "summary": _summary_to_dict(report),
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
