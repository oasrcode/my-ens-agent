"""Markdown renderer for a :class:`~ens_audit.models.ComplianceReport`.

The generated document is written in Spanish (the audit's working language)
while all identifiers, comments and docstrings stay in English. It contains the
sections expected from an ENS conformity report: metadata, executive summary,
scope and methodology, categorisation, the full table of the 73 measures,
non-conformities and recommendations.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from ..catalog.models import Catalog, Medida
from ..models import ComplianceReport, Evidence, MeasureVerdict, Verdict
from . import _human_note

__all__ = ["render_markdown", "write_markdown"]

#: Human-readable Spanish labels for each verdict.
_VERDICT_LABELS: dict[str, str] = {
    Verdict.CUMPLE.value: "Cumple",
    Verdict.NO_CUMPLE.value: "No cumple",
    Verdict.PARCIAL.value: "Parcial",
    Verdict.NO_APLICA.value: "No aplica",
    Verdict.NO_EVALUABLE.value: "No evaluable",
}

#: Verdicts rendered as non-conformities (major: no cumple; minor: parcial).
_NON_CONFORMITY_VERDICTS = (Verdict.NO_CUMPLE, Verdict.PARCIAL)

_STRINGS: dict[str, dict[str, str]] = {
    "es": {
        "title": "Informe de cumplimiento del ENS",
        "metadata": "Metadatos",
        "system": "Sistema",
        "category": "Categoría",
        "date": "Fecha",
        "norm": "Norma",
        "catalog_version": "Versión del catálogo",
        "not_specified": "No especificado",
        "exec_summary": "Resumen ejecutivo",
        "verdict": "Veredicto",
        "measure_count": "Nº de medidas",
        "compliance_pct": "Porcentaje de cumplimiento",
        "scope": "Alcance y metodología",
        "categorisation": "Categorización",
        "measures_table": "Tabla completa de medidas",
        "code": "Código",
        "measure": "Medida",
        "marco_family": "Marco / Familia",
        "non_conformities": "No conformidades",
        "recommendations": "Recomendaciones",
        "rationale": "Justificación",
        "evidence": "Evidencia",
        "no_evidence": "Sin evidencia registrada.",
        "none": "Ninguna.",
    },
    "en": {
        "title": "ENS compliance report",
        "metadata": "Metadata",
        "system": "System",
        "category": "Category",
        "date": "Date",
        "norm": "Standard",
        "catalog_version": "Catalog version",
        "not_specified": "Not specified",
        "exec_summary": "Executive summary",
        "verdict": "Verdict",
        "measure_count": "Measures",
        "compliance_pct": "Compliance percentage",
        "scope": "Scope and methodology",
        "categorisation": "Categorisation",
        "measures_table": "Full measure table",
        "code": "Code",
        "measure": "Measure",
        "marco_family": "Framework / Family",
        "non_conformities": "Non-conformities",
        "recommendations": "Recommendations",
        "rationale": "Rationale",
        "evidence": "Evidence",
        "no_evidence": "No evidence recorded.",
        "none": "None.",
    },
}

_VERDICT_LABELS_EN: dict[str, str] = {
    Verdict.CUMPLE.value: "Compliant",
    Verdict.NO_CUMPLE.value: "Non-compliant",
    Verdict.PARCIAL.value: "Partial",
    Verdict.NO_APLICA.value: "Not applicable",
    Verdict.NO_EVALUABLE.value: "Not evaluable",
}


def _strings(language: str) -> dict[str, str]:
    """Return the string table for ``language``, falling back to Spanish."""
    return _STRINGS.get(language, _STRINGS["es"])


def _verdict_label(verdict: Verdict, language: str) -> str:
    """Return the human-readable label of a verdict."""
    labels = _VERDICT_LABELS_EN if language == "en" else _VERDICT_LABELS
    return labels.get(verdict.value, verdict.value)


def _cell(text: object) -> str:
    """Escape a value so it can be safely embedded in a Markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


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


def _measure_of(catalog: Catalog | None, code: str) -> Medida | None:
    """Return the catalog measure for ``code``, if present."""
    if catalog is None:
        return None
    return catalog.medidas.get(code)


def _format_evidence(evidence: Evidence) -> str:
    """Render a single evidence item as a Markdown bullet body."""
    detail = f": {evidence.detail}" if evidence.detail else ""
    kind = evidence.kind.value if hasattr(evidence.kind, "value") else evidence.kind
    return f"`{evidence.location}` ({kind}){detail}"


def _render_metadata(report: ComplianceReport, t: dict[str, str]) -> list[str]:
    """Render the metadata section."""
    metadata = report.metadata or {}
    rows = [
        (t["system"], metadata.get("target") or t["not_specified"]),
        (t["category"], report.category or t["not_specified"]),
        (t["date"], metadata.get("generated_at") or _now_label()),
        (t["norm"], metadata.get("catalog_norma") or t["not_specified"]),
        (t["catalog_version"], metadata.get("catalog_version") or t["not_specified"]),
    ]
    lines = [f"## {t['metadata']}", "", "| Campo | Valor |", "|---|---|"]
    lines += [f"| {_cell(label)} | {_cell(value)} |" for label, value in rows]
    lines.append("")
    return lines


def _render_summary(
    report: ComplianceReport, t: dict[str, str], language: str
) -> list[str]:
    """Render the executive summary (verdict counts and compliance ratio)."""
    summary = report.summary
    total = summary.total or 1
    rows = [
        (Verdict.CUMPLE, summary.cumple),
        (Verdict.NO_CUMPLE, summary.no_cumple),
        (Verdict.PARCIAL, summary.parcial),
        (Verdict.NO_APLICA, summary.no_aplica),
        (Verdict.NO_EVALUABLE, summary.no_evaluable),
    ]
    compliance_pct = report.metadata.get("compliance_pct")
    lines = [
        f"## {t['exec_summary']}",
        "",
        (
            f"Se han evaluado **{summary.total}** medidas del catálogo ENS. "
            f"El porcentaje de cumplimiento sobre las medidas aplicables es "
            f"**{compliance_pct if compliance_pct is not None else 0.0} %**."
        ),
        "",
        f"| {t['verdict']} | {t['measure_count']} | % |",
        "|---|---:|---:|",
    ]
    for verdict, count in rows:
        pct = round(100 * count / total, 2)
        lines.append(
            f"| {_verdict_label(verdict, language)} | {count} | {pct} % |"
        )
    lines.append("")
    return lines


def _render_scope(
    report: ComplianceReport, t: dict[str, str], catalog: Catalog | None
) -> list[str]:
    """Render the scope and methodology section."""
    metadata = report.metadata or {}
    norm = metadata.get("catalog_norma") or "RD 311/2022"
    scanners = metadata.get("scanners") or []
    scanner_list = ", ".join(scanners) if scanners else "ninguno"
    lines = [
        f"## {t['scope']}",
        "",
        (
            f"Alcance: se auditan las **{report.summary.total}** medidas de "
            f"seguridad del Anexo II del ENS ({norm}) presentes en el catálogo "
            f"OSCAL de referencia."
        ),
        "",
        (
            "Metodología: los veredictos se consolidan con `evaluate_compliance` "
            "siguiendo este orden de precedencia: (1) evaluación manual explícita; "
            "(2) aplicabilidad según la categoría del sistema; (3) hallazgos de "
            "los escáneres deterministas; (4) medidas documentales/organizativas "
            "o físicas sin evidencia automatizable (no evaluables); y (5) "
            "cumplimiento por defecto cuando no hay hallazgos."
        ),
        "",
        f"- Escáneres ejecutados: {scanner_list}.",
        f"- Hallazgos registrados: {metadata.get('finding_count', 0)}.",
        f"- Medidas aplicables: {metadata.get('applicable', 0)}.",
        "",
    ]
    return lines


def _render_categorisation(report: ComplianceReport, t: dict[str, str]) -> list[str]:
    """Render the categorisation section."""
    category = report.category or t["not_specified"]
    return [
        f"## {t['categorisation']}",
        "",
        (
            f"El sistema evaluado se clasifica en la categoría **{category}**. "
            "La aplicabilidad de cada medida se deriva de esa categoría y de la "
            "valoración de las dimensiones de seguridad (confidencialidad, "
            "integridad, disponibilidad, autenticidad y trazabilidad) conforme "
            "al Anexo I del RD 311/2022."
        ),
        "",
    ]


def _render_measures_table(
    report: ComplianceReport,
    catalog: Catalog | None,
    t: dict[str, str],
    language: str,
) -> list[str]:
    """Render the full table of measures (one row per catalog measure)."""
    lines = [
        f"## {t['measures_table']}",
        "",
        (
            f"| {t['code']} | {t['measure']} | {t['marco_family']} | "
            f"{t['verdict']} |"
        ),
        "|---|---|---|---|",
    ]
    for verdict in _ordered_verdicts(report, catalog):
        medida = _measure_of(catalog, verdict.measure_code)
        name = medida.name if medida is not None else ""
        if medida is not None:
            family = medida.familia_nombre or medida.familia
            marco_family = f"{medida.marco} / {family}"
        else:
            marco_family = ""
        lines.append(
            f"| `{_cell(verdict.measure_code)}` | {_cell(name)} | "
            f"{_cell(marco_family)} | "
            f"{_verdict_label(verdict.verdict, language)} |"
        )
    lines.append("")
    return lines


def _render_non_conformities(
    report: ComplianceReport, catalog: Catalog | None, t: dict[str, str], language: str
) -> list[str]:
    """Render the non-conformities section with evidence and rationale."""
    lines = [f"## {t['non_conformities']}", ""]
    findings = [
        verdict
        for verdict in _ordered_verdicts(report, catalog)
        if verdict.verdict in _NON_CONFORMITY_VERDICTS
    ]
    if not findings:
        lines += [f"_{t['none']}_", ""]
        return lines
    for verdict in findings:
        medida = _measure_of(catalog, verdict.measure_code)
        name = f" — {medida.name}" if medida is not None else ""
        label = _verdict_label(verdict.verdict, language)
        lines.append(f"### `{verdict.measure_code}`{name} ({label})")
        lines.append("")
        rationale = _human_note(verdict.rationale) or t["none"]
        lines.append(f"- **{t['rationale']}:** {rationale}")
        if verdict.evidence:
            lines.append(f"- **{t['evidence']}:**")
            lines += [
                f"  - {_format_evidence(evidence)}" for evidence in verdict.evidence
            ]
        else:
            lines.append(f"- **{t['evidence']}:** {t['no_evidence']}")
        lines.append("")
    return lines


def _render_recommendations(
    report: ComplianceReport, catalog: Catalog | None, t: dict[str, str]
) -> list[str]:
    """Render prioritised, data-driven recommendations."""
    ordered = _ordered_verdicts(report, catalog)
    no_cumple = [v.measure_code for v in ordered if v.verdict is Verdict.NO_CUMPLE]
    parcial = [v.measure_code for v in ordered if v.verdict is Verdict.PARCIAL]
    no_evaluable = [
        v.measure_code for v in ordered if v.verdict is Verdict.NO_EVALUABLE
    ]
    lines = [f"## {t['recommendations']}", ""]
    if no_cumple:
        lines.append(
            f"- Remediar **{len(no_cumple)}** no conformidad(es) mayor(es) "
            f"(no cumple): {', '.join(no_cumple)}."
        )
    if parcial:
        lines.append(
            f"- Revisar **{len(parcial)}** medida(s) con cumplimiento parcial: "
            f"{', '.join(parcial)}."
        )
    if no_evaluable:
        lines.append(
            f"- Aportar evidencia documental o evaluación manual para "
            f"**{len(no_evaluable)}** medida(s) no evaluables: "
            f"{', '.join(no_evaluable)}."
        )
    if not (no_cumple or parcial or no_evaluable):
        lines.append(
            "- Todas las medidas aplicables cumplen. Mantener las evidencias y "
            "repetir la auditoría con la periodicidad establecida."
        )
    lines.append("")
    return lines


def _now_label() -> str:
    """Return the current UTC timestamp formatted for the report."""
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")


def render_markdown(
    report: ComplianceReport,
    catalog: Catalog | None = None,
    language: str = "es",
) -> str:
    """Render a compliance report as a Spanish Markdown document.

    :param report: the consolidated compliance report.
    :param catalog: optional catalog used to enrich each measure with its name
        and family; when omitted, measures are shown by code only.
    :param language: report language; ``"es"`` (default) or ``"en"``.
    :returns: the complete Markdown document as a string.
    """
    t = _strings(language)
    lines: list[str] = [
        f"# {t['title']}",
        "",
        "> _Generado automáticamente por `ens_audit`._",
        "",
    ]
    lines += _render_metadata(report, t)
    lines += _render_summary(report, t, language)
    lines += _render_scope(report, t, catalog)
    lines += _render_categorisation(report, t)
    lines += _render_measures_table(report, catalog, t, language)
    lines += _render_non_conformities(report, catalog, t, language)
    lines += _render_recommendations(report, catalog, t)
    return "\n".join(lines).rstrip() + "\n"


def write_markdown(
    report: ComplianceReport,
    path: str | Path,
    catalog: Catalog | None = None,
    language: str = "es",
) -> Path:
    """Render ``report`` as Markdown and write it to ``path``.

    :returns: the :class:`pathlib.Path` written to.
    """
    destination = Path(path)
    destination.write_text(
        render_markdown(report, catalog=catalog, language=language),
        encoding="utf-8",
    )
    return destination
