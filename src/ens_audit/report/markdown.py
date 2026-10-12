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
from ..models import ComplianceReport, Evidence, EvidenceState, MeasureVerdict, Verdict
from . import (
    _human_note,
    activated_refuerzos,
    checked_label_es,
    dimension_levels,
    evidence_state_label_es,
    positive_evidence_items,
    result_label_es,
    risk_items,
    scanner_status_items,
    trace_source_label,
    traceability_map,
)

__all__ = ["render_markdown", "write_markdown"]

#: Human-readable Spanish labels for each verdict.
_VERDICT_LABELS: dict[str, str] = {
    Verdict.CUMPLE.value: "Cumple",
    Verdict.NO_CUMPLE.value: "No cumple",
    Verdict.PARCIAL.value: "Parcial",
    Verdict.NO_APLICA.value: "No aplica",
    Verdict.NO_EVALUABLE.value: "No evaluable",
}

#: Human-readable Spanish labels for a finding severity.
_SEVERITY_LABELS: dict[str, str] = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Media",
    "low": "Baja",
    "info": "Informativa",
}

#: Verdicts rendered as non-conformities (major: no cumple; minor: parcial).
_NON_CONFORMITY_VERDICTS = (Verdict.NO_CUMPLE, Verdict.PARCIAL)

#: Language used when the requested one is unknown. Only Spanish is authored.
_DEFAULT_LANGUAGE = "es"

#: Human-readable labels for the scanner execution statuses.
_STATUS_LABELS: dict[str, dict[str, str]] = {
    "es": {
        "completed": "Completado",
        "failed": "Fallido",
        "skipped": "Omitido",
    },
}

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
        "pct_of_total": "% del total",
        "compliance_pct": "Porcentaje de cumplimiento",
        "scope": "Alcance y metodología",
        "categorisation": "Categorización",
        "dims_refuerzos": "Dimensiones y refuerzos",
        "dims_refuerzos_lead": (
            "Valoración de las dimensiones de seguridad y refuerzos activados a "
            "partir de ella."
        ),
        "dimension": "Dimensión",
        "level": "Nivel",
        "activated_refuerzos": "Refuerzos activados",
        "no_activated_refuerzos": "Sin refuerzos activados para la valoración dada.",
        "no_dimension_valuation": "Sin valoración por dimensiones registrada.",
        "compliance_label": "Cumplimiento",
        "coverage_label": "Cobertura de evaluación",
        "applicable": "medidas aplicables",
        "positive_evidence": "Evidencia positiva",
        "positive_evidence_lead": (
            "Comprobaciones de escáner con resultado favorable: qué se comprobó, "
            "alcance y fecha."
        ),
        "no_positive_evidence": "Sin evidencia positiva registrada.",
        "scanner_status": "Estado de los escáneres",
        "scanner_status_lead": "Resultado de la ejecución de cada escáner.",
        "no_scanner_status": "Sin datos de ejecución de escáneres.",
        "scanner": "Escáner",
        "status": "Estado",
        "checked": "Comprobado",
        "result": "Resultado",
        "evidence_scope": "Alcance",
        "observed_at": "Fecha",
        "failed_scanners": "Escáneres fallidos",
        "failed_scanners_note": "Sus medidas quedan como no evaluables.",
        "measures_table": "Tabla completa de medidas",
        "code": "Código",
        "measure": "Medida",
        "marco_family": "Marco / Familia",
        "evidence_state": "Estado de la evidencia",
        "requirements": "Requisitos",
        "refuerzos": "Refuerzos",
        "traceability": "Trazabilidad",
        "evidence_state_summary": "Estados de la evidencia",
        "evidence_state_summary_lead": (
            "Recuento de medidas según el estado de la evidencia: no comprobado, "
            "no detectado, riesgo detectado, no concluyente, cumplimiento "
            "demostrado e incumplimiento demostrado."
        ),
        "risks": "Riesgos",
        "risks_lead": (
            "Señales de riesgo no demostrativas (por ejemplo, vulnerabilidades o "
            "dependencias sin fijar): no acreditan incumplimiento, pero deben "
            "revisarse."
        ),
        "no_risks": "Sin señales de riesgo registradas.",
        "risk": "Riesgo",
        "severity": "Severidad",
        "measures": "Medidas",
        "tool_method": "Herramienta/Método",
        "non_conformities": "No conformidades",
        "recommendations": "Recomendaciones",
        "rationale": "Justificación",
        "evidence": "Evidencia",
        "no_evidence": "Sin evidencia registrada.",
        "none": "Ninguna.",
    },
}


def _strings(language: str) -> dict[str, str]:
    """Return the string table for ``language``, falling back to Spanish."""
    return _STRINGS.get(language) or _STRINGS[_DEFAULT_LANGUAGE]


def _verdict_label(verdict: Verdict) -> str:
    """Return the human-readable (Spanish) label of a verdict."""
    return _VERDICT_LABELS.get(verdict.value, verdict.value)


def _cell(text: object) -> str:
    """Escape a value so it can be safely embedded in a Markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def _ratio(report: ComplianceReport, key: str, fallback: float) -> float:
    """Return a percentage, preferring ``report.summary`` over metadata.

    ``report.summary`` is the authoritative source for the aggregate ratios;
    the equivalent ``metadata`` key is only consulted when the summary does not
    carry a numeric value. ``fallback`` is the last resort. The result is
    clamped to ``[0, 100]``, mirroring
    :func:`ens_audit.report.html._summary_ratio`.
    """
    value = getattr(report.summary, key, None)
    if not isinstance(value, (int, float)):
        value = (report.metadata or {}).get(key)
    if not isinstance(value, (int, float)):
        value = fallback
    return max(0.0, min(100.0, float(value)))


def _status_label(status: str) -> str:
    """Return the human-readable (Spanish) label of a scanner status."""
    labels = _STATUS_LABELS[_DEFAULT_LANGUAGE]
    return labels.get(status, status)


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


def _render_summary(report: ComplianceReport, t: dict[str, str]) -> list[str]:
    """Render the executive summary: the five counts and both ratios."""
    summary = report.summary
    total = summary.total or 1
    rows = [
        (Verdict.CUMPLE, summary.cumple),
        (Verdict.NO_CUMPLE, summary.no_cumple),
        (Verdict.PARCIAL, summary.parcial),
        (Verdict.NO_APLICA, summary.no_aplica),
        (Verdict.NO_EVALUABLE, summary.no_evaluable),
    ]
    compliance_pct = _ratio(report, "compliance_pct", summary.compliance_pct)
    coverage_pct = _ratio(report, "coverage_pct", summary.coverage_pct)
    covered = summary.applicable - summary.no_evaluable
    lines = [
        f"## {t['exec_summary']}",
        "",
        f"Se han evaluado **{summary.total}** medidas del catálogo ENS.",
        "",
        (
            f"- **{t['compliance_label']}:** **{compliance_pct} %** "
            f"({summary.cumple} / {summary.applicable} {t['applicable']})."
        ),
        (
            f"- **{t['coverage_label']}:** **{coverage_pct} %** "
            f"({covered} / {summary.applicable} {t['applicable']})."
        ),
        "",
        # The headline ratios are applicable-based; the table below shows each
        # verdict's share of the *whole* catalog, so its column is labelled
        # explicitly ("% del total") to avoid a mixed denominator.
        f"| {t['verdict']} | {t['measure_count']} | {t['pct_of_total']} |",
        "|---|---:|---:|",
    ]
    for verdict, count in rows:
        pct = round(100 * count / total, 2)
        lines.append(
            f"| {_verdict_label(verdict)} | {count} | {pct} % |"
        )
    lines.append("")

    # Epistemic evidence-state counts (orthogonal to the verdict counts): they
    # keep "not checked" distinct from "checked and clean" and from "proven".
    state_rows = [
        (EvidenceState.NO_COMPROBADO, summary.no_comprobado),
        (EvidenceState.NO_DETECTADO, summary.no_detectado),
        (EvidenceState.RIESGO_DETECTADO, summary.riesgo_detectado),
        (EvidenceState.NO_CONCLUYENTE, summary.no_concluyente),
        (EvidenceState.CUMPLIMIENTO_DEMOSTRADO, summary.cumplimiento_demostrado),
        (EvidenceState.INCUMPLIMIENTO_DEMOSTRADO, summary.incumplimiento_demostrado),
    ]
    lines += [
        f"### {t['evidence_state_summary']}",
        "",
        f"_{t['evidence_state_summary_lead']}_",
        "",
        f"| {t['evidence_state']} | {t['measure_count']} |",
        "|---|---:|",
    ]
    for state, count in state_rows:
        lines.append(f"| {evidence_state_label_es(state)} | {count} |")
    lines.append("")
    return lines


def _render_positive_evidence(
    report: ComplianceReport, t: dict[str, str]
) -> list[str]:
    """Render the positive evidence section from the report metadata."""
    items = positive_evidence_items(report)
    lines = [f"## {t['positive_evidence']}", "", f"_{t['positive_evidence_lead']}_", ""]
    if not items:
        lines += [f"_{t['no_positive_evidence']}_", ""]
        return lines
    lines += [
        (
            f"| {t['scanner']} | {t['checked']} | {t['result']} | "
            f"{t['evidence_scope']} | {t['observed_at']} |"
        ),
        "|---|---|---|---|---|",
    ]
    for item in items:
        lines.append(
            f"| `{_cell(item['scanner'])}` | {_cell(checked_label_es(item))} | "
            f"{_cell(result_label_es(item))} | {_cell(item['scope'])} | "
            f"{_cell(item['observed_at'] or '—')} |"
        )
    lines.append("")
    return lines


def _render_scanner_status(
    report: ComplianceReport, t: dict[str, str]
) -> list[str]:
    """Render each scanner's execution status, surfacing failures explicitly."""
    statuses = scanner_status_items(report)
    lines = [f"## {t['scanner_status']}", "", f"_{t['scanner_status_lead']}_", ""]
    if not statuses:
        lines += [f"_{t['no_scanner_status']}_", ""]
        return lines
    lines += [f"| {t['scanner']} | {t['status']} |", "|---|---|"]
    for scanner in sorted(statuses):
        lines.append(
            f"| `{_cell(scanner)}` | "
            f"{_cell(_status_label(statuses[scanner]))} |"
        )
    lines.append("")
    failed = sorted(s for s, status in statuses.items() if status == "failed")
    if failed:
        listed = ", ".join(f"`{_cell(scanner)}`" for scanner in failed)
        lines += [
            f"**{t['failed_scanners']}:** {listed}. {t['failed_scanners_note']}",
            "",
        ]
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
            "los escáneres que demuestran incumplimiento de un requisito aplicable "
            "(no conformidad mayor); (4) señales de riesgo no demostrativas (por "
            "ejemplo, vulnerabilidades detectadas o dependencias sin fijar), que "
            "acotan la medida a parcial y se listan como riesgos sin forzar un "
            "incumplimiento; (5) evidencia positiva registrada por los escáneres; "
            "y (6) sin evidencia ni valoración, la medida se marca como no "
            "evaluable (la ausencia de hallazgos no es prueba de cumplimiento)."
        ),
        "",
        f"- Escáneres ejecutados: {scanner_list}.",
        f"- Hallazgos registrados: {metadata.get('finding_count', 0)}.",
        f"- Medidas aplicables: {report.summary.applicable}.",
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


def _render_dimensions_refuerzos(
    report: ComplianceReport, t: dict[str, str]
) -> list[str]:
    """Render the dimension valuation and the activated refuerzos.

    Shows the per-dimension levels carried in the metadata (empty when only a
    category was supplied) and then the refuerzos the valuation activated, one
    bullet per measure.
    """
    levels = dimension_levels(report)
    refuerzos = activated_refuerzos(report)
    lines = [f"## {t['dims_refuerzos']}", "", f"_{t['dims_refuerzos_lead']}_", ""]
    if levels:
        lines += [f"| {t['dimension']} | {t['level']} |", "|---|---|"]
        lines += [
            f"| {_cell(dimension)} | {_cell(level)} |"
            for dimension, level in levels
        ]
    else:
        lines.append(f"_{t['no_dimension_valuation']}_")
    lines += ["", f"### {t['activated_refuerzos']}", ""]
    if refuerzos:
        for code in sorted(refuerzos):
            refs = ", ".join(
                f"`{_cell(refuerzo)}`" for refuerzo in refuerzos[code]
            )
            lines.append(f"- `{_cell(code)}`: {refs}.")
    else:
        lines.append(f"_{t['no_activated_refuerzos']}_")
    lines.append("")
    return lines


def _refs_cell(verdict: MeasureVerdict) -> str:
    """Render a measure's requirement/refuerzo references as one cell."""
    parts: list[str] = []
    if verdict.requirement_refs:
        parts.append("REQ: " + ", ".join(verdict.requirement_refs))
    if verdict.refuerzo_refs:
        parts.append("REF: " + ", ".join(verdict.refuerzo_refs))
    return " · ".join(parts) if parts else "—"


def _trace_cell(entries: list[dict[str, object]]) -> str:
    """Render the distinct tool/method chain of a measure as one cell."""
    labels: list[str] = []
    for entry in entries:
        label = trace_source_label(entry)
        if label not in labels:
            labels.append(label)
    return ", ".join(labels) if labels else "—"


def _render_measures_table(
    report: ComplianceReport,
    catalog: Catalog | None,
    t: dict[str, str],
) -> list[str]:
    """Render the full table of measures (one row per catalog measure).

    Besides the verdict, each row shows the *evidence state* and, where
    available, the traceability chain ``medida -> requisito/refuerzo ->
    herramienta(+versión) -> método``.
    """
    trace = traceability_map(report)
    lines = [
        f"## {t['measures_table']}",
        "",
        (
            f"| {t['code']} | {t['measure']} | {t['marco_family']} | "
            f"{t['evidence_state']} | {t['requirements']} / {t['refuerzos']} | "
            f"{t['traceability']} | {t['verdict']} |"
        ),
        "|---|---|---|---|---|---|---|",
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
            f"{_cell(evidence_state_label_es(verdict.evidence_state))} | "
            f"{_cell(_refs_cell(verdict))} | "
            f"{_cell(_trace_cell(trace.get(verdict.measure_code, [])))} | "
            f"{_verdict_label(verdict.verdict)} |"
        )
    lines.append("")
    return lines


def _render_non_conformities(
    report: ComplianceReport, catalog: Catalog | None, t: dict[str, str]
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
        label = _verdict_label(verdict.verdict)
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


def _render_risks(report: ComplianceReport, t: dict[str, str]) -> list[str]:
    """Render the non-demonstrated findings as a distinct risks table.

    Each row carries the localized rule label, severity, the mapped measures and
    the traceability column (tool + version + method) so a risk always shows
    *which* tool, at *which* version, produced it.
    """
    items = risk_items(report)
    lines = [f"## {t['risks']}", "", f"_{t['risks_lead']}_", ""]
    if not items:
        lines += [f"_{t['no_risks']}_", ""]
        return lines
    lines += [
        (
            f"| {t['risk']} | {t['severity']} | {t['measures']} | "
            f"{t['tool_method']} |"
        ),
        "|---|---|---|---|",
    ]
    for item in items:
        severity = _SEVERITY_LABELS.get(item["severity"], item["severity"])
        label = checked_label_es({"kind": item["kind"], "checked": item["message"]})
        measures = ", ".join(item["measure_codes"]) or "—"
        source = trace_source_label(item)
        lines.append(
            f"| {_cell(label)} | {_cell(severity)} | `{_cell(measures)}` | "
            f"{_cell(source)} |"
        )
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
    :param language: report language; only ``"es"`` is authored and any other
        value falls back to Spanish.
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
    lines += _render_summary(report, t)
    lines += _render_scope(report, t, catalog)
    lines += _render_categorisation(report, t)
    lines += _render_dimensions_refuerzos(report, t)
    lines += _render_positive_evidence(report, t)
    lines += _render_scanner_status(report, t)
    lines += _render_measures_table(report, catalog, t)
    lines += _render_non_conformities(report, catalog, t)
    lines += _render_risks(report, t)
    lines += _render_recommendations(report, catalog, t)
    return "\n".join(lines).rstrip() + "\n"


def write_markdown(
    report: ComplianceReport,
    path: str | Path,
    catalog: Catalog | None = None,
    language: str = "es",
) -> Path:
    """Render ``report`` as Markdown and write it to ``path``.

    :param language: report language; see :func:`render_markdown`.
    :returns: the :class:`pathlib.Path` written to.
    """
    destination = Path(path)
    destination.write_text(
        render_markdown(report, catalog=catalog, language=language),
        encoding="utf-8",
    )
    return destination
