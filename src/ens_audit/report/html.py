"""Self-contained, printable HTML report renderer for ENS compliance reports.

Renders a :class:`~ens_audit.models.ComplianceReport` as a single, standalone
HTML page. The output is deliberately dependency-free and offline-friendly:

* all styles live in one inline ``<style>`` block;
* no external resource is referenced (no CDN, no web font, no script, no
  image over ``http``/``https``);
* no JavaScript is required -- interactivity uses native ``<details>``.

The document is designed to be readable on screen and to print cleanly to PDF;
``@media print`` rules remove navigation chrome, avoid breaking rows across
pages and keep the colour-coded verdict badges legible.

Only Spanish copy is authored here (``language="es"``); any unknown language
falls back to Spanish. Identifiers, comments and docstrings are in English.

Public API
----------
``render_html(report, catalog=None, language="es") -> str``
    Return the full HTML document as a string.
``write_html(report, path, catalog=None, language="es") -> Path``
    Render and write the document as UTF-8, returning the written path.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..models import ComplianceReport, Verdict
from . import _human_note, positive_evidence_items, scanner_status_items

if TYPE_CHECKING:  # pragma: no cover - import used for typing only
    from ..catalog.models import Catalog, Medida

__all__ = ["render_html", "write_html"]

#: Language used when the requested one is unknown.
_DEFAULT_LANGUAGE = "es"

#: UI copy, keyed by language. Only Spanish is authored.
_STRINGS: dict[str, dict[str, str]] = {
    "es": {
        "title": "Informe de cumplimiento ENS",
        "subtitle": "Esquema Nacional de Seguridad — RD 311/2022",
        "system": "Sistema",
        "category": "Categoría",
        "date": "Fecha",
        "not_specified": "No especificado",
        "summary": "Resumen ejecutivo",
        "summary_lead": (
            "Distribución de las medidas evaluadas del Anexo II según su veredicto."
        ),
        "compliance": "Cumplimiento",
        "applicable": "medidas aplicables",
        "of_total": "sobre el total evaluado",
        "coverage": "Cobertura de evaluación",
        "coverage_sub": "medidas aplicables con evidencia",
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
        "scope": "Alcance",
        "observed_at": "Fecha",
        "status_completed": "Completado",
        "status_failed": "Fallido",
        "status_skipped": "Omitido",
        "failed_scanners": "Escáneres fallidos",
        "failed_note": "Sus medidas quedan como no evaluables.",
        "nonconformities": "No conformidades",
        "nonconformities_lead": (
            "Medidas con veredicto «No cumple» o «Parcial». "
            "Requieren acción correctora."
        ),
        "no_nc": "No se han identificado no conformidades en esta evaluación.",
        "recommendations": "Recomendaciones",
        "recommendations_lead": "Acciones sugeridas a partir de los resultados.",
        "measures": "Medidas evaluadas",
        "measures_lead": (
            "Detalle de las 73 medidas del Anexo II agrupadas por marco y familia."
        ),
        "evidence": "Justificación y evidencia",
        "no_evidence": "Sin evidencia registrada.",
        "reasoning": "Valoración",
        "note": "Nota",
        "code": "Código",
        "measure": "Medida",
        "dimensions": "Dimensiones",
        "verdict": "Veredicto",
        "footer_note": (
            "Documento generado automáticamente por ens-audit. "
            "Autocontenido: no referencia recursos externos."
        ),
        "no_measures": "No se han recibido medidas para evaluar.",
    }
}

#: Human-readable verdict labels (also surfaced to tests / other renderers).
_VERDICT_LABELS: dict[Verdict, str] = {
    Verdict.CUMPLE: "Cumple",
    Verdict.NO_CUMPLE: "No cumple",
    Verdict.PARCIAL: "Parcial",
    Verdict.NO_APLICA: "No aplica",
    Verdict.NO_EVALUABLE: "No evaluable",
}

#: Stable, presentation-friendly order for the verdict counts.
_VERDICT_ORDER: tuple[Verdict, ...] = (
    Verdict.CUMPLE,
    Verdict.NO_CUMPLE,
    Verdict.PARCIAL,
    Verdict.NO_APLICA,
    Verdict.NO_EVALUABLE,
)

#: Verdicts rendered as non-conformities (major: no cumple; minor: parcial).
_NON_CONFORMITY_VERDICTS: tuple[Verdict, ...] = (Verdict.NO_CUMPLE, Verdict.PARCIAL)

#: Spanish description shown for a measure's verdict when there is no manual
#: note to display.
_VERDICT_DESCRIPTIONS: dict[Verdict, str] = {
    Verdict.CUMPLE: "La medida se considera cumplida con la evidencia disponible.",
    Verdict.NO_CUMPLE: "Se han detectado incumplimientos para esta medida.",
    Verdict.PARCIAL: (
        "Cumplimiento parcial: coexisten señales de cumplimiento y de incumplimiento."
    ),
    Verdict.NO_APLICA: "La medida no es de aplicación a la categoría del sistema.",
    Verdict.NO_EVALUABLE: (
        "No hay evidencia automatizada ni valoración manual; requiere revisión "
        "documental."
    ),
}

#: Marco identifiers to their display titles.
_MARCO_TITLES: dict[str, str] = {
    "org": "Marco organizativo",
    "op": "Marco operacional",
    "mp": "Marco de protección",
}

#: Single-letter codes for the five ENS security dimensions.
_DIMENSION_SHORT: dict[str, str] = {
    "Confidencialidad": "C",
    "Integridad": "I",
    "Disponibilidad": "D",
    "Autenticidad": "A",
    "Trazabilidad": "T",
}

#: Human-readable labels for evidence kinds.
_EVIDENCE_KIND_LABELS: dict[str, str] = {
    "file_line": "Fichero / línea",
    "config": "Configuración",
    "note": "Nota",
}

#: Scanner execution statuses to their UI copy keys.
_STATUS_STRING_KEYS: dict[str, str] = {
    "completed": "status_completed",
    "failed": "status_failed",
    "skipped": "status_skipped",
}

#: Verdict counts property names on the summary model, in display order.
_SUMMARY_FIELDS: dict[Verdict, str] = {
    Verdict.CUMPLE: "cumple",
    Verdict.NO_CUMPLE: "no_cumple",
    Verdict.PARCIAL: "parcial",
    Verdict.NO_APLICA: "no_aplica",
    Verdict.NO_EVALUABLE: "no_evaluable",
}


@dataclass(frozen=True)
class _MeasureMeta:
    """Presentation metadata for a single measure."""

    code: str
    name: str
    marco: str
    familia: str
    familia_nombre: str
    dimensions: str


def _t(language: str, key: str) -> str:
    """Return UI copy for ``key``, falling back to Spanish."""
    strings = _STRINGS.get(language) or _STRINGS[_DEFAULT_LANGUAGE]
    return strings.get(key, _STRINGS[_DEFAULT_LANGUAGE].get(key, key))


def _esc(value: Any) -> str:
    """HTML-escape any value for safe interpolation into text/attributes."""
    return html.escape(str(value), quote=True)


def _verdict_label(verdict: Verdict) -> str:
    """Spanish label for a verdict."""
    return _VERDICT_LABELS.get(verdict, str(verdict))


def _verdict_class(verdict: Verdict) -> str:
    """CSS modifier suffix for a verdict badge."""
    return "badge--" + str(verdict.value).replace("_", "-")


def _dimensions_label(dimensions: Any) -> str:
    """Render a measure's dimensions as dot-separated single-letter codes.

    Letters follow the canonical ENS order (C, I, D, A, T) regardless of the
    order the catalog declares them in.
    """
    if not dimensions:
        return "—"
    rank = {short: index for index, short in enumerate(_DIMENSION_SHORT.values())}
    letters: list[str] = []
    for dimension in dimensions:
        name = str(getattr(dimension, "value", dimension))
        letters.append(_DIMENSION_SHORT.get(name, name))
    letters.sort(key=lambda letter: rank.get(letter, len(rank)))
    return " · ".join(letters)


def _derive_group(code: str) -> tuple[str, str]:
    """Derive ``(marco, familia)`` from a measure code when no catalog is given."""
    parts = code.split(".")
    marco = parts[0] if parts and parts[0] in _MARCO_TITLES else "otros"
    familia = (
        marco if marco == "org" else ".".join(parts[:2]) if len(parts) >= 2 else marco
    )
    return marco, familia


def _measure_meta(measure_code: str, catalog: Catalog | None) -> _MeasureMeta:
    """Build presentation metadata for a measure, using the catalog if available."""
    medida: Medida | None = None
    if catalog is not None:
        medida = catalog.medidas.get(measure_code)
    if medida is not None:
        return _MeasureMeta(
            code=measure_code,
            name=medida.name or measure_code,
            marco=medida.marco,
            familia=medida.familia,
            familia_nombre=medida.familia_nombre or medida.familia,
            dimensions=_dimensions_label(medida.dimensiones),
        )
    marco, familia = _derive_group(measure_code)
    return _MeasureMeta(
        code=measure_code,
        name=measure_code,
        marco=marco,
        familia=familia,
        familia_nombre=familia,
        dimensions="—",
    )


def _marco_title(marco: str) -> str:
    """Display title for a marco identifier."""
    return _MARCO_TITLES.get(marco, marco)


def _compliance_pct(report: ComplianceReport) -> float:
    """Compliance percentage over applicable measures."""
    value = report.metadata.get("compliance_pct")
    if isinstance(value, (int, float)):
        return max(0.0, min(100.0, float(value)))
    summary = report.summary
    applicable = summary.total - summary.no_aplica
    if applicable <= 0:
        return 0.0
    return max(0.0, min(100.0, round(100 * summary.cumple / applicable, 2)))


def _coverage_pct(report: ComplianceReport) -> float:
    """Evaluation-coverage percentage over applicable measures.

    Coverage is the share of applicable measures that have *some* evidence,
    i.e. that are not ``no_evaluable``: ``(applicable - no_evaluable) /
    applicable``.
    """
    value = report.metadata.get("coverage_pct")
    if isinstance(value, (int, float)):
        return max(0.0, min(100.0, float(value)))
    summary = report.summary
    applicable = summary.total - summary.no_aplica
    if applicable <= 0:
        return 0.0
    covered = applicable - summary.no_evaluable
    return max(0.0, min(100.0, round(100 * covered / applicable, 2)))


def _applicable_count(report: ComplianceReport) -> int:
    """Number of applicable measures (total minus not-applicable)."""
    return report.summary.total - report.summary.no_aplica


def _report_date(report: ComplianceReport) -> str:
    """Best-effort reporting date from metadata, falling back to today."""
    for key in ("date", "generated_at", "timestamp"):
        value = report.metadata.get(key)
        if value:
            return str(value)
    return date.today().isoformat()


def _format_pct(value: float) -> str:
    """Format a percentage with a comma decimal separator (Spanish style)."""
    text = f"{value:.2f}".rstrip("0").rstrip(".")
    return text.replace(".", ",")


def _render_badge(verdict: Verdict) -> str:
    """Render a colour-coded verdict badge."""
    return (
        f'<span class="badge {_verdict_class(verdict)}">'
        f"{_esc(_verdict_label(verdict))}</span>"
    )


def _render_evidence_details(verdict: Any, language: str) -> str:
    """Render the expandable evidence/rationale block for a measure, if any."""
    note = _human_note(verdict.rationale)
    evidence = list(verdict.evidence)
    if not note and not evidence:
        return ""

    parts: list[str] = []
    parts.append("<details open>")
    parts.append(f"<summary>{_esc(_t(language, 'evidence'))}</summary>")
    parts.append('<div class="evidence-body">')
    parts.append(
        f'<p class="reasoning">{_esc(_VERDICT_DESCRIPTIONS.get(verdict.verdict, ""))}</p>'
    )
    if note:
        parts.append(
            f'<p class="note"><span class="note-label">'
            f"{_esc(_t(language, 'note'))}:</span> {_esc(note)}</p>"
        )
    if evidence:
        parts.append('<ul class="evidence-list">')
        for item in evidence:
            kind = getattr(item.kind, "value", str(item.kind))
            kind_label = _EVIDENCE_KIND_LABELS.get(str(kind), str(kind))
            location = _esc(item.location)
            detail = _esc(item.detail) if item.detail else ""
            detail_html = f' <span class="ev-detail">{detail}</span>' if detail else ""
            parts.append(
                '<li class="evidence-item">'
                f'<span class="ev-kind">{_esc(kind_label)}</span> '
                f'<code class="ev-loc">{location}</code>{detail_html}'
                "</li>"
            )
        parts.append("</ul>")
    else:
        parts.append(f'<p class="no-evidence">{_esc(_t(language, "no_evidence"))}</p>')
    parts.append("</div>")
    parts.append("</details>")
    return "".join(parts)


def _render_measure_table(
    meta_rows: list[tuple[_MeasureMeta, Any]],
    familia_nombre: str,
    language: str,
) -> str:
    """Render one familia table with its measure rows and evidence."""
    headers = (
        f'<th scope="col">{_esc(_t(language, "code"))}</th>'
        f'<th scope="col">{_esc(_t(language, "measure"))}</th>'
        f'<th scope="col" class="col-dims">{_esc(_t(language, "dimensions"))}</th>'
        f'<th scope="col">{_esc(_t(language, "verdict"))}</th>'
    )
    body: list[str] = []
    for meta, verdict in meta_rows:
        evidence = _render_evidence_details(verdict, language)
        evidence_row = (
            f'<tr class="evidence-row"><td colspan="4">{evidence}</td></tr>'
            if evidence
            else ""
        )
        anchor = meta.code.replace(".", "-")
        body.append(
            '<tbody class="measure">'
            f'<tr class="measure-row" id="medida-{_esc(anchor)}">'
            f'<th scope="row" class="m-code"><code>{_esc(meta.code)}</code></th>'
            f'<td class="m-name">{_esc(meta.name)}</td>'
            f'<td class="m-dims">{_esc(meta.dimensions)}</td>'
            f'<td class="m-verdict">{_render_badge(verdict.verdict)}</td>'
            "</tr>"
            f"{evidence_row}"
            "</tbody>"
        )
    return (
        '<div class="table-wrap">'
        "<table>"
        f'<caption class="visually-hidden">Familia: {_esc(familia_nombre)}</caption>'
        f"<thead><tr>{headers}</tr></thead>" + "".join(body) + "</table>"
        "</div>"
    )


def _render_measures(
    report: ComplianceReport,
    catalog: Catalog | None,
    language: str,
) -> str:
    """Render the full measure detail grouped by marco and familia."""
    # Group in report order, preserving first-seen marco/familia ordering.
    groups: dict[tuple[str, str, str], list[tuple[_MeasureMeta, Any]]] = {}
    order: list[tuple[str, str, str]] = []
    for verdict in report.verdicts:
        meta = _measure_meta(verdict.measure_code, catalog)
        key = (meta.marco, meta.familia, meta.familia_nombre)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append((meta, verdict))

    if not order:
        return f'<p class="empty">{_esc(_t(language, "no_measures"))}</p>'

    # Group families under their marco, keeping insertion order.
    marcos: dict[str, list[tuple[str, str, str]]] = {}
    marco_order: list[str] = []
    for key in order:
        marco = key[0]
        if marco not in marcos:
            marcos[marco] = []
            marco_order.append(marco)
        marcos[marco].append(key)

    sections: list[str] = []
    for marco in marco_order:
        sections.append(f'<h2 class="marco">{_esc(_marco_title(marco))}</h2>')
        for key in marcos[marco]:
            familia_nombre = key[2]
            # The organizational marco's only family repeats its own title;
            # avoid rendering a duplicate heading in that case.
            if familia_nombre != _marco_title(marco):
                sections.append(f'<h3 class="familia">{_esc(familia_nombre)}</h3>')
            sections.append(
                _render_measure_table(groups[key], familia_nombre, language)
            )
    return "".join(sections)


def _render_summary(report: ComplianceReport, language: str) -> str:
    """Render the executive summary: verdict counts and compliance gauge."""
    summary = report.summary
    tiles: list[str] = []
    for verdict in _VERDICT_ORDER:
        count = getattr(summary, _SUMMARY_FIELDS[verdict], 0)
        tiles.append(
            f'<li class="stat {_verdict_class(verdict)}">'
            f'<span class="stat-value">{count}</span>'
            f'<span class="stat-label">{_esc(_verdict_label(verdict))}</span>'
            "</li>"
        )

    pct = _compliance_pct(report)
    coverage = _coverage_pct(report)
    applicable = _applicable_count(report)
    covered = applicable - summary.no_evaluable
    return (
        '<section class="summary" aria-labelledby="h-resumen">'
        f'<h2 id="h-resumen">{_esc(_t(language, "summary"))}</h2>'
        f'<p class="lead">{_esc(_t(language, "summary_lead"))}</p>'
        '<div class="summary-grid">'
        '<div class="compliance">'
        f'<p class="compliance-value">{_esc(_format_pct(pct))}'
        '<span class="compliance-unit">%</span></p>'
        f'<p class="compliance-label">{_esc(_t(language, "compliance"))}</p>'
        f'<p class="compliance-sub">{applicable} '
        f"{_esc(_t(language, 'applicable'))}</p>"
        '<div class="bar" role="img" '
        f'aria-label="{_esc(_t(language, "compliance"))}: '
        f'{_esc(_format_pct(pct))}%">'
        f'<span class="bar-fill" style="width:{pct:.2f}%"></span>'
        "</div>"
        "</div>"
        '<div class="compliance compliance--coverage">'
        f'<p class="compliance-value">{_esc(_format_pct(coverage))}'
        '<span class="compliance-unit">%</span></p>'
        f'<p class="compliance-label">{_esc(_t(language, "coverage"))}</p>'
        f'<p class="compliance-sub">{covered} '
        f"{_esc(_t(language, 'coverage_sub'))}</p>"
        '<div class="bar" role="img" '
        f'aria-label="{_esc(_t(language, "coverage"))}: '
        f'{_esc(_format_pct(coverage))}%">'
        f'<span class="bar-fill" style="width:{coverage:.2f}%"></span>'
        "</div>"
        "</div>"
        f'<ul class="stats">{"".join(tiles)}</ul>'
        "</div>"
        "</section>"
    )


def _render_positive_evidence(report: ComplianceReport, language: str) -> str:
    """Render the positive evidence section as a table."""
    items = positive_evidence_items(report)
    if not items:
        body = (
            f'<p class="empty">{_esc(_t(language, "no_positive_evidence"))}</p>'
        )
    else:
        headers = (
            f'<th scope="col">{_esc(_t(language, "scanner"))}</th>'
            f'<th scope="col">{_esc(_t(language, "checked"))}</th>'
            f'<th scope="col">{_esc(_t(language, "result"))}</th>'
            f'<th scope="col">{_esc(_t(language, "scope"))}</th>'
            f'<th scope="col">{_esc(_t(language, "observed_at"))}</th>'
        )
        rows: list[str] = []
        for item in items:
            rows.append(
                "<tr>"
                f'<td><code>{_esc(item["scanner"])}</code></td>'
                f'<td class="ev-checked">{_esc(item["checked"])}</td>'
                f'<td>{_esc(item["result"])}</td>'
                f'<td>{_esc(item["scope"])}</td>'
                f'<td class="ev-date">{_esc(item["observed_at"] or "—")}</td>'
                "</tr>"
            )
        body = (
            '<div class="table-wrap"><table>'
            f"<thead><tr>{headers}</tr></thead>"
            f'<tbody>{"".join(rows)}</tbody></table></div>'
        )
    return (
        '<section class="evidence-summary" aria-labelledby="h-evidencia">'
        f'<h2 id="h-evidencia">{_esc(_t(language, "positive_evidence"))}</h2>'
        f'<p class="lead">{_esc(_t(language, "positive_evidence_lead"))}</p>'
        f"{body}"
        "</section>"
    )


def _render_scanner_status(report: ComplianceReport, language: str) -> str:
    """Render each scanner's execution status, surfacing failures explicitly."""
    statuses = scanner_status_items(report)
    if not statuses:
        body = f'<p class="empty">{_esc(_t(language, "no_scanner_status"))}</p>'
        note = ""
    else:
        rows: list[str] = []
        for scanner in sorted(statuses):
            status = statuses[scanner]
            label_key = _STATUS_STRING_KEYS.get(status)
            label = _t(language, label_key) if label_key else status
            row_class = ' class="status-failed"' if status == "failed" else ""
            rows.append(
                f"<tr{row_class}>"
                f'<td><code>{_esc(scanner)}</code></td>'
                f"<td>{_esc(label)}</td>"
                "</tr>"
            )
        body = (
            '<div class="table-wrap"><table>'
            "<thead><tr>"
            f'<th scope="col">{_esc(_t(language, "scanner"))}</th>'
            f'<th scope="col">{_esc(_t(language, "status"))}</th>'
            "</tr></thead>"
            f'<tbody>{"".join(rows)}</tbody></table></div>'
        )
        failed = sorted(s for s, st in statuses.items() if st == "failed")
        if failed:
            names = ", ".join(f"<code>{_esc(s)}</code>" for s in failed)
            note = (
                '<p class="failed-note">'
                f'<strong>{_esc(_t(language, "failed_scanners"))}:</strong> '
                f'{names}. {_esc(_t(language, "failed_note"))}</p>'
            )
        else:
            note = ""
    return (
        '<section class="scanner-status" aria-labelledby="h-escanneres">'
        f'<h2 id="h-escanneres">{_esc(_t(language, "scanner_status"))}</h2>'
        f'<p class="lead">{_esc(_t(language, "scanner_status_lead"))}</p>'
        f"{body}{note}"
        "</section>"
    )


def _render_nonconformities(
    report: ComplianceReport, catalog: Catalog | None, language: str
) -> str:
    """Render the non-conformity section (``no_cumple`` and ``parcial``)."""
    failures = [
        v for v in report.verdicts if v.verdict in _NON_CONFORMITY_VERDICTS
    ]
    if not failures:
        body = f'<p class="empty">{_esc(_t(language, "no_nc"))}</p>'
    else:
        items: list[str] = []
        for verdict in failures:
            meta = _measure_meta(verdict.measure_code, catalog)
            note = _human_note(verdict.rationale)
            detail = f'<p class="nc-detail">{_esc(note)}</p>' if note else ""
            items.append(
                '<li class="nc-item">'
                f'<p class="nc-head"><code>{_esc(meta.code)}</code> '
                f"{_esc(meta.name)}</p>"
                f"{detail}"
                "</li>"
            )
        body = f'<ul class="nc-list">{"".join(items)}</ul>'
    return (
        '<section class="nonconformities" aria-labelledby="h-nc">'
        f'<h2 id="h-nc">{_esc(_t(language, "nonconformities"))}</h2>'
        f'<p class="lead">{_esc(_t(language, "nonconformities_lead"))}</p>'
        f"{body}"
        "</section>"
    )


def _render_recommendations(report: ComplianceReport, language: str) -> str:
    """Derive and render corrective recommendations from the verdict mix."""
    summary = report.summary
    items: list[str] = []
    if summary.no_cumple:
        items.append(
            "Prioridad alta: resolver las "
            f"{summary.no_cumple} no conformidad(es) y registrar la evidencia "
            "de la corrección."
        )
    if summary.parcial:
        items.append(
            f"Completar la evidencia de las {summary.parcial} medida(s) con "
            "cumplimiento parcial hasta alcanzar el cumplimiento total."
        )
    if summary.no_evaluable:
        items.append(
            f"Aportar evidencia documental para las {summary.no_evaluable} "
            "medida(s) no evaluables y repetir la evaluación."
        )
    if summary.no_aplica:
        items.append(
            f"Documentar la justificación de no aplicabilidad de las "
            f"{summary.no_aplica} medida(s) excluidas."
        )
    if not items:
        items.append(
            "No se requieren acciones correctoras a partir de los resultados actuales."
        )
    body = "".join(f"<li>{_esc(item)}</li>" for item in items)
    return (
        '<section class="recommendations" aria-labelledby="h-rec">'
        f'<h2 id="h-rec">{_esc(_t(language, "recommendations"))}</h2>'
        f'<p class="lead">{_esc(_t(language, "recommendations_lead"))}</p>'
        f'<ol class="rec-list">{body}</ol>'
        "</section>"
    )


def _render_header(report: ComplianceReport, language: str) -> str:
    """Render the document masthead with system, category and date."""
    category = report.category or _t(language, "not_specified")
    target = report.metadata.get("target") or _t(language, "not_specified")
    generated = _report_date(report)
    return (
        '<header class="masthead">'
        f'<p class="eyebrow">{_esc(_t(language, "subtitle"))}</p>'
        f"<h1>{_esc(_t(language, 'title'))}</h1>"
        '<dl class="doc-meta">'
        f"<div><dt>{_esc(_t(language, 'system'))}</dt><dd>{_esc(target)}</dd></div>"
        f"<div><dt>{_esc(_t(language, 'category'))}</dt>"
        f"<dd>{_esc(category)}</dd></div>"
        f"<div><dt>{_esc(_t(language, 'date'))}</dt><dd>{_esc(generated)}</dd></div>"
        "</dl>"
        "</header>"
    )


def render_html(
    report: ComplianceReport,
    catalog: Catalog | None = None,
    language: str = "es",
) -> str:
    """Render a compliance report as a single self-contained HTML document.

    :param report: the compliance report produced by
        :func:`ens_audit.evaluate.evaluate_compliance`.
    :param catalog: optional parsed ENS catalog. When supplied it enriches each
        measure with its name, family and security dimensions; when omitted the
        measures are grouped by code prefix and only their codes are shown.
    :param language: report language; only ``"es"`` is authored, unknown values
        fall back to Spanish.
    :returns: the full HTML document as a string.
    """
    lang = language if language in _STRINGS else _DEFAULT_LANGUAGE
    measures = _render_measures(report, catalog, lang)
    document = f"""<!DOCTYPE html>
<html lang="{_esc(lang)}" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="ens-audit">
<title>{_esc(_t(lang, "title"))} — {_esc(report.category or _t(lang, "not_specified"))}</title>
<style>
{_CSS}
</style>
</head>
<body>
<div class="page">
{_render_header(report, lang)}
<main>
{_render_summary(report, lang)}
{_render_scanner_status(report, lang)}
{_render_positive_evidence(report, lang)}
{_render_nonconformities(report, catalog, lang)}
{_render_recommendations(report, lang)}
<section class="measures" aria-labelledby="h-medidas">
<h2 id="h-medidas">{_esc(_t(lang, "measures"))}</h2>
<p class="lead">{_esc(_t(lang, "measures_lead"))}</p>
{measures}
</section>
</main>
<footer class="colophon">
<p>{_esc(_t(lang, "footer_note"))}</p>
</footer>
</div>
</body>
</html>
"""
    return document


def write_html(
    report: ComplianceReport,
    path: str | Path,
    catalog: Catalog | None = None,
    language: str = "es",
) -> Path:
    """Render ``report`` and write it to ``path`` as UTF-8 HTML.

    :returns: the resolved :class:`pathlib.Path` that was written.
    """
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        render_html(report, catalog=catalog, language=language),
        encoding="utf-8",
    )
    return destination


#: Inlined stylesheet. Kept as a module constant (not an f-string) so its braces
#: need no escaping. No external resource is referenced.
_CSS = """
:root{
  --paper:#ffffff;
  --surface:#f4f7fb;
  --surface-2:#e7eef6;
  --line:#ccd8e6;
  --line-strong:#aab9cc;
  --ink:#16232f;
  --ink-soft:#516072;
  --brand:#12456e;
  --brand-soft:#e2edf7;
  --cumple-bg:#e4f3e8; --cumple-ink:#135c33; --cumple-line:#1e7a44;
  --no-cumple-bg:#fbe7e4; --no-cumple-ink:#8a1c15; --no-cumple-line:#b3261e;
  --parcial-bg:#fdf0d4; --parcial-ink:#6f4308; --parcial-line:#b45309;
  --no-aplica-bg:#eceff3; --no-aplica-ink:#414d5b; --no-aplica-line:#7c8794;
  --no-evaluable-bg:#eee9f8; --no-evaluable-ink:#4b2593; --no-evaluable-line:#6d28d9;
  --serif:Georgia,"Iowan Old Style","Palatino Linotype","Times New Roman",serif;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --mono:ui-monospace,"SFMono-Regular","Cascadia Mono",Consolas,"Liberation Mono",monospace;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0;
  background:var(--surface);
  color:var(--ink);
  font-family:var(--sans);
  font-size:16px;
  line-height:1.55;
}
.page{
  max-width:72rem;
  margin:0 auto;
  background:var(--paper);
  padding:clamp(1.25rem,4vw,3.5rem);
}
.visually-hidden{
  position:absolute;width:1px;height:1px;margin:-1px;padding:0;
  overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0;
}
h1,h2,h3{font-family:var(--serif);font-weight:700;color:var(--brand);}
p{max-width:78ch}
a{color:var(--brand)}
:focus-visible{outline:3px solid var(--brand);outline-offset:2px;}
.masthead{
  border-bottom:3px solid var(--brand);
  padding-bottom:1.1rem;
  margin-bottom:1.8rem;
}
.eyebrow{
  margin:0;
  font-size:.78rem;
  letter-spacing:.16em;
  text-transform:uppercase;
  color:var(--ink-soft);
  font-weight:600;
}
h1{font-size:clamp(1.7rem,3.6vw,2.6rem);line-height:1.08;margin:.4rem 0 .6rem;}
.doc-meta{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(10rem,1fr));
  gap:.5rem 1.5rem;
  margin:0;
}
.doc-meta div{border-left:3px solid var(--brand-soft);padding-left:.7rem;}
.doc-meta dt{
  font-size:.72rem;letter-spacing:.08em;text-transform:uppercase;
  color:var(--ink-soft);font-weight:600;
}
.doc-meta dd{margin:.1rem 0 0;font-weight:600;}
main>section{margin:2.6rem 0;padding-top:.4rem;border-top:1px solid var(--line);}
main>section:first-child{border-top:0;}
h2{font-size:clamp(1.3rem,2.4vw,1.7rem);margin:0 0 .3rem;}
.lead{color:var(--ink-soft);margin:.1rem 0 1.2rem;max-width:70ch;}
.summary-grid{
  display:grid;
  grid-template-columns:minmax(10rem,1fr) minmax(10rem,1fr) 2.2fr;
  gap:1.2rem;
  align-items:center;
}
.compliance{
  background:var(--brand-soft);
  border-left:4px solid var(--brand);
  padding:1rem 1.2rem;
}
.compliance--coverage{
  background:var(--surface-2);
  border-left-color:var(--line-strong);
}
.compliance--coverage .compliance-value{color:var(--ink-soft);}
.compliance-value{
  font-family:var(--serif);
  font-size:clamp(2.6rem,7vw,3.6rem);
  line-height:1;
  margin:0;
  color:var(--brand);
}
.compliance-unit{font-size:1.4rem;vertical-align:super;}
.compliance-label{margin:.2rem 0 0;font-weight:700;}
.compliance-sub{margin:0 0 .7rem;color:var(--ink-soft);font-size:.85rem;}
.bar{background:#fff;border:1px solid var(--line);height:.7rem;border-radius:999px;overflow:hidden;}
.bar-fill{display:block;height:100%;background:var(--brand);}
.stats{
  list-style:none;margin:0;padding:0;
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(8.5rem,1fr));
  gap:.7rem;
}
.stat{
  border:1px solid var(--line);
  border-left-width:5px;
  padding:.6rem .8rem;
  background:var(--surface);
}
.stat-value{display:block;font-family:var(--serif);font-size:1.7rem;line-height:1.1;}
.stat-label{display:block;font-size:.82rem;color:var(--ink-soft);font-weight:600;}
.stat.badge--cumple{border-left-color:var(--cumple-line);}
.stat.badge--cumple .stat-value{color:var(--cumple-ink);}
.stat.badge--no-cumple{border-left-color:var(--no-cumple-line);}
.stat.badge--no-cumple .stat-value{color:var(--no-cumple-ink);}
.stat.badge--parcial{border-left-color:var(--parcial-line);}
.stat.badge--parcial .stat-value{color:var(--parcial-ink);}
.stat.badge--no-aplica{border-left-color:var(--no-aplica-line);}
.stat.badge--no-aplica .stat-value{color:var(--no-aplica-ink);}
.stat.badge--no-evaluable{border-left-color:var(--no-evaluable-line);}
.stat.badge--no-evaluable .stat-value{color:var(--no-evaluable-ink);}
.badge{
  display:inline-block;
  padding:.14rem .55rem;
  border-radius:999px;
  border:1px solid;
  font-size:.78rem;
  font-weight:700;
  white-space:nowrap;
}
.badge--cumple{background:var(--cumple-bg);color:var(--cumple-ink);border-color:var(--cumple-line);}
.badge--no-cumple{background:var(--no-cumple-bg);color:var(--no-cumple-ink);border-color:var(--no-cumple-line);}
.badge--parcial{background:var(--parcial-bg);color:var(--parcial-ink);border-color:var(--parcial-line);}
.badge--no-aplica{background:var(--no-aplica-bg);color:var(--no-aplica-ink);border-color:var(--no-aplica-line);}
.badge--no-evaluable{background:var(--no-evaluable-bg);color:var(--no-evaluable-ink);border-color:var(--no-evaluable-line);}
.nc-list,.rec-list{margin:0;padding-left:1.2rem;}
.nc-item{margin-bottom:.8rem;}
.nc-head{margin:0;font-weight:600;}
.nc-head code{font-family:var(--mono);font-size:.85em;background:var(--surface-2);padding:.05rem .35rem;border-radius:4px;}
.nc-detail{margin:.15rem 0 0;color:var(--ink-soft);}
.rec-list li{margin-bottom:.4rem;}
.evidence-summary .ev-checked{min-width:14rem;}
.evidence-summary .ev-date{white-space:nowrap;}
tr.status-failed td{background:var(--no-cumple-bg);}
.failed-note{
  margin:.8rem 0 0;
  padding:.6rem .8rem;
  background:var(--no-cumple-bg);
  border-left:4px solid var(--no-cumple-line);
  color:var(--no-cumple-ink);
}
.failed-note strong{margin-right:.2rem;}
h2.marco{
  font-size:clamp(1.25rem,2.2vw,1.55rem);
  margin:2rem 0 .4rem;
  padding-bottom:.25rem;
  border-bottom:2px solid var(--brand);
}
h3.familia{
  font-size:1.08rem;
  margin:1.3rem 0 .5rem;
  color:var(--ink);
}
.table-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;font-size:.9rem;}
thead th{
  background:var(--surface-2);
  text-align:left;
  font-size:.74rem;
  letter-spacing:.05em;
  text-transform:uppercase;
  color:var(--ink-soft);
  padding:.5rem .6rem;
  border-bottom:2px solid var(--line-strong);
}
tbody td,tbody th{
  padding:.5rem .6rem;
  border-bottom:1px solid var(--line);
  text-align:left;
  vertical-align:top;
}
tbody th{font-weight:600;}
.m-code code{
  font-family:var(--mono);
  font-size:.85rem;
  background:var(--surface-2);
  padding:.1rem .35rem;
  border-radius:4px;
  white-space:nowrap;
}
.col-dims,.m-dims{white-space:nowrap;color:var(--ink-soft);}
.m-name{min-width:12rem;}
.evidence-row td{background:var(--surface);padding:.2rem .6rem .7rem;}
details{margin-top:.2rem;}
summary{
  cursor:pointer;
  color:var(--brand);
  font-weight:600;
  font-size:.84rem;
}
summary:hover{text-decoration:underline;}
.evidence-body{padding:.5rem 0 .2rem .4rem;border-left:2px solid var(--brand-soft);}
.reasoning{margin:.1rem 0 .4rem;}
.note{margin:.1rem 0 .4rem;color:var(--ink-soft);}
.note-label{font-weight:700;color:var(--ink);}
.evidence-list{list-style:none;margin:.2rem 0 0;padding:0;}
.evidence-item{padding:.28rem 0;border-top:1px dashed var(--line);}
.ev-kind{font-size:.72rem;letter-spacing:.05em;text-transform:uppercase;color:var(--ink-soft);font-weight:700;}
.ev-loc{font-family:var(--mono);font-size:.82rem;background:var(--surface-2);padding:.05rem .3rem;border-radius:4px;}
.ev-detail{color:var(--ink-soft);}
.empty{color:var(--ink-soft);font-style:italic;}
.colophon{
  margin-top:3rem;
  padding-top:1rem;
  border-top:1px solid var(--line);
  color:var(--ink-soft);
  font-size:.82rem;
}
@media (max-width:640px){
  .summary-grid{grid-template-columns:1fr;}
  .m-name{min-width:0;}
  table{font-size:.85rem;}
}
@media print{
  @page{margin:14mm;}
  body{background:#fff;font-size:10.5pt;}
  .page{max-width:none;margin:0;padding:0;}
  main>section{margin:1.4rem 0;}
  a{color:inherit;text-decoration:none;}
  details>summary{color:inherit;}
  details,tr,.stat,.compliance{break-inside:avoid;}
  tr,thead{break-inside:avoid;}
  h1,h2,h3{break-after:avoid;}
  .table-wrap{overflow:visible;}
  *{-webkit-print-color-adjust:exact;print-color-adjust:exact;}
}
"""
