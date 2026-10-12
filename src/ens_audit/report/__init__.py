"""Report generation for ENS compliance reports.

Renders a :class:`~ens_audit.models.ComplianceReport` into Markdown, JSON and a
self-contained HTML document. The Markdown and JSON renderers live in the
sibling ``ens_audit.report.markdown`` and ``ens_audit.report.json`` modules;
the HTML renderer lives in ``ens_audit.report.html`` and is imported lazily by
:func:`render_report`.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from pathlib import Path
from typing import Any

from ..catalog.models import Catalog
from ..models import CheckEvidence, ComplianceReport, EvidenceState, ScanReport

#: Auto-generated rationales produced by the evaluator (see
#: :mod:`ens_audit.evaluate`). They are English and machine-authored, so the
#: renderers suppress them rather than leak English into the Spanish report;
#: any rationale not matching is treated as a human note and shown verbatim.
_AUTO_RATIONALE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^Explicit manual assessment\.$"),
    re.compile(r"^Measure not applicable to category .*\.$"),
    re.compile(r"^\d+ failing scanner finding\(s\) for this measure\.$"),
    re.compile(r"^\d+ passing scanner signal\(s\) for this measure\.$"),
    re.compile(
        r"^\d+ demonstrated non-compliance finding\(s\) for this measure\.$"
    ),
    re.compile(r"^\d+ non-demonstrated risk signal\(s\) for this measure\.$"),
    re.compile(
        r"^Documentary/organizational or physical measure with no automated "
        r"evidence and no manual assessment\.$"
    ),
    # R1 evidence-based semantics: new evaluator defaults.
    re.compile(
        r"^Explicit scanner check covers all applicable requirements of this "
        r"measure\.$"
    ),
    re.compile(
        r"^No coverage and no manual assessment: absence of evidence is not "
        r"evidence of compliance\.$"
    ),
)


def _is_auto_rationale(text: str) -> bool:
    """Whether a rationale string is one of the evaluator's English defaults."""
    return any(pattern.match(text) for pattern in _AUTO_RATIONALE_PATTERNS)


def _human_note(rationale: str) -> str:
    """Return the rationale when it is a human note, otherwise an empty string."""
    text = (rationale or "").strip()
    if not text or _is_auto_rationale(text):
        return ""
    return text


#: Spanish descriptions of *what* each scanner rule kind inspects. Keys mirror
#: the rule kinds of :data:`ens_audit.checks.mapping.MEASURE_MAP`; the renderers
#: show these instead of the scanner-authored English ``checked`` text. Kept in
#: sync with the mapping by ``tests/test_report_md_json.py``.
KIND_LABELS_ES: dict[str, str] = {
    "secret.hardcoded": "Credenciales y claves embebidas en el código fuente",
    "crypto.weak_algorithm": (
        "Uso de algoritmos criptográficos débiles o en desuso"
    ),
    "injection.sql": "Construcción segura de consultas SQL (inyección SQL)",
    "injection.command": (
        "Ejecución de código y comandos dinámicos (inyección de comandos)"
    ),
    "transport.tls_missing": "Cifrado del transporte mediante TLS",
    "config.debug_enabled": "Modo de depuración en la configuración de producción",
    "dependency.outdated": "Actualización y fijación de dependencias",
    "logging.audit_disabled": "Registro de auditoría y trazabilidad de eventos",
    "network.service_exposed": "Exposición de servicios de red",
    "storage.unencrypted": "Cifrado de la información en reposo",
    "backup.disabled": "Copias de seguridad y su retención",
    # External (verified) scanner kinds.
    "vuln.dependency": "Vulnerabilidades conocidas en dependencias",
    "container.vuln": "Vulnerabilidades en imágenes y componentes de contenedor",
    "sast.finding": "Hallazgos de análisis estático (SAST)",
    "iac.misconfig": "Configuración incorrecta de infraestructura (IaC)",
}

#: Spanish labels for the machine-facing ``CheckEvidence.result`` values.
RESULT_LABELS_ES: dict[str, str] = {"pass": "correcto"}

#: Spanish labels for the epistemic :class:`EvidenceState` values.
EVIDENCE_STATE_LABELS_ES: dict[str, str] = {
    EvidenceState.NO_APLICA.value: "No aplica",
    EvidenceState.NO_COMPROBADO.value: "No comprobado",
    EvidenceState.NO_DETECTADO.value: "No detectado",
    EvidenceState.RIESGO_DETECTADO.value: "Riesgo detectado",
    EvidenceState.NO_CONCLUYENTE.value: "No concluyente",
    EvidenceState.CUMPLIMIENTO_DEMOSTRADO.value: "Cumplimiento demostrado",
    EvidenceState.INCUMPLIMIENTO_DEMOSTRADO.value: "Incumplimiento demostrado",
}

#: Spanish labels for the independent ``Method`` axis.
METHOD_LABELS_ES: dict[str, str] = {
    "heuristic": "heurístico",
    "verified": "verificado",
}

#: Spanish labels for the independent ``Confidence`` axis.
CONFIDENCE_LABELS_ES: dict[str, str] = {
    "low": "baja",
    "medium": "media",
    "high": "alta",
}


def checked_label_es(item: Mapping[str, Any]) -> str:
    """Return the Spanish description of what an evidence item checked.

    A known scanner ``kind`` resolves to its :data:`KIND_LABELS_ES` label. An
    item with an unknown/absent kind (e.g. hand-authored evidence built without a
    rule kind) keeps its ``checked`` text verbatim, which is expected to be
    authored in the report language already.
    """
    kind = str(item.get("kind") or "")
    label = KIND_LABELS_ES.get(kind)
    if label is not None:
        return label
    return str(item.get("checked") or "")


def result_label_es(item: Mapping[str, Any]) -> str:
    """Return the Spanish label of an evidence item's result value.

    Unknown result values are shown verbatim (they are machine-facing codes
    without a localized equivalent).
    """
    result = str(item.get("result") or "")
    return RESULT_LABELS_ES.get(result, result)


def _enum_value(value: Any) -> str:
    """Return the serialized value of an enum member or a raw string."""
    return str(getattr(value, "value", value) or "")


def evidence_state_label_es(value: Any) -> str:
    """Return the Spanish label of an :class:`EvidenceState` (or raw string)."""
    raw = _enum_value(value)
    return EVIDENCE_STATE_LABELS_ES.get(raw, raw)


def method_label_es(value: Any) -> str:
    """Return the Spanish label of a ``Method`` (or raw string)."""
    raw = _enum_value(value)
    return METHOD_LABELS_ES.get(raw, raw)


def confidence_label_es(value: Any) -> str:
    """Return the Spanish label of a ``Confidence`` (or raw string)."""
    raw = _enum_value(value)
    return CONFIDENCE_LABELS_ES.get(raw, raw)


def _normalise_observed_at(value: object) -> str:
    """Return an ``YYYY-MM-DD`` date label for a raw evidence timestamp.

    Accepts a :class:`datetime.datetime`, a :class:`datetime.date`, or an
    already-serialized ISO-8601 string; anything else yields an empty string so
    the renderers can fall back to a placeholder.
    """
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, str) and value.strip():
        return value.strip()[:10]
    return ""


def _metadata_scan_report(report: ComplianceReport) -> ScanReport | None:
    """Recover a :class:`ScanReport` carried in ``report.metadata``, if any.

    The evaluator may attach the whole scan report (``metadata["scan_report"]``)
    instead of flattening its fields; both shapes are supported.
    """
    raw = report.metadata.get("scan_report")
    if isinstance(raw, ScanReport):
        return raw
    if isinstance(raw, Mapping):
        try:
            return ScanReport(**raw)
        except (TypeError, ValueError):  # pragma: no cover - defensive guard
            return None
    return None


def positive_evidence_items(report: ComplianceReport) -> list[dict[str, Any]]:
    """Normalise the report's positive check evidence to plain dictionaries.

    Positive evidence is the ``ScanReport.evidence`` (a list of
    :class:`~ens_audit.models.CheckEvidence`) carried into
    ``report.metadata["evidence"]``. Each item is returned with stable keys
    (``scanner``, ``measure_codes``, ``checked``, ``kind``, ``scope``,
    ``result``, ``observed_at`` as ``YYYY-MM-DD`` and ``covers_all``) so every
    renderer presents the same data.

    ``checked`` stays the raw scanner-authored text and ``kind`` stays the raw
    rule id: the machine-facing JSON document keeps both (a stable contract for
    tooling). The Spanish human renderers do **not** print ``checked``; they
    localize it through :func:`checked_label_es` using ``kind``.
    """
    raw = report.metadata.get("evidence")
    if raw is None:
        scan = _metadata_scan_report(report)
        raw = list(scan.evidence) if scan is not None else []
    items: list[dict[str, Any]] = []
    for entry in raw or []:
        if isinstance(entry, CheckEvidence):
            data: dict[str, Any] = entry.model_dump()
        elif isinstance(entry, Mapping):
            data = dict(entry)
        else:  # pragma: no cover - defensive guard
            continue
        items.append(
            {
                "scanner": str(data.get("scanner") or ""),
                "tool": str(data.get("tool") or data.get("scanner") or ""),
                "tool_version": (
                    str(data["tool_version"]) if data.get("tool_version") else ""
                ),
                "method": _enum_value(data.get("method")),
                "confidence": _enum_value(data.get("confidence")),
                "measure_codes": [
                    str(code) for code in (data.get("measure_codes") or [])
                ],
                "checked": str(data.get("checked") or ""),
                "kind": (str(data["kind"]) if data.get("kind") else None),
                "scope": str(data.get("scope") or ""),
                "result": str(data.get("result") or ""),
                "observed_at": _normalise_observed_at(data.get("observed_at")),
                "covers_all": bool(data.get("covers_all", False)),
                "requirement_refs": [
                    str(ref) for ref in (data.get("requirement_refs") or [])
                ],
                "refuerzo_refs": [
                    str(ref) for ref in (data.get("refuerzo_refs") or [])
                ],
            }
        )
    return items


def scanner_status_items(report: ComplianceReport) -> dict[str, str]:
    """Normalise ``ScanReport.scanner_status`` carried in the report metadata.

    Returns a ``{scanner: status}`` mapping (statuses are ``completed``,
    ``failed`` or ``skipped``). A ``failed`` scanner is surfaced by every
    renderer, never hidden.
    """
    raw = report.metadata.get("scanner_status")
    if not raw:
        scan = _metadata_scan_report(report)
        raw = scan.scanner_status if scan is not None else {}
    return {str(scanner): str(status) for scanner, status in (raw or {}).items()}


def _str_list(values: Any) -> list[str]:
    """Coerce a value to a list of strings (empty list when absent)."""
    if not values:
        return []
    return [str(value) for value in values]


def _entry_demonstrates(entry: Any) -> bool:
    """Whether a raw finding entry demonstrates non-compliance.

    Findings default to ``demonstrates=True`` and a mapping missing the key is
    treated the same way: only an explicit ``False`` marks a risk signal.
    """
    if hasattr(entry, "demonstrates"):
        return bool(entry.demonstrates)
    if isinstance(entry, Mapping):
        return bool(entry.get("demonstrates", True))
    return True


def risk_items(report: ComplianceReport) -> list[dict[str, Any]]:
    """Normalise the non-demonstrated findings (risks) from the metadata.

    Risks are the findings that carry ``demonstrates=False``: they never force
    ``no_cumple`` and are surfaced in a dedicated report section. The ``kind``
    key mirrors ``id`` so renderers can localize a known rule id through
    :func:`checked_label_es`.

    When ``metadata['risks']`` is absent the report falls back to the scan
    report's findings, which include the demonstrated failures too; only the
    non-demonstrated (``demonstrates=False``) ones are returned, because a
    demonstrated finding is a non-conformity, not a risk.
    """
    raw = report.metadata.get("risks")
    if raw is None:
        scan = _metadata_scan_report(report)
        raw = (
            [finding for finding in scan.findings if not _entry_demonstrates(finding)]
            if scan is not None
            else []
        )
    items: list[dict[str, Any]] = []
    for entry in raw or []:
        if hasattr(entry, "model_dump"):
            data: dict[str, Any] = entry.model_dump(mode="json")
        elif isinstance(entry, Mapping):
            data = dict(entry)
        else:  # pragma: no cover - defensive guard
            continue
        raw_id = str(data.get("id") or "")
        items.append(
            {
                "id": raw_id,
                "kind": raw_id or None,
                "severity": _enum_value(data.get("severity")),
                "message": str(data.get("message") or ""),
                "measure_codes": _str_list(data.get("measure_codes")),
                "tool": str(data.get("tool") or data.get("scanner") or ""),
                "tool_version": (
                    str(data["tool_version"]) if data.get("tool_version") else ""
                ),
                "method": _enum_value(data.get("method")),
                "confidence": _enum_value(data.get("confidence")),
                "requirement_refs": _str_list(data.get("requirement_refs")),
                "refuerzo_refs": _str_list(data.get("refuerzo_refs")),
            }
        )
    return items


def traceability_map(
    report: ComplianceReport,
) -> dict[str, list[dict[str, Any]]]:
    """Return the per-measure traceability chain carried in the metadata.

    The evaluator stores the chain (``medida -> requisito/refuerzo ->
    herramienta(+versión) -> método -> evidencia``) under
    ``metadata['traceability']``; hand-built reports without it degrade to an
    empty mapping.
    """
    raw = report.metadata.get("traceability")
    if not isinstance(raw, Mapping):
        return {}
    result: dict[str, list[dict[str, Any]]] = {}
    for code, entries in raw.items():
        if not isinstance(entries, (list, tuple)):
            continue
        result[str(code)] = [
            dict(entry) for entry in entries if isinstance(entry, Mapping)
        ]
    return result


def dimension_levels(report: ComplianceReport) -> list[tuple[str, str]]:
    """Normalise the report's per-dimension valuation to ordered pairs.

    The evaluator stores the explicit valuation under ``metadata['dimensions']``
    as a ``{dimension: level}`` mapping; a report without one (category-only
    evaluation, or a hand-built report) degrades to an empty list.
    """
    raw = report.metadata.get("dimensions")
    if not isinstance(raw, Mapping):
        return []
    return [(str(dimension), str(level)) for dimension, level in raw.items()]


def activated_refuerzos(report: ComplianceReport) -> dict[str, list[str]]:
    """Normalise the metadata's activated refuerzos to ``{measure: [id]}``.

    The evaluator stores the refuerzos activated by the dimension valuation
    under ``metadata['refuerzos']``; measure codes with no activated refuerzo
    are omitted (or degrade to an empty mapping when the key is absent).
    """
    raw = report.metadata.get("refuerzos")
    if not isinstance(raw, Mapping):
        return {}
    result: dict[str, list[str]] = {}
    for code, refs in raw.items():
        normalized = _str_list(refs)
        if normalized:
            result[str(code)] = normalized
    return result


def trace_source_label(entry: Mapping[str, Any]) -> str:
    """Render one traceability source as a compact Spanish chain fragment."""
    tool = str(entry.get("tool") or entry.get("scanner") or "—")
    version = entry.get("tool_version")
    if version:
        tool = f"{tool} {version}"
    method = method_label_es(entry.get("method"))
    confidence = confidence_label_es(entry.get("confidence"))
    return f"{tool} ({method}, {confidence})"


# Imported after the shared rationale helpers so the sibling renderers can
# import them back from this package without a circular import; the ordering
# below the definitions is therefore intentional.
from .json import build_document, render_json, write_json
from .markdown import render_markdown, write_markdown

__all__ = [
    "CONFIDENCE_LABELS_ES",
    "EVIDENCE_STATE_LABELS_ES",
    "KIND_LABELS_ES",
    "METHOD_LABELS_ES",
    "RESULT_LABELS_ES",
    "activated_refuerzos",
    "build_document",
    "checked_label_es",
    "confidence_label_es",
    "dimension_levels",
    "evidence_state_label_es",
    "method_label_es",
    "render_json",
    "render_markdown",
    "render_report",
    "result_label_es",
    "risk_items",
    "trace_source_label",
    "traceability_map",
    "write_json",
    "write_markdown",
]

#: Base file name (without extension) used by the dispatcher.
_REPORT_STEM = "informe-ens"

#: Supported output formats and their file extensions.
_EXTENSIONS: dict[str, str] = {"md": ".md", "json": ".json", "html": ".html"}


def _write_html(
    report: ComplianceReport, path: Path, catalog: Catalog | None
) -> Path:
    """Lazily delegate HTML rendering to ``ens_audit.report.html``.

    The import is deferred so the (heavier) HTML renderer is only loaded when
    the ``"html"`` format is actually requested.
    """
    try:
        module = importlib.import_module(".html", __package__)
    except ImportError as exc:  # pragma: no cover - defensive guard
        raise RuntimeError(
            "HTML report requested but 'ens_audit.report.html' could not be "
            "imported."
        ) from exc
    if hasattr(module, "write_html"):
        return Path(module.write_html(report, path, catalog=catalog))
    if hasattr(module, "render_html"):  # pragma: no cover - interface fallback
        path.write_text(
            module.render_html(report, catalog=catalog), encoding="utf-8"
        )
        return path
    raise RuntimeError(  # pragma: no cover - interface guard
        "'ens_audit.report.html' does not expose 'write_html' nor 'render_html'."
    )


def render_report(
    report: ComplianceReport,
    formats: Iterable[str] = ("md", "json"),
    output_dir: str | Path | None = None,
    catalog: Catalog | None = None,
) -> list[Path]:
    """Render ``report`` in every requested format and write the files.

    All requested formats are validated up front, so an unsupported format
    raises before any file is written.

    :param report: the consolidated compliance report.
    :param formats: iterable of formats to emit; supported values are ``"md"``,
        ``"json"`` and ``"html"``.
    :param output_dir: destination directory; defaults to the current working
        directory.
    :param catalog: optional catalog used to enrich the reports.
    :returns: the list of :class:`pathlib.Path` objects written, in the order
        the formats were requested.
    :raises ValueError: if an unsupported format is requested (nothing is
        written in that case).
    :raises RuntimeError: if ``"html"`` is requested but the HTML renderer
        module is not available.
    """
    requested = [(fmt, fmt.lower().strip()) for fmt in formats]
    for original, normalized in requested:
        if normalized not in _EXTENSIONS:
            supported = ", ".join(sorted(_EXTENSIONS))
            raise ValueError(
                f"Unsupported report format {original!r}; supported: {supported}."
            )

    destination = Path(output_dir) if output_dir is not None else Path.cwd()
    destination.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    for _original, normalized in requested:
        path = destination / f"{_REPORT_STEM}{_EXTENSIONS[normalized]}"
        if normalized == "md":
            written.append(write_markdown(report, path, catalog=catalog))
        elif normalized == "json":
            written.append(write_json(report, path, catalog=catalog))
        else:
            written.append(_write_html(report, path, catalog))
    return written
