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
from ..models import CheckEvidence, ComplianceReport, ScanReport

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
}

#: Spanish labels for the machine-facing ``CheckEvidence.result`` values.
RESULT_LABELS_ES: dict[str, str] = {"pass": "correcto"}


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
                "measure_codes": [
                    str(code) for code in (data.get("measure_codes") or [])
                ],
                "checked": str(data.get("checked") or ""),
                "kind": (str(data["kind"]) if data.get("kind") else None),
                "scope": str(data.get("scope") or ""),
                "result": str(data.get("result") or ""),
                "observed_at": _normalise_observed_at(data.get("observed_at")),
                "covers_all": bool(data.get("covers_all", False)),
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


# Imported after the shared rationale helpers so the sibling renderers can
# import them back from this package without a circular import; the ordering
# below the definitions is therefore intentional.
from .json import build_document, render_json, write_json
from .markdown import render_markdown, write_markdown

__all__ = [
    "KIND_LABELS_ES",
    "RESULT_LABELS_ES",
    "build_document",
    "checked_label_es",
    "render_json",
    "render_markdown",
    "render_report",
    "result_label_es",
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
