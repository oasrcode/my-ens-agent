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
from collections.abc import Iterable
from pathlib import Path

from ..catalog.models import Catalog
from ..models import ComplianceReport

#: Auto-generated rationales produced by the evaluator (see
#: :mod:`ens_audit.evaluate`). They are English and machine-authored, so the
#: renderers suppress them rather than leak English into the Spanish report;
#: any rationale not matching is treated as a human note and shown verbatim.
_AUTO_RATIONALE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^Explicit manual assessment\.$"),
    re.compile(r"^Measure not applicable to category .*\.$"),
    re.compile(r"^\d+ failing and \d+ passing scanner signal\(s\) for this measure\.$"),
    re.compile(r"^\d+ failing scanner finding\(s\) for this measure\.$"),
    re.compile(r"^\d+ passing scanner signal\(s\) for this measure\.$"),
    re.compile(
        r"^Documentary/organizational or physical measure with no automated "
        r"evidence and no manual assessment\.$"
    ),
    re.compile(r"^No findings for this measure; assumed compliant\.$"),
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


# Imported after the shared rationale helpers so the sibling renderers can
# import them back from this package without a circular import; the ordering
# below the definitions is therefore intentional.
from .json import build_document, render_json, write_json
from .markdown import render_markdown, write_markdown

__all__ = [
    "build_document",
    "render_json",
    "render_markdown",
    "render_report",
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
