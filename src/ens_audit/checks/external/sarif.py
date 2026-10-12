"""Safe parser for SARIF 2.1.0 analysis results.

SARIF (Static Analysis Results Interchange Format) is a broad, deeply nested
format. This module deliberately extracts only the handful of fields the audit
needs from ``runs[].results[]``:

* ``ruleId`` and ``level``;
* ``message.text`` (the human-readable description);
* the first ``locations[].physicalLocation`` (``artifactLocation.uri`` plus
  ``region.startLine``).

It degrades safely: malformed JSON, missing ``runs``/``results`` or wrong-typed
fields yield fewer records, never an exception. Callers get back exactly what is
parseable and nothing more.

Two entry points are offered:

* :func:`parse_sarif` always returns a (possibly empty) list;
* :func:`try_parse_sarif` distinguishes *invalid/unshaped* input (``None``) from
  a *valid but empty* SARIF document (``[]``). The external tool runner uses it
  to decide whether a non-zero exit still produced usable output.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

__all__ = ["SarifResult", "parse_sarif", "try_parse_sarif"]


@dataclass(frozen=True)
class SarifResult:
    """One SARIF ``result`` reduced to the fields the audit consumes.

    Every field is optional: a malformed result may carry only some of them.
    """

    rule_id: str = ""
    level: str = ""
    message: str = ""
    uri: str | None = None
    start_line: int | None = None


def parse_sarif(source: str | bytes | Mapping[str, Any] | list[Any] | None) -> list[SarifResult]:
    """Parse SARIF ``source`` into :class:`SarifResult` records.

    ``source`` may be raw JSON text (``str``/``bytes``) or an already-decoded
    JSON object. Anything unparseable yields an empty list; partial or mistyped
    structures yield only the records that could be read.
    """
    parsed = try_parse_sarif(source)
    return [] if parsed is None else parsed


def try_parse_sarif(
    source: str | bytes | Mapping[str, Any] | list[Any] | None,
) -> list[SarifResult] | None:
    """Parse SARIF ``source``, distinguishing invalid input from an empty report.

    Returns ``None`` when ``source`` is not parseable JSON or does not have the
    ``{... "runs": [...]}`` shape of a SARIF log. Returns a (possibly empty)
    list when the document is a well-formed SARIF log, so a caller can tell a
    "ran and found nothing" report (``[]``) apart from a genuine parse failure
    (``None``).
    """
    if isinstance(source, (str, bytes)):
        try:
            data: Any = json.loads(source)
        except ValueError:  # JSONDecodeError / UnicodeDecodeError are ValueErrors
            return None
    elif isinstance(source, Mapping):
        data = source
    else:
        return None
    if not isinstance(data, Mapping) or not isinstance(data.get("runs"), list):
        return None
    return _parse_runs(data)


def _parse_runs(data: Any) -> list[SarifResult]:
    runs = data.get("runs") if isinstance(data, Mapping) else None
    if not isinstance(runs, list):
        return []
    results: list[SarifResult] = []
    for run in runs:
        if not isinstance(run, Mapping):
            continue
        raw_results = run.get("results")
        if not isinstance(raw_results, list):
            continue
        for raw in raw_results:
            if isinstance(raw, Mapping):
                results.append(_parse_result(raw))
    return results


def _parse_result(raw: Mapping[str, Any]) -> SarifResult:
    uri, start_line = _first_physical_location(raw.get("locations"))
    return SarifResult(
        rule_id=_as_str(raw.get("ruleId")),
        level=_as_str(raw.get("level")),
        message=_message_text(raw.get("message")),
        uri=uri,
        start_line=start_line,
    )


def _first_physical_location(locations: Any) -> tuple[str | None, int | None]:
    """Return the (uri, startLine) of the first location with a physical one."""
    if not isinstance(locations, list):
        return None, None
    for location in locations:
        if not isinstance(location, Mapping):
            continue
        physical = location.get("physicalLocation")
        if not isinstance(physical, Mapping):
            continue
        artifact = physical.get("artifactLocation")
        uri = _as_str(artifact.get("uri")) if isinstance(artifact, Mapping) else ""
        region = physical.get("region")
        start_line = (
            _as_int(region.get("startLine")) if isinstance(region, Mapping) else None
        )
        return (uri or None), start_line
    return None, None


def _message_text(message: Any) -> str:
    """Read ``message.text``; tolerate a bare string in its place."""
    if isinstance(message, Mapping):
        return _as_str(message.get("text"))
    return _as_str(message)


def _as_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _as_int(value: Any) -> int | None:
    # ``bool`` is an ``int`` subclass, but a start line of True/False is nonsense.
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None
