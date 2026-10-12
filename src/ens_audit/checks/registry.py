"""Scanner registry and scan orchestration.

Holds the set of known scanners and runs a subset of them against a target,
aggregating every finding into a single
:class:`~ens_audit.models.ScanReport`.

The registry is process-global. Scanners are registered once at import time (via
the :func:`register` decorator or an explicit call) and can be retrieved by id.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ens_audit.models import CheckEvidence, Finding, ScanReport

from .base import Scanner, ScannerResult

__all__ = [
    "EXTERNAL_CATEGORY",
    "clear_registry",
    "get_scanner",
    "list_scanners",
    "register",
    "run_scans",
    "unregister",
]

logger = logging.getLogger(__name__)

#: Scanner category of the optional external tools (see
#: :mod:`ens_audit.checks.external`). Scanners in this category are opt-in: the
#: default :func:`run_scans` never runs them, so a routine scan does not shell
#: out to third-party tools. They are still selectable by explicit id.
EXTERNAL_CATEGORY = "external"

_REGISTRY: dict[str, Scanner] = {}


def register(scanner: type[Scanner] | Scanner) -> Scanner:
    """Register a scanner (class or instance) and return the instance.

    Usable as a class decorator::

        @register
        class MyScanner(Scanner):
            ...

    Raises :class:`ValueError` if the scanner has an empty id or reuses one
    already taken by a different scanner.
    """
    instance = scanner() if isinstance(scanner, type) else scanner
    if not instance.id:
        raise ValueError("scanner id must be a non-empty string")
    existing = _REGISTRY.get(instance.id)
    if existing is not None and existing is not instance:
        raise ValueError(f"scanner id already registered: {instance.id!r}")
    _REGISTRY[instance.id] = instance
    return instance


def unregister(scanner_id: str) -> None:
    """Remove a scanner from the registry, if present."""
    _REGISTRY.pop(scanner_id, None)


def clear_registry() -> None:
    """Remove all registered scanners (mainly for test isolation)."""
    _REGISTRY.clear()


def get_scanner(scanner_id: str) -> Scanner:
    """Return the scanner registered under ``scanner_id``.

    Raises :class:`KeyError` when no scanner matches.
    """
    try:
        return _REGISTRY[scanner_id]
    except KeyError:
        raise KeyError(f"unknown scanner id: {scanner_id!r}") from None


def list_scanners() -> list[Scanner]:
    """Return the registered scanners in registration order."""
    return list(_REGISTRY.values())


def _default_scanners(include_external: bool) -> list[Scanner]:
    """Return the scanners a run selects by default.

    The optional external tools are excluded unless ``include_external`` is set,
    so a routine scan never shells out to third-party binaries.
    """
    scanners = list_scanners()
    if include_external:
        return scanners
    return [scanner for scanner in scanners if scanner.category != EXTERNAL_CATEGORY]


def _resolve(scanner_ids: list[str] | None, include_external: bool) -> list[Scanner]:
    """Resolve the scanners to run from optional explicit ids.

    An explicit ``scanner_ids`` list always wins (so an external scanner can be
    selected by id); ``include_external`` only affects the default set used when
    no ids are given.
    """
    if scanner_ids is None:
        return _default_scanners(include_external)
    return [get_scanner(scanner_id) for scanner_id in scanner_ids]


def _normalize(finding: Finding, scanner_id: str) -> Finding:
    """Return the finding stamped with its originating scanner id and tool.

    The tool axis is populated centrally here (not per scanner): a finding that
    does not carry a ``tool`` is attributed to the scanner that produced it,
    while ``method``/``confidence`` keep their model defaults.
    """
    updates: dict[str, str] = {}
    if not finding.scanner:
        updates["scanner"] = scanner_id
    if not finding.tool:
        updates["tool"] = scanner_id
    if not updates:
        return finding
    return finding.model_copy(update=updates)


def run_scans(
    target: Path,
    check_ids: list[str] | None = None,
    include_external: bool = False,
) -> ScanReport:
    """Run the selected scanners against ``target`` and aggregate findings.

    :param target: directory (or file) to scan.
    :param check_ids: explicit scanner ids to run, in order; when ``None`` every
        registered scanner is selected *except* the opt-in external scanners
        unless ``include_external`` is set.
    :param include_external: include the optional external scanners
        (``external.*``) in the default selection. They are excluded by default
        so a routine scan never shells out to third-party tools; an external
        scanner requested explicitly through ``check_ids`` runs regardless.
    :returns: a :class:`ScanReport` with the aggregated findings, the ids of
        the scanners that ran, each scanner's status (``completed`` / ``failed``
        / ``skipped``), the aggregated positive evidence and a UTC timestamp.
    :raises KeyError: when a requested ``check_ids`` entry is not registered.
    """
    target = Path(target)
    scanners = _resolve(check_ids, include_external)
    findings: list[Finding] = []
    evidence: list[CheckEvidence] = []
    scanner_status: dict[str, str] = {}

    for scanner in scanners:
        try:
            result = scanner.run(target)
        except Exception:  # one faulty scanner must not sink the whole scan
            logger.exception("scanner %s failed on %s", scanner.id, target)
            # A failed scanner contributes no coverage: no evidence is
            # aggregated, so its measures stay unevaluated.
            scanner_status[scanner.id] = "failed"
            continue
        if isinstance(result, ScannerResult):
            for error in result.errors:
                logger.warning("scanner %s: %s", scanner.id, error)
            scanner_findings: list[Finding] = result.findings
            scanner_status[scanner.id] = result.status or "completed"
            evidence.extend(result.evidence)
        else:
            scanner_findings = result
            scanner_status[scanner.id] = "completed"
        findings.extend(_normalize(f, scanner.id) for f in scanner_findings)

    return ScanReport(
        target=str(target),
        findings=findings,
        scanners=[scanner.id for scanner in scanners],
        evidence=evidence,
        scanner_status=scanner_status,
    )
