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

from ens_audit.models import Finding, ScanReport

from .base import Scanner, ScannerResult

__all__ = [
    "clear_registry",
    "get_scanner",
    "list_scanners",
    "register",
    "run_scans",
    "unregister",
]

logger = logging.getLogger(__name__)

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


def _resolve(scanner_ids: list[str] | None) -> list[Scanner]:
    """Resolve the scanners to run from optional explicit ids."""
    if scanner_ids is None:
        return list_scanners()
    return [get_scanner(scanner_id) for scanner_id in scanner_ids]


def _normalize(finding: Finding, scanner_id: str) -> Finding:
    """Return the finding stamped with its originating scanner id."""
    if finding.scanner:
        return finding
    return finding.model_copy(update={"scanner": scanner_id})


def run_scans(target: Path, check_ids: list[str] | None = None) -> ScanReport:
    """Run the selected scanners against ``target`` and aggregate findings.

    :param target: directory (or file) to scan.
    :param check_ids: explicit scanner ids to run, in order; all registered
        scanners when ``None``.
    :returns: a :class:`ScanReport` with the aggregated findings, the ids of
        the scanners that ran, and a UTC timestamp.
    :raises KeyError: when a requested ``check_ids`` entry is not registered.
    """
    target = Path(target)
    scanners = _resolve(check_ids)
    findings: list[Finding] = []

    for scanner in scanners:
        try:
            result = scanner.run(target)
        except Exception:  # one faulty scanner must not sink the whole scan
            logger.exception("scanner %s failed on %s", scanner.id, target)
            continue
        if isinstance(result, ScannerResult):
            for error in result.errors:
                logger.warning("scanner %s: %s", scanner.id, error)
            scanner_findings: list[Finding] = result.findings
        else:
            scanner_findings = result
        findings.extend(_normalize(f, scanner.id) for f in scanner_findings)

    return ScanReport(
        target=str(target),
        findings=findings,
        scanners=[scanner.id for scanner in scanners],
    )
