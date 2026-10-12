"""Scanner framework primitives.

A *scanner* is a small, deterministic analysis unit that inspects a target
directory and emits :class:`~ens_audit.models.Finding` objects. The framework is
deliberately agnostic about *how* a scanner inspects the target (parsing source
files, reading infra config, shelling out to a linter, ...); it only fixes the
contract and the aggregation surface.

Scanners are expected to be pure with respect to the target: they read it and
return findings, they never mutate it.

Besides findings, a scanner reports **positive evidence**: when it examined a
relevant artifact and found nothing wrong, it records explicitly *what* it
checked (a :class:`~ens_audit.models.CheckEvidence`). Absence of artifacts must
never be mistaken for a clean check, so a scanner that found nothing to look at
returns a ``skipped`` result instead of evidence.
"""

from __future__ import annotations

import abc
from collections.abc import Iterable, Mapping
from pathlib import Path

from pydantic import BaseModel, Field

from ens_audit.models import CheckEvidence, Finding, Severity

from .mapping import measures_for

__all__ = [
    "Scanner",
    "ScannerResult",
    "build_evidence",
    "finalize_scan",
    "scope_for",
]


class ScannerResult(BaseModel):
    """A scanner outcome: the findings it produced plus recoverable errors.

    Errors are non-fatal diagnostics (e.g. an unreadable file) that must not
    abort the whole scan. Fatal failures should raise instead, and the registry
    will isolate them per scanner.

    ``status`` is ``"completed"`` when the scanner examined its target and
    ``"skipped"`` when it found no relevant artifact to inspect. ``evidence``
    holds the positive checks (what was examined and left clean) the scanner
    wants aggregated into the :class:`~ens_audit.models.ScanReport`.
    """

    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    evidence: list[CheckEvidence] = Field(default_factory=list)
    status: str = "completed"


class Scanner(abc.ABC):
    """Contract implemented by every scanner.

    Subclasses declare the class attributes below and implement :meth:`run`. A
    scanner may return either a bare list of findings or a :class:`ScannerResult`
    when it needs to report recoverable errors, positive evidence or a
    ``skipped`` status alongside its findings.
    """

    #: Stable, unique scanner identifier (e.g. ``"code.hardcoded_secret"``).
    id: str = ""
    #: One-line human-readable description of what the scanner checks.
    description: str = ""
    #: Coarse scanner category, e.g. ``"code"`` or ``"infra"``.
    category: str = ""
    #: Finding kinds (rule ids) this scanner can emit. Together they define the
    #: ENS measures the scanner can speak to; see :meth:`coverage_measures`.
    covers: tuple[str, ...] = ()

    @abc.abstractmethod
    def run(self, target: Path) -> list[Finding] | ScannerResult:
        """Inspect ``target`` and return its findings (or a result wrapper)."""
        raise NotImplementedError

    def coverage_measures(self) -> set[str]:
        """Return every ENS measure reachable from this scanner's ``covers``.

        The measure table (:mod:`ens_audit.checks.mapping`) is the single source
        of coverage: a scanner declares the kinds it can emit and the mapping
        resolves them to measure codes.
        """
        codes: set[str] = set()
        for kind in self.covers:
            codes.update(ref.code for ref in measures_for(kind))
        return codes


def scope_for(target: Path, examined: int) -> str:
    """Describe the examined scope as ``"<target> (N file[s])"``."""
    noun = "file" if examined == 1 else "files"
    return f"{target} ({examined} {noun})"


def build_evidence(
    scanner: Scanner,
    *,
    evaluated_kinds: Iterable[str],
    checked: str | Mapping[str, str],
    scope: str,
    findings: Iterable[Finding] = (),
) -> list[CheckEvidence]:
    """Build one positive ``CheckEvidence`` per *evaluated* rule kind.

    ``evaluated_kinds`` is only the set of kinds whose check the scanner
    actually applied to a relevant artifact -- never its whole ``covers`` set.
    A scanner that examined a Dockerfile did not thereby check backups, so it
    must not claim the backup measures.

    For each kind the measure set is its mapped measures minus every measure
    that produced a failure finding (a scanner cannot certify as clean a
    measure it just flagged). ``INFO`` findings are not failures. Kinds whose
    measures are all failed (or that map to no measure) contribute nothing.
    ``checked`` is either one description shared by every kind or a
    ``{kind: description}`` mapping.
    """
    failed = {
        code
        for finding in findings
        if finding.severity is not Severity.INFO
        for code in finding.measure_codes
    }
    texts = checked if isinstance(checked, Mapping) else None
    evidence: list[CheckEvidence] = []
    seen: set[str] = set()
    for kind in evaluated_kinds:
        if kind in seen:
            continue
        seen.add(kind)
        covered = {ref.code for ref in measures_for(kind)} - failed
        if not covered:
            continue
        description = str(texts.get(kind, kind)) if texts is not None else checked
        evidence.append(
            CheckEvidence(
                scanner=scanner.id,
                tool=scanner.id,
                measure_codes=sorted(covered),
                checked=description,
                kind=kind,
                scope=scope,
            )
        )
    return evidence


def finalize_scan(
    scanner: Scanner,
    target: Path,
    findings: list[Finding],
    *,
    evaluated_kinds: Iterable[str],
    examined: int,
    checked: str | Mapping[str, str],
) -> ScannerResult:
    """Wrap a finished scanner run into a :class:`ScannerResult`.

    When ``examined`` is zero, or no rule kind was actually evaluated against a
    relevant artifact, the scanner looked at nothing it can vouch for: it
    returns a ``skipped`` result with no evidence (absence of artifacts is not
    a clean check). Otherwise it emits one positive ``CheckEvidence`` per
    evaluated kind that was left clean.
    """
    kinds = list(evaluated_kinds)
    if examined == 0 or not kinds:
        return ScannerResult(findings=findings, status="skipped")
    evidence = build_evidence(
        scanner,
        evaluated_kinds=kinds,
        checked=checked,
        scope=scope_for(target, examined),
        findings=findings,
    )
    return ScannerResult(findings=findings, evidence=evidence)
