"""Scanner framework primitives.

A *scanner* is a small, deterministic analysis unit that inspects a target
directory and emits :class:`~ens_audit.models.Finding` objects. The framework is
deliberately agnostic about *how* a scanner inspects the target (parsing source
files, reading infra config, shelling out to a linter, ...); it only fixes the
contract and the aggregation surface.

Scanners are expected to be pure with respect to the target: they read it and
return findings, they never mutate it.
"""

from __future__ import annotations

import abc
from pathlib import Path

from pydantic import BaseModel, Field

from ens_audit.models import Finding

__all__ = ["Scanner", "ScannerResult"]


class ScannerResult(BaseModel):
    """A scanner outcome: the findings it produced plus recoverable errors.

    Errors are non-fatal diagnostics (e.g. an unreadable file) that must not
    abort the whole scan. Fatal failures should raise instead, and the registry
    will isolate them per scanner.
    """

    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class Scanner(abc.ABC):
    """Contract implemented by every scanner.

    Subclasses declare three class attributes and implement :meth:`run`. A
    scanner may return either a bare list of findings or a :class:`ScannerResult`
    when it needs to report recoverable errors alongside them.
    """

    #: Stable, unique scanner identifier (e.g. ``"code.hardcoded_secret"``).
    id: str = ""
    #: One-line human-readable description of what the scanner checks.
    description: str = ""
    #: Coarse scanner category, e.g. ``"code"`` or ``"infra"``.
    category: str = ""

    @abc.abstractmethod
    def run(self, target: Path) -> list[Finding] | ScannerResult:
        """Inspect ``target`` and return its findings (or a result wrapper)."""
        raise NotImplementedError
