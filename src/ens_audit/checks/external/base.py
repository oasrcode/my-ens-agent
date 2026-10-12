"""Framework for optional *external* scanners (OSV-Scanner, Semgrep, Trivy, ...).

An external scanner shells out to a third-party tool and translates its SARIF
output into :class:`~ens_audit.models.Finding` objects. These tools are strictly
optional: a tool that is not installed yields a ``skipped`` result with no
findings and no coverage. A missing tool must reduce coverage -- it must never
be read as compliance.

Execution is deliberately conservative:

* arguments are passed as a list with ``shell=False`` (never a shell string);
* every invocation is bounded by a timeout and its output captured;
* each failure mode (tool missing, timeout, non-zero exit, unparseable SARIF)
  is contained in the scanner result so it can never sink the surrounding scan.

A *parseable* SARIF report means the tool ran successfully even if it exited
non-zero (real scanners exit non-zero when they find something). Such a run is
``completed``; only a timeout, an OSError or an unparseable run with a non-zero
exit is ``failed``. A missing tool is ``skipped``.

External findings are **risk signals**, not proof of an ENS breach: they are
stamped ``method=verified`` with ``demonstrates=False`` and claim no measure
coverage (``covers = ()``). Their SARIF rule id is mapped to the ENS measure(s)
of the configured *kind* (see :mod:`ens_audit.checks.mapping`), so a detected
CVE or misconfiguration caps those measures at ``parcial`` without ever
certifying compliance.
"""

from __future__ import annotations

import abc
import logging
import os
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from ens_audit.models import (
    Confidence,
    Evidence,
    EvidenceKind,
    Finding,
    Method,
    Severity,
)

from ..base import Scanner, ScannerResult
from ..mapping import measures_for
from .sarif import SarifResult, parse_sarif, try_parse_sarif

__all__ = [
    "DEFAULT_EXTERNAL_KIND",
    "ExternalScanner",
    "ExternalTool",
    "ToolStatus",
    "findings_from_sarif",
    "import_sarif",
]

logger = logging.getLogger(__name__)

#: Default arguments used to probe a tool's availability and version.
_DEFAULT_VERSION_ARGS = ("--version",)

#: SARIF ``level`` -> finding severity. SARIF's default level is ``"warning"``,
#: so any unknown/absent level maps to ``MEDIUM``.
_LEVEL_SEVERITY: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}
_DEFAULT_SEVERITY = Severity.MEDIUM

#: Tool name used for findings imported without an explicit ``tool_name``.
_DEFAULT_IMPORT_TOOL = "external.sarif"

#: Generic kind for findings whose semantics are unknown (e.g. an arbitrary
#: user-supplied SARIF document). It maps to no specific ENS measure, so such
#: findings are surfaced as risks without touching a measure verdict.
DEFAULT_EXTERNAL_KIND = "external.finding"


@dataclass(frozen=True)
class ToolStatus:
    """Result of probing an external tool: is it runnable, and at what version."""

    available: bool
    version: str | None = None


class ExternalTool(abc.ABC):
    """An optional command-line analysis tool driven without a shell."""

    #: Human-readable tool name used to stamp findings (e.g. ``"osv-scanner"``).
    name: str = ""
    #: Executable invoked (kept separate so callers may override it).
    command: str = ""
    #: Mapping kind assigned to the tool's results (see
    #: :data:`ens_audit.checks.mapping.MEASURE_MAP`). Subclasses override it; a
    #: tool emitting several result classes can refine it per result through
    #: :meth:`kind_for`.
    kind: str = DEFAULT_EXTERNAL_KIND
    #: Arguments used to probe availability and version.
    version_args: tuple[str, ...] = _DEFAULT_VERSION_ARGS
    #: Exit codes that mean success when the output could not be parsed as
    #: SARIF. Parsed SARIF is always treated as success regardless of the code.
    success_codes: tuple[int, ...] = (0,)
    #: Seconds allowed for the version probe and for the analysis run.
    detect_timeout: float = 5.0
    run_timeout: float = 180.0

    @abc.abstractmethod
    def build_command(self, target: Path) -> list[str]:
        """Return the argv to run this tool against ``target`` (no shell)."""
        raise NotImplementedError

    def kind_for(self, result: SarifResult) -> str:
        """Return the mapping kind for one SARIF result.

        The default is the tool-wide :attr:`kind`; a tool whose results span
        several categories (e.g. Trivy vulnerabilities vs misconfigurations)
        overrides this to classify each result.
        """
        return self.kind

    def detect(self) -> ToolStatus:
        """Probe the tool with ``<command> --version``.

        The probe is short and fully guarded: a missing executable, a timeout or
        any non-zero exit all mean *unavailable* (never an exception).
        """
        try:
            probe = subprocess.run(
                [self.command, *self.version_args],
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.detect_timeout,
            )
        except (OSError, subprocess.SubprocessError):
            return ToolStatus(available=False)
        if probe.returncode != 0:
            return ToolStatus(available=False)
        version = _first_line(probe.stdout) or _first_line(probe.stderr)
        return ToolStatus(available=True, version=version)

    def execute(self, target: Path) -> ScannerResult:
        """Run the tool and map the outcome to a :class:`ScannerResult`.

        * tool unavailable -> ``skipped`` (no findings, no coverage);
        * timeout/OS error -> ``failed`` (no findings);
        * parseable SARIF -> ``completed`` with the parsed findings, **even if
          the process exited non-zero** (finding real tools commonly do);
        * unparseable output and a non-success exit code -> ``failed``;
        * unparseable output with a success exit code -> ``completed``, empty.
        """
        status = self.detect()
        if not status.available:
            logger.info("external tool %r unavailable; skipping", self.name)
            return ScannerResult(status="skipped")

        try:
            process = subprocess.run(
                self.build_command(target),
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.run_timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning("external tool %r timed out", self.name)
            return ScannerResult(
                status="failed", errors=[f"{self.name}: timed out"]
            )
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning("external tool %r could not run: %s", self.name, exc)
            return ScannerResult(status="failed", errors=[f"{self.name}: {exc}"])

        parsed = try_parse_sarif(process.stdout)
        if parsed is not None:
            # A parseable report means the tool ran: any findings are usable
            # regardless of the exit code (a non-zero code often just announces
            # that something was found).
            findings = findings_from_sarif(
                parsed,
                tool=self.name,
                tool_version=status.version,
                kind=self.kind,
                kind_for=self.kind_for,
            )
            return ScannerResult(findings=findings, status="completed")

        if process.returncode not in self.success_codes:
            logger.warning(
                "external tool %r exited with code %s and no parseable SARIF",
                self.name,
                process.returncode,
            )
            return ScannerResult(
                status="failed",
                errors=[f"{self.name}: exit code {process.returncode}"],
            )

        # Success exit code but nothing parseable to read: the tool reported
        # success without a SARIF report, so the run completed empty.
        return ScannerResult(status="completed")


class ExternalScanner(Scanner, ExternalTool):
    """A :class:`Scanner` backed by an optional external :class:`ExternalTool`.

    Combines the scanner contract with the tool runner. This class declares the
    external category and claims no measure coverage: mapping external findings
    to ENS measures is a separate concern, and a skipped/failed tool must leave
    those measures unevaluated rather than certify them.
    """

    category = "external"
    covers = ()

    def run(self, target: Path) -> ScannerResult:
        return self.execute(target)


def findings_from_sarif(
    results: Iterable[SarifResult],
    *,
    tool: str,
    tool_version: str | None = None,
    kind: str = DEFAULT_EXTERNAL_KIND,
    kind_for: Callable[[SarifResult], str] | None = None,
) -> list[Finding]:
    """Translate parsed SARIF records into findings.

    External findings are verification-grade (``method=verified``) but do not
    *demonstrate* an ENS breach (``demonstrates=False``): a CVE or a linter
    warning is a risk signal, not proof that an applicable requirement fails.

    ``kind`` is the mapping kind assigned to every result; ``kind_for``, when
    given, refines it per result (e.g. vulnerability vs misconfiguration). The
    resolved kind's measures become the finding's ``measure_codes``.
    """
    return [
        _finding_from(
            result, tool=tool, tool_version=tool_version, kind=kind, kind_for=kind_for
        )
        for result in results
    ]


def import_sarif(
    source: str | bytes | os.PathLike[str] | Path,
    tool_name: str | None = None,
    tool_version: str | None = None,
    kind: str | None = None,
) -> list[Finding]:
    """Ingest user-provided SARIF (a file path or raw text) as findings.

    Uses the same conventions as the external scanners: ``method=verified``,
    ``demonstrates=False`` and the traced tool name/version. ``kind`` selects
    the mapping kind (default: the generic :data:`DEFAULT_EXTERNAL_KIND`, which
    maps to no specific measure). Unreadable or unparseable input yields an
    empty list rather than raising.
    """
    text = _read_source(source)
    if text is None:
        return []
    return findings_from_sarif(
        parse_sarif(text),
        tool=tool_name or _DEFAULT_IMPORT_TOOL,
        tool_version=tool_version,
        kind=kind or DEFAULT_EXTERNAL_KIND,
    )


def _finding_from(
    result: SarifResult,
    *,
    tool: str,
    tool_version: str | None,
    kind: str,
    kind_for: Callable[[SarifResult], str] | None = None,
) -> Finding:
    rule_id = result.rule_id or _DEFAULT_IMPORT_TOOL
    resolved_kind = kind_for(result) if kind_for is not None else kind
    evidence: list[Evidence] = []
    if result.uri:
        location = (
            result.uri
            if result.start_line is None
            else f"{result.uri}:{result.start_line}"
        )
        evidence.append(
            Evidence(
                kind=EvidenceKind.FILE_LINE, location=location, detail=result.level
            )
        )
    return Finding(
        id=rule_id,
        severity=_LEVEL_SEVERITY.get(result.level.strip().lower(), _DEFAULT_SEVERITY),
        message=result.message or rule_id,
        measure_codes=[ref.code for ref in measures_for(resolved_kind)],
        evidence=evidence,
        tool=tool,
        tool_version=tool_version,
        method=Method.VERIFIED,
        confidence=Confidence.HIGH,
        demonstrates=False,
    )


def _read_source(source: str | bytes | os.PathLike[str] | Path) -> str | None:
    """Return SARIF text from a path, raw bytes or a raw string.

    A ``str`` that looks like JSON is treated as text; otherwise it is tried as
    a filesystem path. If neither works the raw string is returned so the parser
    can degrade safely to an empty result.
    """
    if isinstance(source, bytes):
        return source.decode("utf-8", errors="replace")
    if isinstance(source, os.PathLike):
        return _read_file(Path(source))
    if isinstance(source, str):
        if source.lstrip().startswith(("{", "[")):
            return source
        # A long/non-JSON string may be too long to be a valid path name; the
        # stat call then raises OSError (ENAMETOOLONG). Guard it so importing
        # arbitrary text never raises: unreadable input degrades to the raw
        # string, which the SARIF parser rejects safely.
        try:
            path = Path(source)
            is_file = path.is_file()
        except (OSError, ValueError):
            return source
        if is_file:
            return _read_file(path)
        return source
    return None


def _read_file(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _first_line(text: str | None) -> str | None:
    """Return the first non-empty stripped line of ``text``, or ``None``."""
    if not text:
        return None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None
