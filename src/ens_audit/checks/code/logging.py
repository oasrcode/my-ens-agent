"""Audit-logging quality scanner (rule family ``logging.audit_disabled`` plus
secret-exposure findings reusing ``secret.hardcoded``).

Checks three logging-quality signals in application source:

* **Security modules with no logging** — files whose name looks
  authentication/authorisation related but that never call a logging API,
  leaving security-relevant events untraceable (ENS ``op.exp.8``).
* **Secrets written to logs** — logging calls that include password, token,
  credential or key-looking arguments, exposing secrets in log sinks
  (ENS ``op.exp.10`` / ``mp.si.2``).
* **Overly broad exception swallowing** — ``except: pass``-style handlers (or
  empty ``catch`` blocks) that hide failures and sabotage traceability.

These are heuristics: a security-looking filename without logging may delegate
logging to a caller, so a hit is a prompt for review, not a verdict.
"""

from __future__ import annotations

import re
from pathlib import Path

from ens_audit.checks.registry import register
from ens_audit.models import Finding, Severity

from ..base import Scanner, ScannerResult, finalize_scan
from ._common import file_line_finding, iter_source_files, read_text

__all__ = ["LoggingScanner"]

_AUDIT_DISABLED = "logging.audit_disabled"
_SECRET_LOGGED = "secret.hardcoded"

#: Filenames hinting the module handles authentication/authorisation.
_SECURITY_HINT = re.compile(
    r"(?i)(?:auth|login|logout|session|password|passwd|credential|token|oauth|"
    r"permission|rbac|acl|security|signin|signup)"
)
#: A real logging call (Python logging/logger, JS console, Java loggers).
_LOGGING_CALL = re.compile(
    r"(?i)(?:"
    r"\b(?:logging|logger|log|_log)\s*\.\s*"
    r"(?:debug|info|warning|warn|error|critical|exception|trace|log)\s*\("
    r"|\bconsole\s*\.\s*(?:log|warn|error|info|debug)\s*\("
    r"|\b(?:System\.out\.println|printStackTrace)\s*\("
    r")"
)
#: A logging call that includes a secret-looking argument.
_LOG_SECRET = re.compile(
    r"(?i)(?:logging|logger|log|console)\s*\.\s*"
    r"(?:debug|info|warning|warn|error|critical|exception|trace|log)\s*\("
    r"[^\n]*\b(?:password|passwd|secret|token|api[_-]?key|credential|"
    r"authorization|private[_-]?key|access[_-]?key)\b"
)
#: Python single-line swallow: ``except ...: pass|...|continue|return``.
_SWALLOW_ONELINE = re.compile(
    r"^\s*except\b[^\n:]*:\s*(?:pass|\.\.\.|continue|return(?:\s+None)?)\b",
    re.MULTILINE | re.IGNORECASE,
)
#: Empty JS/Java catch block (optionally containing only comments).
_EMPTY_CATCH = re.compile(r"(?is)\bcatch\s*(?:\([^)]*\))?\s*\{\s*(?://[^\n]*\n\s*)*\}")
_DEFINITION = re.compile(r"(?m)^\s*(?:async\s+)?(?:def|function|class)\s+\w+")


@register
class LoggingScanner(Scanner):
    """Check audit-logging quality and secret exposure in logs."""

    id = "code.logging"
    description = "Check audit logging presence, secret leakage and swallowed errors."
    category = "code"
    covers = ("logging.audit_disabled", "secret.hardcoded")

    def run(self, target: Path) -> ScannerResult:
        findings: list[Finding] = []
        examined = 0
        has_logging_call = False
        for path in iter_source_files(target):
            text = read_text(path)
            if text is None:
                continue
            examined += 1
            if _LOGGING_CALL.search(text):
                has_logging_call = True
            findings.extend(self._scan_file(path, text))
        # ``secret.hardcoded`` here means "secret written to a log": without any
        # logging call to inspect, that check was never applied, so it must not
        # certify the secret measures. ``logging.audit_disabled`` (missing
        # logging in security modules, swallowed exceptions) is applied to
        # every scanned source file.
        evaluated = ["logging.audit_disabled"]
        if has_logging_call:
            evaluated.append("secret.hardcoded")
        return finalize_scan(
            self,
            target,
            findings,
            evaluated_kinds=evaluated,
            examined=examined,
            checked=(
                "Checked source for audit-logging coverage, secret leakage in "
                "logs and swallowed exceptions."
            ),
        )

    def _scan_file(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()

        if (
            self._is_security_module(path)
            and not _LOGGING_CALL.search(text)
            and _DEFINITION.search(text)
            and len(lines) > 5
        ):
            findings.append(
                file_line_finding(
                    kind=_AUDIT_DISABLED,
                    severity=Severity.MEDIUM,
                    message=(
                        "Security-related module has no logging calls; "
                        "security events are not traceable."
                    ),
                    path=path,
                    line=1,
                    detail="no logging in security module",
                )
            )

        for lineno, line in enumerate(lines, start=1):
            if _LOG_SECRET.search(line):
                findings.append(
                    file_line_finding(
                        kind=_SECRET_LOGGED,
                        severity=Severity.HIGH,
                        message="Secret or credential appears to be written to a log.",
                        path=path,
                        line=lineno,
                        detail="secret in log",
                    )
                )

        for lineno in self._swallowed_exceptions(lines):
            findings.append(
                file_line_finding(
                    kind=_AUDIT_DISABLED,
                    severity=Severity.MEDIUM,
                    message="Overly broad exception handler swallows failures silently.",
                    path=path,
                    line=lineno,
                    detail="silently swallowed exception",
                )
            )

        for match in _EMPTY_CATCH.finditer(text):
            lineno = text.count("\n", 0, match.start()) + 1
            findings.append(
                file_line_finding(
                    kind=_AUDIT_DISABLED,
                    severity=Severity.MEDIUM,
                    message="Empty catch block hides failures silently.",
                    path=path,
                    line=lineno,
                    detail="empty catch block",
                )
            )
        return findings

    @staticmethod
    def _is_security_module(path: Path) -> bool:
        """Return True when the file's name suggests auth/security handling."""
        stem = path.stem
        if _SECURITY_HINT.search(stem):
            return True
        return any(_SECURITY_HINT.search(part) for part in path.parts[:-1])

    @staticmethod
    def _swallowed_exceptions(lines: list[str]) -> list[int]:
        """Return 1-based lines of ``except`` blocks whose body swallows errors."""
        hits: list[int] = []
        for index, raw in enumerate(lines):
            if _SWALLOW_ONELINE.match(raw):
                hits.append(index + 1)
                continue
            opener = re.match(r"^(\s*)except\b[^\n:]*:\s*(?:#.*)?$", raw)
            if not opener:
                continue
            indent = len(opener.group(1).expandtabs())
            for follow in lines[index + 1 :]:
                stripped = follow.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                body_indent = len(follow) - len(follow.lstrip())
                if body_indent <= indent:
                    break
                if stripped in {"pass", "...", "continue"} or stripped.startswith(
                    "return"
                ):
                    hits.append(index + 1)
                break
        return hits
