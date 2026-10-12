"""Hardcoded-secrets scanner (rule family ``secret.hardcoded``).

Detects credentials committed to source control: cloud access keys, PEM private
keys, JSON Web Tokens and generic password/secret/api-key assignments. Matching
is deliberately conservative (high-confidence patterns only) so that a hit is a
strong signal rather than noise; comments and obvious placeholders or
environment lookups are ignored.
"""

from __future__ import annotations

import re
from pathlib import Path

from ens_audit.checks.registry import register
from ens_audit.models import Finding, Severity

from ..base import Scanner, ScannerResult, finalize_scan
from ._common import file_line_finding, is_source_code, iter_source_files, read_text

__all__ = ["SecretsScanner"]

# Single rule kind shared by every hardcoded-secret finding; maps to the ENS
# cryptography/key-protection measures via the measure table.
_KIND = "secret.hardcoded"

# AWS access key ids: documented prefixes followed by 16 uppercase/digits.
_AWS_ACCESS_KEY = re.compile(
    r"\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|ASCA)[A-Z0-9]{16}\b"
)
# PEM-encoded private keys of any flavour.
_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
)
# A three-segment JWT (header.payload.signature), both URL-safe base64.
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
# Generic "<secret-ish name> = 'literal'" assignments (>=8 char literal).
_SECRET_NAME = (
    r"(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|"
    r"auth[_-]?token|private[_-]?key|client[_-]?secret|secret[_-]?key)"
)
_GENERIC_ASSIGNMENT = re.compile(
    rf"(?i)(?<![A-Za-z]){_SECRET_NAME}(?![A-Za-z])"
    rf"\s*[:=]\s*(?P<quote>[\"'])(?P<value>[^\"'\n]{{8,}})(?P=quote)"
)

# Values that are almost certainly placeholders or environment lookups.
_PLACEHOLDER = re.compile(
    r"(?i)(?:os\.(?:getenv|environ)|process\.env|getenv\(|\$\{|%\(|<%|\{\{|"
    r"<[A-Z_]{2,}>|x{6,}|changeme|placeholder|example|dummy|sample|your[_-]|"
    r"redacted|\*{3,}|\.\.\.|todo)"
)
_WEAK_VALUES = re.compile(
    r"(?i)^(?:password|passw0rd|secret|admin|root|letmein|changeme|default|"
    r"test|example|sample|dummy|foo|bar|baz|todo|none|null)$"
)
# A match on a comment-only line is usually documentation, not a live secret.
_COMMENT_LINE = re.compile(r"^\s*(?:#|//|/\*|\*|--|;)")


def _is_placeholder(value: str) -> bool:
    """Return True when a candidate value looks like a placeholder, not a secret."""
    return bool(_PLACEHOLDER.search(value)) or bool(_WEAK_VALUES.match(value.strip()))


@register
class SecretsScanner(Scanner):
    """Detect hardcoded credentials, tokens and private keys in source."""

    id = "code.secrets"
    description = "Detect hardcoded credentials, tokens and private keys in source."
    category = "code"
    covers = ("secret.hardcoded",)

    def run(self, target: Path) -> ScannerResult:
        findings: list[Finding] = []
        examined = 0
        source_examined = False
        for path in iter_source_files(target):
            text = read_text(path)
            if text is None:
                continue
            examined += 1
            # ``mp.si.2`` / ``op.exp.10`` are protected by source-code checks: a
            # dependency manifest or config file is not source code, so a clean
            # pass over it certifies nothing (same class as the SAST gap).
            if is_source_code(path):
                source_examined = True
            findings.extend(self._scan_file(path, text))
        return finalize_scan(
            self,
            target,
            findings,
            evaluated_kinds=self.covers if source_examined else (),
            examined=examined,
            checked=(
                "Scanned source files for hardcoded credentials, tokens and "
                "private keys."
            ),
        )

    def _scan_file(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _PEM_PRIVATE_KEY.search(line):
                findings.append(
                    self._finding(path, lineno, "PEM private key", Severity.CRITICAL)
                )
            elif _AWS_ACCESS_KEY.search(line):
                findings.append(
                    self._finding(path, lineno, "AWS access key id", Severity.CRITICAL)
                )
            elif _JWT.search(line):
                findings.append(
                    self._finding(path, lineno, "JSON Web Token", Severity.HIGH)
                )
            elif not _COMMENT_LINE.match(line):
                match = _GENERIC_ASSIGNMENT.search(line)
                if match and not _is_placeholder(match.group("value")):
                    findings.append(
                        self._finding(
                            path, lineno, "hardcoded secret assignment", Severity.HIGH
                        )
                    )
        return findings

    @staticmethod
    def _finding(path: Path, lineno: int, what: str, severity: Severity) -> Finding:
        return file_line_finding(
            kind=_KIND,
            severity=severity,
            message=f"Possible hardcoded secret in source ({what}).",
            path=path,
            line=lineno,
            detail=what,
        )
