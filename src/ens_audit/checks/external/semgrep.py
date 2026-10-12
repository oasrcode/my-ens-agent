"""Semgrep adapter (scanner id ``external.semgrep``).

Runs ``semgrep --sarif --quiet <target>`` and reads the SARIF report from
stdout. Semgrep findings are static-analysis warnings; they are risk signals,
so they are emitted as non-demonstrative findings.
"""

from __future__ import annotations

from pathlib import Path

from ens_audit.checks.registry import register

from .base import ExternalScanner

__all__ = ["SemgrepScanner"]


@register
class SemgrepScanner(ExternalScanner):
    """Run Semgrep static analysis and ingest its SARIF output."""

    id = "external.semgrep"
    description = "Run Semgrep static analysis and ingest its SARIF output."
    name = "semgrep"
    command = "semgrep"
    kind = "sast.finding"

    def build_command(self, target: Path) -> list[str]:
        return [self.command, "--sarif", "--quiet", str(target)]
