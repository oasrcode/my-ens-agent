"""OSV-Scanner adapter (scanner id ``external.osv``).

Runs ``osv-scanner --format sarif -r <target>`` and ingests its SARIF output.
OSV-Scanner reports known vulnerabilities in the project's dependencies; that is
a risk signal, not a demonstrated ENS breach, so findings are non-demonstrative.
"""

from __future__ import annotations

from pathlib import Path

from ens_audit.checks.registry import register

from .base import ExternalScanner

__all__ = ["OsvScanner"]


@register
class OsvScanner(ExternalScanner):
    """Scan dependencies for known vulnerabilities with OSV-Scanner."""

    id = "external.osv"
    description = "Scan dependencies for known vulnerabilities with OSV-Scanner."
    name = "osv-scanner"
    command = "osv-scanner"
    kind = "vuln.dependency"

    def build_command(self, target: Path) -> list[str]:
        return [self.command, "--format", "sarif", "-r", str(target)]
