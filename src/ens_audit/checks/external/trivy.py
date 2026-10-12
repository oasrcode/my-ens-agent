"""Trivy adapter (scanner id ``external.trivy``).

Runs ``trivy fs --format sarif --quiet <target>`` and ingests its SARIF output.
Trivy reports vulnerable dependencies and misconfigurations; both are risk
signals rather than demonstrated ENS breaches, so findings are non-demonstrative.
"""

from __future__ import annotations

from pathlib import Path

from ens_audit.checks.registry import register

from .base import ExternalScanner
from .sarif import SarifResult

__all__ = ["TrivyScanner"]

#: Rule-id prefixes Trivy uses for vulnerability results (as opposed to its
#: misconfiguration/secret rules, which use IDs such as ``DS002`` or ``AVD-...``).
_VULN_ID_PREFIXES = ("CVE-", "GHSA-")


@register
class TrivyScanner(ExternalScanner):
    """Scan the filesystem for vulnerabilities and misconfigurations with Trivy."""

    id = "external.trivy"
    description = (
        "Scan the filesystem for vulnerabilities and misconfigurations with Trivy."
    )
    name = "trivy"
    command = "trivy"
    kind = "container.vuln"

    def build_command(self, target: Path) -> list[str]:
        return [self.command, "fs", "--format", "sarif", "--quiet", str(target)]

    def kind_for(self, result: SarifResult) -> str:
        """Classify a Trivy result as a vulnerability or a misconfiguration.

        Vulnerability rules carry a ``CVE-``/``GHSA-`` id; everything else
        (Dockerfile/Kubernetes/terraform policy checks) is a misconfiguration.
        """
        rule_id = result.rule_id.upper()
        if rule_id.startswith(_VULN_ID_PREFIXES):
            return "container.vuln"
        return "iac.misconfig"
