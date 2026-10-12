"""Optional external scanners (``external.*``) and SARIF ingestion.

Importing this package registers the external scanners (OSV-Scanner, Semgrep,
Trivy) in the global registry, so they become discoverable by
:func:`ens_audit.checks.registry.run_scans`. Unlike the built-in scanners they
are *optional*: when the underlying tool is not installed they return a
``skipped`` result with no findings and no coverage.

The package also exposes :func:`import_sarif` for ingesting user-provided SARIF
reports produced elsewhere.
"""

from __future__ import annotations

from .base import (
    DEFAULT_EXTERNAL_KIND,
    ExternalScanner,
    ExternalTool,
    ToolStatus,
    findings_from_sarif,
    import_sarif,
)
from .osv import OsvScanner
from .sarif import SarifResult, parse_sarif, try_parse_sarif
from .semgrep import SemgrepScanner
from .trivy import TrivyScanner

#: Registered external scanners in a stable order. The ``@register`` decorator
#: returns the scanner *instance*, so these names refer to instances, not types.
SCANNERS = (
    OsvScanner,
    SemgrepScanner,
    TrivyScanner,
)

__all__ = [
    "DEFAULT_EXTERNAL_KIND",
    "SCANNERS",
    "ExternalScanner",
    "ExternalTool",
    "OsvScanner",
    "SarifResult",
    "SemgrepScanner",
    "ToolStatus",
    "TrivyScanner",
    "findings_from_sarif",
    "import_sarif",
    "parse_sarif",
    "try_parse_sarif",
]
