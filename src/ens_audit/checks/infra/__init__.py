"""Infrastructure/configuration scanners (``infra.*``).

Importing this package registers every infrastructure scanner in the global
registry, so ``import ens_audit.checks.infra`` is enough to make them
discoverable by :func:`ens_audit.checks.registry.run_scans`. Each scanner module
registers its scanner with the ``@register`` decorator at import time, which
returns the scanner *instance*; the names below therefore refer to instances,
not classes.
"""

from __future__ import annotations

from .backup import BackupScanner
from .compose import ComposeScanner
from .dockerfile import DockerfileScanner
from .terraform import TerraformScanner
from .web import WebScanner

#: Registered infrastructure scanners in a stable order (handy for tests).
SCANNERS = (
    DockerfileScanner,
    ComposeScanner,
    TerraformScanner,
    WebScanner,
    BackupScanner,
)

__all__ = [
    "SCANNERS",
    "BackupScanner",
    "ComposeScanner",
    "DockerfileScanner",
    "TerraformScanner",
    "WebScanner",
]
