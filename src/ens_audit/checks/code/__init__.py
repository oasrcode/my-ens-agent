"""Source-code scanners (``code.*``).

Importing this package registers every code scanner in the global registry, so
``import ens_audit.checks.code`` is enough to make them discoverable by
:func:`ens_audit.checks.registry.run_scans`. Each scanner module registers its
scanner with the ``@register`` decorator at import time, which returns the
scanner *instance*; the names below therefore refer to instances, not classes.
"""

from __future__ import annotations

from .crypto import CryptoScanner
from .dependencies import DependenciesScanner
from .logging import LoggingScanner
from .sast import SastScanner
from .secrets import SecretsScanner

#: Registered code scanners in a stable order (handy for tests and tooling).
SCANNERS = (
    SecretsScanner,
    DependenciesScanner,
    CryptoScanner,
    LoggingScanner,
    SastScanner,
)

__all__ = [
    "SCANNERS",
    "CryptoScanner",
    "DependenciesScanner",
    "LoggingScanner",
    "SastScanner",
    "SecretsScanner",
]
