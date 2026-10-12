"""Shared helpers for the infrastructure/configuration scanners.

These helpers only gather candidate config files, read them defensively and
build findings; the detection rules themselves live in the individual scanner
modules. Keeping the file walking and the ``file_line`` evidence contract here
avoids duplicating it across the five scanners.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from pathlib import Path

from ens_audit.checks.mapping import measures_for
from ens_audit.models import Evidence, EvidenceKind, Finding, Severity

__all__ = [
    "CONFIG_SUFFIXES",
    "file_line_finding",
    "find_line",
    "iter_files",
    "read_text",
]

#: Directories that never hold first-party configuration worth scanning.
_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".tox",
        ".eggs",
    }
)

#: Text file suffixes that may hold infrastructure/configuration.
CONFIG_SUFFIXES = frozenset(
    {
        ".conf",
        ".yaml",
        ".yml",
        ".tf",
        ".tfvars",
        ".json",
        ".env",
        ".ini",
        ".cfg",
        ".toml",
        ".properties",
        ".txt",
    }
)

#: Container/nginx files without a useful suffix that are still candidates.
_CONFIG_NAMES = frozenset({"Dockerfile", "Containerfile", "nginx.conf"})

#: Never read files bigger than this (defensive; keeps scans fast).
_MAX_FILE_BYTES = 1_000_000


def iter_files(
    target: Path, predicate: Callable[[Path], bool] | None = None
) -> Iterator[Path]:
    """Yield candidate configuration files under ``target`` in a stable order.

    ``target`` may be a single file or a directory. VCS/vendor/cache
    directories are skipped, as are oversized files. Only paths matching
    ``predicate`` (when given) are yielded; without one, the suffix/name
    heuristic of :data:`CONFIG_SUFFIXES` / :data:`_CONFIG_NAMES` is applied.
    """

    def default_predicate(path: Path) -> bool:
        if path.name in _CONFIG_NAMES or path.name.startswith("Dockerfile."):
            return True
        return path.suffix.lower() in CONFIG_SUFFIXES

    keep = predicate or default_predicate
    target = Path(target)
    if target.is_file():
        root = target.parent
        candidates = [target]
    elif target.is_dir():
        root = target
        candidates = sorted(path for path in target.rglob("*") if path.is_file())
    else:
        return

    for path in candidates:
        # Only the directory components *below* the scan target are excluded;
        # the target's own path must never disqualify its contents (e.g. a
        # target literally named ``build`` or ``dist``).
        relative_dirs = path.relative_to(root).parts[:-1]
        if any(part in _EXCLUDED_DIRS for part in relative_dirs):
            continue
        if not keep(path):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def read_text(path: Path) -> str | None:
    """Return the file text, or ``None`` when it cannot be read."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def find_line(text: str, pattern: str, flags: int = re.IGNORECASE | re.MULTILINE) -> int:
    """Return the 1-based line number of the first regex match, else ``0``."""
    match = re.search(pattern, text, flags)
    if match is None:
        return 0
    return text.count("\n", 0, match.start()) + 1


def file_line_finding(
    *,
    kind: str,
    severity: Severity,
    message: str,
    path: Path,
    line: int,
    detail: str = "",
) -> Finding:
    """Build a finding with ``file_line`` evidence and its ENS measure codes.

    ``kind`` is the stable rule id used both as the finding id and as the key
    into the ENS measure mapping.
    """
    return Finding(
        id=kind,
        severity=severity,
        message=message,
        measure_codes=[ref.code for ref in measures_for(kind)],
        evidence=[
            Evidence(
                kind=EvidenceKind.FILE_LINE,
                location=f"{path}:{max(line, 1)}",
                detail=detail,
            )
        ],
    )
