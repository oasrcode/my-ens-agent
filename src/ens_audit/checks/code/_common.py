"""Shared helpers for the source-code scanners.

These helpers only gather candidate files, read them defensively and build
findings; the detection rules themselves live in the individual scanner
modules. Keeping the file walking and the ``file_line`` evidence contract here
avoids duplicating it across five scanners.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from ens_audit.checks.mapping import measures_for
from ens_audit.models import Evidence, EvidenceKind, Finding, Severity

__all__ = [
    "SOURCE_CODE_SUFFIXES",
    "SOURCE_SUFFIXES",
    "file_line_finding",
    "is_source_code",
    "iter_source_files",
    "line_number_for",
    "read_text",
]

#: Directories that never hold first-party source worth scanning.
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

#: Text file suffixes the code scanners inspect.
SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".java",
        ".kt",
        ".go",
        ".rb",
        ".php",
        ".cs",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".hpp",
        ".sh",
        ".bash",
        ".ps1",
        ".sql",
        ".yml",
        ".yaml",
        ".toml",
        ".mod",
        ".ini",
        ".cfg",
        ".conf",
        ".env",
        ".properties",
        ".json",
        ".txt",
    }
)

#: Suffixes that hold executable source code the risky-sink rules can assess.
#: Deliberately narrower than :data:`SOURCE_SUFFIXES`: manifests and
#: configuration (``pyproject.toml``, ``package.json``, ``.env``, ``.yaml``, ...)
#: are read for other checks but are not source code, so a clean pass over them
#: says nothing about the source-code measures.
SOURCE_CODE_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".java",
        ".kt",
        ".go",
        ".rb",
        ".php",
        ".cs",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".hpp",
        ".sh",
        ".bash",
        ".ps1",
        ".sql",
    }
)


def is_source_code(path: Path) -> bool:
    """Whether ``path`` is source code, as opposed to a manifest or config."""
    return path.suffix.lower() in SOURCE_CODE_SUFFIXES


#: Never read files bigger than this (defensive; keeps scans fast).
_MAX_FILE_BYTES = 1_000_000


def iter_source_files(target: Path) -> Iterator[Path]:
    """Yield the candidate text files under ``target`` in a stable order.

    ``target`` may be a single file or a directory. VCS/vendor/cache
    directories are skipped, as are files whose suffix is not in
    :data:`SOURCE_SUFFIXES` and files larger than :data:`_MAX_FILE_BYTES`.
    """
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
        if path.suffix.lower() not in SOURCE_SUFFIXES:
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


def line_number_for(text: str, token: str, fallback: int = 1) -> int:
    """Return the 1-based line where ``token`` first appears in ``text``.

    Used by parsers (TOML/JSON) that do not report source positions. Falls back
    to ``fallback`` when the token cannot be located.
    """
    index = text.find(token)
    if index < 0:
        return fallback
    return text.count("\n", 0, index) + 1


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
                location=f"{path}:{line}",
                detail=detail,
            )
        ],
    )
