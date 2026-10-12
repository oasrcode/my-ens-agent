"""Backup configuration scanner (``infra.backup``).

Conservative: it only flags configurations that *explicitly* show backups being
disabled or a retention of zero. Absence of a backup configuration is **not**
reported (a scanner cannot infer intent from silence), so there are no false
positives on projects that simply do not manage backups here.

Findings are mapped to ``backup.disabled`` (``mp.info.6``, backups, ``Anexo
II``). This is a distinct control from ``storage.unencrypted`` (crypto at rest,
``mp.si.2``): a backup being switched off says nothing about the cryptography
of what is stored.
"""

from __future__ import annotations

import re
from pathlib import Path

from ens_audit.checks.registry import register
from ens_audit.models import Finding, Severity

from ..base import Scanner, ScannerResult, finalize_scan
from ._common import file_line_finding, iter_files, read_text

__all__ = ["BackupScanner"]

# Rule kind (key into the ENS measure mapping): its measure is mp.info.6
# ("Copias de seguridad").
_KIND = "backup.disabled"

_BACKUP_WORD = re.compile(r"(?i)\b(?:backup|backups|snapshot|snapshots)\b")
# A backup/snapshot *key* in configuration position (``backup:``,
# ``backup_enabled = false``, ``snapshot_retention = 7``, ...). This is what
# makes a file backup configuration; a bare mention of the word -- e.g. a
# dependency named ``backup-tools`` in a manifest -- is not enough.
_BACKUP_CONFIG = re.compile(
    r"(?im)^[ \t]*(?:[-*]\s+)?[\"']?"
    r"(?:backup|backups|snapshot|snapshots)[\w.\-]*[\"']?\s*"
    r"(?::|=(?!=)\s*(?:true|false|yes|no|on|off|0|1|\d+)\b)"
)
# ``backup_enabled: false`` / ``snapshot_enabled = off`` / ``backups=0`` ...
_DISABLED_DIRECT = re.compile(
    r"(?i)\b(?:backup|backups|snapshot|snapshots)[\w.\-]*\s*[:=]\s*"
    r"[\"']?(?:false|off|no|disabled|0)\b"
)
# ``enabled: false`` whose surrounding block is about backups.
_ENABLED_FALSE = re.compile(r"(?i)\benabled\s*[:=]\s*[\"']?(?:false|off|no|0)\b")
# Terraform RDS: no automated backups retained.
_RETENTION_ZERO = re.compile(r"(?i)\bbackup_retention_period\s*=\s*0\b")


def _looks_like_backup(path: Path, text: str) -> bool:
    """Whether ``path`` really is a backup configuration.

    Only files that actually deal with backups qualify: a backup-like file name
    (mentioning backups/snapshots), or content with a backup/snapshot key in
    configuration position. Arbitrary config files (``pyproject.toml``,
    ``package.json``, ...) must not be treated as backup configuration just
    because the word appears somewhere (e.g. a dependency named
    ``backup-tools``), or the scanner would claim the ``mp.info.6`` control for
    every project.
    """
    name = path.name.lower()
    if "backup" in name or "snapshot" in name:
        return True
    return _BACKUP_CONFIG.search(text) is not None


def _context_is_backup(lines: list[str], index: int, back: int = 3) -> bool:
    """Whether a nearby preceding line mentions backups (for ``enabled: false``)."""
    start = max(0, index - back)
    return any(_BACKUP_WORD.search(line) for line in lines[start:index])


@register
class BackupScanner(Scanner):
    """Flag configurations that explicitly disable backups or retention."""

    id = "infra.backup"
    description = "Flag backup configurations that are explicitly disabled."
    category = "infra"
    covers = ("backup.disabled",)

    def run(self, target: Path) -> ScannerResult:
        findings: list[Finding] = []
        examined = 0
        for path in iter_files(target):
            text = read_text(path)
            if text is None or not _looks_like_backup(path, text):
                continue
            examined += 1
            findings.extend(self._scan_file(path, text))
        return finalize_scan(
            self,
            target,
            findings,
            evaluated_kinds=(_KIND,),
            examined=examined,
            checked=(
                "Checked configuration for backups/snapshots explicitly "
                "disabled or with zero retention."
            ),
        )

    def _scan_file(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if _RETENTION_ZERO.search(line):
                findings.append(self._finding(path, index + 1, "retention is zero"))
            elif _DISABLED_DIRECT.search(line):
                findings.append(self._finding(path, index + 1, "backups disabled"))
            elif _ENABLED_FALSE.search(line) and _context_is_backup(lines, index):
                findings.append(
                    self._finding(path, index + 1, "backups explicitly disabled")
                )
        return findings

    @staticmethod
    def _finding(path: Path, line: int, what: str) -> Finding:
        return file_line_finding(
            kind=_KIND,
            severity=Severity.MEDIUM,
            message=f"Backups appear to be disabled or missing retention ({what}).",
            path=path,
            line=line,
            detail=what,
        )
