"""Backup configuration scanner (``infra.backup``).

Conservative: it only flags configurations that *explicitly* show backups being
disabled or a retention of zero. Absence of a backup configuration is **not**
reported (a scanner cannot infer intent from silence), so there are no false
positives on projects that simply do not manage backups here.

Findings are mapped to ``storage.unencrypted`` because its measure references
include ``mp.info.6`` (backups, ``Anexo II``).
"""

from __future__ import annotations

import re
from pathlib import Path

from ens_audit.checks.registry import register
from ens_audit.models import Finding, Severity

from ..base import Scanner
from ._common import CONFIG_SUFFIXES, file_line_finding, iter_files, read_text

__all__ = ["BackupScanner"]

# Rule kind (key into the ENS measure mapping): its measures include mp.info.6
# ("Copias de seguridad").
_KIND = "storage.unencrypted"

_BACKUP_WORD = re.compile(r"(?i)\b(?:backup|backups|snapshot|snapshots)\b")
# ``backup_enabled: false`` / ``snapshot_enabled = off`` / ``backups=0`` ...
_DISABLED_DIRECT = re.compile(
    r"(?i)\b(?:backup|backups|snapshot|snapshots)[\w.\-]*\s*[:=]\s*"
    r"[\"']?(?:false|off|no|disabled|0)\b"
)
# ``enabled: false`` whose surrounding block is about backups.
_ENABLED_FALSE = re.compile(r"(?i)\benabled\s*[:=]\s*[\"']?(?:false|off|no|0)\b")
# Terraform RDS: no automated backups retained.
_RETENTION_ZERO = re.compile(r"(?i)\bbackup_retention_period\s*=\s*0\b")


def _is_backup_config(path: Path) -> bool:
    """Whether ``path`` is a config file likely to hold backup settings."""
    return path.suffix.lower() in CONFIG_SUFFIXES or "backup" in path.name.lower()


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

    def run(self, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_files(target, _is_backup_config):
            text = read_text(path)
            if text is None:
                continue
            findings.extend(self._scan_file(path, text))
        return findings

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
