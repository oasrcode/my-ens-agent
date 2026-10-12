"""SAST-lite risky-sink scanner (rule families ``injection.sql`` and
``injection.command``).

Flags a handful of high-signal dangerous sinks that commonly lead to injection
or arbitrary-code-execution:

* SQL built by string concatenation/formatting and passed to an execute API;
* ``eval`` / ``exec`` of dynamic input;
* shell command execution (``subprocess(..., shell=True)``, ``os.system``,
  ``child_process.exec``);
* unsafe deserialisation (``pickle.loads``, ``yaml.load`` without a safe loader,
  ``marshal``).

This is a line-oriented heuristic, not a data-flow analyser: it can miss
indirect sinks and may flag safe-looking code, so findings are prompts for
review.
"""

from __future__ import annotations

import re
from pathlib import Path

from ens_audit.checks.registry import register
from ens_audit.models import Finding, Severity

from ..base import Scanner, ScannerResult, finalize_scan
from ._common import file_line_finding, iter_source_files, read_text

__all__ = ["SOURCE_CODE_SUFFIXES", "SastScanner", "is_source_code"]

_INJECTION_SQL = "injection.sql"
_INJECTION_COMMAND = "injection.command"

#: Suffixes that hold executable source code the risky-sink rules can assess.
#: Deliberately narrower than ``_common.SOURCE_SUFFIXES``: manifests and
#: configuration (``pyproject.toml``, ``package.json``, ``.env``, ``.yaml``, ...)
#: are read for other checks but are not source code, so a clean pass over them
#: says nothing about ``mp.sw.1``.
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

# An SQL execution API call.
_SQL_EXEC = re.compile(
    r"(?i)\b(?:execute|executemany|executeQuery|raw|rawQuery|createNativeQuery|"
    r"prepareStatement|query)\s*\("
)
_SQL_KEYWORD = re.compile(
    r"(?i)\b(?:select|insert|update|delete|drop|union|from|where|into|values)\b"
)
# String built by concatenation, tuple-formatting or f-string interpolation.
# ``%s`` parameter placeholders are intentionally NOT matched (only ``%``
# formatting with whitespace/parenthesis is).
_SQL_CONCAT = re.compile(
    r"(?:\+\s*[\w\"')]|[\w\"')]\s*\+|%\s*[\(]|%\s+[A-Za-z_]|\.format\s*\(|f[\"'][^\"']*\{)"
)
# Bare ``eval(...)`` / ``exec(...)`` (not method calls like ``model.eval()``).
_EVAL = re.compile(r"(?<![\w.])eval\s*\(")
_EXEC = re.compile(r"(?<![\w.])exec\s*\(")
# Shell execution sinks.
_SHELL = re.compile(
    r"(?i)(?:"
    r"\bshell\s*=\s*True"
    r"|os\.system\s*\("
    r"|os\.popen\s*\("
    r"|commands\.getoutput\s*\("
    r"|child_process\.exec\s*\("
    r")"
)
# Unsafe deserialisation.
_DESERIALIZE = re.compile(
    r"\b(?:pickle|cPickle|_pickle|dill|marshal)\s*\.\s*loads?\s*\("
)
_YAML_LOAD = re.compile(r"\byaml\s*\.\s*load\s*\(")


@register
class SastScanner(Scanner):
    """Detect risky sinks: SQL injection, eval/exec, shell=True, unsafe loads."""

    id = "code.sast"
    description = "Detect risky sinks (SQL injection, eval/exec, shell, unsafe loads)."
    category = "code"
    covers = ("injection.sql", "injection.command")

    def run(self, target: Path) -> ScannerResult:
        findings: list[Finding] = []
        examined = 0
        evaluated: list[str] = []
        for path in iter_source_files(target):
            text = read_text(path)
            if text is None:
                continue
            examined += 1
            findings.extend(self._scan_file(path, text))
            # ``mp.sw.1`` is a secure-development measure: a manifest or config
            # file is not source code, so scanning it certifies nothing.
            if is_source_code(path):
                for kind in self.covers:
                    if kind not in evaluated:
                        evaluated.append(kind)
        return finalize_scan(
            self,
            target,
            findings,
            evaluated_kinds=evaluated,
            examined=examined,
            checked=(
                "Scanned source for SQL injection, eval/exec, shell execution "
                "and unsafe deserialisation."
            ),
        )

    def _scan_file(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if (
                _SQL_EXEC.search(line)
                and _SQL_KEYWORD.search(line)
                and _SQL_CONCAT.search(line)
            ):
                findings.append(
                    self._finding(
                        _INJECTION_SQL,
                        path,
                        lineno,
                        "SQL query built by string concatenation/formatting.",
                        Severity.HIGH,
                        "sql string concatenation",
                    )
                )
            if _EVAL.search(line) or _EXEC.search(line):
                findings.append(
                    self._finding(
                        _INJECTION_COMMAND,
                        path,
                        lineno,
                        "Dynamic code execution via eval/exec.",
                        Severity.HIGH,
                        "eval/exec",
                    )
                )
            if _SHELL.search(line):
                findings.append(
                    self._finding(
                        _INJECTION_COMMAND,
                        path,
                        lineno,
                        "Shell command execution enabled.",
                        Severity.HIGH,
                        "shell execution",
                    )
                )
            if _DESERIALIZE.search(line):
                findings.append(
                    self._finding(
                        _INJECTION_COMMAND,
                        path,
                        lineno,
                        "Unsafe deserialisation of untrusted data.",
                        Severity.CRITICAL,
                        "unsafe deserialization",
                    )
                )
            elif _YAML_LOAD.search(line) and "SafeLoader" not in line:
                findings.append(
                    self._finding(
                        _INJECTION_COMMAND,
                        path,
                        lineno,
                        "yaml.load without SafeLoader can execute arbitrary objects.",
                        Severity.HIGH,
                        "unsafe yaml.load",
                    )
                )
        return findings

    @staticmethod
    def _finding(
        kind: str,
        path: Path,
        lineno: int,
        message: str,
        severity: Severity,
        detail: str,
    ) -> Finding:
        return file_line_finding(
            kind=kind,
            severity=severity,
            message=message,
            path=path,
            line=lineno,
            detail=detail,
        )
