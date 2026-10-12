"""Dependency-hygiene scanner (SCA-lite, rule family ``dependency.outdated``).

Two cheap, offline checks over the common dependency manifests
(``requirements*.txt``, ``pyproject.toml``, ``package.json``, ``go.mod``):

* **Unpinned / loose version constraints** — a dependency without an exact pin
  can silently drift to a vulnerable release.
* **Known-deprecated or risky packages** — a small, hand-curated denylist of
  packages that are unmaintained or have a poor security track record.

It performs **no network access** and knows nothing about advisories published
after this code was written. This is **NOT** a full CVE/SCA database: treat it
as a cheap first pass and pair it with a real vulnerability scanner for
authoritative results. The denylist is intentionally short to keep false
positives low, and is expected to be extended over time.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from ens_audit.checks.registry import register
from ens_audit.models import Finding, Severity

from ..base import Scanner, ScannerResult, finalize_scan
from ._common import file_line_finding, iter_source_files, line_number_for, read_text

__all__ = ["DependenciesScanner"]

_KIND = "dependency.outdated"

_REQUIREMENTS = re.compile(r"(?i)^requirements(?:[-._].*)?\.txt$")

#: Curated denylist: package name (normalised) -> why it is flagged.
_DEPRECATED: dict[str, str] = {
    "pycrypto": "unmaintained, multiple known CVEs (use pycryptodome or cryptography)",
    "nose": "unmaintained test runner",
    "mysql-python": "unmaintained MySQL driver (use mysqlclient)",
    "sklearn": "deprecated shim package (use scikit-learn)",
    "request": "deprecated HTTP client (npm)",
    "node-uuid": "deprecated package (use uuid)",
    "left-pad": "deprecated package",
    "event-stream": "historically compromised package",
    "github.com/dgrijalva/jwt-go": "unmaintained JWT library (use golang-jwt/jwt)",
    "github.com/satori/go.uuid": "unmaintained UUID library",
}

# A PEP 508 / requirements entry: leading distribution name.
_DIST_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
# Poetry accepts exact versions only in this shape, e.g. "1.2.3".
_POETRY_EXACT = re.compile(r"^\d+(?:\.\d+){0,3}$")
# npm exact pin: a plain semver with no range operators or wildcards.
_NPM_EXACT = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


def _normalize_python(name: str) -> str:
    """Normalise a Python distribution name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def _is_pinned_python(spec: str) -> bool:
    """Return True when a PEP 508/requirements specifier pins an exact version."""
    spec = spec.strip()
    if not spec:
        return False
    return "==" in spec and "*" not in spec


@register
class DependenciesScanner(Scanner):
    """Flag unpinned dependencies and known-deprecated packages in manifests."""

    id = "code.dependencies"
    description = "Check dependency manifests for unpinned/loose or risky packages."
    category = "code"
    covers = ("dependency.outdated",)

    def run(self, target: Path) -> ScannerResult:
        findings: list[Finding] = []
        examined = 0
        for path in iter_source_files(target):
            text = read_text(path)
            if text is None:
                continue
            name = path.name.lower()
            if name == "requirements.txt" or _REQUIREMENTS.match(path.name):
                examined += 1
                findings.extend(self._parse_requirements(path, text))
            elif name == "pyproject.toml":
                examined += 1
                findings.extend(self._parse_pyproject(path, text))
            elif name == "package.json":
                examined += 1
                findings.extend(self._parse_package_json(path, text))
            elif name == "go.mod":
                examined += 1
                findings.extend(self._parse_go_mod(path, text))
        return finalize_scan(
            self,
            target,
            findings,
            evaluated_kinds=self.covers,
            examined=examined,
            checked=(
                "Checked dependency manifests for unpinned or deprecated/risky "
                "packages."
            ),
        )

    # -- requirements*.txt ---------------------------------------------------
    def _parse_requirements(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            if line.lower().startswith(("http://", "https://", "git+", "file:")):
                continue
            # Drop environment markers before looking at the version spec.
            requirement = line.split(";", 1)[0].strip()
            match = _DIST_NAME.match(requirement)
            if not match:
                continue
            name = match.group(1)
            spec = requirement[match.end() :].strip()
            findings.extend(
                self._check(path, name, lineno, spec, _is_pinned_python(spec))
            )
        return findings

    # -- pyproject.toml ------------------------------------------------------
    def _parse_pyproject(self, path: Path, text: str) -> list[Finding]:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return []

        findings: list[Finding] = []
        project = data.get("project", {}) or {}
        entries: list[str] = list(project.get("dependencies", []) or [])
        for items in (project.get("optional-dependencies", {}) or {}).values():
            entries.extend(items or [])
        for entry in entries:
            match = _DIST_NAME.match(entry)
            if not match:
                continue
            name = match.group(1)
            spec = entry[match.end() :].strip()
            line = line_number_for(text, name)
            findings.extend(
                self._check(path, name, line, spec, _is_pinned_python(spec))
            )

        poetry = (data.get("tool", {}) or {}).get("poetry", {}) or {}
        for name, spec in (poetry.get("dependencies", {}) or {}).items():
            if name.lower() == "python":
                continue
            if isinstance(spec, str):
                pinned = bool(_POETRY_EXACT.match(spec.strip()))
            else:  # table/list form: allow ranges, treat as loose
                pinned = False
            line = line_number_for(text, name)
            findings.extend(self._check(path, name, line, "", pinned))
        return findings

    # -- package.json --------------------------------------------------------
    def _parse_package_json(self, path: Path, text: str) -> list[Finding]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for section in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            for name, spec in (data.get(section, {}) or {}).items():
                if not isinstance(spec, str):
                    continue
                if spec.startswith(("workspace:", "file:", "link:", "git+", "http")):
                    continue
                pinned = bool(_NPM_EXACT.match(spec.strip()))
                line = line_number_for(text, f'"{name}"')
                findings.extend(self._check(path, name, line, spec, pinned))
        return findings

    # -- go.mod --------------------------------------------------------------
    def _parse_go_mod(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        in_block = False
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw.split("//", 1)[0].strip()
            if not line:
                continue
            if line.startswith("require ("):
                in_block = True
                continue
            if in_block and line == ")":
                in_block = False
                continue
            if line.startswith("replace"):
                if "=>" in line and re.search(r"=>\s*[./]", line):
                    findings.append(
                        self._finding(
                            path,
                            lineno,
                            "dependency replaced with a local path",
                            Severity.MEDIUM,
                            "local replace directive",
                        )
                    )
                continue
            entry = ""
            if in_block:
                entry = line
            elif line.startswith("require "):
                entry = line[len("require ") :].strip()
            if not entry:
                continue
            parts = entry.split()
            if len(parts) < 2:
                continue
            module, version = parts[0], parts[1]
            pinned = bool(version) and version != "latest"
            findings.extend(self._check(path, module, lineno, version, pinned))
        return findings

    # -- shared --------------------------------------------------------------
    def _check(
        self,
        path: Path,
        name: str,
        line: int,
        spec: str,
        pinned: bool,
    ) -> list[Finding]:
        findings: list[Finding] = []
        reason = _DEPRECATED.get(_normalize_python(name)) or _DEPRECATED.get(
            name.lower()
        )
        if reason:
            findings.append(
                self._finding(
                    path,
                    line,
                    f"Deprecated or risky dependency: {name} ({reason}).",
                    Severity.HIGH,
                    "deprecated package",
                )
            )
        if not pinned:
            detail = f"unpinned constraint: {spec}" if spec else "no version constraint"
            findings.append(
                self._finding(
                    path,
                    line,
                    f"Dependency {name} is not pinned to an exact version.",
                    Severity.MEDIUM,
                    detail,
                )
            )
        return findings

    @staticmethod
    def _finding(
        path: Path, line: int, message: str, severity: Severity, detail: str
    ) -> Finding:
        return file_line_finding(
            kind=_KIND,
            severity=severity,
            message=message,
            path=path,
            line=line,
            detail=detail,
        )
