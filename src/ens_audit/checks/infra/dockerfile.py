"""Dockerfile / Containerfile configuration scanner (``infra.dockerfile``).

Flags container-build hygiene issues, each mapped to the ENS measure(s) it
concerns via the shared measure table:

* ``config.debug_enabled`` -- the image does not switch to a non-root ``USER``
  (insecure service configuration, ``op.exp.2``);
* ``dependency.outdated``  -- an unpinned / ``:latest`` base image or an ``ADD``
  of a remote URL (unverified supply-chain input, ``op.exp.4``/``op.exp.6``);
* ``secret.hardcoded``     -- a credential-looking literal in ``ENV``/``ARG``.

The rules are conservative line heuristics on purpose: a hit is a strong signal,
not a proof of exploitability.
"""

from __future__ import annotations

import re
from pathlib import Path

from ens_audit.checks.registry import register
from ens_audit.models import Finding, Severity

from ..base import Scanner, ScannerResult, finalize_scan
from ._common import file_line_finding, find_line, iter_files, read_text

__all__ = ["DockerfileScanner"]

# Rule kinds (keys into the ENS measure mapping).
_INSECURE_CONFIG = "config.debug_enabled"
_UNPINNED = "dependency.outdated"
_SECRET = "secret.hardcoded"

_SECRET_NAME = re.compile(
    r"(?i)(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|"
    r"PRIVATE[_-]?KEY|CREDENTIAL)"
)
_FROM = re.compile(
    r"(?im)^\s*FROM\s+(?P<image>\S+?)(?:\s+[Aa][Ss]\s+\S+)?"
    r"(?:\s+#.*)?\s*$"
)
_USER = re.compile(r"(?im)^\s*USER\s+(?P<user>\S+)")
_ENV_ARG = re.compile(
    r"(?im)^\s*(?:ENV|ARG)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*[=\s]\s*(?P<value>.+?)\s*$"
)
_ADD_REMOTE = re.compile(r"(?im)^\s*ADD\s+(?:--\S+\s+)*(?P<url>https?://\S+)")


def _is_dockerfile(path: Path) -> bool:
    """Whether ``path`` is a Dockerfile/Containerfile by conventional name."""
    name = path.name
    return (
        name in {"Dockerfile", "Containerfile"}
        or name.startswith("Dockerfile.")
        or name.endswith(".Dockerfile")
    )


def _is_pinned(image: str) -> bool:
    """Whether a ``FROM`` image is pinned to an immutable tag or digest."""
    if "@sha256:" in image:
        return True
    if image == "scratch":
        return True
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        tag = last.rsplit(":", 1)[1]
        return bool(tag) and tag.lower() != "latest"
    # No tag at all: floating reference.
    return False


def _is_literal(value: str) -> bool:
    """Whether an env/arg value is a literal (not a variable/placeholder)."""
    value = value.strip().strip("\"'")
    if not value or value.startswith("$"):
        return False
    return not (value.startswith("<") and value.endswith(">"))


def _line_of(text: str, match: re.Match[str]) -> int:
    """Return the 1-based line where ``match`` starts."""
    return text.count("\n", 0, match.start()) + 1


def _stage_bounds(text: str) -> list[tuple[int, int]]:
    """Return the ``(start, end)`` character offsets of each build stage.

    A Dockerfile is split into stages at every ``FROM`` instruction, so the
    last pair bounds the instructions that make up the final image. An empty
    list means the file has no ``FROM`` at all.
    """
    matches = list(_FROM.finditer(text))
    bounds: list[tuple[int, int]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        bounds.append((match.start(), end))
    return bounds


@register
class DockerfileScanner(Scanner):
    """Inspect Dockerfile/Containerfile build files for hardening issues."""

    id = "infra.dockerfile"
    description = (
        "Dockerfile/Containerfile hardening: root user, unpinned base images, "
        "hardcoded secrets and remote ADD."
    )
    category = "infra"
    covers = ("config.debug_enabled", "dependency.outdated", "secret.hardcoded")

    def run(self, target: Path) -> ScannerResult:
        findings: list[Finding] = []
        examined = 0
        for path in iter_files(target, _is_dockerfile):
            text = read_text(path)
            if text is None:
                continue
            examined += 1
            findings.extend(self._scan_file(path, text))
        return finalize_scan(
            self,
            target,
            findings,
            evaluated_kinds=self.covers,
            examined=examined,
            checked=(
                "Checked Dockerfiles for root user, unpinned base images, "
                "hardcoded secrets and remote ADD."
            ),
        )

    def _scan_file(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_user(path, text))
        findings.extend(self._check_base_images(path, text))
        findings.extend(self._check_secrets(path, text))
        findings.extend(self._check_remote_add(path, text))
        return findings

    def _check_user(self, path: Path, text: str) -> list[Finding]:
        # In a multi-stage build only the final stage's USER determines the
        # user the produced image runs as, so earlier stages are ignored.
        stages = _stage_bounds(text)
        final_stage_start = stages[-1][0] if stages else 0
        users = [
            match
            for match in _USER.finditer(text)
            if match.start() >= final_stage_start
        ]
        if not users:
            if stages:
                line = text.count("\n", 0, final_stage_start) + 1
            else:
                line = find_line(text, r"(?im)^\s*FROM\b")
            return [
                file_line_finding(
                    kind=_INSECURE_CONFIG,
                    severity=Severity.MEDIUM,
                    message=(
                        "Dockerfile runs as root: the final build stage has no "
                        "non-root USER instruction."
                    ),
                    path=path,
                    line=line,
                    detail="implicit user=root",
                )
            ]
        last = users[-1]
        # ``USER`` may carry an optional group (``root:root``), so compare only
        # the user component before the first colon.
        if last.group("user").split(":", 1)[0].lower() in {"root", "0"}:
            return [
                file_line_finding(
                    kind=_INSECURE_CONFIG,
                    severity=Severity.MEDIUM,
                    message="Dockerfile switches to the root USER.",
                    path=path,
                    line=_line_of(text, last),
                    detail=f"USER {last.group('user')}",
                )
            ]
        return []

    def _check_base_images(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _FROM.finditer(text):
            image = match.group("image")
            if _is_pinned(image):
                continue
            findings.append(
                file_line_finding(
                    kind=_UNPINNED,
                    severity=Severity.MEDIUM,
                    message=(
                        f"Base image {image!r} is not pinned to an immutable "
                        "tag or digest."
                    ),
                    path=path,
                    line=_line_of(text, match),
                    detail=f"FROM {image}",
                )
            )
        return findings

    def _check_secrets(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _ENV_ARG.finditer(text):
            name = match.group("name")
            if not _SECRET_NAME.search(name):
                continue
            if not _is_literal(match.group("value")):
                continue
            findings.append(
                file_line_finding(
                    kind=_SECRET,
                    severity=Severity.HIGH,
                    message=(
                        f"Credential-looking value hardcoded in {name}; use a "
                        "build secret or runtime injection instead."
                    ),
                    path=path,
                    line=_line_of(text, match),
                    detail=name,
                )
            )
        return findings

    def _check_remote_add(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _ADD_REMOTE.finditer(text):
            findings.append(
                file_line_finding(
                    kind=_UNPINNED,
                    severity=Severity.MEDIUM,
                    message=(
                        f"ADD fetches {match.group('url')} at build time without "
                        "integrity verification (supply-chain risk)."
                    ),
                    path=path,
                    line=_line_of(text, match),
                    detail="remote ADD",
                )
            )
        return findings
