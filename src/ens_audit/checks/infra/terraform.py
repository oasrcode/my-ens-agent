"""Terraform configuration scanner (``infra.terraform``).

Lightweight, line-oriented HCL heuristics (no Terraform toolchain required) for
the storage/network rules that matter to the ENS:

* public S3 buckets/ACLs and disabled public-access blocks
  (``network.service_exposed``);
* storage that is explicitly unencrypted, or an S3 bucket with no
  server-side-encryption configuration at all (``storage.unencrypted``);
* security-group ingress open to ``0.0.0.0/0`` / ``::/0``
  (``network.service_exposed``);
* S3 buckets with no access logging (``logging.audit_disabled``).

The rules are conservative: a hit is a strong signal, not a proof of exposure.
"""

from __future__ import annotations

import re
from pathlib import Path

from ens_audit.checks.registry import register
from ens_audit.models import Finding, Severity

from ..base import Scanner, ScannerResult, finalize_scan
from ._common import file_line_finding, find_line, iter_files, read_text

__all__ = ["TerraformScanner"]

# Rule kinds (keys into the ENS measure mapping).
_EXPOSED = "network.service_exposed"
_UNENCRYPTED = "storage.unencrypted"
_NO_LOGGING = "logging.audit_disabled"

_ANY_ADDRESS = re.compile(r"0\.0\.0\.0/0|::/0")
_PUBLIC_ACL = re.compile(
    r"(?i)\bacl\s*=\s*\"(?P<acl>public-read|public-read-write)\""
)
_PUBLIC_BLOCK_OFF = re.compile(
    r"(?i)\b(?:block_public_acls|block_public_policy|ignore_public_acls|"
    r"restrict_public_buckets)\s*=\s*false"
)
_ENCRYPTION_OFF = re.compile(
    r"(?i)\b(?:encrypted|storage_encrypted|encryption_at_rest)\s*=\s*false"
)
_S3_BUCKET = re.compile(r"(?i)\bresource\s+\"aws_s3_bucket\"")
_SECURITY_GROUP = re.compile(r"(?i)\bresource\s+\"aws_security_group\"")
_S3_ENCRYPTION = re.compile(r"(?i)server_side_encryption")
_S3_LOGGING = re.compile(r"(?i)aws_s3_bucket_logging|\blogging\b")

#: Per-kind description of what was checked, used for positive evidence.
_CHECKED: dict[str, str] = {
    _EXPOSED: "Checked Terraform security groups for ingress open to the internet.",
    _UNENCRYPTED: "Checked Terraform storage resources for encryption at rest.",
    _NO_LOGGING: "Checked S3 buckets for access logging configuration.",
}


def _is_terraform(path: Path) -> bool:
    """Whether ``path`` is a Terraform HCL file by suffix."""
    return path.suffix.lower() == ".tf"


@register
class TerraformScanner(Scanner):
    """Inspect Terraform files for insecure storage/network configuration."""

    id = "infra.terraform"
    description = (
        "Terraform hardening: public buckets, unencrypted storage, open "
        "security groups and missing access logging."
    )
    category = "infra"
    covers = (
        "network.service_exposed",
        "storage.unencrypted",
        "logging.audit_disabled",
    )

    def run(self, target: Path) -> ScannerResult:
        findings: list[Finding] = []
        examined = 0
        evaluated: list[str] = []
        for path in iter_files(target, _is_terraform):
            text = read_text(path)
            if text is None:
                continue
            examined += 1
            findings.extend(self._scan_file(path, text))
            for kind in self._evaluated_kinds(text):
                if kind not in evaluated:
                    evaluated.append(kind)
        return finalize_scan(
            self,
            target,
            findings,
            evaluated_kinds=evaluated,
            examined=examined,
            checked=_CHECKED,
        )

    @staticmethod
    def _evaluated_kinds(text: str) -> list[str]:
        """Return, in ``covers`` order, the kinds actually applied to ``text``.

        A kind is evaluated only when its relevant artifact is present: the
        network check needs a security group (a bucket alone is not a statement
        about the network perimeter), while the storage/logging checks need an
        S3 bucket or an explicit encryption setting.
        """
        kinds: list[str] = []
        if _SECURITY_GROUP.search(text) or _ANY_ADDRESS.search(text):
            kinds.append(_EXPOSED)
        if _S3_BUCKET.search(text) or _ENCRYPTION_OFF.search(text):
            kinds.append(_UNENCRYPTED)
        if _S3_BUCKET.search(text):
            kinds.append(_NO_LOGGING)
        return kinds

    def _scan_file(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _ANY_ADDRESS.search(line):
                findings.append(
                    file_line_finding(
                        kind=_EXPOSED,
                        severity=Severity.CRITICAL,
                        message="Security group/ingress allows traffic from 0.0.0.0/0.",
                        path=path,
                        line=lineno,
                        detail="open CIDR",
                    )
                )
            acl = _PUBLIC_ACL.search(line)
            if acl:
                findings.append(
                    file_line_finding(
                        kind=_EXPOSED,
                        severity=Severity.HIGH,
                        message=f"Storage/object ACL is public-read ({acl.group('acl')}).",
                        path=path,
                        line=lineno,
                        detail=acl.group("acl"),
                    )
                )
            if _PUBLIC_BLOCK_OFF.search(line):
                findings.append(
                    file_line_finding(
                        kind=_EXPOSED,
                        severity=Severity.HIGH,
                        message="S3 public-access block is explicitly disabled.",
                        path=path,
                        line=lineno,
                        detail="public access block disabled",
                    )
                )
            if _ENCRYPTION_OFF.search(line):
                findings.append(
                    file_line_finding(
                        kind=_UNENCRYPTED,
                        severity=Severity.HIGH,
                        message="Storage is explicitly configured as unencrypted.",
                        path=path,
                        line=lineno,
                        detail="encryption disabled",
                    )
                )

        findings.extend(self._check_s3_bucket(path, text))
        return findings

    def _check_s3_bucket(self, path: Path, text: str) -> list[Finding]:
        """File-level checks that need absence of a companion resource."""
        if not _S3_BUCKET.search(text):
            return []
        bucket_line = find_line(text, r'(?i)\bresource\s+"aws_s3_bucket"')
        findings: list[Finding] = []
        if not _S3_ENCRYPTION.search(text):
            findings.append(
                file_line_finding(
                    kind=_UNENCRYPTED,
                    severity=Severity.MEDIUM,
                    message="S3 bucket has no server-side encryption configuration.",
                    path=path,
                    line=bucket_line,
                    detail="missing server_side_encryption",
                )
            )
        if not _S3_LOGGING.search(text):
            findings.append(
                file_line_finding(
                    kind=_NO_LOGGING,
                    severity=Severity.LOW,
                    message="S3 bucket has no access logging configured.",
                    path=path,
                    line=bucket_line,
                    detail="missing bucket logging",
                )
            )
        return findings
