"""Weak-cryptography scanner (rule families ``crypto.weak_algorithm`` and
``transport.tls_missing``).

Flags common misuse of cryptography in application code:

* weak hashes (MD5, SHA-1) — often used for password storage or signatures;
* broken or deprecated ciphers/modes (DES, RC4, ECB);
* disabled TLS peer verification (and equivalent escape hatches);
* literal ``http://`` endpoints (local/development hosts are ignored);
* hardcoded IVs / salts / encryption keys.

The rules are regex heuristics over source lines: they identify risky *usage*
patterns, not proof of exploitability.
"""

from __future__ import annotations

import re
from pathlib import Path

from ens_audit.checks.registry import register
from ens_audit.models import Finding, Severity

from ..base import Scanner
from ._common import file_line_finding, iter_source_files, read_text

__all__ = ["CryptoScanner"]

_WEAK_ALGO = "crypto.weak_algorithm"
_NO_TLS = "transport.tls_missing"

# Weak hashes in the usual call shapes across languages.
_WEAK_HASH = re.compile(
    r"(?i)(?:"
    r"\bhashlib\.(?:md5|sha1)\s*\("
    r"|(?<![\w.])(?:md5|sha1)\s*\("
    r"|getInstance\s*\(\s*[\"'](?:MD5|SHA-?1)[\"']"
    r"|createHash\s*\(\s*[\"'](?:md5|sha1)[\"']"
    r")"
)
# Broken / deprecated ciphers and modes.
_WEAK_CIPHER = re.compile(
    r"(?i)(?:"
    r"\bDES\b|\b3DES\b|\bRC4\b|\bARC4\b|\bBlowfish\b"
    r"|\bECB\b|MODE_ECB"
    r"|getInstance\s*\(\s*[\"'](?:DES|RC4)"
    r"|createCipheriv\s*\(\s*[\"'](?:des|rc4|aes-\d+-ecb)"
    r")"
)
# TLS peer verification switched off (Python/Go/Node/cURL).
_TLS_VERIFY_OFF = re.compile(
    r"(?i)(?:"
    r"verify\s*=\s*False"
    r"|ssl_verify\s*=\s*False"
    r"|InsecureSkipVerify\s*[:=]\s*true"
    r"|rejectUnauthorized\s*[:=]\s*false"
    r"|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*[\"']?0"
    r"|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|false)"
    r")"
)
_HTTP_URL = re.compile(r"[\"']http://(?P<host>[^/\"'\s]+)")
# Hosts that are acceptable over plain HTTP (local development, XML namespaces).
_HTTP_ALLOWLIST = re.compile(
    r"(?i)^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|example\.(?:com|org|net)|"
    r"schemas\.|www\.w3\.org|xmlns\.|purl\.org|ns\.adobe\.com)"
)
_LOCAL_HOST = re.compile(r"(?i)(?:\.local|\.internal|\.localhost)$")

# Hardcoded IVs/salts and encryption keys assigned to a literal.
_HARDCODED_IV = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:iv|initialization[_-]?vector|nonce|salt)"
    r"(?![A-Za-z0-9])\s*[:=]\s*b?[\"'][^\"'\n]{4,}[\"']"
)
_HARDCODED_KEY = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:secret[_-]?key|encryption[_-]?key|aes[_-]?key|"
    r"cipher[_-]?key|private[_-]?key)(?![A-Za-z0-9])\s*[:=]\s*b?[\"'][^\"'\n]{6,}[\"']"
)


@register
class CryptoScanner(Scanner):
    """Detect weak algorithms, disabled TLS verification and hardcoded key material."""

    id = "code.crypto"
    description = "Detect weak crypto, disabled TLS verification and hardcoded keys."
    category = "code"

    def run(self, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_source_files(target):
            text = read_text(path)
            if text is None:
                continue
            findings.extend(self._scan_file(path, text))
        return findings

    def _scan_file(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _WEAK_HASH.search(line):
                findings.append(
                    self._finding(
                        _WEAK_ALGO,
                        path,
                        lineno,
                        "Weak hash algorithm (MD5/SHA-1) in use.",
                        Severity.MEDIUM,
                        "weak hash",
                    )
                )
            if _WEAK_CIPHER.search(line):
                findings.append(
                    self._finding(
                        _WEAK_ALGO,
                        path,
                        lineno,
                        "Broken or deprecated cipher/mode (DES/RC4/ECB).",
                        Severity.HIGH,
                        "weak cipher",
                    )
                )
            if _TLS_VERIFY_OFF.search(line):
                findings.append(
                    self._finding(
                        _WEAK_ALGO,
                        path,
                        lineno,
                        "TLS peer verification is disabled.",
                        Severity.HIGH,
                        "tls verification disabled",
                    )
                )
            for match in _HTTP_URL.finditer(line):
                host = match.group("host")
                if _HTTP_ALLOWLIST.match(host) or _LOCAL_HOST.search(host):
                    continue
                findings.append(
                    self._finding(
                        _NO_TLS,
                        path,
                        lineno,
                        f"Literal unencrypted http:// endpoint ({host}).",
                        Severity.MEDIUM,
                        "http endpoint",
                    )
                )
            if _HARDCODED_IV.search(line):
                findings.append(
                    self._finding(
                        _WEAK_ALGO,
                        path,
                        lineno,
                        "Hardcoded IV/salt/nonce.",
                        Severity.HIGH,
                        "hardcoded iv",
                    )
                )
            if _HARDCODED_KEY.search(line):
                findings.append(
                    self._finding(
                        _WEAK_ALGO,
                        path,
                        lineno,
                        "Hardcoded encryption key material.",
                        Severity.HIGH,
                        "hardcoded key",
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
