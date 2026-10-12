"""Web server configuration scanner (``infra.web``).

Inspects nginx/Apache configuration files for transport-security and header
issues:

* deprecated TLS protocols (TLS 1.0/1.1) and weak cipher suites
  (``crypto.weak_algorithm``);
* a missing HTTP Strict Transport Security header and plain HTTP listeners
  (``transport.tls_missing``);
* missing hardening headers (``X-Content-Type-Options``, ``Content-Security-
  Policy``, ``X-Frame-Options``) (``config.debug_enabled``).

Rules are line heuristics; a hit is a strong signal, not proof of exploitability.
"""

from __future__ import annotations

import re
from pathlib import Path

from ens_audit.checks.registry import register
from ens_audit.models import Finding, Severity

from ..base import Scanner, ScannerResult, finalize_scan
from ._common import file_line_finding, find_line, iter_files, read_text

__all__ = ["WebScanner"]

# Rule kinds (keys into the ENS measure mapping).
_WEAK_CRYPTO = "crypto.weak_algorithm"
_NO_TLS = "transport.tls_missing"
_INSECURE_CONFIG = "config.debug_enabled"

_WEB_MARKER = re.compile(
    r"(?i)(?:server\s*\{|server_name\b|<VirtualHost|SSLEngine|ssl_protocols|"
    r"listen\s+\d+|ProxyPass)"
)
_PROTOCOLS = re.compile(
    r"(?im)^[ \t]*(?:ssl_protocols|SSLProtocol)\s+(?P<value>.+?);?[ \t]*$"
)
_CIPHERS = re.compile(
    r"(?im)^[ \t]*(?:ssl_ciphers|SSLCipherSuite)\s+(?P<value>.+?);?[ \t]*$"
)
_PLAIN_HTTP = re.compile(r"(?im)^[ \t]*listen\s+80\b")
_TLS_LISTENER = re.compile(r"(?i)listen\s+443")
_HSTS = "Strict-Transport-Security"
_SECURITY_HEADERS = (
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "X-Frame-Options",
)
_WEAK_CIPHER_TOKEN = re.compile(
    r"(?i)\b(?:RC4|ARC4|3DES|DES|DES40|MD5|NULL|EXPORT|ANON|ADH|AECDH|"
    r"LOW|MEDIUM|SEED|IDEA|CAMELLIA|PSK|SRP)\b"
)

#: Per-kind description of what was checked, used for positive evidence.
_CHECKED: dict[str, str] = {
    _WEAK_CRYPTO: (
        "Checked web server TLS configuration for deprecated protocols and "
        "weak cipher suites."
    ),
    _NO_TLS: (
        "Checked web server transport for missing HSTS and plain HTTP listeners."
    ),
    _INSECURE_CONFIG: (
        "Checked web server responses for missing hardening security headers."
    ),
}


def _is_web_config(path: Path) -> bool:
    """Whether ``path`` is a web server configuration file by suffix/name."""
    name = path.name.lower()
    return path.suffix.lower() in {".conf", ".htaccess"} or name in {
        "nginx.conf",
        "apache2.conf",
        "httpd.conf",
    }


def _weak_protocols(value: str) -> bool:
    """Whether an ``ssl_protocols`` value enables deprecated TLS/SSL."""
    upper = value.upper()
    if any(token in upper for token in ("SSLV2", "SSLV3", "TLSV1.1", "TLSV1.0")):
        return True
    if re.search(r"TLSV1(?!\.)", upper):
        return True
    # Apache ``SSLProtocol all`` without explicitly disabling TLS 1.0/1.1.
    return "ALL" in upper and "TLSV1.2" not in upper


def _weak_ciphers(value: str) -> bool:
    """Whether a cipher-suite string includes a weak/broken algorithm."""
    cleaned = re.sub(r"!\S+", "", value)  # drop negated (!aNULL) tokens
    return bool(_WEAK_CIPHER_TOKEN.search(cleaned))


@register
class WebScanner(Scanner):
    """Inspect nginx/Apache configuration for TLS and header weaknesses."""

    id = "infra.web"
    description = (
        "Web server hardening: weak TLS protocols/ciphers, missing HSTS and "
        "security headers, plain HTTP listeners."
    )
    category = "infra"
    covers = ("crypto.weak_algorithm", "transport.tls_missing", "config.debug_enabled")

    def run(self, target: Path) -> ScannerResult:
        findings: list[Finding] = []
        examined = 0
        evaluated: list[str] = []
        for path in iter_files(target, _is_web_config):
            text = read_text(path)
            if text is None or not _WEB_MARKER.search(text):
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

        The TLS/crypto and HSTS/header checks only run against a TLS-enabled
        server (``ssl`` directive or a ``listen 443`` listener): certifying them
        on a plain-HTTP config would claim checks that never happened. A plain
        HTTP listener still exercises the transport check (and fails it), so the
        kind is reported without surviving measures.
        """
        has_tls = bool(re.search(r"(?i)ssl", text)) or bool(
            _TLS_LISTENER.search(text)
        )
        kinds: list[str] = []
        if has_tls:
            kinds.append(_WEAK_CRYPTO)
            kinds.append(_NO_TLS)
            kinds.append(_INSECURE_CONFIG)
        elif _PLAIN_HTTP.search(text):
            kinds.append(_NO_TLS)
        return kinds

    def _scan_file(self, path: Path, text: str) -> list[Finding]:
        findings: list[Finding] = []
        has_tls = bool(re.search(r"(?i)ssl", text)) or bool(
            _TLS_LISTENER.search(text)
        )

        for match in _PROTOCOLS.finditer(text):
            if _weak_protocols(match.group("value")):
                findings.append(
                    file_line_finding(
                        kind=_WEAK_CRYPTO,
                        severity=Severity.HIGH,
                        message=(
                            "Deprecated TLS protocol enabled "
                            f"({match.group('value').strip()})."
                        ),
                        path=path,
                        line=_line_of(text, match),
                        detail="weak TLS protocol",
                    )
                )

        for match in _CIPHERS.finditer(text):
            if _weak_ciphers(match.group("value")):
                findings.append(
                    file_line_finding(
                        kind=_WEAK_CRYPTO,
                        severity=Severity.HIGH,
                        message="Weak or broken cipher suite enabled.",
                        path=path,
                        line=_line_of(text, match),
                        detail="weak cipher suite",
                    )
                )

        if has_tls and _HSTS not in text:
            findings.append(
                file_line_finding(
                    kind=_NO_TLS,
                    severity=Severity.MEDIUM,
                    message="No HTTP Strict Transport Security (HSTS) header set.",
                    path=path,
                    line=_tls_line(text),
                    detail="missing HSTS",
                )
            )

        if has_tls:
            missing = [h for h in _SECURITY_HEADERS if h not in text]
            if missing:
                findings.append(
                    file_line_finding(
                        kind=_INSECURE_CONFIG,
                        severity=Severity.LOW,
                        message=(
                            "Missing security header(s): " + ", ".join(missing) + "."
                        ),
                        path=path,
                        line=_tls_line(text),
                        detail="missing headers",
                    )
                )

        if _PLAIN_HTTP.search(text) and not _TLS_LISTENER.search(text):
            findings.append(
                file_line_finding(
                    kind=_NO_TLS,
                    severity=Severity.HIGH,
                    message="Plain HTTP listener without a matching TLS listener.",
                    path=path,
                    line=find_line(text, r"(?im)^[ \t]*listen\s+80\b"),
                    detail="plain HTTP",
                )
            )
        return findings


def _line_of(text: str, match: re.Match[str]) -> int:
    """Return the 1-based line where ``match`` starts."""
    return text.count("\n", 0, match.start()) + 1


def _tls_line(text: str) -> int:
    """Best-effort line for a TLS/header finding (first TLS-related line)."""
    line = find_line(text, r"(?im)^[ \t]*(?:ssl_protocols|ssl_ciphers|listen\s+443)")
    return line or find_line(text, r"(?im)^[ \t]*(?:server\s*\{|<VirtualHost)")
