"""Finding-kind to ENS-measure mapping.

Deterministic scanners emit findings with a stable ``kind`` (a rule id). This
module translates that kind into the ENS measure(s) of RD 311/2022 (Anexo II)
the finding concerns, plus the CCN-STIC guide(s) that give the technical
verification criteria.

The table is data-driven: add a new rule by adding one entry to
:data:`MEASURE_MAP`. Every measure code is validated against the loaded catalog
by :func:`validate_mapping`, so drift is caught by the test suite.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ens_audit.catalog.models import Catalog

__all__ = [
    "MEASURE_MAP",
    "MeasureRef",
    "covered_measures",
    "known_kinds",
    "measures_for",
    "validate_mapping",
]


class MeasureRef(BaseModel):
    """A reference from a rule kind to one ENS measure and its rationale."""

    code: str
    rationale: str
    #: Relevant CCN-STIC guide ids, e.g. ``"CCN-STIC-807"``.
    guides: list[str] = Field(default_factory=list)


#: Rule kind -> the ENS measures it concerns. Keys are stable rule ids emitted
#: by the (future) real scanners; the test suite only uses this table directly.
MEASURE_MAP: dict[str, list[MeasureRef]] = {
    "secret.hardcoded": [
        MeasureRef(
            code="op.exp.10",
            rationale=(
                "Hardcoded credentials expose cryptographic keys and secrets, "
                "which must be protected for their whole life cycle."
            ),
            guides=["CCN-STIC-807"],
        ),
        MeasureRef(
            code="mp.si.2",
            rationale="Secrets at rest must be protected with approved cryptography.",
            guides=["CCN-STIC-807"],
        ),
    ],
    "crypto.weak_algorithm": [
        MeasureRef(
            code="mp.si.2",
            rationale=(
                "Weak or deprecated algorithms fall below the strength required "
                "by ENS cryptography rules."
            ),
            guides=["CCN-STIC-807"],
        ),
        MeasureRef(
            code="mp.com.2",
            rationale=(
                "Weak transport cryptography fails to protect the "
                "confidentiality of communications."
            ),
            guides=["CCN-STIC-807"],
        ),
    ],
    "injection.sql": [
        MeasureRef(
            code="mp.sw.1",
            rationale=(
                "Unsanitised input leading to SQL injection is a secure "
                "development defect."
            ),
            guides=["CCN-STIC-812"],
        ),
    ],
    "injection.command": [
        MeasureRef(
            code="mp.sw.1",
            rationale=(
                "Command injection is a secure development defect in the "
                "application lifecycle."
            ),
            guides=["CCN-STIC-812"],
        ),
    ],
    "transport.tls_missing": [
        MeasureRef(
            code="mp.com.2",
            rationale=(
                "Unencrypted traffic does not protect the confidentiality of "
                "information in transit."
            ),
            guides=["CCN-STIC-807"],
        ),
        MeasureRef(
            code="mp.com.3",
            rationale=(
                "Without TLS neither integrity nor authenticity of the "
                "communication can be assured."
            ),
            guides=["CCN-STIC-807"],
        ),
    ],
    "config.debug_enabled": [
        MeasureRef(
            code="op.exp.2",
            rationale=(
                "Debug mode in production is an insecure configuration of the "
                "information system."
            ),
            guides=["CCN-STIC-808", "CCN-STIC-812"],
        ),
    ],
    "dependency.outdated": [
        MeasureRef(
            code="op.exp.4",
            rationale=(
                "Unpatched dependencies miss security updates that must be "
                "applied to the system."
            ),
            guides=["CCN-STIC-808"],
        ),
        MeasureRef(
            code="op.exp.6",
            rationale=(
                "Known-vulnerable components raise the risk of malicious code "
                "exploitation."
            ),
            guides=["CCN-STIC-808"],
        ),
    ],
    "logging.audit_disabled": [
        MeasureRef(
            code="op.exp.8",
            rationale=(
                "Without activity logging, traceability of security-relevant "
                "events is lost."
            ),
            guides=["CCN-STIC-808", "CCN-STIC-817"],
        ),
    ],
    "network.service_exposed": [
        MeasureRef(
            code="mp.com.1",
            rationale=(
                "An unnecessarily exposed service weakens the secure perimeter "
                "of the system."
            ),
            guides=["CCN-STIC-811"],
        ),
        MeasureRef(
            code="mp.s.4",
            rationale=(
                "Exposed services increase the attack surface for "
                "denial-of-service attempts."
            ),
            guides=["CCN-STIC-820"],
        ),
    ],
    "storage.unencrypted": [
        MeasureRef(
            code="mp.si.2",
            rationale=(
                "Information at rest must be protected with approved "
                "cryptographic mechanisms."
            ),
            guides=["CCN-STIC-807"],
        ),
    ],
    "backup.disabled": [
        MeasureRef(
            code="mp.info.6",
            rationale=(
                "Backups must exist and be retained: a disabled backup or a "
                "zero retention leaves the information unrecoverable."
            ),
            guides=["CCN-STIC-807"],
        ),
    ],
    # -- external (verified) scanner kinds ------------------------------------
    # These are emitted by the optional third-party tools of
    # ``ens_audit.checks.external``. They are *verified* observations, but a
    # detected vulnerability or misconfiguration is a risk signal, not proof of
    # an ENS breach: the findings stay non-demonstrative (demonstrates=False)
    # and cap the mapped measures at ``parcial``.
    "vuln.dependency": [
        MeasureRef(
            code="op.exp.4",
            rationale=(
                "A dependency with a known vulnerability is missing the security "
                "updates that maintenance must apply."
            ),
            guides=["CCN-STIC-808"],
        ),
        MeasureRef(
            code="op.exp.6",
            rationale=(
                "A known-vulnerable dependency is a vector for malicious code "
                "exploitation."
            ),
            guides=["CCN-STIC-808"],
        ),
        MeasureRef(
            code="op.ext.3",
            rationale=(
                "Third-party components are part of the supply chain that must "
                "be protected."
            ),
            guides=["CCN-STIC-808"],
        ),
    ],
    "container.vuln": [
        MeasureRef(
            code="op.exp.4",
            rationale=(
                "A container image or packaged component with a known "
                "vulnerability misses the security updates maintenance must apply."
            ),
            guides=["CCN-STIC-808"],
        ),
        MeasureRef(
            code="op.exp.6",
            rationale=(
                "A vulnerable image component can carry malicious code into the "
                "running system."
            ),
            guides=["CCN-STIC-808"],
        ),
        MeasureRef(
            code="op.ext.3",
            rationale=(
                "Base images and their packages are part of the supply chain that "
                "must be protected."
            ),
            guides=["CCN-STIC-808"],
        ),
    ],
    "sast.finding": [
        MeasureRef(
            code="mp.sw.1",
            rationale=(
                "A static-analysis finding is a secure-development defect in the "
                "application lifecycle."
            ),
            guides=["CCN-STIC-812"],
        ),
        MeasureRef(
            code="mp.sw.2",
            rationale=(
                "Defects that survive to the acceptance test should have been "
                "caught before putting the service into operation."
            ),
            guides=["CCN-STIC-812"],
        ),
    ],
    "iac.misconfig": [
        MeasureRef(
            code="op.exp.2",
            rationale=(
                "An infrastructure-as-code misconfiguration is an insecure "
                "configuration of the information system."
            ),
            guides=["CCN-STIC-808", "CCN-STIC-812"],
        ),
        MeasureRef(
            code="op.exp.3",
            rationale=(
                "Configuration must be managed and hardened: a detected "
                "misconfiguration is a configuration-management defect."
            ),
            guides=["CCN-STIC-808"],
        ),
    ],
}


def measures_for(kind: str) -> list[MeasureRef]:
    """Return the measure references mapped to ``kind``.

    Unknown kinds return an empty list (a scanner may emit informational
    findings that concern no specific measure). The returned list is a copy.
    """
    return list(MEASURE_MAP.get(kind, []))


def known_kinds() -> list[str]:
    """Return all rule kinds present in the mapping table."""
    return list(MEASURE_MAP)


def covered_measures() -> set[str]:
    """Return every measure code reachable from any rule kind in the table.

    This is the total coverage the deterministic scanners can speak to: the
    union of :func:`measures_for` over all rule kinds. It is the single source
    of truth a caller should use to reason about scanner coverage.
    """
    return {ref.code for refs in MEASURE_MAP.values() for ref in refs}


def validate_mapping(catalog: Catalog) -> dict[str, list[str]]:
    """Return the mapping entries whose measure codes are absent from ``catalog``.

    The result maps each offending rule kind to the unknown measure codes, so an
    empty dict means the whole table validates.
    """
    unknown: dict[str, list[str]] = {}
    for kind, refs in MEASURE_MAP.items():
        missing = [ref.code for ref in refs if ref.code not in catalog.medidas]
        if missing:
            unknown[kind] = missing
    return unknown
