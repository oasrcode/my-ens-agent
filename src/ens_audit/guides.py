"""Built-in registry of CCN-STIC guides relevant to ENS auditing.

The ENS (RD 311/2022) is verified through the CCN-STIC series 800 guides, which
provide the technical criteria an auditor uses to evidence compliance. This
module encodes a small, curated subset of those guides as data, sourced from
``docs/research/ens-catalog.md`` section 3.

Each :class:`Guide` records its official ``id`` (e.g. ``"CCN-STIC-807"``), the
official Spanish ``title``, a short English ``purpose`` and the ENS measure
codes it helps to evidence. Guides that apply transversally (e.g. the audit
process itself) carry an empty ``measures`` list.

The registry is deliberately data-only: it has no dependency on the catalog or
the audit domain, so both the server and the tests can consume it cheaply.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

__all__ = ["GUIDES", "Guide", "get_guide", "guides_for_measure", "list_guides"]


class Guide(BaseModel):
    """A CCN-STIC guide and the ENS measures it helps to evidence."""

    id: str = Field(description="Official guide id, e.g. 'CCN-STIC-807'.")
    title: str = Field(description="Official Spanish title of the guide.")
    purpose: str = Field(description="Short English description of what it is for.")
    measures: list[str] = Field(
        default_factory=list,
        description="ENS measure codes the guide helps to evidence (empty = transversal).",
    )


#: Curated CCN-STIC registry (docs/research/ens-catalog.md section 3), keyed by id.
GUIDES: dict[str, Guide] = {
    "CCN-STIC-800": Guide(
        id="CCN-STIC-800",
        title="Glosario de términos (ENS)",
        purpose="Common ENS terminology.",
    ),
    "CCN-STIC-801": Guide(
        id="CCN-STIC-801",
        title="Responsabilidades y funciones en el ENS",
        purpose="Governance model and information/service/security/system roles.",
        measures=["org.1", "org.2", "org.3", "org.4"],
    ),
    "CCN-STIC-802": Guide(
        id="CCN-STIC-802",
        title="Auditoría en el ENS",
        purpose="ENS audit process: team, phases and impartiality (Anexo III).",
    ),
    "CCN-STIC-803": Guide(
        id="CCN-STIC-803",
        title="Valoración de Sistemas en el ENS (MAGERIT)",
        purpose="System categorization and valuation of dimensions and levels (Anexo I).",
        measures=["op.pl.1"],
    ),
    "CCN-STIC-804": Guide(
        id="CCN-STIC-804",
        title="ENS. Medidas de implantación (Guía de Implantación)",
        purpose="How to implement each measure; maturity model L0-L5.",
    ),
    "CCN-STIC-805": Guide(
        id="CCN-STIC-805",
        title="Política de Seguridad de la Información",
        purpose="Drafting and approving the security policy.",
        measures=["org.1"],
    ),
    "CCN-STIC-806": Guide(
        id="CCN-STIC-806",
        title="Plan de Adecuación al ENS",
        purpose="ENS compliance roadmap and the initial applicability declaration.",
        measures=["org.1", "org.2", "org.3", "org.4"],
    ),
    "CCN-STIC-807": Guide(
        id="CCN-STIC-807",
        title="Criptología de empleo en el ENS",
        purpose=(
            "Authorised cryptographic mechanisms and key strength "
            "(>=112 bits; RSA >=2048, ECC 224-255, SHA-256+)."
        ),
        measures=[
            "mp.si.2",
            "mp.com.2",
            "mp.com.3",
            "mp.info.3",
            "mp.info.4",
            "op.exp.10",
        ],
    ),
    "CCN-STIC-808": Guide(
        id="CCN-STIC-808",
        title="Verificación del cumplimiento de las medidas en el ENS",
        purpose="Measure-by-measure audit checklist and scoring.",
    ),
    "CCN-STIC-809": Guide(
        id="CCN-STIC-809",
        title=(
            "Declaración, certificación y aprobación provisional de "
            "conformidad y distintivos"
        ),
        purpose="Declaration, certification and conformance badges.",
        measures=["org.1", "org.2", "org.3", "org.4"],
    ),
    "CCN-STIC-811": Guide(
        id="CCN-STIC-811",
        title="Interconexión en el ENS",
        purpose="Secure interconnection of systems.",
        measures=["op.ext.4", "mp.com.1"],
    ),
    "CCN-STIC-812": Guide(
        id="CCN-STIC-812",
        title="Seguridad en Entornos y Aplicaciones web",
        purpose="Web hardening and secure development.",
        measures=["mp.s.2", "mp.sw.1", "mp.sw.2"],
    ),
    "CCN-STIC-813": Guide(
        id="CCN-STIC-813",
        title="Componentes certificados en el ENS",
        purpose="Use of certified products.",
        measures=["op.pl.5"],
    ),
    "CCN-STIC-814": Guide(
        id="CCN-STIC-814",
        title="Seguridad en servicio de correo",
        purpose="Secure mail service configuration.",
        measures=["mp.s.1"],
    ),
    "CCN-STIC-815": Guide(
        id="CCN-STIC-815",
        title="Indicadores y métricas en el ENS",
        purpose="Security indicators and metrics.",
        measures=["op.mon.2"],
    ),
    "CCN-STIC-816": Guide(
        id="CCN-STIC-816",
        title="Seguridad en Redes Inalámbricas en el ENS",
        purpose="Secure wireless networks.",
        measures=["mp.com.1", "mp.com.2", "mp.com.3", "mp.com.4"],
    ),
    "CCN-STIC-817": Guide(
        id="CCN-STIC-817",
        title="Gestión de Ciberincidentes",
        purpose="Incident management and response.",
        measures=["op.exp.7", "op.exp.9", "op.mon.1", "op.mon.2", "op.mon.3"],
    ),
    "CCN-STIC-818": Guide(
        id="CCN-STIC-818",
        title="Herramientas de Seguridad en el ENS",
        purpose="Supporting security tools.",
    ),
    "CCN-STIC-819": Guide(
        id="CCN-STIC-819",
        title="Medidas Compensatorias",
        purpose="Justifying alternative/compensating measures (art. 28.3).",
    ),
    "CCN-STIC-820": Guide(
        id="CCN-STIC-820",
        title="Protección contra DoS",
        purpose="Denial-of-service protection.",
        measures=["mp.s.4"],
    ),
    "CCN-STIC-821": Guide(
        id="CCN-STIC-821",
        title="Normas de Seguridad en el ENS",
        purpose="Drafting the security norms.",
        measures=["org.2"],
    ),
    "CCN-STIC-822": Guide(
        id="CCN-STIC-822",
        title="Procedimientos de Seguridad en el ENS",
        purpose="Operational security procedures.",
        measures=["org.3"],
    ),
    "CCN-STIC-823": Guide(
        id="CCN-STIC-823",
        title="Utilización de Servicios en la Nube",
        purpose="Requirements for contracting cloud services (IaaS/PaaS/SaaS).",
        measures=["op.nub.1", "op.ext.1", "op.ext.2", "op.ext.3", "op.ext.4"],
    ),
    "CCN-STIC-824": Guide(
        id="CCN-STIC-824",
        title="Informe del Estado de Seguridad",
        purpose="Annual security state report data and guidance (INES, art. 32).",
        measures=["op.mon.2"],
    ),
    "CCN-STIC-825": Guide(
        id="CCN-STIC-825",
        title="ENS - ISO/IEC 27001 (mapeo, ISO 27001:2022)",
        purpose="Mapping between ENS measures and ISO 27001 controls.",
    ),
    "CCN-STIC-830": Guide(
        id="CCN-STIC-830",
        title="Ámbito de aplicación del ENS",
        purpose="Subjective and objective scope of the ENS.",
    ),
    "CCN-STIC-844": Guide(
        id="CCN-STIC-844",
        title="Manual de usuario de la herramienta INES",
        purpose="Operating the INES tool.",
    ),
    "CCN-STIC-858": Guide(
        id="CCN-STIC-858",
        title="Implantación de sistemas SaaS en modo local (on-premise)",
        purpose="Local/on-premise SaaS deployment.",
        measures=["op.nub.1"],
    ),
    "CCN-STIC-881": Guide(
        id="CCN-STIC-881",
        title="Perfil de cumplimiento: Universidades",
        purpose="Sector-specific compliance profile (art. 30).",
    ),
    "CCN-STIC-891": Guide(
        id="CCN-STIC-891",
        title="Perfil de cumplimiento: sector Salud",
        purpose="Sector-specific compliance profile (art. 30).",
    ),
}


def get_guide(guide_id: str) -> Guide | None:
    """Return the guide registered under ``guide_id``, or ``None``."""
    return GUIDES.get(guide_id)


def list_guides() -> list[Guide]:
    """Return every registered guide in registry order."""
    return list(GUIDES.values())


def guides_for_measure(code: str) -> list[Guide]:
    """Return the guides whose ``measures`` list contains ``code``."""
    return [guide for guide in GUIDES.values() if code in guide.measures]
