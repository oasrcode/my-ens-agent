"""Pydantic v2 data model for the ENS catalog (RD 311/2022, Anexo II).

These models mirror the structure of the official OSCAL catalog published by the
AEAD: a hierarchy of ``groups`` (marco -> familia) containing ``controls``
(medidas), each optionally nesting ``controls`` of class ``ens-refuerzo``.

This module is intentionally self-contained: it must not import from
``ens_audit.models`` (audit domain) to keep the two model layers decoupled.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

# OSCAL property namespace used by the AEAD ENS catalog.
ENS_NS = "urn:es:ens"


class Dimension(str, Enum):
    """Security dimension defined by the ENS (Anexo I)."""

    CONFIDENCIALIDAD = "Confidencialidad"
    INTEGRIDAD = "Integridad"
    DISPONIBILIDAD = "Disponibilidad"
    AUTENTICIDAD = "Autenticidad"
    TRAZABILIDAD = "Trazabilidad"


class Nivel(str, Enum):
    """Security level a dimension can be valued at."""

    BAJO = "BAJO"
    MEDIO = "MEDIO"
    ALTO = "ALTO"


class Categoria(str, Enum):
    """Overall system category derived from the valued dimensions."""

    BASICA = "BASICA"
    MEDIA = "MEDIA"
    ALTA = "ALTA"


class AplicacionPor(str, Enum):
    """How a measure's enforceability is determined."""

    CATEGORIA = "categoria"
    NIVEL_DIMENSION = "nivel-dimension"


# Ordinal ranking used to compare levels and categories.
NIVEL_RANK: dict[Nivel, int] = {Nivel.BAJO: 0, Nivel.MEDIO: 1, Nivel.ALTO: 2}
CATEGORIA_RANK: dict[Categoria, int] = {
    Categoria.BASICA: 0,
    Categoria.MEDIA: 1,
    Categoria.ALTA: 2,
}


class Requisito(BaseModel):
    """A single literal requirement item of a measure or refuerzo."""

    id: str
    label: str | None = None
    texto: str


class SeleccionRefuerzo(BaseModel):
    """A mutually-exclusive refuerzo selection group declared on a measure.

    Encoded in the source as an OSCAL ``param`` of type ``seleccion-refuerzo``
    with ``select.how-many == "one"``, scoped to a category or a level.
    """

    categoria: Categoria | None = None
    nivel: Nivel | None = None
    opciones: list[str] = Field(default_factory=list)


class Refuerzo(BaseModel):
    """An ENS refuerzo (reinforcement) attached to a base measure."""

    id: str
    order: int
    nombre: str = ""
    # True when the source declares neither activation category nor level:
    # such refuerzos are not automatically enforced (Anexo II, apdo. 5.e).
    opcional: bool = False
    # Categories at which the refuerzo is explicitly activated.
    categorias: list[Categoria] = Field(default_factory=list)
    # Levels at which the refuerzo is explicitly activated.
    niveles: list[Nivel] = Field(default_factory=list)
    # Dimensions the refuerzo concerns (informational scope).
    dimensiones: list[Dimension] = Field(default_factory=list)
    # Other refuerzos mutually exclusive with this one (from selection params).
    alternativas: list[str] = Field(default_factory=list)
    requisitos: list[Requisito] = Field(default_factory=list)


class Medida(BaseModel):
    """A base security measure (control) from Anexo II."""

    code: str
    name: str
    # Top-level marco id: "org", "op" or "mp".
    marco: str
    # Family id, e.g. "op.pl"; equals the marco id for the organizational marco.
    familia: str
    familia_nombre: str = ""
    dimensiones: list[Dimension] = Field(default_factory=list)
    aplicacion_por: AplicacionPor
    # For `categoria` measures: categories in which the measure applies.
    categorias: list[Categoria] = Field(default_factory=list)
    # For `nivel-dimension`: levels whose threshold activates the measure.
    niveles: list[Nivel] = Field(default_factory=list)
    requisitos: list[Requisito] = Field(default_factory=list)
    refuerzos: list[Refuerzo] = Field(default_factory=list)
    seleccion: list[SeleccionRefuerzo] = Field(default_factory=list)


class Catalog(BaseModel):
    """The parsed ENS catalog plus its provenance metadata."""

    norma: str
    titulo: str
    uuid: str
    version: str
    oscal_version: str
    last_modified: str
    fuente: str
    licencia: str
    medidas: dict[str, Medida] = Field(default_factory=dict)

    def measure_codes(self) -> list[str]:
        """Return all measure codes in catalog order."""
        return list(self.medidas)
