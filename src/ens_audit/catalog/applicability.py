"""ENS applicability engine.

Given the valued security dimensions of a system, this module derives the
overall :class:`~ens_audit.catalog.models.Categoria` and selects the applicable
measures plus the refuerzos they activate, honouring the two applicability
modes declared by Anexo II:

* ``por_categoria`` -- the measure applies in the listed categories.
* ``por_dimension_nivel`` -- the measure applies when any of its dimensions
  reaches the listed level threshold.
"""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel, Field

from .models import (
    NIVEL_RANK,
    AplicacionPor,
    Catalog,
    Categoria,
    Dimension,
    Medida,
    Nivel,
    Refuerzo,
)


class MedidaAplicable(BaseModel):
    """An applicable measure together with its activated refuerzos."""

    medida: Medida
    refuerzos: list[Refuerzo] = Field(default_factory=list)


class ApplicabilityResult(BaseModel):
    """Outcome of computing applicability for a set of dimension levels."""

    categoria: Categoria
    medidas: list[MedidaAplicable] = Field(default_factory=list)

    def measure_codes(self) -> list[str]:
        """Return the codes of all applicable measures."""
        return [m.medida.code for m in self.medidas]


def derive_categoria(levels: Mapping[Dimension, Nivel]) -> Categoria:
    """Derive the overall category from the valued dimensions (Anexo I).

    ALTA if any dimension is ALTA; MEDIA if any is MEDIA and none is ALTA;
    BASICA otherwise.
    """
    values = list(levels.values())
    if any(value is Nivel.ALTO for value in values):
        return Categoria.ALTA
    if any(value is Nivel.MEDIO for value in values):
        return Categoria.MEDIA
    return Categoria.BASICA


def _max_nivel(
    levels: Mapping[Dimension, Nivel],
    dimensions: list[Dimension],
) -> Nivel | None:
    """Highest level reached among the given dimensions, if any is present."""
    present = [levels[d] for d in dimensions if d in levels]
    if not present:
        return None
    return max(present, key=lambda nivel: NIVEL_RANK[nivel])


def _threshold(niveles: list[Nivel]) -> Nivel:
    """Lowest level in the given list (the activation threshold)."""
    return min(niveles, key=lambda nivel: NIVEL_RANK[nivel])


def _medida_applies(
    medida: Medida,
    categoria: Categoria,
    levels: Mapping[Dimension, Nivel],
) -> bool:
    """Whether a base measure is applicable for the given category/levels."""
    if medida.aplicacion_por is AplicacionPor.CATEGORIA:
        return categoria in medida.categorias
    if not medida.niveles:
        return False
    effective = _max_nivel(levels, medida.dimensiones)
    if effective is None:
        return False
    return NIVEL_RANK[effective] >= NIVEL_RANK[_threshold(medida.niveles)]


def _activated_refuerzos(
    medida: Medida,
    categoria: Categoria,
    levels: Mapping[Dimension, Nivel],
) -> list[Refuerzo]:
    """Return the refuerzos activated for an applicable measure."""
    activated: list[Refuerzo] = []
    for refuerzo in medida.refuerzos:
        if refuerzo.opcional:
            continue
        if _refuerzo_active(refuerzo, medida, categoria, levels):
            activated.append(refuerzo)
    return activated


def _refuerzo_active(
    refuerzo: Refuerzo,
    medida: Medida,
    categoria: Categoria,
    levels: Mapping[Dimension, Nivel],
) -> bool:
    """Evaluate a single refuerzo's activation conditions."""
    if refuerzo.categorias and categoria in refuerzo.categorias:
        return True
    if refuerzo.niveles:
        effective = _max_nivel(
            levels, refuerzo.dimensiones or medida.dimensiones
        )
        if effective is not None and (
            NIVEL_RANK[effective] >= NIVEL_RANK[_threshold(refuerzo.niveles)]
        ):
            return True
    # Mutually-exclusive selection groups (exact scope match).
    for group in medida.seleccion:
        if refuerzo.id not in group.opciones:
            continue
        if group.categoria is not None and categoria == group.categoria:
            return True
        if group.nivel is not None:
            effective = _max_nivel(levels, medida.dimensiones)
            if effective == group.nivel:
                return True
    return False


def compute_applicability(
    catalog: Catalog,
    levels: Mapping[Dimension, Nivel],
    categoria: Categoria | None = None,
) -> ApplicabilityResult:
    """Compute applicable measures and activated refuerzos for ``levels``.

    :param catalog: parsed ENS catalog.
    :param levels: mapping of each security dimension to its valued level.
    :param categoria: optional override; derived from ``levels`` when omitted.
    """
    if categoria is None:
        categoria = derive_categoria(levels)
    medidas: list[MedidaAplicable] = []
    for medida in catalog.medidas.values():
        if not _medida_applies(medida, categoria, levels):
            continue
        medidas.append(
            MedidaAplicable(
                medida=medida,
                refuerzos=_activated_refuerzos(medida, categoria, levels),
            )
        )
    return ApplicabilityResult(categoria=categoria, medidas=medidas)
