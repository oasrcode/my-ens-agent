"""Tests for the ENS applicability engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from ens_audit.catalog.applicability import (
    compute_applicability,
    derive_categoria,
)
from ens_audit.catalog.loader import load_catalog
from ens_audit.catalog.models import Catalog, Categoria, Dimension, Nivel

CATALOG_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "ens_anexo_ii_oscal.json"
)


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return load_catalog(CATALOG_PATH)


def _levels(**overrides: Nivel) -> dict[Dimension, Nivel]:
    """Build a dimension->level map defaulting every dimension to BAJO."""
    values = {dimension: Nivel.BAJO for dimension in Dimension}
    for name, level in overrides.items():
        values[Dimension(name)] = level
    return values


def _all(level: Nivel) -> dict[Dimension, Nivel]:
    """Build a dimension->level map valuing every dimension at ``level``."""
    return {dimension: level for dimension in Dimension}


def test_all_bajo_is_basica() -> None:
    assert derive_categoria(_levels()) is Categoria.BASICA


def test_one_medio_is_media() -> None:
    levels = _levels(Confidencialidad=Nivel.MEDIO)
    assert derive_categoria(levels) is Categoria.MEDIA


def test_one_alto_is_alta() -> None:
    levels = _levels(Disponibilidad=Nivel.ALTO)
    assert derive_categoria(levels) is Categoria.ALTA


def test_alto_dominates_over_medio() -> None:
    levels = _levels(Confidencialidad=Nivel.MEDIO, Integridad=Nivel.ALTO)
    assert derive_categoria(levels) is Categoria.ALTA


def test_measure_sets_differ_by_category(catalog: Catalog) -> None:
    basica = compute_applicability(catalog, _all(Nivel.BAJO))
    media = compute_applicability(catalog, _all(Nivel.MEDIO))
    alta = compute_applicability(catalog, _all(Nivel.ALTO))

    assert basica.categoria is Categoria.BASICA
    assert media.categoria is Categoria.MEDIA
    assert alta.categoria is Categoria.ALTA

    basica_codes = set(basica.measure_codes())
    media_codes = set(media.measure_codes())
    alta_codes = set(alta.measure_codes())

    assert basica_codes < media_codes < alta_codes
    assert len(basica_codes) == 52
    assert len(media_codes) == 68
    assert len(alta_codes) == 73


def test_dimension_driven_measure_requires_level(catalog: Catalog) -> None:
    # op.cont.2 concerns availability and only applies from ALTA.
    basica = set(compute_applicability(catalog, _levels()).measure_codes())
    media = set(
        compute_applicability(catalog, _levels(Disponibilidad=Nivel.MEDIO)).measure_codes()
    )
    alta = set(
        compute_applicability(catalog, _levels(Disponibilidad=Nivel.ALTO)).measure_codes()
    )
    assert "op.cont.2" not in basica
    assert "op.cont.2" not in media
    assert "op.cont.2" in alta


def test_category_measure_respects_level_dimensions(catalog: Catalog) -> None:
    # op.ext.3 applies by category only from ALTA.
    basica = set(compute_applicability(catalog, _levels()).measure_codes())
    media = set(
        compute_applicability(catalog, _levels(Confidencialidad=Nivel.MEDIO)).measure_codes()
    )
    alta = set(
        compute_applicability(catalog, _levels(Disponibilidad=Nivel.ALTO)).measure_codes()
    )
    assert "op.ext.3" not in basica
    assert "op.ext.3" not in media
    assert "op.ext.3" in alta


def test_refuerzos_activated_by_category(catalog: Catalog) -> None:
    media = {
        m.medida.code: [r.id for r in m.refuerzos]
        for m in compute_applicability(
            catalog, _levels(Confidencialidad=Nivel.MEDIO)
        ).medidas
    }
    alta = {
        m.medida.code: [r.id for r in m.refuerzos]
        for m in compute_applicability(
            catalog, _levels(Disponibilidad=Nivel.ALTO)
        ).medidas
    }
    # op.pl.1: R1 at MEDIA, R2 at ALTA (the source does not cumulate them).
    assert media["op.pl.1"] == ["op.pl.1.r1"]
    assert alta["op.pl.1"] == ["op.pl.1.r2"]


def test_optional_refuerzos_not_activated(catalog: Catalog) -> None:
    alta = {
        m.medida.code: [r.id for r in m.refuerzos]
        for m in compute_applicability(
            catalog, _levels(Disponibilidad=Nivel.ALTO)
        ).medidas
    }
    assert "op.pl.5.r1" not in alta["op.pl.5"]
    assert "op.pl.5.r2" not in alta["op.pl.5"]


def test_mutually_exclusive_refuerzos_alternatives(catalog: Catalog) -> None:
    alta = next(
        m
        for m in compute_applicability(catalog, _all(Nivel.ALTO)).medidas
        if m.medida.code == "op.acc.5"
    )
    activated = {r.id for r in alta.refuerzos}
    # ALTA selects the R2/R3/R4 alternative plus the additive R5.
    assert activated == {"op.acc.5.r2", "op.acc.5.r3", "op.acc.5.r4", "op.acc.5.r5"}
