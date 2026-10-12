"""Integrity tests for the OSCAL catalog loader."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from ens_audit.catalog.loader import load_catalog
from ens_audit.catalog.models import Catalog

CATALOG_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "ens_anexo_ii_oscal.json"
)


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return load_catalog(CATALOG_PATH)


def test_base_measure_count(catalog: Catalog) -> None:
    assert len(catalog.medidas) == 73


def test_marco_split(catalog: Catalog) -> None:
    counts = Counter(medida.marco for medida in catalog.medidas.values())
    assert counts == {"org": 4, "op": 33, "mp": 36}


def test_family_count(catalog: Catalog) -> None:
    familias = {medida.familia for medida in catalog.medidas.values()}
    assert len(familias) == 16


def test_refuerzo_count(catalog: Catalog) -> None:
    total = sum(len(medida.refuerzos) for medida in catalog.medidas.values())
    assert total == 133


def test_measure_codes_unique(catalog: Catalog) -> None:
    codes = [medida.code for medida in catalog.medidas.values()]
    assert len(codes) == len(set(codes))


def test_metadata_recorded(catalog: Catalog) -> None:
    assert catalog.norma == "BOE-A-2022-7191"
    assert catalog.version == "1.0.0"
    assert catalog.oscal_version == "1.1.3"
    assert catalog.last_modified.startswith("2026-05-12")
    assert catalog.licencia == "EUPL-1.2"


def test_requisitos_and_refuerzos_parsed(catalog: Catalog) -> None:
    op_pl_1 = catalog.medidas["op.pl.1"]
    assert op_pl_1.requisitos  # base requirements present
    assert [ref.id for ref in op_pl_1.refuerzos] == ["op.pl.1.r1", "op.pl.1.r2"]
    assert op_pl_1.refuerzos[0].requisitos
    assert op_pl_1.refuerzos[0].order == 1


def test_refuerzo_alternatives_derived(catalog: Catalog) -> None:
    op_acc_5 = catalog.medidas["op.acc.5"]
    alternatives = {ref.id: ref.alternativas for ref in op_acc_5.refuerzos}
    assert alternatives["op.acc.5.r1"] == [
        "op.acc.5.r2",
        "op.acc.5.r3",
        "op.acc.5.r4",
    ]


def test_optional_refuerzos_flagged(catalog: Catalog) -> None:
    # op.pl.5.r1/r2 are the documented optional refuerzos (Anexo II, apdo. 5.e).
    op_pl_5 = catalog.medidas["op.pl.5"]
    assert all(ref.opcional for ref in op_pl_5.refuerzos)
