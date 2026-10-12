"""Tests for per-dimension applicability threaded through the evaluator (#4).

Covers the ``dimensiones`` argument of
:func:`ens_audit.evaluate.evaluate_compliance`: it derives the system category
and the applicable measures/refuerzos through
:func:`ens_audit.catalog.applicability.compute_applicability`, records the
valuation and the activated refuerzos in the report metadata, and surfaces them
in every renderer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ens_audit.catalog.loader import load_catalog
from ens_audit.catalog.models import Catalog, Categoria, Dimension, Nivel
from ens_audit.evaluate import evaluate_compliance
from ens_audit.report import render_json, render_markdown
from ens_audit.report.html import render_html

CATALOG_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "ens_anexo_ii_oscal.json"
)


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return load_catalog(CATALOG_PATH)


def _by_code(report) -> dict:
    return {verdict.measure_code: verdict for verdict in report.verdicts}


def test_two_valuations_yield_category_and_refuerzo(catalog: Catalog) -> None:
    """Different dimension sets derive different categories/refuerzos.

    ``op.pl.1`` activates ``r1`` at MEDIA and ``r2`` at ALTA (the source does not
    cumulate them), so the two valuations are directly distinguishable.
    """
    media = evaluate_compliance(
        catalog, dimensiones={"Confidencialidad": "MEDIO"}
    )
    assert media.category == "MEDIA"
    assert media.metadata["dimensions"] == {"Confidencialidad": "MEDIO"}
    assert _by_code(media)["op.pl.1"].refuerzo_refs == ["op.pl.1.r1"]
    assert media.metadata["refuerzos"]["op.pl.1"] == ["op.pl.1.r1"]

    alta = evaluate_compliance(catalog, dimensiones={"Disponibilidad": "ALTO"})
    assert alta.category == "ALTA"
    assert alta.metadata["dimensions"] == {"Disponibilidad": "ALTO"}
    assert _by_code(alta)["op.pl.1"].refuerzo_refs == ["op.pl.1.r2"]
    assert alta.metadata["refuerzos"]["op.pl.1"] == ["op.pl.1.r2"]

    assert media.category != alta.category


def test_dimension_keys_accept_letters_and_enum(catalog: Catalog) -> None:
    """String names, single letters and enum members are all accepted."""
    by_name = evaluate_compliance(
        catalog, dimensiones={"Confidencialidad": "MEDIO"}
    )
    by_letter = evaluate_compliance(catalog, dimensiones={"C": "medio"})
    by_enum = evaluate_compliance(
        catalog, dimensiones={Dimension.CONFIDENCIALIDAD: Nivel.MEDIO}
    )
    assert by_name.category == by_letter.category == by_enum.category == "MEDIA"
    assert (
        by_name.metadata["dimensions"]
        == by_letter.metadata["dimensions"]
        == by_enum.metadata["dimensions"]
        == {"Confidencialidad": "MEDIO"}
    )


def test_categoria_overrides_derived_category(catalog: Catalog) -> None:
    """``categoria`` still wins over the category derived from ``dimensiones``.

    The override only replaces the category; the dimension-driven measures keep
    following the valuation, so ALTA + ``C=MEDIO`` is not the full ALTA set.
    """
    derived = evaluate_compliance(
        catalog, dimensiones={"Confidencialidad": "MEDIO"}
    )
    report = evaluate_compliance(
        catalog,
        dimensiones={"Confidencialidad": "MEDIO"},
        categoria=Categoria.ALTA,
    )
    assert derived.category == "MEDIA"
    assert report.category == "ALTA"
    assert report.summary.applicable == 57
    assert report.summary.applicable > derived.summary.applicable


def test_categoria_only_fallback_is_unchanged(catalog: Catalog) -> None:
    """Without ``dimensiones`` the uniform ``categoria`` valuation is kept."""
    report = evaluate_compliance(catalog, categoria=Categoria.BASICA)
    assert report.category == "BASICA"
    assert report.summary.applicable == 52
    # A categorical fallback is not a real per-dimension valuation.
    assert report.metadata["dimensions"] == {}


def test_no_valuation_records_no_dimensions_or_refuerzos(catalog: Catalog) -> None:
    report = evaluate_compliance(catalog)
    assert report.metadata["dimensions"] == {}
    assert report.metadata["refuerzos"] == {}
    assert report.category == ""


def test_activated_refuerzos_reach_uncovered_applicable_measures(
    catalog: Catalog,
) -> None:
    """An applicable measure with no evidence still carries its refuerzos."""
    report = evaluate_compliance(
        catalog, dimensiones={"Confidencialidad": "MEDIO"}
    )
    verdict = _by_code(report)["op.pl.1"]
    assert verdict.verdict.value == "no_evaluable"
    assert verdict.refuerzo_refs == ["op.pl.1.r1"]


def test_report_lists_dimensions_and_refuerzos(
    catalog: Catalog,
) -> None:
    report = evaluate_compliance(
        catalog, dimensiones={"Confidencialidad": "MEDIO"}
    )

    markdown = render_markdown(report, catalog=catalog)
    assert "## Dimensiones y refuerzos" in markdown
    assert "Confidencialidad" in markdown
    assert "`op.pl.1.r1`" in markdown

    html = render_html(report, catalog=catalog)
    assert "Refuerzos activados" in html
    assert "op.pl.1.r1" in html

    document = json.loads(render_json(report, catalog=catalog))
    assert document["schema_version"] == "1.6"
    assert document["dimensions"] == {"Confidencialidad": "MEDIO"}
    assert document["refuerzos"]["op.pl.1"] == ["op.pl.1.r1"]
