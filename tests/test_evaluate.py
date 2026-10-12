"""Tests for the compliance evaluator (R1 evidence-based verdict semantics).

The fundamental rule under test is: *absence of findings is not evidence of
compliance*. ``CUMPLE`` requires explicit positive verification (an assessment,
or a scanner check that covers every applicable requirement); a clean scanner
check with partial coverage yields ``PARCIAL`` and no coverage at all yields
``NO_EVALUABLE``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ens_audit.catalog.loader import load_catalog
from ens_audit.catalog.models import Catalog, Categoria
from ens_audit.evaluate import evaluate_compliance
from ens_audit.models import (
    Assessment,
    CheckEvidence,
    Evidence,
    EvidenceKind,
    Finding,
    ScanReport,
    Severity,
    Verdict,
)

CATALOG_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "ens_anexo_ii_oscal.json"
)


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return load_catalog(CATALOG_PATH)


def _by_code(report) -> dict:
    return {verdict.measure_code: verdict for verdict in report.verdicts}


def _check(
    code: str, *, covers_all: bool = False, result: str = "pass"
) -> CheckEvidence:
    return CheckEvidence(
        scanner="code.sast",
        measure_codes=[code],
        checked="TLS configuration hardened",
        scope="src/ (12 files)",
        result=result,
        covers_all=covers_all,
        evidence=[
            Evidence(kind=EvidenceKind.FILE_LINE, location=f"{code}:check")
        ],
    )


def test_all_measures_have_exactly_one_verdict(catalog: Catalog) -> None:
    report = evaluate_compliance(catalog)
    codes = [verdict.measure_code for verdict in report.verdicts]
    assert len(codes) == 73
    assert len(set(codes)) == 73
    assert set(codes) == set(catalog.medidas)
    assert report.summary.total == 73


def test_zero_evidence_yields_no_cumple(catalog: Catalog) -> None:
    """Rule 6: with no scan and no assessments, nothing is compliant."""
    report = evaluate_compliance(catalog)
    assert report.summary.cumple == 0
    assert report.summary.no_evaluable == 73
    assert all(
        verdict.verdict is Verdict.NO_EVALUABLE for verdict in report.verdicts
    )


def test_assessment_with_cumple_verdict_is_cumple(catalog: Catalog) -> None:
    report = evaluate_compliance(
        catalog,
        assessments=[
            Assessment(
                measure_code="org.1",
                verdict=Verdict.CUMPLE,
                notes="Security policy approved by the committee.",
                evidence=[
                    Evidence(kind=EvidenceKind.NOTE, location="DA-2026", detail="signed")
                ],
            )
        ],
    )
    verdict = _by_code(report)["org.1"]
    assert verdict.verdict is Verdict.CUMPLE
    assert "Security policy approved" in verdict.rationale
    assert verdict.evidence[0].location == "DA-2026"
    assert report.summary.cumple == 1


def test_assessment_mapping_is_accepted(catalog: Catalog) -> None:
    report = evaluate_compliance(
        catalog,
        assessments={"mp.if.1": Assessment(measure_code="mp.if.1", verdict=Verdict.NO_APLICA)},
    )
    assert _by_code(report)["mp.if.1"].verdict is Verdict.NO_APLICA


def test_positive_check_without_full_coverage_is_parcial(catalog: Catalog) -> None:
    """Rule 5: a clean scanner check that does not cover everything -> parcial."""
    report = evaluate_compliance(
        catalog,
        ScanReport(target="srv-01", evidence=[_check("mp.com.2")]),
    )
    verdict = _by_code(report)["mp.com.2"]
    assert verdict.verdict is Verdict.PARCIAL
    assert report.summary.cumple == 0
    assert report.summary.parcial >= 1


def test_positive_check_with_full_coverage_is_cumple(catalog: Catalog) -> None:
    """Rule 5: only a check covering *all* requirements raises to cumple."""
    report = evaluate_compliance(
        catalog,
        ScanReport(target="srv-01", evidence=[_check("mp.com.2", covers_all=True)]),
    )
    assert _by_code(report)["mp.com.2"].verdict is Verdict.CUMPLE
    assert report.summary.cumple == 1


def test_info_finding_alone_is_parcial(catalog: Catalog) -> None:
    """Legacy positive signal (INFO) without full coverage is not compliance."""
    finding = Finding(
        id="F-INFO",
        severity=Severity.INFO,
        message="header present",
        measure_codes=["mp.com.2"],
    )
    report = evaluate_compliance(
        catalog, ScanReport(target="web", findings=[finding])
    )
    assert _by_code(report)["mp.com.2"].verdict is Verdict.PARCIAL


def test_failure_finding_is_no_cumple_with_evidence(catalog: Catalog) -> None:
    finding = Finding(
        id="F-001",
        severity=Severity.HIGH,
        message="TLS 1.0 still enabled",
        measure_codes=["mp.com.2"],
        evidence=[
            Evidence(
                kind=EvidenceKind.FILE_LINE,
                location="nginx/nginx.conf:42",
                detail="ssl_protocols TLSv1",
            )
        ],
    )
    report = evaluate_compliance(
        catalog, ScanReport(target="srv-01", findings=[finding])
    )
    verdict = _by_code(report)["mp.com.2"]
    assert verdict.verdict is Verdict.NO_CUMPLE
    assert [e.location for e in verdict.evidence] == ["nginx/nginx.conf:42"]
    assert report.summary.no_cumple >= 1


def test_failure_plus_positive_is_no_cumple(catalog: Catalog) -> None:
    """Rule 3: failures dominate; a positive signal cannot soften a failure."""
    findings = [
        Finding(
            id="F-100",
            severity=Severity.MEDIUM,
            message="missing header",
            measure_codes=["mp.s.1"],
        ),
        Finding(
            id="F-101",
            severity=Severity.INFO,
            message="header present on the other vhost",
            measure_codes=["mp.s.1"],
        ),
    ]
    report = evaluate_compliance(
        catalog, ScanReport(target="web", findings=findings)
    )
    assert _by_code(report)["mp.s.1"].verdict is Verdict.NO_CUMPLE


def test_full_coverage_plus_failure_is_no_cumple(catalog: Catalog) -> None:
    """A failure always wins, even with a full-coverage clean check elsewhere."""
    finding = Finding(
        id="F-200",
        severity=Severity.LOW,
        message="weak cipher",
        measure_codes=["mp.com.2"],
    )
    report = evaluate_compliance(
        catalog,
        ScanReport(
            target="srv-01",
            findings=[finding],
            evidence=[_check("mp.com.2", covers_all=True)],
        ),
    )
    assert _by_code(report)["mp.com.2"].verdict is Verdict.NO_CUMPLE


def test_cross_scanner_failure_dominates_positive(catalog: Catalog) -> None:
    """A failure from scanner A is not downgraded by scanner B's clean check.

    Scanner A records a failure on ``mp.com.2``; scanner B emits a clean
    (full-coverage) ``CheckEvidence`` for the same measure. The failure must win
    globally, so the measure is ``NO_CUMPLE`` rather than ``PARCIAL``/``CUMPLE``.
    """
    failure = Finding(
        id="A.weak-cipher",
        severity=Severity.HIGH,
        message="weak cipher enabled",
        measure_codes=["mp.com.2"],
        scanner="scanner.a",
    )
    clean = CheckEvidence(
        scanner="scanner.b",
        measure_codes=["mp.com.2"],
        checked="TLS configuration hardened",
        scope="nginx/ (1 file)",
        result="pass",
        covers_all=True,
    )
    report = evaluate_compliance(
        catalog,
        ScanReport(target="srv-01", findings=[failure], evidence=[clean]),
    )
    assert _by_code(report)["mp.com.2"].verdict is Verdict.NO_CUMPLE


def test_no_aplica_for_non_applicable_measures(catalog: Catalog) -> None:
    report = evaluate_compliance(catalog, categoria=Categoria.BASICA)
    verdicts = _by_code(report)
    # op.ext.3 (supply-chain protection) only applies from ALTA.
    assert verdicts["op.ext.3"].verdict is Verdict.NO_APLICA
    assert verdicts["mp.sw.1"].verdict is Verdict.NO_APLICA
    # 52 measures are applicable under BASICA (documented upper bound).
    assert report.summary.total - report.summary.no_aplica == 52
    assert report.summary.no_aplica == 73 - 52
    assert report.summary.applicable == 52


def test_documentary_measures_without_evidence_are_no_evaluable(
    catalog: Catalog,
) -> None:
    report = evaluate_compliance(catalog)
    verdicts = _by_code(report)
    for code in ("org.1", "org.4", "mp.if.1", "mp.per.3", "op.pl.1", "mp.si.1"):
        assert verdicts[code].verdict is Verdict.NO_EVALUABLE, code
    assert report.summary.no_evaluable == 73


def test_percentages_reflect_verdicts(catalog: Catalog) -> None:
    """compliance_pct = cumple/applicable; coverage_pct = covered/applicable."""
    assessments = [
        Assessment(measure_code="mp.com.2", verdict=Verdict.CUMPLE),
        Assessment(measure_code="mp.com.3", verdict=Verdict.NO_CUMPLE),
    ]
    report = evaluate_compliance(
        catalog, categoria=Categoria.BASICA, assessments=assessments
    )
    summary = report.summary
    assert summary.applicable == 52
    assert summary.cumple == 1
    assert summary.no_cumple == 1
    # Every other applicable measure has no evidence -> no_evaluable.
    assert summary.no_evaluable == 52 - 2
    assert summary.compliance_pct == round(100 * 1 / 52, 2)
    assert summary.coverage_pct == round(100 * (52 - 50) / 52, 2)
    assert report.metadata["applicable"] == summary.applicable
    assert report.metadata["compliance_pct"] == summary.compliance_pct
    assert report.metadata["coverage_pct"] == summary.coverage_pct


def test_summary_and_metadata_consistency(catalog: Catalog) -> None:
    report = evaluate_compliance(catalog, categoria=Categoria.ALTA)
    summary = report.summary
    assert (
        summary.cumple
        + summary.no_cumple
        + summary.parcial
        + summary.no_aplica
        + summary.no_evaluable
        == summary.total
        == 73
    )
    assert report.category == "ALTA"
    assert report.metadata["applicable"] == summary.total - summary.no_aplica
    assert 0.0 <= report.metadata["compliance_pct"] <= 100.0
    assert 0.0 <= report.metadata["coverage_pct"] <= 100.0
