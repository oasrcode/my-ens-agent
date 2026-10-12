"""Tests for the traceability + evidence-state foundation (feedback #4/#5, W0).

They cover the three independent axes (``method`` / ``confidence`` / scope), the
six :class:`~ens_audit.models.EvidenceState` values, the rule that a
non-demonstrated signal (``demonstrates=False``, e.g. a CVE) must **not** yield
``no_cumple``, and the flow of the traceability chain into the reports.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ens_audit.catalog.loader import load_catalog
from ens_audit.catalog.models import Catalog, Categoria
from ens_audit.checks.base import build_evidence
from ens_audit.checks.mapping import measures_for
from ens_audit.checks.registry import _normalize, register, run_scans
from ens_audit.evaluate import evaluate_compliance
from ens_audit.models import (
    Assessment,
    CheckEvidence,
    ComplianceReport,
    Confidence,
    EvidenceState,
    Finding,
    Method,
    ScanReport,
    Severity,
    Verdict,
)
from ens_audit.report import (
    KIND_LABELS_ES,
    render_json,
    render_markdown,
    risk_items,
)
from ens_audit.report.html import render_html

CATALOG_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "ens_anexo_ii_oscal.json"
)
VULNERABLE_CODE = (
    Path(__file__).resolve().parent / "fixtures" / "code" / "vulnerable"
)
CLEAN_CODE = Path(__file__).resolve().parent / "fixtures" / "code" / "clean"


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return load_catalog(CATALOG_PATH)


def _by_code(report) -> dict:
    return {verdict.measure_code: verdict for verdict in report.verdicts}


def _check(code: str, *, covers_all: bool = False) -> CheckEvidence:
    return CheckEvidence(
        scanner="code.sast",
        measure_codes=[code],
        checked="TLS configuration hardened",
        scope="src/ (12 files)",
        result="pass",
        covers_all=covers_all,
    )


def _risk_finding(code: str = "op.exp.4") -> Finding:
    """A verified but non-demonstrated signal (e.g. a detected CVE)."""
    return Finding(
        id="dependency.outdated",
        severity=Severity.HIGH,
        message="CVE-2024-0001 affects libfoo",
        measure_codes=[code],
        tool="osv-scanner",
        tool_version="1.7.0",
        method=Method.VERIFIED,
        confidence=Confidence.HIGH,
        demonstrates=False,
        requirement_refs=[f"{code}.a"],
    )


# -- the five evidence states -------------------------------------------------


def test_evidence_state_for_each_scenario(catalog: Catalog) -> None:
    """Each branch of the evaluator yields its documented evidence state."""
    # no_comprobado: no coverage at all.
    empty = evaluate_compliance(catalog)
    assert empty.summary.no_comprobado == 73
    assert all(
        v.evidence_state is EvidenceState.NO_COMPROBADO for v in empty.verdicts
    )

    # no_aplica: not applicable to the category.
    basica = evaluate_compliance(catalog, categoria=Categoria.BASICA)
    assert _by_code(basica)["op.ext.3"].evidence_state is EvidenceState.NO_APLICA

    # no_detectado: checked and clean, but not full coverage -> parcial.
    partial = evaluate_compliance(
        catalog, ScanReport(target="srv", evidence=[_check("mp.com.2")])
    )
    assert _by_code(partial)["mp.com.2"].evidence_state is EvidenceState.NO_DETECTADO

    # cumplimiento_demostrado: full-coverage positive check -> cumple.
    proven = evaluate_compliance(
        catalog,
        ScanReport(target="srv", evidence=[_check("mp.com.2", covers_all=True)]),
    )
    assert (
        _by_code(proven)["mp.com.2"].evidence_state
        is EvidenceState.CUMPLIMIENTO_DEMOSTRADO
    )

    # incumplimiento_demostrado: a demonstrated failure -> no_cumple.
    failure = Finding(
        id="config.debug_enabled",
        severity=Severity.HIGH,
        message="debug mode enabled",
        measure_codes=["op.exp.2"],
        demonstrates=True,
    )
    failed = evaluate_compliance(
        catalog, ScanReport(target="srv", findings=[failure])
    )
    assert (
        _by_code(failed)["op.exp.2"].evidence_state
        is EvidenceState.INCUMPLIMIENTO_DEMOSTRADO
    )


def test_assessment_derives_evidence_state(catalog: Catalog) -> None:
    report = evaluate_compliance(
        catalog,
        assessments=[
            Assessment(measure_code="org.1", verdict=Verdict.CUMPLE),
            Assessment(measure_code="org.2", verdict=Verdict.NO_CUMPLE),
            Assessment(measure_code="org.3", verdict=Verdict.PARCIAL),
        ],
    )
    verdicts = _by_code(report)
    assert (
        verdicts["org.1"].evidence_state is EvidenceState.CUMPLIMIENTO_DEMOSTRADO
    )
    assert (
        verdicts["org.2"].evidence_state is EvidenceState.INCUMPLIMIENTO_DEMOSTRADO
    )
    assert verdicts["org.3"].evidence_state is EvidenceState.NO_CONCLUYENTE


def test_manual_parcial_assessment_renders_neutral_state(catalog: Catalog) -> None:
    """N1: a manual ``parcial`` is a neutral verdict, not ``no_detectado``."""
    report = evaluate_compliance(
        catalog,
        assessments=[Assessment(measure_code="org.3", verdict=Verdict.PARCIAL)],
    )
    verdict = _by_code(report)["org.3"]
    assert verdict.verdict is Verdict.PARCIAL
    assert verdict.evidence_state is EvidenceState.NO_CONCLUYENTE
    assert report.summary.no_concluyente == 1
    assert report.summary.no_detectado == 0

    # The neutral state is labelled in Spanish, not as ``No detectado``.
    markdown = render_markdown(report, catalog=catalog)
    assert "No concluyente" in markdown
    document = json.loads(render_json(report, catalog=catalog))
    assert document["summary"]["no_concluyente"] == 1
    verdict_json = {v["code"]: v for v in document["verdicts"]}["org.3"]
    assert verdict_json["evidence_state"] == "no_concluyente"
    assert "No concluyente" in render_html(report, catalog=catalog)


# -- demonstrated vs non-demonstrated -----------------------------------------


def test_non_demonstrated_signal_is_not_no_cumple(catalog: Catalog) -> None:
    """A verified CVE (demonstrates=False) caps at parcial and is a risk."""
    report = evaluate_compliance(
        catalog,
        ScanReport(target="srv", findings=[_risk_finding()]),
        categoria=Categoria.ALTA,
    )
    verdict = _by_code(report)["op.exp.4"]
    assert verdict.verdict is Verdict.PARCIAL
    assert verdict.verdict is not Verdict.NO_CUMPLE
    assert verdict.evidence_state is EvidenceState.RIESGO_DETECTADO

    risks = report.metadata["risks"]
    assert [risk["id"] for risk in risks] == ["dependency.outdated"]
    assert risks[0]["method"] == "verified"
    assert risks[0]["demonstrates"] is False
    assert risks[0]["tool"] == "osv-scanner"
    # An explicit ref the scanner set is preserved (the catalog fill only kicks
    # in when the source carries none).
    assert risks[0]["requirement_refs"] == ["op.exp.4.a"]


def test_non_demonstrated_risk_caps_positive_full_coverage(catalog: Catalog) -> None:
    """A risk signal prevents a full-coverage clean check from reaching cumple."""
    report = evaluate_compliance(
        catalog,
        ScanReport(
            target="srv",
            findings=[_risk_finding()],
            evidence=[_check("op.exp.4", covers_all=True)],
        ),
        categoria=Categoria.ALTA,
    )
    verdict = _by_code(report)["op.exp.4"]
    assert verdict.verdict is Verdict.PARCIAL
    assert verdict.evidence_state is EvidenceState.RIESGO_DETECTADO


def test_demonstrated_finding_is_no_cumple(catalog: Catalog) -> None:
    finding = Finding(
        id="secret.hardcoded",
        severity=Severity.HIGH,
        message="hardcoded secret in source",
        measure_codes=["mp.si.2"],
        demonstrates=True,
    )
    report = evaluate_compliance(
        catalog, ScanReport(target="srv", findings=[finding])
    )
    verdict = _by_code(report)["mp.si.2"]
    assert verdict.verdict is Verdict.NO_CUMPLE
    assert verdict.evidence_state is EvidenceState.INCUMPLIMIENTO_DEMOSTRADO
    assert report.metadata["risks"] == []


def test_risk_items_fallback_excludes_demonstrated_findings() -> None:
    """N2: with no ``metadata['risks']`` only non-demonstrated findings are risks.

    The fallback path reads the scan report's findings, which include the
    demonstrated failures too; a demonstrated finding is a non-conformity, not a
    risk, so it must be filtered out of the risks list.
    """
    demonstrated = Finding(
        id="secret.hardcoded",
        severity=Severity.HIGH,
        message="hardcoded secret in source",
        measure_codes=["mp.si.2"],
        demonstrates=True,
    )
    report = ComplianceReport(
        category="ALTA",
        metadata={
            "scan_report": ScanReport(
                target="srv", findings=[demonstrated, _risk_finding()]
            )
        },
    )
    items = risk_items(report)
    assert [item["id"] for item in items] == ["dependency.outdated"]


def test_non_demonstrated_info_finding_is_not_a_risk(catalog: Catalog) -> None:
    """N7: an INFO signal means "not a failure", so it never caps a measure."""
    info = Finding(
        id="logging.audit_disabled",
        severity=Severity.INFO,
        message="audit logging is enabled",
        measure_codes=["mp.com.2"],
        demonstrates=False,
    )
    report = evaluate_compliance(
        catalog,
        ScanReport(target="srv", findings=[info]),
        categoria=Categoria.ALTA,
    )
    verdict = _by_code(report)["mp.com.2"]
    assert verdict.evidence_state is not EvidenceState.RIESGO_DETECTADO
    assert verdict.verdict is not Verdict.PARCIAL
    assert report.metadata["risks"] == []


# -- traceability fields flow through -----------------------------------------


def test_traceability_fields_flow_into_verdict_and_evidence(catalog: Catalog) -> None:
    finding = Finding(
        id="transport.tls_missing",
        severity=Severity.HIGH,
        message="TLS disabled",
        measure_codes=["mp.com.2"],
        scanner="infra.tls",
        tool="semgrep",
        tool_version="1.50.0",
        method=Method.VERIFIED,
        confidence=Confidence.HIGH,
        requirement_refs=["mp.com.2.a"],
        refuerzo_refs=["mp.com.2.r1"],
    )
    report = evaluate_compliance(
        catalog, ScanReport(target="srv", findings=[finding])
    )
    verdict = _by_code(report)["mp.com.2"]
    # The catalog-derived measure requirement is merged with the ref the finding
    # carried explicitly, so the requirement link is never empty for a mapped
    # source.
    assert verdict.requirement_refs == ["mp.com.2.a", "mp.com.2.req.1"]
    assert verdict.refuerzo_refs == ["mp.com.2.r1"]

    trace = report.metadata["traceability"]["mp.com.2"]
    assert trace[0]["tool"] == "semgrep"
    assert trace[0]["tool_version"] == "1.50.0"
    assert trace[0]["method"] == "verified"
    assert trace[0]["confidence"] == "high"
    assert trace[0]["requirement_refs"] == ["mp.com.2.a"]


def test_real_scanner_populates_requirement_refs(catalog: Catalog) -> None:
    """B1: a real scanner run populates the requirement link from the catalog.

    This uses actual ``code.*`` scanners against the vulnerable fixture (no
    fabricated data) so the assertion proves the evaluator derives the
    requirement ids the scanners never set themselves.
    """
    from ens_audit.checks.code import SCANNERS as code_scanners

    for scanner in code_scanners:
        register(scanner)
    scanner_ids = [s.id for s in code_scanners]

    # A failed measure: a real finding from the vulnerable fixture.
    scan = run_scans(VULNERABLE_CODE, check_ids=scanner_ids)
    assert scan.findings, "the vulnerable fixture must yield findings"
    report = evaluate_compliance(catalog, scan, categoria=Categoria.ALTA)
    failed_code = scan.findings[0].measure_codes[0]
    assert _by_code(report)[failed_code].verdict is Verdict.NO_CUMPLE
    assert _by_code(report)[failed_code].requirement_refs != []

    # A covered measure: a real clean check from the clean fixture.
    clean_scan = run_scans(CLEAN_CODE, check_ids=scanner_ids)
    assert clean_scan.evidence, "the clean fixture must yield positive evidence"
    clean_report = evaluate_compliance(catalog, clean_scan, categoria=Categoria.ALTA)
    covered_code = clean_scan.evidence[0].measure_codes[0]
    assert _by_code(clean_report)[covered_code].requirement_refs != []

    # Every populated ref is an actual catalog requirement id (measure or
    # activated-refuerzo requisito).
    catalog_requirements = {
        requisito.id
        for medida in catalog.medidas.values()
        for requisito in (
            *medida.requisitos,
            *(r for refuerzo in medida.refuerzos for r in refuerzo.requisitos),
        )
    }
    assert set(_by_code(report)[failed_code].requirement_refs) <= catalog_requirements
    assert (
        set(_by_code(clean_report)[covered_code].requirement_refs)
        <= catalog_requirements
    )


def test_registry_stamps_tool_centrally() -> None:
    finding = Finding(
        id="x.rule", severity=Severity.LOW, message="m", measure_codes=["op.exp.10"]
    )
    normalized = _normalize(finding, "code.sast")
    assert normalized.scanner == "code.sast"
    assert normalized.tool == "code.sast"
    # The method/confidence axes keep their model defaults.
    assert normalized.method is Method.HEURISTIC
    assert normalized.confidence is Confidence.MEDIUM

    # An explicit tool is preserved.
    explicit = Finding(
        id="x.rule",
        severity=Severity.LOW,
        message="m",
        measure_codes=["op.exp.10"],
        tool="osv-scanner",
    )
    assert _normalize(explicit, "code.sast").tool == "osv-scanner"


class _FakeScanner:
    """Minimal scanner stub for :func:`build_evidence`."""

    id = "code.secrets"


def test_build_evidence_stamps_tool() -> None:
    evidence = build_evidence(
        _FakeScanner(),  # type: ignore[arg-type]
        evaluated_kinds=("secret.hardcoded",),
        checked="scanned",
        scope="src/ (1 file)",
    )
    assert evidence
    check = evidence[0]
    assert check.scanner == "code.secrets"
    assert check.tool == "code.secrets"
    assert check.method is Method.HEURISTIC
    assert check.confidence is Confidence.MEDIUM
    assert check.measure_codes == sorted(
        ref.code for ref in measures_for("secret.hardcoded")
    )


# -- evidence-state counts ----------------------------------------------------


def test_compliance_summary_counts_by_evidence_state(catalog: Catalog) -> None:
    """A synthetic mix exercises every counted evidence state."""
    findings = [
        # demonstrated failure -> incumplimiento_demostrado
        Finding(
            id="config.debug_enabled",
            severity=Severity.HIGH,
            message="debug",
            measure_codes=["op.exp.2"],
        ),
        # non-demonstrated risk -> riesgo_detectado
        _risk_finding(),
    ]
    evidence = [
        _check("mp.com.2", covers_all=True),  # cumplimiento_demostrado
        _check("mp.com.3"),  # no_detectado
    ]
    report = evaluate_compliance(
        catalog,
        ScanReport(target="srv", findings=findings, evidence=evidence),
        categoria=Categoria.ALTA,
    )
    summary = report.summary
    assert summary.cumplimiento_demostrado == 1
    assert summary.incumplimiento_demostrado == 1
    # The CVE risk signal is ``riesgo_detectado``; ``no_detectado`` is reserved
    # for the clean-but-partial positive check.
    assert summary.riesgo_detectado == 1
    assert summary.no_detectado == 1
    # Everything else applicable has no coverage.
    assert summary.no_comprobado == summary.applicable - 4
    assert (
        summary.cumplimiento_demostrado
        + summary.incumplimiento_demostrado
        + summary.riesgo_detectado
        + summary.no_detectado
        + summary.no_comprobado
        == summary.applicable
    )


# -- reports ------------------------------------------------------------------


@pytest.fixture()
def risk_report(catalog: Catalog):
    return evaluate_compliance(
        catalog,
        ScanReport(target="srv", findings=[_risk_finding()]),
        categoria=Categoria.ALTA,
    )


def test_markdown_shows_evidence_state_and_risks(risk_report) -> None:
    markdown = render_markdown(risk_report)
    assert "| Estado de la evidencia |" in markdown
    assert "## Riesgos" in markdown
    # The risk is listed via its localized rule label (NOT as a no_cumple NC).
    assert KIND_LABELS_ES["dependency.outdated"] in markdown
    assert "verificado" in markdown


def test_html_shows_evidence_state_and_risks(risk_report) -> None:
    html = render_html(risk_report)
    assert 'class="ev-state-badge"' in html
    assert 'class="risks"' in html
    assert "Riesgos" in html


def test_json_includes_evidence_state_counts_and_chain(risk_report, catalog) -> None:
    document = json.loads(render_json(risk_report, catalog=catalog))
    assert document["schema_version"] == "1.6"
    assert document["summary"]["riesgo_detectado"] == 1
    assert document["summary"]["no_detectado"] == 0
    assert document["summary"]["no_concluyente"] == 0
    assert document["summary"]["incumplimiento_demostrado"] == 0
    assert document["risks"][0]["id"] == "dependency.outdated"

    verdict = {v["code"]: v for v in document["verdicts"]}["op.exp.4"]
    assert verdict["evidence_state"] == "riesgo_detectado"
    # The requirement link carries both the catalog measure/refuerzo refs and
    # the explicit ref the finding supplied.
    assert "op.exp.4.a" in verdict["requirement_refs"]
    assert "op.exp.4.req.1" in verdict["requirement_refs"]
    assert verdict["traceability"][0]["tool"] == "osv-scanner"
    assert verdict["traceability"][0]["tool_version"] == "1.7.0"
    assert verdict["traceability"][0]["requirement_refs"] == ["op.exp.4.a"]
