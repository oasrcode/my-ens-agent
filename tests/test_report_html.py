"""Tests for the self-contained HTML compliance report renderer."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ens_audit.catalog.loader import load_catalog
from ens_audit.catalog.models import Catalog, Categoria
from ens_audit.checks.code import SCANNERS as CODE_SCANNERS
from ens_audit.checks.registry import register, run_scans
from ens_audit.evaluate import evaluate_compliance
from ens_audit.models import (
    CheckEvidence,
    ComplianceReport,
    ComplianceSummary,
    Finding,
    ScanReport,
    Severity,
)
from ens_audit.report import KIND_LABELS_ES
from ens_audit.report.html import render_html, write_html

CATALOG_PATH = Path(__file__).resolve().parents[1] / "data" / "ens_anexo_ii_oscal.json"
CLEAN_CODE = Path(__file__).resolve().parent / "fixtures" / "code" / "clean"

VERDICT_LABELS = ("Cumple", "No cumple", "Parcial", "No aplica", "No evaluable")

#: Matches ANY absolute http(s) URL. The XHTML namespace is the only harmless
#: exception and is stripped before the check.
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_XMLNS_RE = re.compile(r'xmlns(:\w+)?="https?://www\.w3\.org/[^"]*"')


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return load_catalog(CATALOG_PATH)


@pytest.fixture(scope="module")
def report(catalog: Catalog) -> ComplianceReport:
    """A report exercising every verdict: findings plus a restricted category."""
    findings = [
        # HIGH finding -> NO_CUMPLE on a technical measure.
        Finding(
            id="F-001",
            severity=Severity.HIGH,
            message="TLS 1.0 still enabled",
            measure_codes=["mp.com.2"],
        ),
        # Mixed failure + informational signal -> PARCIAL.
        Finding(
            id="F-002",
            severity=Severity.MEDIUM,
            message="missing HSTS header",
            measure_codes=["mp.s.1"],
        ),
        Finding(
            id="F-003",
            severity=Severity.INFO,
            message="header present on one vhost",
            measure_codes=["mp.s.1"],
        ),
    ]
    return evaluate_compliance(
        catalog,
        ScanReport(target="srv-01", findings=findings),
        categoria=Categoria.BASICA,
    )


@pytest.fixture(scope="module")
def evidence_report(catalog: Catalog) -> ComplianceReport:
    """A report carrying positive evidence and a failed scanner."""
    evidence = [
        CheckEvidence(
            scanner="web",
            measure_codes=["mp.com.2"],
            checked="Configuración TLS del servidor web",
            scope="/etc/nginx/nginx.conf",
            result="pass",
            observed_at=datetime(2026, 1, 15, 10, 30, tzinfo=UTC),
            covers_all=False,
        )
    ]
    scan_report = ScanReport(
        target="srv-01",
        findings=[],
        scanners=["web", "sast"],
        evidence=evidence,
        scanner_status={"web": "completed", "sast": "failed"},
    )
    return evaluate_compliance(catalog, scan_report, categoria=Categoria.MEDIA)


def _expected_pct(value: float) -> str:
    """Format a percentage the way the HTML renderer does (comma separator)."""
    text = f"{value:.2f}".rstrip("0").rstrip(".")
    return text.replace(".", ",")


def test_starts_with_doctype(report: ComplianceReport) -> None:
    html = render_html(report)
    assert html.startswith("<!DOCTYPE html>")


def test_is_single_document_and_self_contained(report: ComplianceReport) -> None:
    html = render_html(report)
    assert "<html" in html and html.rstrip().endswith("</html>")
    # Styles are inlined; there is exactly one page-level stylesheet.
    assert html.count("<style") == 1
    assert "@media print" in html


def test_contains_all_73_measure_codes(
    report: ComplianceReport, catalog: Catalog
) -> None:
    html = render_html(report, catalog=catalog)
    codes = catalog.measure_codes()
    assert len(codes) == 73
    for code in codes:
        # Boundaries guard against prefix collisions (e.g. op.exp.1 vs op.exp.10).
        assert re.search(rf">{re.escape(code)}</code>", html), code


def test_contains_all_verdict_labels(
    report: ComplianceReport, catalog: Catalog
) -> None:
    html = render_html(report, catalog=catalog)
    for label in VERDICT_LABELS:
        assert label in html, label


def test_no_external_resource_references(
    report: ComplianceReport, catalog: Catalog
) -> None:
    html = render_html(report, catalog=catalog)
    # The XHTML namespace is the only permitted http(s) reference.
    without_ns = _XMLNS_RE.sub("", html)
    urls = _URL_RE.findall(without_ns)
    assert urls == [], urls


def test_evidence_is_escapable_and_present(catalog: Catalog) -> None:
    from ens_audit.models import Evidence, EvidenceKind

    finding = Finding(
        id="F-900",
        severity=Severity.HIGH,
        message="xss",
        measure_codes=["mp.s.2"],
        evidence=[
            Evidence(
                kind=EvidenceKind.FILE_LINE,
                location="web/<script>.conf:9",
                detail="<b>unsafe</b>",
            )
        ],
    )
    report = evaluate_compliance(catalog, ScanReport(target="web", findings=[finding]))
    html = render_html(report, catalog=catalog)
    # Raw markup from the evidence must be escaped, not injected.
    assert "<script>" not in html
    assert "<b>unsafe</b>" not in html
    assert "&lt;script&gt;" in html


def test_write_html_round_trip(
    tmp_path: Path, report: ComplianceReport, catalog: Catalog
) -> None:
    target = tmp_path / "nested" / "report.html"
    written = write_html(report, target, catalog=catalog)
    assert written == target
    assert target.is_file()
    content = target.read_text(encoding="utf-8")
    assert content.startswith("<!DOCTYPE html>")
    assert content == render_html(report, catalog=catalog)
    assert target.stat().st_size > 0


def test_render_without_catalog_still_lists_measures(report: ComplianceReport) -> None:
    html = render_html(report)
    for code in ("org.1", "op.acc.1", "mp.com.2"):
        assert re.search(rf">{re.escape(code)}</code>", html), code


def test_parcial_appears_in_nonconformities_section(
    report: ComplianceReport, catalog: Catalog
) -> None:
    """M2: HTML must list ``parcial`` alongside ``no_cumple`` as non-conformity."""
    html = render_html(report, catalog=catalog)
    section = re.search(
        r'<section class="nonconformities".*?</section>', html, re.DOTALL
    )
    assert section is not None
    body = section.group(0)
    # The fixture yields a major (no_cumple) and a minor (parcial) NC.
    assert "<code>mp.com.2</code>" in body
    assert "<code>mp.s.1</code>" in body
    assert "Parcial" in body


def test_summary_shows_both_percentages(
    evidence_report: ComplianceReport, catalog: Catalog
) -> None:
    """R1-4a: the summary shows compliance and evaluation-coverage ratios."""
    html = render_html(evidence_report, catalog=catalog)
    assert "Cumplimiento" in html
    assert "Cobertura de evaluación" in html
    assert html.count('class="compliance-value"') == 2
    assert _expected_pct(evidence_report.summary.compliance_pct) in html
    assert _expected_pct(evidence_report.summary.coverage_pct) in html


def test_positive_evidence_section_with_scope_and_date(
    evidence_report: ComplianceReport, catalog: Catalog
) -> None:
    """R1-3a: positive evidence is rendered with its scope and date."""
    html = render_html(evidence_report, catalog=catalog)
    assert "Evidencia positiva" in html
    assert "Configuración TLS del servidor web" in html
    assert "/etc/nginx/nginx.conf" in html
    assert "2026-01-15" in html


def test_scanner_status_surfaces_failure(
    evidence_report: ComplianceReport, catalog: Catalog
) -> None:
    """R1: scanner status is shown and a failed scanner is surfaced explicitly."""
    html = render_html(evidence_report, catalog=catalog)
    assert "Estado de los escáneres" in html
    assert "sast" in html
    assert "Fallido" in html
    assert 'class="status-failed"' in html
    assert 'class="failed-note"' in html


def _evidence_section(html: str) -> str:
    """Return the positive-evidence ``<section>`` of the rendered document."""
    match = re.search(
        r'<section class="evidence-summary".*?</section>', html, re.DOTALL
    )
    assert match is not None
    return match.group(0)


def test_html_evidence_table_is_spanish_from_real_scanners(catalog: Catalog) -> None:
    """Blocker: the scanner-authored English evidence text must not leak."""
    for scanner in CODE_SCANNERS:
        register(scanner)
    scan_report = run_scans(CLEAN_CODE, check_ids=[s.id for s in CODE_SCANNERS])
    report = evaluate_compliance(catalog, scan_report, categoria=Categoria.ALTA)

    section = _evidence_section(render_html(report, catalog=catalog))

    assert KIND_LABELS_ES["secret.hardcoded"] in section
    assert "correcto" in section
    for leak in ("Scanned source", "Checked source", ">pass<"):
        assert leak not in section, leak


def test_html_summary_first_parity_with_markdown(catalog: Catalog) -> None:
    """R1 residual: HTML reads applicable/ratios from summary, not metadata."""
    report = ComplianceReport(
        category="BASICA",
        summary=ComplianceSummary(
            total=20,
            cumple=8,
            no_cumple=2,
            no_evaluable=10,
            applicable=20,
            compliance_pct=40.0,
            coverage_pct=50.0,
        ),
        metadata={"applicable": 91, "compliance_pct": 7.0, "coverage_pct": 3.0},
    )

    html = render_html(report, catalog=catalog)

    assert 'aria-label="Cumplimiento: 40%"' in html
    assert 'aria-label="Cobertura de evaluación: 50%"' in html
    assert "20 medidas aplicables" in html
    assert "91 medidas aplicables" not in html
    assert 'aria-label="Cumplimiento: 7%"' not in html
    assert 'aria-label="Cobertura de evaluación: 3%"' not in html
