"""Tests for the Markdown and JSON report renderers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ens_audit.catalog.loader import load_catalog
from ens_audit.catalog.models import Catalog, Categoria
from ens_audit.checks import known_kinds
from ens_audit.checks.code import SCANNERS as CODE_SCANNERS
from ens_audit.checks.registry import register, run_scans
from ens_audit.evaluate import evaluate_compliance
from ens_audit.models import (
    CheckEvidence,
    ComplianceReport,
    ComplianceSummary,
    Evidence,
    EvidenceKind,
    EvidenceState,
    Finding,
    MeasureVerdict,
    ScanReport,
    Severity,
    Verdict,
)
from ens_audit.report import (
    KIND_LABELS_ES,
    RESULT_LABELS_ES,
    checked_label_es,
    render_json,
    render_markdown,
    render_report,
    result_label_es,
)
from ens_audit.report.json import SCHEMA_VERSION

CATALOG_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "ens_anexo_ii_oscal.json"
)
CLEAN_CODE = Path(__file__).resolve().parent / "fixtures" / "code" / "clean"


def _evidence_section(markdown: str) -> str:
    """Return the body of the Markdown positive-evidence section."""
    return markdown.split("## Evidencia positiva", 1)[1].split("\n## ", 1)[0]


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return load_catalog(CATALOG_PATH)


@pytest.fixture(scope="module")
def report(catalog: Catalog) -> ComplianceReport:
    findings = [
        Finding(
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
        ),
        Finding(
            id="F-002",
            severity=Severity.INFO,
            message="security headers present",
            measure_codes=["mp.com.3"],
        ),
    ]
    scan_report = ScanReport(
        target="srv-01", findings=findings, scanners=["web", "sast"]
    )
    return evaluate_compliance(
        catalog, scan_report, categoria=Categoria.MEDIA
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


def test_markdown_contains_all_measure_codes(
    report: ComplianceReport, catalog: Catalog
) -> None:
    markdown = render_markdown(report, catalog=catalog)
    codes = catalog.measure_codes()
    assert len(codes) == 73
    missing = [code for code in codes if code not in markdown]
    assert not missing, f"missing measure codes in Markdown: {missing}"
    # Every code is rendered in the summary table's first column.
    rendered = sum(1 for code in codes if f"`{code}`" in markdown)
    assert rendered == 73


def test_markdown_has_expected_sections(
    report: ComplianceReport, catalog: Catalog
) -> None:
    markdown = render_markdown(report, catalog=catalog)
    for heading in (
        "# Informe de cumplimiento del ENS",
        "## Metadatos",
        "## Resumen ejecutivo",
        "## Alcance y metodología",
        "## Categorización",
        "## Tabla completa de medidas",
        "## No conformidades",
        "## Recomendaciones",
    ):
        assert heading in markdown


def test_json_parses_with_schema_version_and_all_verdicts(
    report: ComplianceReport, catalog: Catalog
) -> None:
    document = json.loads(render_json(report, catalog=catalog))
    assert document["schema_version"] == "1.6"
    assert document["schema_version"] == SCHEMA_VERSION
    assert document["category"] == "MEDIA"
    assert document["summary"]["total"] == 73
    assert len(document["verdicts"]) == 73
    codes = [verdict["code"] for verdict in document["verdicts"]]
    assert codes == catalog.measure_codes()
    assert set(codes) == set(catalog.medidas)


def test_json_verdict_shape(report: ComplianceReport, catalog: Catalog) -> None:
    document = json.loads(render_json(report, catalog=catalog))
    by_code = {verdict["code"]: verdict for verdict in document["verdicts"]}
    non_conformant = by_code["mp.com.2"]
    assert non_conformant["verdict"] == "no_cumple"
    assert non_conformant["name"] == "Protección de la confidencialidad"
    assert non_conformant["evidence"][0]["location"] == "nginx/nginx.conf:42"
    assert non_conformant["evidence"][0]["kind"] == "file_line"
    assert non_conformant["rationale"]


def test_render_report_writes_files(
    report: ComplianceReport, catalog: Catalog, tmp_path: Path
) -> None:
    paths = render_report(
        report,
        formats=("md", "json"),
        output_dir=tmp_path,
        catalog=catalog,
    )
    assert [path.suffix for path in paths] == [".md", ".json"]
    for path in paths:
        assert path.exists()
        assert path.stat().st_size > 0
    assert paths[0].name == "informe-ens.md"
    assert paths[1].name == "informe-ens.json"


def test_render_report_rejects_unknown_format(
    report: ComplianceReport, tmp_path: Path
) -> None:
    with pytest.raises(ValueError):
        render_report(report, formats=("pdf",), output_dir=tmp_path)


def test_render_report_writes_nothing_when_a_format_is_invalid(
    report: ComplianceReport, tmp_path: Path
) -> None:
    """All formats are validated before any file is written."""
    with pytest.raises(ValueError):
        render_report(report, formats=("md", "pdf"), output_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_markdown_lists_parcial_in_non_conformities(catalog: Catalog) -> None:
    """M2 parity: a partial measure is a (minor) non-conformity in Markdown."""
    # A positive signal with no failure is ``parcial`` (failures would dominate
    # and make it ``no_cumple``).
    findings = [
        Finding(
            id="F-2",
            severity=Severity.INFO,
            message="control present on one host",
            measure_codes=["mp.s.1"],
        ),
    ]
    partial_report = evaluate_compliance(
        catalog,
        ScanReport(target="srv-01", findings=findings),
        categoria=Categoria.BASICA,
    )
    markdown = render_markdown(partial_report, catalog=catalog)
    section = markdown.split("## No conformidades", 1)[1].split(
        "## Recomendaciones", 1
    )[0]
    assert "`mp.s.1`" in section
    assert "Parcial" in section


def test_markdown_suppresses_english_auto_rationale(
    report: ComplianceReport, catalog: Catalog
) -> None:
    """M3: evaluator-authored English rationales must not leak into Spanish."""
    markdown = render_markdown(report, catalog=catalog)
    assert "failing scanner finding(s) for this measure" not in markdown
    assert "passing scanner signal(s) for this measure" not in markdown
    assert "assumed compliant" not in markdown


def test_markdown_keeps_manual_rationale(catalog: Catalog) -> None:
    """M3: a human-authored rationale is still shown verbatim."""
    manual = "Nota manual en español sobre el hallazgo."
    manual_report = ComplianceReport(
        category="BASICA",
        verdicts=[
            MeasureVerdict(
                measure_code="mp.com.2",
                verdict=Verdict.NO_CUMPLE,
                evidence_state=EvidenceState.INCUMPLIMIENTO_DEMOSTRADO,
                rationale=manual,
            )
        ],
        summary=ComplianceSummary(total=1, no_cumple=1),
    )
    markdown = render_markdown(manual_report, catalog=catalog)
    assert manual in markdown


def test_markdown_summary_shows_both_percentages(
    evidence_report: ComplianceReport, catalog: Catalog
) -> None:
    """R1-4a: compliance and evaluation-coverage percentages are both shown."""
    markdown = render_markdown(evidence_report, catalog=catalog)
    assert "**Cumplimiento:**" in markdown
    assert "**Cobertura de evaluación:**" in markdown
    assert f"{evidence_report.summary.compliance_pct} %" in markdown
    assert f"{evidence_report.summary.coverage_pct} %" in markdown


def test_markdown_positive_evidence_with_scope_and_date(
    evidence_report: ComplianceReport, catalog: Catalog
) -> None:
    """R1-3a: positive evidence is listed with its scope and date."""
    markdown = render_markdown(evidence_report, catalog=catalog)
    assert "## Evidencia positiva" in markdown
    assert "Configuración TLS del servidor web" in markdown
    assert "/etc/nginx/nginx.conf" in markdown
    assert "2026-01-15" in markdown


def test_markdown_scanner_status_surfaces_failure(
    evidence_report: ComplianceReport, catalog: Catalog
) -> None:
    """R1: the scanner status is shown and failures are surfaced explicitly."""
    markdown = render_markdown(evidence_report, catalog=catalog)
    assert "## Estado de los escáneres" in markdown
    assert "`sast`" in markdown
    assert "Fallido" in markdown
    assert "Escáneres fallidos" in markdown


def test_markdown_evidence_report_has_no_english_auto_rationale(
    evidence_report: ComplianceReport, catalog: Catalog
) -> None:
    """M3/R1: evaluator-authored English rationales must not leak."""
    markdown = render_markdown(evidence_report, catalog=catalog)
    for leak in (
        "passing scanner signal(s) for this measure",
        "failing scanner finding(s) for this measure",
        "Explicit scanner check covers all applicable requirements",
        "No coverage and no manual assessment",
        "assumed compliant",
    ):
        assert leak not in markdown


def test_json_includes_coverage_evidence_and_scanner_status(
    evidence_report: ComplianceReport, catalog: Catalog
) -> None:
    """R1-T3: JSON exposes coverage_pct, evidence[] and scanner_status."""
    document = json.loads(render_json(evidence_report, catalog=catalog))
    assert document["summary"]["coverage_pct"] == evidence_report.summary.coverage_pct
    assert document["scanner_status"] == {"web": "completed", "sast": "failed"}
    evidence = document["evidence"]
    assert len(evidence) == 1
    item = evidence[0]
    assert item["scanner"] == "web"
    assert item["checked"] == "Configuración TLS del servidor web"
    assert item["scope"] == "/etc/nginx/nginx.conf"
    assert item["result"] == "pass"
    assert item["observed_at"] == "2026-01-15"


def test_kind_labels_cover_every_mapping_kind() -> None:
    """Every rule kind in the measure mapping has a Spanish label."""
    assert set(KIND_LABELS_ES) == set(known_kinds())
    assert all(label.strip() for label in KIND_LABELS_ES.values())
    assert RESULT_LABELS_ES == {"pass": "correcto"}


def test_checked_and_result_labels_localise_and_fallback() -> None:
    known = {
        "kind": "secret.hardcoded",
        "checked": "Scanned source files for hardcoded credentials.",
        "result": "pass",
    }
    assert checked_label_es(known) == KIND_LABELS_ES["secret.hardcoded"]
    assert result_label_es(known) == "correcto"

    # Unknown/absent kind and result fall back to their raw (input) values.
    unknown = {"kind": None, "checked": "Nota manual.", "result": "custom"}
    assert checked_label_es(unknown) == "Nota manual."
    assert result_label_es(unknown) == "custom"


def test_markdown_evidence_table_is_spanish_from_real_scanners(
    catalog: Catalog,
) -> None:
    """Blocker: the scanner-authored English evidence text must not leak."""
    for scanner in CODE_SCANNERS:
        register(scanner)
    scan_report = run_scans(CLEAN_CODE, check_ids=[s.id for s in CODE_SCANNERS])
    assert scan_report.evidence, "the clean fixture must yield positive evidence"

    report = evaluate_compliance(catalog, scan_report, categoria=Categoria.ALTA)
    section = _evidence_section(render_markdown(report, catalog=catalog))

    # The Spanish checked-control labels and the localized result are shown.
    assert KIND_LABELS_ES["secret.hardcoded"] in section
    assert KIND_LABELS_ES["logging.audit_disabled"] in section
    assert "correcto" in section
    # No scanner-authored English token survives in the evidence table.
    for leak in ("Scanned source", "Checked source", "Checked dependency", "pass"):
        assert leak not in section, leak


def test_json_keeps_raw_checked_and_kind(catalog: Catalog) -> None:
    """The machine-facing JSON keeps the raw ``checked`` text plus the kind."""
    evidence = [
        CheckEvidence(
            scanner="code.secrets",
            kind="secret.hardcoded",
            measure_codes=["mp.si.2"],
            checked="Scanned source files for hardcoded credentials.",
            scope="src/ (1 file)",
            result="pass",
        )
    ]
    report = evaluate_compliance(
        catalog, ScanReport(target="src", evidence=evidence)
    )
    item = json.loads(render_json(report, catalog=catalog))["evidence"][0]
    assert item["checked"] == "Scanned source files for hardcoded credentials."
    assert item["kind"] == "secret.hardcoded"
    assert item["result"] == "pass"


def test_summary_is_authoritative_over_metadata(catalog: Catalog) -> None:
    """M2: reports read applicable/ratios from ``summary``, not ``metadata``."""
    report = ComplianceReport(
        category="BASICA",
        summary=ComplianceSummary(
            total=2,
            cumple=1,
            no_cumple=1,
            applicable=2,
            compliance_pct=50.0,
            coverage_pct=100.0,
        ),
        metadata={"applicable": 99, "compliance_pct": 1.0, "coverage_pct": 2.0},
    )

    document = json.loads(render_json(report, catalog=catalog))
    assert document["summary"]["applicable"] == 2
    assert document["summary"]["compliance_pct"] == 50.0
    assert document["summary"]["coverage_pct"] == 100.0

    markdown = render_markdown(report, catalog=catalog)
    assert "50.0 %" in markdown
    assert "100.0 %" in markdown


def test_markdown_applicable_is_single_consistent_value(catalog: Catalog) -> None:
    """R1-T10: the Alcance section and the summary share ``summary.applicable``.

    A report whose metadata carries a stale/divergent ``applicable`` must still
    render a single, consistent number everywhere.
    """
    report = ComplianceReport(
        category="BASICA",
        summary=ComplianceSummary(
            total=10,
            cumple=3,
            no_cumple=1,
            no_aplica=2,
            no_evaluable=4,
            applicable=8,
            compliance_pct=37.5,
            coverage_pct=50.0,
        ),
        metadata={"applicable": 99},
    )

    markdown = render_markdown(report, catalog=catalog)

    assert "- Medidas aplicables: 8." in markdown
    assert "Medidas aplicables: 99." not in markdown
    # The executive summary uses the same denominator.
    assert "(3 / 8 medidas aplicables)." in markdown
    assert "(3 / 99 medidas aplicables)." not in markdown


def test_markdown_language_falls_back_to_spanish(
    evidence_report: ComplianceReport, catalog: Catalog
) -> None:
    """R1-T10: only Spanish is authored, so ``language="en"`` stays Spanish.

    There is no longer an ``en`` string table, so requesting English must fall
    back wholesale to Spanish instead of mixing English headers with Spanish
    evidence cells.
    """
    markdown = render_markdown(evidence_report, catalog=catalog, language="en")

    assert "## Resumen ejecutivo" in markdown
    assert "## Evidencia positiva" in markdown
    assert "correcto" in markdown
    for english in (
        "ENS compliance report",
        "Executive summary",
        "Scope and methodology",
        "Positive evidence",
        "Checked",
        "Completed",
        "Compliant",
        "Non-compliant",
    ):
        assert english not in markdown, english
