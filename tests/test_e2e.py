"""End-to-end audit test over the intentionally insecure ``audit_target`` fixture.

Exercises the full offline pipeline -- deterministic scanners -> compliance
evaluator -> report renderers -- against a realistic sample application that
mixes source-code and infrastructure/configuration problems, and asserts the
three report formats (Markdown, JSON, HTML) are produced.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import pytest

from ens_audit.catalog.loader import load_catalog
from ens_audit.catalog.models import Catalog, Categoria
from ens_audit.checks.code import SCANNERS as CODE_SCANNERS
from ens_audit.checks.infra import SCANNERS as INFRA_SCANNERS
from ens_audit.checks.registry import register, run_scans
from ens_audit.evaluate import evaluate_compliance
from ens_audit.models import ComplianceReport, ScanReport
from ens_audit.report import render_report

REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "data" / "ens_anexo_ii_oscal.json"
TARGET = Path(__file__).resolve().parent / "fixtures" / "audit_target"

#: Scanner ids of the full pipeline, in a stable order (5 code + 5 infra).
SCANNER_IDS = [scanner.id for scanner in (*CODE_SCANNERS, *INFRA_SCANNERS)]

#: Rule kinds the fixture is expected to trigger via the source-code scanners.
EXPECTED_CODE_KINDS = {
    "secret.hardcoded",
    "crypto.weak_algorithm",
    "transport.tls_missing",
    "injection.sql",
    "injection.command",
    "logging.audit_disabled",
    "dependency.outdated",
}

#: Rule kinds the fixture is expected to trigger via the infra scanners.
EXPECTED_INFRA_KINDS = {
    "config.debug_enabled",
    "network.service_exposed",
    "storage.unencrypted",
    "dependency.outdated",
    "logging.audit_disabled",
}

ALL_EXPECTED_KINDS = EXPECTED_CODE_KINDS | EXPECTED_INFRA_KINDS


@pytest.fixture(scope="module", autouse=True)
def _ensure_scanners_registered() -> None:
    """Re-register both scanner families.

    Other test modules clear the process-global registry for isolation, so the
    E2E run must not depend on import order. ``register`` is a no-op for the
    module-level scanner singletons, so this is idempotent.
    """
    for scanner in (*CODE_SCANNERS, *INFRA_SCANNERS):
        register(scanner)


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return load_catalog(CATALOG_PATH)


@pytest.fixture(scope="module")
def scan_report(_ensure_scanners_registered: None) -> ScanReport:
    return run_scans(TARGET, check_ids=SCANNER_IDS)


@pytest.fixture(scope="module")
def compliance_report(catalog: Catalog, scan_report: ScanReport) -> ComplianceReport:
    return evaluate_compliance(
        catalog, scan_report=scan_report, categoria=Categoria.ALTA
    )


def test_fixture_target_exists() -> None:
    assert TARGET.is_dir()
    for name in (
        "auth_service.py",
        "Dockerfile",
        "deployment.yaml",
        "main.tf",
        "nginx.conf",
        "README.md",
    ):
        assert (TARGET / name).is_file(), name


def test_run_scans_finds_code_and_infra_problems(scan_report: ScanReport) -> None:
    findings = scan_report.findings
    assert findings, "the audit target produced no findings"

    assert scan_report.scanners == SCANNER_IDS

    kinds = Counter(finding.id for finding in findings)
    missing = sorted(ALL_EXPECTED_KINDS - set(kinds))
    assert not missing, f"missing expected finding kinds: {missing}"

    # Both scanner families actually contributed.
    scanners = {finding.scanner for finding in findings}
    assert any(s and s.startswith("code.") for s in scanners)
    assert any(s and s.startswith("infra.") for s in scanners)

    # Every finding carries evidence and an ENS measure mapping.
    for finding in findings:
        assert finding.evidence, finding.id
        assert ":" in finding.evidence[0].location, finding.id
        assert finding.measure_codes, finding.id


def test_evaluate_compliance_yields_73_verdicts_with_non_compliance(
    catalog: Catalog, compliance_report: ComplianceReport
) -> None:
    verdicts = compliance_report.verdicts
    assert len(verdicts) == 73
    assert compliance_report.summary.total == 73
    assert len({v.measure_code for v in verdicts}) == 73
    assert {v.measure_code for v in verdicts} == set(catalog.medidas)

    # The insecure target must produce several non-conformities.
    assert compliance_report.summary.no_cumple >= 3

    by_code = {v.measure_code: v for v in verdicts}
    # injection → mp.sw.1; debug config → op.exp.2. Both have failing findings
    # and no surviving positive evidence, so they must be NO_CUMPLE.
    for code in ("mp.sw.1", "op.exp.2"):
        assert by_code[code].verdict.value == "no_cumple", code

    # mp.si.2 has real failing findings (hardcoded secret, weak crypto,
    # unencrypted storage) and no scanner can certify it clean: every kind that
    # maps to mp.si.2 either failed here or was not evaluated against a
    # relevant artifact. A genuine failure plus no surviving positive evidence
    # is NO_CUMPLE (B1/B2).
    assert by_code["mp.si.2"].verdict.value == "no_cumple"


def test_render_report_writes_md_json_and_html(
    compliance_report: ComplianceReport, catalog: Catalog, tmp_path: Path
) -> None:
    paths = render_report(
        compliance_report,
        formats=("md", "json", "html"),
        output_dir=tmp_path,
        catalog=catalog,
    )

    assert [path.suffix for path in paths] == [".md", ".json", ".html"]
    assert [path.name for path in paths] == [
        "informe-ens.md",
        "informe-ens.json",
        "informe-ens.html",
    ]
    for path in paths:
        assert path.exists()
        assert path.stat().st_size > 0

    markdown, json_text, html = (path.read_text(encoding="utf-8") for path in paths)
    codes = catalog.measure_codes()
    assert len(codes) == 73

    # Markdown: every measure code is rendered in a table cell.
    for code in codes:
        assert f"`{code}`" in markdown, code

    # HTML: every measure code is rendered inside a <code> element.
    for code in codes:
        assert re.search(rf">{re.escape(code)}</code>", html), code

    # JSON: versioned document with one verdict per measure.
    document = json.loads(json_text)
    assert document["schema_version"]
    assert document["summary"]["total"] == 73
    assert len(document["verdicts"]) == 73
    assert [v["code"] for v in document["verdicts"]] == codes
