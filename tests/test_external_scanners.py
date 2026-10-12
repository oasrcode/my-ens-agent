"""Tests for the optional external-scanner framework and SARIF ingestion.

No external tool is required: availability and execution are faked through
``monkeypatch`` on :mod:`subprocess`, and SARIF input comes from the fixtures
under ``tests/fixtures/external``. The fakes assert the runner never uses a
shell and always passes a timeout.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from ens_audit.catalog.loader import load_catalog
from ens_audit.catalog.models import Catalog, Categoria
from ens_audit.checks.external import (
    SCANNERS,
    ToolStatus,
    import_sarif,
    parse_sarif,
    try_parse_sarif,
)
from ens_audit.checks.registry import get_scanner, register, run_scans
from ens_audit.evaluate import evaluate_compliance
from ens_audit.models import Confidence, EvidenceKind, Method, Severity, Verdict
from ens_audit.report import render_json, render_markdown

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "external"
OSV_SARIF = FIXTURES / "osv.sarif.json"
CATALOG_PATH = Path(__file__).resolve().parents[1] / "data" / "ens_anexo_ii_oscal.json"


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return load_catalog(CATALOG_PATH)


@pytest.fixture(autouse=True)
def _ensure_registered() -> Iterator[None]:
    """Re-register the external scanners if another test cleared the registry."""
    for scanner in SCANNERS:
        register(scanner)
    yield


def _install_fake(
    monkeypatch: pytest.MonkeyPatch,
    *,
    available: bool = True,
    version: str = "1.7.1",
    sarif: str = "",
    returncode: int = 0,
    run_error: BaseException | None = None,
) -> None:
    """Replace ``subprocess.run`` with a deterministic, offline fake.

    The fake enforces the framework's safety contract: no shell, captured
    output and an explicit timeout on every call.
    """

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
        assert kwargs.get("shell") is False
        assert kwargs.get("capture_output") is True
        assert kwargs.get("timeout") is not None
        if command[1:] == ["--version"]:
            if not available:
                raise FileNotFoundError(command[0])
            return subprocess.CompletedProcess(
                command, 0, stdout=f"{version}\n", stderr=""
            )
        if run_error is not None:
            raise run_error
        return subprocess.CompletedProcess(
            command, returncode, stdout=sarif, stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)


# -- SARIF parser -------------------------------------------------------------


def test_parse_sarif_fixture_extracts_core_fields() -> None:
    results = parse_sarif(OSV_SARIF.read_text(encoding="utf-8"))

    assert len(results) == 2
    first, second = results
    assert first.rule_id == "GHSA-jfh8-c2jp-5v3q"
    assert first.level == "warning"
    assert "lodash" in first.message
    assert first.uri == "package.json"
    assert first.start_line == 12
    assert second.level == "error"
    assert second.uri == "requirements.txt"
    assert second.start_line == 3


@pytest.mark.parametrize(
    "payload",
    ["", "not json", "{}", "[]", "null", '{"runs": "nope"}', '{"runs": [null, 1]}'],
)
def test_parse_sarif_never_raises_on_malformed_input(payload: str) -> None:
    assert parse_sarif(payload) == []


def test_parse_sarif_tolerates_missing_and_mistyped_fields() -> None:
    payload = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "r1",
                        "level": "note",
                        "message": {"text": "hello"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.py"},
                                    "region": {"startLine": 5},
                                }
                            }
                        ],
                    },
                    {"ruleId": "r2"},
                    {"message": "bare string", "locations": []},
                    "not-a-mapping",
                ]
            },
            "not-a-run",
        ]
    }

    results = parse_sarif(payload)

    assert [result.rule_id for result in results] == ["r1", "r2", ""]
    assert results[0].uri == "a.py"
    assert results[0].start_line == 5
    assert results[0].level == "note"
    assert results[1].uri is None
    assert results[1].start_line is None
    assert results[2].message == "bare string"


# -- availability / execution outcomes ----------------------------------------


def test_detect_reports_available_version(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake(monkeypatch, version="0.50.1")

    assert get_scanner("external.trivy").detect() == ToolStatus(
        available=True, version="0.50.1"
    )


def test_detect_returns_unavailable_when_probe_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake(monkeypatch, available=False)

    assert get_scanner("external.osv").detect() == ToolStatus(available=False)


def test_unavailable_tool_is_skipped_without_findings_or_coverage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install_fake(monkeypatch, available=False)
    scanner = get_scanner("external.osv")

    report = run_scans(tmp_path, check_ids=["external.osv"])

    assert report.scanner_status == {"external.osv": "skipped"}
    assert report.findings == []
    assert report.evidence == []
    # A missing tool claims no coverage: absence is never read as compliance.
    assert scanner.covers == ()
    assert scanner.coverage_measures() == set()


@pytest.mark.parametrize(
    "run_error",
    [subprocess.TimeoutExpired(cmd=["trivy"], timeout=1), OSError("cannot execute")],
)
def test_timeout_or_os_error_is_failed_without_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, run_error: BaseException
) -> None:
    _install_fake(monkeypatch, run_error=run_error)

    report = run_scans(tmp_path, check_ids=["external.trivy"])

    assert report.scanner_status == {"external.trivy": "failed"}
    assert report.findings == []
    assert report.evidence == []


def test_non_zero_exit_with_parseable_sarif_is_completed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Real tools exit non-zero when they find something: the SARIF is usable."""
    _install_fake(
        monkeypatch, returncode=2, sarif=OSV_SARIF.read_text(encoding="utf-8")
    )

    report = run_scans(tmp_path, check_ids=["external.semgrep"])

    assert report.scanner_status == {"external.semgrep": "completed"}
    assert len(report.findings) == 2


def test_non_zero_exit_without_parseable_sarif_is_failed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A genuine failure: non-zero exit and no SARIF to read."""
    _install_fake(monkeypatch, returncode=2, sarif="boom: not sarif")

    report = run_scans(tmp_path, check_ids=["external.osv"])

    assert report.scanner_status == {"external.osv": "failed"}
    assert report.findings == []
    assert report.evidence == []


def test_success_exit_without_sarif_is_completed_empty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A success exit with no parseable report is a completed, empty run."""
    _install_fake(monkeypatch, returncode=0, sarif="")

    report = run_scans(tmp_path, check_ids=["external.trivy"])

    assert report.scanner_status == {"external.trivy": "completed"}
    assert report.findings == []


def test_completed_run_maps_sarif_to_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install_fake(
        monkeypatch, version="1.7.1", sarif=OSV_SARIF.read_text(encoding="utf-8")
    )

    report = run_scans(tmp_path, check_ids=["external.osv"])

    assert report.scanner_status == {"external.osv": "completed"}
    assert len(report.findings) == 2
    for finding in report.findings:
        assert finding.tool == "osv-scanner"
        assert finding.tool_version == "1.7.1"
        assert finding.method is Method.VERIFIED
        assert finding.confidence is Confidence.HIGH
        # A CVE is a risk signal, not a demonstrated ENS breach.
        assert finding.demonstrates is False
        # OSV maps to the known-vulnerable-dependency measures.
        assert finding.measure_codes == ["op.exp.4", "op.exp.6", "op.ext.3"]
        assert finding.scanner == "external.osv"

    warning, error = report.findings
    assert warning.severity is Severity.MEDIUM
    assert error.severity is Severity.HIGH
    assert warning.evidence[0].kind is EvidenceKind.FILE_LINE
    assert warning.evidence[0].location == "package.json:12"


TRIVY_SARIF = {
    "runs": [
        {
            "results": [
                {
                    "ruleId": "CVE-2023-32681",
                    "level": "error",
                    "message": {"text": "requests is vulnerable to CVE-2023-32681."},
                },
                {
                    "ruleId": "DS002",
                    "level": "warning",
                    "message": {"text": "Container runs as root."},
                },
            ]
        }
    ]
}


def test_trivy_classifies_results_by_type(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Trivy results split into container.vuln and iac.misconfig by rule id."""
    import json as _json

    _install_fake(monkeypatch, sarif=_json.dumps(TRIVY_SARIF))

    report = run_scans(tmp_path, check_ids=["external.trivy"])

    vuln, misconfig = report.findings
    assert "op.exp.4" in vuln.measure_codes
    assert "op.exp.4" not in misconfig.measure_codes
    assert "op.exp.2" in misconfig.measure_codes
    assert misconfig.measure_codes != vuln.measure_codes


# -- importing user-provided SARIF --------------------------------------------


def test_import_sarif_from_fixture_file_maps_kind_to_measures() -> None:
    findings = import_sarif(
        OSV_SARIF,
        tool_name="osv-scanner",
        tool_version="1.7.1",
        kind="vuln.dependency",
    )

    assert len(findings) == 2
    assert {finding.tool for finding in findings} == {"osv-scanner"}
    assert all(finding.tool_version == "1.7.1" for finding in findings)
    assert all(finding.method is Method.VERIFIED for finding in findings)
    assert all(finding.demonstrates is False for finding in findings)
    assert all(
        finding.measure_codes == ["op.exp.4", "op.exp.6", "op.ext.3"]
        for finding in findings
    )


def test_import_sarif_default_kind_maps_to_no_measure() -> None:
    """The generic default kind claims no specific measure (risk signal only)."""
    findings = import_sarif(OSV_SARIF.read_text(encoding="utf-8"))

    assert len(findings) == 2
    assert all(finding.measure_codes == [] for finding in findings)


def test_import_sarif_accepts_text_and_defaults_tool() -> None:
    findings = import_sarif(OSV_SARIF.read_text(encoding="utf-8"))

    assert len(findings) == 2
    assert {finding.tool for finding in findings} == {"external.sarif"}
    assert all(finding.tool_version is None for finding in findings)


def test_import_sarif_tolerates_unreadable_or_malformed_input(
    tmp_path: Path,
) -> None:
    assert import_sarif("not json") == []
    assert import_sarif(tmp_path / "missing.sarif.json") == []


def test_import_sarif_never_raises_on_a_very_long_string() -> None:
    """M1: a huge non-JSON string is not a valid path either.

    ``Path(source).is_file()`` raises ``OSError`` (ENAMETOOLONG) for such a
    string; ``import_sarif`` must contain it and return an empty list.
    """
    assert import_sarif("x" * 5000) == []


def test_try_parse_sarif_distinguishes_empty_from_invalid() -> None:
    assert try_parse_sarif('{"runs": []}') == []
    assert try_parse_sarif('{"runs": "nope"}') is None
    assert try_parse_sarif("not json") is None
    assert try_parse_sarif("{}") is None


# -- registration and command construction ------------------------------------


def test_external_scanners_registered_with_category_and_no_coverage() -> None:
    ids = {scanner.id for scanner in SCANNERS}

    assert ids == {"external.osv", "external.semgrep", "external.trivy"}
    for scanner in SCANNERS:
        assert scanner.category == "external"
        assert scanner.covers == ()
        assert scanner.description
        assert get_scanner(scanner.id) is scanner


def test_build_commands_are_argument_lists(tmp_path: Path) -> None:
    assert get_scanner("external.osv").build_command(tmp_path) == [
        "osv-scanner",
        "--format",
        "sarif",
        "-r",
        str(tmp_path),
    ]
    assert get_scanner("external.semgrep").build_command(tmp_path) == [
        "semgrep",
        "--sarif",
        "--quiet",
        str(tmp_path),
    ]
    assert get_scanner("external.trivy").build_command(tmp_path) == [
        "trivy",
        "fs",
        "--format",
        "sarif",
        "--quiet",
        str(tmp_path),
    ]


@pytest.mark.parametrize(
    "scanner_id",
    ["external.osv", "external.semgrep", "external.trivy"],
)
def test_build_command_honours_overridden_command(
    scanner_id: str, tmp_path: Path
) -> None:
    """M2: the argv uses ``self.command``, the same binary ``detect()`` probes.

    Overriding ``command`` (e.g. a wrapper path) must change the executed argv.
    """
    scanner = get_scanner(scanner_id)
    original = scanner.command
    try:
        scanner.command = "custom-tool"
        argv = scanner.build_command(tmp_path)
        assert argv[0] == "custom-tool"
        assert str(tmp_path) in argv
    finally:
        scanner.command = original
    # The default command still leads the argv when not overridden.
    assert scanner.build_command(tmp_path)[0] == original


# -- opt-in wiring ------------------------------------------------------------


def test_default_run_excludes_external_scanners(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A routine scan must not shell out to the external tools by default."""
    _install_fake(monkeypatch, sarif="")

    report = run_scans(tmp_path)

    assert not any(scanner.startswith("external.") for scanner in report.scanners)
    assert "external.osv" not in report.scanner_status


def test_include_external_opts_the_external_scanners_in(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install_fake(monkeypatch, sarif="")

    report = run_scans(tmp_path, include_external=True)

    external_ids = {"external.osv", "external.semgrep", "external.trivy"}
    assert external_ids <= set(report.scanners)
    assert all(report.scanner_status[i] == "completed" for i in external_ids)


def test_external_scanner_is_selectable_by_explicit_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install_fake(monkeypatch, sarif=OSV_SARIF.read_text(encoding="utf-8"))

    report = run_scans(tmp_path, check_ids=["external.osv"])

    assert report.scanners == ["external.osv"]
    assert report.scanner_status == {"external.osv": "completed"}


# -- end-to-end: external evidence in the compliance report -------------------


def test_osv_finding_yields_parcial_with_risk_and_traceability(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, catalog: Catalog
) -> None:
    """A detected CVE maps to its measures -> parcial + listed risk (not no_cumple)."""
    _install_fake(
        monkeypatch, version="1.7.1", sarif=OSV_SARIF.read_text(encoding="utf-8")
    )
    scan = run_scans(tmp_path, check_ids=["external.osv"])

    report = evaluate_compliance(catalog, scan, categoria=Categoria.ALTA)

    by_code = {verdict.measure_code: verdict for verdict in report.verdicts}
    assert by_code["op.exp.4"].verdict is Verdict.PARCIAL
    assert by_code["op.exp.4"].verdict is not Verdict.NO_CUMPLE

    risks = report.metadata["risks"]
    assert risks
    assert risks[0]["tool"] == "osv-scanner"
    assert risks[0]["tool_version"] == "1.7.1"
    assert risks[0]["method"] == "verified"


def test_report_displays_tool_version_and_method_for_risks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, catalog: Catalog
) -> None:
    _install_fake(
        monkeypatch, version="1.7.1", sarif=OSV_SARIF.read_text(encoding="utf-8")
    )
    scan = run_scans(tmp_path, check_ids=["external.osv"])
    report = evaluate_compliance(catalog, scan, categoria=Categoria.ALTA)

    markdown = render_markdown(report, catalog=catalog)
    assert "Herramienta/Método" in markdown
    assert "osv-scanner 1.7.1" in markdown
    assert "verificado" in markdown

    document = json.loads(render_json(report, catalog=catalog))
    assert document["risks"][0]["tool"] == "osv-scanner"
    assert document["risks"][0]["tool_version"] == "1.7.1"
    assert document["risks"][0]["method"] == "verified"
    assert document["risks"][0]["kind"]
