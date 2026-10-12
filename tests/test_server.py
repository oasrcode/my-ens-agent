"""In-process tests for the ENS-audit MCP server.

These exercise the server through FastMCP's in-memory transport (``Client(mcp)``)
so no subprocess or JSON-RPC framing is involved.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from fastmcp import Client

from ens_audit.server import mcp

FIXTURES = Path(__file__).resolve().parent / "fixtures"
VULNERABLE_TARGET = FIXTURES / "code" / "vulnerable"
CLEAN_TARGET = FIXTURES / "code" / "clean"

SCANNER_STATUSES = {"completed", "failed", "skipped"}

EXPECTED_TOOLS = {
    "catalog_list_measures",
    "catalog_get_measure",
    "catalog_compute_applicability",
    "run_scans",
    "import_sarif",
    "record_assessment",
    "evaluate_compliance",
    "render_report",
}

CHECK_IDS = ["code.secrets", "code.sast", "code.crypto"]

EXTERNAL_SARIF = (
    Path(__file__).resolve().parent / "fixtures" / "external" / "osv.sarif.json"
)


@pytest.fixture
async def client():
    async with Client(mcp) as connected:
        yield connected


async def test_lists_all_eight_tools(client: Client) -> None:
    tools = await client.list_tools()
    assert {tool.name for tool in tools} == EXPECTED_TOOLS


async def test_catalog_list_measures(client: Client) -> None:
    result = await client.call_tool("catalog_list_measures", {})
    measures = result.structured_content["result"]
    assert len(measures) == 73
    assert {m["code"] for m in measures} >= {"org.1", "op.acc.1", "mp.com.2"}

    org = await client.call_tool("catalog_list_measures", {"marco": "org"})
    assert {m["code"] for m in org.structured_content["result"]} == {
        "org.1",
        "org.2",
        "org.3",
        "org.4",
    }

    acc = await client.call_tool("catalog_list_measures", {"familia": "op.acc"})
    assert {m["code"] for m in acc.structured_content["result"]} == {
        "op.acc.1",
        "op.acc.2",
        "op.acc.3",
        "op.acc.4",
        "op.acc.5",
        "op.acc.6",
    }


async def test_catalog_get_measure(client: Client) -> None:
    result = await client.call_tool("catalog_get_measure", {"code": "op.acc.1"})
    detail = result.structured_content
    assert detail["code"] == "op.acc.1"
    assert detail["name"] == "Identificación"
    assert detail["marco"] == "op"
    assert detail["familia"] == "op.acc"
    assert detail["aplicacion_por"] == "nivel-dimension"
    assert {d for d in detail["dimensiones"]} >= {"Trazabilidad", "Autenticidad"}
    assert len(detail["requisitos"]) == 11
    assert [r["id"] for r in detail["refuerzos"]] == ["op.acc.1.r1"]
    assert "guides" in detail


async def test_run_scans_explicit_checks(client: Client) -> None:
    result = await client.call_tool(
        "run_scans",
        {"target": str(VULNERABLE_TARGET), "checks": CHECK_IDS},
    )
    report = result.structured_content
    assert report["scanners"] == CHECK_IDS
    assert report["target"].endswith("vulnerable")
    assert len(report["findings"]) > 0
    # R1: the scan report surfaces positive evidence and per-scanner status.
    assert "evidence" in report
    assert report["scanner_status"] == dict.fromkeys(CHECK_IDS, "completed")


async def test_run_scans_reports_positive_evidence(client: Client) -> None:
    result = await client.call_tool("run_scans", {"target": str(CLEAN_TARGET)})
    report = result.structured_content

    statuses = report["scanner_status"]
    assert statuses
    assert set(statuses).issubset(set(report["scanners"]))
    assert set(statuses.values()) <= SCANNER_STATUSES

    # A clean target yields positive CheckEvidence describing what was examined.
    assert report["evidence"]
    for item in report["evidence"]:
        assert {
            "scanner",
            "measure_codes",
            "checked",
            "scope",
            "result",
            "observed_at",
            "covers_all",
        } <= set(item)
        assert item["result"] == "pass"


async def test_run_scans_external_is_opt_in(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """External scanners are excluded by default and opted in explicitly."""

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        assert kwargs.get("shell") is False
        if command[1:] == ["--version"]:
            return subprocess.CompletedProcess(command, 0, stdout="1.0.0\n", stderr="")
        return subprocess.CompletedProcess(
            command, 0, stdout='{"runs": []}', stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    default = await client.call_tool("run_scans", {"target": str(CLEAN_TARGET)})
    assert not any(
        scanner.startswith("external.")
        for scanner in default.structured_content["scanners"]
    )

    opted = await client.call_tool(
        "run_scans", {"target": str(CLEAN_TARGET), "include_external": True}
    )
    scanners = set(opted.structured_content["scanners"])
    assert {"external.osv", "external.semgrep", "external.trivy"} <= scanners


async def test_import_sarif_tool_maps_and_stores_scan(client: Client) -> None:
    """The MCP import path produces the same findings and feeds evaluation."""
    result = await client.call_tool(
        "import_sarif",
        {
            "sarif": EXTERNAL_SARIF.read_text(encoding="utf-8"),
            "tool_name": "osv-scanner",
            "tool_version": "1.7.1",
            "kind": "vuln.dependency",
        },
    )
    report = result.structured_content
    assert report["scanners"] == ["external.import"]
    assert len(report["findings"]) == 2
    assert report["findings"][0]["measure_codes"]
    assert report["findings"][0]["method"] == "verified"
    assert report["findings"][0]["demonstrates"] is False

    evaluated = await client.call_tool(
        "evaluate_compliance", {"categoria": "ALTA"}
    )
    verdicts = {
        verdict["measure_code"]: verdict
        for verdict in evaluated.structured_content["verdicts"]
    }
    assert verdicts["op.exp.4"]["verdict"] == "parcial"


async def test_record_assessment_and_evaluate(client: Client) -> None:
    assessment = await client.call_tool(
        "record_assessment",
        {
            "measure_code": "org.1",
            "verdict": "cumple",
            "notes": "Security policy approved by the committee.",
        },
    )
    assert assessment.data.measure_code == "org.1"

    result = await client.call_tool("evaluate_compliance", {})
    report = result.structured_content
    assert len(report["verdicts"]) == 73
    summary = report["summary"]
    assert summary["total"] == 73
    # R1: the summary exposes both the compliance and the coverage percentages.
    assert "compliance_pct" in summary
    assert "coverage_pct" in summary
    assert summary["applicable"] == summary["total"] - summary["no_aplica"]
    verdicts = {v["measure_code"]: v["verdict"] for v in report["verdicts"]}
    assert verdicts["org.1"] == "cumple"


async def test_evaluate_with_dimensions_derives_category_and_refuerzos(
    client: Client,
) -> None:
    """The MCP tool accepts ``dimensiones`` and carries the derived data."""
    result = await client.call_tool(
        "evaluate_compliance", {"dimensiones": {"Confidencialidad": "MEDIO"}}
    )
    report = result.structured_content
    assert report["category"] == "MEDIA"
    assert report["metadata"]["dimensions"] == {"Confidencialidad": "MEDIO"}
    assert report["metadata"]["refuerzos"]["op.pl.1"] == ["op.pl.1.r1"]
    verdicts = {v["measure_code"]: v for v in report["verdicts"]}
    assert verdicts["op.pl.1"]["refuerzo_refs"] == ["op.pl.1.r1"]


async def test_evaluate_never_defaults_to_cumple(client: Client) -> None:
    # A scan alone (no assessments) must never mark a measure `cumple`: absence of
    # findings is not evidence of compliance, and a clean check is only `parcial`.
    await client.call_tool(
        "run_scans", {"target": str(CLEAN_TARGET), "checks": CHECK_IDS}
    )
    result = await client.call_tool("evaluate_compliance", {})
    report = result.structured_content
    assert report["summary"]["cumple"] == 0
    assert report["summary"]["coverage_pct"] > 0


async def test_render_report_writes_files(client: Client, tmp_path: Path) -> None:
    # Evaluate first so the report falls back to the last evaluated report.
    await client.call_tool("evaluate_compliance", {})
    result = await client.call_tool(
        "render_report",
        {"formats": ["md", "json", "html"], "output_dir": str(tmp_path)},
    )
    written = result.data
    assert len(written) == 3
    names = {Path(path).name for path in written}
    assert names == {"informe-ens.md", "informe-ens.json", "informe-ens.html"}
    for path in written:
        assert Path(path).is_file()


async def test_catalog_and_methodology_resources(client: Client) -> None:
    catalog = await client.read_resource("ens://catalog")
    assert '"measure_count": 73' in catalog[0].text

    measure = await client.read_resource("ens://catalog/measures/op.acc.1")
    assert '"code": "op.acc.1"' in measure[0].text

    guide = await client.read_resource("ens://guides/CCN-STIC-807")
    assert "CCN-STIC-807" in guide[0].text

    methodology = await client.read_resource("ens://methodology")
    assert "ENS audit methodology" in methodology[0].text


async def test_prompts(client: Client) -> None:
    methodology = await client.get_prompt("audit_methodology", {"target": "srv-01"})
    assert methodology.messages
    assert "srv-01" in methodology.messages[0].content.text

    outline = await client.get_prompt("report_outline", {"categoria": "ALTA"})
    assert outline.messages
    assert "ALTA" in outline.messages[0].content.text
