"""Tests for the scanner framework, registry and ENS measure mapping."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from ens_audit.catalog.loader import load_catalog
from ens_audit.catalog.models import Catalog
from ens_audit.checks import (
    Scanner,
    ScannerResult,
    covered_measures,
    known_kinds,
    measures_for,
    register,
    run_scans,
    validate_mapping,
)
from ens_audit.checks.base import finalize_scan
from ens_audit.checks.registry import clear_registry, get_scanner, list_scanners
from ens_audit.models import Evidence, EvidenceKind, Finding, ScanReport, Severity

CATALOG_PATH = Path(__file__).resolve().parents[1] / "data" / "ens_anexo_ii_oscal.json"


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return load_catalog(CATALOG_PATH)


@pytest.fixture(autouse=True)
def _isolated_registry() -> Iterator[None]:
    """Keep each test's registry mutations local."""
    clear_registry()
    yield
    clear_registry()


class DummyScanner(Scanner):
    """Synthetic scanner used only to exercise the framework."""

    id = "dummy.scanner"
    description = "Emit one synthetic finding for framework tests."
    category = "code"
    covers = ("secret.hardcoded",)

    def run(self, target: Path) -> list[Finding]:
        return [
            Finding(
                id="dummy.rule.1",
                severity=Severity.LOW,
                message=f"synthetic finding for {target.name}",
                measure_codes=[ref.code for ref in measures_for("secret.hardcoded")],
                evidence=[
                    Evidence(
                        kind=EvidenceKind.NOTE,
                        location=str(target),
                        detail="synthetic evidence",
                    )
                ],
            )
        ]


def test_dummy_scanner_registered_and_aggregated(tmp_path: Path) -> None:
    scanner = register(DummyScanner)

    assert get_scanner("dummy.scanner") is scanner
    assert scanner in list_scanners()

    report = run_scans(tmp_path)

    assert isinstance(report, ScanReport)
    assert report.target == str(tmp_path)
    assert report.scanners == ["dummy.scanner"]
    assert report.timestamp is not None

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.id == "dummy.rule.1"
    # The registry stamps the originating scanner id onto the finding.
    assert finding.scanner == "dummy.scanner"
    assert finding.measure_codes == ["op.exp.10", "mp.si.2"]


def test_run_scans_filters_and_rejects_unknown(tmp_path: Path) -> None:
    register(DummyScanner)

    selected = run_scans(tmp_path, check_ids=["dummy.scanner"])
    assert selected.scanners == ["dummy.scanner"]

    with pytest.raises(KeyError):
        run_scans(tmp_path, check_ids=["does.not.exist"])


def test_measures_for_known_and_unknown() -> None:
    assert measures_for("no.such.kind") == []
    codes = {ref.code for ref in measures_for("secret.hardcoded")}
    assert codes == {"op.exp.10", "mp.si.2"}
    assert all(ref.rationale for ref in measures_for("secret.hardcoded"))


def test_storage_and_backup_kinds_are_not_conflated() -> None:
    """B2: unencrypted storage (mp.si.2) and disabled backups (mp.info.6) are
    distinct controls and must not share a rule kind."""
    assert {ref.code for ref in measures_for("storage.unencrypted")} == {"mp.si.2"}
    assert {ref.code for ref in measures_for("backup.disabled")} == {"mp.info.6"}
    assert "backup.disabled" in known_kinds()


def test_mapping_codes_validate_against_catalog(catalog: Catalog) -> None:
    assert validate_mapping(catalog) == {}

    for kind in known_kinds():
        refs = measures_for(kind)
        assert refs, f"mapping kind {kind!r} has no measures"
        for ref in refs:
            assert ref.code in catalog.medidas, f"{kind!r} -> unknown {ref.code!r}"
            assert ref.rationale


def test_validate_mapping_detects_unknown_codes(catalog: Catalog) -> None:
    empty = catalog.model_copy(update={"medidas": {}})
    problems = validate_mapping(empty)
    assert problems
    assert all(codes for codes in problems.values())


# -- coverage, status and positive evidence -----------------------------------


def test_scanner_result_defaults() -> None:
    result = ScannerResult()
    assert result.findings == []
    assert result.errors == []
    assert result.evidence == []
    assert result.status == "completed"


def test_covered_measures_is_the_union_of_the_table() -> None:
    expected = {ref.code for kind in known_kinds() for ref in measures_for(kind)}
    assert covered_measures() == expected
    assert covered_measures(), "the mapping must cover at least one measure"


def test_scanner_coverage_measures_resolves_covers() -> None:
    assert DummyScanner.covers == ("secret.hardcoded",)
    assert DummyScanner().coverage_measures() == {"op.exp.10", "mp.si.2"}


class CleanEvidenceScanner(Scanner):
    """Scanner that examined files and only emits positive evidence."""

    id = "clean.evidence"
    description = "Emit positive evidence for two examined files."
    category = "code"
    covers = ("secret.hardcoded",)

    def run(self, target: Path) -> ScannerResult:
        return finalize_scan(
            self,
            target,
            [],
            evaluated_kinds=("secret.hardcoded",),
            examined=2,
            checked="scanned two files, all clean",
        )


class PartialCoverageScanner(Scanner):
    """Scanner that flags one covered measure and certifies the rest clean."""

    id = "partial.coverage"
    description = "Flag logging, certify secrets clean."
    category = "code"
    covers = ("secret.hardcoded", "logging.audit_disabled")

    def run(self, target: Path) -> ScannerResult:
        finding = Finding(
            id="logging.audit_disabled",
            severity=Severity.MEDIUM,
            message="no audit logging",
            measure_codes=[
                ref.code for ref in measures_for("logging.audit_disabled")
            ],
        )
        return finalize_scan(
            self,
            target,
            [finding],
            evaluated_kinds=("secret.hardcoded", "logging.audit_disabled"),
            examined=1,
            checked="checked",
        )


class AllCoveredFailScanner(Scanner):
    """Scanner whose only covered measure always fails."""

    id = "all.fail"
    description = "Always flag the only covered measure."
    category = "code"
    covers = ("secret.hardcoded",)

    def run(self, target: Path) -> ScannerResult:
        finding = Finding(
            id="secret.hardcoded",
            severity=Severity.HIGH,
            message="hardcoded secret",
            measure_codes=[ref.code for ref in measures_for("secret.hardcoded")],
        )
        return finalize_scan(
            self,
            target,
            [finding],
            evaluated_kinds=("secret.hardcoded",),
            examined=1,
            checked="checked",
        )


class SkippedScanner(Scanner):
    """Scanner that found no relevant artifact to inspect."""

    id = "skipped.scanner"
    description = "Nothing relevant to inspect."
    category = "code"
    covers = ("secret.hardcoded",)

    def run(self, target: Path) -> ScannerResult:
        return finalize_scan(
            self,
            target,
            [],
            evaluated_kinds=("secret.hardcoded",),
            examined=0,
            checked="never emitted",
        )


class RaisingScanner(Scanner):
    """Scanner whose run always raises, to exercise failure isolation."""

    id = "raising.scanner"
    description = "Always raises."
    category = "code"
    covers = ("secret.hardcoded",)

    def run(self, target: Path) -> list[Finding]:
        raise RuntimeError("boom")


def test_clean_scanner_emits_positive_evidence(tmp_path: Path) -> None:
    register(CleanEvidenceScanner)

    report = run_scans(tmp_path, check_ids=["clean.evidence"])

    assert report.scanner_status == {"clean.evidence": "completed"}
    assert len(report.evidence) == 1
    check = report.evidence[0]
    assert check.scanner == "clean.evidence"
    assert check.measure_codes == ["mp.si.2", "op.exp.10"]
    assert check.checked == "scanned two files, all clean"
    assert check.scope == f"{tmp_path} (2 files)"
    assert check.result == "pass"
    assert check.observed_at is not None


def test_evidence_excludes_measures_that_failed(tmp_path: Path) -> None:
    register(PartialCoverageScanner)

    report = run_scans(tmp_path, check_ids=["partial.coverage"])

    assert len(report.evidence) == 1
    # op.exp.8 (logging) failed, so it is not certified; secrets measures remain.
    assert report.evidence[0].measure_codes == ["mp.si.2", "op.exp.10"]


def test_no_evidence_when_all_covered_measures_fail(tmp_path: Path) -> None:
    register(AllCoveredFailScanner)

    report = run_scans(tmp_path, check_ids=["all.fail"])

    assert report.findings
    assert report.evidence == []
    assert report.scanner_status == {"all.fail": "completed"}


class TwoKindCleanScanner(Scanner):
    """Clean scanner that evaluated two distinct kinds."""

    id = "two.kind.clean"
    description = "Certify secrets and logging clean."
    category = "code"
    covers = ("secret.hardcoded", "logging.audit_disabled")

    def run(self, target: Path) -> ScannerResult:
        return finalize_scan(
            self,
            target,
            [],
            evaluated_kinds=("secret.hardcoded", "logging.audit_disabled"),
            examined=1,
            checked="checked both kinds",
        )


class PartialEvalScanner(Scanner):
    """Covers two kinds but only actually evaluated one of them."""

    id = "partial.eval"
    description = "Evaluate only the secrets kind."
    category = "code"
    covers = ("secret.hardcoded", "logging.audit_disabled")

    def run(self, target: Path) -> ScannerResult:
        return finalize_scan(
            self,
            target,
            [],
            evaluated_kinds=("secret.hardcoded",),
            examined=1,
            checked="checked secrets only",
        )


def test_positive_evidence_is_emitted_per_evaluated_kind(tmp_path: Path) -> None:
    """B1: one CheckEvidence per evaluated kind, each with only its measures."""
    register(TwoKindCleanScanner)

    report = run_scans(tmp_path, check_ids=["two.kind.clean"])

    assert report.scanner_status == {"two.kind.clean": "completed"}
    assert len(report.evidence) == 2
    measure_sets = sorted(tuple(check.measure_codes) for check in report.evidence)
    assert measure_sets == [("mp.si.2", "op.exp.10"), ("op.exp.8",)]


def test_covered_but_unevaluated_kind_is_not_certified(tmp_path: Path) -> None:
    """B1: declaring a kind in ``covers`` is not the same as having checked it."""
    register(PartialEvalScanner)

    report = run_scans(tmp_path, check_ids=["partial.eval"])

    assert len(report.evidence) == 1
    assert report.evidence[0].measure_codes == ["mp.si.2", "op.exp.10"]
    assert all("op.exp.8" not in check.measure_codes for check in report.evidence)


def test_skipped_scanner_emits_no_evidence(tmp_path: Path) -> None:
    register(SkippedScanner)

    report = run_scans(tmp_path, check_ids=["skipped.scanner"])

    assert report.findings == []
    assert report.evidence == []
    assert report.scanner_status == {"skipped.scanner": "skipped"}


def test_raising_scanner_is_isolated_and_has_no_coverage(tmp_path: Path) -> None:
    register(RaisingScanner)
    register(DummyScanner)

    report = run_scans(tmp_path)

    assert report.scanner_status == {
        "raising.scanner": "failed",
        "dummy.scanner": "completed",
    }
    # The failed scanner contributes no finding and no evidence.
    assert {finding.scanner for finding in report.findings} == {"dummy.scanner"}
    assert all(check.scanner != "raising.scanner" for check in report.evidence)
