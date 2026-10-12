"""Integration tests for the source-code scanners.

Each test runs an explicit set of ``code.*`` scanner ids against the fixtures so
results stay isolated from any other scanners (e.g. the infra ones) that may be
registered in the same process.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

import ens_audit.checks.code as code_checks
from ens_audit.checks.code import SCANNERS
from ens_audit.checks.registry import register, run_scans
from ens_audit.models import EvidenceKind

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "code"
VULNERABLE = FIXTURES / "vulnerable"
CLEAN = FIXTURES / "clean"

CODE_IDS = [scanner.id for scanner in SCANNERS]

#: Rule kinds the vulnerable fixture is expected to trigger.
EXPECTED_KINDS = {
    "secret.hardcoded",
    "dependency.outdated",
    "crypto.weak_algorithm",
    "transport.tls_missing",
    "logging.audit_disabled",
    "injection.sql",
    "injection.command",
}


@pytest.fixture(autouse=True)
def _ensure_code_scanners_registered() -> Iterator[None]:
    """Re-register the code scanners before each test.

    Other test modules legitimately clear the global registry for isolation, so
    we make sure ours are present without ever calling ``clear_registry``.
    ``register`` is a no-op for an instance that is already registered.
    """
    for scanner in SCANNERS:
        register(scanner)
    yield


def _kinds(report) -> set[str]:
    return {finding.id for finding in report.findings}


def test_code_scanners_registered_with_code_category() -> None:
    assert set(CODE_IDS) == {
        "code.secrets",
        "code.dependencies",
        "code.crypto",
        "code.logging",
        "code.sast",
    }
    assert len(CODE_IDS) == len(set(CODE_IDS))
    for scanner in SCANNERS:
        assert scanner.category == "code"
        assert scanner.description


def test_vulnerable_fixture_triggers_expected_kinds() -> None:
    report = run_scans(VULNERABLE, check_ids=CODE_IDS)

    assert report.scanners == CODE_IDS
    assert report.findings
    assert EXPECTED_KINDS <= _kinds(report)

    for finding in report.findings:
        # Every finding carries file:line evidence, an ENS measure mapping and
        # is attributed to the scanner that produced it.
        assert finding.evidence
        assert all(e.kind is EvidenceKind.FILE_LINE for e in finding.evidence)
        assert all(":" in e.location for e in finding.evidence)
        assert finding.measure_codes, f"{finding.id!r} has no ENS measure mapping"
        assert finding.scanner in CODE_IDS


def test_clean_fixture_produces_no_findings() -> None:
    report = run_scans(CLEAN, check_ids=CODE_IDS)

    assert report.scanners == CODE_IDS
    assert report.findings == []
    assert _kinds(report) == set()


def test_clean_fixture_emits_positive_evidence() -> None:
    report = run_scans(CLEAN, check_ids=CODE_IDS)

    assert report.findings == []
    assert report.scanner_status == {sid: "completed" for sid in CODE_IDS}
    assert {check.scanner for check in report.evidence} == set(CODE_IDS)
    for check in report.evidence:
        assert check.checked
        assert "file" in check.scope
        assert check.observed_at is not None
        assert check.measure_codes
        assert check.result == "pass"


def test_no_source_files_skips_code_scanners(tmp_path: Path) -> None:
    # A non-source file leaves every code scanner with nothing to inspect.
    (tmp_path / "README.md").write_text("nothing to see here", encoding="utf-8")

    report = run_scans(tmp_path, check_ids=CODE_IDS)

    assert report.findings == []
    assert report.evidence == []
    assert report.scanner_status == {sid: "skipped" for sid in CODE_IDS}


def test_evidence_excludes_failed_measures(tmp_path: Path) -> None:
    # A weak hash trips crypto.weak_algorithm (mp.si.2 + mp.com.2) but nothing
    # else, so the scanner must still certify transport.tls_missing measures.
    (tmp_path / "app.py").write_text(
        "import hashlib\n\nh = hashlib.md5(b'x')\n", encoding="utf-8"
    )

    report = run_scans(tmp_path, check_ids=["code.crypto"])

    assert report.evidence, "the clean part of the coverage must be certified"
    for check in report.evidence:
        assert check.measure_codes == ["mp.com.3"]


def test_sast_does_not_certify_without_source_code(tmp_path: Path) -> None:
    """C2: a manifest is not source code, so ``mp.sw.1`` is not certified."""
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'demo'\nversion = '0.0.0'\n", encoding="utf-8"
    )

    report = run_scans(tmp_path, check_ids=["code.sast"])

    assert report.findings == []
    assert report.evidence == []
    assert report.scanner_status == {"code.sast": "skipped"}


def test_crypto_does_not_certify_from_a_dependency_manifest(tmp_path: Path) -> None:
    """C2: naming a crypto library in a manifest certifies no crypto measure."""
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        "name = 'demo'\n"
        "dependencies = ['cryptography==42.0.0']\n",
        encoding="utf-8",
    )

    report = run_scans(tmp_path, check_ids=["code.crypto"])

    assert report.findings == []
    assert report.evidence == []
    assert report.scanner_status == {"code.crypto": "skipped"}


def test_logging_and_secrets_do_not_certify_from_a_manifest(
    tmp_path: Path,
) -> None:
    """C2-class: a manifest is not source code, so logging/secrets certify nothing.

    A clean pass over ``pyproject.toml`` must not yield evidence for ``op.exp.8``
    (logging), ``op.exp.10`` / ``mp.si.2`` (secrets).
    """
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'demo'\nversion = '0.0.0'\n", encoding="utf-8"
    )

    report = run_scans(tmp_path, check_ids=["code.logging", "code.secrets"])

    assert report.findings == []
    assert report.evidence == []
    assert report.scanner_status == {
        "code.logging": "skipped",
        "code.secrets": "skipped",
    }


def test_scans_are_deterministic() -> None:
    first = run_scans(VULNERABLE, check_ids=CODE_IDS)
    second = run_scans(VULNERABLE, check_ids=CODE_IDS)

    fingerprint = lambda report: sorted(
        (f.id, f.evidence[0].location) for f in report.findings
    )
    assert fingerprint(first) == fingerprint(second)


def test_scanner_modules_importable() -> None:
    """The package exposes its scanner instances for tooling and tests."""
    assert code_checks.SCANNERS == tuple(SCANNERS)


def test_is_source_code_helper_lives_in_common() -> None:
    """R1-T10: the source-code predicate now lives with the file-walking code."""
    from ens_audit.checks.code._common import SOURCE_CODE_SUFFIXES, is_source_code
    from ens_audit.checks.code.sast import is_source_code as sast_is_source_code

    assert is_source_code(Path("app.py"))
    assert is_source_code(Path("component.tsx"))
    assert not is_source_code(Path("pyproject.toml"))
    assert not is_source_code(Path("package.json"))
    assert ".py" in SOURCE_CODE_SUFFIXES
    assert ".toml" not in SOURCE_CODE_SUFFIXES
    # ``sast`` re-exports the helper for existing importers (e.g. crypto.py).
    assert sast_is_source_code is is_source_code


def test_target_named_like_an_excluded_dir_is_still_scanned(tmp_path: Path) -> None:
    """B1: a target dir called ``build`` must not exclude every file it holds.

    The excluded-directory filter must look only at the parts *below* the scan
    target; otherwise scanning a checkout whose top directory happens to be
    named ``build``/``dist``/``venv`` silently yields an empty report.
    """
    source = (VULNERABLE / "secrets.py").read_text(encoding="utf-8")
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    (build_dir / "secrets.py").write_text(source, encoding="utf-8")
    other_dir = tmp_path / "src"
    other_dir.mkdir()
    (other_dir / "secrets.py").write_text(source, encoding="utf-8")

    build_report = run_scans(build_dir, check_ids=["code.secrets"])
    other_report = run_scans(other_dir, check_ids=["code.secrets"])

    assert build_report.findings, "target named 'build' produced no findings"
    # Same file: the findings (kind and line) are identical regardless of the
    # directory name. Only the absolute path prefix differs.
    def fingerprint(report) -> list[tuple[str, str]]:
        return sorted(
            (f.id, f.evidence[0].location.rsplit(":", 1)[-1])
            for f in report.findings
        )

    assert fingerprint(build_report) == fingerprint(other_report)
