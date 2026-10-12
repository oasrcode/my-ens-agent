"""Tests for the infrastructure/configuration scanners (``infra.*``).

Runs each infra scanner over the ``bad`` and ``good`` fixtures under
``tests/fixtures/infra`` with explicit ``check_ids`` so the assertions are
isolated from the source-code scanners.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from ens_audit.checks import run_scans
from ens_audit.checks.infra import SCANNERS
from ens_audit.checks.infra.dockerfile import _stage_bounds
from ens_audit.checks.registry import list_scanners, register
from ens_audit.models import EvidenceKind, ScanReport

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "infra"
BAD = FIXTURES / "bad"
GOOD = FIXTURES / "good"

#: Every infra scanner id, in registration order.
INFRA_IDS = [scanner.id for scanner in SCANNERS]

#: Rule kinds (finding ids) each scanner must trigger on the bad fixture.
BAD_EXPECTED_KINDS: dict[str, set[str]] = {
    "infra.dockerfile": {
        "config.debug_enabled",
        "dependency.outdated",
        "secret.hardcoded",
    },
    "infra.compose": {
        "config.debug_enabled",
        "network.service_exposed",
        "secret.hardcoded",
    },
    "infra.terraform": {
        "network.service_exposed",
        "storage.unencrypted",
        "logging.audit_disabled",
    },
    "infra.web": {
        "crypto.weak_algorithm",
        "transport.tls_missing",
        "config.debug_enabled",
    },
    "infra.backup": {"backup.disabled"},
}


@pytest.fixture(autouse=True)
def _ensure_registered() -> Iterator[None]:
    """Re-register the infra scanners if another test cleared the registry."""
    for scanner in SCANNERS:
        register(scanner)
    yield


def _kinds(report: ScanReport) -> set[str]:
    """Return the set of rule kinds (finding ids) in ``report``."""
    return {finding.id for finding in report.findings}


def test_infra_scanners_are_registered() -> None:
    assert set(INFRA_IDS) <= {scanner.id for scanner in list_scanners()}


@pytest.mark.parametrize(
    ("scanner_id", "expected"), sorted(BAD_EXPECTED_KINDS.items())
)
def test_bad_fixture_triggers_expected_kinds(
    scanner_id: str, expected: set[str]
) -> None:
    report = run_scans(BAD, check_ids=[scanner_id])

    assert report.scanners == [scanner_id]
    assert report.findings, f"{scanner_id} found nothing on the bad fixture"
    assert expected <= _kinds(report)


@pytest.mark.parametrize("scanner_id", sorted(BAD_EXPECTED_KINDS))
def test_good_fixture_is_clean(scanner_id: str) -> None:
    report = run_scans(GOOD, check_ids=[scanner_id])

    assert report.findings == [], (
        f"{scanner_id} unexpectedly flagged {_kinds(report)} on the good fixture"
    )


def test_good_fixture_emits_positive_evidence() -> None:
    report = run_scans(GOOD, check_ids=INFRA_IDS)

    assert report.findings == []
    assert report.scanner_status == {sid: "completed" for sid in INFRA_IDS}
    assert {check.scanner for check in report.evidence} == set(INFRA_IDS)
    for check in report.evidence:
        assert check.checked
        assert "file" in check.scope
        assert check.observed_at is not None
        assert check.measure_codes
        assert check.result == "pass"


def test_irrelevant_config_emits_no_infra_evidence(tmp_path: Path) -> None:
    """B1/B2: a lone ``pyproject.toml`` is not a backup/network/terraform
    artefact, so no infra scanner may claim coverage from it."""
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'demo'\nversion = '0.0.0'\n", encoding="utf-8"
    )

    report = run_scans(tmp_path, check_ids=INFRA_IDS)

    assert report.findings == []
    assert report.evidence == []
    assert report.scanner_status == {sid: "skipped" for sid in INFRA_IDS}


def test_backup_scanner_certifies_backup_measure_only() -> None:
    """B2: the backup scanner speaks to mp.info.6 (backups), not mp.si.2."""
    report = run_scans(GOOD, check_ids=["infra.backup"])

    assert report.findings == []
    assert len(report.evidence) == 1
    check = report.evidence[0]
    assert check.measure_codes == ["mp.info.6"]
    assert "mp.si.2" not in check.measure_codes


def test_terraform_evidence_is_per_evaluated_kind(tmp_path: Path) -> None:
    """B1: a bucket-only HCL file certifies storage/logging but not network."""
    (tmp_path / "bucket.tf").write_text(
        'resource "aws_s3_bucket" "private" {\n'
        '  bucket = "b"\n'
        '  acl    = "private"\n'
        "}\n"
        'resource "aws_s3_bucket_server_side_encryption_configuration" "private" {\n'
        '  bucket = aws_s3_bucket.private.id\n'
        "}\n"
        'resource "aws_s3_bucket_logging" "private" {\n'
        '  bucket = aws_s3_bucket.private.id\n'
        "}\n",
        encoding="utf-8",
    )

    report = run_scans(tmp_path, check_ids=["infra.terraform"])

    assert report.findings == []
    assert len(report.evidence) == 2
    certified = {code for check in report.evidence for code in check.measure_codes}
    assert certified == {"mp.si.2", "op.exp.8"}
    assert "mp.com.1" not in certified
    assert "mp.s.4" not in certified


def test_plain_http_nginx_certifies_no_crypto_or_tls(tmp_path: Path) -> None:
    """A plain-HTTP config must not certify crypto/TLS measures (mp.si.2/mp.com.*)."""
    (tmp_path / "nginx.conf").write_text(
        "server {\n"
        "    listen 80;\n"
        "    server_name example.com;\n"
        "    location / {\n"
        "        proxy_pass http://127.0.0.1:8080;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    report = run_scans(tmp_path, check_ids=["infra.web"])

    # The plain listener is a real transport finding, but no crypto/TLS check
    # was actually applied, so nothing may be certified clean.
    assert "transport.tls_missing" in _kinds(report)
    certified = {code for check in report.evidence for code in check.measure_codes}
    assert certified.isdisjoint({"mp.si.2", "mp.com.2", "mp.com.3"})


def test_backup_word_in_dependency_is_not_backup_config(tmp_path: Path) -> None:
    """A dependency named ``backup-tools`` must not claim the backup control."""
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        "name = 'demo'\n"
        "dependencies = [\n"
        "    'backup-tools>=1.0',\n"
        "    'snapshot-utils==2.0',\n"
        "]\n",
        encoding="utf-8",
    )

    report = run_scans(tmp_path, check_ids=["infra.backup"])

    assert report.findings == []
    assert report.evidence == []
    assert report.scanner_status == {"infra.backup": "skipped"}


@pytest.mark.parametrize("scanner_id", sorted(BAD_EXPECTED_KINDS))
def test_infra_scanner_skips_without_relevant_files(
    tmp_path: Path, scanner_id: str
) -> None:
    report = run_scans(tmp_path, check_ids=[scanner_id])

    assert report.findings == []
    assert report.evidence == []
    assert report.scanner_status == {scanner_id: "skipped"}


def test_all_infra_scanners_run_together() -> None:
    bad = run_scans(BAD, check_ids=INFRA_IDS)
    good = run_scans(GOOD, check_ids=INFRA_IDS)

    assert bad.scanners == INFRA_IDS
    assert bad.findings
    # ``none`` of the rule kinds fire on the good fixture.
    assert _kinds(good) == set()


def test_findings_carry_file_line_evidence_and_measures() -> None:
    report = run_scans(BAD, check_ids=INFRA_IDS)

    assert report.findings
    for finding in report.findings:
        assert finding.measure_codes, f"{finding.id} has no ENS measure codes"
        assert finding.evidence, f"{finding.id} has no evidence"
        for evidence in finding.evidence:
            assert evidence.kind is EvidenceKind.FILE_LINE
            assert ":" in evidence.location


def test_target_named_like_an_excluded_dir_is_still_scanned(tmp_path: Path) -> None:
    """B1: a target dir called ``build`` must still surface its config files."""
    dockerfile = (BAD / "Dockerfile").read_text(encoding="utf-8")
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    (build_dir / "Dockerfile").write_text(dockerfile, encoding="utf-8")

    report = run_scans(build_dir, check_ids=["infra.dockerfile"])

    assert report.findings, "target named 'build' produced no findings"
    assert BAD_EXPECTED_KINDS["infra.dockerfile"] <= _kinds(report)


#: Multi-stage build: the early stage drops privileges but the final stage
#: (the one that becomes the image) inherits root.
_MULTISTAGE_ROOT_FINAL = """\
FROM python:3.12.4-slim@sha256:1111 AS builder
USER builder
RUN python -m build

FROM python:3.12.4-slim@sha256:2222
COPY --from=builder /app /app
CMD ["python", "-m", "app"]
"""

#: Multi-stage build where the final stage does drop privileges: clean.
_MULTISTAGE_NONROOT_FINAL = """\
FROM python:3.12.4-slim@sha256:1111 AS builder
RUN python -m build

FROM python:3.12.4-slim@sha256:2222
COPY --from=builder /app /app
USER appuser
CMD ["python", "-m", "app"]
"""


def test_multistage_final_stage_without_user_is_flagged(tmp_path: Path) -> None:
    """M1: only the final stage's USER decides; a missing one runs as root."""
    (tmp_path / "Dockerfile").write_text(
        _MULTISTAGE_ROOT_FINAL, encoding="utf-8"
    )
    report = run_scans(tmp_path, check_ids=["infra.dockerfile"])

    assert "config.debug_enabled" in _kinds(report)


def test_multistage_final_stage_with_nonroot_user_is_clean(tmp_path: Path) -> None:
    """M1 counterpart: a non-root USER in the final stage is not flagged."""
    (tmp_path / "Dockerfile").write_text(
        _MULTISTAGE_NONROOT_FINAL, encoding="utf-8"
    )
    report = run_scans(tmp_path, check_ids=["infra.dockerfile"])

    assert "config.debug_enabled" not in _kinds(report)


_PINNED_IMAGE = "python:3.12.4-slim@sha256:" + "1" * 64


@pytest.mark.parametrize("user", ["root", "0", "root:root", "0:0"])
def test_root_user_variants_are_flagged(tmp_path: Path, user: str) -> None:
    """R1: the user component before an optional ``:group`` decides root."""
    (tmp_path / "Dockerfile").write_text(
        f"FROM {_PINNED_IMAGE}\nUSER {user}\n", encoding="utf-8"
    )
    report = run_scans(tmp_path, check_ids=["infra.dockerfile"])

    assert "config.debug_enabled" in _kinds(report)


@pytest.mark.parametrize("user", ["appuser", "1000", "appuser:appuser", "1000:1000"])
def test_nonroot_user_variants_are_clean(tmp_path: Path, user: str) -> None:
    """R1 counterpart: a non-root user (with or without a group) is clean."""
    (tmp_path / "Dockerfile").write_text(
        f"FROM {_PINNED_IMAGE}\nUSER {user}\n", encoding="utf-8"
    )
    report = run_scans(tmp_path, check_ids=["infra.dockerfile"])

    assert "config.debug_enabled" not in _kinds(report)


#: ``FROM`` with a trailing inline comment. The comment must not stop the line
#: from being parsed as a base image, nor from starting a new build stage.
_FROM_WITH_INLINE_COMMENT = f"""\
FROM {_PINNED_IMAGE} AS builder
RUN python -m build

FROM ubuntu:latest # base
USER app
"""


def test_from_with_inline_comment_triggers_unpinned(tmp_path: Path) -> None:
    """R2: a commented ``FROM ... :latest`` is still an unpinned base image."""
    (tmp_path / "Dockerfile").write_text(
        _FROM_WITH_INLINE_COMMENT, encoding="utf-8"
    )
    report = run_scans(tmp_path, check_ids=["infra.dockerfile"])

    assert "dependency.outdated" in _kinds(report)
    # The image reference stops before the comment (no ``# base`` swallowed).
    assert any("ubuntu:latest" in finding.message for finding in report.findings)
    # The commented ``FROM`` is a stage boundary, so ``USER app`` is the
    # final image's user and no root finding is emitted.
    assert "config.debug_enabled" not in _kinds(report)


def test_from_with_inline_comment_starts_a_stage(tmp_path: Path) -> None:
    """R2: ``_stage_bounds`` treats a commented ``FROM`` as a stage boundary."""
    assert len(_stage_bounds(_FROM_WITH_INLINE_COMMENT)) == 2
