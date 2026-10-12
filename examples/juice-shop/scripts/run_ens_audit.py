#!/usr/bin/env python3
"""CLI driver that orchestrates the installed ``ens_audit`` library.

The script is a thin orchestrator: it never reimplements scanning, evaluation
or rendering. It wires the library's public API together to scan a target,
evaluate ENS (RD 311/2022) compliance and render Markdown/JSON/HTML reports.

Usage (run from the repository root)::

    uv run --project . python examples/juice-shop/scripts/run_ens_audit.py [options]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import ens_audit.checks.code  # noqa  (registers the code scanners)
import ens_audit.checks.infra  # noqa  (registers the infra scanners)
from ens_audit.catalog.loader import load_catalog
from ens_audit.catalog.models import Categoria
from ens_audit.checks.registry import run_scans
from ens_audit.evaluate import evaluate_compliance
from ens_audit.models import Assessment
from ens_audit.report import render_report

#: Fixed OSCAL ENS catalog shipped with this repository, resolved from the repo root.
CATALOG_PATH = Path(__file__).resolve().parents[3] / "data" / "ens_anexo_ii_oscal.json"

#: Default target and output directory for the Juice Shop audit workspace (relative
#: to the current working directory, i.e. the repository root).
DEFAULT_TARGET = Path("juice-shop")
DEFAULT_OUT = Path("docs")


def parse_args() -> argparse.Namespace:
    """Parse the command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Orchestrate the ens_audit library: scan, evaluate and report."
    )
    parser.add_argument("--target", default=str(DEFAULT_TARGET), help="path to scan")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="output directory")
    parser.add_argument(
        "--categoria", choices=["BASICA", "MEDIA", "ALTA"], default=None
    )
    parser.add_argument("--dimensions", default=None, help="per-dimension JSON string")
    parser.add_argument("--assessments", default=None, help="path to assessments JSON")
    parser.add_argument(
        "--scans-only",
        dest="scans_only",
        action="store_true",
        help="only scan and dump scan-report.json; skip evaluate/render",
    )
    return parser.parse_args()


def load_assessments(path: str | None) -> list[Assessment] | None:
    """Load manual assessments from a JSON list file, or ``None`` when absent."""
    if path is None:
        return None
    file = Path(path)
    if not file.exists():
        raise SystemExit(f"error: assessments file not found: {path}")
    data = json.loads(file.read_text(encoding="utf-8"))
    return [Assessment(**item) for item in data]


def main() -> int:
    """Run the scan -> evaluate -> render pipeline and print a summary."""
    args = parse_args()
    target = Path(args.target)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    catalog = load_catalog(CATALOG_PATH)
    scan = run_scans(target, None, include_external=False)

    scan_path = out / "scan-report.json"
    scan_path.write_text(
        json.dumps(scan.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"scanned {target} -> {len(scan.findings)} finding(s)")
    print(f"wrote {scan_path}")

    if args.scans_only:
        return 0

    assessments = load_assessments(args.assessments)
    categoria = Categoria(args.categoria.upper()) if args.categoria else None
    dimensiones = json.loads(args.dimensions) if args.dimensions else None

    report = evaluate_compliance(
        catalog, scan, assessments, categoria=categoria, dimensiones=dimensiones
    )
    paths = render_report(report, ["md", "json", "html"], out, catalog=catalog)

    summary = report.summary
    print(
        "verdicts: "
        f"cumple={summary.cumple} no_cumple={summary.no_cumple} "
        f"parcial={summary.parcial} no_aplica={summary.no_aplica} "
        f"no_evaluable={summary.no_evaluable}"
    )
    print(
        f"compliance_pct={summary.compliance_pct} "
        f"coverage_pct={summary.coverage_pct}"
    )
    for path in paths:
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
