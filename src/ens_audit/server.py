"""ENS audit MCP server (stdio).

Exposes the deterministic ENS-audit core over the Model Context Protocol with
FastMCP 4:

* the 73-measure catalog (RD 311/2022, Anexo II) and its applicability engine;
* the 10 built-in scanners, the compliance evaluator and the report renderers;
* the opt-in external scanners (OSV-Scanner / Semgrep / Trivy) plus SARIF
  import, for verification-grade evidence when those tools are available.

The server speaks MCP over **stdio**, so it must never write to stdout; all
diagnostics go through the MCP logging notifications or stderr.

The catalog is parsed once per process (module-level lazy singleton). Mutable
audit-session state (last scan, recorded assessments and last evaluated report)
lives in the FastMCP lifespan context, shared by every request of the process.

Typical use::

    uv run fastmcp run src/ens_audit/server.py:mcp
    uv run python -m ens_audit.server
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Any

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ResourceError, ToolError
from fastmcp.prompts import Message
from fastmcp.server.lifespan import lifespan
from pydantic import BaseModel, Field

from ens_audit.catalog.applicability import ApplicabilityResult, compute_applicability
from ens_audit.catalog.loader import load_catalog
from ens_audit.catalog.models import (
    AplicacionPor,
    Catalog,
    Categoria,
    Dimension,
    Medida,
    Nivel,
    Refuerzo,
    Requisito,
    SeleccionRefuerzo,
)

# Importing the scanner packages registers the 10 built-in scanners in the
# global registry, so ``run_scans`` can discover them. The external package
# additionally registers the opt-in ``external.*`` scanners: they are selectable
# by id but excluded from the default ``run_scans`` selection.
from ens_audit.checks import code as _checks_code  # noqa: F401
from ens_audit.checks import external as _checks_external  # noqa: F401
from ens_audit.checks import infra as _checks_infra  # noqa: F401
from ens_audit.checks.external import import_sarif as _import_sarif
from ens_audit.checks.registry import run_scans as _run_scans
from ens_audit.evaluate import evaluate_compliance as _evaluate_compliance
from ens_audit.guides import Guide, get_guide, guides_for_measure
from ens_audit.models import Assessment, ComplianceReport, Evidence, ScanReport, Verdict
from ens_audit.report import render_report as _render_report

__all__ = ["main", "mcp"]

#: Repository root derived from this module's location
#: (``<root>/src/ens_audit/server.py`` -> ``<root>``).
_REPO_ROOT = Path(__file__).resolve().parents[2]

#: Default catalog path, resolved from the repository layout.
_DEFAULT_CATALOG_PATH = _REPO_ROOT / "data" / "ens_anexo_ii_oscal.json"

#: Uniform dimension level used when only a category is known. Mirrors the
#: evaluator's documented upper-bound valuation (BASICA/MEDIA/ALTA).
_LEVEL_FOR_CATEGORY: dict[Categoria, Nivel] = {
    Categoria.BASICA: Nivel.BAJO,
    Categoria.MEDIA: Nivel.MEDIO,
    Categoria.ALTA: Nivel.ALTO,
}

#: Accepted aliases for the five security dimensions (name and single letter).
_DIMENSION_ALIASES: dict[str, Dimension] = {
    "confidencialidad": Dimension.CONFIDENCIALIDAD,
    "c": Dimension.CONFIDENCIALIDAD,
    "integridad": Dimension.INTEGRIDAD,
    "i": Dimension.INTEGRIDAD,
    "disponibilidad": Dimension.DISPONIBILIDAD,
    "d": Dimension.DISPONIBILIDAD,
    "autenticidad": Dimension.AUTENTICIDAD,
    "a": Dimension.AUTENTICIDAD,
    "trazabilidad": Dimension.TRAZABILIDAD,
    "t": Dimension.TRAZABILIDAD,
}


# --------------------------------------------------------------------------- #
# Catalog loading (once per process) and lifespan state
# --------------------------------------------------------------------------- #
_CATALOG: Catalog | None = None


def _catalog_path() -> Path:
    """Resolve the catalog path from ``ENS_CATALOG_PATH`` or the repo layout."""
    override = os.environ.get("ENS_CATALOG_PATH")
    return Path(override) if override else _DEFAULT_CATALOG_PATH


def get_catalog() -> Catalog:
    """Load and cache the ENS catalog for the lifetime of the process."""
    global _CATALOG
    if _CATALOG is None:
        path = _catalog_path()
        if not path.is_file():
            raise ToolError(
                f"ENS catalog not found at {path}; set ENS_CATALOG_PATH to override."
            )
        _CATALOG = load_catalog(path)
    return _CATALOG


class AuditState:
    """Mutable per-process audit-session state held by the lifespan."""

    def __init__(self, catalog: Catalog) -> None:
        self.catalog = catalog
        self.last_scan: ScanReport | None = None
        self.assessments: dict[str, Assessment] = {}
        self.last_report: ComplianceReport | None = None

    def reset(self) -> None:
        """Clear all mutable audit state (keeps the catalog)."""
        self.last_scan = None
        self.assessments.clear()
        self.last_report = None


@lifespan
async def _app_lifespan(server: FastMCP):
    """Load the catalog and expose the shared audit state to every request."""
    state = AuditState(catalog=get_catalog())
    try:
        yield {"state": state}
    finally:
        state.reset()


mcp = FastMCP("ens-audit", lifespan=_app_lifespan)


# Fallback state for callers that bypass the lifespan (e.g. direct calls or a
# unit test that invokes a helper without a request context).
_FALLBACK_STATE: AuditState | None = None


def _state(ctx: Context | None) -> AuditState:
    """Return the lifespan-scoped audit state, falling back to a process one."""
    if ctx is not None:
        state = ctx.lifespan_context.get("state")
        if isinstance(state, AuditState):
            return state
    global _FALLBACK_STATE
    if _FALLBACK_STATE is None:
        _FALLBACK_STATE = AuditState(catalog=get_catalog())
    return _FALLBACK_STATE


# --------------------------------------------------------------------------- #
# Structured-output models
# --------------------------------------------------------------------------- #
class MeasureSummary(BaseModel):
    """Catalog-listing view of a base measure."""

    code: str
    name: str
    marco: str
    familia: str
    familia_nombre: str
    dimensiones: list[Dimension]
    aplicacion_por: AplicacionPor
    categorias: list[Categoria] = Field(default_factory=list)
    niveles: list[Nivel] = Field(default_factory=list)
    n_refuerzos: int = 0


class MeasureDetail(BaseModel):
    """Full measure view: requirements, refuerzos, applicability and guides."""

    code: str
    name: str
    marco: str
    familia: str
    familia_nombre: str
    dimensiones: list[Dimension]
    aplicacion_por: AplicacionPor
    categorias: list[Categoria] = Field(default_factory=list)
    niveles: list[Nivel] = Field(default_factory=list)
    requisitos: list[Requisito] = Field(default_factory=list)
    refuerzos: list[Refuerzo] = Field(default_factory=list)
    seleccion: list[SeleccionRefuerzo] = Field(default_factory=list)
    guides: list[Guide] = Field(default_factory=list)


def _summary(medida: Medida) -> MeasureSummary:
    """Build the catalog-listing view of ``medida``."""
    return MeasureSummary(
        code=medida.code,
        name=medida.name,
        marco=medida.marco,
        familia=medida.familia,
        familia_nombre=medida.familia_nombre,
        dimensiones=list(medida.dimensiones),
        aplicacion_por=medida.aplicacion_por,
        categorias=list(medida.categorias),
        niveles=list(medida.niveles),
        n_refuerzos=len(medida.refuerzos),
    )


def _detail(medida: Medida) -> MeasureDetail:
    """Build the full view of ``medida``, including its related guides."""
    return MeasureDetail(
        code=medida.code,
        name=medida.name,
        marco=medida.marco,
        familia=medida.familia,
        familia_nombre=medida.familia_nombre,
        dimensiones=list(medida.dimensiones),
        aplicacion_por=medida.aplicacion_por,
        categorias=list(medida.categorias),
        niveles=list(medida.niveles),
        requisitos=list(medida.requisitos),
        refuerzos=list(medida.refuerzos),
        seleccion=list(medida.seleccion),
        guides=guides_for_measure(medida.code),
    )


def _require_measure(catalog: Catalog, code: str) -> Medida:
    """Return the measure ``code`` or raise a client-facing ``ToolError``."""
    medida = catalog.medidas.get(code)
    if medida is None:
        raise ToolError(f"Unknown ENS measure code: {code!r}.")
    return medida


def _parse_dimensions(dimensiones: dict[str, str]) -> dict[Dimension, Nivel]:
    """Coerce a ``{dimension: nivel}`` mapping into enum-keyed form.

    Keys accept the dimension name or its single letter (``C``/``I``/``D``/
    ``A``/``T``), case-insensitively. Values accept ``BAJO``/``MEDIO``/``ALTO``,
    case-insensitively.
    """
    levels: dict[Dimension, Nivel] = {}
    for raw_key, raw_value in dimensiones.items():
        key = raw_key.strip().lower()
        dimension = _DIMENSION_ALIASES.get(key)
        if dimension is None:
            raise ToolError(
                f"Unknown dimension {raw_key!r}; use one of "
                "Confidencialidad, Integridad, Disponibilidad, Autenticidad, "
                "Trazabilidad (or C/I/D/A/T)."
            )
        try:
            levels[dimension] = Nivel(str(raw_value).strip().upper())
        except ValueError as exc:
            raise ToolError(
                f"Unknown level {raw_value!r} for {raw_key!r}; use BAJO, MEDIO or ALTO."
            ) from exc
    return levels


def _parse_category(value: str) -> Categoria:
    """Coerce a category string into a :class:`Categoria`."""
    try:
        return Categoria(value.strip().upper())
    except ValueError as exc:
        raise ToolError(
            f"Unknown category {value!r}; use BASICA, MEDIA or ALTA."
        ) from exc


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #
@mcp.tool(annotations={"readOnlyHint": True})
def catalog_list_measures(
    marco: Annotated[str | None, "Filter by framework id: 'org', 'op' or 'mp'."] = None,
    familia: Annotated[
        str | None, "Filter by family id, e.g. 'op.acc' or 'mp.com'."
    ] = None,
    categoria: Annotated[
        str | None,
        "Filter measures applicable to a system category (BASICA, MEDIA, ALTA).",
    ] = None,
) -> list[MeasureSummary]:
    """List ENS catalog measures (RD 311/2022, Anexo II), optionally filtered.

    The optional ``categoria`` filter keeps only measures applicable to that
    system category, using the documented upper-bound valuation (52/68/73).
    """
    catalog = get_catalog()
    measures = list(catalog.medidas.values())

    if marco is not None:
        wanted = marco.strip().lower()
        measures = [m for m in measures if m.marco == wanted]
    if familia is not None:
        wanted = familia.strip().lower()
        measures = [m for m in measures if m.familia == wanted]
    if categoria is not None:
        category = _parse_category(categoria)
        levels = {dim: _LEVEL_FOR_CATEGORY[category] for dim in Dimension}
        applicable = set(
            compute_applicability(catalog, levels, category).measure_codes()
        )
        measures = [m for m in measures if m.code in applicable]

    return [_summary(m) for m in measures]


@mcp.tool(annotations={"readOnlyHint": True})
def catalog_get_measure(code: str) -> MeasureDetail:
    """Return one ENS measure with its requirements, refuerzos, applicability and guides."""
    return _detail(_require_measure(get_catalog(), code))


@mcp.tool(annotations={"readOnlyHint": True})
def catalog_compute_applicability(
    dimensiones: Annotated[
        dict[str, str],
        "Valued security dimensions, e.g. {'Confidencialidad': 'ALTO', 'D': 'MEDIO'}.",
    ],
) -> ApplicabilityResult:
    """Derive the system category and the applicable measures/refuerzos.

    ``dimensiones`` maps each security dimension (name or C/I/D/A/T) to its
    level (BAJO/MEDIO/ALTO). The category is derived per Anexo I: ALTA if any
    dimension is ALTA, else MEDIA if any is MEDIA, else BASICA.
    """
    levels = _parse_dimensions(dimensiones)
    if not levels:
        raise ToolError("At least one dimension level is required.")
    return compute_applicability(get_catalog(), levels)


@mcp.tool
def run_scans(
    ctx: Context,
    target: str,
    checks: Annotated[
        list[str] | None,
        "Scanner ids to run; all registered (non-external) scanners when omitted.",
    ] = None,
    include_external: Annotated[
        bool,
        "Include the opt-in external scanners (external.osv/semgrep/trivy) in "
        "the default selection. Off by default: a routine scan never runs them.",
    ] = False,
) -> ScanReport:
    """Run deterministic scanners against a directory/file and store the report.

    The resulting :class:`ScanReport` becomes the most recent scan, so a later
    ``evaluate_compliance`` call with no arguments uses it automatically.

    The optional external scanners (``external.osv`` / ``external.semgrep`` /
    ``external.trivy``) shell out to third-party tools, so they are **opt-in**:
    they only run when requested explicitly through ``checks`` or when
    ``include_external`` is true. A tool that is not installed is ``skipped``
    (no coverage, never compliance); a tool that produced parseable SARIF is
    ``completed`` even if it exited non-zero.

    R1 semantics: the report exposes the positive ``evidence`` a scanner collected
    for what it actually examined and found clean, plus each scanner's execution
    ``scanner_status`` (``completed``/``failed``/``skipped``). Absence of findings
    is *not* evidence of compliance, and a failed or skipped scanner grants no
    coverage to the measures it would have checked.
    """
    state = _state(ctx)
    try:
        report = _run_scans(Path(target), checks, include_external)
    except KeyError as exc:
        raise ToolError(str(exc)) from exc
    state.last_scan = report
    return report


@mcp.tool
def import_sarif(
    ctx: Context,
    sarif: Annotated[
        str,
        "SARIF 2.1.0 document: raw JSON text or a path to a .sarif/.json file "
        "produced elsewhere.",
    ],
    tool_name: Annotated[
        str | None, "Tool that produced the SARIF; stamped on each finding."
    ] = None,
    tool_version: Annotated[
        str | None, "Version of the producing tool, when known."
    ] = None,
    kind: Annotated[
        str | None,
        "Mapping kind for the findings (e.g. vuln.dependency, sast.finding, "
        "container.vuln, iac.misconfig). Defaults to a generic external kind "
        "that maps to no specific measure.",
    ] = None,
) -> ScanReport:
    """Import a user-provided SARIF report as findings and store the scan.

    Lets an agent bring results produced elsewhere (outside this host) into the
    audit without running any external tool. Findings use the same conventions
    as the external scanners: ``method=verified``, ``demonstrates=False`` (a
    vulnerability is a risk signal, not a proven ENS breach) and the traced
    tool name/version. ``kind`` maps them to ENS measures; the generic default
    maps to none, so they are surfaced as risks only. The resulting
    :class:`ScanReport` becomes the most recent scan for ``evaluate_compliance``.
    """
    findings = _import_sarif(
        sarif, tool_name=tool_name, tool_version=tool_version, kind=kind
    )
    report = ScanReport(
        target="<imported-sarif>",
        findings=findings,
        scanners=["external.import"],
        scanner_status={"external.import": "completed" if findings else "skipped"},
    )
    state = _state(ctx)
    state.last_scan = report
    return report


@mcp.tool
def record_assessment(
    ctx: Context,
    measure_code: Annotated[str, "ENS measure code, e.g. 'mp.com.2'."],
    verdict: Annotated[
        str,
        "Verdict: cumple, no_cumple, parcial, no_aplica or no_evaluable.",
    ],
    notes: Annotated[str, "Free-text rationale for the verdict."] = "",
    evidence: Annotated[
        list[dict[str, Any]] | None,
        "Evidence items, e.g. [{'kind': 'note', 'location': 'DA-2026'}].",
    ] = None,
) -> Assessment:
    """Record a manual assessment for a measure, overriding scan verdicts.

    The assessment is stored in the session and reused by ``evaluate_compliance``
    when no explicit ``assessments`` argument is given. Under the R1 semantics an
    explicit assessment is the only way to reach ``cumple`` for a measure that no
    scanner check covers in full; scanners never default a measure to ``cumple``.
    """
    state = _state(ctx)
    _require_measure(state.catalog, measure_code)
    try:
        parsed_verdict = Verdict(verdict.strip().lower())
    except ValueError as exc:
        allowed = ", ".join(v.value for v in Verdict)
        raise ToolError(f"Unknown verdict {verdict!r}; use one of {allowed}.") from exc
    try:
        parsed_evidence = [Evidence(**item) for item in (evidence or [])]
    except (TypeError, ValueError) as exc:
        raise ToolError(f"Invalid evidence item: {exc}") from exc

    assessment = Assessment(
        measure_code=measure_code,
        verdict=parsed_verdict,
        notes=notes or None,
        evidence=parsed_evidence,
    )
    state.assessments[measure_code] = assessment
    return assessment


@mcp.tool
def evaluate_compliance(
    ctx: Context,
    scan_report: Annotated[
        ScanReport | None,
        "Scan report to evaluate; defaults to the most recent run_scans result.",
    ] = None,
    assessments: Annotated[
        list[Assessment] | None,
        "Manual assessments; defaults to every assessment recorded this session.",
    ] = None,
    categoria: Annotated[
        str | None, "System category (BASICA, MEDIA, ALTA); enables NO_APLICA."
    ] = None,
    dimensiones: Annotated[
        dict[str, str] | None,
        "Valued security dimensions, e.g. {'Confidencialidad': 'ALTO', 'D': 'MEDIO'}; "
        "derives the category and the activated refuerzos.",
    ] = None,
) -> ComplianceReport:
    """Consolidate scans and assessments into a per-measure compliance report.

    Exactly one verdict is produced per catalog measure (73). Under the R1
    semantics absence of findings is not evidence of compliance: ``cumple`` is
    never reached by default and requires explicit positive verification (an
    assessment, or a scanner check with ``covers_all=True``). A measure a scanner
    covered and found clean is ``parcial``; no coverage, or coverage whose scanner
    failed, leaves it ``no_evaluable``.

    ``dimensiones`` maps each security dimension (name or ``C``/``I``/``D``/
    ``A``/``T``) to its level (``BAJO``/``MEDIO``/``ALTO``). When given, the
    system category and the applicable measures are derived from the valuation
    (via :func:`~ens_audit.catalog.applicability.compute_applicability`) and the
    activated refuerzos are recorded; ``categoria`` then acts as an override.
    The report ``metadata`` carries the valuation (``dimensions``), the derived
    category and the activated refuerzos (``refuerzos``).

    The ``summary`` exposes both the compliance percentage (``compliance_pct``)
    and the evaluation-coverage percentage (``coverage_pct``), and the report
    ``metadata`` carries the positive ``evidence`` and the ``scanner_status``.
    When arguments are omitted the most recent scan and the recorded assessments
    are used, and the report is stored as the last evaluated report for
    ``render_report``.
    """
    state = _state(ctx)
    effective_scan = scan_report if scan_report is not None else state.last_scan
    effective_assessments = (
        assessments if assessments is not None else list(state.assessments.values())
    )
    effective_dimensions = (
        _parse_dimensions(dimensiones) if dimensiones else None
    )
    report = _evaluate_compliance(
        state.catalog,
        effective_scan,
        effective_assessments,
        categoria,
        dimensiones=effective_dimensions,
    )
    state.last_report = report
    return report


@mcp.tool
def render_report(
    ctx: Context,
    report: Annotated[
        ComplianceReport | None,
        "Report to render; defaults to the last evaluated report.",
    ] = None,
    formats: Annotated[
        list[str] | None, "Formats to emit: md, json and/or html (all by default)."
    ] = None,
    output_dir: Annotated[
        str | None, "Destination directory; defaults to the working directory."
    ] = None,
) -> list[str]:
    """Render a compliance report to files and return their absolute paths.

    The rendered artefacts (Markdown, JSON and HTML) separate the compliance
    percentage from the evaluation-coverage percentage and include the positive
    evidence (what was checked, result, scope and date) and each scanner's status.
    """
    state = _state(ctx)
    effective_report = report if report is not None else state.last_report
    if effective_report is None:
        raise ToolError(
            "No compliance report available; call evaluate_compliance first or "
            "pass report explicitly."
        )
    chosen = formats if formats else ["md", "json", "html"]
    try:
        written = _render_report(effective_report, chosen, output_dir, state.catalog)
    except (ValueError, RuntimeError) as exc:
        raise ToolError(str(exc)) from exc
    return [str(path) for path in written]


# --------------------------------------------------------------------------- #
# Resources
# --------------------------------------------------------------------------- #
@mcp.resource("ens://catalog", mime_type="application/json")
def catalog_resource() -> dict[str, Any]:
    """The full ENS catalog: provenance metadata and every measure summary."""
    catalog = get_catalog()
    return {
        "norma": catalog.norma,
        "titulo": catalog.titulo,
        "version": catalog.version,
        "oscal_version": catalog.oscal_version,
        "uuid": catalog.uuid,
        "last_modified": catalog.last_modified,
        "fuente": catalog.fuente,
        "licencia": catalog.licencia,
        "measure_count": len(catalog.medidas),
        "measures": [
            _summary(m).model_dump(mode="json") for m in catalog.medidas.values()
        ],
    }


@mcp.resource("ens://catalog/measures/{code}", mime_type="application/json")
def measure_resource(code: str) -> dict[str, Any]:
    """One ENS measure with requirements, refuerzos, applicability and guides."""
    medida = get_catalog().medidas.get(code)
    if medida is None:
        raise ResourceError(f"Unknown ENS measure code: {code!r}.")
    return _detail(medida).model_dump(mode="json")


@mcp.resource("ens://guides/{guide_id}", mime_type="application/json")
def guide_resource(guide_id: str) -> dict[str, Any]:
    """A CCN-STIC guide and the ENS measures it helps to evidence."""
    guide = get_guide(guide_id)
    if guide is None:
        raise ResourceError(f"Unknown CCN-STIC guide id: {guide_id!r}.")
    return guide.model_dump(mode="json")


@mcp.resource("ens://methodology")
def methodology_resource() -> str:
    """A written methodology for auditing a system against the ENS."""
    return _METHODOLOGY


# --------------------------------------------------------------------------- #
# Prompts
# --------------------------------------------------------------------------- #
@mcp.prompt
def audit_methodology(target: str = "the target system") -> list[Message]:
    """Guide an agent through a full ENS audit of ``target``."""
    return [
        Message(
            "You are auditing "
            f"{target} against the ENS (RD 311/2022). Work in this order: "
            "(1) value the five dimensions (Confidencialidad, Integridad, "
            "Disponibilidad, Autenticidad, Trazabilidad) at BAJO/MEDIO/ALTO and "
            "derive the category with catalog_compute_applicability; "
            "(2) run the deterministic scanners with run_scans over the code and "
            "infrastructure of the system; "
            "(3) record the qualitative verdicts with record_assessment for "
            "measures a scanner cannot evidence; "
            "(4) call evaluate_compliance with the derived category to get the "
            "73-verdict report, which separates the compliance and coverage "
            "percentages and carries the positive evidence and scanner status; "
            "(5) render_report to emit the Markdown, JSON and HTML artefacts. "
            "For each measure cite the CCN-STIC guide that backs the evidence "
            "(ens://guides/CCN-STIC-808 is the measure-by-measure checklist)."
        )
    ]


@mcp.prompt
def report_outline(categoria: str = "MEDIA") -> list[Message]:
    """Ask an agent to write the report outline for a given category."""
    return [
        Message(
            "Write the outline of an ENS compliance report for a "
            f"{categoria} system. Sections: (1) scope and system description; "
            "(2) dimension valuation and resulting category, citing Anexo I and "
            "CCN-STIC-803; (3) methodology and evidence sources (CCN-STIC-802 "
            "audit process, CCN-STIC-808 checklist); (4) per-measure verdicts "
            "grouped by marco (org/op/mp), each with its rationale and CCN-STIC "
            "guide; (5) non-conformities and compensating measures "
            "(CCN-STIC-819); (6) conclusions and the compliance and coverage "
            "percentages. "
            "Base every claim on the evaluate_compliance report."
        )
    ]


_METHODOLOGY = """\
ENS audit methodology (RD 311/2022, Anexo II)
=============================================

1. Scope and actor model
   Identify the information system and the responsible roles (CCN-STIC-801).
   The audit verifies the measures in Anexo II as declared in the Declaracion
   de Aplicabilidad (art. 28).

2. Categorisation (Anexo I)
   Value the five dimensions -- Confidencialidad, Integridad, Disponibilidad,
   Autenticidad and Trazabilidad -- at BAJO/MEDIO/ALTO. The system category is
   ALTA if any dimension is ALTA, MEDIA if any is MEDIA and none is ALTA, and
   BASICA otherwise. Use catalog_compute_applicability to get the category, the
   applicable measures and the activated refuerzos (CCN-STIC-803).

3. Applicability
   The catalog applies measures in two ways: by category (45 measures) and by
   dimension/level (28 measures). The upper-bound counts are 52 (BASICA),
   68 (MEDIA) and 73 (ALTA) applicable measures.

4. Evidence collection
   Run the deterministic scanners with run_scans over the source code and the
   infrastructure configuration. Scanner findings map to measures via the
   built-in rule-to-measure table (see checks/mapping.py); each scanner also
   emits positive CheckEvidence for what it actually examined and found clean,
   and records its execution status (completed/failed/skipped). Measures that a
   scanner cannot evidence (documents, management processes, physical controls)
   require a manual record_assessment.

   Optional external tools (OSV-Scanner, Semgrep, Trivy) add verification-grade
   evidence: they are opt-in (run_scans(include_external=True) or an explicit
   external.osv/external.semgrep/external.trivy id) so a routine scan never
   shells out. Their findings map to measures but are non-demonstrative risk
   signals (demonstrates=False): a detected CVE caps the measure at parcial, it
   never forces no_cumple. Reports produced elsewhere can be brought in with the
   import_sarif tool, which produces the same findings.

5. Evaluation
   Call evaluate_compliance to consolidate the scan and the assessments into
   exactly one verdict per catalog measure (73). Absence of findings is not
   evidence of compliance: CUMPLE is never reached by default. Verdict
   precedence: explicit assessment, then applicability (NO_APLICA), then scanner
   signals -- failing-only NO_CUMPLE, mixed PARCIAL, positive-only PARCIAL
   (CUMPLE only when a check covers every applicable requirement) -- and finally
   NO_EVALUABLE when there is no coverage, or when the covering scanner failed.

6. Reporting
   Call render_report to emit Markdown, JSON and HTML artifacts. The summary
   separates the compliance percentage from the evaluation-coverage percentage,
   lists the positive evidence (what was checked, result, scope and date) and
   shows each scanner's status. Cite the relevant CCN-STIC guide for each
   measure; CCN-STIC-808 provides the measure-by-measure verification checklist.
"""


def main() -> None:
    """Run the server over stdio (the transport opencode expects)."""
    mcp.run()


if __name__ == "__main__":
    main()
