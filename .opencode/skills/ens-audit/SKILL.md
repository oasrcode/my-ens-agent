---
name: ens-audit
description: Use when auditing a system, repository or application against the Spanish ENS (Esquema Nacional de Seguridad, RD 311/2022 / Anexo II) and the CCN-STIC 800-series guides; derives the system category from the five security dimensions, runs the deterministic scanners, records qualitative assessments for non-automatable measures, evaluates the 73 measures and renders a compliance report. Triggers on "audit ENS", "ENS compliance", "RD 311/2022", "Anexo II", "CCN-STIC", "declare applicability", "informe ENS".
---

# ENS audit

End-to-end methodology for auditing a system against the ENS (RD 311/2022, Anexo II)
with the `ens-audit` MCP server. The server provides the deterministic core (catalog,
applicability, 10 scanners, evaluator, report renderers); you provide the judgement.
All tool/resource calls are prefixed `ens-audit_` in opencode.

Announce: "I'm using the ens-audit skill."

## When to use

Use this skill whenever you must decide **what an ENS system complies with** and
produce evidence: categorising a system, checking source code / infrastructure
configuration for ENS measures, filling the documentary and organizational gaps a
scanner cannot cover, or generating the Markdown/JSON/HTML compliance report.

## Workflow (do it in this order)

1. **Scope the target.** Identify the system under audit and the attack surface
   (source code path and/or infrastructure/config path). Confirm what is in scope;
   the report audits all 73 Anexo II measures, so scope is about *evidence*, not
   about trimming the catalog.

2. **Derive the category.** Value the five dimensions — Confidencialidad,
   Integridad, Disponibilidad, Autenticidad, Trazabilidad — at `BAJO`/`MEDIO`/`ALTO`
   and call `catalog_compute_applicability` with a `dimensiones` map. This returns
   the derived `categoria` and the applicable measures with their activated
   `refuerzos`. The category rule: `ALTA` if any dimension is `ALTA`, else `MEDIA`
   if any is `MEDIA`, else `BASICA`. If the user already fixed the category, you can
   pass `categoria` directly to `evaluate_compliance` instead.

3. **Inspect the catalog as needed.** Use `catalog_list_measures` to find measures
   (filter by `marco` `org`/`op`/`mp`, by `familia`, or by `categoria`) and
   `catalog_get_measure` for one measure's requirements, refuerzos and related
   CCN-STIC guides. Do not dump the whole catalog into context; query what you need.

4. **Run the deterministic scanners.** Call `run_scans(target=<path>)`; omit
   `checks` to run all 10, or pass scanner ids: `code.secrets`, `code.crypto`,
   `code.sast`, `code.dependencies`, `code.logging`, `infra.web`,
   `infra.dockerfile`, `infra.backup`, `infra.terraform`, `infra.compose`. The
   returned `ScanReport` is stored as the session's last scan. Findings carry the
   ENS `measure_codes` they concern and their evidence; see
   [`references/mapping.md`](references/mapping.md) for the kind → measure table.

5. **Assess what scanners cannot evidence.** For documentary, organizational or
   physical measures (see *Non-automatable measures* below) call
   `record_assessment(measure_code, verdict, notes, evidence)` with the appropriate
   verdict and a rationale. Repeat once per measure. This is where human/agent
   judgement enters the report; explicit assessments override scan verdicts.

6. **Evaluate.** Call `evaluate_compliance` (no arguments reuses the last scan and
   every assessment recorded this session; pass `categoria` to enable `NO_APLICA`).
   It returns exactly one verdict per catalog measure (73) plus the aggregate summary
   and compliance percentage, and stores the report for rendering.

7. **Render.** Call `render_report(formats=["md","json","html"], output_dir=...)` to
   write `informe-ens.{md,json,html}`; it defaults to the last evaluated report, all
   three formats, and the working directory. Report structure and verdict semantics:
   [`references/report-format.md`](references/report-format.md).

## MCP tools (7)

| Tool | Signature | When to call |
| --- | --- | --- |
| `catalog_list_measures` | `(marco?, familia?, categoria?)` | Discover/filter measures (read-only). |
| `catalog_get_measure` | `(code)` | Full detail for one measure. |
| `catalog_compute_applicability` | `(dimensiones)` | Derive category + applicable measures/refuerzos. |
| `run_scans` | `(target, checks?)` | Run scanners over a path; stores last scan. |
| `record_assessment` | `(measure_code, verdict, notes?, evidence?)` | Record a manual verdict for a measure. |
| `evaluate_compliance` | `(scan_report?, assessments?, categoria?)` | Consolidate into the 73-measure report. |
| `render_report` | `(report?, formats?, output_dir?)` | Write md/json/html and return absolute paths. |

`dimensiones` keys accept the dimension name or its letter (`C`/`I`/`D`/`A`/`T`),
case-insensitively; values are `BAJO`/`MEDIO`/`ALTO`. `evidence` items are
`{"kind": "file_line"|"config"|"note", "location": "...", "detail": "..."}`.

## Resources (4)

- `ens://catalog` — provenance metadata and every measure summary.
- `ens://catalog/measures/{code}` — one measure with requirements, refuerzos and guides.
- `ens://guides/{guide_id}` — one CCN-STIC guide (e.g. `CCN-STIC-808`) and the
  measures it helps to evidence.
- `ens://methodology` — the written audit methodology (Markdown text).

Read `ens://catalog/measures/{code}` when a verdict needs the exact requirement text
or the guide list, and `ens://guides/CCN-STIC-808` for the measure-by-measure
verification checklist.

## Prompts (2)

- `audit_methodology(target)` — guided walkthrough of a full audit for `target`.
- `report_outline(categoria)` — outline skeleton for a report of a given category.

## Verdict semantics

Every measure ends with exactly one verdict: `cumple`, `no_cumple`, `parcial`,
`no_aplica` or `no_evaluable`. Resolved in precedence order:

1. **Explicit assessment** — an `Assessment` (from `record_assessment`) wins over everything.
2. **Applicability** — when `categoria` is given, measures not applicable to it are `no_aplica`.
3. **Scanner findings** — findings aggregated by `measure_codes`: any failing signal only → `no_cumple`; only positive signals → `cumple`; both → `parcial`. A finding is a *failure signal* unless its severity is `info` (INFO is a passing/positive signal).
4. **No automated evidence** — a non-automatable measure with no findings and no assessment → `no_evaluable`.
5. **Default** — any other measure with no findings → `cumple`.

Absence of evidence is not compliance: measures a scanner cannot see become
`no_evaluable`, not `cumple`.

## Non-automatable measures (auto `no_evaluable`)

These families have no machine-checkable evidence and must be covered by
`record_assessment` to avoid `no_evaluable`:

- `org.*` — organizational marco (policy, norms, procedures, roles).
- `op.pl.1` — risk analysis (documented management activity).
- `op.cont.*` — service continuity (impact analysis, plans, drills).
- `mp.if.*` — facilities and physical infrastructure.
- `mp.eq.*` — physical protection of equipment/workstations.
- `mp.per.*` — personnel duties, awareness and training.
- `mp.info.2` — information classification (organizational decision).
- `mp.si.1` — media marking (physical/organizational control).

They still evaluate normally if they have findings or an explicit assessment.
