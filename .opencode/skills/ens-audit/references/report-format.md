# ENS report format and verdict semantics

Reference for what `render_report` produces and how `evaluate_compliance`
decides each verdict. Source of truth: `src/ens_audit/report/` and
`src/ens_audit/evaluate.py`.

## Verdicts

Five values, exactly one per catalog measure (73):

| Verdict | Spanish label | Meaning |
| --- | --- | --- |
| `cumple` | Cumple | **Every** applicable requirement verified with sufficient evidence: an explicit assessment, or a scanner check with `covers_all=true`. Never reached by default. |
| `no_cumple` | No cumple | A failing signal / explicit non-compliance. Major non-conformity. |
| `parcial` | Parcial | Mixed failing and passing signals, or a scanner-covered measure that ran clean without covering the whole measure. Minor non-conformity. |
| `no_aplica` | No aplica | Measure not applicable to the system category. Excluded from both denominators. |
| `no_evaluable` | No evaluable | No coverage, or coverage whose scanner failed, and no assessment. |

### Precedence (first match wins)

1. **Explicit assessment** — an `Assessment` from `record_assessment` is used
   verbatim (verdict, notes as rationale, evidence). Overrides everything,
   including applicability.
2. **Applicability** — when `categoria` is passed to `evaluate_compliance`,
   measures not applicable to that category are `no_aplica`.
3. **Scanner signals** — consumed via their `measure_codes`. A *positive signal*
   is a `CheckEvidence` with `result == "pass"` or an `info`-severity finding; a
   *failure signal* is any other finding:
   - failing-only → `no_cumple`;
   - failing + positive → `parcial`;
   - positive-only → `parcial`, **unless** some `CheckEvidence` has
     `covers_all=true`, which raises the measure to `cumple`.
4. **No signal at all** → `no_evaluable`, whether or not a scanner claimed
   coverage. No coverage, or coverage whose scanner failed, is `no_evaluable`.

`cumple` is never reached by default: *absence of findings is not evidence of
compliance*. A clean scanner check that does not cover the whole measure yields
`parcial`, not `cumple`.

### Percentages

- `compliance_pct = round(100 * cumple / applicable, 2)`.
- `coverage_pct = round(100 * (applicable − no_evaluable) / applicable, 2)`.

`applicable = total − no_aplica`. `no_aplica` is excluded from both denominators;
`no_evaluable` stays in both (it is neither compliance nor coverage). A high
`coverage_pct` with a low `compliance_pct` means the system was checked and found
failing, not that it complies.

## Output formats

`render_report(report?, formats?, output_dir?)` writes one file per format into
`output_dir` (defaults to the process working directory) and returns their
absolute paths. Base name `informe-ens`:

- `informe-ens.md` — `md`
- `informe-ens.json` — `json` (stable, versioned)
- `informe-ens.html` — `html` (self-contained, printable)

`formats` defaults to all three. `report` defaults to the last `evaluate_compliance`
result.

## Markdown structure

Generated in Spanish (the audit's working language); identifiers stay English.

1. Title and provenance line.
2. **Metadatos** — system, category, date, norm, catalog version.
3. **Resumen ejecutivo** — verdict counts table and **both** the compliance
   percentage and the coverage percentage.
4. **Alcance y metodología** — scope, precedence order, scanners run and their
   status, findings, positive evidence, applicable count.
5. **Categorización** — derived category and its Anexo I basis.
6. **Tabla completa de medidas** — one row per catalog measure: code, name,
   framework/family, verdict.
7. **No conformidades** — every `no_cumple` and `parcial` with rationale and
   evidence.
8. **Evidencia positiva y estado de escáneres** — what each scanner checked
   (what/result/scope/date) and each scanner's status
   (`completed`/`failed`/`skipped`).
9. **Recomendaciones** — data-driven: remediate major non-conformities, review
   partial ones, supply evidence for `no_evaluable` ones.

## JSON structure

Versioned document (`schema_version: "1.1"`), deterministic ordering (catalog
order when a catalog is available):

```json
{
  "schema_version": "1.1",
  "generated_at": "<ISO-8601 UTC>",
  "category": "MEDIA",
  "summary": {
    "total": 73, "cumple": 0, "no_cumple": 0, "parcial": 0,
    "no_aplica": 0, "no_evaluable": 0, "applicable": 0,
    "compliance_pct": 0.0, "coverage_pct": 0.0
  },
  "evidence": [
    {
      "scanner": "code.crypto",
      "measure_codes": ["mp.com.2"],
      "checked": "TLS configuration of the web endpoints",
      "scope": "src/",
      "result": "pass",
      "observed_at": "<ISO-8601 UTC>",
      "covers_all": false
    }
  ],
  "scanner_status": {"code.crypto": "completed", "infra.dockerfile": "skipped"},
  "verdicts": [
    {
      "code": "mp.com.2",
      "name": "...",
      "verdict": "cumple",
      "evidence": [{"kind": "file_line", "location": "...", "detail": ""}],
      "rationale": "..."
    }
  ]
}
```

Each `verdicts[].evidence[].kind` is one of `file_line`, `config` or `note`.

## Non-automatable families (auto `no_evaluable`)

A conservative, closed allow-list in `evaluate.py` used to enrich the rationale of
`no_evaluable` verdicts:

- `org.*` — organizational marco (policy, norms, procedures, roles).
- `op.pl.1` — risk analysis.
- `op.cont.*` — service continuity.
- `mp.if.*` — facilities and physical infrastructure.
- `mp.eq.*` — physical protection of equipment/workstations.
- `mp.per.*` — personnel duties, awareness and training.
- `mp.info.2` — information classification.
- `mp.si.1` — media marking.

Any measure with no evidence and no assessment is `no_evaluable` regardless of
family (there is no default `cumple`); this list only enriches the rationale.
Measures in these families with findings or an explicit assessment still evaluate
normally (precedence rules 1 and 3).
