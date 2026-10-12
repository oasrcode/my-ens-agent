# ENS report format and verdict semantics

Reference for what `render_report` produces and how `evaluate_compliance`
decides each verdict. Source of truth: `src/ens_audit/report/` and
`src/ens_audit/evaluate.py`.

## Verdicts

Five values, exactly one per catalog measure (73):

| Verdict | Spanish label | Meaning |
| --- | --- | --- |
| `cumple` | Cumple | Measure satisfied (or compliant by default with no findings). |
| `no_cumple` | No cumple | A failing signal / explicit non-compliance. Major non-conformity. |
| `parcial` | Parcial | Mixed failing and passing signals. Minor non-conformity. |
| `no_aplica` | No aplica | Measure not applicable to the system category. Excluded from the compliance %. |
| `no_evaluable` | No evaluable | Documentary/organizational/physical measure with no evidence and no assessment. |

### Precedence (first match wins)

1. **Explicit assessment** — an `Assessment` from `record_assessment` is used
   verbatim (verdict, notes as rationale, evidence). Overrides everything,
   including applicability.
2. **Applicability** — when `categoria` is passed to `evaluate_compliance`,
   measures not applicable to that category are `no_aplica`.
3. **Scanner findings** — findings consumed via their `measure_codes`:
   failing-only → `no_cumple`; positive-only → `cumple`; mixed → `parcial`.
   A finding is a *failure signal* unless its severity is `info`.
4. **No automated evidence** — a measure matching a non-automatable family
   (below) with no findings and no assessment → `no_evaluable`.
5. **Default** — any other measure with no findings → `cumple`.

### Compliance percentage

`compliance_pct = round(100 * cumple / applicable, 2)`, where
`applicable = total - no_aplica`. `no_aplica` measures are excluded from the
denominator; `no_evaluable` measures stay in it (they are not compliance).

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
3. **Resumen ejecutivo** — verdict counts table and the compliance percentage.
4. **Alcance y metodología** — scope, precedence order, scanners run, findings,
   applicable count.
5. **Categorización** — derived category and its Anexo I basis.
6. **Tabla completa de medidas** — one row per catalog measure: code, name,
   framework/family, verdict.
7. **No conformidades** — every `no_cumple` and `parcial` with rationale and
   evidence.
8. **Recomendaciones** — data-driven: remediate major non-conformities, review
   partial ones, supply evidence for `no_evaluable` ones.

## JSON structure

Versioned document (`schema_version: "1.0"`), deterministic ordering (catalog
order when a catalog is available):

```json
{
  "schema_version": "1.0",
  "generated_at": "<ISO-8601 UTC>",
  "category": "MEDIA",
  "summary": {
    "total": 73, "cumple": 0, "no_cumple": 0, "parcial": 0,
    "no_aplica": 0, "no_evaluable": 0, "applicable": 0, "compliance_pct": 0.0
  },
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

Each `evidence.kind` is one of `file_line`, `config` or `note`.

## Non-automatable families (auto `no_evaluable`)

A conservative, closed allow-list in `evaluate.py`; a measure here with no
findings and no assessment is reported `no_evaluable`:

- `org.*` — organizational marco (policy, norms, procedures, roles).
- `op.pl.1` — risk analysis.
- `op.cont.*` — service continuity.
- `mp.if.*` — facilities and physical infrastructure.
- `mp.eq.*` — physical protection of equipment/workstations.
- `mp.per.*` — personnel duties, awareness and training.
- `mp.info.2` — information classification.
- `mp.si.1` — media marking.

Extending the list only ever moves a no-evidence measure from `cumple` to
`no_evaluable`. Measures in these families with findings or an explicit
assessment still evaluate normally (precedence rules 1 and 3).
