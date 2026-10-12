# `data/` — Seed dataset

## `ens_anexo_ii_oscal.json`

Official **ENS (Esquema Nacional de Seguridad) Anexo II** catalog in **OSCAL** format,
published by the **AEAD** (Agencia Española de Administración Digital) on the PAe portal
("ENS legible por máquina"). It is the seed dataset for the ENS control model.

This is a verbatim copy: the file is served by the source as `.txt` and is renamed to
`.json` here. Its contents are unmodified.

### Provenance

| Field | Value |
|---|---|
| Title | `ENS (2022) – Catálogo OSCAL: ANEXO II – Medidas de Seguridad` |
| Author / publisher | **AEAD** (Agencia Española de Administración Digital) |
| Source page | <https://administracionelectronica.gob.es/pae_Home/pae_Estrategias/pae_Seguridad_Inicio/pae_Esquema_Nacional_de_Seguridad.html> (section "ENS legible por máquina") |
| Direct download | <https://administracionelectronica.gob.es/pae_Home/dam/jcr:e8fd2caf-b77f-4bbe-9290-a628f968a9c9/ENS_Anexo_II_rev_10.txt> |
| License | **EUPL-1.2** (European Union Public License 1.2) — <https://eupl.eu/1.2/es/> |
| Catalog `version` | `1.0.0` |
| `oscal-version` | `1.1.3` |
| `last-modified` | `2026-05-12T12:56:24+02:00` |
| Catalog `uuid` | `82632e96-0c4b-509f-b90d-cd20c28dfa56` |
| Legal source | Real Decreto 311/2022 (ENS) — **BOE-A-2022-7191** — <https://www.boe.es/eli/es/rd/2022/05/03/311/con> |
| Retrieval date | **2026-10-12** |
| SHA-256 | `9f38f3258f8bb03c26447346800938d40ed461a313b849a9097bb8d523cfa330` |
| Size | 442,339 bytes |

### Retrieval method

The PAe site is behind a WAF that rejects plain `curl`/`requests` with HTTP 403
(`Location: .../general/error.htm?errorhttp=403`). The file was therefore fetched through
a real browser session (Playwright Chromium): navigate to the source page to establish a
session, then `fetch()` the direct download URL from within the page context. See the
retrieval notes in `docs/research/ens-catalog.md` §2.3.

To refresh this dataset, re-run the same browser-based download and update the
`last-modified`, SHA-256 and retrieval date in this file if they change.

### Structure and verified counts

Top-level `catalog.groups` = 3 marcos (`org`, `op`, `mp`), with the `op`/`mp` marcos nesting
per-family subgroups: **16 families** total (1 + 7 + 8).

- **73 base controls**
- **133 refuerzo nodes** (nested `controls` with `class: "ens-refuerzo"`, ids `X.rN`)
- 206 total control nodes

Distribution by marco: `org` = 4, `op` = 33, `mp` = 36.

> **Legal notice (from the source `metadata.remarks`):** the content is informative and has
> no normative character. The only legally valid version is the one published in the BOE.

## License notice

The catalog is distributed under the **EUPL-1.2**. Retain attribution to the **AEAD** and
the EUPL-1.2 license terms when redistributing or deriving from this data.
