# Ejemplo: auditoría ENS de OWASP Juice Shop

Este directorio es un **ejemplo de trabajo completo** de `ens-audit`: la auditoría del
**Esquema Nacional de Seguridad (ENS, RD 311/2022)** realizada sobre
[**OWASP Juice Shop**](https://owasp.org/www-project-juice-shop/), una aplicación web
**deliberadamente vulnerable** que sirve como blanco de pruebas. Se incluyen tanto los
**informes generados** como el **driver** que los produjo, de modo que el ejemplo es
autocontenido y reproducible.

- **Norma:** Real Decreto 311/2022, de 3 de mayo (`BOE-A-2022-7191`).
- **Sistema auditado:** OWASP Juice Shop (Node.js/TypeScript, contenedor Docker, IaC).
- **Categoría:** **ALTA**.
- **Resultado:** **0,0 %** de cumplimiento, **52,05 %** de cobertura (detalle más abajo).

---

## Qué es

Una auditoría **medida a medida** de las **73 medidas** del Anexo II del ENS contra el
código y la infraestructura de Juice Shop, hecha **con esta herramienta** (`ens-audit`).
El ejemplo combina:

1. Un **escaneo determinista** de los 10 escáneres incluidos sobre el árbol de Juice Shop.
2. **61 valoraciones manuales** para las medidas que ningún escáner puede evidenciar.
3. La **evaluación** de las 73 medidas y el **render** del informe en Markdown, JSON y HTML.

La herramienta no asume cumplimiento: la ausencia de evidencia **no** se interpreta como
conformidad, sino como `no_evaluable` (estado de evidencia `no_comprobado`).

---

## Categorización

Se valoraron las **cinco dimensiones** de seguridad del Anexo I en **ALTO**, lo que deriva
en **categoría ALTA** y en las **73/73 medidas aplicables** (sin ningún `no_aplica`):

| Dimensión | Nivel |
|---|---|
| Confidencialidad | ALTO |
| Integridad | ALTO |
| Disponibilidad | ALTO |
| Autenticidad | ALTO |
| Trazabilidad | ALTO |

Categoría resultante: **ALTA** → **73/73** medidas aplicables (**0** `no_aplica`), con
**88 refuerzos** activados en **38** medidas.

---

## Cómo se generó

La auditoría se ejecutó **por CLI** desde la raíz del repositorio, porque el **servidor MCP
no estaba cargado** en ese momento. `uv` resuelve el entorno del proyecto y el driver orquesta la librería
`ens_audit` (no reimplementa escaneo, evaluación ni render).

Comando exacto (con `--project .` apuntando a la raíz del repositorio):

```bash
uv run --project . python examples/juice-shop/scripts/run_ens_audit.py \
    --categoria ALTA \
    --dimensions '{"confidencialidad":"alto","integridad":"alto","disponibilidad":"alto","autenticidad":"alto","trazabilidad":"alto"}' \
    --assessments examples/juice-shop/assessments.json
```

El driver escribió después los informes en el directorio indicado con `--out` (por defecto
en el espacio de trabajo original de la auditoría; en este ejemplo los artefactos ya
generados se copiaron junto a este README). Las `--dimensions` fijan los cinco niveles en
alto y `--categoria ALTA` actúa como *override*; `--assessments` aporta las valoraciones
manuales.

Flujo interno del driver: `load_catalog` → `run_scans` → `evaluate_compliance` →
`render_report`.

---

## Artefactos

Todos los informes comparten el nombre base `informe-ens` y se generan desde un mismo
modelo de resultados:

| Fichero | Qué contiene |
|---|---|
| `informe-ens.md` | Informe legible: metadatos, resumen ejecutivo, alcance/metodología, categorización, dimensiones y refuerzos, evidencia positiva, estado de los escáneres, tabla de las 73 medidas, no conformidades y recomendaciones. |
| `informe-ens.json` | Consumo automatizado. Documento estable con `schema_version` (`1.6`), `summary`, `dimensions`, `refuerzos` y los veredictos en orden de catálogo. **No registra el `target`**. |
| `informe-ens.html` | Página autocontenida e imprimible a PDF, sin recursos externos ni JavaScript; interactividad con `<details>` nativo. |
| `assessments.json` | Las **61 valoraciones manuales** (una entrada por medida con `measure_code`, `verdict` y `notes`) que evidencia cualitativamente lo que ningún escáner puede comprobar. |
| `scan-report.json` | El **`ScanReport` completo**: los **760 hallazgos** con su evidencia (`fichero:línea` o clave/valor), los escáneres registrados y su `scanner_status`. |
| `scripts/run_ens_audit.py` | Driver CLI que orquestó el escaneo, la evaluación y el render. |

---

## Resultados

Las **73 medidas** del catálogo reciben exactamente un veredicto:

| Veredicto | Nº | % del total |
|---|---:|---:|
| `cumple` | 0 | 0,0 % |
| `no_cumple` | 19 | 26,03 % |
| `parcial` | 19 | 26,03 % |
| `no_aplica` | 0 | 0,0 % |
| `no_evaluable` | 35 | 47,95 % |
| **Total** | **73** | **100 %** |

- **% de cumplimiento:** **0,0 %** (0 / 73 medidas aplicables).
- **% de cobertura:** **52,05 %** (38 / 73 medidas aplicables).
- **760 hallazgos** de los escáneres deterministas sobre el árbol de Juice Shop (9 `completed`; `infra.web` quedó `skipped`).
- **0 `cumple` sin evidencia positiva**: ningún veredicto positivo se emitió por defecto.

---

## Limitaciones

- **35 medidas `no_evaluable`** (de naturaleza documental, organizativa o física, sin
  artefacto automatizable ni valoración manual) **no deben leerse como conformes**: quedan
  en estado `no_comprobado` precisamente porque no hay evidencia.
- **Escáneres externos no ejecutados.** OSV-Scanner, Semgrep y Trivy **no estaban
  instalados**, por lo que **no** se ejecutaron y **no** aportan hallazgos de CVE. El
  escaneo cubre solo los 10 escáneres deterministas integrados.
- **El `informe-ens.json` no registra el `target`** ni un **manifiesto de invocación**: el
  sistema auditado y los parámetros exactos de la ejecución deben reconstruirse desde este
  README (el `target` sí aparece en `scan-report.json` y en el Markdown).
- **Escáneres, no DAST.** No se audita la aplicación en ejecución ni se hace auditoría
  documental/organizativa reglada.

---

## Licencia

- Los **informes** de este ejemplo están redactados en **español**.
- El **catálogo ENS** (Anexo II) es **EUPL-1.2**, © **AEAD** — véase
  [`data/README.md`](../../data/README.md).
- El **código** de `ens-audit` es **MIT** — véase [`LICENSE`](../../LICENSE).
