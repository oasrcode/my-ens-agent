# `ens-audit`

Herramienta de auditoría del **Esquema Nacional de Seguridad (ENS, RD 311/2022)**.
Audita **código fuente** e **infraestructura/configuración** contra las medidas del
**Anexo II** y genera informes de cumplimiento **medida a medida** en Markdown, HTML y
JSON. El núcleo se expone además como **servidor MCP (stdio)** para que un agente
(p. ej. [opencode](https://opencode.ai)) conduzca la auditoría.

- **Norma:** Real Decreto 311/2022, de 3 de mayo (`BOE-A-2022-7191`).
- **Catálogo:** 73 medidas de seguridad del Anexo II, en formato OSCAL (EUPL-1.2).
- **Salida:** veredicto por cada medida (`cumple`, `no_cumple`, `parcial`, `no_aplica`,
  `no_evaluable`) con su **estado de evidencia** (`no_comprobado`, `no_detectado`,
  `riesgo_detectado`, `cumplimiento_demostrado`, `incumplimiento_demostrado`), más resumen,
  porcentaje de cumplimiento y porcentaje de cobertura.

---

## Qué es

`ens-audit` combina tres capacidades deterministas:

1. **Catálogo versionado** del ENS (las 73 medidas, sus refuerzos y su aplicabilidad por
   categoría y por dimensión/nivel).
2. **Escáneres deterministas** (10) sobre código fuente e infraestructura, que producen
   hallazgos con evidencia (`fichero:línea` o clave/valor de configuración) y su medida
   ENS asociada, más **3 escáneres externos opcionales** (OSV-Scanner, Semgrep, Trivy) y la
   **importación de SARIF**.
3. **Evaluador y generador de informes** que consolida hallazgos y valoraciones manuales
   en un `ComplianceReport` (un veredicto por medida) y lo renderiza a `.md`, `.json` y
   `.html`.

El agente aporta el juicio cualitativo en las medidas que ningún escáner puede evidenciar
(políticas, procedimientos, controles físicos); la herramienta **nunca asume cumplimiento**:
las deja `no_evaluable` (estado de evidencia `no_comprobado`) en lugar de darlas por cumplidas.

---

## Características

- **Catálogo ENS (RD 311/2022, Anexo II)** en OSCAL: 73 controles base
  (`org` = 4, `op` = 33, `mp` = 36), 16 familias y 133 refuerzos, con motor de
  **aplicabilidad** por categoría (BÁSICA/MEDIA/ALTA) y por dimensión/nivel.
- **10 escáneres deterministas**: 5 de código y 5 de infraestructura, más **3 escáneres
  externos opcionales** (OSV-Scanner, Semgrep y Trivy) que se activan explícitamente.
- **Evaluador de las 73 medidas**: exactamente un veredicto por medida, con **veredictos
  basados en evidencia** (sin `cumple` por defecto). Acepta los niveles por dimensión para
  derivar la categoría y los refuerzos aplicables.
- **Importación de SARIF** aportado por el usuario, para incorporar resultados producidos
  fuera de este host sin ejecutar herramientas externas.
- **Informes en Markdown, HTML y JSON** desde un mismo modelo de resultados.
- **Servidor MCP (FastMCP)** sobre stdio: 8 *tools*, 4 *resources* y 2 *prompts*.
- **Skill de opencode** (`.opencode/skills/ens-audit/`) que orquesta la auditoría de
  extremo a extremo.

### Escáneres incluidos (10)

| ID | Ámbito | Qué comprueba |
|---|---|---|
| `code.secrets` | código | credenciales, tokens y claves privadas *hardcodeadas*. |
| `code.dependencies` | código | manifiestos con dependencias sin fijar o de riesgo. |
| `code.crypto` | código | criptografía débil, verificación TLS desactivada, claves fijas. |
| `code.logging` | código | presencia de log de auditoría, fuga de secretos, errores silenciados. |
| `code.sast` | código | *sinks* peligrosos (inyección SQL, `eval`/`exec`, shell, *loads* inseguros). |
| `infra.dockerfile` | infra | usuario root, imágenes base sin fijar, secretos, `ADD` remoto. |
| `infra.compose` | infra | Docker Compose/Kubernetes: privilegios, *host namespaces*, límites, secretos. |
| `infra.terraform` | infra | buckets públicos, almacenamiento sin cifrar, *security groups* abiertos, logs ausentes. |
| `infra.web` | infra | TLS/protocolos débiles, HSTS y cabeceras de seguridad ausentes, HTTP en claro. |
| `infra.backup` | infra | configuraciones de copia de seguridad deshabilitadas explícitamente. |

### Escáneres externos (opt-in) y SARIF

Además de los 10 escáneres deterministas, la herramienta puede orquestar **tres escáneres
externos** (opt-in) que invocan herramientas de terceros por `subprocess` (sin *shell*, con
*timeout* y errores controlados):

| ID | Herramienta | Qué aporta |
|---|---|---|
| `external.osv` | [OSV-Scanner](https://github.com/google/osv-scanner) | vulnerabilidades conocidas en dependencias. |
| `external.semgrep` | [Semgrep](https://semgrep.dev/) | hallazgos SAST. |
| `external.trivy` | [Trivy](https://trivy.dev/) | vulnerabilidades y *misconfigurations* de contenedores/IaC. |

Por ser costosos y depender de binarios no siempre instalados, **nunca se ejecutan en un
escaneo de rutina**: deben pedirse explícitamente con `run_scans(checks=[...])` o activarse
con `run_scans(include_external=true)`. Una herramienta **ausente** o **fallida** deja su
medida como **no comprobada** (`skipped`: menos cobertura, *nunca* cumplimiento).

Los resultados externos se importan también como hallazgos con trazabilidad de
**herramienta y versión**. Si ya dispones de un informe **SARIF 2.1.0** generado en otro
sitio, puedes incorporarlo sin instalar nada con la tool `import_sarif` (texto JSON o ruta a
un fichero `.sarif`/`.json`; admite `tool_name`, `tool_version` y un `kind` para mapearlo a
medidas ENS).

### Semántica de veredictos basada en evidencia

El evaluador **no asume cumplimiento**: la ausencia de hallazgos **no** es evidencia de
cumplimiento. Cada medida recibe uno de estos estados, y solo la evidencia positiva
suficiente (una valoración manual explícita, o un escáner que la cubra por completo) lleva a
`cumple`:

- **`no_comprobado`** — sin cobertura: ningún escáner la examinó, o el escáner que debía
  hacerlo falló o no estaba instalado.
- **`no_detectado`** — se comprobó y no se encontró nada; **no** es prueba de cumplimiento
  (la medida queda `parcial`).
- **`riesgo_detectado`** — se detectó una señal de riesgo **no demostrativa** (p. ej. una CVE
  o una versión sin fijar): se reporta como riesgo y contribuye a `parcial`, pero **no**
  fuerza `no_cumple`.
- **`cumplimiento_demostrado`** — evidencia positiva suficiente (`cumple`).
- **`incumplimiento_demostrado`** — evidencia que demuestra el incumplimiento de un requisito
  ENS aplicable (`no_cumple`).

`verified` (un hallazgo de herramienta verificada) **no** implica `no_cumple` por sí solo:
solo lo hace la evidencia que demuestra el incumplimiento de un requisito aplicable.

---

## Instalación

Requisitos: **`uv`** (gestiona el intérprete y el entorno; no hace falta `pip`) y
**Python 3.12** (fijado en `.python-version`; `uv` lo descarga si hace falta).

```bash
git clone https://github.com/oasrcode/my-ens-agent.git
cd my-ens-agent
uv sync          # crea .venv e instala las dependencias
```

Comprobación rápida de que el catálogo carga:

```bash
uv run python -c "from ens_audit.catalog.loader import load_catalog; print(len(load_catalog('data/ens_anexo_ii_oscal.json').medidas))"
# -> 73
```

---

## Uso

### Arrancar el servidor MCP (stdio)

```bash
# Forma recomendada por el proyecto (usa el objeto `mcp` del módulo):
uv run fastmcp run src/ens_audit/server.py:mcp

# Alternativa (usa el guard `__main__`):
uv run python -m ens_audit.server

# Inspeccionar las tools sin cliente:
uv run fastmcp list src/ens_audit/server.py:mcp
```

El servidor habla MCP por **stdio**, por lo que **nunca escribe a stdout**; los
diagnósticos van por las notificaciones de logging de MCP o por `stderr`.

**Superficie MCP:**

- **Tools (8):** `catalog_list_measures`, `catalog_get_measure`,
  `catalog_compute_applicability`, `run_scans`, `import_sarif`, `record_assessment`,
  `evaluate_compliance`, `render_report`.
- **Resources (4):** `ens://catalog`, `ens://catalog/measures/{code}`,
  `ens://guides/{guide_id}`, `ens://methodology`.
- **Prompts (2):** `audit_methodology`, `report_outline`.

### Integrarlo en opencode

`opencode.json` ya declara el servidor como MCP **local** (stdio), invocado de forma
**portable** desde la raíz del repositorio:

```json
{
  "mcp": {
    "ens-audit": {
      "type": "local",
      "enabled": true,
      "timeout": 10000,
      "command": ["uv", "run", "--project", ".", "fastmcp", "run", "src/ens_audit/server.py:mcp"]
    }
  }
}
```

No contiene rutas absolutas: el servidor resuelve el catálogo desde su propia ubicación
de módulo (`<repo>/data/ens_anexo_ii_oscal.json`). Dentro de opencode las tools quedan
expuestas con el prefijo `ens-audit_`.

La metodología completa vive en la skill
[`.opencode/skills/ens-audit/SKILL.md`](.opencode/skills/ens-audit/SKILL.md), con
referencias en [`references/mapping.md`](.opencode/skills/ens-audit/references/mapping.md)
(hallazgo → medida) y
[`references/report-format.md`](.opencode/skills/ens-audit/references/report-format.md)
(estructura del informe).

### Cómo funciona una auditoría

Flujo metodológico (Anexo II e ITS de Auditoría), orquestado por el agente sobre las tools:

1. **Categorización (Anexo I).** Se valoran las cinco dimensiones —Confidencialidad,
   Integridad, Disponibilidad, Autenticidad, Trazabilidad— en BAJO/MEDIO/ALTO y se deriva
   la categoría con `catalog_compute_applicability`.
2. **Escaneo determinista.** `run_scans` ejecuta los 10 escáneres sobre el código y la
   infraestructura del sistema y agrega los hallazgos en un `ScanReport`. Los **escáneres
   externos** (OSV-Scanner, Semgrep, Trivy) solo se ejecutan si se piden por `checks` o con
   `include_external=true`; alternativamente se puede **importar un SARIF** ya generado con
   `import_sarif`.
3. **Valoración manual.** `record_assessment` registra el veredicto cualitativo de las
   medidas que ningún escáner puede evidenciar.
4. **Evaluación.** `evaluate_compliance` consolida todo en **un veredicto por cada una de
   las 73 medidas**. Opcionalmente acepta **`dimensiones`** (los niveles de las cinco
   dimensiones de seguridad, p. ej. `{'Confidencialidad': 'ALTO', 'D': 'MEDIO'}`) para derivar
   la categoría, las medidas aplicables y los **refuerzos** activados; `categoria` actúa como
   *override*. El resultado es un veredicto **basado en evidencia** (véase la semántica más
   arriba), con porcentaje de cumplimiento y porcentaje de cobertura.
5. **Informe.** `render_report` emite los artefactos en los formatos elegidos.

---

## Formatos de informe

Todos los formatos se generan desde un mismo `ComplianceReport` y comparten el nombre base
`informe-ens`:

| Formato | Extensión | Uso |
|---|---|---|
| Markdown | `informe-ens.md` | informe legible: metadatos, resumen ejecutivo, alcance/metodología, categorización, tabla de las 73 medidas, no conformidades y recomendaciones. |
| JSON | `informe-ens.json` | consumo automatizado; documento estable con `schema_version` (`1.0`) y veredictos en orden de catálogo. |
| HTML | `informe-ens.html` | página autocontenida e imprimible a PDF: sin recursos externos ni JavaScript; interactividad con `<details>` nativo. |

El contenido de los informes (copy) está en **español**; los identificadores, comentarios y
docstrings del código, en **inglés**.

---

## Procedencia y licencia

### Catálogo ENS (`data/`) — EUPL-1.2

El catálogo vive en `data/ens_anexo_ii_oscal.json` (copia literal, sin modificar):

- **Título:** `ENS (2022) – Catálogo OSCAL: ANEXO II – Medidas de Seguridad`.
- **Editor:** **AEAD** (Agencia Española de Administración Digital), publicado en el PAe
  ("ENS legible por máquina").
- **Formato:** OSCAL `1.1.3`; catálogo `version` `1.0.0`.
- **Fuente jurídica:** **RD 311/2022** — `BOE-A-2022-7191`.
- **Licencia:** **EUPL-1.2** (European Union Public License 1.2).

Procedencia, método de descarga, `SHA-256` y aviso legal completos en
[`data/README.md`](data/README.md). El aviso del editor es explícito: **el catálogo es
informativo y sin valor normativo**; la única versión jurídicamente válida es la publicada
en el BOE. Al redistribuir o derivar de este dato, conserva la atribución a la **AEAD** y
los términos de la **EUPL-1.2**.

### Código (`src/`, `opencode.json`, skill, README) — MIT

El **código** de `ens-audit` se distribuye bajo **licencia MIT** (véase
[`LICENSE`](LICENSE)), `Copyright (c) 2026 oasrcode`. La licencia MIT cubre únicamente el
software; el catálogo de `data/` mantiene su licencia **EUPL-1.2** y su atribución a la
**AEAD**.

---

## Alcance y limitaciones

- **Cobertura no total por diseño.** No todas las medidas son automatizables. Las de
  naturaleza **documental, organizativa o física** (p. ej. `org.*`, `op.pl.1`, `op.cont.*`,
  `mp.if.*`, `mp.eq.*`, `mp.per.*`, `mp.info.2`, `mp.si.1`) se reportan como
  **`no_evaluable`** cuando no hay evidencia automatizable ni valoración manual: la
  ausencia de evidencia **no** es evidencia de cumplimiento.
- **Aplicabilidad de límite superior.** Cuando solo se conoce la categoría (sin los niveles
  por dimensión), la aplicabilidad se resuelve con una valoración uniforme, lo que produce
  los recuentos de **límite superior** 52 (BÁSICA) / 68 (MEDIA) / 73 (ALTA).
- **Escáneres deterministas, no DAST.** No se audita la aplicación en ejecución ni se hace
  auditoría documental/organizativa; eso queda del lado del agente y de la evidencia manual.
- **Escáneres externos opt-in.** OSV-Scanner, Semgrep y Trivy requieren estar instalados en
  el host y solo se ejecutan si se piden; una herramienta ausente o fallida **no** aporta
  cobertura (la medida queda `no_comprobado`). Si no se quieren ejecutar, se puede `import_sarif`
  un informe SARIF 2.1.0 generado en otro sitio (los campos no reconocidos se degradan sin romper).
- **Sin firma ni PDF nativo.** El HTML es imprimible a PDF desde el navegador, pero no se
  firma ni se exporta a PDF de forma nativa.
- **Deriva normativa.** El catálogo es **dato versionado**; la actualización de la fuente
  debe revalidar los recuentos (73 medidas, 16 familias).

---

## Tests y CI

Este repositorio público distribuye un **subconjunto curado** de la batería de pruebas —
importación del paquete, integridad del catálogo, aplicabilidad, evaluador, trazabilidad,
informes (Markdown/JSON/HTML), escáneres de código e infraestructura, escáneres externos/SARIF,
superficie MCP y *end-to-end*— junto con los *fixtures* que necesita. El detalle está en
[`tests/README.md`](tests/README.md).

```bash
uv sync
uv run pytest -q                 # suite curada (offline, autocontenida)
uv run ruff check src tests      # lint
```

La **integración continua** corre en GitHub Actions (`.github/workflows/ci.yml`) en cada `push` y
`pull request` a `main`: `uv sync`, `ruff`, `pytest` y un escaneo de secretos con `gitleaks`.

> **Fixtures y secretos.** `tests/fixtures/**` contiene muestras **deliberadamente vulnerables y
> ficticias** (credenciales, claves y tokens de ejemplo): sus defectos son el propósito de los
> escáneres. Por eso se excluyen de `ruff` y de la detección de secretos mediante una allowlist
> acotada en [`.gitleaks.toml`](.gitleaks.toml).

> **Aviso sobre GitHub Secret Scanning.** La allowlist de `.gitleaks.toml` configura **solo**
> `gitleaks`; **no** configura GitHub Secret Scanning. En consecuencia, cualquier alerta de GitHub
> sobre esas rutas de *fixtures* es un **falso positivo conocido**.

---

## Licencia

- **Código:** MIT — [`LICENSE`](LICENSE), `Copyright (c) 2026 oasrcode`.
- **Catálogo (`data/`):** © **AEAD**, distribuido bajo **EUPL-1.2** — [`data/README.md`](data/README.md).
