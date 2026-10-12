# Public test suite (curated subset)

This directory is published to the public `ens-audit` repository by
`scripts/sync-public.sh` from the private development repository. Only an
explicit **allowlist** of test modules and the fixtures they need is mirrored
here; every other file under `tests/` in the dev repo stays private.

## What is covered

| Area | Module |
| --- | --- |
| Package import smoke test | `test_smoke.py` |
| Catalog integrity (73 measures / 16 families) | `test_catalog_loader.py` |
| Applicability (category / dimension / level) | `test_applicability.py` |
| Dimension-driven evaluation + refuerzos | `test_dimension_evaluate.py` |
| Compliance evaluator | `test_evaluate.py` |
| Traceability chain (measure → requirement → tool → evidence → verdict) | `test_traceability.py` |
| Reports (Markdown / JSON) | `test_report_md_json.py` |
| Reports (HTML) | `test_report_html.py` |
| Checks framework (registry, scan report) | `test_checks_framework.py` |
| Code scanners (+ false-positive assertions on clean fixtures) | `test_code_scanners.py` |
| Infra scanners (+ false-positive assertions on good fixtures) | `test_infra_scanners.py` |
| External scanners + SARIF import | `test_external_scanners.py` |
| MCP server surface | `test_server.py` |
| End-to-end demo over `fixtures/audit_target` | `test_e2e.py` |

## Running

```bash
uv sync
uv run pytest -q
uv run ruff check src tests
```

The suite is fully offline and self-contained: it only needs the shipped catalog
(`data/ens_anexo_ii_oscal.json`), the source package and the fixtures in this
directory. No external scanner is required — the external-scanner tests use
fixture SARIF and monkeypatched `subprocess`.

## Fixtures

`fixtures/**` contains **intentionally insecure** sample files (hardcoded
credentials, weak crypto, insecure infrastructure). Their defects are the
scanners' whole purpose, so they are excluded from `ruff`
(`[tool.ruff] extend-exclude = ["tests/fixtures"]`) and must never be "fixed".
The clean counterparts (`fixtures/code/clean`, `fixtures/infra/good`) must stay
clean: they back the false-positive assertions.

`fixtures/audit_target/` is the reproducible **demo target** used by
`test_e2e.py`: a deliberately insecure sample app (source + Dockerfile +
Kubernetes + Terraform + nginx + requirements) that exercises the full offline
pipeline (scanners → evaluator → Markdown/JSON/HTML reports).

### Secrets in fixtures are fictional

**Every credential in these fixtures is fictional.** They use well-known
placeholder/documentation values only — for example AWS's canonical example key
(`AKIA...EXAMPLE`), the jwt.io sample JWT, and obvious placeholders such as
`S3cr3t-Passw0rd-For-Demo`. No real secret is present.

### gitleaks

Because the fixtures deliberately look like leaked secrets, a `gitleaks` scan
will flag them. The dev repo carries a narrow allowlist for `tests/fixtures/` in
`.gitleaks.toml`; the public CI should apply the same **scoped** allowlist. The
gitleaks allowlist does **not** configure GitHub Secret Scanning — any GitHub
alerts on these paths are known false positives.
