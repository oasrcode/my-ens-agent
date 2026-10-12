# Finding-kind → ENS measure mapping

The deterministic scanners emit findings with a stable rule `kind`. The table
below (source of truth: `src/ens_audit/checks/mapping.py`, `MEASURE_MAP`)
translates each kind into the ENS measure(s) of RD 311/2022, Anexo II that the
finding concerns, plus the CCN-STIC guide(s) that give the technical verification
criteria.

A scanner finding may reference several measures; the evaluator aggregates by
`measure_codes`, so one finding can move several measures at once.

## Table

| Rule kind | Scanner(s) | ENS measure(s) | CCN-STIC guide(s) | Rationale |
| --- | --- | --- | --- | --- |
| `secret.hardcoded` | `code.secrets`, `code.logging`, `infra.compose`, `infra.dockerfile` | `op.exp.10`, `mp.si.2` | 807 | Hardcoded credentials expose keys/secrets that must be protected for their whole life cycle; secrets at rest need approved cryptography. |
| `crypto.weak_algorithm` | `code.crypto`, `infra.web` | `mp.si.2`, `mp.com.2` | 807 | Weak/deprecated algorithms fall below the required strength; weak transport crypto fails to protect communications confidentiality. |
| `injection.sql` | `code.sast` | `mp.sw.1` | 812 | Unsanitised input leading to SQL injection is a secure-development defect. |
| `injection.command` | `code.sast` | `mp.sw.1` | 812 | Command injection is a secure-development defect in the application lifecycle. |
| `transport.tls_missing` | `code.crypto`, `infra.web` | `mp.com.2`, `mp.com.3` | 807 | Unencrypted traffic does not protect confidentiality; without TLS neither integrity nor authenticity can be assured. |
| `config.debug_enabled` | `infra.compose`, `infra.dockerfile`, `infra.web` | `op.exp.2` | 808, 812 | Debug mode in production is an insecure configuration of the information system. |
| `dependency.outdated` | `code.dependencies`, `infra.dockerfile` | `op.exp.4`, `op.exp.6` | 808 | Unpatched dependencies miss security updates; known-vulnerable components raise the risk of malicious-code exploitation. |
| `logging.audit_disabled` | `code.logging`, `infra.terraform` | `op.exp.8` | 808, 817 | Without activity logging, traceability of security-relevant events is lost. |
| `network.service_exposed` | `infra.compose`, `infra.terraform` | `mp.com.1`, `mp.s.4` | 811, 820 | An unnecessarily exposed service weakens the secure perimeter and raises the DoS attack surface. |
| `storage.unencrypted` | `infra.backup`, `infra.terraform` | `mp.si.2`, `mp.info.6` | 807 | Information at rest must use approved cryptography; backups holding unencrypted data must still protect confidentiality. |

## Notes

- **Unknown kinds return no measures.** `measures_for(kind)` yields an empty list
  for any kind absent from `MEASURE_MAP`; such a finding is informational and does
  not affect any measure verdict.
- **Severity drives the signal.** A finding is a *failure signal* unless its
  severity is `info`. INFO findings are treated as positive/passing signals by the
  evaluator. Only the kind determines which measures a finding touches.
- **The table is data-driven and validated.** `validate_mapping(catalog)` checks
  every measure code against the loaded catalog; the test suite fails on drift
  (a mapping entry pointing at a non-existent measure). `known_kinds()` lists all
  rule ids.
- **Adding a rule** means adding one `MEASURE_MAP` entry (`MeasureRef` with
  `code`, `rationale`, `guides`); no evaluator change is needed because the
  evaluator consumes `measure_codes` directly.

## Scanner inventory (10)

`code.secrets`, `code.crypto`, `code.sast`, `code.dependencies`, `code.logging`,
`infra.web`, `infra.dockerfile`, `infra.backup`, `infra.terraform`,
`infra.compose`. Pass a subset as `run_scans(target, checks=[...])`; omit `checks`
to run all.
