# audit_target (intentionally insecure fixture)

This directory is **not** a real application. It is a deliberately insecure
sample target used by the end-to-end audit test (`tests/test_e2e.py`).

It mixes source-code and infrastructure/configuration weaknesses so that the
deterministic scanners (both `code.*` and `infra.*`) produce findings mapped to
ENS measures:

- `auth_service.py` — hardcoded secret, disabled TLS verification, weak hash,
  SQL string concatenation, `subprocess(..., shell=True)` and no audit logging.
- `Dockerfile` — unpinned `:latest` base image, no non-root `USER`, hardcoded
  `ENV` credential and a remote `ADD`.
- `deployment.yaml` — Kubernetes workload that runs `privileged`, shares the
  host network, sets a plaintext secret and has no `NetworkPolicy`.
- `main.tf` — public S3 bucket, unencrypted volume and a security group open to
  `0.0.0.0/0`.
- `nginx.conf` — TLS 1.0/1.1 and weak ciphers enabled.
- `requirements.txt` — unpinned / deprecated dependencies.

Nothing here should be copied into production code. It exists only to exercise
the audit pipeline deterministically and fully offline.
