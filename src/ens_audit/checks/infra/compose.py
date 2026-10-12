"""Docker Compose and Kubernetes manifest scanner (``infra.compose``).

Handles both ``docker-compose*.y*ml`` files and Kubernetes YAML manifests
(identified structurally by ``apiVersion`` + ``kind``), flagging:

* privileged containers (``config.debug_enabled``);
* host namespace sharing -- ``network_mode: host`` / ``pid: host`` /
  ``hostNetwork`` / ``hostPID`` (``network.service_exposed``);
* containers that may run as root (missing ``runAsNonRoot``)
  (``config.debug_enabled``);
* missing CPU/memory limits (``network.service_exposed`` -- DoS exposure);
* hardcoded plaintext secrets (``secret.hardcoded``);
* Kubernetes workloads with no ``NetworkPolicy`` anywhere in the scanned set
  (``network.service_exposed``).

YAML is parsed with :mod:`pyyaml`; source positions are recovered by locating
the relevant key in the raw text so evidence stays ``file_line``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from ens_audit.checks.registry import register
from ens_audit.models import Finding, Severity

from ..base import Scanner, ScannerResult, finalize_scan
from ._common import file_line_finding, find_line, iter_files, read_text

__all__ = ["ComposeScanner"]

# Rule kinds (keys into the ENS measure mapping).
_INSECURE_CONFIG = "config.debug_enabled"
_EXPOSED = "network.service_exposed"
_SECRET = "secret.hardcoded"

_COMPOSE_NAME = re.compile(r"(?i)^(?:docker-)?compose(?:\.[\w.-]+)?\.ya?ml$")
_WORKLOAD_KINDS = frozenset(
    {
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "ReplicaSet",
        "ReplicationController",
        "Job",
        "CronJob",
        "Pod",
    }
)
_SECRET_NAME = re.compile(
    r"(?i)(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|"
    r"PRIVATE[_-]?KEY|CREDENTIAL)"
)


def _is_yaml(path: Path) -> bool:
    """Whether ``path`` is a YAML document by suffix."""
    return path.suffix.lower() in {".yaml", ".yml"}


def _load_docs(text: str) -> list[Any]:
    """Parse a (possibly multi-document) YAML text into a list of documents."""
    try:
        return [doc for doc in yaml.safe_load_all(text) if doc is not None]
    except yaml.YAMLError:
        return []


def _is_k8s(docs: list[Any]) -> bool:
    """Whether the parsed documents look like a Kubernetes manifest."""
    return any(
        isinstance(doc, dict) and "apiVersion" in doc and "kind" in doc
        for doc in docs
    )


def _looks_like_compose(docs: list[Any]) -> bool:
    """Whether the first parsed document has a ``services`` mapping."""
    return bool(docs) and isinstance(docs[0], dict) and "services" in docs[0]


def _is_literal(value: Any) -> bool:
    """Whether an environment value is a literal (not a variable reference)."""
    text = str(value).strip().strip("\"'")
    if not text or text.startswith("$"):
        return False
    return not (text.startswith("<") and text.endswith(">"))


def _has_limits(service: dict[str, Any]) -> bool:
    """Whether a compose service declares CPU/memory limits."""
    for key in ("mem_limit", "cpu_count", "cpus"):
        if service.get(key):
            return True
    limits = (service.get("deploy") or {}).get("resources") or {}
    return bool(limits.get("limits"))


def _runs_nonroot(container_sc: dict[str, Any], pod_sc: dict[str, Any]) -> bool:
    """Whether the effective security context enforces a non-root user."""
    for sc in (container_sc, pod_sc):
        if sc.get("runAsNonRoot") is True:
            return True
        user = sc.get("runAsUser")
        if isinstance(user, int) and user > 0:
            return True
    return False


@register
class ComposeScanner(Scanner):
    """Inspect Docker Compose files and Kubernetes manifests for misconfig."""

    id = "infra.compose"
    description = (
        "Docker Compose/Kubernetes hardening: privileges, host namespaces, "
        "non-root, resource limits, secrets and network policies."
    )
    category = "infra"
    covers = ("config.debug_enabled", "network.service_exposed", "secret.hardcoded")

    def run(self, target: Path) -> ScannerResult:
        entries: list[tuple[Path, str, list[Any]]] = []
        for path in iter_files(target, _is_yaml):
            text = read_text(path)
            if text is None:
                continue
            entries.append((path, text, _load_docs(text)))

        has_network_policy = any(
            isinstance(doc, dict) and doc.get("kind") == "NetworkPolicy"
            for _, _, docs in entries
            for doc in docs
        )

        findings: list[Finding] = []
        examined = 0
        for path, text, docs in entries:
            if _is_k8s(docs):
                examined += 1
                findings.extend(self._scan_k8s(path, text, docs, has_network_policy))
            elif _COMPOSE_NAME.match(path.name) or _looks_like_compose(docs):
                examined += 1
                findings.extend(self._scan_compose(path, text, docs))
        return finalize_scan(
            self,
            target,
            findings,
            evaluated_kinds=self.covers,
            examined=examined,
            checked=(
                "Checked Compose/Kubernetes manifests for privileges, host "
                "namespaces, resource limits, non-root and plaintext secrets."
            ),
        )

    # -- Docker Compose ---------------------------------------------------

    def _scan_compose(
        self, path: Path, text: str, docs: list[Any]
    ) -> list[Finding]:
        services = docs[0].get("services")
        if not isinstance(services, dict):
            return []
        findings: list[Finding] = []
        for name, service in services.items():
            if not isinstance(service, dict):
                continue
            line = find_line(text, rf"(?m)^[ \t]+{re.escape(str(name))}\s*:")
            if service.get("privileged") is True:
                findings.append(
                    file_line_finding(
                        kind=_INSECURE_CONFIG,
                        severity=Severity.HIGH,
                        message=f"Compose service {name!r} runs privileged.",
                        path=path,
                        line=line,
                        detail="privileged: true",
                    )
                )
            if str(service.get("network_mode", "")).lower() == "host" or (
                str(service.get("pid", "")).lower() == "host"
            ):
                findings.append(
                    file_line_finding(
                        kind=_EXPOSED,
                        severity=Severity.HIGH,
                        message=(
                            f"Compose service {name!r} shares a host namespace "
                            "(network_mode/pid=host)."
                        ),
                        path=path,
                        line=line,
                        detail="host namespace",
                    )
                )
            findings.extend(self._env_secrets(path, text, str(name), service, line))
            if not _has_limits(service):
                findings.append(
                    file_line_finding(
                        kind=_EXPOSED,
                        severity=Severity.LOW,
                        message=(
                            f"Compose service {name!r} has no CPU/memory limits."
                        ),
                        path=path,
                        line=line,
                        detail="no resource limits",
                    )
                )
        return findings

    def _env_secrets(
        self,
        path: Path,
        text: str,
        owner: str,
        spec: dict[str, Any],
        fallback_line: int,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for key, value in _environment_items(spec):
            if not _SECRET_NAME.search(str(key)) or not _is_literal(value):
                continue
            line = find_line(text, rf"(?m)\b{re.escape(str(key))}\b\s*[:=]") or fallback_line
            findings.append(
                file_line_finding(
                    kind=_SECRET,
                    severity=Severity.HIGH,
                    message=(
                        f"{owner!r} sets {key!r} to a plaintext literal; inject "
                        "it as a secret instead."
                    ),
                    path=path,
                    line=line,
                    detail=str(key),
                )
            )
        return findings

    # -- Kubernetes -------------------------------------------------------

    def _scan_k8s(
        self, path: Path, text: str, docs: list[Any], has_network_policy: bool
    ) -> list[Finding]:
        findings: list[Finding] = []
        first_workload_line = 0
        workload_present = False

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind")
            if kind not in _WORKLOAD_KINDS:
                continue
            workload_present = True
            name = (doc.get("metadata") or {}).get("name", kind)
            kind_line = find_line(text, rf"(?m)^\s*kind:\s*{re.escape(str(kind))}\b")
            if not first_workload_line:
                first_workload_line = kind_line or find_line(text, r"(?m)^\s*kind:")

            pod = _pod_spec(doc)
            pod_sc = pod.get("securityContext") or {}
            if pod.get("hostNetwork") is True or pod.get("hostPID") is True:
                findings.append(
                    file_line_finding(
                        kind=_EXPOSED,
                        severity=Severity.HIGH,
                        message=(
                            f"Workload {name!r} shares the host network/PID "
                            "namespace."
                        ),
                        path=path,
                        line=kind_line,
                        detail="hostNetwork/hostPID",
                    )
                )

            for container in pod.get("containers") or []:
                if not isinstance(container, dict):
                    continue
                findings.extend(
                    self._scan_k8s_container(
                        path, text, container, pod_sc, kind_line
                    )
                )

        if workload_present and not has_network_policy:
            findings.append(
                file_line_finding(
                    kind=_EXPOSED,
                    severity=Severity.MEDIUM,
                    message=(
                        "Kubernetes workloads are deployed without any "
                        "NetworkPolicy restricting traffic."
                    ),
                    path=path,
                    line=first_workload_line,
                    detail="missing NetworkPolicy",
                )
            )
        return findings

    def _scan_k8s_container(
        self,
        path: Path,
        text: str,
        container: dict[str, Any],
        pod_sc: dict[str, Any],
        fallback_line: int,
    ) -> list[Finding]:
        findings: list[Finding] = []
        cname = container.get("name", "container")
        line = (
            find_line(text, rf"(?m)^\s*-\s*name:\s*{re.escape(str(cname))}\b")
            or fallback_line
        )
        sc = container.get("securityContext") or {}

        if sc.get("privileged") is True:
            findings.append(
                file_line_finding(
                    kind=_INSECURE_CONFIG,
                    severity=Severity.HIGH,
                    message=f"Container {cname!r} runs privileged.",
                    path=path,
                    line=line,
                    detail="privileged: true",
                )
            )
        if not _runs_nonroot(sc, pod_sc):
            findings.append(
                file_line_finding(
                    kind=_INSECURE_CONFIG,
                    severity=Severity.MEDIUM,
                    message=(
                        f"Container {cname!r} does not enforce runAsNonRoot; it "
                        "may run as root."
                    ),
                    path=path,
                    line=line,
                    detail="missing runAsNonRoot",
                )
            )
        if not (container.get("resources") or {}).get("limits"):
            findings.append(
                file_line_finding(
                    kind=_EXPOSED,
                    severity=Severity.LOW,
                    message=f"Container {cname!r} has no resource limits.",
                    path=path,
                    line=line,
                    detail="no resource limits",
                )
            )

        for item in container.get("env") or []:
            if not isinstance(item, dict):
                continue
            key = item.get("name")
            if not key or "value" not in item:
                continue
            if _SECRET_NAME.search(str(key)) and _is_literal(item.get("value")):
                findings.append(
                    file_line_finding(
                        kind=_SECRET,
                        severity=Severity.HIGH,
                        message=(
                            f"Container {cname!r} sets {key!r} to a plaintext "
                            "literal; use a Secret instead."
                        ),
                        path=path,
                        line=line,
                        detail=str(key),
                    )
                )
        return findings


def _environment_items(spec: dict[str, Any]) -> list[tuple[Any, Any]]:
    """Normalize a compose ``environment`` mapping/list into key/value pairs."""
    environment = spec.get("environment")
    if isinstance(environment, dict):
        return list(environment.items())
    if isinstance(environment, list):
        pairs: list[tuple[Any, Any]] = []
        for item in environment:
            if isinstance(item, str) and "=" in item:
                key, value = item.split("=", 1)
                pairs.append((key, value))
        return pairs
    return []


def _pod_spec(doc: dict[str, Any]) -> dict[str, Any]:
    """Return the pod spec of a workload document (the doc itself for ``Pod``)."""
    spec = doc.get("spec") or {}
    if doc.get("kind") == "Pod":
        return spec if isinstance(spec, dict) else {}
    pod = (spec.get("template") or {}).get("spec")
    return pod if isinstance(pod, dict) else {}
