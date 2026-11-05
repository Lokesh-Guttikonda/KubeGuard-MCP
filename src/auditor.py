"""Static manifest validation and cluster-wide risk audit.

:func:`validate_manifest` lints Kubernetes manifests (and docker-compose files)
for the reliability and security defects that most often turn into incidents:
missing memory limits, ``:latest`` images, privileged containers, host mounts,
plaintext credentials, Service/Deployment port drift, JVM heaps larger than the
container limit, risky RBAC and more.

:func:`audit_cluster` aggregates manifest findings, RBAC analysis, secret
exposure and the zero-trust classification of a list of commands into a single
risk score - the engine behind the ``audit`` CLI command and the
``audit_cluster_risks`` MCP tool.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from . import yaml_lite
from .correlator import _java_size, parse_quantity
from .patcher import get_in
from .policy import PolicyDecision, PolicyEngine, Verdict, analyze_rbac
from .redactor import SEVERITY_ORDER, Redactor, default_redactor, is_secret_key

__all__ = ["AuditFinding", "ClusterAudit", "ManifestReport", "audit_cluster", "validate_manifest"]

_PENALTY = {"critical": 25, "high": 12, "medium": 5, "low": 2}
_RISK_WEIGHT = {"critical": 25, "high": 10, "medium": 4, "low": 1}
_WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod", "ReplicationController"}
_DANGEROUS_CAPS = {"ALL": "critical", "SYS_ADMIN": "critical", "SYS_MODULE": "critical", "SYS_PTRACE": "high",
                   "NET_ADMIN": "high", "NET_RAW": "medium", "DAC_READ_SEARCH": "high", "SYS_RAWIO": "high", "BPF": "high"}  # fmt: skip
_SENSITIVE_HOST_PATHS = ("/var/run/docker.sock", "/run/containerd", "/var/lib/kubelet", "/etc", "/root", "/proc", "/")


@dataclass
class AuditFinding:
    rule_id: str
    severity: str
    resource: str
    message: str
    recommendation: str
    file: Optional[str] = None
    line: Optional[int] = None
    container: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "resource": self.resource,
            "message": self.message,
            "recommendation": self.recommendation,
        }
        for k in ("file", "line", "container"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d


def _sort_key(f: AuditFinding) -> Tuple[int, str, int, str]:
    return (-SEVERITY_ORDER.get(f.severity, 0), f.file or "", f.line or 0, f.rule_id)


@dataclass
class ManifestReport:
    file: str
    findings: List[AuditFinding] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        return max(0, 100 - sum(_PENALTY.get(f.severity, 0) for f in self.findings))

    @property
    def grade(self) -> str:
        s = self.score
        return "A" if s >= 90 else "B" if s >= 80 else "C" if s >= 65 else "D" if s >= 50 else "F"

    @property
    def passed(self) -> bool:
        return not self.errors and not any(f.severity in ("critical", "high") for f in self.findings)

    @property
    def by_severity(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0)))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "passed": self.passed,
            "score": self.score,
            "grade": self.grade,
            "resources": list(self.resources),
            "by_severity": self.by_severity,
            "errors": list(self.errors),
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_markdown(self) -> str:
        lines = [
            f"### Manifest validation — `{self.file}`",
            "",
            f"**{'PASS' if self.passed else 'FAIL'}** · score {self.score}/100 (grade {self.grade}) · "
            f"{len(self.resources)} resource(s) · {len(self.findings)} finding(s)",
            "",
        ]
        if self.errors:
            lines += [f"- ❌ parse error: {e}" for e in self.errors] + [""]
        if self.findings:
            lines += ["| Severity | Rule | Resource | Line | Finding | Fix |", "|---|---|---|---|---|---|"]
            for f in self.findings:
                where = f.resource + (f" ({f.container})" if f.container else "")
                lines.append(
                    f"| {f.severity} | `{f.rule_id}` | {where} | {f.line or ''} | {f.message} | {f.recommendation} |"
                )
            lines.append("")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Workload checks
# --------------------------------------------------------------------------- #


def _pod_spec_path(kind: str) -> Tuple[Any, ...]:
    if kind == "Pod":
        return ("spec",)
    if kind == "CronJob":
        return ("spec", "jobTemplate", "spec", "template", "spec")
    return ("spec", "template", "spec")


class _Checker:
    def __init__(self, file: str, redactor: Redactor) -> None:
        self.file = file
        self.redactor = redactor
        self.findings: List[AuditFinding] = []

    def add(
        self,
        rule_id: str,
        severity: str,
        resource: str,
        message: str,
        recommendation: str,
        line: Optional[int] = None,
        container: Optional[str] = None,
    ) -> None:
        self.findings.append(
            AuditFinding(rule_id, severity, resource, message, recommendation, self.file, line, container)
        )

    # ------------------------------------------------------------------ #
    def workload(self, doc: yaml_lite.Document) -> None:
        data = doc.data
        kind = data.get("kind")
        name = (data.get("metadata") or {}).get("name", "?")
        ref = f"{kind}/{name}"
        base = _pod_spec_path(kind)
        pod = get_in(data, base) or {}
        if not isinstance(pod, dict):
            return

        def line_of(path: Tuple[Any, ...]) -> Optional[int]:
            span = doc.spans.get(path)
            return span.line + 1 if span else None

        if (
            kind == "Deployment"
            and isinstance(get_in(data, ("spec", "replicas")), int)
            and data["spec"]["replicas"] < 2
        ):
            self.add(
                "KG016",
                "low",
                ref,
                f"replicas={data['spec']['replicas']}: no redundancy during node failure or rollout",
                "run at least 2 replicas with a PodDisruptionBudget",
                line_of(("spec", "replicas")),
            )
        for flag in ("hostNetwork", "hostPID", "hostIPC"):
            if pod.get(flag) is True:
                self.add(
                    "KG007",
                    "high",
                    ref,
                    f"{flag}: true shares the node's namespace",
                    f"remove {flag} unless this is a node agent",
                    line_of(base + (flag,)),
                )
        if pod.get("automountServiceAccountToken") is not False and kind in ("Deployment", "StatefulSet", "Pod"):
            sa = pod.get("serviceAccountName") or "default"
            if sa == "default":
                self.add(
                    "KG015",
                    "low",
                    ref,
                    "default ServiceAccount token is auto-mounted",
                    "set automountServiceAccountToken: false or use a dedicated ServiceAccount",
                    line_of(base),
                )
        pod_sc = pod.get("securityContext") or {}
        for vi, vol in enumerate(pod.get("volumes") or []):
            if isinstance(vol, dict) and isinstance(vol.get("hostPath"), dict):
                hp = str(vol["hostPath"].get("path", ""))
                sev = (
                    "critical"
                    if any(hp == p or (p != "/" and hp.startswith(p)) for p in _SENSITIVE_HOST_PATHS)
                    else "high"
                )
                self.add(
                    "KG008",
                    sev,
                    ref,
                    f"hostPath volume '{vol.get('name')}' mounts {hp} from the node",
                    "use a PVC/emptyDir; never mount the container runtime socket",
                    line_of(base + ("volumes", vi)),
                )
        containers = [("containers", i, c) for i, c in enumerate(pod.get("containers") or []) if isinstance(c, dict)]
        containers += [
            ("initContainers", i, c) for i, c in enumerate(pod.get("initContainers") or []) if isinstance(c, dict)
        ]
        for section, i, c in containers:
            self.container(
                doc,
                ref,
                kind,
                base + (section, i),
                c,
                pod_sc,
                line_of(base + (section, i)),
                section == "initContainers",
            )

    def container(
        self,
        doc: yaml_lite.Document,
        ref: str,
        kind: str,
        path: Tuple[Any, ...],
        c: Dict[str, Any],
        pod_sc: Dict[str, Any],
        line: Optional[int],
        init: bool,
    ) -> None:
        cname = str(c.get("name", "?"))

        def line_of(sub: Tuple[Any, ...]) -> Optional[int]:
            span = doc.spans.get(path + sub)
            return span.line + 1 if span else line

        image = str(c.get("image") or "")
        last = image.rsplit("/", 1)[-1]
        if image and "@sha256:" not in image and (":" not in last or last.endswith(":latest")):
            self.add(
                "KG001",
                "medium",
                ref,
                f"image '{image}' is unpinned (:latest or no tag)",
                "pin an immutable version tag or digest",
                line_of(("image",)),
                cname,
            )
        res = c.get("resources") or {}
        limits = res.get("limits") or {}
        requests = res.get("requests") or {}
        if not limits.get("memory"):
            self.add(
                "KG002",
                "high",
                ref,
                "no memory limit - one leak can OOM the whole node",
                "set resources.limits.memory",
                line_of(("resources",)),
                cname,
            )
        if not requests:
            self.add(
                "KG003",
                "medium",
                ref,
                "no resource requests - the scheduler cannot place the pod safely",
                "set resources.requests.cpu/memory",
                line_of(("resources",)),
                cname,
            )
        for r in ("memory", "cpu"):
            lq, rq = parse_quantity(limits.get(r)), parse_quantity(requests.get(r))
            if lq is not None and rq is not None and rq > lq:
                self.add(
                    "KG013",
                    "high",
                    ref,
                    f"requests.{r} ({requests.get(r)}) exceeds limits.{r} ({limits.get(r)})",
                    "requests must be <= limits (the API server rejects this)",
                    line_of(("resources", "requests", r)),
                    cname,
                )
        sc = c.get("securityContext") or {}
        if sc.get("privileged") is True:
            self.add(
                "KG004",
                "critical",
                ref,
                "privileged container (full host access)",
                "remove privileged: true; grant only the specific capability needed",
                line_of(("securityContext", "privileged")),
                cname,
            )
        if sc.get("allowPrivilegeEscalation") is not False and not init:
            self.add(
                "KG005",
                "medium",
                ref,
                "allowPrivilegeEscalation is not disabled",
                "set securityContext.allowPrivilegeEscalation: false",
                line_of(("securityContext",)),
                cname,
            )
        run_as = sc.get("runAsUser", pod_sc.get("runAsUser"))
        non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
        if run_as == 0:
            self.add(
                "KG006",
                "high",
                ref,
                "runs as root (runAsUser: 0)",
                "run as an unprivileged UID (e.g. 10001)",
                line_of(("securityContext", "runAsUser")),
                cname,
            )
        elif non_root is not True and not isinstance(run_as, int):
            self.add(
                "KG006",
                "medium",
                ref,
                "runAsNonRoot is not enforced",
                "set securityContext.runAsNonRoot: true",
                line_of(("securityContext",)),
                cname,
            )
        caps = (sc.get("capabilities") or {}).get("add") or []
        for cap in caps:
            sev = _DANGEROUS_CAPS.get(str(cap).upper().replace("CAP_", ""))
            if sev:
                self.add(
                    "KG009",
                    sev,
                    ref,
                    f"adds Linux capability {cap}",
                    "drop ALL and add only what is required",
                    line_of(("securityContext", "capabilities")),
                    cname,
                )
        if sc.get("readOnlyRootFilesystem") is not True and not init:
            self.add(
                "KG010",
                "low",
                ref,
                "root filesystem is writable",
                "set readOnlyRootFilesystem: true (+ emptyDir for /tmp)",
                line_of(("securityContext",)),
                cname,
            )
        if kind in ("Deployment", "StatefulSet", "DaemonSet") and not init:
            if not c.get("readinessProbe"):
                self.add(
                    "KG011",
                    "medium",
                    ref,
                    "no readinessProbe - traffic reaches pods before they are ready",
                    "add a readinessProbe",
                    line,
                    cname,
                )
            if not c.get("livenessProbe"):
                self.add(
                    "KG011",
                    "low",
                    ref,
                    "no livenessProbe - hung processes are never restarted",
                    "add a livenessProbe (and a startupProbe for slow starts)",
                    line,
                    cname,
                )
        for ei, env in enumerate(c.get("env") or []):
            if not isinstance(env, dict) or "value" not in env:
                continue
            ename, value = str(env.get("name", "")), env.get("value")
            if value in (None, ""):
                continue
            sval = str(value)
            if (is_secret_key(ename) and not sval.startswith("$(")) or self.redactor.contains_secrets(sval):
                self.add(
                    "KG012",
                    "critical",
                    ref,
                    f"plaintext credential in env var {ename}",
                    "move it to a Secret and reference it with valueFrom.secretKeyRef",
                    line_of(("env", ei, "value")),
                    cname,
                )
            m = re.search(r"-Xmx(\d+[kKmMgG]?)\b", sval)
            mem_limit = parse_quantity(limits.get("memory"))
            if m and mem_limit:
                heap = _java_size(m.group(1))
                if heap and heap >= 0.75 * mem_limit:
                    self.add(
                        "KG014",
                        "high",
                        ref,
                        f"JVM heap {m.group(0)} is {int(100 * heap / mem_limit)}% of the {limits.get('memory')} limit",
                        "use -XX:MaxRAMPercentage=75.0 or raise the memory limit",
                        line_of(("env", ei, "value")),
                        cname,
                    )

    # ------------------------------------------------------------------ #
    def secret(self, doc: yaml_lite.Document) -> None:
        data = doc.data
        name = (data.get("metadata") or {}).get("name", "?")
        values = list((data.get("data") or {}).keys()) + list((data.get("stringData") or {}).keys())
        if values:
            span = doc.spans.get(("data",)) or doc.spans.get(("stringData",))
            self.add(
                "KG017",
                "high",
                f"Secret/{name}",
                f"secret material committed to the manifest ({len(values)} key(s))",
                "use SealedSecrets / External Secrets / SOPS instead of committing Secret data",
                span.line + 1 if span else None,
            )

    def compose(self, doc: yaml_lite.Document) -> None:
        for sname, svc in (doc.data.get("services") or {}).items():
            if not isinstance(svc, dict):
                continue
            ref = f"compose/{sname}"
            span = doc.spans.get(("services", sname))
            line = span.line + 1 if span else None
            if svc.get("privileged") is True:
                self.add("KGC001", "critical", ref, "privileged: true", "remove privileged mode", line)
            for vol in svc.get("volumes") or []:
                if isinstance(vol, str) and "docker.sock" in vol:
                    self.add(
                        "KGC002",
                        "critical",
                        ref,
                        f"mounts the Docker socket ({vol})",
                        "never give containers control of the Docker daemon",
                        line,
                    )
            if svc.get("network_mode") == "host":
                self.add("KGC003", "high", ref, "network_mode: host", "use a bridge network", line)
            if not svc.get("mem_limit") and get_in(svc, ("deploy", "resources", "limits", "memory")) is None:
                self.add("KGC004", "medium", ref, "no memory limit", "set deploy.resources.limits.memory", line)
            env = svc.get("environment") or {}
            items = env.items() if isinstance(env, dict) else (str(e).partition("=")[::2] for e in env)
            for k, v in items:
                if v not in (None, "") and (is_secret_key(str(k)) or self.redactor.contains_secrets(str(v))):
                    if not str(v).startswith("${"):
                        self.add(
                            "KGC005",
                            "critical",
                            ref,
                            f"plaintext credential in environment variable {k}",
                            "use secrets: or an env_file excluded from version control",
                            line,
                        )


def _service_checks(chk: _Checker, docs: List[yaml_lite.Document]) -> None:
    workloads = [d for d in docs if isinstance(d.data, dict) and d.data.get("kind") in _WORKLOADS]
    for d in docs:
        data = d.data
        if not isinstance(data, dict) or data.get("kind") != "Service" or not workloads:
            continue
        spec = data.get("spec") or {}
        selector = spec.get("selector") or {}
        if not selector or spec.get("type") == "ExternalName":
            continue
        name = (data.get("metadata") or {}).get("name", "?")
        matched = []
        for w in workloads:
            base = _pod_spec_path(w.data.get("kind"))
            labels = (
                get_in(w.data, ("metadata", "labels"))
                if w.data.get("kind") == "Pod"
                else get_in(w.data, base[:-1] + ("metadata", "labels"))
            )
            if isinstance(labels, dict) and all(labels.get(k) == v for k, v in selector.items()):
                matched.append(w)
        span = d.spans.get(("spec", "selector"))
        if not matched:
            chk.add(
                "KG019",
                "medium",
                f"Service/{name}",
                f"selector {selector} matches no workload in this file",
                "align the selector with the pod template labels",
                span.line + 1 if span else None,
            )
            continue
        ports: List[Tuple[Optional[str], int]] = []
        for w in matched:
            for c in get_in(w.data, _pod_spec_path(w.data.get("kind")) + ("containers",)) or []:
                for p in (c.get("ports") or []) if isinstance(c, dict) else []:
                    if isinstance(p, dict) and isinstance(p.get("containerPort"), int):
                        ports.append((p.get("name"), p["containerPort"]))
        if not ports:
            continue
        for pi, sp in enumerate(spec.get("ports") or []):
            if not isinstance(sp, dict):
                continue
            target = sp.get("targetPort", sp.get("port"))
            ok = (isinstance(target, int) and target in [p for _, p in ports]) or (
                isinstance(target, str) and target in [n for n, _ in ports if n]
            )
            if not ok:
                tspan = d.spans.get(("spec", "ports", pi, "targetPort")) or d.spans.get(("spec", "ports", pi))
                exposed = ", ".join(f"{n + '=' if n else ''}{p}" for n, p in ports)
                chk.add(
                    "KG018",
                    "high",
                    f"Service/{name}",
                    f"targetPort {target} matches no containerPort ({exposed})",
                    "point targetPort at the named container port",
                    tspan.line + 1 if tspan else None,
                )


def validate_manifest(
    text: str, filename: str = "manifest.yaml", redactor: Optional[Redactor] = None
) -> ManifestReport:
    """Lint one manifest file (multi-document YAML, JSON or a List)."""
    engine = redactor or default_redactor()
    report = ManifestReport(file=filename)
    try:
        docs = yaml_lite.parse_documents(text)
    except yaml_lite.YamlError as exc:
        report.errors.append(str(exc))
        return report
    expanded: List[yaml_lite.Document] = []
    for d in docs:
        if isinstance(d.data, dict) and d.data.get("kind") == "List" and isinstance(d.data.get("items"), list):
            expanded.extend(yaml_lite.Document(item, {}, d.start, d.end) for item in d.data["items"])
        else:
            expanded.append(d)
    chk = _Checker(filename, engine)
    rbac_objs = []
    for d in expanded:
        data = d.data
        if not isinstance(data, dict):
            continue
        kind = data.get("kind")
        if kind:
            report.resources.append(f"{kind}/{(data.get('metadata') or {}).get('name', '?')}")
        if kind in _WORKLOADS:
            chk.workload(d)
        elif kind == "Secret":
            chk.secret(d)
        elif kind in ("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"):
            rbac_objs.append(data)
        elif "services" in data and kind is None:
            chk.compose(d)
            report.resources.extend(f"compose/{s}" for s in (data.get("services") or {}))
    _service_checks(chk, expanded)
    for rf in analyze_rbac(rbac_objs):
        chk.add(rf.rule_id, rf.severity, rf.resource, rf.message, rf.recommendation)
    leaked = engine.scan(text)
    if leaked and not any(f.rule_id in ("KG012", "KG017", "KGC005") for f in chk.findings):
        chk.add(
            "KG020",
            "high",
            filename,
            f"{len(leaked)} secret-like value(s) found ({', '.join(sorted({f.rule for f in leaked}))})",
            "remove credentials from manifests; reference Secrets instead",
        )
    report.findings = sorted(chk.findings, key=_sort_key)
    return report


# --------------------------------------------------------------------------- #
# Cluster audit
# --------------------------------------------------------------------------- #


@dataclass
class ClusterAudit:
    manifests: List[ManifestReport] = field(default_factory=list)
    commands: List[PolicyDecision] = field(default_factory=list)
    secrets_found: Dict[str, int] = field(default_factory=dict)

    @property
    def findings(self) -> List[AuditFinding]:
        out = [f for r in self.manifests for f in r.findings]
        return sorted(out, key=_sort_key)

    @property
    def risk_score(self) -> int:
        score = sum(_RISK_WEIGHT.get(f.severity, 0) for f in self.findings)
        score += 15 * sum(1 for c in self.commands if c.verdict is Verdict.BLOCKED_DESTRUCTIVE)
        score += 5 * sum(1 for c in self.commands if c.verdict is Verdict.APPROVAL_REQUIRED)
        return min(100, score)

    @property
    def risk_level(self) -> str:
        s = self.risk_score
        return "CRITICAL" if s >= 75 else "HIGH" if s >= 50 else "MEDIUM" if s >= 25 else "LOW"

    def to_dict(self) -> Dict[str, Any]:
        sev: Dict[str, int] = {}
        for f in self.findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "findings_by_severity": dict(sorted(sev.items(), key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0))),
            "top_risks": [f.to_dict() for f in self.findings[:10]],
            "manifests": [r.to_dict() for r in self.manifests],
            "commands": [c.to_dict() for c in self.commands],
            "secrets_found": dict(self.secrets_found),
        }

    def to_markdown(self) -> str:
        lines = [
            "## Cluster risk audit",
            "",
            f"**Risk score {self.risk_score}/100 — {self.risk_level}** · {len(self.manifests)} manifest file(s) · "
            f"{len(self.findings)} finding(s) · {len(self.commands)} command(s) classified",
            "",
        ]
        if self.findings:
            lines += ["### Top risks", "", "| Severity | Rule | Resource | Finding |", "|---|---|---|---|"]
            for f in self.findings[:10]:
                lines.append(f"| {f.severity} | `{f.rule_id}` | {f.resource} | {f.message} |")
            lines.append("")
        if self.commands:
            lines += ["### Command policy", "", "| Command | Verdict | Risk | Reason |", "|---|---|---|---|"]
            for c in self.commands:
                cmd = c.command.replace("|", "\\|")
                lines.append(f"| `{cmd}` | {c.verdict.value} | {c.risk_score} | {c.reason} |")
            lines.append("")
        if self.secrets_found:
            lines += ["### Secret exposure", ""]
            lines += [f"- `{k}`: {v} value(s)" for k, v in self.secrets_found.items()]
            lines.append("")
        for r in self.manifests:
            lines.append(r.to_markdown())
        return "\n".join(lines)


def audit_cluster(
    manifests: Union[str, Dict[str, str], Iterable[Tuple[str, str]], None] = None,
    commands: Sequence[str] = (),
    role: str = "operator",
    redactor: Optional[Redactor] = None,
) -> ClusterAudit:
    """Aggregate manifest, RBAC, secret-exposure and command-policy risk."""
    engine = redactor or default_redactor()
    policy = PolicyEngine(role=role)
    audit = ClusterAudit()
    if isinstance(manifests, str):
        files: List[Tuple[str, str]] = [("manifest.yaml", manifests)]
    elif isinstance(manifests, dict):
        files = list(manifests.items())
    elif manifests is None:
        files = []
    else:
        files = list(manifests)
    for name, text in files:
        audit.manifests.append(validate_manifest(text, name, engine))
        for f in engine.scan(text):
            audit.secrets_found[f.rule] = audit.secrets_found.get(f.rule, 0) + 1
    audit.secrets_found = dict(sorted(audit.secrets_found.items(), key=lambda kv: (-kv[1], kv[0])))
    audit.commands = [policy.classify(c) for c in commands if str(c).strip()]
    return audit
