"""Deterministic Kubernetes & Docker incident correlator.

Given an *incident bundle* - Pod JSON, Events, container logs and the source
manifests (Deployment/Service YAML, Dockerfile, docker-compose, ``docker
inspect`` output) - the correlator cross-references every signal and diagnoses
the six failure modes that cause most real-world pod outages:

==============================  =============================================
``OOMKilled``                   container exceeded its memory limit
``CrashLoopBackOff``            process keeps exiting (sub-cause analysis)
``ImagePullBackOff``            registry auth / missing tag / bad image name
``CreateContainerConfigError``  missing Secret/ConfigMap/key, runAsNonRoot
``Unschedulable``               requests too large, selector/taint mismatch
``ServicePortMismatch``         Service targetPort/selector not matching pods
==============================  =============================================

For each diagnosis it emits weighted evidence, a confidence score, a root-cause
narrative, policy-classified follow-up commands and - where the fix is
deterministic - an exact unified diff against the user's own YAML/JSON or
Dockerfile.  No LLM, no network, no randomness: the same bundle always yields
the same answer.
"""

from __future__ import annotations

import base64
import difflib
import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from . import yaml_lite
from .patcher import AppendItem, InsertKey, Patch, ReplaceKey, SetValue, get_in, make_patch, unified_diff
from .policy import PolicyEngine
from .redactor import RULE_CATEGORY, Redactor, default_redactor, is_secret_key

__all__ = [
    "CorrelationResult",
    "Correlator",
    "Diagnosis",
    "Evidence",
    "FailureType",
    "IncidentBundle",
    "SuggestedCommand",
    "TimelineEntry",
    "correlate",
    "format_memory",
    "load_bundle",
    "parse_quantity",
]

Mi = 1024**2
Gi = 1024**3


class FailureType(str, Enum):
    OOM_KILLED = "OOMKilled"
    CRASH_LOOP = "CrashLoopBackOff"
    IMAGE_PULL = "ImagePullBackOff"
    CONFIG_ERROR = "CreateContainerConfigError"
    UNSCHEDULABLE = "Unschedulable"
    SERVICE_PORT_MISMATCH = "ServicePortMismatch"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


# Root causes outrank pure symptoms when confidences tie.
_PRECEDENCE = {
    FailureType.OOM_KILLED: 0,
    FailureType.CONFIG_ERROR: 1,
    FailureType.IMAGE_PULL: 2,
    FailureType.UNSCHEDULABLE: 3,
    FailureType.SERVICE_PORT_MISMATCH: 4,
    FailureType.CRASH_LOOP: 5,
}

_SEVERITY = {
    FailureType.OOM_KILLED: "SEV-2",
    FailureType.CRASH_LOOP: "SEV-2",
    FailureType.IMAGE_PULL: "SEV-2",
    FailureType.CONFIG_ERROR: "SEV-2",
    FailureType.UNSCHEDULABLE: "SEV-3",
    FailureType.SERVICE_PORT_MISMATCH: "SEV-1",
}

_WORKLOAD_KINDS = {
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Job",
    "CronJob",
    "Pod",
    "ReplicationController",
}


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #


@dataclass
class Evidence:
    source: str
    detail: str
    weight: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "detail": self.detail, "weight": round(self.weight, 2)}


@dataclass
class SuggestedCommand:
    command: str
    purpose: str
    verdict: str = ""
    risk: int = 0
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "purpose": self.purpose,
            "verdict": self.verdict,
            "risk": self.risk,
            "reason": self.reason,
        }


@dataclass
class Diagnosis:
    failure: FailureType
    confidence: float
    title: str
    root_cause: str
    severity: str = "SEV-3"
    sub_cause: str = ""
    container: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    patches: List[Patch] = field(default_factory=list)
    commands: List[SuggestedCommand] = field(default_factory=list)
    symptom_of: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "failure": self.failure.value,
            "confidence": round(self.confidence, 2),
            "severity": self.severity,
            "title": self.title,
            "sub_cause": self.sub_cause,
            "container": self.container,
            "root_cause": self.root_cause,
            "symptom_of": self.symptom_of,
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation": list(self.remediation),
            "patches": [dict(p.to_dict(), diff=redacted_diff(p)) for p in self.patches],
            "commands": [c.to_dict() for c in self.commands],
        }


@dataclass
class TimelineEntry:
    time: str
    source: str
    kind: str
    reason: str
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "time": self.time,
            "source": self.source,
            "type": self.kind,
            "reason": self.reason,
            "message": self.message,
        }


@dataclass
class CorrelationResult:
    bundle: str
    namespace: Optional[str]
    pod: Optional[str]
    workload: Optional[str]
    diagnoses: List[Diagnosis]
    timeline: List[TimelineEntry]
    redaction: Dict[str, Dict[str, Any]]
    redaction_samples: List[Tuple[str, int, str]]
    redactor: Redactor = field(default_factory=default_redactor, repr=False)

    @property
    def primary(self) -> Optional[Diagnosis]:
        return self.diagnoses[0] if self.diagnoses else None

    @property
    def healthy(self) -> bool:
        return not self.diagnoses

    @property
    def secrets_blocked(self) -> int:
        return sum(a.get("redaction_count", 0) for a in self.redaction.values())

    @property
    def redaction_by_rule(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for audit in self.redaction.values():
            for rule, n in audit.get("by_rule", {}).items():
                out[rule] = out.get(rule, 0) + n
        return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))

    @property
    def runtime_leaks(self) -> Dict[str, int]:
        """Credentials (not PII) that leaked at *runtime* - logs/events, not manifests."""
        out: Dict[str, int] = {}
        for name, audit in self.redaction.items():
            if _is_runtime_source(name):
                for rule, n in audit.get("by_rule", {}).items():
                    if RULE_CATEGORY.get(rule, "secret") == "secret":
                        out[rule] = out.get(rule, 0) + n
        return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))

    @property
    def severity(self) -> str:
        if not self.primary:
            return "SEV-4"
        sev = self.primary.severity
        critical_leak = any(
            _is_runtime_source(name) and a.get("max_severity") == "critical" for name, a in self.redaction.items()
        )
        if critical_leak:
            return "SEV-1"
        return sev

    @property
    def incident_id(self) -> str:
        first = self.timeline[0].time if self.timeline else ""
        key = "|".join(
            [
                self.bundle,
                self.namespace or "",
                self.pod or "",
                self.primary.failure.value if self.primary else "",
                first,
            ]
        )
        return "KG-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:8].upper()

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "incident_id": self.incident_id,
            "bundle": self.bundle,
            "namespace": self.namespace,
            "pod": self.pod,
            "workload": self.workload,
            "severity": self.severity,
            "healthy": self.healthy,
            "primary": self.primary.failure.value if self.primary else None,
            "diagnoses": [d.to_dict() for d in self.diagnoses],
            "timeline": [t.to_dict() for t in self.timeline],
            "secret_firewall": {
                "secrets_blocked": self.secrets_blocked,
                "by_rule": self.redaction_by_rule,
                "runtime_leaks": self.runtime_leaks,
                "files": self.redaction,
            },
        }
        clean, _ = self.redactor.redact_obj(data)  # defence in depth: never emit a secret
        return clean


def _is_runtime_source(name: str) -> bool:
    low = name.lower()
    return low.endswith((".log", ".txt")) or "log" in low or "event" in low


# --------------------------------------------------------------------------- #
# Quantities
# --------------------------------------------------------------------------- #

_QTY_RE = re.compile(r"^\s*([+-]?\d+(?:\.\d+)?)(?:[eE]([+-]?\d+))?\s*(Ki|Mi|Gi|Ti|Pi|Ei|k|K|M|G|T|P|E|m)?\s*$")
_QTY_UNITS = {
    None: 1,
    "m": 0.001,
    "k": 1e3,
    "K": 1e3,
    "M": 1e6,
    "G": 1e9,
    "T": 1e12,
    "P": 1e15,
    "E": 1e18,
    "Ki": 1024,
    "Mi": 1024**2,
    "Gi": 1024**3,
    "Ti": 1024**4,
    "Pi": 1024**5,
    "Ei": 1024**6,
}


def parse_quantity(value: Any) -> Optional[float]:
    """Parse a Kubernetes quantity (``512Mi``, ``1.5Gi``, ``250m``, ``2``)."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    m = _QTY_RE.match(str(value))
    if not m:
        return None
    number = float(m.group(1))
    if m.group(2):
        number *= 10 ** int(m.group(2))
    return number * _QTY_UNITS[m.group(3)]


def format_memory(num_bytes: float) -> str:
    """Render bytes as the most natural binary quantity (``1Gi``, ``768Mi``)."""
    b = round(num_bytes)
    if b >= Gi and b % Gi == 0:
        return f"{b // Gi}Gi"
    if b % Mi == 0:
        return f"{b // Mi}Mi"
    return f"{math.ceil(b / Mi)}Mi"


def format_cpu(cores: float) -> str:
    milli = round(cores * 1000)
    if milli % 1000 == 0:
        return str(milli // 1000)
    return f"{milli}m"


_JAVA_SIZE_RE = re.compile(r"^(\d+)([kKmMgGtT]?)$")


def _java_size(text: str) -> Optional[int]:
    m = _JAVA_SIZE_RE.match(text)
    if not m:
        return None
    mult = {"": 1, "k": 1024, "m": Mi, "g": Gi, "t": 1024**4}[m.group(2).lower()]
    return int(m.group(1)) * mult


# --------------------------------------------------------------------------- #
# Bundle loading
# --------------------------------------------------------------------------- #

_SPECIAL_JSON = {
    "pod.json": "pod",
    "events.json": "events",
    "secrets.json": "secrets",
    "configmaps.json": "configmaps",
    "nodes.json": "nodes",
    "endpoints.json": "endpoints",
    "docker_inspect.json": "docker_inspect",
    "inspect.json": "docker_inspect",
    "scenario.json": "metadata",
}
_TEXT_FILES = (".txt", ".log")
_MAX_FILE_BYTES = 20 * 1024 * 1024


def _read_text(path: Path) -> str:
    data = path.read_bytes()[:_MAX_FILE_BYTES]
    return data.decode("utf-8", errors="replace")


def _parse_any(text: Union[str, bytes, Any]) -> Any:
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    if not isinstance(text, str):
        return text
    s = text.strip()
    if not s:
        return None
    try:
        return json.loads(s)
    except ValueError:
        docs = yaml_lite.load_all(text)
        return docs[0] if len(docs) == 1 else docs


_MAX_NESTING = 8


def _items(obj: Any) -> List[Dict[str, Any]]:
    """Flatten lists and ``*List`` objects into the Kubernetes objects they hold.

    Iterative with a depth cap: hostile input (``[[[[...]]]]`` nested 100k deep)
    must never exhaust the Python stack, even on interpreters whose ``json``
    module happily parses it.
    """
    out: List[Dict[str, Any]] = []
    stack: List[Tuple[Any, int]] = [(obj, 0)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            items = node.get("items")
            if isinstance(items, list) and (str(node.get("kind", "")).endswith("List") or "kind" not in node):
                out.extend(i for i in items if isinstance(i, dict))
            else:
                out.append(node)
        elif isinstance(node, list) and depth < _MAX_NESTING:
            stack.extend((x, depth + 1) for x in reversed(node))
    return out


_EVENT_TABLE_RE = re.compile(
    r"^(?P<last>\S+)\s+(?P<type>Normal|Warning)\s+(?P<reason>\S+)\s+(?P<object>\S+)\s+(?P<message>.+)$"
)


def _parse_event_table(text: str) -> List[Dict[str, Any]]:
    """Parse ``kubectl get events`` plain-text output."""
    out = []
    for line in text.splitlines():
        m = _EVENT_TABLE_RE.match(line.strip())
        if not m:
            continue
        kind, _, name = m.group("object").partition("/")
        out.append(
            {
                "type": m.group("type"),
                "reason": m.group("reason"),
                "message": m.group("message").strip(),
                "involvedObject": {"kind": kind.capitalize(), "name": name},
                "lastTimestamp": None,
                "_age": m.group("last"),
            }
        )
    return out


@dataclass
class IncidentBundle:
    """Everything known about one incident.  Paths are bundle-relative names."""

    name: str = "incident"
    pod: Optional[Dict[str, Any]] = None
    events: List[Dict[str, Any]] = field(default_factory=list)
    logs: str = ""
    manifests: Dict[str, str] = field(default_factory=dict)
    dockerfiles: Dict[str, str] = field(default_factory=dict)
    secrets: List[Dict[str, Any]] = field(default_factory=list)
    configmaps: List[Dict[str, Any]] = field(default_factory=list)
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    endpoints: List[Dict[str, Any]] = field(default_factory=list)
    docker_inspect: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_files: Dict[str, str] = field(default_factory=dict)

    # -- constructors ------------------------------------------------------ #
    @classmethod
    def from_directory(
        cls, path: Union[str, Path], name: Optional[str] = None, confine: bool = False
    ) -> IncidentBundle:
        """Load every recognised file in ``path``.

        With ``confine=True`` (used by the MCP server) files whose real path lies
        outside the bundle directory - e.g. symlinks to ``/etc`` - are skipped.
        """
        root = Path(path)
        if not root.is_dir():
            raise FileNotFoundError(f"bundle directory not found: {root}")
        real_root = root.resolve()
        bundle = cls(name=name or root.name)
        log_parts: List[str] = []
        for file in sorted(p for p in root.iterdir() if p.is_file()):
            if confine and real_root not in file.resolve().parents:
                continue
            fname = file.name
            low = fname.lower()
            if file.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = _read_text(file)
            if low == "scenario.json":
                bundle.metadata = json.loads(text)
                continue
            bundle.raw_files[fname] = text
            if low == "dockerfile" or low.endswith(".dockerfile") or low.startswith("dockerfile."):
                bundle.dockerfiles[fname] = text
            elif low.endswith(_TEXT_FILES):
                if "event" in low:
                    bundle.events.extend(_parse_event_table(text))
                else:
                    log_parts.append(text)
            elif low.endswith((".json", ".yaml", ".yml")):
                bundle._ingest_structured(fname, text)
        bundle.logs = "\n".join(p.rstrip("\n") for p in log_parts) + ("\n" if log_parts else "")
        return bundle

    @classmethod
    def from_inputs(
        cls,
        pod: Any = None,
        events: Any = None,
        logs: Optional[str] = None,
        manifests: Any = None,
        dockerfile: Optional[str] = None,
        secrets: Any = None,
        configmaps: Any = None,
        nodes: Any = None,
        endpoints: Any = None,
        docker_inspect: Any = None,
        name: str = "incident",
    ) -> IncidentBundle:
        """Build a bundle from in-memory values (dicts, JSON or YAML strings)."""
        b = cls(name=name)
        if pod is not None:
            b._ingest_obj("pod.json", _parse_any(pod), as_kind="pod")
            b._keep_raw("pod.json", pod)
        if events is not None:
            if isinstance(events, str) and events.strip() and events.strip()[0] not in "[{" and "Warning" in events:
                b.events.extend(_parse_event_table(events))
            else:
                b.events.extend(_items(_parse_any(events)))
            b._keep_raw("events.json", events)
        if logs:
            b.logs = logs
            b.raw_files["logs.txt"] = logs
        if manifests is not None:
            if (
                isinstance(manifests, dict)
                and all(isinstance(v, str) for v in manifests.values())
                and "kind" not in manifests
            ):
                files = dict(manifests)
            elif isinstance(manifests, str):
                files = {"manifest.yaml": manifests}
            else:
                docs = manifests if isinstance(manifests, list) else [manifests]
                files = {"manifest.yaml": yaml_lite.dump_all([d for d in docs if isinstance(d, dict)], seq_indent=0)}
            for fname, text in files.items():
                b.raw_files[fname] = text
                b._ingest_structured(fname, text)
        if dockerfile:
            b.dockerfiles["Dockerfile"] = dockerfile
            b.raw_files["Dockerfile"] = dockerfile
        for attr, value in (
            ("secrets", secrets),
            ("configmaps", configmaps),
            ("nodes", nodes),
            ("endpoints", endpoints),
            ("docker_inspect", docker_inspect),
        ):
            if value is not None:
                getattr(b, attr).extend(_items(_parse_any(value)))
                b._keep_raw(f"{attr}.json", value)
        return b

    # -- ingestion --------------------------------------------------------- #
    def _keep_raw(self, fname: str, value: Any) -> None:
        """Remember an input's text for the redaction audit (never raises)."""
        if isinstance(value, str):
            self.raw_files[fname] = value
            return
        try:
            self.raw_files[fname] = json.dumps(value, indent=2, default=str)
        except (RecursionError, ValueError, TypeError):
            pass  # hostile / unserialisable input: nothing to audit, nothing to leak

    def _ingest_structured(self, fname: str, text: str) -> None:
        low = fname.lower()
        try:
            docs = yaml_lite.load_all(text)
        except (yaml_lite.YamlError, ValueError, RecursionError):
            return
        hint = _SPECIAL_JSON.get(low)
        if low.startswith("events.") or low.startswith("event"):
            hint = "events"
        is_source = False
        for doc in docs:
            if hint == "docker_inspect" or (
                isinstance(doc, list) and doc and isinstance(doc[0], dict) and "State" in doc[0]
            ):
                self.docker_inspect.extend(d for d in _items(doc) if isinstance(d, dict))
                continue
            if isinstance(doc, dict) and "services" in doc and "kind" not in doc:
                is_source = True  # docker-compose
                continue
            for obj in _items(doc):
                if self._ingest_obj(fname, obj, as_kind=hint):
                    is_source = True
        if is_source:
            self.manifests[fname] = text

    def _ingest_obj(self, fname: str, obj: Any, as_kind: Optional[str] = None) -> bool:
        """Route a parsed object; returns True when it is a patchable source manifest."""
        if not isinstance(obj, dict):
            return False
        kind = obj.get("kind")
        if as_kind == "events" or kind == "Event":
            self.events.append(obj)
            return False
        if kind == "Secret" or as_kind == "secrets":
            self.secrets.append(obj)
            return False
        if kind == "ConfigMap" or as_kind == "configmaps":
            self.configmaps.append(obj)
            return as_kind is None
        if kind == "Node" or as_kind == "nodes":
            self.nodes.append(obj)
            return False
        if kind == "Endpoints" or as_kind == "endpoints":
            self.endpoints.append(obj)
            return False
        if "State" in obj and "Config" in obj:
            self.docker_inspect.append(obj)
            return False
        if kind == "Pod" and (as_kind == "pod" or "status" in obj):
            if self.pod is None:
                self.pod = obj
            return False
        return kind in _WORKLOAD_KINDS or kind == "Service"


def load_bundle(path: Union[str, Path]) -> IncidentBundle:
    return IncidentBundle.from_directory(path)


# --------------------------------------------------------------------------- #
# Normalised views
# --------------------------------------------------------------------------- #


@dataclass
class _Status:
    name: str
    image: str = ""
    ready: bool = False
    restarts: int = 0
    state: str = "unknown"
    reason: Optional[str] = None
    message: Optional[str] = None
    exit_code: Optional[int] = None
    last_reason: Optional[str] = None
    last_exit_code: Optional[int] = None
    last_message: Optional[str] = None
    last_started: Optional[str] = None
    last_finished: Optional[str] = None
    init: bool = False


@dataclass
class _Event:
    type: str
    reason: str
    message: str
    count: int
    first: Optional[str]
    last: Optional[str]
    obj_kind: str
    obj_name: str


@dataclass
class _Workload:
    file: str
    doc_index: int
    kind: str
    name: str
    namespace: Optional[str]
    data: Dict[str, Any]
    pod_spec_path: Tuple[Any, ...]

    @property
    def pod_spec(self) -> Dict[str, Any]:
        spec = get_in(self.data, self.pod_spec_path)
        return spec if isinstance(spec, dict) else {}

    @property
    def template_labels(self) -> Dict[str, Any]:
        if self.kind == "Pod":
            labels = get_in(self.data, ("metadata", "labels"))
        else:
            labels = get_in(self.data, self.pod_spec_path[:-1] + ("metadata", "labels"))
        return labels if isinstance(labels, dict) else {}

    @property
    def containers(self) -> List[Dict[str, Any]]:
        cs = self.pod_spec.get("containers")
        return [c for c in cs if isinstance(c, dict)] if isinstance(cs, list) else []

    @property
    def ref(self) -> str:
        return f"{self.kind.lower()}/{self.name}"

    def container_path(self, index: int) -> Tuple[Any, ...]:
        return self.pod_spec_path + ("containers", index)


def _pod_spec_path(kind: str) -> Tuple[Any, ...]:
    if kind == "Pod":
        return ("spec",)
    if kind == "CronJob":
        return ("spec", "jobTemplate", "spec", "template", "spec")
    return ("spec", "template", "spec")


def _norm_status(cs: Dict[str, Any], init: bool = False) -> _Status:
    st = _Status(name=str(cs.get("name", "?")), image=str(cs.get("image", "")), init=init)
    st.ready = bool(cs.get("ready"))
    st.restarts = int(cs.get("restartCount") or 0)
    state = cs.get("state") or {}
    for key in ("waiting", "running", "terminated"):
        if isinstance(state.get(key), dict):
            st.state = key
            inner = state[key]
            st.reason = inner.get("reason")
            st.message = inner.get("message")
            if key == "terminated":
                st.exit_code = inner.get("exitCode")
            break
    last = (cs.get("lastState") or {}).get("terminated")
    if isinstance(last, dict):
        st.last_reason = last.get("reason")
        st.last_exit_code = last.get("exitCode")
        st.last_message = last.get("message")
        st.last_started = last.get("startedAt")
        st.last_finished = last.get("finishedAt")
    return st


def _norm_docker(d: Dict[str, Any]) -> _Status:
    state = d.get("State") or {}
    name = str(d.get("Name", "container")).lstrip("/")
    st = _Status(name=name, image=str((d.get("Config") or {}).get("Image", "")))
    st.restarts = int(d.get("RestartCount") or 0)
    status = str(state.get("Status", "")).lower()
    exit_code = state.get("ExitCode")
    st.ready = status == "running" and not state.get("Restarting")
    if state.get("OOMKilled"):
        st.last_reason = "OOMKilled"
        st.last_exit_code = exit_code if exit_code not in (None, 0) else 137
        st.last_finished = state.get("FinishedAt")
        st.last_started = state.get("StartedAt")
    elif exit_code not in (None, 0):
        st.last_reason = "Error"
        st.last_exit_code = exit_code
        st.last_finished = state.get("FinishedAt")
    if status == "restarting" or state.get("Restarting") or (st.restarts >= 3 and not st.ready):
        st.state = "waiting"
        st.reason = "CrashLoopBackOff"
        st.message = f"docker restart loop ({st.restarts} restarts)"
    elif status == "exited":
        st.state = "terminated"
        st.reason = st.last_reason
        st.exit_code = exit_code
    elif status == "running":
        st.state = "running"
    return st


def _docker_spec(d: Dict[str, Any]) -> Dict[str, Any]:
    """Express ``docker inspect`` output as a Kubernetes-like container spec."""
    cfg = d.get("Config") or {}
    host = d.get("HostConfig") or {}
    env = []
    for item in cfg.get("Env") or []:
        k, _, v = str(item).partition("=")
        env.append({"name": k, "value": v})
    spec: Dict[str, Any] = {
        "name": str(d.get("Name", "container")).lstrip("/"),
        "image": cfg.get("Image", ""),
        "env": env,
    }
    if cfg.get("Cmd"):
        spec["args"] = list(cfg.get("Cmd") or [])
    if host.get("Memory"):
        spec["resources"] = {"limits": {"memory": format_memory(int(host["Memory"]))}}
    return spec


def _norm_event(e: Dict[str, Any]) -> _Event:
    obj = e.get("involvedObject") or e.get("regarding") or {}
    return _Event(
        type=str(e.get("type") or "Normal"),
        reason=str(e.get("reason") or ""),
        message=str(e.get("message") or e.get("note") or ""),
        count=int(e.get("count") or (e.get("series") or {}).get("count") or e.get("deprecatedCount") or 1),
        first=e.get("firstTimestamp") or e.get("eventTime") or (e.get("metadata") or {}).get("creationTimestamp"),
        last=e.get("lastTimestamp") or (e.get("series") or {}).get("lastObservedTime") or e.get("eventTime"),
        obj_kind=str(obj.get("kind") or ""),
        obj_name=str(obj.get("name") or ""),
    )


def _short_time(ts: Optional[str]) -> str:
    if not ts:
        return ""
    s = str(ts)
    m = re.match(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", s)
    return f"{m.group(1)}T{m.group(2)}Z" if m else s


def _clip(text: str, n: int = 160) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"


def _norm_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


# --------------------------------------------------------------------------- #
# Correlation context
# --------------------------------------------------------------------------- #


class _Ctx:
    def __init__(self, bundle: IncidentBundle, redactor: Redactor, policy: PolicyEngine) -> None:
        self.bundle = bundle
        self.redactor = redactor
        self.policy = policy
        pod = bundle.pod or {}
        meta = pod.get("metadata") or {}
        self.pod_name: Optional[str] = meta.get("name")
        self.namespace: Optional[str] = meta.get("namespace")
        self.pod_labels: Dict[str, Any] = meta.get("labels") or {}
        self.owner_names = [o.get("name", "") for o in meta.get("ownerReferences") or [] if isinstance(o, dict)]
        status = pod.get("status") or {}
        self.phase: Optional[str] = status.get("phase")
        self.conditions = [c for c in status.get("conditions") or [] if isinstance(c, dict)]
        self.statuses: List[_Status] = [_norm_status(c) for c in status.get("containerStatuses") or []]
        self.statuses += [_norm_status(c, init=True) for c in status.get("initContainerStatuses") or []]
        self.statuses += [_norm_docker(d) for d in bundle.docker_inspect]
        self.events: List[_Event] = [_norm_event(e) for e in bundle.events if isinstance(e, dict)]
        for ev in self.events:  # ingress firewall: detectors only ever see masked text
            ev.message = redactor.redact(ev.message).text
        self.logs = redactor.redact(bundle.logs).text if bundle.logs else ""
        self.log_lines = self.logs.splitlines()
        self.workloads: List[_Workload] = []
        self.services: List[Tuple[str, int, Dict[str, Any]]] = []
        self.compose: List[Tuple[str, int, Dict[str, Any]]] = []
        for fname, text in bundle.manifests.items():
            try:
                docs = yaml_lite.load_all(text)
            except (yaml_lite.YamlError, ValueError, RecursionError):
                continue
            if len(docs) == 1 and isinstance(docs[0], dict) and docs[0].get("kind") == "List":
                docs = _items(docs[0])
            for idx, doc in enumerate(docs):
                if not isinstance(doc, dict):
                    continue
                kind = doc.get("kind")
                if kind in _WORKLOAD_KINDS:
                    dmeta = doc.get("metadata") or {}
                    self.workloads.append(
                        _Workload(
                            fname,
                            idx,
                            kind,
                            str(dmeta.get("name", "?")),
                            dmeta.get("namespace"),
                            doc,
                            _pod_spec_path(kind),
                        )
                    )
                elif kind == "Service":
                    self.services.append((fname, idx, doc))
                elif "services" in doc and "kind" not in doc:
                    self.compose.append((fname, idx, doc))
        if self.namespace is None:
            for w in self.workloads:
                if w.namespace:
                    self.namespace = w.namespace
                    break
        self.secrets: Dict[str, Dict[str, Any]] = {}
        for s in bundle.secrets:
            sname = (s.get("metadata") or {}).get("name")
            if sname:
                self.secrets[str(sname)] = s
        self.configmaps: Dict[str, Dict[str, Any]] = {}
        for cm in bundle.configmaps:
            cname = (cm.get("metadata") or {}).get("name")
            if cname:
                self.configmaps[str(cname)] = cm
        self.workload = self._match_workload()
        self.docker_specs: Dict[str, Dict[str, Any]] = {}
        for d in bundle.docker_inspect:
            spec = _docker_spec(d)
            self.docker_specs[spec["name"]] = spec

    # -- lookups ----------------------------------------------------------- #
    def _match_workload(self) -> Optional[_Workload]:
        candidates = [w for w in self.workloads if w.kind != "Pod" or not self.pod_name or w.name == self.pod_name]
        if not candidates:
            candidates = list(self.workloads)
        if not candidates:
            return None
        if self.pod_labels:
            for w in candidates:
                tl = w.template_labels
                if tl and all(self.pod_labels.get(k) == v for k, v in tl.items()):
                    return w
        names = list(self.owner_names)
        if self.pod_name:
            names.append(self.pod_name)
        for n in names:
            for w in candidates:
                if n == w.name or n.startswith(w.name + "-"):
                    return w
        return candidates[0]

    def container_spec(self, name: Optional[str]) -> Tuple[Optional[int], Dict[str, Any]]:
        w = self.workload
        if w is None:
            spec = self.docker_specs.get(name or "") or (
                next(iter(self.docker_specs.values())) if self.docker_specs else {}
            )
            return None, spec
        containers = w.containers
        for i, c in enumerate(containers):
            if c.get("name") == name:
                return i, c
        if len(containers) == 1 or (containers and name is None):
            return 0, containers[0]
        return None, {}

    def manifest_text(self, w: Optional[_Workload]) -> Optional[str]:
        return self.bundle.manifests.get(w.file) if w else None

    @property
    def ns_flag(self) -> str:
        return f" -n {self.namespace}" if self.namespace else ""

    @property
    def pod_ref(self) -> str:
        return self.pod_name or "<pod>"

    def events_matching(self, pattern: str, reasons: Sequence[str] = ()) -> List[_Event]:
        rx = re.compile(pattern, re.I) if pattern else None
        out = []
        for e in self.events:
            if reasons and e.reason not in reasons:
                continue
            if rx is not None and not rx.search(e.message):
                continue
            out.append(e)
        return out

    def log_search(self, pattern: re.Pattern[str]) -> Optional[Tuple[int, str, re.Match[str]]]:
        for i, line in enumerate(self.log_lines):
            m = pattern.search(line)
            if m:
                return i + 1, line, m
        return None

    def cmd(self, command: str, purpose: str) -> SuggestedCommand:
        d = self.policy.classify(command)
        return SuggestedCommand(command, purpose, d.verdict.value, d.risk_score, d.reason)

    def apply_cmd(self, w: Optional[_Workload]) -> SuggestedCommand:
        target = w.file if w else "<manifest>.yaml"
        return self.cmd(f"kubectl apply -f {target}{self.ns_flag}", "roll out the patched manifest")

    def patch(self, w: Optional[_Workload], edits: Sequence[Any], description: str) -> Optional[Patch]:
        if w is None or not edits:
            return None
        text = self.manifest_text(w)
        if text is None:
            return None
        edits = [_with_doc(e, w.doc_index) for e in edits]
        return make_patch(w.file, text, edits, description)

    def secret_keys(self, name: str) -> List[str]:
        s = self.secrets.get(name) or {}
        keys = set((s.get("data") or {}).keys()) | set((s.get("stringData") or {}).keys())
        return sorted(str(k) for k in keys)

    def configmap_keys(self, name: str) -> List[str]:
        c = self.configmaps.get(name) or {}
        return sorted(str(k) for k in set((c.get("data") or {}).keys()) | set((c.get("binaryData") or {}).keys()))


def _with_doc(edit: Any, doc_index: int) -> Any:
    if getattr(edit, "doc_index", 0) == doc_index:
        return edit
    cls = type(edit)
    kwargs = dict(edit.__dict__)
    kwargs["doc_index"] = doc_index
    return cls(**kwargs)


def _confidence(score: float) -> float:
    return round(min(0.99, max(0.0, score)), 2)


# --------------------------------------------------------------------------- #
# Detector: OOMKilled
# --------------------------------------------------------------------------- #

_OOM_LOG_RE = re.compile(
    r"java\.lang\.OutOfMemoryError|JavaScript heap out of memory|MemoryError|Out of memory: Kill(?:ed)? process"
    r"|fatal error: runtime: out of memory|Cannot allocate memory|std::bad_alloc|OOMKilled|oom-kill",
    re.I,
)
_XMX_RE = re.compile(r"-Xmx(\d+[kKmMgGtT]?)\b")
_NODE_HEAP_RE = re.compile(r"--max-old-space-size=(\d+)")
_HEAP_ENV_NAMES = ("JAVA_TOOL_OPTIONS", "JAVA_OPTS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "NODE_OPTIONS")


@dataclass
class _Heap:
    size: int
    flag: str
    source: str  # "env" | "args" | "dockerfile" | "logs"
    runtime: str  # "jvm" | "node"
    env_index: Optional[int] = None
    env_name: Optional[str] = None
    env_value: Optional[str] = None
    dockerfile: Optional[str] = None


def _find_heap(ctx: _Ctx, container: Dict[str, Any]) -> Optional[_Heap]:
    def scan(text: str) -> Optional[Tuple[int, str, str]]:
        m = _XMX_RE.search(text)
        if m:
            size = _java_size(m.group(1))
            if size:
                return size, m.group(0), "jvm"
        m = _NODE_HEAP_RE.search(text)
        if m:
            return int(m.group(1)) * Mi, m.group(0), "node"
        return None

    for i, env in enumerate(container.get("env") or []):
        if isinstance(env, dict) and isinstance(env.get("value"), str):
            hit = scan(env["value"])
            if hit:
                return _Heap(hit[0], hit[1], "env", hit[2], i, str(env.get("name")), env["value"])
    for key in ("args", "command"):
        joined = " ".join(str(a) for a in container.get(key) or [])
        hit = scan(joined)
        if hit:
            return _Heap(hit[0], hit[1], "args", hit[2])
    for fname, text in ctx.bundle.dockerfiles.items():
        hit = scan(text)
        if hit:
            return _Heap(hit[0], hit[1], "dockerfile", hit[2], dockerfile=fname)
    hit = scan(ctx.logs)
    if hit:
        return _Heap(hit[0], hit[1], "logs", hit[2])
    return None


def _recommend_memory(limit: Optional[float], heap: Optional[int]) -> int:
    candidates = [limit * 2 if limit else 512 * Mi]
    if heap:
        candidates.append(heap / 0.75)
    rec = max(candidates)
    step = 256 * Mi if rec <= 4 * Gi else Gi
    return int(math.ceil(rec / step) * step)


def _detect_oom(ctx: _Ctx) -> Optional[Diagnosis]:
    score = 0.0
    evidence: List[Evidence] = []
    target: Optional[_Status] = None
    for st in ctx.statuses:
        if st.reason == "OOMKilled" or st.last_reason == "OOMKilled":
            where = "state" if st.reason == "OOMKilled" else "lastState"
            code = st.exit_code if where == "state" else st.last_exit_code
            score += 0.6
            evidence.append(
                Evidence(
                    "pod.status" if not ctx.bundle.docker_inspect else "docker inspect",
                    f'container "{st.name}" {where}.terminated.reason=OOMKilled (exitCode={code}, restarts={st.restarts})',
                    0.6,
                )
            )
            if code == 137:
                score += 0.1
            target = st
            break
    if target is None:
        for st in ctx.statuses:
            if 137 in (st.exit_code, st.last_exit_code):
                score += 0.15
                evidence.append(Evidence("pod.status", f'container "{st.name}" exited with code 137 (SIGKILL)', 0.15))
                target = st
                break
    oom_events = [
        e
        for e in ctx.events
        if e.reason in ("OOMKilling", "OOMKilled")
        or re.search(r"oom-?kill|out of memory|memory cgroup", e.message, re.I)
    ]
    if oom_events:
        score += 0.15
        e = oom_events[0]
        evidence.append(Evidence("events", f"{e.type}/{e.reason}: {_clip(e.message)}", 0.15))
    hit = ctx.log_search(_OOM_LOG_RE)
    if hit:
        score += 0.1
        evidence.append(Evidence("logs", f"line {hit[0]}: {_clip(hit[1])}", 0.1))
    if score < 0.35:
        return None

    name = target.name if target else None
    idx, spec = ctx.container_spec(name)
    if name is None and spec:
        name = spec.get("name")
    w = ctx.workload
    limits = get_in(spec, ("resources", "limits")) or {}
    requests = get_in(spec, ("resources", "requests")) or {}
    limit_raw = limits.get("memory") if isinstance(limits, dict) else None
    request_raw = requests.get("memory") if isinstance(requests, dict) else None
    limit = parse_quantity(limit_raw)
    heap = _find_heap(ctx, spec)
    rec = _recommend_memory(limit, heap.size if heap else None)
    rec_str = format_memory(rec)

    if heap and limit and heap.size >= 0.75 * limit:
        pct = round(100 * heap.size / limit)
        runtime = "JVM max heap" if heap.runtime == "jvm" else "Node.js old-space limit"
        root = (
            f"{runtime} {heap.flag} ({format_memory(heap.size)}) is {pct}% of the container memory limit "
            f"({limit_raw}). Heap + metaspace + thread stacks + off-heap buffers exceed the cgroup limit, so the "
            "kernel OOM killer SIGKILLs the process (exit 137) before the runtime can even throw an "
            "OutOfMemoryError."
        )
        score += 0.08
        evidence.append(
            Evidence(
                heap.source if heap.source != "env" else "manifest",
                f"{heap.flag} set in "
                + (
                    f"env {heap.env_name}"
                    if heap.env_name
                    else heap.dockerfile
                    if heap.dockerfile
                    else "container args"
                    if heap.source == "args"
                    else "the JVM startup log"
                )
                + f", but resources.limits.memory={limit_raw}",
                0.08,
            )
        )
    elif limit:
        root = (
            f'Container "{name}" exceeded its memory limit ({limit_raw}) and was SIGKILLed by the kernel OOM '
            "killer (exit 137). The limit is below the working set the process needs under load."
        )
        evidence.append(Evidence("manifest", f"resources.limits.memory={limit_raw}", 0.0))
    else:
        root = (
            f'Container "{name}" has no memory limit, so it competes for node memory and was OOM-killed under '
            "pressure (exit 137). Without requests/limits the scheduler cannot place it safely."
        )
        evidence.append(Evidence("manifest", "no resources.limits.memory set", 0.0))

    edits: List[Any] = []
    remediation: List[str] = []
    patches: List[Patch] = []
    if w is not None and idx is not None:
        cpath = w.container_path(idx)
        if limit_raw is not None:
            edits.append(SetValue(cpath + ("resources", "limits", "memory"), rec_str))
            remediation.append(f'Raise resources.limits.memory of container "{name}" from {limit_raw} to {rec_str}.')
            if request_raw is not None and parse_quantity(request_raw) == limit:
                edits.append(SetValue(cpath + ("resources", "requests", "memory"), rec_str))
                remediation.append(f"Keep Guaranteed QoS: raise requests.memory to {rec_str} as well.")
        else:
            edits.append(InsertKey(cpath + ("resources", "limits"), "memory", rec_str))
            remediation.append(f'Set resources.limits.memory={rec_str} on container "{name}".')
            if request_raw is None:
                edits.append(InsertKey(cpath + ("resources", "requests"), "memory", format_memory(rec // 2)))
        if heap and heap.source == "env" and heap.env_index is not None and heap.env_value is not None:
            new_val = _rewrite_heap_flag(heap, rec)
            edits.append(SetValue(cpath + ("env", heap.env_index, "value"), new_val))
            remediation.append(f"Size the heap from the cgroup limit: replace {heap.flag} in {heap.env_name}.")
        p = ctx.patch(w, edits, f"memory limit {limit_raw or 'unset'} -> {rec_str}")
        if p:
            patches.append(p)
    patches.extend(_compose_memory_patch(ctx, name, rec_str))
    if heap and heap.source == "dockerfile" and heap.dockerfile:
        text = ctx.bundle.dockerfiles[heap.dockerfile]
        new_text = text.replace(heap.flag, _heap_replacement(heap, rec), 1)
        if new_text != text:
            patches.append(
                Patch(heap.dockerfile, f"replace {heap.flag} with a limit-relative heap", text, new_text, "dockerfile")
            )
            remediation.append(
                f"Replace {heap.flag} with {_heap_replacement(heap, rec)} in {heap.dockerfile} so the heap tracks "
                "the container limit instead of a hard-coded size."
            )
    elif heap and heap.source in ("args", "logs"):
        remediation.append(
            f"Replace the hard-coded {heap.flag} with {_heap_replacement(heap, rec)} so the heap follows the limit."
        )
    remediation.append(
        "After the rollout, confirm the working set stays below ~80% of the limit (kubectl top) and consider a "
        "VerticalPodAutoscaler in recommendation mode."
    )
    commands = [
        ctx.cmd(f"kubectl describe pod {ctx.pod_ref}{ctx.ns_flag}", "confirm Last State: OOMKilled"),
        ctx.cmd(f"kubectl top pod {ctx.pod_ref}{ctx.ns_flag} --containers", "observe live memory usage"),
        ctx.cmd(
            f"kubectl logs {ctx.pod_ref}{ctx.ns_flag} -c {name or '<container>'} --previous",
            "logs from the killed container",
        ),
        ctx.apply_cmd(w),
        ctx.cmd(f"kubectl rollout status {w.ref if w else 'deployment/<name>'}{ctx.ns_flag}", "watch the rollout"),
    ]
    return Diagnosis(
        failure=FailureType.OOM_KILLED,
        confidence=_confidence(score),
        severity=_SEVERITY[FailureType.OOM_KILLED],
        title=f'Container "{name}" is being OOMKilled',
        root_cause=root,
        sub_cause="heap_exceeds_limit" if heap and limit and heap.size >= 0.75 * limit else "limit_too_low",
        container=name,
        evidence=evidence,
        remediation=remediation,
        patches=patches,
        commands=commands,
    )


def _heap_replacement(heap: _Heap, limit: int) -> str:
    if heap.runtime == "node":
        return f"--max-old-space-size={int(limit * 0.75 / Mi)}"
    return "-XX:MaxRAMPercentage=75.0"


def _rewrite_heap_flag(heap: _Heap, limit: int) -> str:
    assert heap.env_value is not None
    return heap.env_value.replace(heap.flag, _heap_replacement(heap, limit), 1)


def _compose_memory_patch(ctx: _Ctx, container: Optional[str], rec: str) -> List[Patch]:
    out: List[Patch] = []
    for fname, idx, doc in ctx.compose:
        services = doc.get("services") or {}
        for sname, svc in services.items():
            if not isinstance(svc, dict):
                continue
            cname = svc.get("container_name") or sname
            if container and container not in (sname, cname) and len(services) > 1:
                continue
            edits: List[Any] = []
            if "mem_limit" in svc:
                edits.append(SetValue(("services", sname, "mem_limit"), rec, idx))
            elif get_in(svc, ("deploy", "resources", "limits", "memory")) is not None:
                edits.append(SetValue(("services", sname, "deploy", "resources", "limits", "memory"), rec, idx))
            else:
                edits.append(InsertKey(("services", sname, "deploy", "resources", "limits"), "memory", rec, idx))
            p = make_patch(fname, ctx.bundle.manifests[fname], edits, f"compose memory limit -> {rec}")
            if p:
                out.append(p)
    return out


# --------------------------------------------------------------------------- #
# Detector: CrashLoopBackOff
# --------------------------------------------------------------------------- #

_DB_AUTH_RE = re.compile(
    r"password authentication failed|access denied for user|authentication failed|SASL authentication failed"
    r"|WRONGPASS|NOAUTH|Login failed for user|invalid username/password|ORA-01017|auth(?:entication)? error",
    re.I,
)
_MISSING_ENV_RES = (
    re.compile(r"KeyError: ['\"]([A-Z][A-Z0-9_]{2,})['\"]"),
    re.compile(
        r"(?:environment variable|env var|env)\s+[\"'`]?([A-Z][A-Z0-9_]{2,})[\"'`]?\s+(?:is\s+)?"
        r"(?:not set|missing|required|undefined|empty|not defined)",
        re.I,
    ),
    re.compile(
        r"missing required (?:environment variable|configuration|config|setting|env)[:\s]+[\"'`]?([A-Z][A-Z0-9_]{2,})"
    ),
    re.compile(r"\b([A-Z][A-Z0-9_]{2,}) (?:must be set|is required|is not set|not defined)"),
)
_EXEC_FORMAT_RE = re.compile(r"exec format error", re.I)
_NOT_FOUND_RE = re.compile(r"executable file not found|no such file or directory|command not found", re.I)
_PERMISSION_RE = re.compile(r"permission denied|EACCES|read-only file system", re.I)
_ERROR_LINE_RE = re.compile(r"\b(?:error|exception|fatal|panic|traceback|failed)\b", re.I)
_STARTUP_RE = re.compile(r"(?:Started \S+ in|startup took|ready in|started in)\s+([\d.]+)\s*(ms|s|seconds)?", re.I)
_LISTEN_RE = re.compile(
    r"(?:listening|listen|serving|server started|running|started)\b[^\n]{0,40}?(?:port[ :=]+|:)(\d{2,5})\b"
    r"|Tomcat started on port\(s\):\s*(\d{2,5})|on port (\d{2,5})",
    re.I,
)


def _exit_meaning(code: Optional[int]) -> str:
    return {
        0: "completed",
        1: "application error",
        2: "misuse of shell builtins / bad arguments",
        126: "command cannot execute (permissions)",
        127: "command not found",
        128: "invalid exit argument",
        134: "SIGABRT (abort)",
        137: "SIGKILL (OOM or forced kill)",
        139: "SIGSEGV (segmentation fault)",
        143: "SIGTERM (graceful shutdown)",
    }.get(code if code is not None else -1, "non-zero exit")


def _plaintext_secret_envs(container: Dict[str, Any], redactor: Redactor) -> List[Tuple[int, str, str]]:
    out = []
    for i, env in enumerate(container.get("env") or []):
        if not isinstance(env, dict) or "value" not in env or "valueFrom" in env:
            continue
        name = str(env.get("name", ""))
        value = env.get("value")
        if value in (None, ""):
            continue
        sval = str(value)
        if is_secret_key(name) or redactor.contains_secrets(f"{sval}") or redactor.contains_secrets(f"{name}={sval}"):
            if not sval.startswith("[REDACTED") and not sval.startswith("$("):
                out.append((i, name, sval))
    return out


def _match_secret_key(ctx: _Ctx, env_name: str) -> Optional[Tuple[str, str]]:
    target = _norm_key(env_name)
    best: Optional[Tuple[float, str, str]] = None
    for sname in sorted(ctx.secrets):
        for key in ctx.secret_keys(sname):
            nk = _norm_key(key)
            if nk == target:
                return sname, key
            ratio = difflib.SequenceMatcher(None, nk, target).ratio()
            if min(len(nk), len(target)) >= 6 and (target.endswith(nk) or nk.endswith(target)):
                ratio = max(ratio, 0.85)
            if ratio >= 0.8 and (best is None or ratio > best[0]):
                best = (ratio, sname, key)
    return (best[1], best[2]) if best else None


def _detect_crashloop(ctx: _Ctx) -> Optional[Diagnosis]:
    score = 0.0
    evidence: List[Evidence] = []
    target: Optional[_Status] = None
    for st in ctx.statuses:
        if st.reason == "CrashLoopBackOff":
            target = st
            score += 0.55
            evidence.append(
                Evidence(
                    "pod.status",
                    f'container "{st.name}" waiting: CrashLoopBackOff, restarts={st.restarts}'
                    + (
                        f", last exit {st.last_exit_code} ({_exit_meaning(st.last_exit_code)})"
                        if st.last_exit_code is not None
                        else ""
                    ),
                    0.55,
                )
            )
            break
    backoff = ctx.events_matching(r"back-?off restarting failed container", ("BackOff",)) or ctx.events_matching(
        r"back-?off restarting failed container"
    )
    if backoff:
        score += 0.2
        e = backoff[0]
        evidence.append(Evidence("events", f"{e.type}/{e.reason} x{e.count}: {_clip(e.message)}", 0.2))
    if target is None:
        if not backoff:
            return None
        restarters = sorted(ctx.statuses, key=lambda s: -s.restarts)
        target = restarters[0] if restarters else None
    if target and target.restarts >= 3:
        score += 0.1
    if target and target.last_exit_code not in (None, 0):
        score += 0.05
    if score < 0.35:
        return None

    name = target.name if target else None
    idx, spec = ctx.container_spec(name)
    w = ctx.workload
    exit_code = target.last_exit_code if target else None
    symptom_of: Optional[str] = None
    sub = "application_error"
    root = ""
    edits: List[Any] = []
    remediation: List[str] = []
    patches: List[Patch] = []
    commands: List[SuggestedCommand] = [
        ctx.cmd(
            f"kubectl logs {ctx.pod_ref}{ctx.ns_flag} -c {name or '<container>'} --previous",
            "read the crash output of the last run",
        ),
        ctx.cmd(f"kubectl describe pod {ctx.pod_ref}{ctx.ns_flag}", "exit codes, probes and restart history"),
    ]

    if target and target.last_reason == "OOMKilled":
        symptom_of = FailureType.OOM_KILLED.value
        sub = "oom"
        root = "The restarts are a symptom: each run is OOMKilled (see the OOMKilled diagnosis)."
        score *= 0.6
    else:
        db = ctx.log_search(_DB_AUTH_RE)
        missing = None
        for rx in _MISSING_ENV_RES:
            missing = ctx.log_search(rx)
            if missing:
                break
        liveness = ctx.events_matching(r"liveness probe failed") or ctx.events_matching(r"failed liveness probe")
        if db:
            sub = "db_auth_failure"
            score += 0.12
            evidence.append(Evidence("logs", f"line {db[0]}: {_clip(db[1])}", 0.12))
            plain = _plaintext_secret_envs(spec, ctx.redactor) if spec else []
            root = (
                f"The application cannot authenticate to its backing service ({_clip(db[2].group(0), 60)}) and exits "
                f"with code {exit_code if exit_code is not None else '?'} on startup, so the kubelet restarts it with "
                "exponential back-off."
            )
            if plain:
                names = ", ".join(n for _, n, _ in plain)
                score += 0.08
                evidence.append(
                    Evidence(
                        "manifest",
                        f"credentials hard-coded as plaintext env values in {w.file if w else 'manifest'}: {names}",
                        0.08,
                    )
                )
                root += (
                    f" The credentials are hard-coded in plaintext in the Deployment ({names}) instead of being "
                    "read from a Secret, so they went stale when the Secret was rotated - and they leak into the "
                    "startup logs."
                )
                created: List[str] = []
                for env_index, env_name, _ in plain:
                    match = _match_secret_key(ctx, env_name)
                    if match:
                        sname, skey = match
                        rotated = _rotation_note(ctx.secrets.get(sname) or {})
                        evidence.append(
                            Evidence(
                                "secrets",
                                f"Secret {sname} holds key '{skey}' matching {env_name}{rotated}",
                                0.0,
                            )
                        )
                    else:
                        sname = f"{w.name if w else 'app'}-secrets"
                        skey = re.sub(r"[^a-z0-9]+", "-", env_name.lower()).strip("-")
                        created.append(f"{skey}=${env_name}")
                    edits.append(
                        ReplaceKey(
                            w.container_path(idx) + ("env", env_index, "value") if w and idx is not None else (),
                            "valueFrom",
                            {"secretKeyRef": {"name": sname, "key": skey}},
                        )
                    )
                remediation.append(
                    "Replace the plaintext env values with secretKeyRef references (patch below) so the Pod always "
                    "reads the current, rotated credential."
                )
                if created:
                    remediation.append(
                        "Create the missing Secret from your secret manager (never paste values into manifests)."
                    )
                    commands.append(
                        ctx.cmd(
                            f"kubectl create secret generic {w.name if w else 'app'}-secrets{ctx.ns_flag} "
                            + " ".join(f"--from-literal={c}" for c in created),
                            "store the credentials as a Secret",
                        )
                    )
                remediation.append(
                    "Rotate every credential that appeared in the logs (database password, cloud keys) - they must be "
                    "treated as compromised."
                )
                remediation.append("Stop logging configuration values at startup; log only key names.")
                if w is not None and idx is not None:
                    p = ctx.patch(w, edits, "move plaintext credentials to secretKeyRef")
                    if p:
                        patches.append(p)
            else:
                remediation.append("Verify the credentials in the referenced Secret match the database user.")
        elif missing:
            var = missing[2].group(1)
            sub = "missing_config"
            score += 0.12
            evidence.append(Evidence("logs", f"line {missing[0]}: {_clip(missing[1])}", 0.12))
            root = (
                f"The process exits at startup because the required setting {var} is not provided to the container "
                f"(exit {exit_code if exit_code is not None else '?'})."
            )
            source = _find_config_source(ctx, var)
            if source and w is not None and idx is not None:
                kind, oname, okey = source
                ref = "secretKeyRef" if kind == "Secret" else "configMapKeyRef"
                item = {"name": var, "valueFrom": {ref: {"name": oname, "key": okey}}}
                p = ctx.patch(
                    w, [AppendItem(w.container_path(idx) + ("env",), item)], f"inject {var} from {kind} {oname}"
                )
                evidence.append(Evidence(kind.lower() + "s", f"{kind} {oname} provides key '{okey}'", 0.05))
                score += 0.05
                if p:
                    patches.append(p)
                remediation.append(f"Inject {var} from {kind} {oname} (key {okey}) - patch below.")
            else:
                remediation.append(f"Provide {var} via a ConfigMap/Secret and reference it in the container env.")
        elif liveness:
            sub = "liveness_probe"
            e = liveness[0]
            score += 0.1
            evidence.append(Evidence("events", f"{e.type}/{e.reason} x{e.count}: {_clip(e.message)}", 0.1))
            root = (
                "The kubelet keeps killing the container because its liveness probe fails before the application is "
                "ready, producing a restart loop."
            )
            if spec and w is not None and idx is not None:
                probe = spec.get("livenessProbe") or {}
                listen = _listen_ports(ctx)
                declared = [p.get("containerPort") for p in spec.get("ports") or [] if isinstance(p, dict)]
                probe_kind = "httpGet" if "httpGet" in probe else "tcpSocket" if "tcpSocket" in probe else None
                probe_port = get_in(probe, (probe_kind, "port")) if probe_kind else None
                cpath = w.container_path(idx)
                startup = ctx.log_search(_STARTUP_RE)
                if isinstance(probe_port, int) and listen and probe_port not in listen:
                    fix = listen[0]
                    edits.append(SetValue(cpath + ("livenessProbe", probe_kind, "port"), fix))
                    root += f" The probe targets port {probe_port} but the app listens on {fix}."
                    remediation.append(f"Point the liveness probe at port {fix}.")
                elif isinstance(probe_port, int) and declared and probe_port not in declared and len(declared) == 1:
                    fix = declared[0]
                    edits.append(SetValue(cpath + ("livenessProbe", probe_kind, "port"), fix))
                    root += f" The probe targets port {probe_port} but the container exposes {fix}."
                    remediation.append(f"Point the liveness probe at port {fix}.")
                elif startup:
                    seconds = float(startup[2].group(1))
                    if (startup[2].group(2) or "s").lower() == "ms":
                        seconds /= 1000.0
                    delay = int(probe.get("initialDelaySeconds") or 0)
                    budget = delay + int(probe.get("periodSeconds") or 10) * int(probe.get("failureThreshold") or 3)
                    if seconds >= budget * 0.8:
                        new_delay = int(math.ceil(seconds * 1.5 / 5.0) * 5)
                        root += f" Startup takes {seconds:g}s but the probe gives up after ~{budget}s."
                        evidence.append(Evidence("logs", f"line {startup[0]}: {_clip(startup[1])}", 0.05))
                        if "initialDelaySeconds" in probe:
                            edits.append(SetValue(cpath + ("livenessProbe", "initialDelaySeconds"), new_delay))
                        else:
                            edits.append(InsertKey(cpath + ("livenessProbe",), "initialDelaySeconds", new_delay))
                        remediation.append(
                            f"Delay the liveness probe to {new_delay}s (or add a startupProbe) so slow starts are not killed."
                        )
                if edits:
                    p = ctx.patch(w, edits, "fix liveness probe")
                    if p:
                        patches.append(p)
            if not edits:
                remediation.append("Add a startupProbe or relax livenessProbe timing; make the health endpoint cheap.")
        else:
            special = (
                (
                    "exec_format",
                    _EXEC_FORMAT_RE,
                    "The image was built for a different CPU architecture (exec format error).",
                ),
                ("command_not_found", _NOT_FOUND_RE, "The container entrypoint/command cannot be found in the image."),
                (
                    "permission_denied",
                    _PERMISSION_RE,
                    "The process lacks filesystem permissions (e.g. read-only root filesystem or non-root user).",
                ),
            )
            for key, rx, text in special:
                hit = ctx.log_search(rx)
                if hit or (key == "command_not_found" and exit_code == 127):
                    sub = key
                    root = text
                    if hit:
                        evidence.append(Evidence("logs", f"line {hit[0]}: {_clip(hit[1])}", 0.1))
                        score += 0.1
                    break
            if not root:
                err = None
                for i in range(len(ctx.log_lines) - 1, -1, -1):
                    if _ERROR_LINE_RE.search(ctx.log_lines[i]):
                        err = (i + 1, ctx.log_lines[i])
                        break
                root = (
                    f"The main process exits with code {exit_code if exit_code is not None else '?'} "
                    f"({_exit_meaning(exit_code)}) shortly after start; Kubernetes restarts it with back-off."
                )
                if err:
                    evidence.append(Evidence("logs", f"last error at line {err[0]}: {_clip(err[1])}", 0.05))
                    root += f" Last error in the logs: {_clip(err[1], 120)}"
            if sub == "exec_format":
                remediation.append(
                    "Rebuild the image for the node architecture: docker buildx build --platform linux/amd64,linux/arm64."
                )
            elif sub == "command_not_found":
                remediation.append(
                    "Fix the container command/args or the image ENTRYPOINT so the binary exists in the image."
                )
            elif sub == "permission_denied":
                remediation.append(
                    "Mount an emptyDir for writable paths and align runAsUser/fsGroup with file ownership."
                )
            else:
                remediation.append("Fix the application error shown in the previous container logs, then roll out.")

    if patches:
        commands.append(ctx.apply_cmd(w))
        commands.append(
            ctx.cmd(f"kubectl rollout status {w.ref if w else 'deployment/<name>'}{ctx.ns_flag}", "watch the rollout")
        )
    title = f'Container "{name}" is crash-looping' + (f" ({sub.replace('_', ' ')})" if sub not in ("oom",) else "")
    return Diagnosis(
        failure=FailureType.CRASH_LOOP,
        confidence=_confidence(score),
        severity=_SEVERITY[FailureType.CRASH_LOOP],
        title=title,
        root_cause=root,
        sub_cause=sub,
        container=name,
        evidence=evidence,
        remediation=remediation,
        patches=patches,
        commands=commands,
        symptom_of=symptom_of,
    )


def _rotation_note(secret: Dict[str, Any]) -> str:
    ann = (secret.get("metadata") or {}).get("annotations") or {}
    for k, v in sorted(ann.items()):
        if "rotat" in k.lower():
            return f" (rotated {v})"
    return ""


def _find_config_source(ctx: _Ctx, var: str) -> Optional[Tuple[str, str, str]]:
    target = _norm_key(var)
    for sname in sorted(ctx.secrets):
        for key in ctx.secret_keys(sname):
            if _norm_key(key) == target:
                return "Secret", sname, key
    for cname in sorted(ctx.configmaps):
        for key in ctx.configmap_keys(cname):
            if _norm_key(key) == target:
                return "ConfigMap", cname, key
    return None


def _listen_ports(ctx: _Ctx) -> List[int]:
    ports: List[int] = []
    for line in ctx.log_lines:
        for m in _LISTEN_RE.finditer(line):
            val = next((g for g in m.groups() if g), None)
            if val:
                port = int(val)
                # < 80 is almost always a clock ("10:00:02"), not a listen port
                if 80 <= port <= 65535 and port not in ports:
                    ports.append(port)
    return ports


# --------------------------------------------------------------------------- #
# Detector: ImagePullBackOff
# --------------------------------------------------------------------------- #

_PULL_REASONS = ("ImagePullBackOff", "ErrImagePull", "InvalidImageName", "ErrImageNeverPull", "RegistryUnavailable")
_AUTH_RE = re.compile(
    r"401 Unauthorized|unauthorized|authentication required|pull access denied|denied: requested access"
    r"|403 Forbidden|no basic auth credentials|insufficient_scope",
    re.I,
)
_NOTFOUND_RE = re.compile(
    r"manifest unknown|not found|manifest for \S+ not found|404|does not exist|no such manifest", re.I
)
_NET_RE = re.compile(
    r"no such host|i/o timeout|connection refused|TLS handshake timeout|x509|dial tcp|network is unreachable", re.I
)
_RATE_RE = re.compile(r"toomanyrequests|rate limit", re.I)
_IMAGE_IN_MSG_RE = re.compile(r"(?:image|pulling image|pull image)\s+\"([^\"]+)\"", re.I)


def _split_image(image: str) -> Tuple[str, str]:
    """Return (repository, tag-or-digest)."""
    if "@" in image:
        repo, digest = image.split("@", 1)
        return repo, "@" + digest
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        repo, tag = image.rsplit(":", 1)
        return repo, tag
    return image, "latest"


def _registry_of(image: str) -> str:
    first = image.split("/", 1)[0]
    if "/" in image and ("." in first or ":" in first or first == "localhost"):
        return first
    return "docker.io"


def _pull_secret_for(ctx: _Ctx, registry: str) -> Optional[str]:
    candidates = []
    for name in sorted(ctx.secrets):
        s = ctx.secrets[name]
        if s.get("type") not in ("kubernetes.io/dockerconfigjson", "kubernetes.io/dockercfg"):
            continue
        hosts: List[str] = []
        for key in (".dockerconfigjson", ".dockercfg"):
            raw = (s.get("data") or {}).get(key)
            if isinstance(raw, str) and not raw.startswith("[REDACTED"):
                try:
                    decoded = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "replace"))
                    auths = decoded.get("auths", decoded) if isinstance(decoded, dict) else {}
                    hosts = [re.sub(r"^https?://", "", h).split("/", 1)[0] for h in auths]
                except (ValueError, TypeError, AttributeError):
                    hosts = []
        candidates.append((name, hosts))
    for name, hosts in candidates:
        if registry in hosts:
            return name
    for name, hosts in candidates:
        if not hosts:
            return name
    return candidates[0][0] if candidates else None


def _detect_image_pull(ctx: _Ctx) -> Optional[Diagnosis]:
    score = 0.0
    evidence: List[Evidence] = []
    target: Optional[_Status] = None
    for st in ctx.statuses:
        if st.reason in _PULL_REASONS:
            target = st
            score += 0.6
            evidence.append(
                Evidence("pod.status", f'container "{st.name}" waiting: {st.reason} - {_clip(st.message or "")}', 0.6)
            )
            break
    failed = ctx.events_matching(r"failed to pull image|error: errimagepull|pull access denied|ErrImagePull")
    backoff = ctx.events_matching(r"back-?off pulling image")
    if failed:
        score += 0.2
        evidence.append(
            Evidence("events", f"{failed[0].type}/{failed[0].reason}: {_clip(failed[0].message, 220)}", 0.2)
        )
    if backoff:
        score += 0.1
        evidence.append(
            Evidence(
                "events", f"{backoff[0].type}/{backoff[0].reason} x{backoff[0].count}: {_clip(backoff[0].message)}", 0.1
            )
        )
    if score < 0.35:
        return None
    name = target.name if target else None
    idx, spec = ctx.container_spec(name)
    w = ctx.workload
    image = str(spec.get("image") or (target.image if target else "") or "")
    if not image:
        for e in failed + backoff:
            m = _IMAGE_IN_MSG_RE.search(e.message)
            if m:
                image = m.group(1)
                break
    registry = _registry_of(image) if image else "?"
    pull_reasons = ("Failed", "BackOff", "ErrImagePull", "ImagePullBackOff", "InspectFailed", "ErrImageNeverPull")
    related = [e for e in ctx.events if e.reason in pull_reasons or e in failed]
    messages = " ".join([e.message for e in related] + [(target.message or "") if target else ""])
    edits: List[Any] = []
    remediation: List[str] = []
    patches: List[Patch] = []
    commands: List[SuggestedCommand] = [
        ctx.cmd(f"kubectl describe pod {ctx.pod_ref}{ctx.ns_flag}", "full pull error from the kubelet"),
        ctx.cmd(f"kubectl get events{ctx.ns_flag} --field-selector involvedObject.name={ctx.pod_ref}", "pull events"),
    ]
    reason_status = target.reason if target else ""
    if reason_status == "InvalidImageName" or (
        image and image != image.lower() and _split_image(image)[0] != _split_image(image)[0].lower()
    ):
        sub = "invalid_name"
        repo, tag = _split_image(image)
        fixed = repo.lower() + (tag if tag.startswith("@") else f":{tag}")
        root = f'The image reference "{image}" is invalid: repository names must be lowercase.'
        if w is not None and idx is not None and fixed != image:
            edits.append(SetValue(w.container_path(idx) + ("image",), fixed))
            remediation.append(f"Use the lowercase reference {fixed}.")
        score += 0.1
    elif _AUTH_RE.search(messages):
        sub = "registry_auth"
        score += 0.12
        pod_spec = w.pod_spec if w else {}
        existing = [s.get("name") for s in pod_spec.get("imagePullSecrets") or [] if isinstance(s, dict)]
        secret = _pull_secret_for(ctx, registry)
        root = f"The kubelet is not authorised to pull {image} from the private registry {registry} (401/denied). "
        if existing and all(e not in ctx.secrets for e in existing) and ctx.secrets:
            root += f"The pod references imagePullSecrets {existing} which do not exist in the namespace."
            if secret and w is not None:
                edits.append(SetValue(w.pod_spec_path + ("imagePullSecrets", 0, "name"), secret))
                remediation.append(f"Reference the existing pull secret {secret}.")
        elif not existing:
            root += "The pod spec has no imagePullSecrets, so the pull is anonymous."
            name_ = secret or "regcred"
            if w is not None:
                edits.append(InsertKey(w.pod_spec_path, "imagePullSecrets", [{"name": name_}]))
            if secret:
                evidence.append(Evidence("secrets", f"dockerconfigjson Secret {secret} exists for {registry}", 0.05))
                score += 0.05
                remediation.append(f"Attach the existing pull secret {secret} to the pod template (patch below).")
                commands.append(ctx.cmd(f"kubectl get secret {secret}{ctx.ns_flag}", "confirm the pull secret exists"))
            else:
                remediation.append("Create a docker-registry Secret from your CI credentials and attach it.")
                commands.append(
                    ctx.cmd(
                        f"kubectl create secret docker-registry regcred{ctx.ns_flag} --docker-server={registry} "
                        "--docker-username=$REGISTRY_USER --docker-password=$REGISTRY_TOKEN",
                        "create the pull secret",
                    )
                )
        else:
            root += f"The referenced pull secret(s) {existing} lack access to this repository or have expired."
            remediation.append(
                "Refresh the registry token stored in the pull secret and verify repository permissions."
            )
    elif _NOTFOUND_RE.search(messages):
        sub = "tag_not_found"
        repo, tag = _split_image(image)
        root = f'The tag "{tag}" of {repo} does not exist in the registry (manifest unknown).'
        good = _last_known_good(ctx, repo, image)
        if good and w is not None and idx is not None:
            edits.append(SetValue(w.container_path(idx) + ("image",), good))
            root += f" The last image that pulled successfully was {good}."
            evidence.append(Evidence("events", f"last successful pull for {repo}: {good}", 0.05))
            score += 0.05
            remediation.append(f"Roll back to the last known-good image {good} (patch below), then fix the CI tag.")
        else:
            remediation.append("Push the missing tag or correct the image reference; pin images by digest.")
    elif _RATE_RE.search(messages):
        sub = "rate_limited"
        root = f"The registry {registry} is rate-limiting anonymous pulls (toomanyrequests)."
        remediation.append("Authenticate pulls with imagePullSecrets or mirror the image to a private registry.")
    elif _NET_RE.search(messages):
        sub = "registry_unreachable"
        root = f"Nodes cannot reach the registry {registry} (DNS/TLS/network error)."
        remediation.append("Check node DNS/egress to the registry and that its CA is trusted by the container runtime.")
    else:
        sub = "unknown"
        root = f"The image {image} cannot be pulled."
        remediation.append("Inspect the full pull error with kubectl describe pod.")
    if edits and w is not None:
        p = ctx.patch(w, edits, f"fix image pull ({sub.replace('_', ' ')})")
        if p:
            patches.append(p)
            commands.append(ctx.apply_cmd(w))
            commands.append(ctx.cmd(f"kubectl rollout status {w.ref}{ctx.ns_flag}", "watch the rollout"))
    return Diagnosis(
        failure=FailureType.IMAGE_PULL,
        confidence=_confidence(score),
        severity=_SEVERITY[FailureType.IMAGE_PULL],
        title=f"Image {image or '?'} cannot be pulled ({sub.replace('_', ' ')})",
        root_cause=root,
        sub_cause=sub,
        container=name,
        evidence=evidence,
        remediation=remediation,
        patches=patches,
        commands=commands,
    )


def _last_known_good(ctx: _Ctx, repo: str, current: str) -> Optional[str]:
    rx = re.compile(r"(?:Successfully pulled image|Container image) \"([^\"]+)\"", re.I)
    found: List[str] = []
    for e in ctx.events:
        for m in rx.finditer(e.message):
            img = m.group(1)
            if img != current and _split_image(img)[0] == repo:
                found.append(img)
    ann = get_in(ctx.workload.data if ctx.workload else {}, ("metadata", "annotations")) or {}
    for k, v in sorted(ann.items()) if isinstance(ann, dict) else []:
        if "last-known-good" in k and isinstance(v, str) and _split_image(v)[0] == repo:
            found.append(v)
    return found[-1] if found else None


# --------------------------------------------------------------------------- #
# Detector: CreateContainerConfigError
# --------------------------------------------------------------------------- #

_SECRET_NF_RE = re.compile(r"secret \"([^\"]+)\" not found", re.I)
_CM_NF_RE = re.compile(r"configmaps? \"([^\"]+)\" not found", re.I)
_KEY_NF_RE = re.compile(r"couldn't find key (\S+) in (Secret|ConfigMap) ([^/\s]+)/(\S+)", re.I)
_NONROOT_RE = re.compile(r"runAsNonRoot and image will run as root|non-numeric user \(([^)]*)\)", re.I)


def _detect_config_error(ctx: _Ctx) -> Optional[Diagnosis]:
    score = 0.0
    evidence: List[Evidence] = []
    target: Optional[_Status] = None
    for st in ctx.statuses:
        if st.reason in ("CreateContainerConfigError", "CreateContainerError"):
            target = st
            score += 0.65
            evidence.append(
                Evidence("pod.status", f'container "{st.name}" waiting: {st.reason} - {_clip(st.message or "")}', 0.65)
            )
            break
    texts = [(target.message or "") if target else ""] + [e.message for e in ctx.events]
    failed = [
        e
        for e in ctx.events
        if re.search(r"CreateContainerConfigError|not found|couldn't find key|runAsNonRoot", e.message)
    ]
    if failed:
        score += 0.25
        evidence.append(Evidence("events", f"{failed[0].type}/{failed[0].reason}: {_clip(failed[0].message)}", 0.25))
    if score < 0.35:
        return None
    blob = "\n".join(texts)
    name = target.name if target else None
    idx, spec = ctx.container_spec(name)
    w = ctx.workload
    cpath = w.container_path(idx) if w is not None and idx is not None else None
    edits: List[Any] = []
    remediation: List[str] = []
    patches: List[Patch] = []
    patches_extra: List[Patch] = []
    commands = [ctx.cmd(f"kubectl describe pod {ctx.pod_ref}{ctx.ns_flag}", "see the exact config error")]
    m_key = _KEY_NF_RE.search(blob)
    m_sec = _SECRET_NF_RE.search(blob)
    m_cm = _CM_NF_RE.search(blob)
    m_root = _NONROOT_RE.search(blob)
    sub = "unknown"
    root = "The container configuration references something that does not exist."
    if m_key:
        key, kind, _ns, obj = m_key.group(1), m_key.group(2), m_key.group(3), m_key.group(4)
        sub = "missing_key"
        available = ctx.secret_keys(obj) if kind.lower() == "secret" else ctx.configmap_keys(obj)
        close = difflib.get_close_matches(key, available, n=1, cutoff=0.6)
        root = f"The container references key '{key}' in {kind} {obj}, but that key does not exist."
        if available:
            evidence.append(Evidence(kind.lower() + "s", f"{kind} {obj} has keys: {', '.join(available)}", 0.05))
        if close and cpath is not None:
            root += f" The {kind} provides '{close[0]}' - a typo in the reference."
            score += 0.05
            ref = "secretKeyRef" if kind.lower() == "secret" else "configMapKeyRef"
            for j, env in enumerate(spec.get("env") or []):
                kr = get_in(env, ("valueFrom", ref)) if isinstance(env, dict) else None
                if isinstance(kr, dict) and kr.get("name") == obj and kr.get("key") == key:
                    edits.append(SetValue(cpath + ("env", j, "valueFrom", ref, "key"), close[0]))
            remediation.append(f"Reference key '{close[0]}' instead of '{key}' (patch below).")
        else:
            remediation.append(f"Add key '{key}' to {kind} {obj} or fix the reference.")
    elif m_sec or m_cm:
        kind = "Secret" if m_sec else "ConfigMap"
        obj = (m_sec or m_cm).group(1)  # type: ignore[union-attr]
        sub = "missing_secret" if m_sec else "missing_configmap"
        pool = sorted(ctx.secrets) if m_sec else sorted(ctx.configmaps)
        close = difflib.get_close_matches(obj, pool, n=1, cutoff=0.6)
        root = f"{kind} {obj} referenced by the pod does not exist in namespace {ctx.namespace or '?'}."
        if close and cpath is not None and w is not None:
            root += f" A {kind} named {close[0]} exists - the reference is misspelled."
            score += 0.05
            evidence.append(Evidence(kind.lower() + "s", f"existing {kind}s: {', '.join(pool)}", 0.05))
            edits.extend(_rename_refs(w, idx, spec, kind, obj, close[0]))
            remediation.append(f"Reference {kind} {close[0]} instead of {obj} (patch below).")
        else:
            remediation.append(f"Create {kind} {obj} (from your secret manager / config source) before the rollout.")
            commands.append(
                ctx.cmd(
                    f"kubectl create {'secret generic' if m_sec else 'configmap'} {obj}{ctx.ns_flag} --from-env-file=.env",
                    f"create the missing {kind}",
                )
            )
    elif m_root:
        sub = "run_as_non_root"
        root = (
            "The pod enforces runAsNonRoot but the image's USER is root (or non-numeric), so the kubelet refuses to "
            "start the container."
        )
        if cpath is not None:
            sc = spec.get("securityContext")
            if isinstance(sc, dict) and sc:
                edits.append(
                    InsertKey(cpath + ("securityContext",), "runAsUser", 10001)
                    if "runAsUser" not in sc
                    else SetValue(cpath + ("securityContext", "runAsUser"), 10001)
                )
            else:
                edits.append(InsertKey(cpath, "securityContext", {"runAsUser": 10001, "runAsNonRoot": True}))
            remediation.append("Run the container as an unprivileged numeric UID (runAsUser: 10001) - patch below.")
        for fname, text in ctx.bundle.dockerfiles.items():
            if not re.search(r"(?im)^\s*USER\s+", text):
                new = _dockerfile_add_user(text)
                if new != text:
                    patches_extra.append(Patch(fname, "run the image as a non-root user", text, new, "dockerfile"))
                    remediation.append(f"Bake a non-root USER into {fname} so every runtime is safe by default.")
    if edits and w is not None:
        p = ctx.patch(w, edits, f"fix container config ({sub.replace('_', ' ')})")
        if p:
            patches.append(p)
    patches.extend(patches_extra)
    if patches:
        commands.append(ctx.apply_cmd(w))
    return Diagnosis(
        failure=FailureType.CONFIG_ERROR,
        confidence=_confidence(score),
        severity=_SEVERITY[FailureType.CONFIG_ERROR],
        title=f'Container "{name}" cannot be created ({sub.replace("_", " ")})',
        root_cause=root,
        sub_cause=sub,
        container=name,
        evidence=evidence,
        remediation=remediation,
        patches=patches,
        commands=commands,
    )


def _rename_refs(w: _Workload, idx: Optional[int], spec: Dict[str, Any], kind: str, old: str, new: str) -> List[Any]:
    edits: List[Any] = []
    if idx is None:
        return edits
    cpath = w.container_path(idx)
    ref = "secretKeyRef" if kind == "Secret" else "configMapKeyRef"
    from_ref = "secretRef" if kind == "Secret" else "configMapRef"
    for j, env in enumerate(spec.get("env") or []):
        if isinstance(env, dict) and get_in(env, ("valueFrom", ref, "name")) == old:
            edits.append(SetValue(cpath + ("env", j, "valueFrom", ref, "name"), new))
    for j, ef in enumerate(spec.get("envFrom") or []):
        if isinstance(ef, dict) and get_in(ef, (from_ref, "name")) == old:
            edits.append(SetValue(cpath + ("envFrom", j, from_ref, "name"), new))
    for j, vol in enumerate(w.pod_spec.get("volumes") or []):
        if not isinstance(vol, dict):
            continue
        if kind == "Secret" and get_in(vol, ("secret", "secretName")) == old:
            edits.append(SetValue(w.pod_spec_path + ("volumes", j, "secret", "secretName"), new))
        if kind == "ConfigMap" and get_in(vol, ("configMap", "name")) == old:
            edits.append(SetValue(w.pod_spec_path + ("volumes", j, "configMap", "name"), new))
    return edits


def _dockerfile_add_user(text: str) -> str:
    lines = text.split("\n")
    insert_at = None
    for i in range(len(lines) - 1, -1, -1):
        if re.match(r"(?i)^\s*(CMD|ENTRYPOINT)\b", lines[i]):
            insert_at = i
    if insert_at is None:
        insert_at = len(lines) - (1 if lines and lines[-1] == "" else 0)
    return "\n".join(lines[:insert_at] + ["USER 10001:10001"] + lines[insert_at:])


# --------------------------------------------------------------------------- #
# Detector: Unschedulable
# --------------------------------------------------------------------------- #

_SCHED_PART_RE = re.compile(r"(\d+)\s+(Insufficient \w+|node\(s\)[^,.]+|Too many pods)", re.I)


def _detect_unschedulable(ctx: _Ctx) -> Optional[Diagnosis]:
    score = 0.0
    evidence: List[Evidence] = []
    cond_msg = ""
    for c in ctx.conditions:
        if c.get("type") == "PodScheduled" and str(c.get("status")) == "False":
            score += 0.55
            cond_msg = str(c.get("message") or "")
            evidence.append(
                Evidence("pod.status", f"PodScheduled=False reason={c.get('reason')}: {_clip(cond_msg)}", 0.55)
            )
            break
    failed = [e for e in ctx.events if e.reason == "FailedScheduling"]
    if failed:
        score += 0.3
        evidence.append(
            Evidence(
                "events", f"{failed[0].type}/FailedScheduling x{failed[0].count}: {_clip(failed[0].message, 220)}", 0.3
            )
        )
    if ctx.phase == "Pending":
        score += 0.1
    if score < 0.35:
        return None
    message = (failed[0].message if failed else "") + " " + cond_msg
    parts = {m.group(2).strip(): int(m.group(1)) for m in _SCHED_PART_RE.finditer(message)}
    w = ctx.workload
    edits: List[Any] = []
    remediation: List[str] = []
    patches: List[Patch] = []
    commands = [
        ctx.cmd(f"kubectl describe pod {ctx.pod_ref}{ctx.ns_flag}", "scheduler decision per node"),
        ctx.cmd("kubectl describe nodes", "allocatable vs requested resources"),
        ctx.cmd("kubectl top nodes", "live node utilisation"),
    ]
    sub = "unknown"
    root = "The scheduler cannot find a node that satisfies the pod's constraints."
    insufficient = [k for k in parts if k.lower().startswith("insufficient")]
    if insufficient:
        sub = "insufficient_resources"
        res = [k.split()[-1].lower() for k in insufficient]
        root = f"No node has enough free {', '.join(res)} for the pod's requests ({_clip(message.strip(), 140)})."
        if w is not None and ctx.bundle.nodes:
            for ci, c in enumerate(w.containers):
                for r in res:
                    if r not in ("cpu", "memory"):
                        continue
                    req_raw = get_in(c, ("resources", "requests", r))
                    req = parse_quantity(req_raw)
                    allocs = [parse_quantity(get_in(n, ("status", "allocatable", r))) for n in ctx.bundle.nodes]
                    allocs = [a for a in allocs if a]
                    if req and allocs and req > max(allocs) * 0.9:
                        fit = max(allocs) * 0.6
                        new = (
                            format_memory(int(fit // Mi) * Mi)
                            if r == "memory"
                            else format_cpu(math.floor(fit * 10) / 10)
                        )
                        edits.append(SetValue(w.container_path(ci) + ("resources", "requests", r), new))
                        evidence.append(
                            Evidence(
                                "nodes",
                                f"largest node allocatable {r}="
                                + (format_memory(max(allocs)) if r == "memory" else format_cpu(max(allocs)))
                                + f" < container {c.get('name')} request {req_raw}",
                                0.05,
                            )
                        )
                        score += 0.05
                        root += f" Container {c.get('name')} requests {r}={req_raw}, more than any node can offer."
                        remediation.append(f"Lower requests.{r} of {c.get('name')} to {new} (fits the largest node).")
        if not edits:
            remediation.append(
                "Right-size requests from real usage, or add capacity (Cluster Autoscaler / bigger nodes)."
            )
    elif any("affinity" in k.lower() or "selector" in k.lower() for k in parts):
        sub = "node_selector_mismatch"
        selector = (w.pod_spec.get("nodeSelector") if w else None) or {}
        root = f"No node matches the pod's nodeSelector/affinity {selector or ''}".strip() + "."
        if w is not None and ctx.bundle.nodes and isinstance(selector, dict):
            labels = [(n.get("metadata") or {}).get("labels") or {} for n in ctx.bundle.nodes]
            for key, value in selector.items():
                if any(lbl.get(key) == value for lbl in labels):
                    continue
                values = sorted({str(lbl[key]) for lbl in labels if key in lbl})
                close = difflib.get_close_matches(str(value), values, n=1, cutoff=0.5)
                if close:
                    edits.append(SetValue(w.pod_spec_path + ("nodeSelector", key), close[0]))
                    root += f" Nodes are labelled {key}={close[0]}, the pod asks for {key}={value}."
                    evidence.append(Evidence("nodes", f"node label values for {key}: {', '.join(values)}", 0.05))
                    remediation.append(f"Use nodeSelector {key}: {close[0]} (patch below).")
                    score += 0.05
                else:
                    keys = sorted({k for lbl in labels for k in lbl})
                    close_key = difflib.get_close_matches(key, keys, n=1, cutoff=0.7)
                    if close_key:
                        edits.append(ReplaceKey(w.pod_spec_path + ("nodeSelector", key), close_key[0], value))
                        root += f" No node carries label '{key}'; did you mean '{close_key[0]}'?"
                        remediation.append(f"Rename the selector key to {close_key[0]} (patch below).")
                        score += 0.05
        if not edits:
            remediation.append("Label a node to match, or relax the nodeSelector/affinity.")
            commands.append(ctx.cmd("kubectl get nodes --show-labels", "compare node labels with the selector"))
    elif any("taint" in k.lower() for k in parts):
        sub = "untolerated_taint"
        root = "Every eligible node carries a taint the pod does not tolerate."
        remediation.append("Add a matching toleration only if the pod is meant for those dedicated nodes.")
    elif "persistentvolumeclaim" in message.lower():
        sub = "unbound_pvc"
        root = "The pod waits for a PersistentVolumeClaim that is not bound."
        remediation.append("Check the PVC's StorageClass and provisioner.")
        commands.append(ctx.cmd(f"kubectl get pvc{ctx.ns_flag}", "inspect claim status"))
    elif any("too many pods" in k.lower() for k in parts):
        sub = "too_many_pods"
        root = "Nodes reached their maximum pod count."
        remediation.append("Add nodes or raise maxPods.")
    if edits and w is not None:
        p = ctx.patch(w, edits, f"make the pod schedulable ({sub.replace('_', ' ')})")
        if p:
            patches.append(p)
            commands.append(ctx.apply_cmd(w))
    return Diagnosis(
        failure=FailureType.UNSCHEDULABLE,
        confidence=_confidence(score),
        severity=_SEVERITY[FailureType.UNSCHEDULABLE],
        title=f"Pod {ctx.pod_ref} cannot be scheduled ({sub.replace('_', ' ')})",
        root_cause=root,
        sub_cause=sub,
        evidence=evidence,
        remediation=remediation,
        patches=patches,
        commands=commands,
    )


# --------------------------------------------------------------------------- #
# Detector: ServicePortMismatch
# --------------------------------------------------------------------------- #


def _detect_service_mismatch(ctx: _Ctx) -> List[Diagnosis]:
    out: List[Diagnosis] = []
    for fname, doc_index, svc in ctx.services:
        spec = svc.get("spec") or {}
        if spec.get("type") == "ExternalName":
            continue
        selector = spec.get("selector") or {}
        if not isinstance(selector, dict) or not selector:
            continue
        sname = (svc.get("metadata") or {}).get("name", "?")
        svc_ns = (svc.get("metadata") or {}).get("namespace") or ctx.namespace
        matched = [
            w
            for w in ctx.workloads
            if w.template_labels and all(w.template_labels.get(k) == v for k, v in selector.items())
        ]
        pod_match = bool(ctx.pod_labels) and all(ctx.pod_labels.get(k) == v for k, v in selector.items())
        evidence: List[Evidence] = []
        edits: List[Any] = []
        remediation: List[str] = []
        score = 0.0
        ns_flag = f" -n {svc_ns}" if svc_ns else ""
        commands = [
            ctx.cmd(f"kubectl get endpoints {sname}{ns_flag}", "check which pod IPs/ports back the Service"),
            ctx.cmd(f"kubectl describe service {sname}{ns_flag}", "selector and targetPort"),
        ]
        if not matched and not pod_match:
            if not ctx.workloads:
                continue
            # Selector matches nothing in the bundle: propose aligning it with the closest workload.
            best = max(
                ctx.workloads,
                key=lambda w: sum(1 for k in selector if k in w.template_labels),
            )
            labels = best.template_labels
            for k, v in selector.items():
                if k in labels and labels[k] != v:
                    edits.append(SetValue(("spec", "selector", k), labels[k], doc_index))
            score = 0.6 + (0.2 if edits else 0.0)
            root = (
                f"Service {sname} selects {selector}, but no pod carries those labels (the {best.ref} template is "
                f"labelled {labels}), so the Service has no endpoints and every request fails."
            )
            evidence.append(Evidence("service", f"{fname}: selector {selector} matches no workload template", 0.6))
            if edits:
                remediation.append(f"Align the Service selector with {best.ref}'s labels (patch below).")
            else:
                remediation.append("Fix the Service selector or the pod template labels so they match.")
            out.append(
                _svc_diag(
                    ctx, fname, svc, edits, remediation, evidence, commands, score, root, "selector_mismatch", sname
                )
            )
            continue
        targets = matched or ([ctx.workload] if ctx.workload else [])
        container_ports: List[Tuple[Optional[str], int, str]] = []
        for w in targets:
            for c in w.containers:
                for p in c.get("ports") or []:
                    if isinstance(p, dict) and isinstance(p.get("containerPort"), int):
                        container_ports.append((p.get("name"), p["containerPort"], str(c.get("name"))))
        listen = _listen_ports(ctx)
        for pi, port in enumerate(spec.get("ports") or []):
            if not isinstance(port, dict):
                continue
            target = port.get("targetPort", port.get("port"))
            declared_nums = [cp for _, cp, _ in container_ports]
            declared_names = [n for n, _, _ in container_ports if n]
            ok = (
                isinstance(target, int) and (target in declared_nums or (not declared_nums and target in listen))
            ) or (isinstance(target, str) and target in declared_names)
            if ok or (isinstance(target, int) and not declared_nums and not listen):
                continue
            score = 0.6
            evidence.append(
                Evidence(
                    "service",
                    f"{fname}: port {port.get('port')} -> targetPort {target}, but containers expose "
                    + (", ".join(f"{n + '=' if n else ''}{p}" for n, p, _ in container_ports) or "no ports"),
                    0.6,
                )
            )
            actual: Optional[Tuple[Optional[str], int]] = None
            if listen:
                lp = listen[0]
                evidence.append(Evidence("logs", f"application reports it is listening on port {lp}", 0.2))
                score += 0.2
                named = [(n, p) for n, p, _ in container_ports if p == lp]
                actual = named[0] if named else (None, lp)
            elif len(container_ports) == 1:
                actual = (container_ports[0][0], container_ports[0][1])
            if ctx.statuses and all(s.ready for s in ctx.statuses if not s.init):
                score += 0.1
                evidence.append(
                    Evidence("pod.status", "pods are Running and Ready - traffic fails only through the Service", 0.1)
                )
            for ep in ctx.bundle.endpoints:
                if (ep.get("metadata") or {}).get("name") == sname:
                    eports = [
                        p.get("port")
                        for sub in ep.get("subsets") or []
                        for p in sub.get("ports") or []
                        if isinstance(p, dict)
                    ]
                    if eports:
                        evidence.append(Evidence("endpoints", f"Endpoints {sname} route to port(s) {eports}", 0.05))
                        score += 0.05
            if actual is not None:
                new_value: Any = actual[0] if actual[0] else actual[1]
                edits.append(SetValue(("spec", "ports", pi, "targetPort"), new_value, doc_index))
                shown = f"{actual[0]} ({actual[1]})" if actual[0] else str(actual[1])
                remediation.append(
                    f"Set targetPort of Service {sname} port {port.get('port')} to {shown} (patch below)."
                )
                if actual[0]:
                    remediation.append("Referencing the named container port keeps Service and Deployment in sync.")
                root = (
                    f"Service {sname} forwards port {port.get('port')} to targetPort {target}, but the container "
                    f"listens on {actual[1]}. kube-proxy sends traffic to a closed port, so clients get connection "
                    "refused / 502s while the pods themselves look healthy."
                )
            else:
                root = f"Service {sname} targetPort {target} does not match any container port."
                remediation.append("Align the Service targetPort with the containerPort the app listens on.")
            out.append(
                _svc_diag(ctx, fname, svc, edits, remediation, evidence, commands, score, root, "target_port", sname)
            )
            break
    return out


def _svc_diag(
    ctx: _Ctx,
    fname: str,
    svc: Dict[str, Any],
    edits: List[Any],
    remediation: List[str],
    evidence: List[Evidence],
    commands: List[SuggestedCommand],
    score: float,
    root: str,
    sub: str,
    sname: str,
) -> Diagnosis:
    patches: List[Patch] = []
    if edits:
        p = make_patch(fname, ctx.bundle.manifests[fname], edits, f"fix Service {sname} ({sub.replace('_', ' ')})")
        if p:
            patches.append(p)
            commands.append(ctx.cmd(f"kubectl apply -f {fname}{ctx.ns_flag}", "apply the fixed Service"))
            commands.append(
                ctx.cmd(f"kubectl get endpoints {sname}{ctx.ns_flag}", "verify endpoints now use the right port")
            )
    return Diagnosis(
        failure=FailureType.SERVICE_PORT_MISMATCH,
        confidence=_confidence(score),
        severity=_SEVERITY[FailureType.SERVICE_PORT_MISMATCH],
        title=f"Service {sname} does not route to its pods ({sub.replace('_', ' ')})",
        root_cause=root,
        sub_cause=sub,
        evidence=evidence,
        remediation=remediation,
        patches=patches,
        commands=commands,
    )


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def _timeline(ctx: _Ctx) -> List[TimelineEntry]:
    entries: List[TimelineEntry] = []
    for e in ctx.events:
        ts = _short_time(e.last or e.first)
        msg = ctx.redactor.redact(e.message).text
        if e.count > 1:
            msg = f"{msg} (x{e.count})"
        entries.append(TimelineEntry(ts, "event", e.type, e.reason, _clip(msg, 200)))
    for st in ctx.statuses:
        if st.last_finished and st.last_reason:
            entries.append(
                TimelineEntry(
                    _short_time(st.last_finished),
                    "container",
                    "Warning" if st.last_reason != "Completed" else "Normal",
                    st.last_reason,
                    f'container "{st.name}" terminated (exit {st.last_exit_code}, restarts={st.restarts})',
                )
            )
    entries.sort(key=lambda t: (t.time or "9999", t.source != "event"))
    return entries


class Correlator:
    """Run every detector over an :class:`IncidentBundle`."""

    def __init__(self, redactor: Optional[Redactor] = None, policy: Optional[PolicyEngine] = None) -> None:
        self.redactor = redactor or default_redactor()
        self.policy = policy or PolicyEngine()

    def correlate(self, bundle: IncidentBundle) -> CorrelationResult:
        ctx = _Ctx(bundle, self.redactor, self.policy)
        diagnoses: List[Diagnosis] = []
        for detector in (
            _detect_oom,
            _detect_crashloop,
            _detect_image_pull,
            _detect_config_error,
            _detect_unschedulable,
        ):
            d = detector(ctx)
            if d is not None:
                diagnoses.append(d)
        diagnoses.extend(_detect_service_mismatch(ctx))
        # A crash loop caused by OOM is a symptom, never the headline.
        if any(d.failure is FailureType.OOM_KILLED for d in diagnoses):
            for d in diagnoses:
                if (
                    d.failure is FailureType.CRASH_LOOP
                    and d.symptom_of is None
                    and d.sub_cause in ("application_error",)
                ):
                    d.symptom_of = FailureType.OOM_KILLED.value
        diagnoses.sort(key=lambda d: (d.symptom_of is not None, -d.confidence, _PRECEDENCE[d.failure]))
        redaction: Dict[str, Dict[str, Any]] = {}
        samples: List[Tuple[str, int, str]] = []
        for fname in sorted(bundle.raw_files):
            result = self.redactor.redact(bundle.raw_files[fname], source=fname)
            if result.count:
                redaction[fname] = result.audit()
                lines = result.text.splitlines()
                for ln in result.lines:
                    if 0 < ln <= len(lines):
                        samples.append((fname, ln, lines[ln - 1].strip()))
        samples.sort(key=lambda s: (not _is_runtime_source(s[0]), s[0], s[1]))
        workload = ctx.workload.ref if ctx.workload else None
        return CorrelationResult(
            bundle=bundle.name,
            namespace=ctx.namespace,
            pod=ctx.pod_name,
            workload=workload,
            diagnoses=diagnoses,
            timeline=_timeline(ctx),
            redaction=redaction,
            redaction_samples=samples,
            redactor=self.redactor,
        )


def correlate(
    bundle: Union[IncidentBundle, str, Path],
    redactor: Optional[Redactor] = None,
    policy: Optional[PolicyEngine] = None,
) -> CorrelationResult:
    """Diagnose an incident bundle (object or directory path)."""
    if not isinstance(bundle, IncidentBundle):
        bundle = IncidentBundle.from_directory(bundle)
    return Correlator(redactor, policy).correlate(bundle)


def redacted_diff(patch: Patch, redactor: Optional[Redactor] = None) -> str:
    """The patch's unified diff with every secret masked (safe to display).

    Both sides are redacted *as whole files* first - multi-line rules such as
    ``- name: DB_PASSWORD`` / ``value: ...`` need their context, which a diff
    hunk may split - and the resulting diff is scanned once more.
    """
    engine = redactor or default_redactor()
    before = engine.redact(patch.original).text
    after = engine.redact(patch.patched).text
    return engine.redact(unified_diff(before, after, patch.file)).text


def iter_patches(result: CorrelationResult) -> Iterable[Patch]:
    for d in result.diagnoses:
        yield from d.patches
