"""Model Context Protocol server (JSON-RPC 2.0 over stdio).

Connect Claude Desktop, Claude Code, Cursor or any MCP client and get five
*read-only analysis* tools:

``diagnose_pod``         correlate pod/events/logs/manifests -> root cause + exact patch
``redact_logs``          run the secret & PII firewall over arbitrary text
``validate_manifest``    lint a manifest for reliability/security defects
``audit_cluster_risks``  aggregate manifest, RBAC, secret and command risk
``classify_command``     zero-trust verdict for a kubectl/docker/helm command

Zero-trust by construction: the server holds no cluster credentials, never
executes commands, never opens a network connection, and every byte it writes
to stdout passes the redaction firewall.  Only JSON-RPC messages go to stdout
(newline-delimited UTF-8); diagnostics go to stderr.

Run it with ``kubeguard serve-mcp`` (or ``python -m src serve-mcp`` from a
checkout).
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path
from typing import IO, Any, Callable, Dict, List, Optional, Union

from . import __version__
from .auditor import audit_cluster, validate_manifest
from .correlator import IncidentBundle, correlate
from .policy import ROLES, PolicyEngine
from .redactor import Redactor, default_redactor
from .report import render_json, render_markdown
from .scenarios import list_scenarios, load_scenario, scenario_dir, scenario_metadata

__all__ = ["SUPPORTED_PROTOCOL_VERSIONS", "TOOLS", "MCPServer", "RpcError", "main", "serve"]

SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]
MAX_MESSAGE_BYTES = 16 * 1024 * 1024

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
RESOURCE_NOT_FOUND = -32002

_READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
_ANY_JSON = ["object", "array", "string"]

INSTRUCTIONS = (
    "KubeGuard is a zero-trust Kubernetes/Docker triage server. Collect data with SAFE_READ commands only "
    "(kubectl get pod <pod> -o json, kubectl get events -o json, kubectl logs <pod> --previous, the workload "
    "YAML) and pass it to diagnose_pod. Secrets are redacted before analysis and in every response. Before "
    "suggesting any command to the user, check it with classify_command: never run BLOCKED_DESTRUCTIVE commands, "
    "and ask for explicit human approval for APPROVAL_REQUIRED ones."
)


def _example_names() -> List[str]:
    try:
        return list_scenarios()
    except OSError:  # pragma: no cover - unreadable install
        return []


def _tools() -> List[Dict[str, Any]]:
    examples = _example_names()
    example_prop: Dict[str, Any] = {"type": "string", "description": "Diagnose one of the bundled offline examples."}
    if examples:
        example_prop["enum"] = examples
    return [
        {
            "name": "diagnose_pod",
            "title": "Diagnose a failing pod",
            "description": (
                "Deterministically correlate Pod JSON, Events, container logs and Deployment/Service YAML (plus "
                "optional Dockerfile, Secrets metadata, Nodes, Endpoints or docker inspect output) to diagnose "
                "OOMKilled, CrashLoopBackOff, ImagePullBackOff, CreateContainerConfigError, Unschedulable and "
                "Service port mismatches. Returns the root cause, weighted evidence, an exact unified diff patch "
                "and a policy-classified command plan. All secrets are redacted. No LLM, no network."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pod": {
                        "type": ["object", "string"],
                        "description": "kubectl get pod <name> -o json (object or JSON/YAML text)",
                    },
                    "events": {
                        "type": _ANY_JSON,
                        "description": "kubectl get events -o json, an event list, or the plain-text table",
                    },
                    "logs": {"type": "string", "description": "kubectl logs <pod> [--previous] output"},
                    "manifests": {
                        "type": _ANY_JSON,
                        "description": "Workload/Service YAML or JSON (multi-document OK), or {filename: content}",
                    },
                    "dockerfile": {"type": "string", "description": "Dockerfile content (enables Dockerfile patches)"},
                    "secrets": {"type": _ANY_JSON, "description": "Secret objects; values are redacted automatically"},
                    "nodes": {"type": _ANY_JSON, "description": "kubectl get nodes -o json (for scheduling analysis)"},
                    "endpoints": {"type": _ANY_JSON, "description": "kubectl get endpoints <svc> -o json"},
                    "docker_inspect": {
                        "type": ["array", "object", "string"],
                        "description": "docker inspect <container> output",
                    },
                    "example": example_prop,
                    "bundle_path": {
                        "type": "string",
                        "description": "Directory containing pod.json, events.json, logs.txt, *.yaml (must be under KUBEGUARD_MCP_ROOTS)",
                    },
                    "format": {"type": "string", "enum": ["markdown", "json"], "default": "markdown"},
                },
                "additionalProperties": False,
            },
            "annotations": dict(_READ_ONLY, title="Diagnose a failing pod"),
        },
        {
            "name": "redact_logs",
            "title": "Redact secrets & PII",
            "description": (
                "Strip AWS keys, JWTs/service-account tokens, kubeconfig credentials, database connection-string "
                "passwords, .env secrets, private keys, API keys and PII from logs or manifests. Returns the clean "
                "text plus a redaction audit (counts per rule, line numbers) - never the secret values."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Logs, YAML, JSON or any text"},
                    "include_pii": {
                        "type": "boolean",
                        "default": True,
                        "description": "Also redact e-mails, card numbers, SSNs",
                    },
                    "redact_ips": {"type": "boolean", "default": False, "description": "Also redact IPv4 addresses"},
                },
                "required": ["text"],
                "additionalProperties": False,
            },
            "annotations": dict(_READ_ONLY, title="Redact secrets & PII"),
        },
        {
            "name": "validate_manifest",
            "title": "Validate a Kubernetes manifest",
            "description": (
                "Lint Kubernetes YAML/JSON (or docker-compose) for incident-causing defects: missing memory limits, "
                "unpinned images, privileged/root containers, host mounts, plaintext credentials, Service targetPort "
                "drift, JVM heaps above the memory limit and risky RBAC. Returns findings with line numbers and a "
                "0-100 score."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "manifest": {"type": "string", "description": "Manifest text (multi-document YAML allowed)"},
                    "filename": {"type": "string", "default": "manifest.yaml"},
                },
                "required": ["manifest"],
                "additionalProperties": False,
            },
            "annotations": dict(_READ_ONLY, title="Validate a Kubernetes manifest"),
        },
        {
            "name": "audit_cluster_risks",
            "title": "Audit cluster risk",
            "description": (
                "Aggregate risk across manifests (workloads, Services, Secrets, Roles/Bindings) and a list of "
                "kubectl/docker/helm commands into one 0-100 risk score with the top risks, RBAC escalation paths, "
                "secret exposure counts and per-command zero-trust verdicts."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "manifests": {
                        "type": ["string", "object"],
                        "description": "Manifest text, or {filename: content} for several files",
                    },
                    "commands": {"type": "array", "items": {"type": "string"}, "description": "Commands to classify"},
                    "role": {"type": "string", "enum": list(ROLES), "default": "operator"},
                },
                "additionalProperties": False,
            },
            "annotations": dict(_READ_ONLY, title="Audit cluster risk"),
        },
        {
            "name": "classify_command",
            "title": "Check a command against the zero-trust policy",
            "description": (
                "Classify a kubectl/oc/docker/podman/helm command as SAFE_READ, APPROVAL_REQUIRED or "
                "BLOCKED_DESTRUCTIVE, with reasons and a risk score, and say whether the given role may run it. "
                "Pipes, chaining, command substitution and non-allowlisted binaries are blocked."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "role": {"type": "string", "enum": list(ROLES), "default": "operator"},
                    "approved": {"type": "boolean", "default": False, "description": "A human approved this command"},
                },
                "required": ["command"],
                "additionalProperties": False,
            },
            "annotations": dict(_READ_ONLY, title="Check a command"),
        },
    ]


TOOLS = _tools()


class RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class ToolError(Exception):
    """A tool failed in a way the model can correct (bad input, missing file)."""


_JSON_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "integer": int,
    "number": (int, float),
    "null": type(None),
}


def _validate(schema: Dict[str, Any], args: Any) -> None:
    if not isinstance(args, dict):
        raise ToolError("arguments must be a JSON object")
    props = schema.get("properties", {})
    for req in schema.get("required", []):
        if req not in args:
            raise ToolError(f"missing required argument '{req}'")
    for key, value in args.items():
        if key not in props:
            if schema.get("additionalProperties") is False:
                raise ToolError(f"unknown argument '{key}' (expected one of: {', '.join(sorted(props))})")
            continue
        spec = props[key]
        types = spec.get("type")
        if types:
            allowed = types if isinstance(types, list) else [types]
            ok = any(
                isinstance(value, _JSON_TYPES[t]) and not (t in ("integer", "number") and isinstance(value, bool))
                for t in allowed
            )
            if not ok:
                raise ToolError(f"argument '{key}' must be of type {' or '.join(allowed)}")
        if "enum" in spec and value not in spec["enum"]:
            raise ToolError(f"argument '{key}' must be one of: {', '.join(map(str, spec['enum']))}")
        if spec.get("type") == "array" and "items" in spec and isinstance(value, list):
            item_type = _JSON_TYPES.get(spec["items"].get("type", ""), object)
            if not all(isinstance(v, item_type) for v in value):
                raise ToolError(f"every item of '{key}' must be of type {spec['items'].get('type')}")


class MCPServer:
    """Transport-independent MCP request handler."""

    def __init__(self, redactor: Optional[Redactor] = None, roots: Optional[List[Union[str, Path]]] = None) -> None:
        self.redactor = redactor or default_redactor()
        if roots is None:
            env = os.environ.get("KUBEGUARD_MCP_ROOTS")
            roots = [p for p in env.split(os.pathsep) if p] if env else [os.getcwd()]
        self.roots = [Path(r).resolve() for r in roots]
        self.initialized = False
        self.protocol_version = LATEST_PROTOCOL_VERSION
        self.client_info: Dict[str, Any] = {}
        self.log_level = "info"
        self._methods: Dict[str, Callable[[Dict[str, Any]], Any]] = {
            "initialize": self._initialize,
            "ping": lambda p: {},
            "tools/list": self._tools_list,
            "tools/call": self._tools_call,
            "resources/list": self._resources_list,
            "resources/read": self._resources_read,
            "resources/templates/list": lambda p: {"resourceTemplates": []},
            "prompts/list": self._prompts_list,
            "prompts/get": self._prompts_get,
            "logging/setLevel": self._set_level,
        }
        self._notifications = {
            "notifications/initialized",
            "notifications/cancelled",
            "notifications/roots/list_changed",
        }
        self._tools: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
            "diagnose_pod": self._tool_diagnose,
            "redact_logs": self._tool_redact,
            "validate_manifest": self._tool_validate,
            "audit_cluster_risks": self._tool_audit,
            "classify_command": self._tool_classify,
        }

    # ------------------------------------------------------------------ #
    # JSON-RPC plumbing
    # ------------------------------------------------------------------ #
    def handle_line(self, line: Union[str, bytes]) -> Optional[str]:
        """Process one newline-delimited message; return the serialized reply (or None)."""
        if isinstance(line, bytes):
            if len(line) > MAX_MESSAGE_BYTES:
                return self._dump(self._error(None, INVALID_REQUEST, "message too large"))
            line = line.decode("utf-8", errors="replace")
        if len(line) > MAX_MESSAGE_BYTES:
            return self._dump(self._error(None, INVALID_REQUEST, "message too large"))
        line = line.strip()
        if not line:
            return None
        try:
            message = json.loads(line)
        except (ValueError, RecursionError):
            return self._dump(self._error(None, PARSE_ERROR, "Parse error: invalid JSON"))
        if isinstance(message, list):
            if not message:
                return self._dump(self._error(None, INVALID_REQUEST, "Invalid Request: empty batch"))
            replies = [r for r in (self.handle_message(m) for m in message) if r is not None]
            return self._dump(replies) if replies else None
        reply = self.handle_message(message)
        return self._dump(reply) if reply is not None else None

    def handle_message(self, message: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            mid = message.get("id") if isinstance(message, dict) and _valid_id(message.get("id")) else None
            return self._error(mid, INVALID_REQUEST, "Invalid Request: expected a JSON-RPC 2.0 object")
        method = message.get("method")
        if method is None and ("result" in message or "error" in message):
            return None  # a response to a server->client request; we never send any
        is_request = "id" in message
        mid = message.get("id")
        if is_request and not _valid_id(mid):
            return self._error(None, INVALID_REQUEST, "Invalid Request: id must be a string or an integer")
        if not isinstance(method, str):
            return self._error(mid if is_request else None, INVALID_REQUEST, "Invalid Request: missing method")
        params = message.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            if not is_request:
                return None
            return self._error(mid, INVALID_PARAMS, "Invalid params: params must be an object")
        if not is_request:
            if method == "notifications/initialized":
                self.initialized = True
            return None  # notifications never get a reply, even on error
        handler = self._methods.get(method)
        if handler is None:
            return self._error(mid, METHOD_NOT_FOUND, f"Method not found: {method}")
        try:
            result = handler(params)
        except RpcError as exc:
            return self._error(mid, exc.code, exc.message, exc.data)
        except Exception as exc:  # pragma: no cover - defensive
            self._log("error", f"internal error in {method}: {type(exc).__name__}: {exc}\n{traceback.format_exc()}")
            return self._error(mid, INTERNAL_ERROR, "Internal error")
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def _error(self, mid: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
        err: Dict[str, Any] = {"code": code, "message": self.redactor.redact(message).text}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": "2.0", "id": mid, "error": err}

    def _dump(self, obj: Any) -> str:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

    def _log(self, level: str, message: str) -> None:
        order = ["debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"]
        if order.index(level) >= order.index(self.log_level if self.log_level in order else "info"):
            try:
                sys.stderr.write(f"[kubeguard-mcp] {level}: {self.redactor.redact(message).text}\n")
                sys.stderr.flush()
            except (OSError, ValueError):  # pragma: no cover
                pass

    # ------------------------------------------------------------------ #
    # Lifecycle & discovery
    # ------------------------------------------------------------------ #
    def _initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        requested = params.get("protocolVersion")
        self.protocol_version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else LATEST_PROTOCOL_VERSION
        info = params.get("clientInfo")
        self.client_info = info if isinstance(info, dict) else {}
        return {
            "protocolVersion": self.protocol_version,
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"subscribe": False, "listChanged": False},
                "prompts": {"listChanged": False},
                "logging": {},
            },
            "serverInfo": {"name": "kubeguard-mcp", "title": "KubeGuard Zero-Trust K8s Triage", "version": __version__},
            "instructions": INSTRUCTIONS,
        }

    def _set_level(self, params: Dict[str, Any]) -> Dict[str, Any]:
        level = params.get("level")
        if not isinstance(level, str):
            raise RpcError(INVALID_PARAMS, "Invalid params: level is required")
        self.log_level = level
        return {}

    def _tools_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {"tools": _tools()}

    def _resources_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        resources = [
            {
                "uri": "kubeguard://policy/verdicts",
                "name": "zero-trust-policy",
                "title": "Zero-trust command policy",
                "description": "How KubeGuard classifies kubectl/docker/helm commands",
                "mimeType": "text/markdown",
            }
        ]
        for name in _example_names():
            meta = scenario_metadata(name)
            resources.append(
                {
                    "uri": f"kubeguard://examples/{name}",
                    "name": name,
                    "title": meta.get("title", name),
                    "description": meta.get("summary", "offline incident bundle"),
                    "mimeType": "application/json",
                }
            )
        return {"resources": resources}

    def _resources_read(self, params: Dict[str, Any]) -> Dict[str, Any]:
        uri = params.get("uri")
        if not isinstance(uri, str):
            raise RpcError(INVALID_PARAMS, "Invalid params: uri is required")
        if uri == "kubeguard://policy/verdicts":
            return {"contents": [{"uri": uri, "mimeType": "text/markdown", "text": POLICY_DOC}]}
        prefix = "kubeguard://examples/"
        if uri.startswith(prefix) and uri[len(prefix) :] in _example_names():
            name = uri[len(prefix) :]
            folder = scenario_dir(name)
            files = {}
            for f in sorted(folder.iterdir()):
                if f.is_file():
                    files[f.name] = self.redactor.redact(f.read_text(encoding="utf-8", errors="replace")).text
            payload = {"scenario": scenario_metadata(name), "files": files}
            return {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(payload, indent=2, ensure_ascii=False),
                    }
                ]
            }
        raise RpcError(RESOURCE_NOT_FOUND, "Resource not found", {"uri": uri})

    def _prompts_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "prompts": [
                {
                    "name": "triage_pod",
                    "title": "Zero-trust pod triage",
                    "description": "Collect read-only evidence for a failing pod and diagnose it with KubeGuard",
                    "arguments": [
                        {"name": "pod", "description": "Pod name", "required": True},
                        {"name": "namespace", "description": "Namespace (default: default)", "required": False},
                    ],
                }
            ]
        }

    def _prompts_get(self, params: Dict[str, Any]) -> Dict[str, Any]:
        if params.get("name") != "triage_pod":
            raise RpcError(INVALID_PARAMS, f"Unknown prompt: {params.get('name')}")
        args = params.get("arguments") or {}
        pod = str(args.get("pod") or "").strip()
        if not pod:
            raise RpcError(INVALID_PARAMS, "Missing required argument: pod")
        ns = str(args.get("namespace") or "default").strip()
        text = (
            f"Triage the failing pod {pod} in namespace {ns} using only SAFE_READ commands:\n"
            f"1. kubectl get pod {pod} -n {ns} -o json\n"
            f"2. kubectl get events -n {ns} --field-selector involvedObject.name={pod} -o json\n"
            f"3. kubectl logs {pod} -n {ns} --all-containers --previous\n"
            f"4. kubectl get deployment,service -n {ns} -o yaml (the owning workload and its Service)\n"
            "Pass everything to the diagnose_pod tool. Present the root cause, the evidence and the patch. "
            "Check every command you suggest with classify_command and never run BLOCKED_DESTRUCTIVE commands."
        )
        return {
            "description": f"Zero-trust triage of {ns}/{pod}",
            "messages": [{"role": "user", "content": {"type": "text", "text": text}}],
        }

    # ------------------------------------------------------------------ #
    # Tools
    # ------------------------------------------------------------------ #
    def _tools_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        name = params.get("name")
        if not isinstance(name, str) or name not in self._tools:
            raise RpcError(INVALID_PARAMS, f"Unknown tool: {name}")
        args = params.get("arguments")
        if args is None:
            args = {}
        schema = next(t["inputSchema"] for t in _tools() if t["name"] == name)
        try:
            _validate(schema, args)
            result = self._tools[name](args)
        except ToolError as exc:
            return self._tool_error(str(exc))
        except (ValueError, KeyError, FileNotFoundError, NotADirectoryError) as exc:
            return self._tool_error(f"{type(exc).__name__}: {exc}")
        except Exception as exc:  # never leak a traceback to the model
            self._log("error", f"tool {name} crashed: {type(exc).__name__}: {exc}\n{traceback.format_exc()}")
            return self._tool_error(f"internal error while running {name} ({type(exc).__name__})")
        engine = result.pop("_redactor", None) or self.redactor
        return self._finalize(result, engine)

    def _tool_error(self, message: str) -> Dict[str, Any]:
        return {"content": [{"type": "text", "text": self.redactor.redact(message).text}], "isError": True}

    def _finalize(self, result: Dict[str, Any], engine: Redactor) -> Dict[str, Any]:
        """Final egress firewall over every string in the tool result."""
        clean, _ = engine.redact_obj(result)
        clean.setdefault("isError", False)
        return clean

    def _resolve_bundle(self, path: str) -> Path:
        target = Path(path).expanduser().resolve()
        if not any(target == root or _is_relative_to(target, root) for root in self.roots):
            raise ToolError(
                f"bundle_path is outside the allowed roots ({', '.join(str(r) for r in self.roots)}); "
                "set KUBEGUARD_MCP_ROOTS to allow it"
            )
        if not target.is_dir():
            raise ToolError(f"bundle_path {path!r} is not a directory")
        return target

    def _tool_diagnose(self, args: Dict[str, Any]) -> Dict[str, Any]:
        scenario: Dict[str, Any] = {}
        if args.get("example"):
            bundle = load_scenario(args["example"])
            scenario = scenario_metadata(args["example"])
        elif args.get("bundle_path"):
            bundle = IncidentBundle.from_directory(self._resolve_bundle(args["bundle_path"]), confine=True)
        else:
            keys = (
                "pod",
                "events",
                "logs",
                "manifests",
                "dockerfile",
                "secrets",
                "nodes",
                "endpoints",
                "docker_inspect",
            )
            given = {k: args[k] for k in keys if args.get(k) not in (None, "", [], {})}
            if not given:
                raise ToolError("provide incident data (pod/events/logs/manifests...), an example name, or bundle_path")
            bundle = IncidentBundle.from_inputs(**given)
        result = correlate(bundle, redactor=self.redactor)
        fmt = args.get("format", "markdown")
        text = render_json(result) if fmt == "json" else render_markdown(result, scenario=scenario)
        return {"content": [{"type": "text", "text": text}], "structuredContent": result.to_dict()}

    def _tool_redact(self, args: Dict[str, Any]) -> Dict[str, Any]:
        engine = Redactor(include_pii=args.get("include_pii", True), redact_ips=args.get("redact_ips", False))
        res = engine.redact(args["text"])
        audit = res.audit()
        summary = f"{res.count} value(s) redacted" + (
            ": " + ", ".join(f"{k} x{v}" for k, v in res.by_rule.items()) if res.count else ""
        )
        return {
            "content": [{"type": "text", "text": res.text}, {"type": "text", "text": summary}],
            "structuredContent": {"redacted": res.text, "audit": audit},
            "_redactor": engine,  # egress pass must honour include_pii / redact_ips
        }

    def _tool_validate(self, args: Dict[str, Any]) -> Dict[str, Any]:
        report = validate_manifest(args["manifest"], args.get("filename") or "manifest.yaml", self.redactor)
        return {"content": [{"type": "text", "text": report.to_markdown()}], "structuredContent": report.to_dict()}

    def _tool_audit(self, args: Dict[str, Any]) -> Dict[str, Any]:
        manifests = args.get("manifests")
        if isinstance(manifests, dict) and not all(isinstance(v, str) for v in manifests.values()):
            raise ToolError("manifests must be a string or an object mapping file names to strings")
        commands = args.get("commands") or []
        if manifests in (None, "", {}) and not commands:
            raise ToolError("provide manifests and/or commands to audit")
        audit = audit_cluster(manifests, commands, role=args.get("role", "operator"), redactor=self.redactor)
        return {"content": [{"type": "text", "text": audit.to_markdown()}], "structuredContent": audit.to_dict()}

    def _tool_classify(self, args: Dict[str, Any]) -> Dict[str, Any]:
        engine = PolicyEngine(role=args.get("role", "operator"))
        auth = engine.authorize(args["command"], approved=bool(args.get("approved", False)))
        d = auth.decision
        text = (
            f"{d.verdict.value} (risk {d.risk_score}/100) - {'; '.join(d.reasons)}\n"
            f"role={auth.role}: {'ALLOWED' if auth.allowed else 'DENIED'} - {auth.reason}"
        )
        return {"content": [{"type": "text", "text": text}], "structuredContent": auth.to_dict()}

    # ------------------------------------------------------------------ #
    # stdio transport
    # ------------------------------------------------------------------ #
    def serve(self, stdin: Optional[IO[bytes]] = None, stdout: Optional[IO[bytes]] = None) -> int:
        """Blocking newline-delimited JSON-RPC loop over binary stdio (UTF-8 on every OS)."""
        inp = stdin if stdin is not None else sys.stdin.buffer
        out = stdout if stdout is not None else sys.stdout.buffer
        self._log("info", f"kubeguard-mcp {__version__} ready on stdio (protocol {LATEST_PROTOCOL_VERSION})")
        while True:
            raw = inp.readline(MAX_MESSAGE_BYTES + 1)
            if not raw:
                break
            if len(raw) > MAX_MESSAGE_BYTES and not raw.endswith(b"\n"):
                # drain the rest of the oversized line
                while raw and not raw.endswith(b"\n"):
                    raw = inp.readline(MAX_MESSAGE_BYTES)
                reply: Optional[str] = self._dump(self._error(None, INVALID_REQUEST, "message too large"))
            else:
                reply = self.handle_line(raw)
            if reply is not None:
                try:
                    out.write(reply.encode("utf-8") + b"\n")
                    out.flush()
                except (BrokenPipeError, OSError):
                    break
        return 0


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool))


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


POLICY_DOC = """# KubeGuard zero-trust command policy

| Verdict | Meaning | Examples |
|---|---|---|
| SAFE_READ | read-only, non-sensitive; may run unattended | `kubectl get/describe/logs/top`, `docker ps/logs/inspect`, `helm status` |
| APPROVAL_REQUIRED | mutates state, opens a shell/tunnel, or reads secret values | `kubectl apply/scale/rollout restart/exec`, `kubectl get secret -o yaml`, `docker run` |
| BLOCKED_DESTRUCTIVE | irreversible, bulk, privilege-escalating or shell-injected | `kubectl delete ns`, `delete --all`, `drain`, cluster-admin bindings, `docker system prune`, `--privileged`, `;`/`&&`/`|`/`$(...)` |

Unknown binaries are denied by default; unknown verbs require approval; mutations in
kube-system/kube-public/kube-node-lease are blocked.
"""


def serve() -> int:
    return MCPServer().serve()


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point for the ``kubeguard-mcp`` console script."""
    return serve()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
