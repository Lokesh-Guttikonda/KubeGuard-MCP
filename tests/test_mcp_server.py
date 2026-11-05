import io
import json
import subprocess
import sys

import pytest

from src import __version__
from src.mcp_server import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    RESOURCE_NOT_FOUND,
    SUPPORTED_PROTOCOL_VERSIONS,
    MCPServer,
)
from tests.conftest import EXAMPLES, ROOT, SCENARIOS, assert_no_secrets, clean_env, deployment

TOOL_NAMES = {"diagnose_pod", "redact_logs", "validate_manifest", "audit_cluster_risks", "classify_command"}


@pytest.fixture
def server():
    return MCPServer(roots=[EXAMPLES])


def rpc(server, method, params=None, id_=1):
    msg = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        msg["params"] = params
    return json.loads(server.handle_line(json.dumps(msg)))


def call(server, tool, **arguments):
    reply = rpc(server, "tools/call", {"name": tool, "arguments": arguments})
    assert "result" in reply, reply
    return reply["result"]


# --------------------------------------------------------------------------- #
# lifecycle
# --------------------------------------------------------------------------- #


def test_initialize(server):
    reply = rpc(
        server,
        "initialize",
        {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
    )
    res = reply["result"]
    assert reply["id"] == 1 and reply["jsonrpc"] == "2.0"
    assert res["protocolVersion"] == "2025-06-18"
    assert res["serverInfo"] == {
        "name": "kubeguard-mcp",
        "title": "KubeGuard Zero-Trust K8s Triage",
        "version": __version__,
    }
    assert set(res["capabilities"]) >= {"tools", "resources", "prompts", "logging"}
    assert "SAFE_READ" in res["instructions"]
    assert server.client_info["name"] == "t"


@pytest.mark.parametrize(
    "requested,negotiated",
    [(v, v) for v in SUPPORTED_PROTOCOL_VERSIONS] + [("1999-01-01", "2025-06-18"), (None, "2025-06-18")],
)
def test_protocol_version_negotiation(server, requested, negotiated):
    params = {"capabilities": {}}
    if requested:
        params["protocolVersion"] = requested
    assert rpc(server, "initialize", params)["result"]["protocolVersion"] == negotiated


def test_initialized_notification_has_no_reply(server):
    assert server.handle_line('{"jsonrpc": "2.0", "method": "notifications/initialized"}') is None
    assert server.initialized


def test_ping(server):
    assert rpc(server, "ping", id_="abc") == {"jsonrpc": "2.0", "id": "abc", "result": {}}


def test_logging_set_level(server):
    assert rpc(server, "logging/setLevel", {"level": "warning"})["result"] == {}
    assert rpc(server, "logging/setLevel", {})["error"]["code"] == INVALID_PARAMS


# --------------------------------------------------------------------------- #
# JSON-RPC error handling
# --------------------------------------------------------------------------- #


def test_parse_error(server):
    reply = json.loads(server.handle_line("{not json"))
    assert reply == {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": PARSE_ERROR, "message": "Parse error: invalid JSON"},
    }


@pytest.mark.parametrize(
    "message",
    [
        {"id": 1, "method": "ping"},
        {"jsonrpc": "1.0", "id": 1, "method": "ping"},
        {"jsonrpc": "2.0", "id": 1},
        {"jsonrpc": "2.0", "id": True, "method": "ping"},
        {"jsonrpc": "2.0", "id": None, "method": "ping"},
        {"jsonrpc": "2.0", "id": 1.5, "method": "ping"},
        [],
        "just a string",
    ],
)
def test_invalid_requests(server, message):
    reply = json.loads(server.handle_line(json.dumps(message)))
    assert reply["error"]["code"] == INVALID_REQUEST


def test_method_not_found(server):
    assert rpc(server, "tools/frobnicate")["error"]["code"] == METHOD_NOT_FOUND


def test_params_must_be_an_object(server):
    reply = json.loads(server.handle_line('{"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": [1]}'))
    assert reply["error"]["code"] == INVALID_PARAMS and reply["id"] == 3


def test_notifications_never_get_replies_even_on_error(server):
    assert server.handle_line('{"jsonrpc": "2.0", "method": "does/not/exist"}') is None
    assert (
        server.handle_line('{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}')
        is None
    )


def test_client_responses_are_ignored(server):
    assert server.handle_line('{"jsonrpc": "2.0", "id": 9, "result": {}}') is None


def test_batch_requests(server):
    batch = [
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "nope"},
    ]
    replies = json.loads(server.handle_line(json.dumps(batch)))
    assert [r["id"] for r in replies] == [1, 2]
    assert "result" in replies[0] and replies[1]["error"]["code"] == METHOD_NOT_FOUND
    assert server.handle_line(json.dumps([{"jsonrpc": "2.0", "method": "notifications/initialized"}])) is None


def test_bytes_and_invalid_utf8_input(server):
    reply = json.loads(server.handle_line(b'{"jsonrpc": "2.0", "id": 1, "method": "ping"}\n'))
    assert reply["result"] == {}
    reply = json.loads(server.handle_line(b"\xff\xfe garbage"))
    assert reply["error"]["code"] == PARSE_ERROR


def test_blank_lines_are_ignored(server):
    assert server.handle_line("   \n") is None


# --------------------------------------------------------------------------- #
# tools
# --------------------------------------------------------------------------- #


def test_tools_list(server):
    tools = rpc(server, "tools/list")["result"]["tools"]
    assert {t["name"] for t in tools} == TOOL_NAMES
    for t in tools:
        assert t["inputSchema"]["type"] == "object"
        assert t["annotations"]["readOnlyHint"] is True and t["annotations"]["destructiveHint"] is False
        assert len(t["description"]) > 80
    diagnose = next(t for t in tools if t["name"] == "diagnose_pod")
    assert diagnose["inputSchema"]["properties"]["example"]["enum"] == SCENARIOS


@pytest.mark.parametrize("name", SCENARIOS)
def test_diagnose_pod_examples(server, name):
    res = call(server, "diagnose_pod", example=name)
    assert res["isError"] is False
    text = res["content"][0]["text"]
    assert text.startswith("# 🚨 SRE Incident Report") and "```diff" in text
    assert (
        res["structuredContent"]["primary"]
        == json.loads((EXAMPLES / name / "scenario.json").read_text(encoding="utf-8"))["expected_failure"]
    )
    assert_no_secrets(json.dumps(res))


def test_diagnose_pod_with_raw_inputs(server):
    pod_json = (EXAMPLES / "oom_killed" / "pod.json").read_text(encoding="utf-8")
    res = call(
        server,
        "diagnose_pod",
        pod=pod_json,
        events=json.loads((EXAMPLES / "oom_killed" / "events.json").read_text(encoding="utf-8")),
        logs=(EXAMPLES / "oom_killed" / "logs.txt").read_text(encoding="utf-8"),
        manifests=(EXAMPLES / "oom_killed" / "deployment.yaml").read_text(encoding="utf-8"),
        dockerfile=(EXAMPLES / "oom_killed" / "Dockerfile").read_text(encoding="utf-8"),
        format="json",
    )
    data = json.loads(res["content"][0]["text"])
    assert data["primary"] == "OOMKilled"
    files = {p["file"] for p in data["diagnoses"][0]["patches"]}
    assert files == {"manifest.yaml", "Dockerfile"}


def test_diagnose_pod_bundle_path_inside_roots(server):
    res = call(server, "diagnose_pod", bundle_path=str(EXAMPLES / "service_port_mismatch"))
    assert res["structuredContent"]["primary"] == "ServicePortMismatch"


def test_diagnose_pod_bundle_path_outside_roots_is_refused(server, tmp_path):
    res = call(server, "diagnose_pod", bundle_path=str(tmp_path))
    assert res["isError"] is True and "outside the allowed roots" in res["content"][0]["text"]


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_diagnose_pod_ignores_symlinks_escaping_the_bundle(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.log").write_text("ESCAPED-FILE-CONTENT DB_PASSWORD=hunter2\n", encoding="utf-8")
    bundle = tmp_path / "root" / "bundle"
    bundle.mkdir(parents=True)
    for f in ("pod.json", "events.json", "logs.txt", "deployment.yaml"):
        (bundle / f).write_bytes((EXAMPLES / "oom_killed" / f).read_bytes())
    (bundle / "leak.log").symlink_to(outside / "secret.log")
    res = call(MCPServer(roots=[tmp_path / "root"]), "diagnose_pod", bundle_path=str(bundle), format="json")
    assert res["structuredContent"]["primary"] == "OOMKilled"
    assert "ESCAPED-FILE-CONTENT" not in json.dumps(res)
    assert "leak.log" not in res["structuredContent"]["secret_firewall"]["files"]


def test_diagnose_pod_requires_input(server):
    res = call(server, "diagnose_pod")
    assert res["isError"] is True and "provide incident data" in res["content"][0]["text"]


def test_redact_logs(server):
    res = call(server, "redact_logs", text="DB_PASSWORD=hunter2 mail bob@example.org")
    assert res["content"][0]["text"] == "DB_PASSWORD=[REDACTED:secret_assignment] mail [REDACTED:email]"
    audit = res["structuredContent"]["audit"]
    assert audit["redaction_count"] == 2 and "hunter2" not in json.dumps(res)


def test_redact_logs_respects_include_pii_false(server):
    res = call(server, "redact_logs", text="mail bob@example.org", include_pii=False)
    assert res["content"][0]["text"] == "mail bob@example.org"


def test_validate_manifest_tool(server):
    manifest = deployment(
        "      - name: app\n        image: nginx\n        securityContext:\n          privileged: true\n"
    )
    res = call(server, "validate_manifest", manifest=manifest, filename="d.yaml")
    sc = res["structuredContent"]
    assert sc["passed"] is False and sc["file"] == "d.yaml"
    assert "KG004" in {f["rule_id"] for f in sc["findings"]}
    assert "Manifest validation" in res["content"][0]["text"]


def test_audit_cluster_risks_tool(server):
    manifest = (EXAMPLES / "crashloop_secret_leak" / "deployment.yaml").read_text(encoding="utf-8")
    res = call(
        server,
        "audit_cluster_risks",
        manifests={"deployment.yaml": manifest},
        commands=["kubectl delete ns shop", "kubectl get pods"],
    )
    sc = res["structuredContent"]
    assert sc["risk_level"] in ("HIGH", "CRITICAL")
    assert [c["verdict"] for c in sc["commands"]] == ["BLOCKED_DESTRUCTIVE", "SAFE_READ"]
    assert_no_secrets(json.dumps(res))


def test_audit_requires_input(server):
    assert call(server, "audit_cluster_risks")["isError"] is True


@pytest.mark.parametrize(
    "command,role,approved,verdict,allowed",
    [
        ("kubectl get pods", "viewer", False, "SAFE_READ", True),
        ("kubectl rollout restart deploy/web", "operator", False, "APPROVAL_REQUIRED", False),
        ("kubectl rollout restart deploy/web", "operator", True, "APPROVAL_REQUIRED", True),
        ("kubectl delete ns prod", "admin", True, "BLOCKED_DESTRUCTIVE", False),
    ],
)
def test_classify_command_tool(server, command, role, approved, verdict, allowed):
    res = call(server, "classify_command", command=command, role=role, approved=approved)
    sc = res["structuredContent"]
    assert sc["decision"]["verdict"] == verdict and sc["allowed"] is allowed
    assert res["content"][0]["text"].startswith(verdict)


@pytest.mark.parametrize(
    "tool,arguments,fragment",
    [
        ("redact_logs", {}, "missing required argument 'text'"),
        ("redact_logs", {"text": 5}, "must be of type string"),
        ("redact_logs", {"text": "x", "bogus": 1}, "unknown argument 'bogus'"),
        ("classify_command", {"command": "x", "role": "root"}, "must be one of"),
        ("audit_cluster_risks", {"commands": [1, 2]}, "every item"),
        ("diagnose_pod", {"example": "nope"}, "must be one of"),
        ("redact_logs", {"text": "x", "include_pii": "yes"}, "boolean"),
    ],
)
def test_argument_validation_errors_are_tool_errors(server, tool, arguments, fragment):
    reply = rpc(server, "tools/call", {"name": tool, "arguments": arguments})
    assert reply["result"]["isError"] is True
    assert fragment in reply["result"]["content"][0]["text"]


def test_unknown_tool_is_a_protocol_error(server):
    reply = rpc(server, "tools/call", {"name": "kubectl_exec", "arguments": {}})
    assert reply["error"]["code"] == INVALID_PARAMS and "Unknown tool" in reply["error"]["message"]


def test_arguments_must_be_object(server):
    reply = rpc(server, "tools/call", {"name": "redact_logs", "arguments": "text"})
    assert reply["result"]["isError"] is True


# --------------------------------------------------------------------------- #
# resources & prompts
# --------------------------------------------------------------------------- #


def test_resources_list_and_read(server):
    resources = rpc(server, "resources/list")["result"]["resources"]
    uris = [r["uri"] for r in resources]
    assert "kubeguard://policy/verdicts" in uris and f"kubeguard://examples/{SCENARIOS[0]}" in uris
    policy = rpc(server, "resources/read", {"uri": "kubeguard://policy/verdicts"})["result"]["contents"][0]
    assert policy["mimeType"] == "text/markdown" and "BLOCKED_DESTRUCTIVE" in policy["text"]
    ex = rpc(server, "resources/read", {"uri": "kubeguard://examples/crashloop_secret_leak"})["result"]["contents"][0]
    payload = json.loads(ex["text"])
    assert "deployment.yaml" in payload["files"] and payload["scenario"]["expected_failure"] == "CrashLoopBackOff"
    assert_no_secrets(ex["text"])


def test_resource_not_found(server):
    reply = rpc(server, "resources/read", {"uri": "kubeguard://examples/../../etc/passwd"})
    assert reply["error"]["code"] == RESOURCE_NOT_FOUND
    assert rpc(server, "resources/templates/list")["result"] == {"resourceTemplates": []}


def test_prompts(server):
    prompts = rpc(server, "prompts/list")["result"]["prompts"]
    assert prompts[0]["name"] == "triage_pod"
    got = rpc(server, "prompts/get", {"name": "triage_pod", "arguments": {"pod": "web-1", "namespace": "prod"}})[
        "result"
    ]
    text = got["messages"][0]["content"]["text"]
    assert "kubectl get pod web-1 -n prod -o json" in text and "classify_command" in text
    assert rpc(server, "prompts/get", {"name": "triage_pod", "arguments": {}})["error"]["code"] == INVALID_PARAMS
    assert rpc(server, "prompts/get", {"name": "nope"})["error"]["code"] == INVALID_PARAMS


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #


def test_serve_loop_in_process():
    lines = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "redact_logs", "arguments": {"text": "héllo ✓ token=abc123def"}},
        },
    ]
    stdin = io.BytesIO(("\n".join(json.dumps(m, ensure_ascii=False) for m in lines) + "\n").encode("utf-8"))
    stdout = io.BytesIO()
    assert MCPServer().serve(stdin, stdout) == 0
    replies = [json.loads(line) for line in stdout.getvalue().decode("utf-8").splitlines()]
    assert [r["id"] for r in replies] == [1, 2]
    assert replies[0]["result"]["protocolVersion"] == "2025-03-26"
    assert replies[1]["result"]["content"][0]["text"] == "héllo ✓ token=[REDACTED:secret_assignment]"


def test_stdio_subprocess_end_to_end():
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "diagnose_pod", "arguments": {"example": "crashloop_secret_leak", "format": "json"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "classify_command", "arguments": {"command": "kubectl delete ns shop"}},
        },
    ]
    payload = "".join(json.dumps(r) + "\n" for r in requests).encode("utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "src", "serve-mcp"],
        input=payload,
        capture_output=True,
        cwd=str(ROOT),
        env=clean_env(),
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    replies = [json.loads(line) for line in proc.stdout.decode("utf-8").splitlines() if line.strip()]
    assert [r["id"] for r in replies] == [1, 2, 3, 4]
    assert len(replies[1]["result"]["tools"]) == 5
    assert json.loads(replies[2]["result"]["content"][0]["text"])["primary"] == "CrashLoopBackOff"
    assert replies[3]["result"]["structuredContent"]["decision"]["verdict"] == "BLOCKED_DESTRUCTIVE"
    assert_no_secrets(proc.stdout.decode("utf-8"))
    assert b"ready on stdio" in proc.stderr  # diagnostics go to stderr, never stdout
