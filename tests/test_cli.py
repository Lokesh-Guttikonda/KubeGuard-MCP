import io
import json
import sys

import pytest

from src import __version__, yaml_lite
from src.cli import main
from tests.conftest import EXAMPLES, assert_no_secrets, run_py


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def feed_stdin(monkeypatch, text):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(text.encode("utf-8")), encoding="utf-8"))


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"kubeguard-mcp {__version__}"


def test_no_command_prints_help(capsys):
    code, out, _ = run(capsys)
    assert code == 0 and "serve-mcp" in out and "diagnose" in out


def test_bad_arguments_exit_2(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["diagnose", "--format", "pdf"])
    assert exc.value.code == 2


# --------------------------------------------------------------------------- #
# demo
# --------------------------------------------------------------------------- #


def test_demo_all(capsys):
    code, out, _ = run(capsys, "demo", "--no-color")
    assert code == 0
    assert "4/4 incidents diagnosed correctly" in out
    assert "# 🛡️ KubeGuard SRE Incident Report" in out
    assert_no_secrets(out)


def test_demo_single_without_report(capsys):
    code, out, _ = run(capsys, "demo", "-s", "image_pull_backoff", "--no-report", "--no-color")
    assert code == 0 and "[1/1] image_pull_backoff" in out and "SRE Incident Report" not in out


def test_demo_json(capsys):
    code, out, _ = run(capsys, "demo", "--json")
    data = json.loads(out)
    assert code == 0 and data["all_diagnosed_correctly"] is True
    assert [i["primary"] for i in data["incidents"]] == [
        "OOMKilled",
        "CrashLoopBackOff",
        "ServicePortMismatch",
        "ImagePullBackOff",
    ]


def test_demo_writes_report_file(capsys, tmp_path):
    target = tmp_path / "out" / "report.md"
    code, out, _ = run(capsys, "demo", "--report", str(target), "--no-report")
    assert code == 0 and target.read_text(encoding="utf-8").startswith("# 🛡️ KubeGuard SRE Incident Report")


# --------------------------------------------------------------------------- #
# diagnose
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "fmt,marker",
    [("text", "Secret firewall"), ("markdown", "## Root cause analysis"), ("json", '"primary": "OOMKilled"')],
)
def test_diagnose_formats(capsys, fmt, marker):
    code, out, _ = run(capsys, "diagnose", str(EXAMPLES / "oom_killed"), "--format", fmt, "--no-color")
    assert code == 0 and marker in out
    assert_no_secrets(out)


def test_diagnose_example_flag(capsys):
    code, out, _ = run(capsys, "diagnose", "--example", "crashloop_secret_leak", "--no-color")
    assert code == 0 and "CrashLoopBackOff" in out and "BLOCKED_DESTRUCTIVE" in out
    assert_no_secrets(out)


def test_diagnose_individual_files(capsys):
    d = EXAMPLES / "service_port_mismatch"
    code, out, _ = run(
        capsys,
        "diagnose",
        "--pod", str(d / "pod.json"),
        "--events", str(d / "events.json"),
        "--logs", str(d / "logs.txt"),
        "-m", str(d / "deployment.yaml"),
        "-m", str(d / "service.yaml"),
        "--format", "json",
    )  # fmt: skip
    data = json.loads(out)
    assert code == 0 and data["primary"] == "ServicePortMismatch"
    assert data["diagnoses"][0]["patches"][0]["file"] == "service.yaml"


def test_diagnose_logs_from_stdin(capsys, monkeypatch):
    feed_stdin(monkeypatch, (EXAMPLES / "oom_killed" / "logs.txt").read_text(encoding="utf-8"))
    d = EXAMPLES / "oom_killed"
    code, out, _ = run(capsys, "diagnose", "--pod", str(d / "pod.json"), "--logs", "-", "--format", "json")
    assert code == 0 and json.loads(out)["primary"] == "OOMKilled"


def test_diagnose_patch_out_and_write_fixed(capsys, tmp_path):
    patch_file = tmp_path / "fix.patch"
    fixed = tmp_path / "fixed"
    code, _, err = run(
        capsys,
        "diagnose",
        str(EXAMPLES / "crashloop_secret_leak"),
        "--patch-out",
        str(patch_file),
        "--write-fixed",
        str(fixed),
        "-o",
        str(tmp_path / "r.txt"),
    )
    assert code == 0
    diff = patch_file.read_text(encoding="utf-8")
    assert diff.startswith("--- a/deployment.yaml") and "secretKeyRef" in diff
    assert_no_secrets(diff)
    assert "hunks contain redacted values" in err
    env = yaml_lite.load((fixed / "deployment.yaml").read_text(encoding="utf-8"))["spec"]["template"]["spec"][
        "containers"
    ][0]["env"]
    assert env[0]["valueFrom"]["secretKeyRef"]["name"] == "orders-db-credentials"


def test_diagnose_clean_patch_has_no_warning(capsys, tmp_path):
    code, _, err = run(
        capsys,
        "diagnose",
        "--example",
        "service_port_mismatch",
        "--patch-out",
        str(tmp_path / "p.diff"),
        "-o",
        str(tmp_path / "r"),
    )
    assert code == 0 and "patch written" in err and "redacted values" not in err


def test_diagnose_with_mock_review(capsys):
    code, out, _ = run(capsys, "diagnose", "--example", "oom_killed", "--review", "--format", "markdown")
    assert code == 0 and "AI second opinion (`mock`)" in out


def test_diagnose_review_failure_is_non_fatal(capsys, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    code, out, err = run(capsys, "diagnose", "--example", "oom_killed", "--provider", "groq", "--format", "json")
    assert code == 0 and "AI review unavailable" in err and json.loads(out)["primary"] == "OOMKilled"


def test_diagnose_fail_on_diagnosis(capsys):
    assert run(capsys, "diagnose", "--example", "oom_killed", "--fail-on-diagnosis", "-f", "json")[0] == 3


def test_diagnose_errors(capsys, tmp_path):
    code, _, err = run(capsys, "diagnose", str(tmp_path / "missing"))
    assert code == 1 and "bundle directory not found" in err
    code, _, err = run(capsys, "diagnose")
    assert code == 1 and "nothing to diagnose" in err


# --------------------------------------------------------------------------- #
# redact
# --------------------------------------------------------------------------- #


def test_redact_stdin(capsys, monkeypatch):
    feed_stdin(monkeypatch, "DB_PASSWORD=hunter2\nok line\n")
    code, out, err = run(capsys, "redact", "--audit")
    assert code == 0 and out == "DB_PASSWORD=[REDACTED:secret_assignment]\nok line\n"
    assert "1 redaction(s)" in err and "hunter2" not in err


def test_redact_files_json(capsys):
    code, out, _ = run(capsys, "redact", str(EXAMPLES / "crashloop_secret_leak" / "logs.txt"), "--json")
    data = json.loads(out)
    assert code == 0 and data["redaction_count"] == 3
    assert data["files"][0]["audit"]["by_rule"]["aws_access_key_id"] == 1
    assert_no_secrets(out)


def test_redact_fail_on_secrets_gate(capsys, monkeypatch, tmp_path):
    feed_stdin(monkeypatch, "nothing to see\n")
    assert run(capsys, "redact", "--fail-on-secrets")[0] == 0
    leaky = tmp_path / "leak.env"
    leaky.write_text("API_TOKEN=abcdef123456\n", encoding="utf-8")
    code, _, _ = run(capsys, "redact", str(leaky), "--fail-on-secrets", "-o", str(tmp_path / "clean.env"))
    assert code == 3 and "abcdef123456" not in (tmp_path / "clean.env").read_text(encoding="utf-8")


def test_redact_no_pii_and_ips(capsys, monkeypatch):
    feed_stdin(monkeypatch, "bob@example.org from 10.1.2.3")
    code, out, _ = run(capsys, "redact", "--no-pii", "--ips")
    assert out == "bob@example.org from [REDACTED:ipv4]"


def test_redact_missing_file(capsys):
    code, _, err = run(capsys, "redact", "no-such-file.log")
    assert code == 1 and "file not found" in err


# --------------------------------------------------------------------------- #
# audit & check
# --------------------------------------------------------------------------- #


def test_audit_examples_directory(capsys):
    code, out, _ = run(capsys, "audit", str(EXAMPLES), "--no-color", "-c", "kubectl delete ns prod")
    assert code == 0 and "risk score" in out and "KG012" in out and "BLOCKED_DESTRUCTIVE" in out
    assert_no_secrets(out)


def test_audit_json_and_fail_on(capsys):
    code, out, _ = run(
        capsys,
        "audit",
        str(EXAMPLES / "crashloop_secret_leak" / "deployment.yaml"),
        "--format",
        "json",
        "--fail-on",
        "critical",
    )
    assert code == 3 and json.loads(out)["risk_level"] in ("HIGH", "CRITICAL")


def test_audit_commands_file_and_markdown(capsys, tmp_path):
    cmds = tmp_path / "cmds.txt"
    cmds.write_text("# proposed by the agent\nkubectl get pods\nkubectl drain node-1\n", encoding="utf-8")
    code, out, _ = run(capsys, "audit", "--commands-file", str(cmds), "--format", "markdown")
    assert code == 0 and "### Command policy" in out and "kubectl drain node-1" in out


def test_audit_fail_on_blocked_command(capsys):
    assert run(capsys, "audit", "-c", "kubectl delete ns prod", "--fail-on", "critical")[0] == 4


def test_audit_requires_input(capsys):
    assert run(capsys, "audit")[0] == 1


@pytest.mark.parametrize(
    "argv,code",
    [
        (["check", "kubectl", "get", "pods"], 0),
        (["check", "kubectl apply -f x.yaml"], 3),
        (["check", "kubectl", "apply", "-f", "x.yaml", "--approved"], 0),
        (["check", "kubectl", "delete", "ns", "prod"], 4),
        (["check", "--role", "viewer", "kubectl", "scale", "deploy/x", "--replicas=2", "--approved"], 3),
        (["check", "rm", "-rf", "/"], 4),
    ],
)
def test_check_exit_codes(capsys, argv, code):
    assert run(capsys, *argv)[0] == code


def test_check_json(capsys):
    code, out, _ = run(capsys, "check", "kubectl", "drain", "node-1", "--json")
    data = json.loads(out)
    assert code == 4 and data["decision"]["verdict"] == "BLOCKED_DESTRUCTIVE" and data["allowed"] is False


def test_check_text_output(capsys):
    code, out, _ = run(capsys, "check", "--no-color", "kubectl get secret db -o yaml")
    assert code == 3 and "APPROVAL_REQUIRED" in out and "reads Secret values" in out


# --------------------------------------------------------------------------- #
# entry points as real processes
# --------------------------------------------------------------------------- #


def test_python_dash_m_src_entrypoint():
    proc = run_py(["-m", "src", "check", "kubectl", "get", "pods"])
    assert proc.returncode == 0 and b"SAFE_READ" in proc.stdout


def test_serve_mcp_subcommand_roundtrip():
    req = b'{"jsonrpc":"2.0","id":7,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}\n'
    proc = run_py(["-m", "src", "serve-mcp", "--roots", str(EXAMPLES)], input=req)
    reply = json.loads(proc.stdout.decode("utf-8").splitlines()[0])
    assert reply["id"] == 7 and reply["result"]["protocolVersion"] == "2024-11-05"


def test_zero_install_launcher_script():
    proc = run_py(["scripts/kubeguard.py", "diagnose", "--example", "image_pull_backoff", "--format", "json"])
    assert proc.returncode == 0 and json.loads(proc.stdout)["primary"] == "ImagePullBackOff"
