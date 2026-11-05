"""Windows / legacy-code-page safety.

Windows consoles and pipes frequently run with cp1252 (or plain ASCII in some
CI collectors).  These tests simulate those environments with
``PYTHONIOENCODING`` and ``PYTHONUTF8`` on every OS and assert that nothing ever
crashes with ``UnicodeEncodeError``, that output degrades to clean ASCII, and
that the MCP stdio transport is byte-exact UTF-8 regardless of the locale.
"""

import io
import json

import pytest

from src import yaml_lite
from src.console import GLYPHS, Style, can_encode, to_ascii, write
from src.correlator import IncidentBundle, correlate
from tests.conftest import EXAMPLES, ROOT, assert_no_secrets, clean_env, run_py

LEGACY = [
    pytest.param({"PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}, "cp1252", id="cp1252"),
    pytest.param({"PYTHONIOENCODING": "ascii", "PYTHONUTF8": "0"}, "ascii", id="ascii"),
]


@pytest.mark.parametrize("env,encoding", LEGACY)
def test_demo_offline_on_legacy_code_pages(env, encoding):
    proc = run_py(["scripts/demo_offline.py"], env=clean_env(**env))
    assert proc.returncode == 0, proc.stderr.decode(encoding, "replace")
    assert b"Traceback" not in proc.stderr and b"UnicodeEncodeError" not in proc.stderr
    out = proc.stdout.decode(encoding)  # must be valid in the target code page
    assert "4/4 incidents diagnosed correctly" in out
    assert "+ SAFE_READ" in out and "x BLOCKED_DESTRUCTIVE" in out  # ASCII glyph fallbacks
    assert "[REDACTED:aws_access_key_id]" in out
    assert_no_secrets(out)


def test_demo_offline_with_pythonutf8():
    proc = run_py(["scripts/demo_offline.py", "-s", "oom_killed"], env=clean_env(PYTHONUTF8="1"))
    out = proc.stdout.decode("utf-8")
    assert proc.returncode == 0
    assert "✔ SAFE_READ" in out and "━━━" in out and "╔" in out


def test_demo_offline_isolated_mode_needs_no_packages():
    # -I ignores PYTHONPATH, user site-packages and the CWD: proves stdlib-only.
    proc = run_py(["-I", "scripts/demo_offline.py", "--no-report"], env=clean_env(PYTHONUTF8="1"))
    assert proc.returncode == 0, proc.stderr.decode()
    assert "4/4 incidents diagnosed correctly" in proc.stdout.decode("utf-8")


def test_demo_runs_from_another_working_directory(tmp_path):
    proc = run_py(
        [str(ROOT / "scripts" / "demo_offline.py"), "-s", "image_pull_backoff", "--no-report"],
        env=clean_env(PYTHONUTF8="1"),
        cwd=tmp_path,
    )
    assert proc.returncode == 0 and "ImagePullBackOff" in proc.stdout.decode("utf-8")


@pytest.mark.parametrize("env,encoding", LEGACY)
def test_cli_diagnose_markdown_on_legacy_code_pages(env, encoding):
    proc = run_py(
        ["-m", "src", "diagnose", "--example", "crashloop_secret_leak", "--format", "markdown"], env=clean_env(**env)
    )
    assert proc.returncode == 0 and b"Traceback" not in proc.stderr
    out = proc.stdout.decode(encoding)
    assert "SRE Incident Report" in out and "(X) BLOCKED_DESTRUCTIVE" in out


@pytest.mark.parametrize("env,encoding", LEGACY)
def test_redact_cli_with_unicode_input_on_legacy_code_page(tmp_path, env, encoding):
    src = tmp_path / "app.log"
    src.write_bytes("Grüße 🚀 DB_PASSWORD=hunter2 ✓\n".encode())
    proc = run_py(["-m", "src", "redact", str(src)], env=clean_env(**env))
    assert proc.returncode == 0 and b"Traceback" not in proc.stderr
    out = proc.stdout.decode(encoding)
    assert "DB_PASSWORD=[REDACTED:secret_assignment]" in out and "hunter2" not in out


def test_redact_cli_output_file_is_always_utf8(tmp_path):
    src = tmp_path / "in.txt"
    src.write_bytes("é ✓ token=abc123def456\n".encode())
    dst = tmp_path / "out.txt"
    proc = run_py(
        ["-m", "src", "redact", str(src), "-o", str(dst)], env=clean_env(PYTHONIOENCODING="ascii", PYTHONUTF8="0")
    )
    assert proc.returncode == 0
    assert dst.read_bytes().decode("utf-8") == "é ✓ token=[REDACTED:secret_assignment]\n"


@pytest.mark.parametrize("env,_encoding", LEGACY)
def test_mcp_stdio_is_byte_exact_utf8_under_any_locale(env, _encoding):
    req = {
        "jsonrpc": "2.0",
        "id": "ü-1",
        "method": "tools/call",
        "params": {"name": "redact_logs", "arguments": {"text": "Ünïcödé 🚀 – API_KEY=abc123def456"}},
    }
    proc = run_py(
        ["-m", "src", "serve-mcp"],
        env=clean_env(**env),
        input=(json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8"),
    )
    assert proc.returncode == 0, proc.stderr
    reply = json.loads(proc.stdout.decode("utf-8"))
    assert reply["id"] == "ü-1"
    assert reply["result"]["content"][0]["text"] == "Ünïcödé 🚀 – API_KEY=[REDACTED:secret_assignment]"
    assert b"\r\n" not in proc.stdout  # newline-delimited JSON, no CRLF translation


def test_check_command_exit_codes_survive_ascii_locale():
    proc = run_py(["-m", "src", "check", "kubectl", "delete", "ns", "prod"], env=clean_env(PYTHONIOENCODING="ascii"))
    assert proc.returncode == 4 and b"x BLOCKED_DESTRUCTIVE" in proc.stdout


# --------------------------------------------------------------------------- #
# in-process console behaviour
# --------------------------------------------------------------------------- #


def _stream(encoding):
    return io.TextIOWrapper(io.BytesIO(), encoding=encoding, errors="strict", newline="")


def test_write_degrades_to_ascii_on_cp1252_stream():
    stream = _stream("cp1252")
    write("✔ ok ━━ ✖ fail → done 🚨\n", stream)
    stream.flush()
    assert stream.buffer.getvalue().decode("cp1252") == "+ ok == x fail -> done [!]\n"


def test_write_never_raises_on_unknown_glyphs():
    stream = _stream("ascii")
    write("emoji 🦄 and ✔\n", stream)
    stream.flush()
    assert stream.buffer.getvalue() == b"emoji ? and +\n"


def test_can_encode_and_style_detection(monkeypatch):
    assert can_encode(_stream("utf-8")) and not can_encode(_stream("cp1252"))
    assert Style.for_stream(_stream("utf-8")).unicode
    assert not Style.for_stream(_stream("cp1252")).unicode
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert Style.for_stream(_stream("utf-8")).color
    monkeypatch.setenv("NO_COLOR", "1")
    assert not Style.for_stream(_stream("utf-8")).color


def test_every_glyph_has_an_ascii_fallback():
    for glyph, repl in GLYPHS.items():
        assert repl.isascii()
        assert to_ascii(glyph).isascii()


def test_crlf_manifests_are_diagnosed_and_patched_with_crlf():
    folder = EXAMPLES / "oom_killed"

    def crlf(name):
        return (folder / name).read_text(encoding="utf-8").replace("\r\n", "\n").replace("\n", "\r\n")

    manifest = crlf("deployment.yaml")
    bundle = IncidentBundle.from_inputs(
        pod=crlf("pod.json"),
        events=(folder / "events.json").read_text(encoding="utf-8"),
        logs=crlf("logs.txt"),
        manifests={"deployment.yaml": manifest},
    )
    p = correlate(bundle).primary
    assert p.failure.value == "OOMKilled"
    patched = p.patches[0].patched
    assert "memory: 1Gi\r\n" in patched and "\n" not in patched.replace("\r\n", "")
    yaml_lite.load(patched)
