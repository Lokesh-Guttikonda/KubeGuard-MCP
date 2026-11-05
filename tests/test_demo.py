import io
import json
import sys

import pytest

from src import demo
from src.console import Style
from src.policy import classify
from src.scenarios import SCENARIOS, find_examples_dir, list_scenarios, load_scenario, scenario_metadata
from tests.conftest import EXAMPLES, ROOT, assert_no_secrets, clean_env, run_py


@pytest.fixture(scope="module")
def runs():
    return demo.run_demo()


def _capture_main(monkeypatch, argv):
    buf = io.BytesIO()
    stream = io.TextIOWrapper(buf, encoding="utf-8", newline="")
    monkeypatch.setattr(sys, "stdout", stream)
    code = demo.main(argv)
    stream.flush()
    return code, buf.getvalue().decode("utf-8")


def test_scenarios_are_discovered_in_canonical_order():
    assert list_scenarios() == list(SCENARIOS)
    assert find_examples_dir() == EXAMPLES


def test_examples_dir_env_override(monkeypatch, tmp_path):
    (tmp_path / "oom_killed").mkdir()
    monkeypatch.setenv("KUBEGUARD_EXAMPLES", str(tmp_path))
    assert find_examples_dir() == tmp_path


def test_unknown_scenario():
    with pytest.raises(KeyError):
        load_scenario("nope")


@pytest.mark.parametrize("name", SCENARIOS)
def test_scenario_metadata_is_complete(name):
    meta = scenario_metadata(name)
    assert meta["title"] and meta["summary"] and meta["expected_failure"]
    verdicts = {classify(c).verdict.value for c in meta["agent_proposals"]}
    assert verdicts == {"SAFE_READ", "APPROVAL_REQUIRED", "BLOCKED_DESTRUCTIVE"}, (
        "each scenario shows all three verdicts"
    )


@pytest.mark.parametrize("name", SCENARIOS)
def test_each_bundle_has_the_four_core_inputs(name):
    files = {p.name for p in (EXAMPLES / name).iterdir()}
    assert {"pod.json", "events.json", "logs.txt", "scenario.json"} <= files
    assert any(f.endswith(".yaml") for f in files)


def test_run_demo_diagnoses_all_expected(runs):
    assert [r["name"] for r in runs] == list(SCENARIOS)
    for r in runs:
        assert r["result"].primary.failure.value == r["expected"]
        assert r["review"] is not None and r["review"].provider == "mock"


def test_firewall_blocks_db_and_aws_credentials_in_logs(runs):
    crash = next(r for r in runs if r["name"] == "crashloop_secret_leak")["result"]
    logs = crash.redaction["logs.txt"]["by_rule"]
    assert logs["db_connection_string"] == 1 and logs["aws_access_key_id"] == 1 and logs["aws_secret_access_key"] == 1


def test_summary_and_banner(runs):
    style = Style(color=False)
    summary = demo.render_summary(runs, style)
    assert "4/4 incidents diagnosed correctly" in summary
    for name in SCENARIOS:
        assert name in summary
    assert "OFFLINE DEMO" in demo.render_banner(style)


def test_main_output_is_deterministic(monkeypatch):
    a = _capture_main(monkeypatch, ["--no-color"])
    b = _capture_main(monkeypatch, ["--no-color"])
    assert a == b and a[0] == 0
    out = a[1]
    assert out.count("━━━ [") == 4
    assert "━━━ Markdown SRE Incident Report" in out
    assert out.count("```diff") == 5  # oom_killed patches both deployment.yaml and the Dockerfile
    assert_no_secrets(out)


def test_main_json(monkeypatch):
    code, out = _capture_main(monkeypatch, ["--json"])
    data = json.loads(out)
    assert code == 0 and data["all_diagnosed_correctly"] and len(data["incidents"]) == 4
    assert_no_secrets(out)


def test_main_reports_failure_when_expectation_breaks(monkeypatch):
    original = demo.scenario_metadata
    monkeypatch.setattr(demo, "scenario_metadata", lambda n: dict(original(n), expected_failure="Unschedulable"))
    code, out = _capture_main(monkeypatch, ["-s", "oom_killed", "--no-report", "--no-color"])
    assert code == 1 and "0/1 incidents diagnosed correctly" in out


def test_demo_script_runs_with_pythonutf8():
    proc = run_py(
        ["scripts/demo_offline.py", "--no-report", "-s", "service_port_mismatch"], env=clean_env(PYTHONUTF8="1")
    )
    assert proc.returncode == 0 and "ServicePortMismatch" in proc.stdout.decode("utf-8")


def test_readme_embeds_current_real_demo_output():
    proc = run_py(["scripts/update_readme.py", "--check"])
    assert proc.returncode == 0, proc.stderr.decode()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "$ python scripts/demo_offline.py --no-report" in readme
    assert "4/4 incidents diagnosed correctly" in readme
    assert_no_secrets(readme)
