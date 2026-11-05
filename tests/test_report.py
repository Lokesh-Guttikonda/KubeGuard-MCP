import json
import re

import pytest

from src.console import Style
from src.correlator import IncidentBundle, correlate
from src.demo import run_demo
from src.llm_reviewer import LLMReviewer
from src.report import plural, render_combined_markdown, render_console, render_json, render_markdown
from src.scenarios import scenario_metadata
from tests.conftest import EXAMPLES, SCENARIOS, assert_no_secrets, cstatus, pod


@pytest.fixture(scope="module")
def results():
    return {name: correlate(EXAMPLES / name) for name in SCENARIOS}


@pytest.mark.parametrize("name", SCENARIOS)
def test_markdown_report_sections(results, name):
    md = render_markdown(
        results[name], scenario=scenario_metadata(name), proposals=scenario_metadata(name)["agent_proposals"]
    )
    for heading in (
        "# 🚨 SRE Incident Report",
        "## Summary",
        "## Root cause analysis",
        "## Remediation",
        "### Proposed patch",
        "```diff",
        "## Zero-trust command plan",
        "## Agent guardrail check",
        "## Timeline (UTC)",
        "## Secret firewall audit",
    ):
        assert heading in md, heading
    assert "🔴 BLOCKED_DESTRUCTIVE" in md
    assert_no_secrets(md)


def test_markdown_is_deterministic(results):
    a = render_markdown(results["oom_killed"])
    b = render_markdown(correlate(EXAMPLES / "oom_killed"))
    assert a == b


def test_markdown_security_impact_only_for_runtime_credential_leaks(results):
    assert "Security impact" in render_markdown(results["crashloop_secret_leak"])
    assert "1 credential written to runtime logs" in render_markdown(results["oom_killed"])


def test_markdown_heading_level():
    md = render_markdown(correlate(EXAMPLES / "oom_killed"), level=3)
    assert md.startswith("### 🚨") and "#### Summary" in md


def test_healthy_report():
    result = correlate(IncidentBundle.from_inputs(pod=pod(statuses=[cstatus(running=True, ready=True)])))
    md = render_markdown(result)
    assert "No known failure signature" in md and "**SEV-4**" in md
    assert "healthy" in render_console(result)


def test_review_section(results):
    review = LLMReviewer().review(results["oom_killed"])
    md = render_markdown(results["oom_killed"], review=review)
    assert "## AI second opinion (`mock`)" in md and "**Verdict:** AGREE" in md


def test_combined_report(results):
    runs = run_demo()
    md = render_combined_markdown(runs)
    assert md.startswith("# 🛡️ KubeGuard SRE Incident Report")
    assert len(re.findall(r"(?m)^\| \d \| `KG-[0-9A-F]{8}` \|", md)) == 4
    assert md.count("## 🚨 SRE Incident Report") == 4
    assert_no_secrets(md)


def test_console_render_plain_has_no_ansi(results):
    text = render_console(results["crashloop_secret_leak"], Style(color=False))
    assert "\x1b[" not in text
    assert "Secret firewall" in text and "[REDACTED:aws_access_key_id]" in text
    assert_no_secrets(text)


def test_console_render_colour_has_ansi(results):
    text = render_console(results["oom_killed"], Style(color=True))
    assert "\x1b[1m" in text and "\x1b[32m+" in text  # bold + green diff additions


def test_json_render(results):
    data = json.loads(render_json(results["image_pull_backoff"], LLMReviewer().review(results["image_pull_backoff"])))
    assert data["primary"] == "ImagePullBackOff"
    assert data["review"]["provider"] == "mock"
    assert data["secret_firewall"]["secrets_blocked"] == 4
    assert_no_secrets(json.dumps(data))


@pytest.mark.parametrize(
    "n,word,many,expected",
    [(1, "patch", "patches", "1 patch"), (2, "patch", "patches", "2 patches"), (0, "secret", None, "0 secrets")],
)
def test_plural(n, word, many, expected):
    assert plural(n, word, many) == expected
