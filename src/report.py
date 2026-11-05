"""Renderers: Markdown SRE incident reports, console walkthroughs and JSON.

Everything rendered here comes from a :class:`~src.correlator.CorrelationResult`
whose strings already passed the secret firewall; each renderer still runs a
final redaction pass over its output (defence in depth).  Output is fully
deterministic - timestamps come from the incident data, never the wall clock -
so reports can be diffed, snapshot-tested and embedded in documentation.
"""

from __future__ import annotations

import json
import textwrap
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .console import Style
from .correlator import CorrelationResult, redacted_diff
from .policy import PolicyDecision, PolicyEngine
from .redactor import default_redactor

__all__ = ["VERDICT_BADGE", "render_combined_markdown", "render_console", "render_json", "render_markdown"]

VERDICT_BADGE = {
    "SAFE_READ": "\U0001f7e2 SAFE_READ",
    "APPROVAL_REQUIRED": "\U0001f7e1 APPROVAL_REQUIRED",
    "BLOCKED_DESTRUCTIVE": "\U0001f534 BLOCKED_DESTRUCTIVE",
}


def plural(n: int, word: str, many: Optional[str] = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def _pct(x: float) -> str:
    return f"{round(x * 100)}%"


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _code(text: str) -> str:
    text = str(text)
    fence = "``" if "`" in text else "`"
    pad = " " if fence == "``" else ""
    return f"{fence}{pad}{text}{pad}{fence}".replace("|", "\\|")


def _rules_summary(by_rule: Dict[str, int], sep: str = ", ") -> str:
    return sep.join(f"{k} \u00d7{v}" for k, v in by_rule.items())


def _clean(text: str) -> str:
    return default_redactor().redact(text).text


def _evaluate(proposals: Sequence[str], policy: Optional[PolicyEngine] = None) -> List[PolicyDecision]:
    engine = policy or PolicyEngine()
    return [engine.classify(p) for p in proposals]


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #


def render_markdown(
    result: CorrelationResult,
    review: Any = None,
    scenario: Optional[Dict[str, Any]] = None,
    level: int = 1,
    proposals: Optional[Sequence[str]] = None,
) -> str:
    """A complete Markdown SRE incident report for one incident."""
    h = "#" * level
    hh = "#" * (level + 1)
    scenario = scenario or {}
    p = result.primary
    out: List[str] = []
    title = scenario.get("title") or (p.title if p else "No failure detected")
    out.append(f"{h} \U0001f6a8 SRE Incident Report \u2014 {result.incident_id}")
    out.append("")
    out.append(f"> **{_cell(title)}**")
    if scenario.get("summary"):
        out.append(">")
        out.append(f"> {_cell(scenario['summary'])}")
    out.append("")
    first_seen = next((t.time for t in result.timeline if t.time), "")
    rows = [
        ("Incident ID", _code(result.incident_id)),
        ("Severity", f"**{result.severity}**"),
        (
            "Status",
            "Root cause identified \u2014 fix proposed" if p and p.patches else ("Diagnosed" if p else "Healthy"),
        ),
        ("Primary failure", f"{_code(p.failure.value)} \u00b7 confidence **{_pct(p.confidence)}**" if p else "none"),
        (
            "Workload",
            f"{_code(result.workload)} in namespace {_code(result.namespace or 'default')}"
            if result.workload
            else "n/a",
        ),
        ("Pod", _code(result.pod) if result.pod else "n/a"),
        ("First signal", first_seen or "n/a"),
        (
            "Secret firewall",
            f"**{result.secrets_blocked}** {'value' if result.secrets_blocked == 1 else 'values'} redacted"
            + (f" ({_cell(_rules_summary(result.redaction_by_rule))})" if result.secrets_blocked else ""),
        ),
        ("Engine", f"kubeguard-mcp v{__version__} \u00b7 deterministic \u00b7 offline"),
    ]
    out.append("| Field | Value |")
    out.append("|---|---|")
    for k, v in rows:
        out.append(f"| **{k}** | {v} |")
    out.append("")

    if p is None:
        out.append(f"{hh} Summary")
        out.append("")
        out.append("No known failure signature was found in the provided pod status, events, logs and manifests.")
        out.append("")
    else:
        out.append(f"{hh} Summary")
        out.append("")
        out.append(_cell(p.root_cause).replace("\\|", "|"))
        out.append("")
        out.append(f"{hh} Root cause analysis")
        out.append("")
        out.append(f"**{p.title}** \u2014 `{p.failure.value}` / `{p.sub_cause}` \u2014 confidence {_pct(p.confidence)}")
        out.append("")
        out.append("| Signal source | Evidence |")
        out.append("|---|---|")
        for e in p.evidence:
            out.append(f"| `{e.source}` | {_cell(e.detail)} |")
        out.append("")
        out.append(f"{hh} Remediation")
        out.append("")
        for i, step in enumerate(p.remediation, 1):
            out.append(f"{i}. {step}")
        out.append("")
        for patch in p.patches:
            out.append(f"{hh}# Proposed patch \u2014 `{patch.file}`")
            out.append("")
            out.append(f"_{patch.description}_")
            out.append("")
            out.append("```diff")
            out.append(redacted_diff(patch).rstrip("\n"))
            out.append("```")
            out.append("")
        secondary = result.diagnoses[1:]
        if secondary:
            out.append(f"{hh} Secondary findings")
            out.append("")
            for d in secondary:
                note = f" \u2014 symptom of `{d.symptom_of}`" if d.symptom_of else ""
                out.append(f"- `{d.failure.value}` ({_pct(d.confidence)}): {_cell(d.title)}{note}")
            out.append("")
        out.append(f"{hh} Zero-trust command plan")
        out.append("")
        out.append("Every command was classified by the policy engine; KubeGuard never executes anything itself.")
        out.append("")
        out.append("| # | Command | Verdict | Purpose |")
        out.append("|---|---|---|---|")
        for i, c in enumerate(p.commands, 1):
            out.append(f"| {i} | {_code(c.command)} | {VERDICT_BADGE.get(c.verdict, c.verdict)} | {_cell(c.purpose)} |")
        out.append("")

    if proposals:
        out.append(f"{hh} Agent guardrail check")
        out.append("")
        out.append("Actions an autonomous agent proposed for this incident, as judged by the zero-trust policy:")
        out.append("")
        out.append("| Proposed action | Verdict | Risk | Reason |")
        out.append("|---|---|---|---|")
        for d in _evaluate(proposals):
            out.append(
                f"| {_code(d.command)} | {VERDICT_BADGE[d.verdict.value]} | {d.risk_score} | {_cell(d.reason)} |"
            )
        out.append("")

    out.append(f"{hh} Timeline (UTC)")
    out.append("")
    if result.timeline:
        out.append("| Time | Source | Type | Reason | Message |")
        out.append("|---|---|---|---|---|")
        for t in result.timeline[:15]:
            out.append(f"| {t.time or '-'} | {t.source} | {t.kind} | {t.reason} | {_cell(t.message)} |")
        if len(result.timeline) > 15:
            out.append(f"| \u2026 | | | | {len(result.timeline) - 15} more |")
    else:
        out.append("_No events were provided._")
    out.append("")

    out.append(f"{hh} Secret firewall audit")
    out.append("")
    if result.redaction:
        out.append("| File | Redactions | Max severity | Rules |")
        out.append("|---|---|---|---|")
        for fname, audit in result.redaction.items():
            out.append(
                f"| `{fname}` | {audit['redaction_count']} | {audit['max_severity']} | {_cell(_rules_summary(audit['by_rule']))} |"
            )
        out.append("")
        leaks = result.runtime_leaks
        if leaks:
            out.append(
                f"> \u26a0\ufe0f **Security impact:** {plural(sum(leaks.values()), 'credential')} written to runtime logs "
                f"({_cell(_rules_summary(leaks))}). Anything that reached a log pipeline must be treated as "
                "compromised: rotate it, then purge the log streams."
            )
            out.append("")
        out.append("Values were masked *before* analysis and before any output, report or LLM call.")
    else:
        out.append("No secrets or PII were found in the bundle.")
    out.append("")

    if review is not None:
        out.append(f"{hh} AI second opinion (`{review.provider}`)")
        out.append("")
        out.append(f"**Verdict:** {review.verdict} \u2014 {_cell(review.summary)}")
        out.append("")
        for r in review.risks:
            out.append(f"- \u26a0\ufe0f {_cell(r)}")
        for c in review.next_checks:
            out.append(f"- \U0001f50d {_cell(c)}")
        out.append("")
        out.append(f"_The reviewer received only redacted data ({review.payload_chars} chars)._")
        out.append("")

    out.append("---")
    out.append(
        f"_Generated by kubeguard-mcp v{__version__} \u00b7 deterministic correlation \u00b7 zero network calls \u00b7 "
        "every line passed the secret firewall._"
    )
    return _clean("\n".join(out) + "\n")


def render_combined_markdown(runs: Sequence[Dict[str, Any]], title: str = "KubeGuard SRE Incident Report") -> str:
    """One report covering several incidents (used by the offline demo)."""
    total_blocked = sum(r["result"].secrets_blocked for r in runs)
    out = [
        f"# \U0001f6e1\ufe0f {title}",
        "",
        f"_{plural(len(runs), 'incident')} \u00b7 {plural(total_blocked, 'secret')} blocked \u00b7 0 network calls \u00b7 "
        "0 API keys \u00b7 "
        f"kubeguard-mcp v{__version__}_",
        "",
        "| # | Incident | Scenario | Root cause | Confidence | Severity | Secrets blocked | Fix |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for i, run in enumerate(runs, 1):
        res: CorrelationResult = run["result"]
        p = res.primary
        fix = ", ".join(f"`{pt.file}`" for pt in p.patches) if p and p.patches else "manual"
        out.append(
            f"| {i} | `{res.incident_id}` | {run['name']} | `{p.failure.value if p else 'healthy'}` "
            f"| {_pct(p.confidence) if p else '-'} | {res.severity} | {res.secrets_blocked} | {fix} |"
        )
    out.append("")
    for run in runs:
        out.append(
            render_markdown(
                run["result"], run.get("review"), run.get("scenario"), level=2, proposals=run.get("proposals")
            )
        )
    return _clean("\n".join(out))


# --------------------------------------------------------------------------- #
# Console
# --------------------------------------------------------------------------- #

_WIDTH = 100


def _wrap(text: str, indent: int, width: int = _WIDTH, hang: int = 0) -> List[str]:
    pad = " " * indent
    return textwrap.wrap(
        text, width=width, initial_indent=pad, subsequent_indent=pad + " " * hang, break_on_hyphens=False
    ) or [pad]


def _window(line: str, width: int = 88) -> str:
    """Clip a long log line around its first redaction token."""
    line = " ".join(line.split())
    if len(line) <= width:
        return line
    idx = line.find("[REDACTED")
    if idx < 0:
        return line[: width - 1] + "\u2026"
    start = max(0, idx - width // 2)
    end = min(len(line), start + width)
    start = max(0, end - width)
    return ("\u2026" if start else "") + line[start:end] + ("\u2026" if end < len(line) else "")


def render_console(
    result: CorrelationResult,
    style: Optional[Style] = None,
    review: Any = None,
    scenario: Optional[Dict[str, Any]] = None,
    proposals: Optional[Sequence[str]] = None,
    header: Optional[str] = None,
    max_samples: int = 4,
) -> str:
    """Human-friendly walkthrough of one diagnosis (used by ``diagnose``/``demo``)."""
    s = style or Style(color=False, unicode=True)
    scenario = scenario or {}
    out: List[str] = []
    hr = "\u2501"
    label = header or result.bundle
    out.append(s.bold(s.cyan(f"{hr * 3} {label} " + hr * max(3, _WIDTH - len(label) - 5))))
    if scenario.get("title"):
        out.append(s.bold(scenario["title"]))
    meta = [f"incident {result.incident_id}"]
    if result.pod:
        meta.append(f"pod {result.namespace + '/' if result.namespace else ''}{result.pod}")
    if result.workload:
        meta.append(result.workload)
    out.append(s.dim(" \u00b7 ".join(meta)))
    out.append("")

    step = 0

    def section(name: str, summary: str) -> None:
        nonlocal step
        step += 1
        out.append(f"{s.bold(s.magenta(chr(0x25B6)))} {s.bold(f'{step}. {name:<18}')} {summary}")

    # 1. secret firewall
    if result.secrets_blocked:
        section(
            "Secret firewall",
            s.red(s.bold(f"{plural(result.secrets_blocked, 'secret')} blocked"))
            + f" before analysis ({_rules_summary(result.redaction_by_rule)})",
        )
        for fname, line, text in result.redaction_samples[:max_samples]:
            loc = f"{fname}:{line}"
            out.append(f"     {s.dim(f'{loc:<18}')} {_window(text)}")
        if len(result.redaction_samples) > max_samples:
            more = len(result.redaction_samples) - max_samples
            out.append(s.dim(f"     \u2026 and {plural(more, 'more redacted line')}"))
    else:
        section("Secret firewall", s.green("clean") + " - no secrets or PII found")

    # 2. diagnosis
    p = result.primary
    if p is None:
        section("Diagnosis", s.green("healthy") + " - no known failure signature")
    else:
        section(
            "Diagnosis",
            s.bold(s.red(p.failure.value))
            + f" \u00b7 confidence {s.bold(_pct(p.confidence))} \u00b7 {result.severity}",
        )
        out.extend(_wrap("root cause: " + p.root_cause, 5))
        out.append("     evidence:")
        for e in p.evidence:
            first, *rest = _wrap(f"[{e.source}] {e.detail}", 9, _WIDTH)
            out.append("       \u2022 " + first.strip())
            out.extend(rest)
        for d in result.diagnoses[1:]:
            note = f" - symptom of {d.symptom_of}" if d.symptom_of else ""
            out.append(s.dim(f"     also: {d.failure.value} ({_pct(d.confidence)}){note}"))

        # 3. fix
        if p.patches:
            files = ", ".join(pt.file for pt in p.patches)
            section("Exact fix", f"{plural(len(p.patches), 'patch', 'patches')} \u2192 {files}")
            for pt in p.patches:
                for line in redacted_diff(pt).rstrip("\n").split("\n"):
                    out.append("     " + s.diff_line(line))
                out.append("")
            if out[-1] == "":
                out.pop()
        else:
            section("Exact fix", "no safe automatic patch - follow the remediation steps")
        for i, r in enumerate(p.remediation, 1):
            out.extend(_wrap(f"{i}. {r}", 5, hang=3))

    # 4. policy
    if proposals:
        section("Zero-trust policy", "agent-proposed actions")
        for d in _evaluate(proposals):
            out.append(f"     {s.verdict(d.verdict.value)} {d.command}")
            if d.verdict.value != "SAFE_READ":
                out.append(s.dim(f"     {'':<22}\u2514 {d.reason}"))
    elif p is not None and p.commands:
        section("Zero-trust policy", "follow-up command plan")
        for c in p.commands:
            out.append(f"     {s.verdict(c.verdict)} {c.command}")

    # 5. review
    if review is not None:
        section(f"AI review ({review.provider})", s.bold(review.verdict) + " - redacted payload only")
        out.extend(_wrap(review.summary, 5))
        for r in review.risks[:2]:
            out.extend(_wrap(f"risk: {r}", 5, hang=6))
    out.append("")
    return _clean("\n".join(out) + "\n")


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def render_json(result: CorrelationResult, review: Any = None, indent: int = 2) -> str:
    data = result.to_dict()
    if review is not None:
        data["review"] = review.to_dict()
    clean, _ = default_redactor().redact_obj(data)
    return json.dumps(clean, indent=indent, ensure_ascii=False) + "\n"
