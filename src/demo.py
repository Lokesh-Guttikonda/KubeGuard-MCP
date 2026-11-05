"""Offline demo: four realistic incidents, zero packages, zero API keys.

For every bundled scenario the demo shows the full KubeGuard pipeline:

1. the secret firewall masking leaked credentials before anything else runs,
2. the deterministic root-cause diagnosis with weighted evidence,
3. the exact unified-diff fix for the user's YAML / Dockerfile,
4. the zero-trust verdicts for the actions an over-eager agent proposed,
5. an (offline, mock) AI second opinion that only saw redacted data,

and finally prints one Markdown SRE incident report covering all incidents.
Run it with ``python scripts/demo_offline.py`` or ``kubeguard demo``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .console import Style, ensure_safe_stdio, write
from .correlator import correlate
from .llm_reviewer import LLMReviewer, ReviewerError
from .report import render_combined_markdown, render_console
from .scenarios import list_scenarios, load_scenario, scenario_metadata

__all__ = ["main", "render_banner", "render_summary", "run_demo", "run_scenario"]


def run_scenario(name: str, provider: str = "mock") -> Dict[str, Any]:
    bundle = load_scenario(name)
    meta = scenario_metadata(name)
    result = correlate(bundle)
    try:
        review = LLMReviewer(provider=provider).review(result)
    except ReviewerError as exc:
        review = None
        meta = dict(meta, review_error=str(exc))
    return {
        "name": name,
        "scenario": meta,
        "bundle": bundle,
        "result": result,
        "review": review,
        "proposals": list(meta.get("agent_proposals") or []),
        "expected": meta.get("expected_failure"),
    }


def run_demo(names: Optional[Sequence[str]] = None, provider: str = "mock") -> List[Dict[str, Any]]:
    return [run_scenario(n, provider) for n in (names or list_scenarios())]


def render_banner(style: Style, provider: str = "mock") -> str:
    inner = 84
    title = f"KubeGuard-MCP v{__version__} · Zero-Trust Kubernetes & Container Triage · OFFLINE DEMO"
    lines = [
        "╔" + "═" * inner + "╗",
        "║" + title.center(inner) + "║",
        "╚" + "═" * inner + "╝",
    ]
    info = f"  engine: deterministic correlator · network calls: 0 · API keys: 0 · LLM reviewer: {provider}"
    return "\n".join(style.bold(style.cyan(line)) for line in lines) + "\n" + style.dim(info) + "\n\n"


def render_summary(runs: Sequence[Dict[str, Any]], style: Style) -> str:
    hr = "━"
    out = [style.bold(style.cyan(f"{hr * 3} Summary " + hr * 89)), ""]
    header = f"  {'#':<2} {'scenario':<23} {'root cause':<28} {'conf':>4}  {'sev':<5}  {'secrets':>7}  fix"
    out.append(style.bold(header))
    ok = 0
    blocked = 0
    for i, run in enumerate(runs, 1):
        res = run["result"]
        p = res.primary
        cause = p.failure.value if p else "healthy"
        good = run.get("expected") is None or run.get("expected") == (p.failure.value if p else None)
        ok += 1 if good else 0
        blocked += res.secrets_blocked
        mark = style.green("✔") if good else style.red("✖")
        fix = ", ".join(pt.file for pt in p.patches) if p and p.patches else "manual"
        conf = f"{round(p.confidence * 100)}%" if p else "-"
        out.append(
            f"  {i:<2} {run['name']:<23} {mark} {cause:<26} {conf:>4}  {res.severity:<5}  {res.secrets_blocked:>7}  {fix}"
        )
    out.append("")
    verdict = style.green if ok == len(runs) else style.red
    out.append(
        "  "
        + verdict(style.bold(f"{ok}/{len(runs)} incidents diagnosed correctly"))
        + f" · {blocked} secrets blocked · 0 network calls · 0 API keys · no LLM required"
    )
    out.append("")
    return "\n".join(out) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="demo_offline",
        description="Run the four bundled Kubernetes incidents fully offline (no packages, no API keys).",
    )
    parser.add_argument(
        "--scenario",
        "-s",
        action="append",
        choices=list_scenarios() or None,
        help="run only this scenario (repeatable; default: all)",
    )
    parser.add_argument("--report", metavar="FILE", help="also write the Markdown SRE incident report to FILE")
    parser.add_argument("--no-report", action="store_true", help="do not print the Markdown report to stdout")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON instead of the walkthrough")
    parser.add_argument("--provider", default="mock", help="LLM reviewer provider (default: mock, fully offline)")
    color = parser.add_mutually_exclusive_group()
    color.add_argument("--color", dest="color", action="store_true", default=None, help="force ANSI colours")
    color.add_argument("--no-color", dest="color", action="store_false", help="disable ANSI colours")
    args = parser.parse_args(argv)

    ensure_safe_stdio()
    if not list_scenarios():
        write("error: bundled examples not found (set KUBEGUARD_EXAMPLES)\n", sys.stderr)
        return 1
    style = Style.for_stream(sys.stdout, color=args.color)
    runs = run_demo(args.scenario, provider=args.provider)
    all_ok = all(
        r.get("expected") in (None, r["result"].primary.failure.value if r["result"].primary else None) for r in runs
    )

    if args.json:
        payload = {
            "version": __version__,
            "all_diagnosed_correctly": all_ok,
            "incidents": [
                dict(r["result"].to_dict(), scenario=r["name"], review=r["review"].to_dict() if r["review"] else None)
                for r in runs
            ],
        }
        write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", sys.stdout, style)
        return 0 if all_ok else 1

    write(render_banner(style, args.provider), sys.stdout, style)
    total = len(runs)
    for i, run in enumerate(runs, 1):
        text = render_console(
            run["result"],
            style,
            review=run["review"],
            scenario=run["scenario"],
            proposals=run["proposals"],
            header=f"[{i}/{total}] {run['name']}",
        )
        write(text, sys.stdout, style)
    write(render_summary(runs, style), sys.stdout, style)

    report = render_combined_markdown(runs)
    if args.report:
        path = Path(args.report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(report.encode("utf-8"))
        write(style.dim(f"  Markdown SRE incident report written to {path}\n\n"), sys.stdout, style)
    if not args.no_report:
        hr = "━"
        write(style.bold(style.cyan(f"{hr * 3} Markdown SRE Incident Report " + hr * 68)) + "\n\n", sys.stdout, style)
        write(report, sys.stdout, style)
    return 0 if all_ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
