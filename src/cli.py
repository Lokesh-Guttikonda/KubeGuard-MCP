"""``kubeguard`` command line interface.

Commands::

    kubeguard demo        run the four offline incident scenarios
    kubeguard diagnose    diagnose an incident bundle (directory or individual files)
    kubeguard redact      secret & PII firewall for files or stdin
    kubeguard audit       lint manifests, analyse RBAC and classify commands
    kubeguard check       zero-trust verdict for one command (exit 0/3/4)
    kubeguard serve-mcp   start the MCP server on stdio

Exit codes: 0 success, 1 error, 2 usage error, 3 findings/approval required
(``--fail-on`` / ``--fail-on-secrets`` / ``check``), 4 blocked command.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from . import __version__
from .console import Style, ensure_safe_stdio, write

__all__ = ["build_parser", "main"]

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 3
EXIT_BLOCKED = 4
_SEVERITIES = ("low", "medium", "high", "critical")
_MANIFEST_EXT = (".yaml", ".yml", ".json")
_SKIP_FILES = {"scenario.json", "events.json", "nodes.json", "endpoints.json", "docker_inspect.json"}


class CliError(Exception):
    pass


def _out(text: str, style: Optional[Style] = None) -> None:
    write(text, sys.stdout, style)


def _err(text: str) -> None:
    write(text, sys.stderr)


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.buffer.read().decode("utf-8", errors="replace")
    p = Path(path)
    if not p.is_file():
        raise CliError(f"file not found: {path}")
    return p.read_bytes().decode("utf-8", errors="replace")


def _write_file(path: str, text: str) -> None:
    p = Path(path)
    if p.parent and not p.parent.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(text.encode("utf-8"))


def _style(args: argparse.Namespace) -> Style:
    return Style.for_stream(sys.stdout, color=getattr(args, "color", None))


def _add_color(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--color", dest="color", action="store_true", default=None, help="force ANSI colours")
    g.add_argument("--no-color", dest="color", action="store_false", help="disable ANSI colours")


# --------------------------------------------------------------------------- #
# demo
# --------------------------------------------------------------------------- #


def cmd_demo(args: argparse.Namespace) -> int:
    from .demo import main as demo_main

    argv: List[str] = []
    for s in args.scenario or []:
        argv += ["--scenario", s]
    if args.report:
        argv += ["--report", args.report]
    if args.no_report:
        argv.append("--no-report")
    if args.json:
        argv.append("--json")
    if args.provider:
        argv += ["--provider", args.provider]
    if args.color is True:
        argv.append("--color")
    elif args.color is False:
        argv.append("--no-color")
    return demo_main(argv)


# --------------------------------------------------------------------------- #
# diagnose
# --------------------------------------------------------------------------- #


def _load_bundle(args: argparse.Namespace):
    from .correlator import IncidentBundle
    from .scenarios import load_scenario, scenario_metadata

    if args.example:
        return load_scenario(args.example), scenario_metadata(args.example)
    if args.bundle:
        path = Path(args.bundle)
        if not path.is_dir():
            raise CliError(f"bundle directory not found: {args.bundle}")
        bundle = IncidentBundle.from_directory(path)
        meta_file = path / "scenario.json"
        meta = json.loads(meta_file.read_text(encoding="utf-8")) if meta_file.is_file() else {}
        return bundle, meta
    inputs: Dict[str, object] = {}
    for attr, key in (
        ("pod", "pod"),
        ("events", "events"),
        ("logs", "logs"),
        ("dockerfile", "dockerfile"),
        ("secrets", "secrets"),
        ("nodes", "nodes"),
        ("endpoints", "endpoints"),
        ("docker_inspect", "docker_inspect"),
    ):
        value = getattr(args, attr)
        if value:
            inputs[key] = _read(value)
    if args.manifest:
        inputs["manifests"] = {Path(m).name: _read(m) for m in args.manifest}
    if not inputs:
        raise CliError("nothing to diagnose: pass a bundle directory, --example, or --pod/--events/--logs/--manifest")
    return IncidentBundle.from_inputs(**inputs), {}  # type: ignore[arg-type]


def cmd_diagnose(args: argparse.Namespace) -> int:
    from .correlator import correlate, redacted_diff
    from .llm_reviewer import LLMReviewer, ReviewerError
    from .report import render_console, render_json, render_markdown

    bundle, meta = _load_bundle(args)
    result = correlate(bundle)
    review = None
    if args.review or args.provider:
        try:
            review = LLMReviewer(provider=args.provider).review(result)
        except ReviewerError as exc:
            _err(f"warning: AI review unavailable: {exc}\n")
    style = _style(args)
    if args.format == "json":
        text = render_json(result, review)
        style = Style(color=False, unicode=style.unicode)
    elif args.format == "markdown":
        text = render_markdown(result, review, meta, proposals=meta.get("agent_proposals"))
        style = Style(color=False, unicode=style.unicode)
    else:
        text = render_console(result, style, review, meta, proposals=meta.get("agent_proposals"))
    if args.output:
        _write_file(args.output, text)
        _err(f"report written to {args.output}\n")
    else:
        _out(text, style)

    patches = list(result.primary.patches) if result.primary else []
    if args.patch_out:
        if not patches:
            _err("no patch was generated for this incident\n")
        else:
            combined = "".join(redacted_diff(p) for p in patches)
            _write_file(args.patch_out, combined)
            raw = "".join(p.diff for p in patches)
            note = (
                " (hunks contain redacted values; use --write-fixed for directly usable files)"
                if raw != combined
                else ""
            )
            _err(f"patch written to {args.patch_out}{note}\n")
    if args.write_fixed:
        if not patches:
            _err("no patch was generated for this incident\n")
        else:
            out_dir = Path(args.write_fixed)
            out_dir.mkdir(parents=True, exist_ok=True)
            for p in patches:
                target = out_dir / Path(p.file).name
                target.write_bytes(p.patched.encode("utf-8"))
                _err(f"fixed file written to {target}\n")
    if args.fail_on_diagnosis and not result.healthy:
        return EXIT_FINDINGS
    return EXIT_OK


# --------------------------------------------------------------------------- #
# redact
# --------------------------------------------------------------------------- #


def cmd_redact(args: argparse.Namespace) -> int:
    from .redactor import Redactor

    engine = Redactor(include_pii=not args.no_pii, redact_ips=args.ips)
    sources = args.files or ["-"]
    total = 0
    outputs: List[str] = []
    audits = []
    for src in sources:
        res = engine.redact(_read(src), source="stdin" if src == "-" else src)
        total += res.count
        outputs.append(res.text)
        audits.append(res.audit())
    if args.json:
        payload = {"redaction_count": total, "files": [{"redacted": o, "audit": a} for o, a in zip(outputs, audits)]}
        text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    else:
        text = "".join(outputs)
    if args.output:
        _write_file(args.output, text)
    else:
        _out(text)
    if args.audit and not args.json:
        for a in audits:
            rules = ", ".join(f"{k} x{v}" for k, v in a["by_rule"].items()) or "none"
            _err(f"[kubeguard] {a['source']}: {a['redaction_count']} redaction(s) ({rules}); lines {a['lines']}\n")
    if args.fail_on_secrets and total:
        return EXIT_FINDINGS
    return EXIT_OK


# --------------------------------------------------------------------------- #
# audit
# --------------------------------------------------------------------------- #


def _collect_manifests(paths: Sequence[str]) -> List[Tuple[str, str]]:
    files: List[Tuple[str, str]] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and f.suffix.lower() in _MANIFEST_EXT and f.name not in _SKIP_FILES:
                    files.append((str(f), f.read_bytes().decode("utf-8", errors="replace")))
        elif p.is_file() or raw == "-":
            files.append((raw, _read(raw)))
        else:
            raise CliError(f"path not found: {raw}")
    return files


def cmd_audit(args: argparse.Namespace) -> int:
    from .auditor import audit_cluster

    commands = list(args.command or [])
    if args.commands_file:
        commands += [
            ln.strip()
            for ln in _read(args.commands_file).splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")
        ]
    files = _collect_manifests(args.paths)
    if not files and not commands:
        raise CliError("nothing to audit: pass manifest files/directories and/or --command")
    audit = audit_cluster(files, commands, role=args.role)
    if args.format == "json":
        _out(json.dumps(audit.to_dict(), indent=2, ensure_ascii=False) + "\n")
    elif args.format == "markdown":
        _out(audit.to_markdown() + "\n")
    else:
        style = _style(args)
        _out(_render_audit_text(audit, style), style)
    if args.fail_on:
        threshold = _SEVERITIES.index(args.fail_on)
        if any(_SEVERITIES.index(f.severity) >= threshold for f in audit.findings if f.severity in _SEVERITIES):
            return EXIT_FINDINGS
        if any(c.blocked for c in audit.commands):
            return EXIT_BLOCKED
    return EXIT_OK


def _render_audit_text(audit, style: Style) -> str:
    colour = {"CRITICAL": style.red, "HIGH": style.red, "MEDIUM": style.yellow, "LOW": style.green}[audit.risk_level]
    lines = [
        style.bold("KubeGuard cluster risk audit"),
        f"  risk score {colour(style.bold(f'{audit.risk_score}/100 {audit.risk_level}'))} · "
        f"{len(audit.manifests)} file(s) · {len(audit.findings)} finding(s) · {len(audit.commands)} command(s)",
        "",
    ]
    for r in audit.manifests:
        status = style.green("PASS") if r.passed else style.red("FAIL")
        lines.append(f"  {status} {r.file}  score {r.score}/100 (grade {r.grade})")
        for e in r.errors:
            lines.append(f"      {style.red('parse error')}: {e}")
        for f in r.findings:
            sev = {"critical": style.red, "high": style.red, "medium": style.yellow}.get(f.severity, style.dim)(
                f"{f.severity:<8}"
            )
            loc = f":{f.line}" if f.line else ""
            who = f.resource + (f" [{f.container}]" if f.container else "")
            lines.append(f"      {sev} {f.rule_id:<12} {who}{loc} - {f.message}")
    if audit.commands:
        lines += ["", style.bold("  Command policy")]
        for c in audit.commands:
            lines.append(f"    {style.verdict(c.verdict.value)} {c.command}")
            if c.verdict.value != "SAFE_READ":
                lines.append(style.dim(f"    {'':<22}└ {c.reason}"))
    if audit.secrets_found:
        lines += [
            "",
            "  " + style.bold("Secret exposure: ") + ", ".join(f"{k} x{v}" for k, v in audit.secrets_found.items()),
        ]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# check
# --------------------------------------------------------------------------- #


def cmd_check(args: argparse.Namespace) -> int:
    from .policy import PolicyEngine

    command = " ".join(args.cmd) if len(args.cmd) > 1 else (args.cmd[0] if args.cmd else "")
    auth = PolicyEngine(role=args.role).authorize(command, approved=args.approved)
    d = auth.decision
    if args.json:
        _out(json.dumps(auth.to_dict(), indent=2, ensure_ascii=False) + "\n")
    else:
        style = _style(args)
        _out(f"{style.verdict(d.verdict.value)} risk {d.risk_score}/100  {d.command}\n", style)
        for reason in d.reasons:
            _out(f"  └ {reason}\n", style)
        allowed = style.green("ALLOWED") if auth.allowed else style.red("DENIED")
        _out(f"  role={auth.role}: {allowed} - {auth.reason}\n", style)
    if auth.allowed:
        return EXIT_OK
    return EXIT_BLOCKED if d.blocked else EXIT_FINDINGS


# --------------------------------------------------------------------------- #
# serve-mcp
# --------------------------------------------------------------------------- #


def cmd_serve(args: argparse.Namespace) -> int:
    from .mcp_server import MCPServer

    roots = args.roots or None
    if roots is None and os.environ.get("KUBEGUARD_MCP_ROOTS") is None:
        roots = [os.getcwd()]
    return MCPServer(roots=roots).serve()


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    from .scenarios import list_scenarios

    examples = list_scenarios() or None
    parser = argparse.ArgumentParser(
        prog="kubeguard",
        description="Zero-trust Kubernetes & container triage: secret firewall, policy engine, deterministic "
        "incident correlator and MCP server. Offline, no API keys.",
        epilog="Run 'kubeguard demo' to see all features on four realistic incidents.",
    )
    parser.add_argument("--version", action="version", version=f"kubeguard-mcp {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p = sub.add_parser("demo", help="run the offline incident scenarios", description="Run the bundled offline demo.")
    p.add_argument("--scenario", "-s", action="append", choices=examples, help="only this scenario (repeatable)")
    p.add_argument("--report", metavar="FILE", help="write the Markdown SRE incident report to FILE")
    p.add_argument("--no-report", action="store_true", help="do not print the Markdown report")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--provider", default=None, help="LLM reviewer provider (default: mock)")
    _add_color(p)
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser(
        "diagnose", help="diagnose an incident bundle", description="Correlate pod/events/logs/manifests."
    )
    p.add_argument("bundle", nargs="?", help="directory with pod.json, events.json, logs.txt, *.yaml, Dockerfile")
    p.add_argument("--example", choices=examples, help="diagnose a bundled example")
    p.add_argument("--pod", metavar="FILE", help="kubectl get pod -o json output")
    p.add_argument("--events", metavar="FILE", help="kubectl get events -o json (or table) output")
    p.add_argument("--logs", metavar="FILE", help="container logs ('-' for stdin)")
    p.add_argument("--manifest", "-m", metavar="FILE", action="append", help="workload/service manifest (repeatable)")
    p.add_argument("--dockerfile", metavar="FILE")
    p.add_argument("--secrets", metavar="FILE", help="Secret objects (values are redacted)")
    p.add_argument("--nodes", metavar="FILE", help="kubectl get nodes -o json")
    p.add_argument("--endpoints", metavar="FILE", help="kubectl get endpoints -o json")
    p.add_argument("--docker-inspect", metavar="FILE", help="docker inspect output")
    p.add_argument("--format", "-f", choices=("text", "markdown", "json"), default="text")
    p.add_argument("--output", "-o", metavar="FILE", help="write the report to FILE")
    p.add_argument("--patch-out", metavar="FILE", help="write the (redacted) unified diff to FILE")
    p.add_argument("--write-fixed", metavar="DIR", help="write the patched manifest files into DIR")
    p.add_argument("--review", action="store_true", help="add an AI second opinion (PROVIDER env, default mock)")
    p.add_argument("--provider", help="mock | groq | gemini | anthropic (implies --review)")
    p.add_argument("--fail-on-diagnosis", action="store_true", help="exit 3 when a failure is diagnosed")
    _add_color(p)
    p.set_defaults(func=cmd_diagnose)

    p = sub.add_parser("redact", help="redact secrets & PII from files or stdin", description="Secret & PII firewall.")
    p.add_argument("files", nargs="*", help="files to redact (default: stdin)")
    p.add_argument("--no-pii", action="store_true", help="only redact secrets, keep e-mails etc.")
    p.add_argument("--ips", action="store_true", help="also redact IPv4 addresses")
    p.add_argument("--audit", action="store_true", help="print the redaction audit to stderr")
    p.add_argument("--json", action="store_true", help="JSON output with audit")
    p.add_argument("--output", "-o", metavar="FILE")
    p.add_argument("--fail-on-secrets", action="store_true", help="exit 3 if anything was redacted (CI gate)")
    p.set_defaults(func=cmd_redact)

    p = sub.add_parser("audit", help="audit manifests, RBAC and commands", description="Cluster risk audit.")
    p.add_argument("paths", nargs="*", help="manifest files or directories")
    p.add_argument("--command", "-c", action="append", help="command to classify (repeatable)")
    p.add_argument("--commands-file", metavar="FILE", help="file with one command per line")
    p.add_argument("--role", choices=("viewer", "operator", "admin"), default="operator")
    p.add_argument("--format", "-f", choices=("text", "markdown", "json"), default="text")
    p.add_argument("--fail-on", choices=_SEVERITIES, help="exit 3 if a finding of this severity or higher exists")
    _add_color(p)
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("check", help="classify one command (exit 0 safe, 3 approval, 4 blocked)")
    p.add_argument("cmd", nargs=argparse.REMAINDER, help="the command, e.g. kubectl delete ns prod")
    p.add_argument("--role", choices=("viewer", "operator", "admin"), default="operator")
    p.add_argument("--approved", action="store_true", help="a human approved this command")
    p.add_argument("--json", action="store_true")
    _add_color(p)
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("serve-mcp", help="run the MCP server on stdio", description="Model Context Protocol server.")
    p.add_argument("--roots", nargs="*", metavar="DIR", help="directories diagnose_pod may read bundles from")
    p.set_defaults(func=cmd_serve)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    ensure_safe_stdio()
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_OK
    if args.func is cmd_check:
        # REMAINDER swallows our own flags when they follow the command; pull them out.
        rest: List[str] = []
        for tok in args.cmd:
            if tok == "--json":
                args.json = True
            elif tok == "--approved":
                args.approved = True
            elif tok == "--no-color":
                args.color = False
            else:
                rest.append(tok)
        args.cmd = rest
        if not args.cmd:
            parser.error("check: missing command")
    try:
        return int(args.func(args) or 0)
    except CliError as exc:
        _err(f"kubeguard: error: {exc}\n")
        return EXIT_ERROR
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    except BrokenPipeError:  # pragma: no cover - e.g. `kubeguard demo | head`
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
