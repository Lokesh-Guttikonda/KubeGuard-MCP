#!/usr/bin/env python3
"""Regenerate the real demo output embedded in README.md.

    python scripts/update_readme.py           # rewrite the marked blocks
    python scripts/update_readme.py --check   # exit 1 if README.md is stale (used by the test-suite)

Each block between ``<!-- demo:NAME:start -->`` and ``<!-- demo:NAME:end -->``
is produced by actually running the command below in a subprocess, exactly as
a user would in a terminal (UTF-8, no colours).
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"

# name -> (argv after "python", style)
BLOCKS: Dict[str, Tuple[List[str], str]] = {
    "single": (["scripts/demo_offline.py", "--scenario", "crashloop_secret_leak", "--no-report"], "terminal"),
    "full": (["scripts/demo_offline.py", "--no-report"], "terminal"),
    "report": (["scripts/kubeguard.py", "diagnose", "--example", "oom_killed", "--format", "markdown"], "markdown"),
}


def run(argv: List[str]) -> str:
    env = {k: v for k, v in os.environ.items() if k not in ("FORCE_COLOR", "PROVIDER", "KUBEGUARD_PROVIDER")}
    env.update({"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "NO_COLOR": "1"})
    proc = subprocess.run([sys.executable, *argv], cwd=str(ROOT), env=env, capture_output=True, timeout=300)
    if proc.returncode != 0:
        raise SystemExit(f"command failed: python {' '.join(argv)}\n{proc.stderr.decode('utf-8', 'replace')}")
    return proc.stdout.decode("utf-8").replace("\r\n", "\n")


def render_block(name: str) -> str:
    argv, style = BLOCKS[name]
    out = run(argv)
    if style == "terminal":
        return "```text\n$ python " + " ".join(argv) + "\n" + out.rstrip() + "\n```"
    # Rendered Markdown: demote headings two levels so they nest inside the README
    # (never touching lines inside fenced code blocks, e.g. YAML comments in a diff).
    lines = []
    in_fence = False
    for ln in out.rstrip().split("\n"):
        if ln.startswith("```"):
            in_fence = not in_fence
        lines.append("##" + ln if ln.startswith("#") and not in_fence else ln)
    return "\n".join(lines)


def update(text: str) -> str:
    for name in BLOCKS:
        pattern = re.compile(rf"(<!-- demo:{name}:start -->)(.*?)(<!-- demo:{name}:end -->)", re.S)
        if not pattern.search(text):
            raise SystemExit(f"README.md is missing the demo:{name} markers")
        block = render_block(name)
        text = pattern.sub(lambda m, b=block: m.group(1) + "\n" + b + "\n" + m.group(3), text)
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if README.md is out of date")
    args = parser.parse_args()
    current = README.read_text(encoding="utf-8")
    fresh = update(current)
    if args.check:
        if fresh != current:
            print("README.md demo output is stale - run: python scripts/update_readme.py", file=sys.stderr)
            return 1
        print("README.md demo output is up to date")
        return 0
    README.write_bytes(fresh.encode("utf-8"))
    print("README.md updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
