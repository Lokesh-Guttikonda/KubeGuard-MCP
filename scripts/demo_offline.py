#!/usr/bin/env python3
"""KubeGuard-MCP offline demo - zero packages, zero API keys, zero network.

    python scripts/demo_offline.py                 # all four incidents + Markdown report
    python scripts/demo_offline.py -s oom_killed   # a single scenario
    python scripts/demo_offline.py --report out/incident-report.md --no-report

Works on Linux, macOS and Windows (set PYTHONUTF8=1 for the full Unicode glyphs
in legacy Windows consoles; without it the output degrades to clean ASCII).
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.demo import main

if __name__ == "__main__":
    sys.exit(main())
