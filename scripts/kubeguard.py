#!/usr/bin/env python3
"""Zero-install launcher for the ``kubeguard`` CLI from a source checkout.

python scripts/kubeguard.py diagnose examples/oom_killed
python /path/to/KubeGuard-MCP/scripts/kubeguard.py serve-mcp   # MCP clients
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.cli import main

if __name__ == "__main__":
    sys.exit(main())
