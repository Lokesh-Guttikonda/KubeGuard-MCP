"""Locate and load the bundled offline incident scenarios.

The scenarios live in ``examples/`` at the repository root.  Wheels ship the
same files as package data (``kubeguard/examples``), so discovery checks, in
order: ``$KUBEGUARD_EXAMPLES``, the installed package data, the source
checkout next to the package, and ``./examples``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from .correlator import IncidentBundle

__all__ = ["SCENARIOS", "find_examples_dir", "list_scenarios", "load_scenario", "scenario_metadata"]

# Canonical demo order.
SCENARIOS = ("oom_killed", "crashloop_secret_leak", "service_port_mismatch", "image_pull_backoff")


def _candidates() -> List[Path]:
    here = Path(__file__).resolve().parent
    out = []
    env = os.environ.get("KUBEGUARD_EXAMPLES")
    if env:
        out.append(Path(env))
    out += [here / "examples", here.parent / "examples", Path.cwd() / "examples"]
    return out


def find_examples_dir() -> Optional[Path]:
    for cand in _candidates():
        if cand.is_dir() and any((cand / name).is_dir() for name in SCENARIOS):
            return cand
    return None


def list_scenarios() -> List[str]:
    root = find_examples_dir()
    if root is None:
        return []
    found = sorted(p.name for p in root.iterdir() if p.is_dir() and not p.name.startswith(("_", ".")))
    ordered = [s for s in SCENARIOS if s in found]
    return ordered + [s for s in found if s not in ordered]


def scenario_dir(name: str) -> Path:
    root = find_examples_dir()
    if root is None:
        raise FileNotFoundError("bundled examples not found; set KUBEGUARD_EXAMPLES to the examples/ directory")
    if name not in list_scenarios():
        raise KeyError(f"unknown scenario {name!r}; available: {', '.join(list_scenarios())}")
    return root / name


def scenario_metadata(name: str) -> Dict[str, Any]:
    meta = scenario_dir(name) / "scenario.json"
    if meta.is_file():
        return json.loads(meta.read_text(encoding="utf-8"))
    return {}


def load_scenario(name: str) -> IncidentBundle:
    return IncidentBundle.from_directory(scenario_dir(name), name=name)
