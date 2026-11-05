"""Shared fixtures and builders for the KubeGuard test-suite.

Fake credentials are assembled at runtime (never stored as literals) so the
repository itself never contains strings that look like live provider tokens.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
SCENARIOS = ["oom_killed", "crashloop_secret_leak", "service_port_mismatch", "image_pull_backoff"]

# Credentials planted in the example bundles - none may ever appear in output.
EXAMPLE_SECRETS = [
    "Wint3r-2025!",
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "4f9c2b7e1d8a6f3c5b0e9d7a2c4f6b8e",
    "maria.garcia@example.com",
    "lena.schmidt@example.de",
    "p-z1Carp4No-nt3AZVpoDqyvJqLIFNKWoljv_jci_l0",
    "a3ViZWd1YXJkIGRlbW8gY2xpZW50IGtleSBtYXRlcmlhbCAtIG5vdCBhIHJlYWwga2V5",
    "U3ByMW5nLTIwMjYtcm90YXRlZA==",
    "1DkjY6dwOsq2SwCIYEtj",
]


# --------------------------------------------------------------------------- #
# fake secret builders (runtime-assembled)
# --------------------------------------------------------------------------- #


def fake(prefix: str, body_len: int, alphabet: str = "A1b2C3d4E5f6G7h8") -> str:
    body = (alphabet * (body_len // len(alphabet) + 1))[:body_len]
    return prefix + body


def fake_jwt() -> str:
    return "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiJ0ZXN0In0" + "." + "c2lnbmF0dXJlX19fX19fX19fX18"


def fake_aws_key_id() -> str:
    return "AKIA" + "Z7Q3X5N2R8K4M6PL"


def fake_aws_secret() -> str:
    return "abcd" + "EFGH/ijkl+MNOP0123qrstUVWX4567yzAB89"  # exactly 40 chars


# --------------------------------------------------------------------------- #
# Kubernetes object builders
# --------------------------------------------------------------------------- #


def cstatus(
    name: str = "app",
    waiting: Optional[str] = None,
    message: str = "",
    last_reason: Optional[str] = None,
    last_exit: Optional[int] = None,
    restarts: int = 0,
    ready: bool = False,
    running: bool = False,
    image: str = "registry.example.com/team/app:1.0.0",
) -> Dict[str, Any]:
    st: Dict[str, Any] = {"name": name, "image": image, "ready": ready, "restartCount": restarts}
    if waiting:
        st["state"] = {"waiting": {"reason": waiting, "message": message}}
    elif running:
        st["state"] = {"running": {"startedAt": "2026-01-01T00:00:00Z"}}
    if last_reason:
        st["lastState"] = {
            "terminated": {
                "reason": last_reason,
                "exitCode": last_exit,
                "startedAt": "2026-01-01T00:00:00Z",
                "finishedAt": "2026-01-01T00:01:00Z",
            }
        }
    return st


def pod(
    name: str = "app-6d4cf56db6-abcde",
    ns: str = "prod",
    labels: Optional[Dict[str, str]] = None,
    statuses: Optional[List[Dict[str, Any]]] = None,
    phase: str = "Running",
    conditions: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": ns,
            "labels": labels if labels is not None else {"app": "app"},
            "ownerReferences": [{"kind": "ReplicaSet", "name": name.rsplit("-", 1)[0]}],
        },
        "status": {"phase": phase, "conditions": conditions or [], "containerStatuses": statuses or []},
    }


def event(
    reason: str,
    message: str,
    type_: str = "Warning",
    count: int = 1,
    ts: str = "2026-01-01T00:00:30Z",
    kind: str = "Pod",
    name: str = "app-6d4cf56db6-abcde",
) -> Dict[str, Any]:
    return {
        "type": type_,
        "reason": reason,
        "message": message,
        "count": count,
        "firstTimestamp": ts,
        "lastTimestamp": ts,
        "involvedObject": {"kind": kind, "name": name},
    }


def deployment(
    containers_yaml: str,
    name: str = "app",
    ns: str = "prod",
    labels: str = "app: app",
    extra_pod_spec: str = "",
) -> str:
    """Render a Deployment; ``containers_yaml`` is indented at 6 spaces (compact list)."""
    return (
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        f"  name: {name}\n"
        f"  namespace: {ns}\n"
        "spec:\n"
        "  replicas: 2\n"
        "  selector:\n"
        "    matchLabels:\n"
        f"      {labels}\n"
        "  template:\n"
        "    metadata:\n"
        "      labels:\n"
        f"        {labels}\n"
        "    spec:\n"
        "      containers:\n"
        f"{containers_yaml}"
        f"{extra_pod_spec}"
    )


def secret_obj(name: str, keys: Dict[str, str], type_: str = "Opaque", ns: str = "prod") -> Dict[str, Any]:
    return {"kind": "Secret", "type": type_, "metadata": {"name": name, "namespace": ns}, "data": keys}


# --------------------------------------------------------------------------- #
# subprocess helpers
# --------------------------------------------------------------------------- #


def clean_env(**overrides: str) -> Dict[str, str]:
    env = {
        k: v for k, v in os.environ.items() if k not in ("PROVIDER", "KUBEGUARD_PROVIDER", "NO_COLOR", "FORCE_COLOR")
    }
    env.pop("PYTHONIOENCODING", None)
    env.update(overrides)
    return env


def run_py(
    args: List[str],
    env: Optional[Dict[str, str]] = None,
    input: Optional[bytes] = None,
    cwd: Path = ROOT,
    timeout: int = 180,
):
    return subprocess.run(
        [sys.executable, *args],
        cwd=str(cwd),
        env=env or clean_env(),
        input=input,
        capture_output=True,
        timeout=timeout,
    )


@pytest.fixture
def examples_dir() -> Path:
    return EXAMPLES


@pytest.fixture(autouse=True)
def _no_provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("PROVIDER", "KUBEGUARD_PROVIDER", "KUBEGUARD_LLM_MODEL", "KUBEGUARD_LLM_BASE_URL"):
        monkeypatch.delenv(var, raising=False)


def assert_no_secrets(text: str) -> None:
    for s in EXAMPLE_SECRETS:
        assert s not in text, f"secret leaked: {s[:6]}..."


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))
