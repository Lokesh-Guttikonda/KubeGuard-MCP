"""kubeguard-mcp - Zero-Trust Kubernetes & Container Triage MCP Server + CLI.

The core engine uses only the Python standard library:

* :mod:`.redactor`     - secret & PII redaction firewall
* :mod:`.policy`       - zero-trust command & RBAC policy engine
* :mod:`.correlator`   - deterministic incident correlator + patch generator
* :mod:`.auditor`      - manifest validation and cluster risk audit
* :mod:`.mcp_server`   - JSON-RPC 2.0 stdio Model Context Protocol server
* :mod:`.llm_reviewer` - optional redacted-only LLM second opinion
* :mod:`.cli`          - the ``kubeguard`` command line
"""

from __future__ import annotations

import importlib
from typing import Any

__version__ = "1.0.0"

_EXPORTS = {
    "Redactor": ".redactor",
    "RedactionResult": ".redactor",
    "redact": ".redactor",
    "PolicyEngine": ".policy",
    "Verdict": ".policy",
    "classify": ".policy",
    "analyze_rbac": ".policy",
    "IncidentBundle": ".correlator",
    "CorrelationResult": ".correlator",
    "FailureType": ".correlator",
    "correlate": ".correlator",
    "load_bundle": ".correlator",
    "validate_manifest": ".auditor",
    "audit_cluster": ".auditor",
    "LLMReviewer": ".llm_reviewer",
    "MCPServer": ".mcp_server",
}

__all__ = ["__version__", *sorted(_EXPORTS)]


def __getattr__(name: str) -> Any:  # PEP 562 lazy re-exports keep `import` fast
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(importlib.import_module(module, __name__), name)


def __dir__() -> list:
    return sorted(set(globals()) | set(_EXPORTS))
