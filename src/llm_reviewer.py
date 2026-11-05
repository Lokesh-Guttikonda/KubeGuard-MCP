"""Optional LLM "second opinion" - which only ever sees redacted data.

``PROVIDER=mock`` (the default) is fully offline and deterministic, so
KubeGuard costs nothing to run.  Setting ``PROVIDER`` to ``groq``, ``gemini``
or ``anthropic`` (plus the matching API key) asks a hosted model to review the
deterministic diagnosis.  Guarantees:

* The payload is built from the already-redacted :class:`CorrelationResult`
  (never from raw files) and is scanned by the firewall *again* right before
  sending; any residual match is masked and counted in ``redactions_applied``.
* The model can only comment - it never changes the diagnosis or the patch.
* ``httpx`` is used when installed (``pip install kubeguard-mcp[llm]``);
  otherwise the stdlib :mod:`urllib` transport is used, so there is still no
  mandatory dependency.

Environment variables::

    PROVIDER / KUBEGUARD_PROVIDER     mock | groq | gemini | anthropic
    GROQ_API_KEY, GEMINI_API_KEY (or GOOGLE_API_KEY), ANTHROPIC_API_KEY
    KUBEGUARD_LLM_MODEL               override the provider's default model
    KUBEGUARD_LLM_BASE_URL            override the endpoint (proxies, gateways)
    KUBEGUARD_LLM_TIMEOUT             request timeout in seconds (default 30)
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .correlator import CorrelationResult, FailureType
from .redactor import Redactor, default_redactor

__all__ = ["DEFAULT_MODELS", "PROVIDERS", "SYSTEM_PROMPT", "LLMReviewer", "Review", "ReviewerError"]

PROVIDERS = ("mock", "groq", "gemini", "anthropic")
DEFAULT_MODELS = {
    "mock": "kubeguard-rules-v1",
    "groq": "llama-3.3-70b-versatile",
    "gemini": "gemini-2.5-flash",
    "anthropic": "claude-opus-5-5",
}
_ENDPOINTS = {
    "groq": "https://api.groq.com/openai/v1/chat/completions",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
    "anthropic": "https://api.anthropic.com/v1/messages",
}
_KEY_ENV = {
    "groq": ("GROQ_API_KEY",),
    "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    "anthropic": ("ANTHROPIC_API_KEY",),
}

SYSTEM_PROMPT = (
    "You are a senior Site Reliability Engineer reviewing an automated, deterministic Kubernetes incident "
    "diagnosis. All secrets were replaced with [REDACTED:<rule>] tokens before you received the data; never ask "
    "for them. Judge whether the evidence supports the stated root cause and whether the proposed patch is safe. "
    'Reply with ONLY a JSON object: {"verdict": "AGREE" | "PARTIAL" | "DISAGREE", "summary": "<one sentence>", '
    '"risks": ["<risk>", ...], "next_checks": ["<read-only check>", ...]}. Keep lists to at most 3 items.'
)

Transport = Callable[[str, Dict[str, str], Dict[str, Any], float], Tuple[int, Any]]


class ReviewerError(RuntimeError):
    """The configured provider could not produce a review."""


@dataclass
class Review:
    provider: str
    model: str
    verdict: str
    summary: str
    risks: List[str] = field(default_factory=list)
    next_checks: List[str] = field(default_factory=list)
    payload_chars: int = 0
    redactions_applied: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "verdict": self.verdict,
            "summary": self.summary,
            "risks": list(self.risks),
            "next_checks": list(self.next_checks),
            "payload_chars": self.payload_chars,
            "redactions_applied": self.redactions_applied,
        }


# --------------------------------------------------------------------------- #
# Transports
# --------------------------------------------------------------------------- #


def _urllib_transport(url: str, headers: Dict[str, str], body: Dict[str, Any], timeout: float) -> Tuple[int, Any]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")  # noqa: S310 - fixed https endpoints
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https endpoints
            return resp.status, json.loads(resp.read().decode("utf-8") or "null")
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8") or "null")
        except ValueError:
            payload = None
        return exc.code, payload


def _httpx_transport(url: str, headers: Dict[str, str], body: Dict[str, Any], timeout: float) -> Tuple[int, Any]:
    import httpx  # optional dependency

    resp = httpx.post(url, headers=headers, json=body, timeout=timeout)
    try:
        payload = resp.json()
    except ValueError:
        payload = None
    return resp.status_code, payload


def default_transport() -> Transport:
    try:
        import httpx  # noqa: F401
    except ImportError:
        return _urllib_transport
    return _httpx_transport


# --------------------------------------------------------------------------- #
# Reviewer
# --------------------------------------------------------------------------- #

_MOCK_RISKS = {
    FailureType.OOM_KILLED: [
        "A higher memory limit raises node memory pressure; confirm allocatable headroom before the rollout.",
        "If memory keeps growing after the fix, investigate a leak instead of raising the limit again.",
    ],
    FailureType.CRASH_LOOP: [
        "Restarting pods will not help until the underlying startup error is fixed.",
        "Rotate any credential that appeared in logs before rolling out, or the leaked values stay valid.",
    ],
    FailureType.IMAGE_PULL: [
        "Pull secrets are namespace-scoped; every namespace that runs the image needs its own copy.",
        "Pin images by digest so a re-pushed tag cannot change what runs in production.",
    ],
    FailureType.CONFIG_ERROR: [
        "Creating the missing object with placeholder values can start the app with wrong configuration.",
    ],
    FailureType.UNSCHEDULABLE: [
        "Lowering requests can cause CPU throttling or OOM under real load; validate with production metrics.",
    ],
    FailureType.SERVICE_PORT_MISMATCH: [
        "Ingress/NetworkPolicy objects that reference the old port number must be updated together.",
    ],
}
_MOCK_CHECKS = {
    FailureType.OOM_KILLED: ["kubectl top pod --containers after rollout", "inspect GC logs for heap growth"],
    FailureType.CRASH_LOOP: ["kubectl logs --previous on a fresh pod", "confirm the Secret keys exist"],
    FailureType.IMAGE_PULL: [
        "kubectl get secret <pull-secret> in the namespace",
        "verify the tag exists in the registry",
    ],
    FailureType.CONFIG_ERROR: ["kubectl get secret,configmap in the namespace"],
    FailureType.UNSCHEDULABLE: ["kubectl describe nodes for allocatable capacity"],
    FailureType.SERVICE_PORT_MISMATCH: ["kubectl get endpoints after the fix", "curl the Service from a debug pod"],
}


class LLMReviewer:
    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: Optional[float] = None,
        transport: Optional[Transport] = None,
        redactor: Optional[Redactor] = None,
        base_url: Optional[str] = None,
    ) -> None:
        chosen = (
            (provider or os.environ.get("PROVIDER") or os.environ.get("KUBEGUARD_PROVIDER") or "mock").strip().lower()
        )
        if chosen not in PROVIDERS:
            raise ReviewerError(f"unknown PROVIDER {chosen!r}; choose one of {', '.join(PROVIDERS)}")
        self.provider = chosen
        self.model = model or os.environ.get("KUBEGUARD_LLM_MODEL") or DEFAULT_MODELS[chosen]
        self.timeout = float(timeout or os.environ.get("KUBEGUARD_LLM_TIMEOUT") or 30.0)
        self.redactor = redactor or default_redactor()
        self.base_url = base_url or os.environ.get("KUBEGUARD_LLM_BASE_URL")
        self._transport = transport
        self._api_key = api_key
        if chosen != "mock" and not self.api_key:
            names = " or ".join(_KEY_ENV[chosen])
            raise ReviewerError(f"PROVIDER={chosen} requires {names} to be set")

    @property
    def api_key(self) -> Optional[str]:
        if self.provider == "mock":
            return None
        if self._api_key:
            return self._api_key
        for name in _KEY_ENV[self.provider]:
            if os.environ.get(name):
                return os.environ[name]
        return None

    @property
    def transport(self) -> Transport:
        return self._transport or default_transport()

    # -- payload ------------------------------------------------------------ #
    def build_payload(self, result: CorrelationResult) -> Tuple[str, int]:
        """Return (prompt_text, residual_redactions).  Only redacted data is used."""
        data = result.to_dict()  # already passed redact_obj()
        compact = {
            "incident_id": data["incident_id"],
            "severity": data["severity"],
            "workload": data["workload"],
            "namespace": data["namespace"],
            "diagnoses": [
                {
                    k: d[k]
                    for k in ("failure", "confidence", "sub_cause", "root_cause", "evidence", "remediation", "patches")
                }
                for d in data["diagnoses"][:2]
            ],
            "timeline": data["timeline"][:12],
            "secret_firewall": {
                "secrets_blocked": data["secret_firewall"]["secrets_blocked"],
                "by_rule": data["secret_firewall"]["by_rule"],
            },
        }
        text = json.dumps(compact, indent=1, ensure_ascii=False)
        final = self.redactor.redact(text)  # last line of defence before egress
        return final.text, final.count

    # -- review ------------------------------------------------------------- #
    def review(self, result: CorrelationResult, raise_errors: bool = False) -> Review:
        payload, residual = self.build_payload(result)
        try:
            if self.provider == "mock":
                review = self._mock(result)
            else:
                review = self._remote(payload)
        except ReviewerError as exc:
            if raise_errors:
                raise
            review = Review(self.provider, self.model, "UNAVAILABLE", f"review skipped: {exc}")
        review.payload_chars = len(payload)
        review.redactions_applied = residual
        return review

    def _mock(self, result: CorrelationResult) -> Review:
        p = result.primary
        if p is None:
            return Review(
                "mock",
                self.model,
                "AGREE",
                "No failure signature detected; the workload looks healthy from the provided data.",
                [],
                ["re-collect events if the incident is ongoing"],
            )
        strong = sum(1 for e in p.evidence if e.weight >= 0.1)
        if p.confidence >= 0.8 and p.patches:
            verdict = "AGREE"
            summary = (
                f"{strong} independent signals corroborate {p.failure.value} ({p.sub_cause.replace('_', ' ')}); "
                "the patch is minimal and reversible."
            )
        elif p.confidence >= 0.6:
            verdict = "PARTIAL"
            summary = (
                f"Evidence supports {p.failure.value}, but no automatic patch could be derived - confirm manually."
            )
        else:
            verdict = "PARTIAL"
            summary = f"Weak evidence for {p.failure.value}; collect more signals before acting."
        risks = list(_MOCK_RISKS.get(p.failure, []))
        leaked = sum(result.runtime_leaks.values())
        if leaked:
            noun = "credential" if leaked == 1 else "credentials"
            risks.insert(0, f"{leaked} {noun} leaked into runtime logs - rotate before rolling out the fix.")
        return Review("mock", self.model, verdict, summary, risks[:3], list(_MOCK_CHECKS.get(p.failure, []))[:3])

    def _request(self, payload: str) -> Tuple[str, Dict[str, str], Dict[str, Any]]:
        key = self.api_key or ""
        if self.provider == "groq":
            url = self.base_url or _ENDPOINTS["groq"]
            headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
            body: Dict[str, Any] = {
                "model": self.model,
                "temperature": 0,
                "max_tokens": 800,
                "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": payload}],
            }
        elif self.provider == "gemini":
            url = (self.base_url or _ENDPOINTS["gemini"]).format(model=self.model)
            headers = {"x-goog-api-key": key, "Content-Type": "application/json"}
            body = {
                "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                "contents": [{"role": "user", "parts": [{"text": payload}]}],
                "generationConfig": {"temperature": 0, "maxOutputTokens": 800, "responseMimeType": "application/json"},
            }
        else:
            url = self.base_url or _ENDPOINTS["anthropic"]
            headers = {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
            body = {
                "model": self.model,
                "max_tokens": 800,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": payload}],
            }
        return url, headers, body

    def _remote(self, payload: str) -> Review:
        url, headers, body = self._request(payload)
        try:
            status, data = self.transport(url, headers, body, self.timeout)
        except Exception as exc:  # network errors, timeouts, TLS ...
            raise ReviewerError(f"{self.provider} request failed: {type(exc).__name__}") from exc
        if status != 200 or not isinstance(data, dict):
            detail = ""
            if isinstance(data, dict):
                err = data.get("error")
                detail = err.get("message", "") if isinstance(err, dict) else str(err or "")
            raise ReviewerError(
                f"{self.provider} returned HTTP {status} {self.redactor.redact(detail[:200]).text}".strip()
            )
        text = _extract_text(self.provider, data)
        if not text:
            raise ReviewerError(f"{self.provider} returned an empty response")
        return self._parse(text)

    def _parse(self, text: str) -> Review:
        obj = _first_json_object(text)
        clean = self.redactor.redact_obj(obj)[0] if obj is not None else None
        if not isinstance(clean, dict):
            summary = self.redactor.redact(" ".join(text.split())[:300]).text
            return Review(self.provider, self.model, "PARTIAL", summary)
        verdict = str(clean.get("verdict", "PARTIAL")).upper()
        if verdict not in ("AGREE", "PARTIAL", "DISAGREE"):
            verdict = "PARTIAL"
        return Review(
            self.provider,
            self.model,
            verdict,
            str(clean.get("summary", ""))[:500],
            [str(x)[:300] for x in (clean.get("risks") or [])][:3],
            [str(x)[:300] for x in (clean.get("next_checks") or [])][:3],
        )


def _extract_text(provider: str, data: Dict[str, Any]) -> str:
    try:
        if provider == "groq":
            return str(data["choices"][0]["message"]["content"] or "")
        if provider == "gemini":
            parts = data["candidates"][0]["content"]["parts"]
            return "".join(str(p.get("text", "")) for p in parts)
        blocks = data.get("content") or []
        return "".join(str(b.get("text", "")) for b in blocks if isinstance(b, dict) and b.get("type") == "text")
    except (KeyError, IndexError, TypeError, AttributeError):
        return ""


def _first_json_object(text: str) -> Optional[Any]:
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    try:
        return json.loads(text)
    except ValueError:
        pass
    start = text.find("{")
    while start >= 0:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except ValueError:
                        break
        start = text.find("{", start + 1)
    return None
