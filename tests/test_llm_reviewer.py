import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from src import llm_reviewer as lr
from src.correlator import correlate
from src.llm_reviewer import LLMReviewer, ReviewerError
from tests.conftest import EXAMPLE_SECRETS, EXAMPLES


@pytest.fixture(scope="module")
def crash():
    return correlate(EXAMPLES / "crashloop_secret_leak")


class FakeTransport:
    def __init__(self, status=200, data=None, exc=None):
        self.status, self.data, self.exc = status, data, exc
        self.calls = []

    def __call__(self, url, headers, body, timeout):
        self.calls.append({"url": url, "headers": headers, "body": body, "timeout": timeout})
        if self.exc:
            raise self.exc
        return self.status, self.data


REVIEW = {"verdict": "AGREE", "summary": "Evidence is consistent.", "risks": ["r1"], "next_checks": ["c1", "c2"]}


def test_default_provider_is_mock(crash):
    reviewer = LLMReviewer()
    assert reviewer.provider == "mock" and reviewer.api_key is None
    review = reviewer.review(crash)
    assert review.verdict == "AGREE" and review.provider == "mock"
    assert review.risks[0].startswith("3 credentials leaked")


def test_mock_review_is_deterministic(crash):
    assert LLMReviewer().review(crash).to_dict() == LLMReviewer().review(crash).to_dict()


def test_provider_from_env_requires_key(monkeypatch):
    monkeypatch.setenv("PROVIDER", "groq")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(ReviewerError, match="GROQ_API_KEY"):
        LLMReviewer()
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    assert LLMReviewer().provider == "groq"


def test_unknown_provider():
    with pytest.raises(ReviewerError, match="unknown PROVIDER"):
        LLMReviewer(provider="openai-ish")


def test_gemini_accepts_google_api_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", "g-key")
    assert LLMReviewer(provider="gemini").api_key == "g-key"


def test_payload_contains_only_redacted_data(crash):
    payload, residual = LLMReviewer().build_payload(crash)
    assert residual == 0
    for s in EXAMPLE_SECRETS:
        assert s not in payload
    assert "[REDACTED:" in payload and json.loads(payload)["diagnoses"][0]["failure"] == "CrashLoopBackOff"


@pytest.mark.parametrize(
    "provider,response,url_part,auth_header",
    [
        ("groq", {"choices": [{"message": {"content": json.dumps(REVIEW)}}]}, "api.groq.com", "Authorization"),
        (
            "gemini",
            {"candidates": [{"content": {"parts": [{"text": json.dumps(REVIEW)}]}}]},
            ":generateContent",
            "x-goog-api-key",
        ),
        (
            "anthropic",
            {"content": [{"type": "text", "text": "```json\n" + json.dumps(REVIEW) + "\n```"}]},
            "api.anthropic.com",
            "x-api-key",
        ),
    ],
)
def test_remote_providers_request_shape(crash, provider, response, url_part, auth_header):
    transport = FakeTransport(200, response)
    review = LLMReviewer(provider=provider, api_key="k-123", transport=transport).review(crash, raise_errors=True)
    assert (review.verdict, review.summary, review.next_checks) == ("AGREE", "Evidence is consistent.", ["c1", "c2"])
    call = transport.calls[0]
    assert url_part in call["url"] and auth_header in call["headers"]
    sent = json.dumps(call["body"])
    for s in EXAMPLE_SECRETS:
        assert s not in sent
    if provider == "anthropic":
        assert call["headers"]["anthropic-version"] == "2023-06-01"
        assert call["body"]["system"] == lr.SYSTEM_PROMPT
    if provider == "groq":
        assert call["body"]["messages"][0]["role"] == "system"


def test_model_and_base_url_overrides(crash, monkeypatch):
    monkeypatch.setenv("KUBEGUARD_LLM_MODEL", "custom-model")
    monkeypatch.setenv("KUBEGUARD_LLM_BASE_URL", "https://gateway.internal/v1/chat")
    transport = FakeTransport(200, {"choices": [{"message": {"content": json.dumps(REVIEW)}}]})
    LLMReviewer(provider="groq", api_key="k", transport=transport).review(crash)
    assert transport.calls[0]["url"] == "https://gateway.internal/v1/chat"
    assert transport.calls[0]["body"]["model"] == "custom-model"


def test_http_error_fails_open_by_default(crash):
    transport = FakeTransport(429, {"error": {"message": "rate limited, key sk-ant-api03-" + "x" * 30}})
    review = LLMReviewer(provider="anthropic", api_key="k", transport=transport).review(crash)
    assert review.verdict == "UNAVAILABLE" and "429" in review.summary
    assert "xxxxxxxxxx" not in review.summary  # provider error text is redacted too


def test_http_error_raises_when_requested(crash):
    with pytest.raises(ReviewerError, match="HTTP 500"):
        LLMReviewer(provider="groq", api_key="k", transport=FakeTransport(500, None)).review(crash, raise_errors=True)


def test_transport_exception_is_wrapped(crash):
    transport = FakeTransport(exc=TimeoutError("boom"))
    with pytest.raises(ReviewerError, match="TimeoutError"):
        LLMReviewer(provider="gemini", api_key="k", transport=transport).review(crash, raise_errors=True)


def test_non_json_model_text_becomes_partial(crash):
    transport = FakeTransport(200, {"choices": [{"message": {"content": "Looks fine to me overall."}}]})
    review = LLMReviewer(provider="groq", api_key="k", transport=transport).review(crash)
    assert review.verdict == "PARTIAL" and "Looks fine" in review.summary


def test_model_output_is_redacted(crash):
    leaky = dict(REVIEW, summary="the password is DB_PASSWORD=hunter2", verdict="weird")
    transport = FakeTransport(200, {"choices": [{"message": {"content": json.dumps(leaky)}}]})
    review = LLMReviewer(provider="groq", api_key="k", transport=transport).review(crash)
    assert "hunter2" not in review.summary and review.verdict == "PARTIAL"


def test_empty_response_is_an_error(crash):
    review = LLMReviewer(provider="groq", api_key="k", transport=FakeTransport(200, {"choices": []})).review(crash)
    assert review.verdict == "UNAVAILABLE"


@pytest.mark.parametrize(
    "text,expected",
    [
        ('{"a": 1}', {"a": 1}),
        ('```json\n{"a": 2}\n```', {"a": 2}),
        ('Sure! Here it is: {"a": {"b": 3}} hope that helps', {"a": {"b": 3}}),
        ("no json here", None),
    ],
)
def test_first_json_object(text, expected):
    assert lr._first_json_object(text) == expected


def test_default_transport_falls_back_to_urllib(monkeypatch):
    monkeypatch.setitem(sys.modules, "httpx", None)
    assert lr.default_transport() is lr._urllib_transport


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        status = 200 if body.get("ok") else 503
        payload = json.dumps({"echo": body, "auth": self.headers.get("Authorization")}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def test_urllib_transport_real_http_roundtrip():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/v1"
        status, data = lr._urllib_transport(
            url, {"Authorization": "Bearer t", "Content-Type": "application/json"}, {"ok": True}, 5
        )
        assert status == 200 and data["echo"] == {"ok": True} and data["auth"] == "Bearer t"
        status, data = lr._urllib_transport(url, {"Content-Type": "application/json"}, {"ok": False}, 5)
        assert status == 503 and data["echo"] == {"ok": False}
    finally:
        server.shutdown()
