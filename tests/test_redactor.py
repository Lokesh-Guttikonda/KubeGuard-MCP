import json
import time

import pytest

from src.redactor import DEFAULT_RULES, Redactor, Rule, is_secret_key, redact, redact_text, scan
from tests.conftest import fake, fake_aws_key_id, fake_aws_secret, fake_jwt

PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAn0demo\nZm9vYmFy\n-----END RSA PRIVATE KEY-----"


def _cases():
    return [
        ("aws_access_key_id", f"key={fake_aws_key_id()} region=eu-west-1", fake_aws_key_id()),
        ("aws_secret_access_key", f"AWS_SECRET_ACCESS_KEY={fake_aws_secret()}", fake_aws_secret()),
        ("aws_secret_access_key", f'{{"SecretAccessKey": "{fake_aws_secret()}"}}', fake_aws_secret()),
        ("aws_session_token", "aws_session_token = " + fake("FwoG", 120), fake("FwoG", 120)),
        ("jwt", f"token is {fake_jwt()} ok", fake_jwt()),
        ("bearer_token", "Authorization: Bearer " + fake("tok_", 30), fake("tok_", 30)),
        ("basic_auth", "Authorization: Basic dXNlcjpodW50ZXIyMjI=", "dXNlcjpodW50ZXIyMjI="),
        ("kubeconfig_token", "users:\n- name: ci\n  user:\n    token: " + fake("k8s", 40), fake("k8s", 40)),
        ("kubeconfig_token", "    client-key-data: " + fake("LS0t", 60), fake("LS0t", 60)),
        ("private_key", f"key:\n{PEM}\nend", "MIIEowIBAAKCAQEAn0demo"),
        ("db_connection_string", "DSN postgres://app:S3cr3t!@db.prod:5432/app", "S3cr3t!"),
        ("db_connection_string", "mongodb+srv://svc:pa55w0rd@cluster0.mongodb.net/db", "pa55w0rd"),
        ("db_connection_string", "rediss://default:r3d1sPass@cache:6380/0", "r3d1sPass"),
        ("url_credentials", "clone https://deploy:gh0stPass@git.example.com/repo.git", "gh0stPass"),
        ("url_param_secret", "jdbc:sqlserver://db;user=sa;password=Jdbc-Pass-1", "Jdbc-Pass-1"),
        ("github_token", "GH=" + fake("ghp_", 36), fake("ghp_", 36)),
        ("gitlab_token", "token " + fake("glpat-", 20), fake("glpat-", 20)),
        ("slack_token", "slack " + fake("xoxb-", 30, "1234567890-ab"), fake("xoxb-", 30, "1234567890-ab")),
        ("stripe_key", "stripe " + fake("sk_live_", 24), fake("sk_live_", 24)),
        ("google_api_key", "maps " + fake("AIza", 35), fake("AIza", 35)),
        ("llm_api_key", "ANTHROPIC " + fake("sk-ant-api03-", 40), fake("sk-ant-api03-", 40)),
        ("llm_api_key", "groq " + fake("gsk_", 48), fake("gsk_", 48)),
        ("docker_auth", '{"auths": {"r.io": {"auth": "Y2ktYm90OnNlY3JldDEyMw=="}}}', "Y2ktYm90OnNlY3JldDEyMw=="),
        ("secret_assignment", "DB_PASSWORD=hunter2 started", "hunter2"),
        ("secret_assignment", "export API_KEY='abc123def456'", "abc123def456"),
        ("secret_assignment", "password: Tr0ub4dor&3", "Tr0ub4dor&3"),
        ("json_secret_field", '{"client_secret": "cs-9f8e7d6c"}', "cs-9f8e7d6c"),
        ("k8s_env_secret", "        - name: DB_PASSWORD\n          value: hunter2\n", "hunter2"),
        ("k8s_env_secret", '{"name": "API_TOKEN", "value": "tok-123456"}', "tok-123456"),
        ("email", "contact jane.doe@example.com today", "jane.doe@example.com"),
        ("credit_card", "card 4111 1111 1111 1111 charged", "4111 1111 1111 1111"),
        ("us_ssn", "ssn 123-45-6789", "123-45-6789"),
    ]


@pytest.mark.parametrize("rule,text,secret", _cases(), ids=lambda v: v if isinstance(v, str) and len(v) < 25 else None)
def test_rule_detects_and_masks(rule, text, secret):
    res = redact(text)
    assert secret not in res.text
    assert f"[REDACTED:{rule}]" in res.text
    assert rule in res.by_rule


@pytest.mark.parametrize(
    "text",
    [
        'asyncpg.exceptions.InvalidPasswordError: password authentication failed for user "orders"',
        "max_tokens=1024 retries=3",
        "secretName: db-credentials",
        "token: expired",
        "kind: Secret\ntype: Opaque",
        "image: nginx:1.25.3",
        "trace_id=4f9c2b7e1d8a6f3c status=200",
        "pool = create_pool(dsn=settings.database_url)",
        "valueFrom:\n  secretKeyRef:\n    name: db\n    key: password",
        "DB_PASSWORD_FILE=/run/secrets/db",
        "Authorization: Bearer ${TOKEN}",
        "git clone git@github.com:org/repo.git",
        "connect user@orders-db.shop.svc.cluster.local",
        "card 4111 1111 1111 1112",
        "deployed at 2026-11-04 by ci",
        "redis://cache:6379/0",
    ],
)
def test_no_false_positives(text):
    res = redact(text)
    assert res.count == 0, res.findings
    assert res.text == text


def test_db_url_keeps_user_and_host():
    out = redact_text("postgresql://orders_svc:Xk9mP2vL8qRt4@orders-db.shop.svc:5432/orders")
    assert out == "postgresql://orders_svc:[REDACTED:db_connection_string]@orders-db.shop.svc:5432/orders"


def test_more_specific_rule_wins_overlaps():
    res = redact(f"Authorization: Bearer {fake_jwt()}")
    assert res.by_rule == {"jwt": 1}


def test_idempotent():
    text = "\n".join(c[1] for c in _cases())
    once = redact(text)
    twice = redact(once.text)
    assert twice.count == 0
    assert twice.text == once.text


def test_audit_never_contains_secret_and_has_counts():
    text = f"a=1\nDB_PASSWORD=hunter2\nkey {fake_aws_key_id()}\nmail bob@example.org\n"
    res = redact(text, source="app.log")
    audit = res.audit()
    assert audit["redaction_count"] == 3 == res.count
    assert audit["by_category"] == {"pii": 1, "secret": 2}
    assert audit["max_severity"] == "critical"
    assert audit["lines"] == [2, 3, 4]
    assert audit["source"] == "app.log"
    blob = json.dumps(audit) + json.dumps([f.to_dict() for f in res.findings])
    assert "hunter2" not in blob and fake_aws_key_id() not in blob


def test_line_and_column_are_reported():
    res = redact("first line\n  DB_PASSWORD=hunter2\n")
    f = res.findings[0]
    assert (f.line, f.column, f.length) == (2, 15, 7)


def test_include_pii_false_keeps_email():
    res = Redactor(include_pii=False).redact("bob@example.org DB_PASSWORD=hunter2")
    assert "bob@example.org" in res.text and "hunter2" not in res.text


def test_ip_redaction_is_opt_in():
    assert redact("pod ip 10.0.3.142").count == 0
    assert "[REDACTED:ipv4]" in Redactor(redact_ips=True).redact("pod ip 10.0.3.142").text


def test_fingerprints_correlate_without_revealing():
    engine = Redactor(fingerprint_salt="s3")
    a = engine.redact("DB_PASSWORD=hunter2 again DB_PASSWORD=hunter2").findings
    b = engine.redact("DB_PASSWORD=other").findings
    assert a[0].fingerprint == a[1].fingerprint != b[0].fingerprint
    assert "#" in engine.redact("DB_PASSWORD=hunter2").text
    assert Redactor(fingerprint_salt="other").redact("DB_PASSWORD=hunter2").findings[0].fingerprint != a[0].fingerprint


def test_kubernetes_secret_yaml_structural_pass():
    text = (
        'apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\ndata:\n  username: YWRtaW4=\n  url: "cG9zdA=="\n'
        "stringData:\n  cert: |\n    line1\n    line2\n"
    )
    res = redact(text)
    assert "YWRtaW4=" not in res.text and "cG9zdA==" not in res.text and "line1" not in res.text
    assert res.by_rule["k8s_secret_data"] == 3
    assert "name: s" in res.text


def test_kubernetes_secret_json_list():
    text = json.dumps({"kind": "List", "items": [{"kind": "Secret", "data": {"token": "dG9rZW4tdmFsdWU="}}]}, indent=2)
    res = redact(text)
    assert "dG9rZW4tdmFsdWU=" not in res.text
    assert res.by_rule == {"k8s_secret_data": 1}
    json.loads(res.text)  # still valid JSON


def test_configmap_data_is_not_masked():
    text = "kind: ConfigMap\ndata:\n  LOG_LEVEL: debug\n  FEATURE_X: 'on'\n"
    assert redact(text).count == 0


def test_redact_obj_structural():
    obj = {
        "spec": {"containers": [{"env": [{"name": "API_TOKEN", "value": "abc"}, {"name": "MODE", "value": "fast"}]}]},
        "password": "x1",
        "max_tokens": 4096,
        "items": [{"kind": "Secret", "data": {"k": "dmFs"}}, "DB_PASSWORD=hunter2"],
    }
    clean, n = Redactor().redact_obj(obj)
    assert n == 4
    env = clean["spec"]["containers"][0]["env"]
    assert env[0]["value"].startswith("[REDACTED") and env[1]["value"] == "fast"
    assert clean["password"].startswith("[REDACTED") and clean["max_tokens"] == 4096
    assert clean["items"][0]["data"]["k"].startswith("[REDACTED")
    assert "hunter2" not in json.dumps(clean)
    assert obj["password"] == "x1"  # input is not mutated
    assert Redactor().redact_obj(clean)[1] == 0  # idempotent


def test_scan_and_contains_secrets():
    assert scan("DB_PASSWORD=hunter2")[0].rule == "secret_assignment"
    assert Redactor().contains_secrets(fake_jwt())
    assert not Redactor().contains_secrets("all quiet")


def test_empty_input():
    assert redact("").text == "" and redact("").count == 0


def test_unicode_is_preserved():
    res = redact("Grüße 🚀 DB_PASSWORD=hunter2 – ok")
    assert res.text == "Grüße 🚀 DB_PASSWORD=[REDACTED:secret_assignment] – ok"


def test_case_folding_fallback_when_lowercase_changes_length():
    # "İ".lower() is two code points; offsets would shift, so the engine must fall back.
    res = redact("İİİ DB_PASSWORD=hunter2 İ")
    assert "hunter2" not in res.text and res.text.startswith("İİİ DB_PASSWORD=[REDACTED")


def test_crlf_input():
    res = redact("a\r\nDB_PASSWORD=hunter2\r\nb")
    assert res.text == "a\r\nDB_PASSWORD=[REDACTED:secret_assignment]\r\nb"


def test_private_key_block_spans_lines():
    res = redact(f"before\n{PEM}\nafter")
    assert res.text == "before\n[REDACTED:private_key]\nafter"


def test_extra_rules():
    rule = Rule("ticket_id", "secret", "low", __import__("re").compile(r"TKT-\d{6}"))
    res = Redactor(extra_rules=[rule]).redact("see TKT-123456")
    assert res.text == "see [REDACTED:ticket_id]"


@pytest.mark.parametrize(
    "key,expected",
    [
        ("DB_PASSWORD", True),
        ("client_secret", True),
        ("SESSION_SECRET", True),
        ("api-key", True),
        ("DATABASE_URL", True),
        ("secretName", False),
        ("DB_PASSWORD_FILE", False),
        ("AWS_ACCESS_KEY_ID", False),
        ("token_endpoint", False),
        ("InvalidPasswordError", False),
        ("LOG_LEVEL", False),
    ],
)
def test_is_secret_key(key, expected):
    assert is_secret_key(key) is expected


def test_rules_have_unique_descriptions_and_valid_severity():
    for r in DEFAULT_RULES:
        assert r.severity in ("low", "medium", "high", "critical")
        assert r.category in ("secret", "pii")
        assert r.description


def test_throughput_one_megabyte():
    line = '2026-11-04T10:00:00Z INFO GET /api/v1/orders/123 status=200 latency_ms=12 ua="kube-probe/1.31"\n'
    text = line * (1_000_000 // len(line)) + "DB_PASSWORD=hunter2\n"
    start = time.perf_counter()
    res = redact(text)
    elapsed = time.perf_counter() - start
    assert res.count == 1
    assert elapsed < 3.0, f"redaction too slow: {elapsed:.2f}s/MB"
