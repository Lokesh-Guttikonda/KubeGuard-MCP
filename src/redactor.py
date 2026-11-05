"""High-speed secret & PII redaction firewall.

Every byte that leaves KubeGuard - terminal output, Markdown reports, MCP tool
results and (optional) LLM prompts - passes through :class:`Redactor` first.

Design goals
------------
* **Zero dependencies** - only :mod:`re` and friends from the stdlib.
* **Fast** - precompiled patterns, cheap substring pre-filters ("needles") that
  skip a rule entirely when its trigger text is absent, and a single output
  pass that splices all replacements at once.
* **Precise** - rules run in priority order and a later (more generic) rule
  can never overlap a span already claimed by an earlier, more specific one, so
  ``postgres://app:hunter2@db`` becomes ``postgres://app:[REDACTED:...]@db``
  (host and user stay visible for debugging) instead of losing the whole URL.
* **Idempotent** - redacting already-redacted text finds nothing new.
* **Auditable** - every redaction is reported (rule, category, severity,
  line, column) without ever storing the secret itself.
"""

from __future__ import annotations

import bisect
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Pattern, Sequence, Tuple

__all__ = [
    "DEFAULT_RULES",
    "RULE_CATEGORY",
    "SEVERITY_ORDER",
    "Finding",
    "RedactionResult",
    "Redactor",
    "Rule",
    "default_redactor",
    "is_secret_key",
    "redact",
    "redact_text",
    "scan",
]

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
TOKEN_PREFIX = "[REDACTED"


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Rule:
    name: str
    category: str  # "secret" | "pii"
    severity: str  # low | medium | high | critical
    pattern: Pattern[str]
    group: Any = 0
    needles: Tuple[str, ...] = ()
    validator: Optional[Callable[[str, re.Match[str]], bool]] = None
    description: str = ""
    # When True the (lower-case, flag-free) pattern runs against ``text.lower()``,
    # which is ~10x faster than an IGNORECASE alternation in CPython's ``re``.
    fold_case: bool = False


@dataclass(frozen=True)
class Finding:
    rule: str
    category: str
    severity: str
    line: int  # 1-based, in the original text
    column: int  # 1-based
    length: int
    fingerprint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "rule": self.rule,
            "category": self.category,
            "severity": self.severity,
            "line": self.line,
            "column": self.column,
            "length": self.length,
        }
        if self.fingerprint:
            d["fingerprint"] = self.fingerprint
        return d


@dataclass
class RedactionResult:
    text: str
    findings: List[Finding] = field(default_factory=list)
    source: Optional[str] = None

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def by_rule(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.rule] = out.get(f.rule, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))

    @property
    def by_category(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.category] = out.get(f.category, 0) + 1
        return dict(sorted(out.items()))

    @property
    def by_severity(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0)))

    @property
    def max_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity

    @property
    def lines(self) -> List[int]:
        return sorted({f.line for f in self.findings})

    def audit(self) -> Dict[str, Any]:
        """A JSON-serialisable audit record that never contains secret values."""
        return {
            "source": self.source,
            "redaction_count": self.count,
            "by_rule": self.by_rule,
            "by_category": self.by_category,
            "by_severity": self.by_severity,
            "max_severity": self.max_severity,
            "lines": self.lines,
        }


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

_SECRET_WORDS = (
    r"password|passwd|pwd|passphrase|secret|token|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key"
    r"|client[_\-]?secret|client[_\-]?key|credentials?|auth[_\-]?key|signing[_\-]?key|encryption[_\-]?key|session[_\-]?key"
    r"|master[_\-]?key|dsn|conn(?:ection)?[_\-]?str(?:ing)?|database[_\-]?url|db[_\-]?url|webhook[_\-]?url"
)
# Keys that *mention* a secret but hold a reference, a flag or metadata.
_NON_SECRET_KEY_RE = re.compile(
    r"(?i)(?:name|names|ref|refs|keyref|type|kind|url_?file|file|files|path|paths|dir|mount|policy|expir\w*|ttl"
    r"|length|len|count|size|limit|max|min|id|ids|version|enabled|disabled|mode|format|provider\w*|class|selector"
    r"|header|field|env|source|store|manager|rotation\w*|algorithm|alg|issuer|audience|scope|scopes|endpoint"
    r"|uri_?template|prefix|suffix|label|labels|annotation|annotations|hint|required|optional|exists|seconds"
    r"|timeout|interval|duration|key_?ref|_?usage|names?pace|volume|error|errors|exception|failed|failure|invalid"
    r"|warning|denied|mismatch|expired|missing)$"
)
_SECRET_KEY_RE = re.compile(rf"(?i)(?:{_SECRET_WORDS})")
_NON_SECRET_VALUES = frozenset(
    {
        "true", "false", "null", "none", "nil", "undefined", "yes", "no", "on", "off", "-", "''", '""', "[]", "{}",
        "expired", "invalid", "missing", "required", "ok", "not", "found", "failed", "error", "unauthorized",
        "denied", "empty", "set", "unset", "present", "redacted", "enabled", "disabled", "valid", "rotated",
        "refreshed", "accepted", "rejected", "revoked", "unknown", "n/a", "na", "default", "optional",
    }
)  # fmt: skip
_PLACEHOLDER_RE = re.compile(
    r"^(?:\$\{[^}]*\}|\$\([^)]*\)|\$[A-Z_][A-Z0-9_]*|\{\{.*\}\}|<[^>]*>|%\([^)]*\)s|\*{3,}|x{4,}|X{4,}|\.{3,}"
    r"|\[REDACTED[^\]]*\]?.*|[|>][+-]?\d*"
    # code references in stack traces / config dumps: settings.database_url, process.env.TOKEN
    r"|(?:settings|config|cfg|conf|os|env|self|this|process|args|opts|options|params|props|ctx|context|app|vault"
    r"|secrets?)(?:\.[A-Za-z_][A-Za-z0-9_]*)+(?:\(\))?[)\]]*)$"
)


def is_secret_key(key: str) -> bool:
    """True when a mapping/env key name suggests its value is a credential."""
    k = key.strip().strip("\"'")
    if not k or not _SECRET_KEY_RE.search(k):
        return False
    return not _NON_SECRET_KEY_RE.search(k)


def _is_placeholder(value: str) -> bool:
    v = value.strip().strip("\"'")
    if not v:
        return True
    if v.lower() in _NON_SECRET_VALUES:
        return True
    return bool(_PLACEHOLDER_RE.match(v))


def _luhn_ok(value: str, _m: re.Match[str]) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _value_not_placeholder(value: str, _m: re.Match[str]) -> bool:
    return not _is_placeholder(value)


def _assignment_ok(value: str, m: re.Match[str]) -> bool:
    key = m.group("key")
    if not is_secret_key(key):
        return False
    if _is_placeholder(value):
        return False
    # max_tokens: 1024, retries=3 ... short pure numbers are configuration
    if value.isdigit() and len(value) <= 5:
        return False
    return True


def _email_ok(value: str, _m: re.Match[str]) -> bool:
    local, _, domain = value.partition("@")
    if local.lower() in {"git", "noreply", "no-reply"}:
        return False
    return not domain.lower().endswith((".svc", ".local", ".internal", ".cluster.local"))


_SECRET_NEEDLES = (
    "pass", "pwd", "secret", "token", "key", "credential", "dsn", "conn", "database", "db_url", "db-url", "webhook",
)  # fmt: skip


def _r(pattern: str, flags: int = 0) -> Pattern[str]:
    return re.compile(pattern, flags)


DEFAULT_RULES: Tuple[Rule, ...] = (
    Rule(
        "private_key",
        "secret",
        "critical",
        _r(r"-----BEGIN[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----"),
        needles=("private key",),
        description="PEM/OpenSSH/PGP private key block",
    ),
    Rule(
        "aws_access_key_id",
        "secret",
        "critical",
        _r(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA)[A-Z0-9]{16}\b"),
        needles=("akia", "asia", "abia", "acca", "agpa", "aida", "aipa", "anpa", "anva", "apka", "aroa", "asca", "a3t"),
        description="AWS access key ID",
    ),
    Rule(
        "aws_secret_access_key",
        "secret",
        "critical",
        _r(
            r"(?i)(?:aws_?secret_?(?:access_?)?key|secret_?access_?key)[\"']?\s*[:=]\s*[\"']?"
            r"([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
        ),
        group=1,
        needles=("secret",),
        description="AWS secret access key",
    ),
    Rule(
        "aws_session_token",
        "secret",
        "critical",
        _r(
            r"(?i)(?:aws_?session_?token|x-amz-security-token|sessiontoken)[\"']?\s*[:=]\s*[\"']?"
            r"([A-Za-z0-9/+=]{100,})"
        ),
        group=1,
        needles=("session", "security-token"),
        description="AWS STS session token",
    ),
    Rule(
        "kubeconfig_token",
        "secret",
        "critical",
        _r(
            r"(?im)^[ \t]*(?:-[ \t]+)?(?:token|id-token|refresh-token|access-token|auth-token|client-key-data)"
            r"[ \t]*:[ \t]*[\"']?([^\s\"'#]{8,})[\"']?"
        ),
        group=1,
        needles=("token", "client-key-data"),
        validator=_value_not_placeholder,
        description="kubeconfig user credential (token / client-key-data)",
    ),
    Rule(
        "jwt",
        "secret",
        "high",
        _r(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
        needles=("eyj",),
        description="JSON Web Token (incl. Kubernetes service-account tokens)",
    ),
    Rule(
        "bearer_token",
        "secret",
        "high",
        _r(r"(?i)\bbearer[ \t]+([A-Za-z0-9\-._~+/]{16,}=*)"),
        group=1,
        needles=("bearer",),
        validator=_value_not_placeholder,
        description="HTTP bearer token",
    ),
    Rule(
        "basic_auth",
        "secret",
        "high",
        _r(r"(?i)(?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?basic[ \t]+([A-Za-z0-9+/]{8,}={0,2})"),
        group=1,
        needles=("basic",),
        description="HTTP basic-auth credentials",
    ),
    Rule(
        "db_connection_string",
        "secret",
        "critical",
        _r(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|oracle"
            r"|cockroachdb|clickhouse|couchdb|cassandra|neo4j(?:\+s)?|nats|kafka|memcached)://[^:@/\s'\"]*:"
            r"([^@\s'\"/]+)@"
        ),
        group=1,
        needles=("://",),
        validator=_value_not_placeholder,
        description="password embedded in a database/queue connection string",
    ),
    Rule(
        "url_credentials",
        "secret",
        "high",
        _r(r"(?i)\b[a-z][a-z0-9+.\-]{1,20}://[^:@/\s'\"]+:([^@\s'\"/]+)@"),
        group=1,
        needles=("://",),
        validator=_value_not_placeholder,
        description="password embedded in a URL (user:pass@host)",
    ),
    Rule(
        "github_token",
        "secret",
        "critical",
        _r(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
        needles=("gh", "github_pat"),
        description="GitHub token",
    ),
    Rule(
        "gitlab_token",
        "secret",
        "critical",
        _r(r"\bglpat-[A-Za-z0-9_\-]{20,}"),
        needles=("glpat-",),
        description="GitLab personal access token",
    ),
    Rule(
        "slack_token",
        "secret",
        "high",
        _r(r"\bxox[abposr]-[A-Za-z0-9-]{10,}|https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+"),
        needles=("xox", "hooks.slack.com"),
        description="Slack token or incoming webhook",
    ),
    Rule(
        "stripe_key",
        "secret",
        "critical",
        _r(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        needles=("_live_", "_test_"),
        description="Stripe secret/restricted key",
    ),
    Rule(
        "google_api_key",
        "secret",
        "high",
        _r(r"\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])"),
        needles=("aiza",),
        description="Google API key",
    ),
    Rule(
        "llm_api_key",
        "secret",
        "critical",
        _r(
            r"\b(?:sk-ant-[a-z]+\d*-[A-Za-z0-9_\-]{20,}|sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}|gsk_[A-Za-z0-9]{40,})"
        ),
        needles=("sk-", "gsk_"),
        description="LLM provider API key (Anthropic / OpenAI / Groq)",
    ),
    Rule(
        "docker_auth",
        "secret",
        "critical",
        _r(r"\"auth\"\s*:\s*\"([A-Za-z0-9+/=]{12,})\""),
        group=1,
        needles=('"auth"',),
        description="registry credential inside a docker config.json",
    ),
    Rule(
        "url_param_secret",
        "secret",
        "high",
        _r(
            r"(?i)[?&;](?:password|pwd|passwd|pass|secret|token|api[_-]?key|access[_-]?token|client_secret"
            r"|x-amz-signature|sig)=([^&;\s'\"#]+)"
        ),
        group=1,
        needles=("=",),
        validator=_value_not_placeholder,
        description="credential passed as a URL/JDBC parameter",
    ),
    Rule(
        "k8s_env_secret",
        "secret",
        "critical",
        _r(
            # the optional leading [-+ ] tolerates unified-diff line markers
            rf"(?m)^[-+ ]?[ \t]*-?[ \t]*name:[ \t]*[\"']?(?P<key>[A-Za-z0-9_.\-]*(?:{_SECRET_WORDS})[A-Za-z0-9_.\-]*)"
            r"[\"']?[ \t]*\r?\n[-+ ]?[ \t]*value:[ \t]*[\"']?(?P<val>[^\r\n\"']+?)[\"']?(?:[ \t]+#.*)?[ \t]*$"
        ),
        group="val",
        needles=_SECRET_NEEDLES,
        validator=_assignment_ok,
        fold_case=True,
        description="plaintext secret in a Kubernetes env var (YAML)",
    ),
    Rule(
        "k8s_env_secret",
        "secret",
        "critical",
        _r(
            rf"\"name\"\s*:\s*\"(?P<key>[A-Za-z0-9_.\-]*(?:{_SECRET_WORDS})[A-Za-z0-9_.\-]*)\"\s*,\s*"
            r"\"value\"\s*:\s*\"(?P<val>(?:[^\"\\]|\\.)*)\""
        ),
        group="val",
        needles=_SECRET_NEEDLES,
        validator=_assignment_ok,
        fold_case=True,
        description="plaintext secret in a Kubernetes env var (JSON)",
    ),
    Rule(
        "json_secret_field",
        "secret",
        "high",
        _r(
            rf"[\"'](?P<key>[A-Za-z0-9_.\-]*(?:{_SECRET_WORDS})[A-Za-z0-9_.\-]*)[\"']\s*:\s*"
            r"[\"'](?P<val>(?:[^\"'\\]|\\.)+)[\"']"
        ),
        group="val",
        needles=_SECRET_NEEDLES,
        validator=_assignment_ok,
        fold_case=True,
        description="secret-named field in JSON",
    ),
    Rule(
        "secret_assignment",
        "secret",
        "high",
        _r(
            # Anchored on the secret keyword (not on the identifier start) so the
            # regex engine can skip ahead quickly; only the key's suffix matters
            # for the exclusion check in is_secret_key().
            rf"(?P<key>(?:{_SECRET_WORDS})[A-Za-z0-9_.\-]*)"
            r"[ \t]*[=:][ \t]*[\"']?(?P<val>[^\s\"',;}{\]\[]+)"
        ),
        group="val",
        needles=_SECRET_NEEDLES,
        validator=_assignment_ok,
        fold_case=True,
        description=".env style KEY=value / key: value credential",
    ),
    Rule(
        "credit_card",
        "pii",
        "high",
        _r(r"\b(?:4\d{3}|5[1-5]\d{2}|2[2-7]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))(?:[ -]?\d{4}){2}[ -]?\d{1,7}\b"),
        validator=_luhn_ok,
        description="payment card number (Luhn validated)",
    ),
    Rule(
        "us_ssn",
        "pii",
        "high",
        _r(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        needles=("-",),
        description="US social security number",
    ),
    Rule(
        "email",
        "pii",
        "medium",
        _r(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,24}\b"),
        needles=("@",),
        validator=_email_ok,
        description="e-mail address",
    ),
)

IPV4_RULE = Rule(
    "ipv4",
    "pii",
    "low",
    _r(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    description="IPv4 address (opt-in)",
)


# --------------------------------------------------------------------------- #
# Redactor
# --------------------------------------------------------------------------- #

_Span = Tuple[int, int, Rule]
_NEWLINE_RE = re.compile("\n")


class Redactor:
    """Configurable redaction engine.

    Parameters
    ----------
    include_pii:
        Also redact personal data (e-mails, card numbers, SSNs).
    redact_ips:
        Redact IPv4 addresses (off by default: pod IPs are useful for triage).
    fingerprint_salt:
        When set, each token carries a short keyed hash (``[REDACTED:jwt#1a2b3c4d]``)
        so identical secrets can be correlated without being revealed.
    extra_rules:
        Additional :class:`Rule` objects, evaluated after the built-in ones.
    """

    def __init__(
        self,
        include_pii: bool = True,
        redact_ips: bool = False,
        fingerprint_salt: Optional[str] = None,
        extra_rules: Iterable[Rule] = (),
        rules: Optional[Sequence[Rule]] = None,
    ) -> None:
        base = list(rules) if rules is not None else list(DEFAULT_RULES)
        if not include_pii:
            base = [r for r in base if r.category != "pii"]
        if redact_ips:
            base.append(IPV4_RULE)
        base.extend(extra_rules)
        self.rules: Tuple[Rule, ...] = tuple(base)
        self.include_pii = include_pii
        self._salt = fingerprint_salt.encode("utf-8") if fingerprint_salt else None
        self._ci_patterns: Dict[int, Pattern[str]] = {}

    def _ci_pattern(self, rule: Rule) -> Pattern[str]:
        pat = self._ci_patterns.get(id(rule))
        if pat is None:
            pat = re.compile(rule.pattern.pattern, rule.pattern.flags | re.IGNORECASE)
            self._ci_patterns[id(rule)] = pat
        return pat

    # -- token formatting --------------------------------------------------- #
    def _token(self, rule: Rule, secret: str) -> Tuple[str, Optional[str]]:
        if self._salt is None:
            return f"{TOKEN_PREFIX}:{rule.name}]", None
        fp = hmac.new(self._salt, secret.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:8]
        return f"{TOKEN_PREFIX}:{rule.name}#{fp}]", fp

    # -- span discovery ----------------------------------------------------- #
    def _candidate_spans(self, text: str) -> List[_Span]:
        lowered: Optional[str] = None
        # The structural Kubernetes-Secret pass is the most precise, so it claims
        # its spans first; regex rules then fill the gaps in priority order.
        accepted: List[Tuple[int, int, Rule]] = sorted(self._secret_manifest_spans(text, []), key=lambda s: s[0])
        starts: List[int] = [s[0] for s in accepted]
        for rule in self.rules:
            if rule.needles or rule.fold_case:
                if lowered is None:
                    lowered = text.lower()
                if rule.needles and not any(n in lowered for n in rule.needles):
                    continue
            source, pattern = text, rule.pattern
            if rule.fold_case:
                if lowered is not None and len(lowered) == len(text):
                    source = lowered
                else:  # lower() changed offsets (rare Unicode) - fall back
                    pattern = self._ci_pattern(rule)
            for m in pattern.finditer(source):
                try:
                    start, end = m.span(rule.group)
                except IndexError:  # pragma: no cover - misconfigured custom rule
                    start, end = m.span()
                if start < 0 or end <= start:
                    continue
                value = text[start:end]
                # Already redacted, or a value truncated by an existing token
                # (e.g. "URL=postgres://u:[REDACTED:..]@h" on a second pass).
                if value.startswith(TOKEN_PREFIX) or text.startswith(TOKEN_PREFIX, end):
                    continue
                if rule.validator is not None and not rule.validator(value, m):
                    continue
                pos = bisect.bisect_left(starts, start)
                if pos > 0 and accepted[pos - 1][1] > start:
                    continue
                if pos < len(accepted) and accepted[pos][0] < end:
                    continue
                starts.insert(pos, start)
                accepted.insert(pos, (start, end, rule))
        return accepted

    def _secret_manifest_spans(self, text: str, taken: List[_Span]) -> List[_Span]:
        """Structural pass: values under ``data``/``stringData`` of ``kind: Secret``."""
        if "Secret" not in text or "data" not in text.lower():
            return []
        found: List[Tuple[int, int]] = []
        stripped = text.lstrip()
        if stripped[:1] in ("{", "["):
            found = _json_secret_value_spans(text)
        elif re.search(r"(?m)^\s*kind:\s*[\"']?Secret[\"']?\s*$", text):
            found = _yaml_secret_value_spans(text)
        out: List[_Span] = []
        for start, end in found:
            if text[start:end].startswith(TOKEN_PREFIX) or _is_placeholder(text[start:end]):
                continue
            if any(s < end and start < e for s, e, _ in taken) or any(s < end and start < e for s, e, _ in out):
                continue
            out.append((start, end, _K8S_SECRET_RULE))
        return out

    # -- public API --------------------------------------------------------- #
    def redact(self, text: str, source: Optional[str] = None) -> RedactionResult:
        """Redact ``text`` and return the clean text plus an audit trail."""
        if not text:
            return RedactionResult(text="" if text is None else text, findings=[], source=source)
        spans = self._candidate_spans(text)
        if not spans:
            return RedactionResult(text=text, findings=[], source=source)
        newlines = [m.start() for m in _NEWLINE_RE.finditer(text)]
        pieces: List[str] = []
        findings: List[Finding] = []
        cursor = 0
        for start, end, rule in spans:
            secret = text[start:end]
            token, fp = self._token(rule, secret)
            pieces.append(text[cursor:start])
            pieces.append(token)
            cursor = end
            line_idx = bisect.bisect_left(newlines, start)
            line_start = newlines[line_idx - 1] + 1 if line_idx > 0 else 0
            findings.append(
                Finding(
                    rule=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    line=line_idx + 1,
                    column=start - line_start + 1,
                    length=end - start,
                    fingerprint=fp,
                )
            )
        pieces.append(text[cursor:])
        return RedactionResult(text="".join(pieces), findings=findings, source=source)

    __call__ = redact

    def scan(self, text: str) -> List[Finding]:
        """Detect secrets without producing redacted text."""
        return self.redact(text).findings

    def contains_secrets(self, text: str) -> bool:
        return bool(text) and bool(self._candidate_spans(text))

    def redact_obj(self, obj: Any) -> Tuple[Any, int]:
        """Recursively redact a JSON-like structure.

        Besides scanning every string, values of secret-named keys, Kubernetes
        env entries (``{"name": "DB_PASSWORD", "value": ...}``) and the
        ``data``/``stringData`` of ``kind: Secret`` objects are always masked.
        Returns ``(clean_copy, redaction_count)``.
        """
        counter = [0]
        clean = self._redact_node(obj, counter, parent_key=None)
        return clean, counter[0]

    def _mask(self, rule_name: str, counter: List[int]) -> str:
        counter[0] += 1
        return f"{TOKEN_PREFIX}:{rule_name}]"

    def _redact_node(self, node: Any, counter: List[int], parent_key: Optional[str]) -> Any:
        if isinstance(node, str):
            result = self.redact(node)
            counter[0] += result.count
            return result.text
        if isinstance(node, list):
            return [self._redact_node(v, counter, parent_key) for v in node]
        if not isinstance(node, dict):
            return node
        is_secret_obj = node.get("kind") == "Secret"
        env_secret = (
            isinstance(node.get("name"), str)
            and "value" in node
            and is_secret_key(node["name"])
            and isinstance(node.get("value"), (str, int, float))
            and not _is_placeholder(str(node.get("value")))
        )
        out: Dict[str, Any] = {}
        for key, value in node.items():
            skey = str(key)
            if is_secret_obj and skey in ("data", "stringData") and isinstance(value, dict):
                out[key] = {
                    k: (
                        self._mask("k8s_secret_data", counter)
                        if v not in (None, "") and not str(v).startswith(TOKEN_PREFIX)
                        else v
                    )
                    for k, v in value.items()
                }
            elif env_secret and skey == "value":
                out[key] = self._mask("k8s_env_secret", counter)
            elif (
                isinstance(value, (str, int, float))
                and not isinstance(value, bool)
                and is_secret_key(skey)
                and not _is_placeholder(str(value))
                and not (isinstance(value, int) and abs(value) < 100000)
                and not str(value).startswith(TOKEN_PREFIX)
            ):
                out[key] = self._mask("secret_field", counter)
            else:
                out[key] = self._redact_node(value, counter, skey)
        return out


_K8S_SECRET_RULE = Rule(
    "k8s_secret_data",
    "secret",
    "critical",
    re.compile(r"(?!x)x"),
    description="value stored in a Kubernetes Secret manifest",
)

#: rule name -> category ("secret" | "pii"), for every built-in rule
RULE_CATEGORY: Dict[str, str] = {r.name: r.category for r in (*DEFAULT_RULES, IPV4_RULE, _K8S_SECRET_RULE)}
RULE_CATEGORY.update({"secret_field": "secret"})


def _json_secret_value_spans(text: str) -> List[Tuple[int, int]]:
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return []
    values: List[Tuple[str, str]] = []

    # Iterative walk: deeply nested hostile JSON must not exhaust the stack.
    stack: List[Any] = [data]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if node.get("kind") == "Secret":
                for section in ("data", "stringData"):
                    block = node.get(section)
                    if isinstance(block, dict):
                        for k, v in block.items():
                            if isinstance(v, str) and v:
                                values.append((str(k), v))
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    spans: List[Tuple[int, int]] = []
    for key, value in values:
        for ascii_only in (False, True):  # the file may use \uXXXX escapes
            encoded_key = json.dumps(key, ensure_ascii=ascii_only)
            encoded_val = json.dumps(value, ensure_ascii=ascii_only)[1:-1]
            pat = re.compile(re.escape(encoded_key) + r"\s*:\s*\"(" + re.escape(encoded_val) + r")\"")
            hits = [m.span(1) for m in pat.finditer(text)]
            if hits:
                spans.extend(hits)
                break
    return sorted(set(spans))


def _yaml_secret_value_spans(text: str) -> List[Tuple[int, int]]:
    from . import yaml_lite  # local import keeps module import cheap

    try:
        docs = yaml_lite.parse_documents(text)
    except Exception:  # a firewall must never crash on hostile input
        return []
    lines = text.split("\n")
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line) + 1)
    spans: List[Tuple[int, int]] = []
    for doc in docs:
        if not isinstance(doc.data, dict) or doc.data.get("kind") != "Secret":
            continue
        for section in ("data", "stringData"):
            block = doc.data.get(section)
            if not isinstance(block, dict):
                continue
            for key in block:
                span = doc.spans.get((section, key))
                if span is None:
                    continue
                line = lines[span.line].rstrip("\r")
                code = yaml_lite.strip_comment(line[span.col :])
                kr = yaml_lite.find_key(code.rstrip())
                if kr is None:
                    continue
                _, rest, colon = kr
                value_text = rest.strip()
                if value_text and value_text[0] not in "|>":
                    vstart = span.col + colon + 1 + (len(rest) - len(rest.lstrip()))
                    vend = vstart + len(value_text)
                    if value_text[0] in "\"'" and len(value_text) >= 2:
                        vstart, vend = vstart + 1, vend - 1
                    spans.append((offsets[span.line] + vstart, offsets[span.line] + vend))
                elif span.end > span.line:  # block scalar body
                    first = offsets[span.line + 1]
                    body_first_line = lines[span.line + 1]
                    first += len(body_first_line) - len(body_first_line.lstrip())
                    last = offsets[span.end] + len(lines[span.end].rstrip("\r"))
                    spans.append((first, last))
    return spans


# --------------------------------------------------------------------------- #
# Module-level convenience API
# --------------------------------------------------------------------------- #

_DEFAULT: Optional[Redactor] = None


def default_redactor() -> Redactor:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = Redactor()
    return _DEFAULT


def redact(text: str, source: Optional[str] = None, **kwargs: Any) -> RedactionResult:
    """Redact ``text`` with the default rules (or a custom configuration)."""
    engine = Redactor(**kwargs) if kwargs else default_redactor()
    return engine.redact(text, source=source)


def redact_text(text: str) -> str:
    """Shorthand returning only the clean text."""
    return default_redactor().redact(text).text


def scan(text: str) -> List[Finding]:
    return default_redactor().scan(text)
