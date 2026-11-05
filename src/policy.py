"""Zero-Trust RBAC & command policy engine.

Every ``kubectl`` / ``oc`` / ``docker`` / ``podman`` / ``helm`` command that
KubeGuard suggests - or that an AI agent wants to run - is classified into one
of three verdicts:

``SAFE_READ``
    Read-only and non-sensitive.  May run without a human in the loop.
``APPROVAL_REQUIRED``
    Mutates state, opens an interactive channel (``exec``/``port-forward``) or
    reads sensitive material (``get secret -o yaml``).  Needs explicit approval.
``BLOCKED_DESTRUCTIVE``
    Irreversible, bulk, privilege-escalating or shell-injected.  Never executed
    on an agent's behalf; only an ``admin`` with a written break-glass reason can
    override it.

The engine is *default-deny*: unknown binaries are blocked, unknown verbs need
approval, and anything that is not a single plain command (pipes, ``;``,
``&&``, ``$(...)``, redirections) is blocked outright.

It also ships :func:`analyze_rbac`, a static analyser for Kubernetes
``Role``/``ClusterRole``/``*RoleBinding`` objects that flags wildcard grants,
secret readers, exec rights, escalation verbs and cluster-admin bindings.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

__all__ = [
    "DEFAULT_PROTECTED_NAMESPACES",
    "ROLES",
    "Authorization",
    "PolicyDecision",
    "PolicyEngine",
    "RbacFinding",
    "Verdict",
    "analyze_rbac",
    "classify",
]


class Verdict(str, Enum):
    SAFE_READ = "SAFE_READ"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    BLOCKED_DESTRUCTIVE = "BLOCKED_DESTRUCTIVE"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {Verdict.SAFE_READ: 0, Verdict.APPROVAL_REQUIRED: 1, Verdict.BLOCKED_DESTRUCTIVE: 2}

DEFAULT_PROTECTED_NAMESPACES: Tuple[str, ...] = ("kube-system", "kube-public", "kube-node-lease")
ROLES = ("viewer", "operator", "admin")


@dataclass
class PolicyDecision:
    command: str
    verdict: Verdict
    tool: Optional[str] = None
    verb: Optional[str] = None
    resources: List[str] = field(default_factory=list)
    namespace: Optional[str] = None
    reasons: List[str] = field(default_factory=list)
    rule_ids: List[str] = field(default_factory=list)
    risk_score: int = 0

    @property
    def requires_approval(self) -> bool:
        return self.verdict is not Verdict.SAFE_READ

    @property
    def blocked(self) -> bool:
        return self.verdict is Verdict.BLOCKED_DESTRUCTIVE

    @property
    def reason(self) -> str:
        return self.reasons[0] if self.reasons else ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "verdict": self.verdict.value,
            "tool": self.tool,
            "verb": self.verb,
            "resources": list(self.resources),
            "namespace": self.namespace,
            "risk_score": self.risk_score,
            "reasons": list(self.reasons),
            "rule_ids": list(self.rule_ids),
        }


@dataclass
class Authorization:
    allowed: bool
    decision: PolicyDecision
    reason: str
    role: str
    break_glass: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "role": self.role,
            "reason": self.reason,
            "break_glass": self.break_glass,
            "decision": self.decision.to_dict(),
        }


class _Builder:
    """Accumulates findings; the strongest verdict wins."""

    def __init__(self, command: str) -> None:
        self.d = PolicyDecision(command=command, verdict=Verdict.SAFE_READ)

    def hit(self, verdict: Verdict, rule_id: str, reason: str, risk: int) -> None:
        if verdict.rank > self.d.verdict.rank:
            self.d.verdict = verdict
        if rule_id not in self.d.rule_ids:
            self.d.rule_ids.append(rule_id)
            self.d.reasons.append(reason)
        self.d.risk_score = max(self.d.risk_score, risk)

    def done(self) -> PolicyDecision:
        floor = {Verdict.SAFE_READ: 0, Verdict.APPROVAL_REQUIRED: 40, Verdict.BLOCKED_DESTRUCTIVE: 80}
        self.d.risk_score = min(100, max(self.d.risk_score, floor[self.d.verdict]))
        if not self.d.reasons:
            self.d.reasons.append("read-only command")
            self.d.rule_ids.append("KGP-READ")
        return self.d


# --------------------------------------------------------------------------- #
# Tokenisation & shell safety
# --------------------------------------------------------------------------- #

_SHELL_OPERATORS = {";", "&&", "||", "|", "&", ">", ">>", "<", "<<", "|&", ">&", "<&", "(", ")", ";;"}
_DANGEROUS_BINARIES = {
    "rm", "dd", "mkfs", "shred", "shutdown", "reboot", "halt", "poweroff", "kill", "killall", "pkill",
    "chmod", "chown", "iptables", "nft", "systemctl", "curl", "wget", "nc", "ncat", "bash", "sh", "zsh",
    "python", "python3", "perl", "eval", "sudo", "su", "mv", "truncate", "wipefs", "fdisk", "parted",
}  # fmt: skip
_TOOL_ALIASES = {
    "kubectl": "kubectl",
    "oc": "kubectl",
    "k": "kubectl",
    "microk8s.kubectl": "kubectl",
    "docker": "docker",
    "podman": "docker",
    "nerdctl": "docker",
    "docker-compose": "docker-compose",
    "helm": "helm",
}


def _tokenize(command: str) -> Tuple[Optional[List[str]], Optional[str]]:
    """Return (tokens, error).  ``error`` is set for unsafe/unparseable input."""
    if "\n" in command or "\r" in command:
        return None, "multi-line input (command chaining) is not allowed"
    if "`" in command or "$(" in command:
        return None, "command substitution ($(...) or backticks) is not allowed"
    if "<(" in command or ">(" in command:
        return None, "process substitution is not allowed"
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        lex.commenters = ""
        tokens = list(lex)
    except ValueError as exc:
        return None, f"unparseable command ({exc})"
    for tok in tokens:
        if tok in _SHELL_OPERATORS or (tok and set(tok) <= set(";&|<>()")):
            return None, f"shell operator {tok!r} (pipes, chaining, redirection) is not allowed; submit one command"
    return tokens, None


def _strip_prefixes(tokens: List[str]) -> Tuple[List[str], List[str]]:
    """Drop ``sudo``/``env``/``VAR=value`` prefixes; return (rest, notes)."""
    notes: List[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("sudo", "doas"):
            notes.append("sudo")
            i += 1
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 1
            continue
        if tok == "env":
            i += 1
            continue
        if "=" in tok and not tok.startswith("-") and tok.split("=", 1)[0].replace("_", "").isalnum():
            name = tok.split("=", 1)[0]
            notes.append(f"env:{name}")
            i += 1
            continue
        break
    return tokens[i:], notes


def _basename(binary: str) -> str:
    name = binary.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for ext in (".exe", ".cmd", ".bat"):
        if name.endswith(ext):
            name = name[: -len(ext)]
    return name


@dataclass
class _Parsed:
    positionals: List[str]
    flags: Dict[str, List[str]]
    after_dashdash: List[str]

    def has(self, *names: str) -> bool:
        return any(n in self.flags for n in names)

    def get(self, *names: str) -> Optional[str]:
        for n in names:
            vals = self.flags.get(n)
            if vals:
                return vals[-1]
        return None


def _parse_args(args: Sequence[str], value_flags: Iterable[str], short_value: str = "") -> _Parsed:
    value_flags = set(value_flags)
    positionals: List[str] = []
    flags: Dict[str, List[str]] = {}
    rest: List[str] = []
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            rest = list(args[i + 1 :])
            break
        if tok.startswith("--"):
            if "=" in tok:
                name, val = tok.split("=", 1)
                flags.setdefault(name, []).append(val)
            elif tok in value_flags and i + 1 < len(args):
                flags.setdefault(tok, []).append(args[i + 1])
                i += 1
            else:
                flags.setdefault(tok, []).append("true")
        elif tok.startswith("-") and len(tok) > 1 and not tok[1:].isdigit():
            name = tok[:2]
            if "=" in tok and len(tok) > 3 and tok[2] == "=":
                flags.setdefault(name, []).append(tok[3:])
            elif name in value_flags:
                if len(tok) > 2:
                    flags.setdefault(name, []).append(tok[2:])
                elif i + 1 < len(args):
                    flags.setdefault(name, []).append(args[i + 1])
                    i += 1
                else:
                    flags.setdefault(name, []).append("")
            else:
                # combined boolean short flags (-it); the last may take a value
                for j, ch in enumerate(tok[1:], start=1):
                    short = "-" + ch
                    if short in value_flags:
                        val = tok[j + 1 :] or (args[i + 1] if i + 1 < len(args) else "")
                        if not tok[j + 1 :]:
                            i += 1
                        flags.setdefault(short, []).append(val)
                        break
                    flags.setdefault(short, []).append("true")
        else:
            positionals.append(tok)
        i += 1
    return _Parsed(positionals, flags, rest)


# --------------------------------------------------------------------------- #
# kubectl
# --------------------------------------------------------------------------- #

_KUBECTL_VALUE_FLAGS = {
    "-n", "--namespace", "--context", "--cluster", "--user", "--kubeconfig", "-s", "--server", "--token",
    "--as", "--as-group", "--as-uid", "--request-timeout", "--certificate-authority", "--client-certificate",
    "--client-key", "--tls-server-name", "-v", "--v", "--log-file", "--cache-dir", "--profile",
    "-o", "--output", "-l", "--selector", "-f", "--filename", "-c", "--container", "--field-selector",
    "--grace-period", "--timeout", "--tail", "--since", "--since-time", "--replicas", "--image", "--type",
    "--from-literal", "--from-file", "--from-env-file", "-p", "--patch", "--template", "--sort-by",
    "--chunk-size", "-k", "--kustomize", "--port", "--target-port", "--address", "--accept-hosts",
    "--clusterrole", "--role", "--serviceaccount", "--group", "--overrides", "--env", "--limits",
    "--requests", "--current-replicas", "--resource-version", "--min", "--max", "--cpu-percent", "--to-revision",
    "--prune-allowlist", "--field-manager", "--subresource", "--duration", "--docker-server", "--docker-username",
    "--docker-password", "--docker-email", "--cert", "--key", "--profile-name", "--target", "--copy-to",
    "--share-processes", "--pod-running-timeout", "--for", "--raw", "--local-ssd-count", "--attach",
}  # fmt: skip

_KUBECTL_KIND_ALIASES = {
    "po": "pod", "pods": "pod", "pod": "pod",
    "deploy": "deployment", "deployments": "deployment", "deployment": "deployment",
    "svc": "service", "services": "service", "service": "service",
    "ns": "namespace", "namespaces": "namespace", "namespace": "namespace",
    "no": "node", "nodes": "node", "node": "node",
    "pv": "persistentvolume", "persistentvolumes": "persistentvolume", "persistentvolume": "persistentvolume",
    "pvc": "persistentvolumeclaim", "persistentvolumeclaims": "persistentvolumeclaim",
    "persistentvolumeclaim": "persistentvolumeclaim",
    "crd": "customresourcedefinition", "crds": "customresourcedefinition",
    "customresourcedefinitions": "customresourcedefinition", "customresourcedefinition": "customresourcedefinition",
    "secret": "secret", "secrets": "secret",
    "cm": "configmap", "configmaps": "configmap", "configmap": "configmap",
    "sa": "serviceaccount", "serviceaccounts": "serviceaccount", "serviceaccount": "serviceaccount",
    "sts": "statefulset", "statefulsets": "statefulset", "statefulset": "statefulset",
    "ds": "daemonset", "daemonsets": "daemonset", "daemonset": "daemonset",
    "rs": "replicaset", "replicasets": "replicaset", "replicaset": "replicaset",
    "job": "job", "jobs": "job", "cj": "cronjob", "cronjob": "cronjob", "cronjobs": "cronjob",
    "ing": "ingress", "ingress": "ingress", "ingresses": "ingress",
    "sc": "storageclass", "storageclass": "storageclass", "storageclasses": "storageclass",
    "clusterrole": "clusterrole", "clusterroles": "clusterrole",
    "clusterrolebinding": "clusterrolebinding", "clusterrolebindings": "clusterrolebinding",
    "role": "role", "roles": "role", "rolebinding": "rolebinding", "rolebindings": "rolebinding",
    "netpol": "networkpolicy", "networkpolicy": "networkpolicy", "networkpolicies": "networkpolicy",
    "pdb": "poddisruptionbudget", "poddisruptionbudget": "poddisruptionbudget",
    "poddisruptionbudgets": "poddisruptionbudget",
    "hpa": "horizontalpodautoscaler", "horizontalpodautoscaler": "horizontalpodautoscaler",
    "horizontalpodautoscalers": "horizontalpodautoscaler",
    "ev": "event", "events": "event", "event": "event",
    "ep": "endpoints", "endpoints": "endpoints",
    "mutatingwebhookconfiguration": "mutatingwebhookconfiguration",
    "mutatingwebhookconfigurations": "mutatingwebhookconfiguration",
    "validatingwebhookconfiguration": "validatingwebhookconfiguration",
    "validatingwebhookconfigurations": "validatingwebhookconfiguration",
    "apiservice": "apiservice", "apiservices": "apiservice",
    "csr": "certificatesigningrequest", "certificatesigningrequest": "certificatesigningrequest",
    "certificatesigningrequests": "certificatesigningrequest",
    "all": "all",
}  # fmt: skip

_KUBECTL_SAFE_VERBS = {
    "get", "describe", "logs", "top", "explain", "api-resources", "api-versions", "version", "events",
    "diff", "wait", "completion", "options", "kustomize", "help",
}  # fmt: skip
_KUBECTL_MUTATING_VERBS = {
    "apply", "create", "edit", "patch", "replace", "scale", "autoscale", "set", "label", "annotate", "rollout",
    "cordon", "uncordon", "taint", "expose", "run", "exec", "cp", "port-forward", "attach", "proxy", "debug",
    "config", "certificate", "delete", "drain", "auth", "cluster-info", "plugin", "alpha",
}  # fmt: skip
_BLOCKED_DELETE_KINDS = {
    "namespace", "node", "persistentvolume", "persistentvolumeclaim", "customresourcedefinition", "storageclass",
    "clusterrole", "clusterrolebinding", "mutatingwebhookconfiguration", "validatingwebhookconfiguration",
    "apiservice", "all",
}  # fmt: skip
_SENSITIVE_OUTPUT = ("yaml", "json", "jsonpath", "go-template", "template", "custom-columns")
_ESCALATED_IDENTITIES = ("system:masters", "system:admin", "cluster-admin", "system:kube-controller-manager")
_DESTRUCTIVE_EXEC = (
    "rm -rf", "rm -fr", "rm -r /", "mkfs", "dd if=", "shred", ":(){", "shutdown", "reboot", "halt", "poweroff",
    "kill -9 1", "kill 1", "pkill", "killall", "chmod -r 777 /", "> /dev/sd", "truncate -s 0", "wipefs",
    "drop database", "drop table", "flushall", "flushdb",
)  # fmt: skip


def _kinds(token: str) -> List[Tuple[str, Optional[str]]]:
    """``deploy/foo`` -> [("deployment", "foo")]; ``po,svc`` -> two kinds."""
    out: List[Tuple[str, Optional[str]]] = []
    for part in token.split(","):
        name: Optional[str] = None
        if "/" in part:
            part, name = part.split("/", 1)
        base = part.split(".", 1)[0].lower()
        out.append((_KUBECTL_KIND_ALIASES.get(base, base), name))
    return out


class PolicyEngine:
    """Classify and authorise infrastructure commands.

    ``role`` controls :meth:`authorize`:

    * ``viewer``   - only ``SAFE_READ``.
    * ``operator`` - ``SAFE_READ``; ``APPROVAL_REQUIRED`` once approved.
    * ``admin``    - like operator; ``BLOCKED_DESTRUCTIVE`` only with approval
      *and* a written break-glass justification.
    """

    def __init__(
        self,
        role: str = "operator",
        protected_namespaces: Iterable[str] = DEFAULT_PROTECTED_NAMESPACES,
    ) -> None:
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}; expected one of {', '.join(ROLES)}")
        self.role = role
        self.protected_namespaces = tuple(protected_namespaces)

    # ------------------------------------------------------------------ #
    def classify(self, command: Union[str, Sequence[str]]) -> PolicyDecision:
        if isinstance(command, (list, tuple)):
            raw = " ".join(shlex.quote(str(c)) for c in command)
        else:
            raw = str(command).strip()
        b = _Builder(raw)
        if not raw:
            b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-EMPTY", "empty command", 80)
            return b.done()
        tokens, error = _tokenize(raw)
        if tokens is None:
            b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-SHELL", error or "unsafe shell syntax", 95)
            return b.done()
        tokens, notes = _strip_prefixes(tokens)
        if "sudo" in notes:
            b.hit(Verdict.APPROVAL_REQUIRED, "KGP-SUDO", "runs with elevated host privileges (sudo)", 60)
        if any(n.split(":", 1)[1].upper() in ("KUBECONFIG",) for n in notes if n.startswith("env:")):
            b.hit(Verdict.SAFE_READ, "KGP-KUBECONFIG", "overrides KUBECONFIG for this command", 10)
        if not tokens:
            b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-EMPTY", "no command after prefixes", 80)
            return b.done()
        binary = _basename(tokens[0])
        tool = _TOOL_ALIASES.get(binary)
        b.d.tool = tool or binary
        if tool is None:
            if binary in _DANGEROUS_BINARIES or binary.startswith("mkfs"):
                b.hit(
                    Verdict.BLOCKED_DESTRUCTIVE, "KGP-BIN-DANGER", f"'{binary}' is a host-level destructive tool", 100
                )
            else:
                b.hit(
                    Verdict.BLOCKED_DESTRUCTIVE,
                    "KGP-BIN-DENY",
                    f"'{binary}' is not on the allowlist (kubectl/oc/docker/podman/helm); default-deny",
                    85,
                )
            return b.done()
        args = tokens[1:]
        if tool == "kubectl":
            self._kubectl(args, b)
        elif tool == "helm":
            self._helm(args, b)
        elif tool == "docker-compose":
            self._docker(["compose"] + args, b)
        else:
            self._docker(args, b)
        return b.done()

    def authorize(
        self,
        command: Union[str, Sequence[str]],
        approved: bool = False,
        break_glass_reason: Optional[str] = None,
    ) -> Authorization:
        d = self.classify(command)
        if d.verdict is Verdict.SAFE_READ:
            return Authorization(True, d, "read-only command auto-approved", self.role)
        if d.verdict is Verdict.APPROVAL_REQUIRED:
            if self.role == "viewer":
                return Authorization(False, d, "viewer role may only run SAFE_READ commands", self.role)
            if approved:
                return Authorization(True, d, "approved by a human operator", self.role)
            return Authorization(False, d, "human approval required", self.role)
        if self.role == "admin" and approved and break_glass_reason and break_glass_reason.strip():
            return Authorization(True, d, f"BREAK-GLASS: {break_glass_reason.strip()}", self.role, break_glass=True)
        return Authorization(False, d, "blocked by zero-trust policy (destructive or privilege escalation)", self.role)

    # ------------------------------------------------------------------ #
    def _check_namespace(self, ns: Optional[str], mutating: bool, b: _Builder) -> None:
        if ns and mutating and ns in self.protected_namespaces:
            b.hit(
                Verdict.BLOCKED_DESTRUCTIVE,
                "KGP-PROTECTED-NS",
                f"mutating the protected namespace '{ns}' is blocked",
                90,
            )

    def _kubectl(self, args: List[str], b: _Builder) -> None:
        p = _parse_args(args, _KUBECTL_VALUE_FLAGS)
        ns = p.get("-n", "--namespace")
        all_ns = p.has("-A", "--all-namespaces")
        b.d.namespace = "*" if all_ns else ns
        if p.has("--token"):
            b.hit(
                Verdict.APPROVAL_REQUIRED,
                "KGP-TOKEN-FLAG",
                "bearer token passed on the command line (leaks into shell history/process list)",
                55,
            )
        for ident_flag in ("--as", "--as-group"):
            ident = p.get(ident_flag)
            if ident:
                if any(x in ident for x in _ESCALATED_IDENTITIES):
                    b.hit(
                        Verdict.BLOCKED_DESTRUCTIVE, "KGP-IMPERSONATE", f"impersonates privileged identity {ident}", 95
                    )
                else:
                    b.hit(Verdict.APPROVAL_REQUIRED, "KGP-IMPERSONATE", f"impersonates {ident}", 60)
        if not p.positionals:
            b.hit(Verdict.SAFE_READ, "KGP-HELP", "prints kubectl help", 0)
            return
        verb = p.positionals[0].lower()
        b.d.verb = verb
        rest = p.positionals[1:]
        kinds: List[Tuple[str, Optional[str]]] = []
        if rest and verb not in ("config", "rollout", "auth", "set", "certificate", "exec", "logs", "cp", "run"):
            kinds = _kinds(rest[0])
        elif verb in ("rollout", "set") and len(rest) > 1:
            kinds = _kinds(rest[1])
        b.d.resources = [k + (f"/{n}" if n else "") for k, n in kinds]
        names = [n for _, n in kinds if n] + [r for r in rest[1:] if verb not in ("rollout", "set")]

        if verb in _KUBECTL_SAFE_VERBS:
            if verb == "get" and any(k == "secret" for k, _ in kinds):
                out = (p.get("-o", "--output") or "").split("=", 1)[0].lower()
                if out.startswith(_SENSITIVE_OUTPUT):
                    b.hit(
                        Verdict.APPROVAL_REQUIRED,
                        "KGP-SECRET-READ",
                        "reads Secret values (-o yaml/json/jsonpath decodes credentials)",
                        65,
                    )
                else:
                    b.hit(Verdict.SAFE_READ, "KGP-SECRET-LIST", "lists Secret names only (no values)", 10)
            elif verb == "diff":
                b.hit(Verdict.SAFE_READ, "KGP-READ", "server-side dry-run diff (read-only)", 5)
            elif verb == "get" and p.get("--raw"):
                b.hit(Verdict.SAFE_READ, "KGP-READ", "raw API read", 15)
            return

        if verb not in _KUBECTL_MUTATING_VERBS:
            b.hit(
                Verdict.APPROVAL_REQUIRED, "KGP-UNKNOWN-VERB", f"unrecognised kubectl verb '{verb}'; human review", 50
            )
            return

        sub = rest[0].lower() if rest else ""
        if verb == "config":
            if sub in ("view",) and not p.has("--raw", "--flatten"):
                b.hit(Verdict.SAFE_READ, "KGP-READ", "views kubeconfig (credentials redacted by kubectl)", 5)
            elif sub in ("view",):
                b.hit(Verdict.APPROVAL_REQUIRED, "KGP-KUBECONFIG-RAW", "--raw/--flatten prints cluster credentials", 70)
            elif sub in ("get-contexts", "current-context", "get-clusters", "get-users"):
                b.hit(Verdict.SAFE_READ, "KGP-READ", "reads kubeconfig metadata", 0)
            else:
                b.hit(Verdict.APPROVAL_REQUIRED, "KGP-KUBECONFIG", f"modifies kubeconfig ({sub or 'config'})", 45)
            return
        if verb == "auth":
            if sub in ("can-i", "whoami"):
                b.hit(Verdict.SAFE_READ, "KGP-READ", "RBAC self-check (read-only)", 0)
            else:
                b.hit(Verdict.APPROVAL_REQUIRED, "KGP-RBAC-WRITE", f"auth {sub} modifies RBAC objects", 70)
            return
        if verb == "cluster-info":
            if sub == "dump":
                b.hit(Verdict.APPROVAL_REQUIRED, "KGP-DUMP", "cluster-info dump exports logs and objects in bulk", 45)
            else:
                b.hit(Verdict.SAFE_READ, "KGP-READ", "prints control-plane endpoints", 0)
            return
        if verb in ("plugin", "alpha"):
            if sub == "list":
                b.hit(Verdict.SAFE_READ, "KGP-READ", "lists plugins", 0)
            else:
                b.hit(Verdict.APPROVAL_REQUIRED, "KGP-UNKNOWN-VERB", f"kubectl {verb} {sub}; human review", 50)
            return
        if verb == "rollout":
            if sub in ("status", "history"):
                b.hit(Verdict.SAFE_READ, "KGP-READ", f"rollout {sub} is read-only", 0)
                return
            b.hit(Verdict.APPROVAL_REQUIRED, "KGP-ROLLOUT", f"rollout {sub or '?'} changes a live workload", 50)
            self._check_namespace(ns, True, b)
            return

        # ---- every remaining verb mutates state ----
        self._check_namespace(ns, True, b)
        if all_ns and verb not in ("get",):
            b.hit(
                Verdict.BLOCKED_DESTRUCTIVE,
                "KGP-ALL-NS",
                f"'{verb}' across all namespaces has cluster-wide blast radius",
                95,
            )

        if verb == "delete":
            self._kubectl_delete(p, kinds, names, b)
            return
        if verb == "drain":
            b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-DRAIN", "drain evicts every pod on the node", 90)
            return
        if verb == "taint":
            if any("NoExecute" in r for r in rest):
                b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-TAINT-EVICT", "NoExecute taint evicts running pods", 90)
            else:
                b.hit(Verdict.APPROVAL_REQUIRED, "KGP-TAINT", "changes node scheduling constraints", 55)
            return
        if verb in ("replace", "apply") and p.has("--force"):
            b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-FORCE", f"{verb} --force deletes and recreates objects", 90)
            return
        if verb == "apply" and p.has("--prune"):
            b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-PRUNE", "apply --prune deletes objects missing from manifests", 90)
            return
        if verb == "create" and sub in ("clusterrolebinding", "rolebinding"):
            role = (p.get("--clusterrole") or p.get("--role") or "").lower()
            if role in ("cluster-admin", "admin", "system:masters"):
                b.hit(
                    Verdict.BLOCKED_DESTRUCTIVE,
                    "KGP-ESCALATE",
                    f"grants '{role}' via {sub} (privilege escalation)",
                    100,
                )
                return
            b.hit(Verdict.APPROVAL_REQUIRED, "KGP-RBAC-WRITE", f"creates a {sub}", 65)
            return
        if verb == "create" and sub == "token":
            b.hit(Verdict.APPROVAL_REQUIRED, "KGP-MINT-TOKEN", "mints a service-account bearer token", 70)
            return
        if verb == "certificate":
            b.hit(Verdict.APPROVAL_REQUIRED, "KGP-CSR", f"certificate {sub}: CSR decisions can mint credentials", 75)
            return
        if verb == "debug":
            target = rest[0] if rest else ""
            if target.startswith(("node/", "nodes/", "no/")) or p.get("--profile") in ("sysadmin",):
                b.hit(
                    Verdict.BLOCKED_DESTRUCTIVE,
                    "KGP-NODE-ROOT",
                    "node debugging grants root on the host filesystem",
                    90,
                )
            else:
                b.hit(Verdict.APPROVAL_REQUIRED, "KGP-DEBUG", "starts an ephemeral debug container", 55)
            return
        if verb == "exec" or verb == "attach":
            inner = " ".join(p.after_dashdash).lower()
            if any(pat in inner for pat in _DESTRUCTIVE_EXEC):
                b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-EXEC-DESTRUCT", "destructive command inside the container", 95)
            elif p.has("-i", "--stdin") or p.after_dashdash[:1] in (["sh"], ["bash"], ["/bin/sh"], ["/bin/bash"]):
                b.hit(Verdict.APPROVAL_REQUIRED, "KGP-EXEC-SHELL", "interactive shell inside a running container", 65)
            else:
                b.hit(Verdict.APPROVAL_REQUIRED, "KGP-EXEC", "executes a process inside a running container", 55)
            return
        if verb == "run":
            if p.has("--privileged"):
                b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-PRIVILEGED", "starts a privileged pod", 95)
                return
            b.hit(Verdict.APPROVAL_REQUIRED, "KGP-RUN", "starts a new pod", 50)
            return
        if verb == "proxy" or verb == "port-forward":
            addr = p.get("--address") or ""
            if addr in ("0.0.0.0", "::") and verb == "proxy":  # noqa: S104 - comparing, not binding
                b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-EXPOSE-API", "exposes the API server on all interfaces", 90)
                return
            exposure = " on all interfaces" if addr in ("0.0.0.0", "::") else ""  # noqa: S104
            b.hit(Verdict.APPROVAL_REQUIRED, "KGP-TUNNEL", f"opens a network tunnel into the cluster{exposure}", 55)
            return
        if verb == "scale":
            replicas = p.get("--replicas")
            if replicas is not None and replicas.strip() == "0":
                b.hit(Verdict.APPROVAL_REQUIRED, "KGP-SCALE-ZERO", "scales the workload to zero (full outage)", 75)
                return
            b.hit(Verdict.APPROVAL_REQUIRED, "KGP-SCALE", "changes replica count", 45)
            return
        if verb == "cp":
            b.hit(Verdict.APPROVAL_REQUIRED, "KGP-CP", "copies files to/from a container", 55)
            return
        b.hit(Verdict.APPROVAL_REQUIRED, "KGP-MUTATE", f"'{verb}' changes cluster state", 45)

    def _kubectl_delete(
        self,
        p: _Parsed,
        kinds: List[Tuple[str, Optional[str]]],
        names: List[str],
        b: _Builder,
    ) -> None:
        if p.has("--all"):
            b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-BULK-DELETE", "delete --all removes every matching object", 100)
        if p.has("-l", "--selector", "--field-selector"):
            b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-BULK-DELETE", "label/field-selector delete is a bulk operation", 95)
        if p.has("-f", "--filename", "-k", "--kustomize"):
            b.hit(
                Verdict.BLOCKED_DESTRUCTIVE,
                "KGP-BULK-DELETE",
                "delete from manifest/kustomization has unknown blast radius",
                90,
            )
        if p.has("--force") or (p.get("--grace-period") or "").strip() == "0" or p.has("--now"):
            b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-FORCE-DELETE", "force delete skips graceful termination", 90)
        dangerous = sorted({k for k, _ in kinds if k in _BLOCKED_DELETE_KINDS})
        if dangerous:
            b.hit(
                Verdict.BLOCKED_DESTRUCTIVE,
                "KGP-DELETE-KIND",
                f"deleting {', '.join(dangerous)} is irreversible / cluster-scoped",
                100,
            )
        if b.d.verdict is Verdict.BLOCKED_DESTRUCTIVE:
            return
        kind_desc = ", ".join(k for k, _ in kinds) or "resource"
        if kinds and all(k == "pod" for k, _ in kinds):
            b.hit(
                Verdict.APPROVAL_REQUIRED,
                "KGP-DELETE-POD",
                "deletes a named pod (controller will recreate it)",
                50,
            )
        elif names:
            b.hit(Verdict.APPROVAL_REQUIRED, "KGP-DELETE", f"deletes named {kind_desc}", 70)
        else:
            b.hit(Verdict.APPROVAL_REQUIRED, "KGP-DELETE", f"delete {kind_desc} without explicit names", 75)

    # ------------------------------------------------------------------ #
    # docker / podman / compose
    # ------------------------------------------------------------------ #

    _DOCKER_VALUE_FLAGS = {
        "-H", "--host", "--context", "-c", "--config", "-l", "--log-level", "--tlscacert", "--tlscert", "--tlskey",
        "-v", "--volume", "--mount", "-e", "--env", "--env-file", "-p", "--publish", "--name", "--network", "--net",
        "--pid", "--ipc", "--uts", "--userns", "--cap-add", "--cap-drop", "--security-opt", "--device", "-u",
        "--user", "-w", "--workdir", "--entrypoint", "-m", "--memory", "--cpus", "--restart", "--label",
        "-f", "--file", "--filter", "--format", "--tag", "--tail", "--since", "--until", "-n", "--project-name",
        "--profile", "--platform", "--build-arg", "--target", "--signal", "--time", "--hostname",
        "--add-host", "--dns", "--log-driver", "--log-opt", "--gpus", "--runtime", "--volumes-from",
    }  # fmt: skip
    _DOCKER_SAFE = {
        "ps", "images", "logs", "inspect", "version", "info", "stats", "top", "port", "diff", "history", "events",
        "search", "help", "ls", "df", "show", "config", "lsof",
    }  # fmt: skip
    _DOCKER_MGMT = {
        "container", "image", "network", "volume", "system", "compose", "buildx", "builder", "context", "plugin",
        "node", "swarm", "service", "stack", "secret", "config", "trust", "manifest", "scout", "machine",
    }  # fmt: skip
    _DOCKER_APPROVAL = {
        "run", "create", "start", "stop", "restart", "kill", "pause", "unpause", "exec", "cp", "attach", "pull",
        "push", "build", "tag", "commit", "login", "logout", "update", "rename", "rm", "rmi", "connect",
        "disconnect", "up", "down", "use", "load", "save", "import", "export", "wait", "bake", "scale", "watch",
    }  # fmt: skip

    def _docker(self, args: List[str], b: _Builder) -> None:
        p = _parse_args(args, self._DOCKER_VALUE_FLAGS)
        if not p.positionals:
            b.hit(Verdict.SAFE_READ, "KGP-HELP", "prints docker help", 0)
            return
        first = p.positionals[0].lower()
        if first in self._DOCKER_MGMT and len(p.positionals) > 1:
            group, verb = first, p.positionals[1].lower()
        elif first in self._DOCKER_MGMT:
            group, verb = first, "ls"
        else:
            group, verb = "", first
        b.d.verb = f"{group} {verb}".strip()
        target = p.positionals[2:] if group else p.positionals[1:]
        b.d.resources = target[:3]

        if verb == "prune" or (group == "system" and verb == "prune"):
            b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-PRUNE", f"docker {b.d.verb} permanently deletes data", 95)
            return
        if group == "volume" and verb in ("rm", "remove"):
            b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-VOLUME-RM", "removes volumes (data loss)", 95)
            return
        if group in ("swarm",) and verb == "leave" and p.has("-f", "--force"):
            b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-SWARM", "forces the node out of the swarm", 90)
            return
        if group in ("stack", "node", "secret") and verb in ("rm", "remove"):
            b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-DOCKER-RM", f"removes a {group} (irreversible)", 90)
            return
        if group == "compose" and verb == "down" and p.has("-v", "--volumes"):
            b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-VOLUME-RM", "compose down -v deletes named volumes", 95)
            return
        if verb in ("rm",) and p.has("-v", "--volumes") and group in ("", "container"):
            b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-VOLUME-RM", "rm -v also deletes the container's volumes", 85)
            return

        if verb in ("run", "create") or (group == "compose" and verb == "run"):
            self._docker_runtime_flags(p, b)
            if b.d.blocked:
                return

        if group == "compose" and verb in ("ps", "logs", "config", "ls", "images", "top", "version", "port"):
            b.hit(Verdict.SAFE_READ, "KGP-READ", f"compose {verb} is read-only", 0)
            return
        if group == "context" and verb in ("ls", "inspect", "show"):
            b.hit(Verdict.SAFE_READ, "KGP-READ", f"context {verb} is read-only", 0)
            return
        if verb in self._DOCKER_SAFE or (verb in ("inspect", "ls", "list") and group):
            if group == "secret" and verb == "inspect":
                b.hit(Verdict.SAFE_READ, "KGP-READ", "inspects secret metadata", 10)
            return
        if verb == "exec":
            inner = " ".join(target[1:]).lower()
            if any(pat in inner for pat in _DESTRUCTIVE_EXEC):
                b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-EXEC-DESTRUCT", "destructive command inside the container", 95)
                return
            b.hit(Verdict.APPROVAL_REQUIRED, "KGP-EXEC", "executes a process inside a running container", 60)
            return
        if verb in self._DOCKER_APPROVAL or group:
            risk = 45
            if verb in ("rm", "rmi", "kill") and p.has("-f", "--force"):
                risk = 70
            b.hit(Verdict.APPROVAL_REQUIRED, "KGP-MUTATE", f"docker {b.d.verb} changes container/host state", risk)
            return
        b.hit(Verdict.APPROVAL_REQUIRED, "KGP-UNKNOWN-VERB", f"unrecognised docker command '{verb}'; human review", 50)

    def _docker_runtime_flags(self, p: _Parsed, b: _Builder) -> None:
        if p.has("--privileged"):
            b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-PRIVILEGED", "--privileged disables container isolation", 100)
        for flag in ("--pid", "--ipc", "--uts", "--userns"):
            if (p.get(flag) or "").lower() == "host":
                b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-HOST-NS", f"{flag}=host shares a host namespace", 95)
        if (p.get("--network", "--net") or "").lower() == "host":
            b.hit(Verdict.APPROVAL_REQUIRED, "KGP-HOST-NET", "--network=host shares the host network stack", 65)
        for cap in p.flags.get("--cap-add", []):
            if cap.upper().replace("CAP_", "") in ("ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH"):
                b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-CAPS", f"--cap-add={cap} enables container escape", 95)
        for opt in p.flags.get("--security-opt", []):
            if "unconfined" in opt or opt.replace(" ", "") in ("label=disable", "label:disable"):
                b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-SECOPT", f"--security-opt {opt} removes kernel hardening", 90)
        if p.flags.get("--device"):
            b.hit(Verdict.APPROVAL_REQUIRED, "KGP-DEVICE", "maps host devices into the container", 70)
        mounts = list(p.flags.get("-v", [])) + list(p.flags.get("--volume", []))
        for m in p.flags.get("--mount", []):
            parts = dict(kv.split("=", 1) for kv in m.split(",") if "=" in kv)
            src = parts.get("source") or parts.get("src")
            if src:
                mounts.append(f"{src}:{parts.get('target') or parts.get('dst') or ''}")
        for m in mounts:
            src = m.split(":", 1)[0]
            if (
                src in ("/", "/etc", "/root", "/proc", "/sys", "/dev", "/boot", "/var/lib/kubelet")
                or "docker.sock" in src
            ):
                b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-HOST-MOUNT", f"bind-mounts sensitive host path {src}", 100)

    # ------------------------------------------------------------------ #
    # helm
    # ------------------------------------------------------------------ #

    _HELM_VALUE_FLAGS = {
        "-n", "--namespace", "--kube-context", "--kubeconfig", "-f", "--values", "--set", "--set-string",
        "--set-file", "--version", "--repo", "-o", "--output", "--timeout", "--revision", "--max",
        "--description", "--registry-config", "--repository-config", "--repository-cache", "--post-renderer",
    }  # fmt: skip
    _HELM_SAFE = {
        "list", "ls", "status", "history", "hist", "get", "show", "inspect", "search", "template", "lint",
        "version", "env", "verify", "completion", "help", "diff",
    }  # fmt: skip
    _HELM_APPROVAL = {
        "install", "upgrade", "rollback", "test", "repo", "dependency", "dep", "pull", "fetch", "push",
        "package", "registry", "plugin", "create",
    }  # fmt: skip

    def _helm(self, args: List[str], b: _Builder) -> None:
        p = _parse_args(args, self._HELM_VALUE_FLAGS)
        ns = p.get("-n", "--namespace")
        b.d.namespace = ns
        if not p.positionals:
            b.hit(Verdict.SAFE_READ, "KGP-HELP", "prints helm help", 0)
            return
        verb = p.positionals[0].lower()
        b.d.verb = verb
        b.d.resources = p.positionals[1:3]
        sub = p.positionals[1].lower() if len(p.positionals) > 1 else ""
        if verb in self._HELM_SAFE:
            return
        if verb in ("repo", "dependency", "dep", "plugin") and sub in ("list", "ls"):
            return
        self._check_namespace(ns, True, b)
        if verb in ("uninstall", "delete", "del", "un"):
            b.hit(
                Verdict.BLOCKED_DESTRUCTIVE, "KGP-HELM-UNINSTALL", "uninstalls a release and deletes its resources", 90
            )
            return
        if verb in ("upgrade", "install", "rollback") and p.has("--force"):
            b.hit(Verdict.BLOCKED_DESTRUCTIVE, "KGP-FORCE", f"helm {verb} --force replaces resources", 85)
            return
        if verb in self._HELM_APPROVAL:
            b.hit(Verdict.APPROVAL_REQUIRED, "KGP-MUTATE", f"helm {verb} changes cluster state", 50)
            return
        b.hit(Verdict.APPROVAL_REQUIRED, "KGP-UNKNOWN-VERB", f"unrecognised helm command '{verb}'; human review", 50)


def classify(command: Union[str, Sequence[str]]) -> PolicyDecision:
    """Classify a command with the default engine."""
    return PolicyEngine().classify(command)


def engine_from_env() -> PolicyEngine:
    role = os.environ.get("KUBEGUARD_ROLE", "operator").strip().lower() or "operator"
    extra = [n.strip() for n in os.environ.get("KUBEGUARD_PROTECTED_NAMESPACES", "").split(",") if n.strip()]
    return PolicyEngine(
        role=role if role in ROLES else "operator", protected_namespaces=DEFAULT_PROTECTED_NAMESPACES + tuple(extra)
    )


# --------------------------------------------------------------------------- #
# RBAC analysis
# --------------------------------------------------------------------------- #


@dataclass
class RbacFinding:
    rule_id: str
    severity: str
    resource: str
    message: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "resource": self.resource,
            "message": self.message,
            "recommendation": self.recommendation,
        }


_READ_VERBS = {"get", "list", "watch", "*"}
_PUBLIC_GROUPS = {"system:anonymous", "system:unauthenticated", "system:authenticated"}


def _as_list(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]


def analyze_rbac(objects: Iterable[Dict[str, Any]]) -> List[RbacFinding]:
    """Flag dangerous permissions in Role/ClusterRole/(Cluster)RoleBinding objects."""
    findings: List[RbacFinding] = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        kind = obj.get("kind")
        name = (obj.get("metadata") or {}).get("name", "?")
        ref = f"{kind}/{name}"
        if kind in ("Role", "ClusterRole"):
            cluster = kind == "ClusterRole"
            for rule in obj.get("rules") or []:
                if not isinstance(rule, dict):
                    continue
                verbs = {v.lower() for v in _as_list(rule.get("verbs"))}
                resources = {r.lower() for r in _as_list(rule.get("resources"))}
                groups = set(_as_list(rule.get("apiGroups")))
                if "*" in verbs and "*" in resources:
                    findings.append(
                        RbacFinding(
                            "KG-RBAC-001",
                            "critical" if cluster or "*" in groups else "high",
                            ref,
                            "wildcard verbs on wildcard resources (cluster-admin equivalent)",
                            "enumerate the exact resources and verbs the workload needs",
                        )
                    )
                    continue
                if "*" in resources and verbs & _READ_VERBS:
                    findings.append(
                        RbacFinding(
                            "KG-RBAC-002",
                            "high",
                            ref,
                            "read access to all resources (includes Secrets)",
                            "replace '*' with an explicit resource list",
                        )
                    )
                if "secrets" in resources and verbs & _READ_VERBS:
                    findings.append(
                        RbacFinding(
                            "KG-RBAC-003",
                            "high" if cluster else "medium",
                            ref,
                            f"can read Secrets ({', '.join(sorted(verbs & _READ_VERBS))})",
                            "mount only the specific Secret, or use resourceNames to scope access",
                        )
                    )
                if resources & {"pods/exec", "pods/attach"} and verbs & {"create", "get", "*"}:
                    findings.append(
                        RbacFinding(
                            "KG-RBAC-004",
                            "high",
                            ref,
                            "can exec/attach into pods (arbitrary code execution)",
                            "remove pods/exec; use ephemeral debug workflows with approval",
                        )
                    )
                if verbs & {"escalate", "bind", "impersonate"}:
                    findings.append(
                        RbacFinding(
                            "KG-RBAC-005",
                            "critical",
                            ref,
                            f"privilege-escalation verbs: {', '.join(sorted(verbs & {'escalate', 'bind', 'impersonate'}))}",
                            "grant escalate/bind/impersonate only to cluster administrators",
                        )
                    )
                if resources & {"nodes/proxy", "serviceaccounts/token", "certificatesigningrequests/approval"}:
                    hit = sorted(
                        resources & {"nodes/proxy", "serviceaccounts/token", "certificatesigningrequests/approval"}
                    )
                    findings.append(
                        RbacFinding(
                            "KG-RBAC-006",
                            "high",
                            ref,
                            f"access to credential-minting/host-proxy subresources: {', '.join(hit)}",
                            "remove these subresources unless the workload is a cluster component",
                        )
                    )
                if (
                    resources & {"mutatingwebhookconfigurations", "validatingwebhookconfigurations"}
                    and verbs - _READ_VERBS
                ):
                    findings.append(
                        RbacFinding(
                            "KG-RBAC-007",
                            "high",
                            ref,
                            "can modify admission webhooks (intercepts every API request)",
                            "restrict webhook management to platform administrators",
                        )
                    )
                if "pods" in resources and verbs & {"create", "*"}:
                    findings.append(
                        RbacFinding(
                            "KG-RBAC-008",
                            "medium",
                            ref,
                            "can create pods (may mount any ServiceAccount token in the namespace)",
                            "create pods through controllers and enforce Pod Security admission",
                        )
                    )
                if "*" in _as_list(rule.get("nonResourceURLs")):
                    findings.append(
                        RbacFinding(
                            "KG-RBAC-009",
                            "medium",
                            ref,
                            "wildcard nonResourceURLs",
                            "list the exact non-resource URLs (e.g. /healthz)",
                        )
                    )
        elif kind in ("ClusterRoleBinding", "RoleBinding"):
            role_ref = (obj.get("roleRef") or {}).get("name", "")
            subjects = obj.get("subjects") or []
            subject_names = [
                f"{s.get('kind', '?')}:{s.get('namespace', '') + '/' if s.get('namespace') else ''}{s.get('name', '?')}"
                for s in subjects
                if isinstance(s, dict)
            ]
            for s in subjects:
                if isinstance(s, dict) and s.get("name") in _PUBLIC_GROUPS:
                    findings.append(
                        RbacFinding(
                            "KG-RBAC-010",
                            "critical",
                            ref,
                            f"binds '{role_ref}' to the public group {s.get('name')}",
                            "never bind roles to anonymous/unauthenticated/all-authenticated groups",
                        )
                    )
            if role_ref == "cluster-admin":
                findings.append(
                    RbacFinding(
                        "KG-RBAC-011",
                        "critical" if kind == "ClusterRoleBinding" else "high",
                        ref,
                        f"grants cluster-admin to {', '.join(subject_names) or 'subjects'}",
                        "bind a least-privilege role instead of cluster-admin",
                    )
                )
            for s in subjects:
                if isinstance(s, dict) and s.get("kind") == "ServiceAccount" and s.get("name") == "default":
                    findings.append(
                        RbacFinding(
                            "KG-RBAC-012",
                            "medium",
                            ref,
                            "grants permissions to the namespace 'default' ServiceAccount (shared by every pod)",
                            "create a dedicated ServiceAccount per workload",
                        )
                    )
    return findings
