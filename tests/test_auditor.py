import json

from src.auditor import audit_cluster, validate_manifest
from tests.conftest import EXAMPLES, fake_aws_key_id

GOOD = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: good
spec:
  replicas: 3
  selector:
    matchLabels: {app: good}
  template:
    metadata:
      labels: {app: good}
    spec:
      serviceAccountName: good
      containers:
      - name: app
        image: registry.example.com/good:1.2.3
        ports:
        - name: http
          containerPort: 8080
        resources:
          requests: {cpu: 100m, memory: 128Mi}
          limits: {memory: 256Mi}
        readinessProbe: {httpGet: {path: /ready, port: http}}
        livenessProbe: {httpGet: {path: /live, port: http}}
        securityContext:
          runAsNonRoot: true
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
---
apiVersion: v1
kind: Service
metadata:
  name: good
spec:
  selector: {app: good}
  ports:
  - port: 80
    targetPort: http
"""

BAD = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: bad
    spec:
      hostNetwork: true
      volumes:
      - name: sock
        hostPath:
          path: /var/run/docker.sock
      containers:
      - name: app
        image: nginx
        ports:
        - containerPort: 80
        env:
        - name: DB_PASSWORD
          value: hunter2
        - name: JAVA_OPTS
          value: -Xmx900m
        resources:
          limits:
            memory: 1Gi
        securityContext:
          privileged: true
          runAsUser: 0
          capabilities:
            add: ["SYS_ADMIN"]
---
apiVersion: v1
kind: Service
metadata:
  name: bad
spec:
  selector:
    app: bad
  ports:
  - port: 80
    targetPort: 8080
"""


def _ids(report):
    return {f.rule_id for f in report.findings}


def test_good_manifest_passes_with_grade_a():
    report = validate_manifest(GOOD, "good.yaml")
    assert report.passed, [f.to_dict() for f in report.findings]
    assert report.grade == "A" and report.score >= 90
    assert report.resources == ["Deployment/good", "Service/good"]


def test_bad_manifest_flags_everything():
    report = validate_manifest(BAD, "bad.yaml")
    assert not report.passed and report.grade == "F"
    expected = {
        "KG001",
        "KG003",
        "KG004",
        "KG006",
        "KG007",
        "KG008",
        "KG009",
        "KG011",
        "KG012",
        "KG014",
        "KG016",
        "KG018",
    }
    assert expected <= _ids(report)
    sev = {f.rule_id: f.severity for f in report.findings}
    assert sev["KG004"] == "critical" and sev["KG008"] == "critical" and sev["KG012"] == "critical"
    assert report.findings[0].severity == "critical"  # sorted by severity


def test_findings_carry_line_numbers():
    report = validate_manifest(BAD, "bad.yaml")
    secret = next(f for f in report.findings if f.rule_id == "KG012")
    assert secret.line == BAD.splitlines().index("          value: hunter2") + 1
    assert secret.container == "app" and secret.file == "bad.yaml"


def test_report_output_never_leaks_secret():
    report = validate_manifest(BAD)
    assert "hunter2" not in json.dumps(report.to_dict()) + report.to_markdown()


def test_request_greater_than_limit():
    text = GOOD.replace("requests: {cpu: 100m, memory: 128Mi}", "requests: {cpu: 100m, memory: 512Mi}")
    assert "KG013" in _ids(validate_manifest(text))


def test_service_selector_matching_nothing():
    text = GOOD.replace("selector: {app: good}\n  ports", "selector: {app: other}\n  ports")
    assert "KG019" in _ids(validate_manifest(text))


def test_secret_manifest_and_rbac():
    text = (
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\ndata:\n  password: aHVudGVyMg==\n---\n"
        "kind: ClusterRole\nmetadata:\n  name: god\nrules:\n- apiGroups: ['*']\n  resources: ['*']\n  verbs: ['*']\n"
    )
    ids = _ids(validate_manifest(text))
    assert {"KG017", "KG-RBAC-001"} <= ids


def test_compose_checks():
    compose = (
        "services:\n  web:\n    image: web:1\n    privileged: true\n    network_mode: host\n"
        "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n    environment:\n      API_TOKEN: tok-123456\n"
    )
    report = validate_manifest(compose, "docker-compose.yml")
    assert {"KGC001", "KGC002", "KGC003", "KGC004", "KGC005"} <= _ids(report)
    assert report.resources == ["compose/web"]


def test_parse_error_is_reported_not_raised():
    report = validate_manifest("a: 1\na: 2\n", "dup.yaml")
    assert report.errors and not report.passed


def test_plain_secret_outside_known_fields_is_caught():
    text = f"kind: ConfigMap\nmetadata:\n  name: c\ndata:\n  creds: aws={fake_aws_key_id()}\n"
    assert "KG020" in _ids(validate_manifest(text))


def test_audit_cluster_aggregates_risk():
    audit = audit_cluster(
        {"good.yaml": GOOD, "bad.yaml": BAD},
        ["kubectl get pods", "kubectl apply -f x.yaml", "kubectl delete ns prod"],
    )
    data = audit.to_dict()
    assert audit.risk_score == 100 and audit.risk_level == "CRITICAL"
    assert data["top_risks"][0]["severity"] == "critical"
    assert [c["verdict"] for c in data["commands"]] == ["SAFE_READ", "APPROVAL_REQUIRED", "BLOCKED_DESTRUCTIVE"]
    assert data["secrets_found"]
    json.dumps(data)
    md = audit.to_markdown()
    assert "Risk score 100/100" in md and "kubectl delete ns prod" in md


def test_audit_of_clean_input_is_low():
    audit = audit_cluster(GOOD, ["kubectl get pods -n prod"])
    assert audit.risk_level == "LOW" and audit.risk_score < 25


def test_audit_examples_directory_files():
    files = [(str(p), p.read_text(encoding="utf-8")) for p in sorted(EXAMPLES.rglob("*.yaml"))]
    audit = audit_cluster(files)
    assert len(audit.manifests) == len(files) >= 5
    crash = next(r for r in audit.manifests if "crashloop_secret_leak" in r.file)
    assert "KG012" in {f.rule_id for f in crash.findings}
