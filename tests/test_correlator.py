import base64
import json

import pytest

from src import yaml_lite
from src.correlator import (
    FailureType,
    IncidentBundle,
    _items,
    correlate,
    format_memory,
    parse_quantity,
    redacted_diff,
)
from src.scenarios import load_scenario, scenario_metadata
from tests.conftest import (
    EXAMPLES,
    SCENARIOS,
    assert_no_secrets,
    cstatus,
    deployment,
    event,
    pod,
    secret_obj,
)

APP = (
    "      - name: app\n"
    "        image: registry.example.com/team/app:1.0.0\n"
    "        ports:\n"
    "        - name: http\n"
    "          containerPort: 8080\n"
)


def _diag(result, failure):
    for d in result.diagnoses:
        if d.failure is failure:
            return d
    raise AssertionError(f"{failure} not diagnosed: {[d.failure for d in result.diagnoses]}")


def _patched(diagnosis, file=None):
    patch = next(p for p in diagnosis.patches if file is None or p.file == file)
    return patch.patched


# --------------------------------------------------------------------------- #
# bundled examples
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", SCENARIOS)
def test_examples_diagnose_expected_root_cause(name):
    result = correlate(EXAMPLES / name)
    expected = scenario_metadata(name)["expected_failure"]
    assert result.primary is not None
    assert result.primary.failure.value == expected
    assert result.primary.confidence >= 0.9
    assert result.primary.patches, "every bundled scenario has a deterministic fix"


@pytest.mark.parametrize("name", SCENARIOS)
def test_example_output_never_contains_secrets(name):
    result = correlate(EXAMPLES / name)
    blob = json.dumps(result.to_dict())
    assert_no_secrets(blob)
    for d in result.diagnoses:
        for p in d.patches:
            assert_no_secrets(redacted_diff(p))


@pytest.mark.parametrize("name", SCENARIOS)
def test_example_patches_are_valid_yaml(name):
    for patch in correlate(EXAMPLES / name).primary.patches:
        if patch.kind != "dockerfile":
            yaml_lite.load_all(patch.patched)


def test_oom_example_details():
    p = correlate(EXAMPLES / "oom_killed").primary
    assert p.sub_cause == "heap_exceeds_limit"
    assert "150%" in p.root_cause
    dep = yaml_lite.load(_patched(p, "deployment.yaml"))
    assert dep["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"] == "1Gi"
    assert "-XX:MaxRAMPercentage=75.0" in _patched(p, "Dockerfile")
    assert "-Xmx768m" not in _patched(p, "Dockerfile")


def test_oom_example_marks_crashloop_as_symptom():
    result = correlate(EXAMPLES / "oom_killed")
    crash = _diag(result, FailureType.CRASH_LOOP)
    assert crash.symptom_of == "OOMKilled"
    assert result.diagnoses[0].failure is FailureType.OOM_KILLED


def test_crashloop_example_moves_credentials_to_secret_refs():
    p = correlate(EXAMPLES / "crashloop_secret_leak").primary
    assert p.sub_cause == "db_auth_failure"
    env = yaml_lite.load(_patched(p))["spec"]["template"]["spec"]["containers"][0]["env"]
    refs = {e["name"]: e["valueFrom"]["secretKeyRef"] for e in env if "valueFrom" in e}
    assert refs["DATABASE_URL"] == {"name": "orders-db-credentials", "key": "database-url"}
    assert refs["AWS_SECRET_ACCESS_KEY"]["name"] == "orders-aws-credentials"
    assert "Wint3r-2025!" not in _patched(p)


def test_crashloop_example_is_sev1_because_credentials_leaked_at_runtime():
    result = correlate(EXAMPLES / "crashloop_secret_leak")
    assert result.severity == "SEV-1"
    assert result.runtime_leaks["aws_access_key_id"] == 1
    assert "email" not in result.runtime_leaks


def test_service_example_uses_named_port():
    p = correlate(EXAMPLES / "service_port_mismatch").primary
    svc = yaml_lite.load(_patched(p, "service.yaml"))
    assert svc["spec"]["ports"][0]["targetPort"] == "http"


def test_image_pull_example_attaches_existing_pull_secret():
    p = correlate(EXAMPLES / "image_pull_backoff").primary
    assert p.sub_cause == "registry_auth"
    spec = yaml_lite.load(_patched(p))["spec"]["template"]["spec"]
    assert spec["imagePullSecrets"] == [{"name": "acme-registry-creds"}]


def test_results_are_deterministic():
    a = correlate(EXAMPLES / "crashloop_secret_leak").to_dict()
    b = correlate(load_scenario("crashloop_secret_leak")).to_dict()
    assert a == b
    assert a["incident_id"].startswith("KG-") and len(a["incident_id"]) == 11


def test_timeline_is_sorted():
    times = [t.time for t in correlate(EXAMPLES / "oom_killed").timeline]
    assert times == sorted(times)


# --------------------------------------------------------------------------- #
# synthetic bundles: OOMKilled
# --------------------------------------------------------------------------- #


def _oom_pod():
    return pod(statuses=[cstatus(waiting="CrashLoopBackOff", last_reason="OOMKilled", last_exit=137, restarts=4)])


def test_oom_without_limit_inserts_limits_and_requests():
    manifest = deployment(APP)
    result = correlate(IncidentBundle.from_inputs(pod=_oom_pod(), manifests=manifest))
    p = _diag(result, FailureType.OOM_KILLED)
    res = yaml_lite.load(_patched(p))["spec"]["template"]["spec"]["containers"][0]["resources"]
    assert res == {"limits": {"memory": "512Mi"}, "requests": {"memory": "256Mi"}}
    assert p.sub_cause == "limit_too_low"


def test_oom_guaranteed_qos_raises_request_too():
    c = (
        APP
        + "        resources:\n          requests:\n            memory: 1Gi\n          limits:\n            memory: 1Gi\n"
    )
    p = _diag(correlate(IncidentBundle.from_inputs(pod=_oom_pod(), manifests=deployment(c))), FailureType.OOM_KILLED)
    res = yaml_lite.load(_patched(p))["spec"]["template"]["spec"]["containers"][0]["resources"]
    assert res["limits"]["memory"] == res["requests"]["memory"] == "2Gi"


def test_oom_java_opts_in_env_is_rewritten():
    c = (
        APP
        + "        env:\n        - name: JAVA_OPTS\n          value: -Xmx900m -Dfoo=bar\n"
        + "        resources:\n          limits:\n            memory: 1Gi\n"
    )
    p = _diag(correlate(IncidentBundle.from_inputs(pod=_oom_pod(), manifests=deployment(c))), FailureType.OOM_KILLED)
    container = yaml_lite.load(_patched(p))["spec"]["template"]["spec"]["containers"][0]
    assert container["env"][0]["value"] == "-XX:MaxRAMPercentage=75.0 -Dfoo=bar"
    assert container["resources"]["limits"]["memory"] == "2Gi"


def test_oom_node_heap_flag():
    c = (
        APP
        + '        args: ["--max-old-space-size=2048"]\n        resources:\n          limits:\n            memory: 2Gi\n'
    )
    p = _diag(correlate(IncidentBundle.from_inputs(pod=_oom_pod(), manifests=deployment(c))), FailureType.OOM_KILLED)
    assert "Node.js" in p.root_cause
    assert any("--max-old-space-size" in r for r in p.remediation)


def test_oom_from_docker_inspect_and_compose_patch():
    inspect = [
        {
            "Name": "/worker",
            "RestartCount": 7,
            "State": {"Status": "restarting", "OOMKilled": True, "ExitCode": 137, "Restarting": True},
            "Config": {"Image": "acme/worker:1", "Env": ["JAVA_TOOL_OPTIONS=-Xmx600m"]},
            "HostConfig": {"Memory": 536870912},
        }
    ]
    compose = "services:\n  worker:\n    image: acme/worker:1\n    mem_limit: 512m\n"
    result = correlate(IncidentBundle.from_inputs(docker_inspect=inspect, manifests={"docker-compose.yml": compose}))
    p = result.primary
    assert p.failure is FailureType.OOM_KILLED and p.sub_cause == "heap_exceeds_limit"
    assert "docker inspect" in p.evidence[0].source
    patched = yaml_lite.load(_patched(p, "docker-compose.yml"))
    assert patched["services"]["worker"]["mem_limit"] == "1Gi"


# --------------------------------------------------------------------------- #
# CrashLoopBackOff sub-causes
# --------------------------------------------------------------------------- #


def _crash_pod(exit_code=1):
    return pod(statuses=[cstatus(waiting="CrashLoopBackOff", last_reason="Error", last_exit=exit_code, restarts=5)])


BACKOFF = event("BackOff", "Back-off restarting failed container app in pod app-6d4cf56db6-abcde_prod", count=9)


def test_crashloop_missing_env_injected_from_configmap():
    cm = {"kind": "ConfigMap", "metadata": {"name": "app-config"}, "data": {"REDIS_URL": "redis://cache:6379"}}
    logs = "starting\nTraceback (most recent call last):\nKeyError: 'REDIS_URL'\n"
    bundle = IncidentBundle.from_inputs(
        pod=_crash_pod(), events=[BACKOFF], logs=logs, manifests=deployment(APP), configmaps=[cm]
    )
    p = correlate(bundle).primary
    assert (p.failure, p.sub_cause) == (FailureType.CRASH_LOOP, "missing_config")
    env = yaml_lite.load(_patched(p))["spec"]["template"]["spec"]["containers"][0]["env"]
    assert env == [{"name": "REDIS_URL", "valueFrom": {"configMapKeyRef": {"name": "app-config", "key": "REDIS_URL"}}}]


def test_crashloop_liveness_probe_port_mismatch():
    c = APP + "        livenessProbe:\n          httpGet:\n            path: /healthz\n            port: 9090\n"
    events = [
        BACKOFF,
        event("Unhealthy", "Liveness probe failed: Get http://10.0.0.1:9090/healthz: connection refused", count=12),
    ]
    logs = "INFO server listening on port 8080\n"
    p = correlate(
        IncidentBundle.from_inputs(pod=_crash_pod(137), events=events, logs=logs, manifests=deployment(c))
    ).primary
    assert p.sub_cause == "liveness_probe"
    probe = yaml_lite.load(_patched(p))["spec"]["template"]["spec"]["containers"][0]["livenessProbe"]
    assert probe["httpGet"]["port"] == 8080


def test_crashloop_liveness_probe_slow_startup():
    c = (
        APP
        + "        livenessProbe:\n          httpGet:\n            path: /healthz\n            port: http\n          initialDelaySeconds: 10\n"
    )
    events = [BACKOFF, event("Killing", "Container app failed liveness probe, will be restarted", count=6)]
    logs = "Started App in 64.2 seconds (process running for 65)\n"
    p = correlate(
        IncidentBundle.from_inputs(pod=_crash_pod(137), events=events, logs=logs, manifests=deployment(c))
    ).primary
    probe = yaml_lite.load(_patched(p))["spec"]["template"]["spec"]["containers"][0]["livenessProbe"]
    assert probe["initialDelaySeconds"] == 100


@pytest.mark.parametrize(
    "logs,exit_code,sub",
    [
        ("exec /app/server: exec format error\n", 1, "exec_format"),
        ("/bin/sh: /app/start.sh: not found\n", 127, "command_not_found"),
        ("open /data/cache: permission denied\n", 1, "permission_denied"),
        ("INFO boot\nERROR unhandled exception in main loop: boom\n", 1, "application_error"),
    ],
)
def test_crashloop_sub_causes(logs, exit_code, sub):
    bundle = IncidentBundle.from_inputs(
        pod=_crash_pod(exit_code), events=[BACKOFF], logs=logs, manifests=deployment(APP)
    )
    p = correlate(bundle).primary
    assert p.failure is FailureType.CRASH_LOOP and p.sub_cause == sub
    assert p.remediation


def test_crashloop_without_matching_secret_suggests_create_secret():
    c = APP + "        env:\n        - name: DB_PASSWORD\n          value: hunter2\n"
    logs = "FATAL: password authentication failed for user app\n"
    p = correlate(
        IncidentBundle.from_inputs(pod=_crash_pod(), events=[BACKOFF], logs=logs, manifests=deployment(c))
    ).primary
    ref = yaml_lite.load(_patched(p))["spec"]["template"]["spec"]["containers"][0]["env"][0]["valueFrom"][
        "secretKeyRef"
    ]
    assert ref == {"name": "app-secrets", "key": "db-password"}
    create = [c for c in p.commands if c.command.startswith("kubectl create secret")]
    assert create and create[0].verdict == "APPROVAL_REQUIRED"
    assert "hunter2" not in json.dumps(p.to_dict())


# --------------------------------------------------------------------------- #
# ImagePullBackOff
# --------------------------------------------------------------------------- #


def _pull_pod(reason="ImagePullBackOff", image="registry.example.com/team/app:1.0.1"):
    return pod(
        phase="Pending", statuses=[cstatus(waiting=reason, message=f'Back-off pulling image "{image}"', image=image)]
    )


def test_image_tag_not_found_rolls_back_to_last_known_good():
    c = APP.replace("app:1.0.0", "app:1.0.1")
    events = [
        event(
            "Pulled",
            'Successfully pulled image "registry.example.com/team/app:1.0.0" in 2s',
            "Normal",
            ts="2026-01-01T00:00:00Z",
        ),
        event(
            "Failed", 'Failed to pull image "registry.example.com/team/app:1.0.1": manifest unknown: manifest unknown'
        ),
    ]
    p = correlate(IncidentBundle.from_inputs(pod=_pull_pod(), events=events, manifests=deployment(c))).primary
    assert (p.failure, p.sub_cause) == (FailureType.IMAGE_PULL, "tag_not_found")
    assert yaml_lite.load(_patched(p))["spec"]["template"]["spec"]["containers"][0]["image"].endswith(":1.0.0")


def test_image_invalid_name_is_lowercased():
    c = APP.replace("registry.example.com/team/app:1.0.0", "registry.example.com/Team/App:1.0.0")
    p = correlate(
        IncidentBundle.from_inputs(
            pod=_pull_pod("InvalidImageName", "registry.example.com/Team/App:1.0.0"), manifests=deployment(c)
        )
    ).primary
    assert p.sub_cause == "invalid_name"
    assert (
        yaml_lite.load(_patched(p))["spec"]["template"]["spec"]["containers"][0]["image"]
        == "registry.example.com/team/app:1.0.0"
    )


def test_image_auth_without_pull_secret_suggests_creating_one():
    events = [event("Failed", 'Failed to pull image "registry.example.com/team/app:1.0.1": 401 Unauthorized')]
    p = correlate(IncidentBundle.from_inputs(pod=_pull_pod(), events=events, manifests=deployment(APP))).primary
    assert p.sub_cause == "registry_auth"
    assert yaml_lite.load(_patched(p))["spec"]["template"]["spec"]["imagePullSecrets"] == [{"name": "regcred"}]
    create = [c for c in p.commands if "docker-registry" in c.command]
    assert create and create[0].verdict == "APPROVAL_REQUIRED" and "$REGISTRY_TOKEN" in create[0].command


def test_image_pull_secret_matched_by_registry_host():
    cfg = base64.b64encode(json.dumps({"auths": {"registry.example.com": {"auth": "eA=="}}}).encode()).decode()
    other = base64.b64encode(json.dumps({"auths": {"ghcr.io": {"auth": "eA=="}}}).encode()).decode()
    secrets = [
        secret_obj("aaa-ghcr", {".dockerconfigjson": other}, "kubernetes.io/dockerconfigjson"),
        secret_obj("zzz-internal", {".dockerconfigjson": cfg}, "kubernetes.io/dockerconfigjson"),
    ]
    events = [event("Failed", "pull access denied for registry.example.com/team/app")]
    p = correlate(
        IncidentBundle.from_inputs(pod=_pull_pod(), events=events, manifests=deployment(APP), secrets=secrets)
    ).primary
    assert yaml_lite.load(_patched(p))["spec"]["template"]["spec"]["imagePullSecrets"] == [{"name": "zzz-internal"}]


@pytest.mark.parametrize(
    "message,sub",
    [
        ("toomanyrequests: You have reached your pull rate limit", "rate_limited"),
        ("dial tcp: lookup registry: no such host", "registry_unreachable"),
    ],
)
def test_image_pull_other_sub_causes(message, sub):
    p = correlate(IncidentBundle.from_inputs(pod=_pull_pod("ErrImagePull"), events=[event("Failed", message)])).primary
    assert p.failure is FailureType.IMAGE_PULL and p.sub_cause == sub


# --------------------------------------------------------------------------- #
# CreateContainerConfigError
# --------------------------------------------------------------------------- #


def _cfg_pod(message):
    return pod(phase="Pending", statuses=[cstatus(waiting="CreateContainerConfigError", message=message)])


def test_config_error_missing_key_typo_is_fixed():
    c = (
        APP
        + "        env:\n        - name: DB_PASS\n          valueFrom:\n            secretKeyRef:\n              name: db\n              key: pasword\n"
    )
    msg = "couldn't find key pasword in Secret prod/db"
    secrets = [secret_obj("db", {"password": "eA==", "username": "eA=="})]
    p = correlate(IncidentBundle.from_inputs(pod=_cfg_pod(msg), manifests=deployment(c), secrets=secrets)).primary
    assert (p.failure, p.sub_cause) == (FailureType.CONFIG_ERROR, "missing_key")
    ref = yaml_lite.load(_patched(p))["spec"]["template"]["spec"]["containers"][0]["env"][0]["valueFrom"][
        "secretKeyRef"
    ]
    assert ref == {"name": "db", "key": "password"}


def test_config_error_misspelled_secret_name_fixed_everywhere():
    c = (
        APP
        + "        env:\n        - name: DB_PASSWORD\n          valueFrom:\n            secretKeyRef:\n              name: db-credentails\n              key: password\n"
        + "        envFrom:\n        - secretRef:\n            name: db-credentails\n"
    )
    extra = "      volumes:\n      - name: creds\n        secret:\n          secretName: db-credentails\n"
    msg = 'secret "db-credentails" not found'
    secrets = [secret_obj("db-credentials", {"password": "eA=="})]
    p = correlate(
        IncidentBundle.from_inputs(pod=_cfg_pod(msg), manifests=deployment(c, extra_pod_spec=extra), secrets=secrets)
    ).primary
    assert p.sub_cause == "missing_secret"
    patched = _patched(p)
    assert "db-credentails" not in patched and patched.count("db-credentials") == 3


def test_config_error_missing_configmap_without_candidate():
    p = correlate(
        IncidentBundle.from_inputs(pod=_cfg_pod('configmap "app-config" not found'), manifests=deployment(APP))
    ).primary
    assert p.sub_cause == "missing_configmap" and not p.patches
    assert any(c.command.startswith("kubectl create configmap app-config") for c in p.commands)


def test_config_error_run_as_non_root():
    msg = "container has runAsNonRoot and image will run as root (pod: app_prod, container: app)"
    dockerfile = 'FROM python:3.12-slim\nCOPY . /app\nCMD ["python", "/app/main.py"]\n'
    bundle = IncidentBundle.from_inputs(pod=_cfg_pod(msg), manifests=deployment(APP), dockerfile=dockerfile)
    p = correlate(bundle).primary
    assert p.sub_cause == "run_as_non_root"
    sc = yaml_lite.load(_patched(p, "manifest.yaml"))["spec"]["template"]["spec"]["containers"][0]["securityContext"]
    assert sc == {"runAsUser": 10001, "runAsNonRoot": True}
    assert "USER 10001:10001\nCMD" in _patched(p, "Dockerfile")


# --------------------------------------------------------------------------- #
# Unschedulable
# --------------------------------------------------------------------------- #


def _pending(message):
    cond = [{"type": "PodScheduled", "status": "False", "reason": "Unschedulable", "message": message}]
    return pod(phase="Pending", conditions=cond), [event("FailedScheduling", message, count=3)]


def _node(name, mem="8Gi", cpu="4", labels=None):
    return {
        "kind": "Node",
        "metadata": {"name": name, "labels": labels or {}},
        "status": {"allocatable": {"memory": mem, "cpu": cpu}},
    }


def test_unschedulable_insufficient_memory_right_sizes_request():
    p_, ev = _pending("0/3 nodes are available: 3 Insufficient memory. preemption: 0/3 nodes are available.")
    c = (
        APP
        + "        resources:\n          requests:\n            memory: 64Gi\n          limits:\n            memory: 64Gi\n"
    )
    nodes = [_node("a", "8Gi"), _node("b", "16Gi")]
    p = correlate(IncidentBundle.from_inputs(pod=p_, events=ev, manifests=deployment(c), nodes=nodes)).primary
    assert (p.failure, p.sub_cause) == (FailureType.UNSCHEDULABLE, "insufficient_resources")
    req = yaml_lite.load(_patched(p))["spec"]["template"]["spec"]["containers"][0]["resources"]["requests"]["memory"]
    assert parse_quantity(req) <= 16 * 1024**3


def test_unschedulable_without_node_data_only_recommends():
    p_, ev = _pending("0/2 nodes are available: 2 Insufficient cpu.")
    p = correlate(IncidentBundle.from_inputs(pod=p_, events=ev, manifests=deployment(APP))).primary
    assert p.failure is FailureType.UNSCHEDULABLE and not p.patches and p.remediation


def test_unschedulable_node_selector_typo():
    p_, ev = _pending("0/2 nodes are available: 2 node(s) didn't match Pod's node affinity/selector.")
    extra = "      nodeSelector:\n        disktype: sdd\n"
    nodes = [_node("a", labels={"disktype": "ssd"}), _node("b", labels={"disktype": "hdd"})]
    p = correlate(
        IncidentBundle.from_inputs(pod=p_, events=ev, manifests=deployment(APP, extra_pod_spec=extra), nodes=nodes)
    ).primary
    assert p.sub_cause == "node_selector_mismatch"
    assert yaml_lite.load(_patched(p))["spec"]["template"]["spec"]["nodeSelector"] == {"disktype": "ssd"}


def test_unschedulable_taint():
    p_, ev = _pending("0/1 nodes are available: 1 node(s) had untolerated taint {dedicated: gpu}.")
    assert correlate(IncidentBundle.from_inputs(pod=p_, events=ev)).primary.sub_cause == "untolerated_taint"


# --------------------------------------------------------------------------- #
# ServicePortMismatch
# --------------------------------------------------------------------------- #

SVC = "apiVersion: v1\nkind: Service\nmetadata:\n  name: app\nspec:\n  selector:\n    app: {sel}\n  ports:\n  - port: 80\n    targetPort: {tp}\n"


def _healthy_pod():
    return pod(statuses=[cstatus(running=True, ready=True)])


def test_service_selector_mismatch_is_aligned():
    files = {"deploy.yaml": deployment(APP), "svc.yaml": SVC.format(sel="app-v2", tp="http")}
    p = correlate(IncidentBundle.from_inputs(pod=_healthy_pod(), manifests=files)).primary
    assert (p.failure, p.sub_cause) == (FailureType.SERVICE_PORT_MISMATCH, "selector_mismatch")
    assert yaml_lite.load(_patched(p, "svc.yaml"))["spec"]["selector"] == {"app": "app"}


def test_service_unknown_named_port():
    files = {"deploy.yaml": deployment(APP), "svc.yaml": SVC.format(sel="app", tp="web")}
    p = correlate(IncidentBundle.from_inputs(pod=_healthy_pod(), manifests=files)).primary
    assert p.sub_cause == "target_port"
    assert yaml_lite.load(_patched(p, "svc.yaml"))["spec"]["ports"][0]["targetPort"] == "http"


def test_service_matching_port_is_healthy():
    files = {"deploy.yaml": deployment(APP), "svc.yaml": SVC.format(sel="app", tp=8080)}
    result = correlate(IncidentBundle.from_inputs(pod=_healthy_pod(), manifests=files))
    assert result.healthy and result.severity == "SEV-4" and result.primary is None


# --------------------------------------------------------------------------- #
# inputs, normalisation, helpers
# --------------------------------------------------------------------------- #


def test_events_k8s_io_v1_format():
    ev = {"type": "Warning", "reason": "BackOff", "note": "Back-off restarting failed container app", "deprecatedCount": 4,
          "regarding": {"kind": "Pod", "name": "x"}, "eventTime": "2026-01-01T00:00:00.000000Z"}  # fmt: skip
    result = correlate(IncidentBundle.from_inputs(pod=_crash_pod(), events=[ev]))
    crash = _diag(result, FailureType.CRASH_LOOP)
    assert any("x4" in e.detail for e in crash.evidence)
    assert result.timeline[0].time == "2026-01-01T00:00:00Z"


def test_event_table_text_is_parsed():
    table = (
        "LAST SEEN   TYPE      REASON    OBJECT                    MESSAGE\n"
        "2m          Warning   BackOff   pod/app-6d4cf56db6-abcde   Back-off restarting failed container app in pod x\n"
    )
    bundle = IncidentBundle.from_inputs(pod=_crash_pod(), events=table)
    assert bundle.events[0]["reason"] == "BackOff"
    assert _diag(correlate(bundle), FailureType.CRASH_LOOP)


def test_from_inputs_accepts_json_and_yaml_strings():
    bundle = IncidentBundle.from_inputs(pod=json.dumps(_oom_pod()), manifests=deployment(APP), logs="x\n")
    assert bundle.pod["metadata"]["name"] == "app-6d4cf56db6-abcde"
    assert "manifest.yaml" in bundle.manifests and bundle.logs == "x\n"
    yaml_pod = yaml_lite.dump(_oom_pod())
    assert IncidentBundle.from_inputs(pod=yaml_pod).pod["kind"] == "Pod"


def test_from_inputs_with_manifest_objects():
    obj = yaml_lite.load(deployment(APP))
    result = correlate(IncidentBundle.from_inputs(pod=_oom_pod(), manifests=[obj]))
    assert _diag(result, FailureType.OOM_KILLED).patches


def test_missing_bundle_directory():
    with pytest.raises(FileNotFoundError):
        IncidentBundle.from_directory(EXAMPLES / "does-not-exist")


def test_json_manifest_is_patched_structurally():
    manifest = json.dumps(yaml_lite.load(deployment(APP)), indent=2) + "\n"
    p = _diag(
        correlate(IncidentBundle.from_inputs(pod=_oom_pod(), manifests={"deploy.json": manifest})),
        FailureType.OOM_KILLED,
    )
    patch = p.patches[0]
    assert patch.kind == "json"
    assert (
        json.loads(patch.patched)["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"]
        == "512Mi"
    )


def test_event_messages_are_masked_on_ingress():
    ev = event("BackOff", "Back-off restarting failed container app; DB_PASSWORD=hunter2 seen in env", count=3)
    result = correlate(IncidentBundle.from_inputs(pod=_crash_pod(), events=[ev]))
    crash = _diag(result, FailureType.CRASH_LOOP)
    assert any("[REDACTED:secret_assignment]" in e.detail for e in crash.evidence)
    assert "hunter2" not in json.dumps(result.to_dict())


def _nested_list(depth):
    root = cur = []
    for _ in range(depth):
        nxt = []
        cur.append(nxt)
        cur = nxt
    return root


def test_flattening_hostile_nesting_never_recurses():
    # Regression: on Python 3.14/macOS json.loads accepts 100k-deep arrays, after
    # which a recursive flattener blew the stack. Exercise it directly.
    assert _items(_nested_list(5000)) == []
    assert _items([[{"kind": "Pod"}]]) == [{"kind": "Pod"}]
    assert _items({"kind": 5, "items": "x"}) == [{"kind": 5, "items": "x"}]
    bundle = IncidentBundle.from_inputs(pod=pod(), docker_inspect=_nested_list(5000), events=_nested_list(5000))
    assert bundle.docker_inspect == [] and bundle.events == []


def test_redactor_secret_walk_handles_hostile_nesting():
    from src.redactor import _json_secret_value_spans

    depth = 5000
    text = '{"x": ' * depth + '{"kind": "Secret", "data": {"k": "dmFsdWU="}}' + "}" * depth
    spans = _json_secret_value_spans(text)  # must not raise, whatever json.loads does here
    # Either this interpreter's json refuses the depth (nothing found) or the
    # iterative walk reaches the Secret and locates its value exactly.
    assert spans == [] or [text[a:b] for a, b in spans] == ["dmFsdWU="]


def test_deeply_nested_json_file_is_ignored(tmp_path):
    (tmp_path / "pod.json").write_bytes((EXAMPLES / "oom_killed" / "pod.json").read_bytes())
    (tmp_path / "evil.json").write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
    assert correlate(tmp_path).primary.failure is FailureType.OOM_KILLED


def test_healthy_bundle():
    result = correlate(
        IncidentBundle.from_inputs(pod=_healthy_pod(), events=[event("Started", "Started container app", "Normal")])
    )
    assert result.healthy and result.to_dict()["primary"] is None


def test_commands_are_policy_classified():
    p = correlate(EXAMPLES / "oom_killed").primary
    verdicts = {c.command.split()[1]: c.verdict for c in p.commands}
    assert verdicts["describe"] == "SAFE_READ" and verdicts["apply"] == "APPROVAL_REQUIRED"


@pytest.mark.parametrize(
    "qty,value",
    [
        ("512Mi", 512 * 1024**2),
        ("1Gi", 1024**3),
        ("1.5Gi", 1.5 * 1024**3),
        ("250m", 0.25),
        ("2", 2.0),
        ("1e3", 1000.0),
        ("128M", 128e6),
        (3, 3.0),
    ],
)
def test_parse_quantity(qty, value):
    assert parse_quantity(qty) == pytest.approx(value)


@pytest.mark.parametrize("bad", [None, True, "lots", "12Qi", ""])
def test_parse_quantity_rejects_garbage(bad):
    assert parse_quantity(bad) is None


@pytest.mark.parametrize(
    "num,text",
    [(1024**3, "1Gi"), (768 * 1024**2, "768Mi"), (2 * 1024**3, "2Gi"), (1536 * 1024**2, "1536Mi"), (1000, "1Mi")],
)
def test_format_memory(num, text):
    assert format_memory(num) == text
