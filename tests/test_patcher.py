import json

import pytest

from src import yaml_lite
from src.patcher import (
    AppendItem,
    InsertKey,
    PatchError,
    ReplaceKey,
    SetValue,
    apply_edits,
    get_in,
    make_patch,
    unified_diff,
)

BASE = """apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: api   # main container
        image: app:1
        resources:
          limits:
            memory: 512Mi  # old value
        env:
        - name: A
          value: "1"
      nodeSelector: {}
"""
C = ("spec", "template", "spec", "containers", 0)


def _changed_lines(diff: str):
    return [ln for ln in diff.splitlines() if ln[:1] in "+-" and not ln.startswith(("+++", "---"))]


def test_set_value_is_minimal_and_drops_stale_comment():
    out = apply_edits(BASE, [SetValue((*C, "resources", "limits", "memory"), "1Gi")])
    assert "            memory: 1Gi\n" in out
    assert "# old value" not in out
    assert "# main container" in out  # untouched lines keep their comments
    assert _changed_lines(unified_diff(BASE, out, "d.yaml")) == [
        "-            memory: 512Mi  # old value",
        "+            memory: 1Gi",
    ]


def test_set_value_can_keep_comment():
    out = apply_edits(BASE, [SetValue((*C, "resources", "limits", "memory"), "1Gi", keep_comment=True)])
    assert "memory: 1Gi  # old value" in out


def test_set_value_on_first_key_of_sequence_item_keeps_dash():
    out = apply_edits(BASE, [SetValue((*C, "name"), "web")])
    assert "      - name: web\n" in out


def test_insert_key_indents_like_siblings():
    out = apply_edits(BASE, [InsertKey((*C, "resources", "limits"), "cpu", "500m")])
    assert "            memory: 512Mi  # old value\n            cpu: 500m\n" in out


def test_insert_key_creates_missing_parents():
    out = apply_edits(BASE, [InsertKey((*C, "resources", "requests"), "memory", "256Mi")])
    data = yaml_lite.load(out)
    assert get_in(data, (*C, "resources", "requests", "memory")) == "256Mi"


def test_insert_key_into_flow_empty_mapping():
    out = apply_edits(BASE, [InsertKey(("spec", "template", "spec", "nodeSelector"), "disk", "ssd")])
    assert "      nodeSelector:\n        disk: ssd\n" in out


def test_insert_existing_key_is_an_error():
    with pytest.raises(PatchError):
        apply_edits(BASE, [InsertKey(C, "image", "x")])


def test_replace_key_with_block():
    out = apply_edits(
        BASE, [ReplaceKey((*C, "env", 0, "value"), "valueFrom", {"secretKeyRef": {"name": "s", "key": "k"}})]
    )
    env = yaml_lite.load(out)["spec"]["template"]["spec"]["containers"][0]["env"][0]
    assert env == {"name": "A", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}


def test_append_item_to_existing_sequence():
    out = apply_edits(BASE, [AppendItem((*C, "env"), {"name": "B", "value": "2"})])
    env = yaml_lite.load(out)["spec"]["template"]["spec"]["containers"][0]["env"]
    assert env[-1] == {"name": "B", "value": "2"}
    assert '        - name: B\n          value: "2"\n' in out


def test_append_item_creates_sequence():
    out = apply_edits(BASE, [AppendItem((*C, "args"), "--verbose")])
    assert yaml_lite.load(out)["spec"]["template"]["spec"]["containers"][0]["args"] == ["--verbose"]


def test_append_item_to_flow_empty_sequence():
    out = apply_edits("a:\n  items: []\n", [AppendItem(("a", "items"), {"x": 1})])
    assert yaml_lite.load(out) == {"a": {"items": [{"x": 1}]}}


def test_sequence_indent_style_is_preserved():
    indented = "spec:\n  items:\n    - a\n  other: 1\n"
    out = apply_edits(indented, [InsertKey(("spec",), "list", ["x"])])
    assert "  list:\n    - x\n" in out
    compact = "spec:\n  items:\n  - a\n"
    out = apply_edits(compact, [InsertKey(("spec",), "list", ["x"])])
    assert "  list:\n  - x\n" in out


def test_multi_document_targets_the_right_document():
    text = "kind: A\nv: 1\n---\nkind: B\nv: 1\n"
    out = apply_edits(text, [SetValue(("v",), 2, doc_index=1)])
    assert out == "kind: A\nv: 1\n---\nkind: B\nv: 2\n"


def test_json_manifest_edit_preserves_indentation():
    text = json.dumps({"spec": {"ports": [{"port": 80, "targetPort": 8080}]}}, indent=4) + "\n"
    out = apply_edits(text, [SetValue(("spec", "ports", 0, "targetPort"), "http")])
    assert json.loads(out)["spec"]["ports"][0]["targetPort"] == "http"
    assert '\n    "spec"' in out and out.endswith("\n")


def test_crlf_line_endings_are_preserved():
    text = BASE.replace("\n", "\r\n")
    out = apply_edits(text, [SetValue((*C, "image"), "app:2")])
    assert "image: app:2\r\n" in out
    assert "\n" not in out.replace("\r\n", "")


def test_unified_diff_format():
    assert unified_diff("a\n", "a\n", "x.yaml") == ""
    diff = unified_diff("a\nb\n", "a\nc\n", "dir\\x.yaml")
    assert diff.startswith("--- a/dir/x.yaml\n+++ b/dir/x.yaml\n@@")
    assert "\\ No newline at end of file" in unified_diff("a", "b", "f")


def test_make_patch_returns_none_on_failure_or_noop():
    assert make_patch("d.yaml", BASE, [SetValue(("missing", "path"), 1)], "x") is None
    assert make_patch("d.yaml", BASE, [SetValue((*C, "image"), "app:1")], "x") is None
    patch = make_patch("d.yaml", BASE, [SetValue((*C, "image"), "app:2")], "bump")
    assert patch is not None and patch.changed and patch.to_dict()["file"] == "d.yaml"


def test_get_in():
    data = {"a": [{"b": 1}]}
    assert get_in(data, ("a", 0, "b")) == 1
    assert get_in(data, ("a", 5, "b"), "dflt") == "dflt"
    assert get_in(data, ("x",)) is None
