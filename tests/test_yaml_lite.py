import math

import pytest

from src import yaml_lite as y


@pytest.mark.parametrize(
    "text,expected",
    [
        ("a: true", True),
        ("a: False", False),
        ("a: null", None),
        ("a: ~", None),
        ("a:", None),
        ("a: 42", 42),
        ("a: -7", -7),
        ("a: 0x1F", 31),
        ("a: 0o17", 15),
        ("a: 0644", 420),
        ("a: 1.5", 1.5),
        ("a: 1e3", 1000.0),
        ("a: '42'", "42"),
        ('a: "true"', "true"),
        ("a: 256Mi", "256Mi"),
        ("a: nginx:1.25", "nginx:1.25"),
        ("a: http://example.com/x#frag", "http://example.com/x#frag"),
        ("a: yes", "yes"),
        ("a: v1.2.3", "v1.2.3"),
        ("a: 500m", "500m"),
    ],
)
def test_scalar_resolution(text, expected):
    assert y.load(text)["a"] == expected


def test_special_floats():
    data = y.load("a: .inf\nb: -.inf\nc: .nan\n")
    assert data["a"] == math.inf and data["b"] == -math.inf and math.isnan(data["c"])


def test_double_quoted_escapes():
    assert y.load(r'a: "x\ny\t\u00e9\x41 \"q\""')["a"] == 'x\ny\téA "q"'


def test_single_quoted_doubling():
    assert y.load("a: 'it''s fine'")["a"] == "it's fine"


@pytest.mark.parametrize(
    "line,expected",
    [
        ("a: b # comment", "b"),
        ("a: 'b # not a comment'", "b # not a comment"),
        ('a: "b # nope"', "b # nope"),
        ("a: don't # comment", "don't"),
        ("a: x#y", "x#y"),
    ],
)
def test_comments(line, expected):
    assert y.load(line)["a"] == expected


def test_block_scalars_and_chomping():
    text = "lit: |\n  one\n  # not a comment\n  two\n\nstrip: |-\n  x\n  y\nkeep: |+\n  k\n\nfold: >\n  a\n  b\n\n  c\nfoldstrip: >-\n  p\n  q\n"
    d = y.load(text)
    assert d["lit"] == "one\n# not a comment\ntwo\n"
    assert d["strip"] == "x\ny"
    assert d["keep"] == "k\n\n"
    assert d["fold"] == "a b\nc\n"
    assert d["foldstrip"] == "p q"


def test_block_scalar_explicit_indent():
    assert y.load("a: |2\n    indented\n  base\n")["a"] == "  indented\nbase\n"


def test_flow_collections_nested():
    d = y.load('a: [1, "two", {b: c, d: [x, y]}, [], {}]\nb: {k: v, "q": 3}')
    assert d == {"a": [1, "two", {"b": "c", "d": ["x", "y"]}, [], {}], "b": {"k": "v", "q": 3}}


def test_multiline_flow():
    assert y.load("args: [\n  --port, 8080,\n  --verbose\n]\n") == {"args": ["--port", 8080, "--verbose"]}


def test_compact_and_indented_sequences_equal():
    compact = "containers:\n- name: a\n  image: x\n- name: b\nother: 1\n"
    indented = "containers:\n  - name: a\n    image: x\n  - name: b\nother: 1\n"
    assert (
        y.load(compact) == y.load(indented) == {"containers": [{"name": "a", "image": "x"}, {"name": "b"}], "other": 1}
    )


def test_nested_sequence_inline():
    assert y.load("- - a\n  - b\n- - c\n") == [["a", "b"], ["c"]]


def test_sequence_of_maps_with_nested_maps():
    d = y.load(
        "env:\n- name: A\n  valueFrom:\n    secretKeyRef:\n      name: s\n      key: k\n- name: B\n  value: '1'\n"
    )
    assert d["env"][0]["valueFrom"]["secretKeyRef"] == {"name": "s", "key": "k"}
    assert d["env"][1] == {"name": "B", "value": "1"}


def test_multi_document_stream():
    text = "# leading comment\n---\na: 1\n---\n# only a comment\n---\nb: 2\n...\n"
    assert y.load_all(text) == [{"a": 1}, {"b": 2}]


def test_load_rejects_multiple_documents():
    with pytest.raises(y.YamlError):
        y.load("a: 1\n---\nb: 2\n")


def test_empty_stream():
    assert y.load("") is None
    assert y.load_all("# nothing\n") == []


def test_spans_point_at_exact_lines():
    text = "spec:\n  containers:\n  - name: app\n    resources:\n      limits:\n        memory: 512Mi\n"
    doc = y.parse_documents(text)[0]
    span = doc.spans[("spec", "containers", 0, "resources", "limits", "memory")]
    assert (span.line, span.col, span.end) == (5, 8, 5)
    item = doc.spans[("spec", "containers", 0)]
    assert item.line == 2 and item.end == 5
    assert doc.spans[("spec", "containers", 0, "name")].col == 4


def test_detect_seq_indent():
    compact = y.parse_documents("a:\n- 1\n")[0]
    indented = y.parse_documents("a:\n  - 1\n")[0]
    assert y.detect_seq_indent(compact) == 0
    assert y.detect_seq_indent(indented) == 2


@pytest.mark.parametrize(
    "bad,fragment",
    [
        ("a: 1\na: 2\n", "duplicate"),
        ("a:\n\t b: 1\n", "tab"),
        ("a: 1\n   b: 2\n", "indentation"),
        ('a: "unterminated\n', "unterminated"),
        ("a: [1, 2\n", "unterminated"),
    ],
)
def test_errors_carry_line_numbers(bad, fragment):
    with pytest.raises(y.YamlError) as exc:
        y.load(bad)
    assert fragment in str(exc.value).lower()


def test_json_input_and_list_expansion():
    assert y.load('{"a": [1, 2]}') == {"a": [1, 2]}
    docs = y.parse_documents('{"kind": "List", "items": [{"kind": "Pod"}, {"kind": "Service"}]}')
    assert [d.data["kind"] for d in docs] == ["Pod", "Service"]


def test_anchors_aliases_and_merge_keys():
    d = y.load("base: &b\n  cpu: 1\n  mem: 2\nother:\n  <<: *b\n  mem: 3\ncopy: *b\n")
    assert d["other"] == {"mem": 3, "cpu": 1}
    assert d["copy"] == {"cpu": 1, "mem": 2}


def test_bom_and_crlf():
    assert y.load("\ufeffa: 1\r\nb: two\r\n") == {"a": 1, "b": "two"}


def test_multiline_plain_scalar_folds():
    assert y.load("msg: this is\n  continued here\n") == {"msg": "this is continued here"}


def test_keys_are_strings():
    assert y.load("8080: http\ntrue: x\n") == {"8080": "http", "true": "x"}


@pytest.mark.parametrize(
    "data",
    [
        {"a": 1, "b": [1, 2, {"c": "d"}], "e": {}},
        [{"name": "x", "ports": [{"containerPort": 80}]}, [], {}],
        {"multi": "line one\nline two\n", "strip": "no newline\nat end", "empty": ""},
        {"tricky": ["true", "123", "0644", "a: b", "- x", "#c", " pad", "null", "1e3", "yes"]},
        {"unicode": "héllo ✓ 🚀", "nested": {"deep": {"deeper": [None, True, False, 1.5]}}},
    ],
)
def test_dump_round_trip(data):
    for seq_indent in (0, 2):
        assert y.load(y.dump(data, seq_indent=seq_indent)) == data


@pytest.mark.parametrize(
    "value,rendered",
    [
        (None, "null"),
        (True, "true"),
        (1.5, "1.5"),
        ("plain", "plain"),
        ("true", '"true"'),
        ("123", '"123"'),
        ("", '""'),
        ("a: b", '"a: b"'),
        ("-x", '"-x"'),
        ("0644", '"0644"'),
    ],
)
def test_format_scalar(value, rendered):
    assert y.format_scalar(value) == rendered


def test_find_key_variants():
    assert y.find_key("image: nginx:1.25")[0] == "image"
    assert y.find_key('"a: b": c')[0] == '"a: b"'
    assert y.find_key("- item") is None
    assert y.find_key("http://x") is None
    assert y.find_key("[a, b]") is None
