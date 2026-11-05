"""Surgical, comment-preserving edits for YAML/JSON manifests and Dockerfiles.

The correlator expresses fixes as small *edits* addressed by a YAML path
(``("spec", "template", "spec", "containers", 0, "resources")``) instead of
line numbers.  :func:`apply_edits` applies them one at a time, re-parsing the
text between edits, so the resulting unified diff only touches the lines that
really change and every other byte of the user's file is preserved.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import yaml_lite
from .yaml_lite import Document, YamlPath

__all__ = [
    "AppendItem",
    "Edit",
    "InsertKey",
    "Patch",
    "PatchError",
    "ReplaceKey",
    "SetValue",
    "apply_edits",
    "get_in",
    "make_patch",
    "unified_diff",
]


class PatchError(ValueError):
    """An edit could not be applied to the given manifest."""


@dataclass(frozen=True)
class SetValue:
    """Replace the value at ``path`` (scalar or collection)."""

    path: YamlPath
    value: Any
    doc_index: int = 0
    keep_comment: bool = False


@dataclass(frozen=True)
class InsertKey:
    """Add ``key: value`` to the mapping at ``parent_path`` (creating parents)."""

    parent_path: YamlPath
    key: str
    value: Any
    doc_index: int = 0


@dataclass(frozen=True)
class ReplaceKey:
    """Replace the entry at ``path`` by ``new_key: new_value`` (same position)."""

    path: YamlPath
    new_key: str
    new_value: Any
    doc_index: int = 0


@dataclass(frozen=True)
class AppendItem:
    """Append ``value`` to the sequence at ``path`` (creating it if missing)."""

    path: YamlPath
    value: Any
    doc_index: int = 0


Edit = Any  # Union[SetValue, InsertKey, ReplaceKey, AppendItem]


@dataclass
class Patch:
    """A file-level fix produced by the correlator."""

    file: str
    description: str
    original: str
    patched: str
    kind: str = "yaml"  # yaml | json | dockerfile
    notes: List[str] = field(default_factory=list)

    @property
    def diff(self) -> str:
        return unified_diff(self.original, self.patched, self.file)

    @property
    def changed(self) -> bool:
        return self.original != self.patched

    def to_dict(self) -> Dict[str, Any]:
        return {"file": self.file, "kind": self.kind, "description": self.description, "diff": self.diff}


# --------------------------------------------------------------------------- #
# Generic helpers
# --------------------------------------------------------------------------- #


def get_in(data: Any, path: Sequence[Any], default: Any = None) -> Any:
    cur = data
    for part in path:
        if (isinstance(cur, dict) and isinstance(part, str) and part in cur) or (
            isinstance(cur, list) and isinstance(part, int) and -len(cur) <= part < len(cur)
        ):
            cur = cur[part]
        else:
            return default
    return cur


def unified_diff(original: str, patched: str, filename: str, context: int = 3) -> str:
    """Return a ``git apply`` compatible unified diff (empty when unchanged)."""
    if original == patched:
        return ""
    a = original.splitlines(keepends=True)
    b = patched.splitlines(keepends=True)
    if a and not a[-1].endswith("\n"):
        a[-1] += "\n\\ No newline at end of file\n"
    if b and not b[-1].endswith("\n"):
        b[-1] += "\n\\ No newline at end of file\n"
    name = filename.replace("\\", "/").lstrip("/")
    lines = difflib.unified_diff(a, b, fromfile=f"a/{name}", tofile=f"b/{name}", n=context)
    return "".join(lines)


def _split(text: str) -> Tuple[List[str], str]:
    newline = "\r\n" if "\r\n" in text else "\n"
    return text.replace("\r\n", "\n").split("\n"), newline


def _join(lines: List[str], newline: str) -> str:
    return newline.join(lines)


# --------------------------------------------------------------------------- #
# YAML text edits
# --------------------------------------------------------------------------- #


def _document(text: str, doc_index: int) -> Document:
    docs = yaml_lite.parse_documents(text)
    if not 0 <= doc_index < len(docs):
        raise PatchError(f"document #{doc_index} not found (file has {len(docs)})")
    return docs[doc_index]


def _key_line_parts(line: str, col: int) -> Tuple[str, str]:
    """Split a ``key: value  # comment`` line into (prefix-through-colon, comment)."""
    segment = line[col:]
    code = yaml_lite.strip_comment(segment)
    comment = segment[len(code.rstrip()) :] if len(code) != len(segment) else ""
    kr = yaml_lite.find_key(code.rstrip())
    if kr is None:
        raise PatchError(f"cannot locate mapping key on line {line!r}")
    _, _, colon = kr
    return line[: col + colon + 1], comment


def _render_entry(key: str, value: Any, col: int, seq_indent: int) -> List[str]:
    return yaml_lite.dump_lines({key: value}, indent=col, seq_indent=seq_indent)


def _set_value(text: str, edit: SetValue) -> str:
    doc = _document(text, edit.doc_index)
    if not edit.path:
        raise PatchError("cannot replace the document root")
    span = doc.spans.get(tuple(edit.path))
    if span is None:
        raise PatchError(f"path {'.'.join(map(str, edit.path))} not found")
    lines, nl = _split(text)
    seq_indent = yaml_lite.detect_seq_indent(doc)
    last = edit.path[-1]
    if isinstance(last, int):
        line = lines[span.line]
        dash = line.index("-", span.col)
        if isinstance(edit.value, (dict, list)):
            raise PatchError("replacing a sequence item with a collection is not supported")
        lines[span.line : span.end + 1] = [line[: dash + 1] + " " + yaml_lite.format_scalar(edit.value)]
        return _join(lines, nl)
    # Keep the original key spelling/quoting and anything before it (e.g. "- ").
    # An inline comment describes the *old* value, so it goes with it unless
    # the caller asks to keep it.
    prefix, comment = _key_line_parts(lines[span.line], span.col)
    if not edit.keep_comment:
        comment = ""
    rendered = _render_entry(str(last), edit.value, span.col, seq_indent)
    if isinstance(edit.value, (dict, list)) and edit.value:
        new_lines = [prefix + comment] + rendered[1:]
    else:
        kr = yaml_lite.find_key(rendered[0][span.col :])
        value_part = kr[1].strip() if kr else yaml_lite.format_scalar(edit.value)
        new_lines = [f"{prefix} {value_part}{comment}"] + rendered[1:]
    lines[span.line : span.end + 1] = new_lines
    return _join(lines, nl)


def _insert_key(text: str, edit: InsertKey) -> str:
    doc = _document(text, edit.doc_index)
    parent_path = tuple(edit.parent_path)
    parent = get_in(doc.data, parent_path) if parent_path else doc.data
    lines, nl = _split(text)
    seq_indent = yaml_lite.detect_seq_indent(doc)

    if parent is None:
        # Create the missing parent chain: find the deepest existing ancestor.
        for depth in range(len(parent_path) - 1, -1, -1):
            anc_path = parent_path[:depth]
            anc = get_in(doc.data, anc_path) if anc_path else doc.data
            if isinstance(anc, dict):
                value: Any = {edit.key: edit.value}
                for part in reversed(parent_path[depth + 1 :]):
                    value = {part: value}
                return _insert_key(text, InsertKey(anc_path, str(parent_path[depth]), value, edit.doc_index))
        raise PatchError(f"cannot create parent path {parent_path}")
    if not isinstance(parent, dict):
        raise PatchError(f"{'.'.join(map(str, parent_path))} is not a mapping")
    if edit.key in parent:
        raise PatchError(f"key {edit.key!r} already exists at {'.'.join(map(str, parent_path))}")

    if parent:
        child_spans = [doc.spans[parent_path + (k,)] for k in parent if parent_path + (k,) in doc.spans]
        if not child_spans:
            raise PatchError("parent mapping is written in flow style; cannot insert")
        col = child_spans[0].col
        insert_at = max(s.end for s in child_spans) + 1
        lines[insert_at:insert_at] = _render_entry(edit.key, edit.value, col, seq_indent)
        return _join(lines, nl)

    # Empty parent mapping: either "key: {}" / "key:" or an empty document.
    if not parent_path:
        lines[doc.start : doc.start] = _render_entry(edit.key, edit.value, 0, seq_indent)
        return _join(lines, nl)
    pspan = doc.spans.get(parent_path)
    if pspan is None:
        raise PatchError(f"path {parent_path} not found")
    prefix, comment = _key_line_parts(lines[pspan.line], pspan.col)
    lines[pspan.line] = prefix + comment
    lines[pspan.line + 1 : pspan.line + 1] = _render_entry(edit.key, edit.value, pspan.col + 2, seq_indent)
    return _join(lines, nl)


def _replace_key(text: str, edit: ReplaceKey) -> str:
    doc = _document(text, edit.doc_index)
    span = doc.spans.get(tuple(edit.path))
    if span is None or not edit.path or not isinstance(edit.path[-1], str):
        raise PatchError(f"path {edit.path} not found")
    lines, nl = _split(text)
    seq_indent = yaml_lite.detect_seq_indent(doc)
    rendered = _render_entry(edit.new_key, edit.new_value, span.col, seq_indent)
    original_first = lines[span.line]
    rendered[0] = original_first[: span.col] + rendered[0][span.col :]
    lines[span.line : span.end + 1] = rendered
    return _join(lines, nl)


def _append_item(text: str, edit: AppendItem) -> str:
    doc = _document(text, edit.doc_index)
    path = tuple(edit.path)
    seq = get_in(doc.data, path)
    if seq is None:
        return _insert_key(text, InsertKey(path[:-1], str(path[-1]), [edit.value], edit.doc_index))
    if not isinstance(seq, list):
        raise PatchError(f"{'.'.join(map(str, path))} is not a sequence")
    if not seq:
        return _set_value(text, SetValue(path, [edit.value], edit.doc_index))
    last = doc.spans.get(path + (len(seq) - 1,))
    if last is None:
        raise PatchError("sequence is written in flow style; cannot append")
    lines, nl = _split(text)
    seq_indent = yaml_lite.detect_seq_indent(doc)
    lines[last.end + 1 : last.end + 1] = yaml_lite.dump_lines([edit.value], indent=last.col, seq_indent=seq_indent)
    return _join(lines, nl)


# --------------------------------------------------------------------------- #
# JSON structural edits
# --------------------------------------------------------------------------- #


def _json_indent(text: str) -> int:
    m = re.search(r"\n( +)\S", text)
    return len(m.group(1)) if m else 2


def _apply_json(text: str, edits: Sequence[Edit]) -> str:
    data = json.loads(text)
    root = data
    for edit in edits:
        target_root = root
        if isinstance(root, dict) and root.get("kind") == "List" and isinstance(root.get("items"), list):
            target_root = root["items"][edit.doc_index]
        if isinstance(edit, SetValue):
            parent = get_in(target_root, edit.path[:-1])
            if parent is None:
                raise PatchError(f"path {edit.path} not found")
            parent[edit.path[-1]] = edit.value
        elif isinstance(edit, InsertKey):
            parent = target_root
            for part in edit.parent_path:
                if isinstance(parent, dict):
                    parent = parent.setdefault(part, {})
                else:
                    parent = parent[part]
            if not isinstance(parent, dict):
                raise PatchError("insert target is not an object")
            parent[edit.key] = edit.value
        elif isinstance(edit, AppendItem):
            parent = get_in(target_root, edit.path[:-1])
            if not isinstance(parent, dict):
                raise PatchError(f"path {edit.path} not found")
            parent.setdefault(edit.path[-1], []).append(edit.value)
        elif isinstance(edit, ReplaceKey):
            parent = get_in(target_root, edit.path[:-1])
            if not isinstance(parent, dict):
                raise PatchError(f"path {edit.path} not found")
            items = list(parent.items())
            parent.clear()
            for k, v in items:
                if k == edit.path[-1]:
                    parent[edit.new_key] = edit.new_value
                else:
                    parent[k] = v
        else:  # pragma: no cover - defensive
            raise PatchError(f"unsupported edit {edit!r}")
    out = json.dumps(root, indent=_json_indent(text), ensure_ascii=False)
    return out + ("\n" if text.endswith("\n") else "")


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def apply_edits(text: str, edits: Sequence[Edit]) -> str:
    """Apply ``edits`` in order and return the new text."""
    if not edits:
        return text
    if text.lstrip()[:1] in ("{", "["):
        try:
            return _apply_json(text, edits)
        except json.JSONDecodeError:
            pass
    for edit in edits:
        if isinstance(edit, SetValue):
            text = _set_value(text, edit)
        elif isinstance(edit, InsertKey):
            text = _insert_key(text, edit)
        elif isinstance(edit, ReplaceKey):
            text = _replace_key(text, edit)
        elif isinstance(edit, AppendItem):
            text = _append_item(text, edit)
        else:
            raise PatchError(f"unsupported edit {edit!r}")
    return text


def make_patch(file: str, text: str, edits: Sequence[Edit], description: str) -> Optional[Patch]:
    """Build a :class:`Patch` or return ``None`` if the edits change nothing."""
    try:
        patched = apply_edits(text, edits)
    except (PatchError, yaml_lite.YamlError, KeyError, IndexError, TypeError):
        return None
    if patched == text:
        return None
    kind = "json" if text.lstrip()[:1] in ("{", "[") else "yaml"
    return Patch(file=file, description=description, original=text, patched=patched, kind=kind)
