"""Dependency-free YAML subset loader/dumper tuned for Kubernetes manifests.

KubeGuard must run with *zero* third-party packages, so instead of PyYAML we
ship a small, strict parser for the subset of YAML that Kubernetes manifests,
Docker Compose files and kubeconfigs actually use:

* block mappings and block sequences (including the "compact" style where the
  ``-`` sits at the same indentation as its parent key, as kubectl emits),
* plain, single-quoted and double-quoted scalars (with escapes),
* flow collections (``[a, b]``, ``{k: v}``), including multi-line ones,
* literal/folded block scalars (``|``, ``|-``, ``>``, ``>+`` ...),
* comments, multi-document streams (``---``), simple anchors/aliases.

Unlike a general purpose loader, every node also records a :class:`NodeSpan`
(line, column, last line) so that :mod:`src.patcher` can rewrite *exactly* the
lines that need to change and produce a minimal unified diff that preserves
the user's comments and formatting.

Mapping keys are always loaded as strings (mirroring ``sigs.k8s.io/yaml``,
which round-trips through JSON).
"""

from __future__ import annotations

import copy
import json
import math
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "Document",
    "NodeSpan",
    "YamlError",
    "detect_seq_indent",
    "dump",
    "dump_all",
    "find_key",
    "format_scalar",
    "load",
    "load_all",
    "parse_documents",
    "strip_comment",
]

YamlPath = Tuple[Any, ...]


class YamlError(ValueError):
    """Raised when the input is not valid (supported) YAML."""

    def __init__(self, message: str, line: Optional[int] = None) -> None:
        self.line = line  # 1-based line number, when known
        self.reason = message
        super().__init__(f"line {line}: {message}" if line else message)


@dataclass(frozen=True)
class NodeSpan:
    """Location of a mapping key or sequence item in the source text.

    ``line``/``end`` are 0-based line indexes (inclusive); ``col`` is the column
    of the key (for mapping entries) or of the dash (for sequence items).
    """

    line: int
    col: int
    end: int


@dataclass
class Document:
    """A parsed YAML document plus the span of every node inside it."""

    data: Any
    spans: Dict[YamlPath, NodeSpan]
    start: int
    end: int


# --------------------------------------------------------------------------- #
# Scalar helpers
# --------------------------------------------------------------------------- #

_INT_RE = re.compile(r"^[-+]?(?:0|[1-9][0-9_]*)$")
_HEX_RE = re.compile(r"^0x[0-9a-fA-F_]+$")
_OCT_RE = re.compile(r"^0o[0-7_]+$")
_LEGACY_OCT_RE = re.compile(r"^0[0-7]+$")  # YAML 1.1 (go-yaml / kubectl) octal
_FLOAT_RE = re.compile(r"^[-+]?(?:\.[0-9]+|[0-9][0-9_]*\.[0-9_]*|[0-9][0-9_]*(?:\.[0-9_]*)?[eE][-+]?[0-9]+)$")
_INF_RE = re.compile(r"^[-+]?\.(?:inf|Inf|INF)$")
_NAN_RE = re.compile(r"^\.(?:nan|NaN|NAN)$")

_NULLS = frozenset({"", "~", "null", "Null", "NULL"})
_TRUES = frozenset({"true", "True", "TRUE"})
_FALSES = frozenset({"false", "False", "FALSE"})

_DQ_ESCAPES = {
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "\t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    " ": " ",
    '"': '"',
    "/": "/",
    "\\": "\\",
    "N": "\x85",
    "_": "\xa0",
    "L": " ",
    "P": " ",
}


def resolve_plain(text: str) -> Any:
    """Resolve an unquoted scalar into a Python value (YAML 1.2 core schema)."""
    s = text.strip()
    if s in _NULLS:
        return None
    if s in _TRUES:
        return True
    if s in _FALSES:
        return False
    if _INT_RE.match(s):
        return int(s.replace("_", ""))
    if _LEGACY_OCT_RE.match(s):
        return int(s, 8)
    if _HEX_RE.match(s):
        return int(s.replace("_", ""), 16)
    if _OCT_RE.match(s):
        return int(s[2:].replace("_", ""), 8)
    if _FLOAT_RE.match(s):
        return float(s.replace("_", ""))
    if _INF_RE.match(s):
        return float("-inf") if s.startswith("-") else float("inf")
    if _NAN_RE.match(s):
        return float("nan")
    return s


def _unescape_double(body: str, line: Optional[int]) -> str:
    out: List[str] = []
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        if i + 1 >= n:
            raise YamlError("dangling escape in double-quoted scalar", line)
        e = body[i + 1]
        if e in _DQ_ESCAPES:
            out.append(_DQ_ESCAPES[e])
            i += 2
        elif e in "xuU":
            width = {"x": 2, "u": 4, "U": 8}[e]
            hexpart = body[i + 2 : i + 2 + width]
            if len(hexpart) != width or not re.fullmatch(r"[0-9a-fA-F]+", hexpart):
                raise YamlError(f"invalid \\{e} escape", line)
            out.append(chr(int(hexpart, 16)))
            i += 2 + width
        else:
            raise YamlError(f"unknown escape sequence \\{e}", line)
    return "".join(out)


def _find_closing_quote(s: str, start: int) -> int:
    """Index of the quote closing the quoted scalar that opens at ``start``."""
    q = s[start]
    i = start + 1
    n = len(s)
    while i < n:
        c = s[i]
        if q == '"' and c == "\\":
            i += 2
            continue
        if c == q:
            if q == "'" and i + 1 < n and s[i + 1] == "'":
                i += 2
                continue
            return i
        i += 1
    return -1


def _parse_quoted(s: str, line: Optional[int]) -> str:
    q = s[0]
    end = _find_closing_quote(s, 0)
    if end < 0:
        raise YamlError("unterminated quoted scalar", line)
    if s[end + 1 :].strip():
        raise YamlError(f"unexpected characters after quoted scalar: {s[end + 1 :]!r}", line)
    body = s[1:end]
    if q == "'":
        return body.replace("''", "'")
    return _unescape_double(body, line)


def _quote_can_open(s: str, i: int) -> bool:
    j = i - 1
    while j >= 0 and s[j] in " \t":
        j -= 1
    return j < 0 or s[j] in ":-[{,?"


def strip_comment(s: str) -> str:
    """Remove a trailing ``# comment`` (respecting quotes)."""
    if "#" not in s:
        return s
    in_s = in_d = False
    prev = " "
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if in_d:
            if c == "\\":
                prev = c
                i += 2
                continue
            if c == '"':
                in_d = False
        elif in_s:
            if c == "'":
                if i + 1 < n and s[i + 1] == "'":
                    i += 2
                    continue
                in_s = False
        else:
            if c == "#" and prev in " \t":
                return s[:i]
            if c == '"' and _quote_can_open(s, i):
                in_d = True
            elif c == "'" and _quote_can_open(s, i):
                in_s = True
        prev = c
        i += 1
    return s


_KEY_SEP_RE = re.compile(r":(?=\s|$)")


def find_key(content: str) -> Optional[Tuple[str, str, int]]:
    """Split ``key: value`` content.

    Returns ``(raw_key, rest, colon_index)`` or ``None`` when ``content`` is not a
    block mapping entry.  ``raw_key`` keeps its quotes, if any.
    """
    if not content or content[0] in "[{":
        return None
    if content[0] in "\"'":
        end = _find_closing_quote(content, 0)
        if end < 0:
            return None
        j = end + 1
        while j < len(content) and content[j] in " \t":
            j += 1
        if j < len(content) and content[j] == ":" and (j + 1 == len(content) or content[j + 1] in " \t"):
            return content[: end + 1], content[j + 1 :], j
        return None
    if content.startswith(("- ", "? ")) or content in ("-", "?"):
        return None
    m = _KEY_SEP_RE.search(content)
    if not m:
        return None
    j = m.start()
    key = content[:j].rstrip()
    if not key:
        return None
    return key, content[j + 1 :], j


def _parse_key(raw: str, line: int) -> str:
    raw = raw.strip()
    if raw and raw[0] in "\"'":
        return _parse_quoted(raw, line)
    return raw


def _is_seq_item(content: str) -> bool:
    return content == "-" or content.startswith("- ") or content.startswith("-\t")


def _brackets_balanced(s: str) -> bool:
    depth = 0
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c in "\"'" and _quote_can_open(s, i):
            end = _find_closing_quote(s, i)
            if end < 0:
                return False
            i = end + 1
            continue
        if c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
        i += 1
    return depth <= 0


# --------------------------------------------------------------------------- #
# Flow collections
# --------------------------------------------------------------------------- #


class _FlowParser:
    def __init__(self, s: str, line: int, anchors: Dict[str, Any]) -> None:
        self.s = s
        self.pos = 0
        self.line = line
        self.anchors = anchors

    def error(self, msg: str) -> YamlError:
        return YamlError(f"{msg} in flow collection {self.s!r}", self.line)

    def ws(self) -> None:
        while self.pos < len(self.s) and self.s[self.pos] in " \t\r\n":
            self.pos += 1

    def parse(self) -> Any:
        self.ws()
        value = self.value()
        self.ws()
        if self.pos != len(self.s):
            raise self.error("unexpected trailing characters")
        return value

    def value(self) -> Any:
        self.ws()
        if self.pos >= len(self.s):
            raise self.error("unexpected end")
        c = self.s[self.pos]
        if c == "[":
            return self.seq()
        if c == "{":
            return self.mapping()
        if c in "\"'":
            return self.quoted()
        if c == "*":
            name = self.plain(stop_on_colon=False)[1:]
            if name not in self.anchors:
                raise self.error(f"unknown alias *{name}")
            return copy.deepcopy(self.anchors[name])
        return resolve_plain(self.plain(stop_on_colon=False))

    def quoted(self) -> str:
        end = _find_closing_quote(self.s, self.pos)
        if end < 0:
            raise self.error("unterminated quoted scalar")
        text = self.s[self.pos : end + 1]
        self.pos = end + 1
        return _parse_quoted(text, self.line)

    def plain(self, stop_on_colon: bool) -> str:
        start = self.pos
        while self.pos < len(self.s):
            c = self.s[self.pos]
            if c in ",[]{}":
                break
            if c == ":" and (self.pos + 1 >= len(self.s) or self.s[self.pos + 1] in " ,]}\t") and stop_on_colon:
                break
            self.pos += 1
        return self.s[start : self.pos].strip()

    def seq(self) -> List[Any]:
        self.pos += 1
        out: List[Any] = []
        while True:
            self.ws()
            if self.pos >= len(self.s):
                raise self.error("unterminated sequence")
            if self.s[self.pos] == "]":
                self.pos += 1
                return out
            item = self.value()
            self.ws()
            # single-pair mapping inside a flow sequence: [a: 1]
            if self.pos < len(self.s) and self.s[self.pos] == ":":
                self.pos += 1
                val = self.value()
                item = {str(item): val}
                self.ws()
            out.append(item)
            if self.pos < len(self.s) and self.s[self.pos] == ",":
                self.pos += 1
            elif self.pos < len(self.s) and self.s[self.pos] == "]":
                continue
            else:
                raise self.error("expected ',' or ']'")

    def mapping(self) -> Dict[str, Any]:
        self.pos += 1
        out: Dict[str, Any] = {}
        while True:
            self.ws()
            if self.pos >= len(self.s):
                raise self.error("unterminated mapping")
            if self.s[self.pos] == "}":
                self.pos += 1
                return out
            if self.s[self.pos] in "\"'":
                key = self.quoted()
            else:
                key = self.plain(stop_on_colon=True)
            self.ws()
            value: Any = None
            if self.pos < len(self.s) and self.s[self.pos] == ":":
                self.pos += 1
                self.ws()
                if self.pos < len(self.s) and self.s[self.pos] not in ",}":
                    value = self.value()
            out[str(key)] = value
            self.ws()
            if self.pos < len(self.s) and self.s[self.pos] == ",":
                self.pos += 1
            elif self.pos < len(self.s) and self.s[self.pos] == "}":
                continue
            else:
                raise self.error("expected ',' or '}'")


# --------------------------------------------------------------------------- #
# Block parser
# --------------------------------------------------------------------------- #

_BLOCK_HEADER_RE = re.compile(r"^([|>])(?:([+-])([1-9])?|([1-9])([+-])?)?$")


class _Parser:
    def __init__(self, lines: List[str], start: int, end: int) -> None:
        self.lines = lines
        self.i = start
        self.end = end
        self.start = start
        self.last = start - 1
        self.spans: Dict[YamlPath, NodeSpan] = {}
        self.virtual: Dict[int, Tuple[int, str]] = {}
        self.anchors: Dict[str, Any] = {}

    # -- line access ------------------------------------------------------- #
    def _logical(self, idx: int) -> Tuple[int, str]:
        if idx in self.virtual:
            return self.virtual[idx]
        raw = self.lines[idx]
        stripped = raw.lstrip(" ")
        indent = len(raw) - len(stripped)
        if stripped.startswith("\t") and stripped.strip():
            raise YamlError("tab characters are not allowed for indentation", idx + 1)
        content = strip_comment(stripped).rstrip()
        return indent, content

    def peek(self) -> Optional[Tuple[int, int, str]]:
        while self.i < self.end:
            indent, content = self._logical(self.i)
            if content == "":
                self.i += 1
                continue
            return self.i, indent, content
        return None

    def consume(self) -> None:
        self.last = max(self.last, self.i)
        self.i += 1

    # -- nodes ------------------------------------------------------------- #
    def parse_document(self) -> Any:
        pk = self.peek()
        if pk is None:
            return None
        value = self.parse_block(())
        rest = self.peek()
        if rest is not None:
            raise YamlError(f"unexpected content {rest[2]!r} (check indentation)", rest[0] + 1)
        return value

    def parse_block(self, path: YamlPath) -> Any:
        pk = self.peek()
        assert pk is not None
        idx, indent, content = pk
        if _is_seq_item(content):
            return self.parse_seq(indent, path)
        if find_key(content) is not None:
            return self.parse_map(indent, path)
        self.consume()
        return self.parse_inline(content, indent - 1, idx, path, allow_compact_seq=False)

    def parse_map(self, indent: int, path: YamlPath) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        merged_keys = set()  # keys pulled in by "<<: *alias" may be overridden
        while True:
            pk = self.peek()
            if pk is None:
                break
            idx, ind, content = pk
            if ind < indent:
                break
            if ind > indent:
                raise YamlError("bad indentation of a mapping entry", idx + 1)
            if _is_seq_item(content):
                raise YamlError("sequence item not allowed here (check indentation)", idx + 1)
            kr = find_key(content)
            if kr is None:
                raise YamlError(f"expected 'key: value' but found {content!r}", idx + 1)
            raw_key, rest, _ = kr
            if raw_key.startswith("? "):
                raise YamlError("complex mapping keys are not supported", idx + 1)
            key = _parse_key(raw_key, idx + 1)
            if key == "<<":
                self.consume()
                merged = self.parse_inline(rest, ind, idx, path + (key,), allow_compact_seq=True)
                sources = merged if isinstance(merged, list) else [merged]
                for src in sources:
                    if isinstance(src, dict):
                        for k, v in src.items():
                            if k not in result:
                                result[k] = v
                                merged_keys.add(k)
                continue
            if key in result and key not in merged_keys:
                raise YamlError(f"duplicate mapping key {key!r}", idx + 1)
            merged_keys.discard(key)
            self.consume()
            kpath = path + (key,)
            result[key] = self.parse_inline(rest, ind, idx, kpath, allow_compact_seq=True)
            self.spans[kpath] = NodeSpan(idx, ind, self.last)
        return result

    def parse_seq(self, indent: int, path: YamlPath) -> List[Any]:
        result: List[Any] = []
        while True:
            pk = self.peek()
            if pk is None:
                break
            idx, ind, content = pk
            if ind < indent or not _is_seq_item(content):
                if ind > indent:
                    raise YamlError("bad indentation of a sequence entry", idx + 1)
                break
            if ind > indent:
                raise YamlError("bad indentation of a sequence entry", idx + 1)
            ipath = path + (len(result),)
            after = content[1:]
            stripped = after.lstrip(" \t")
            if stripped == "":
                self.consume()
                nxt = self.peek()
                value = self.parse_block(ipath) if nxt is not None and nxt[1] > indent else None
            else:
                col = ind + 1 + (len(after) - len(stripped))
                if _is_seq_item(stripped) or find_key(stripped) is not None:
                    self.virtual[idx] = (col, stripped)
                    value = self.parse_block(ipath)
                else:
                    self.consume()
                    value = self.parse_inline(stripped, ind, idx, ipath, allow_compact_seq=False)
            result.append(value)
            self.spans[ipath] = NodeSpan(idx, ind, self.last)
        return result

    def parse_inline(
        self,
        rest: str,
        parent_indent: int,
        idx: int,
        path: YamlPath,
        allow_compact_seq: bool,
    ) -> Any:
        rest = rest.strip()
        anchor: Optional[str] = None
        force_str = False
        # node properties: tags and anchors (in any order)
        while rest[:1] in ("!", "&"):
            token, _, remainder = rest.partition(" ")
            if token.startswith("&"):
                anchor = token[1:]
            elif token in ("!!str", "!str"):
                force_str = True
            rest = remainder.strip()
        value = self._parse_inline_value(rest, parent_indent, idx, path, allow_compact_seq)
        if force_str and value is not None and not isinstance(value, str):
            value = rest
        if anchor:
            self.anchors[anchor] = value
        return value

    def _parse_inline_value(
        self,
        rest: str,
        parent_indent: int,
        idx: int,
        path: YamlPath,
        allow_compact_seq: bool,
    ) -> Any:
        if rest == "":
            nxt = self.peek()
            if nxt is not None:
                _, nind, ncontent = nxt
                if nind > parent_indent:
                    return self.parse_block(path)
                if allow_compact_seq and nind == parent_indent and _is_seq_item(ncontent):
                    return self.parse_seq(nind, path)
            return None
        c = rest[0]
        if c in "|>":
            return self.parse_block_scalar(rest, parent_indent, idx)
        if c in "[{":
            return self.parse_flow(rest, idx)
        if c == "*":
            name = rest[1:].strip()
            if name not in self.anchors:
                raise YamlError(f"unknown alias *{name}", idx + 1)
            return copy.deepcopy(self.anchors[name])
        if c in "\"'":
            end = _find_closing_quote(rest, 0)
            if end < 0:
                rest = self._continue_quoted(rest, idx)
            return _parse_quoted(rest, idx + 1)
        if rest[0] in "@`":
            raise YamlError(f"reserved indicator {rest[0]!r} cannot start a plain scalar", idx + 1)
        # multi-line plain scalar: fold continuation lines that are more indented
        parts = [rest]
        while True:
            nxt = self.peek()
            if nxt is None or nxt[1] <= parent_indent:
                break
            nidx, _, ncontent = nxt
            if find_key(ncontent) is not None or _is_seq_item(ncontent):
                raise YamlError("mapping values are not allowed here (check indentation)", nidx + 1)
            parts.append(ncontent.strip())
            self.consume()
        if len(parts) > 1:
            return " ".join(parts)
        return resolve_plain(rest)

    def _continue_quoted(self, first: str, idx: int) -> str:
        pieces = [first]
        q = first[0]
        while self.i < self.end:
            raw = self.lines[self.i].strip()
            self.consume()
            pieces.append(raw)
            joined = " ".join(pieces)
            if _find_closing_quote(joined, 0) >= 0:
                return joined
        raise YamlError(f"unterminated {q}quoted scalar", idx + 1)

    def parse_flow(self, rest: str, idx: int) -> Any:
        text = rest
        while not _brackets_balanced(text):
            if self.i >= self.end:
                raise YamlError("unterminated flow collection", idx + 1)
            raw = self.lines[self.i]
            self.consume()
            text += " " + strip_comment(raw.strip())
        return _FlowParser(text, idx + 1, self.anchors).parse()

    def parse_block_scalar(self, header: str, parent_indent: int, idx: int) -> str:
        m = _BLOCK_HEADER_RE.match(header.strip())
        if not m:
            raise YamlError(f"invalid block scalar header {header!r}", idx + 1)
        style = m.group(1)
        chomp = m.group(2) or m.group(5) or ""
        explicit = m.group(3) or m.group(4)
        block_indent: Optional[int] = max(parent_indent, 0) + int(explicit) if explicit else None
        collected: List[str] = []
        while self.i < self.end:
            raw = self.lines[self.i]
            if raw.strip() == "":
                collected.append("")
                self.i += 1
                continue
            ind = len(raw) - len(raw.lstrip(" "))
            if block_indent is None:
                if ind <= parent_indent:
                    break
                block_indent = ind
            if ind < block_indent:
                break
            collected.append(raw[block_indent:])
            self.consume()
        # trailing blank lines are part of the chomping decision
        trailing = 0
        while collected and collected[-1] == "":
            collected.pop()
            trailing += 1
        if style == "|":
            core = "\n".join(collected)
        else:
            core = _fold(collected)
        if not collected:
            return "\n" * trailing if chomp == "+" else ""
        if chomp == "-":
            return core
        if chomp == "+":
            return core + "\n" * (1 + trailing)
        return core + "\n"


def _fold(lines: List[str]) -> str:
    out = ""
    for i, line in enumerate(lines):
        if i == 0:
            out = line
            continue
        prev = lines[i - 1]
        if line == "":
            out += "\n"
        elif prev == "":
            out += line
        elif line[:1] in (" ", "\t") or prev[:1] in (" ", "\t"):
            out += "\n" + line
        else:
            out += " " + line
    return out


# --------------------------------------------------------------------------- #
# Public loading API
# --------------------------------------------------------------------------- #


def _split_documents(lines: List[str]) -> List[Tuple[int, int]]:
    ranges: List[Tuple[int, int]] = []
    start = 0
    for i, line in enumerate(lines):
        if line.startswith("---") and (len(line.rstrip()) == 3 or line[3] in " \t"):
            ranges.append((start, i))
            start = i + 1
            trailing = strip_comment(line[3:]).strip()
            if trailing:
                raise YamlError("content on the '---' document marker line is not supported", i + 1)
        elif line.rstrip() == "...":
            ranges.append((start, i))
            start = i + 1
        elif line.startswith("%") and i == start:
            start = i + 1  # directive (%YAML / %TAG)
    ranges.append((start, len(lines)))
    out = []
    for s, e in ranges:
        if any(strip_comment(ln).strip() for ln in lines[s:e]):
            out.append((s, e))
    return out


def _looks_like_json(text: str) -> bool:
    s = text.lstrip()
    return s[:1] in ("{", "[")


def _split_lines(text: str) -> List[str]:
    if text.startswith("﻿"):
        text = text[1:]
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def parse_documents(text: str) -> List[Document]:
    """Parse every non-empty document in ``text`` keeping node spans."""
    if _looks_like_json(text):
        try:
            data = json.loads(text)
        except ValueError:
            pass
        else:
            lines = _split_lines(text)
            if isinstance(data, dict) and data.get("kind") == "List" and isinstance(data.get("items"), list):
                return [Document(item, {}, 0, len(lines) - 1) for item in data["items"]]
            return [Document(data, {}, 0, len(lines) - 1)]
    lines = _split_lines(text)
    docs: List[Document] = []
    for start, end in _split_documents(lines):
        parser = _Parser(lines, start, end)
        data = parser.parse_document()
        spans = dict(parser.spans)
        spans[()] = NodeSpan(start, 0, max(parser.last, start))
        docs.append(Document(data, spans, start, end - 1))
    return docs


def load_all(text: str) -> List[Any]:
    """Load every document of a (multi-document) YAML or JSON stream."""
    return [d.data for d in parse_documents(text)]


def load(text: str) -> Any:
    """Load a single YAML/JSON document (``None`` for an empty stream)."""
    docs = load_all(text)
    if not docs:
        return None
    if len(docs) > 1:
        raise YamlError(f"expected a single document but found {len(docs)}")
    return docs[0]


# --------------------------------------------------------------------------- #
# Dumper
# --------------------------------------------------------------------------- #

_PLAIN_UNSAFE_START = set("-?:,[]{}#&*!|>'\"%@`")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\x85  ]")


def _needs_quotes(v: str) -> bool:
    if v == "":
        return True
    if v != v.strip():
        return True
    if v[0] in _PLAIN_UNSAFE_START:
        return True
    if ": " in v or " #" in v or v.endswith(":") or "\t" in v or "\n" in v:
        return True
    if _CONTROL_RE.search(v):
        return True
    return resolve_plain(v) != v or v in ("y", "Y", "n", "N", "yes", "no", "on", "off", "Yes", "No", "On", "Off")


def format_scalar(value: Any) -> str:
    """Render a scalar so that :func:`load` reads back the exact same value."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value):
            return ".nan"
        if math.isinf(value):
            return ".inf" if value > 0 else "-.inf"
        return repr(value)
    s = str(value)
    if _needs_quotes(s):
        return json.dumps(s, ensure_ascii=False)
    return s


def _format_key(key: Any) -> str:
    s = str(key)
    if _needs_quotes(s):
        return json.dumps(s, ensure_ascii=False)
    return s


def _is_scalar(v: Any) -> bool:
    return not isinstance(v, (dict, list))


def _block_literal_ok(s: str) -> bool:
    if "\n" not in s or s.endswith("\n\n") or s.startswith((" ", "\t", "\n")):
        return False
    if _CONTROL_RE.search(s) or "\r" in s:
        return False
    return all(line == line.rstrip() for line in s.split("\n"))


def _dump_value(key_prefix: str, v: Any, indent: int, out: List[str], seq_indent: int) -> None:
    pad = " " * indent
    if isinstance(v, dict) and v:
        out.append(f"{pad}{key_prefix}:")
        _dump_mapping(v, indent + 2, out, seq_indent)
    elif isinstance(v, list) and v:
        out.append(f"{pad}{key_prefix}:")
        _dump_sequence(v, indent + seq_indent, out, seq_indent)
    elif isinstance(v, dict):
        out.append(f"{pad}{key_prefix}: {{}}")
    elif isinstance(v, list):
        out.append(f"{pad}{key_prefix}: []")
    elif isinstance(v, str) and _block_literal_ok(v):
        header = "|" if v.endswith("\n") else "|-"
        out.append(f"{pad}{key_prefix}: {header}")
        body = v[:-1] if v.endswith("\n") else v
        for line in body.split("\n"):
            out.append(f"{pad}  {line}" if line else "")
    else:
        out.append(f"{pad}{key_prefix}: {format_scalar(v)}")


def _dump_mapping(d: Dict[Any, Any], indent: int, out: List[str], seq_indent: int) -> None:
    for k, v in d.items():
        _dump_value(_format_key(k), v, indent, out, seq_indent)


def _dump_sequence(items: List[Any], indent: int, out: List[str], seq_indent: int) -> None:
    pad = " " * indent
    for item in items:
        if isinstance(item, dict) and item:
            sub: List[str] = []
            _dump_mapping(item, indent + 2, sub, seq_indent)
            out.append(pad + "- " + sub[0][indent + 2 :])
            out.extend(sub[1:])
        elif isinstance(item, list) and item:
            sub = []
            _dump_sequence(item, indent + 2, sub, seq_indent)
            out.append(pad + "- " + sub[0][indent + 2 :])
            out.extend(sub[1:])
        elif isinstance(item, dict):
            out.append(pad + "- {}")
        elif isinstance(item, list):
            out.append(pad + "- []")
        else:
            out.append(pad + "- " + format_scalar(item))


def dump_lines(data: Any, indent: int = 0, seq_indent: int = 2) -> List[str]:
    """Serialise ``data`` as block-style YAML lines starting at column ``indent``."""
    out: List[str] = []
    if isinstance(data, dict):
        if data:
            _dump_mapping(data, indent, out, seq_indent)
        else:
            out.append(" " * indent + "{}")
    elif isinstance(data, list):
        if data:
            _dump_sequence(data, indent, out, seq_indent)
        else:
            out.append(" " * indent + "[]")
    else:
        out.append(" " * indent + format_scalar(data))
    return out


def dump(data: Any, indent: int = 0, seq_indent: int = 2) -> str:
    """Serialise ``data`` as a YAML document (always ends with a newline)."""
    return "\n".join(dump_lines(data, indent, seq_indent)) + "\n"


def dump_all(docs: List[Any], seq_indent: int = 2) -> str:
    return "---\n".join(dump(d, seq_indent=seq_indent) for d in docs)


def detect_seq_indent(doc: Document, default: int = 2) -> int:
    """Infer whether sequences are indented under their parent key (2) or not (0)."""
    for path, span in doc.spans.items():
        if path and isinstance(path[-1], int) and len(path) >= 2 and isinstance(path[-2], str):
            parent = doc.spans.get(path[:-1])
            if parent is not None and parent.line != span.line:
                return max(0, span.col - parent.col)
    return default
