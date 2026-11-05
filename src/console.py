"""Terminal output that never crashes - on Linux, macOS or a cp1252 Windows pipe.

Renderers produce Unicode text.  :func:`write` decides at the last moment
whether the destination stream can encode it; if not (legacy Windows code
pages, ``PYTHONIOENCODING=ascii``, CI log collectors), every glyph we use is
mapped to an ASCII equivalent and anything else is replaced instead of raising
``UnicodeEncodeError``.  Colours are emitted only for real TTYs and honour the
``NO_COLOR`` / ``FORCE_COLOR`` conventions.
"""

from __future__ import annotations

import codecs
import os
import sys
from typing import IO, Optional

__all__ = ["GLYPHS", "Style", "can_encode", "ensure_safe_stdio", "to_ascii", "write"]

# Every non-ASCII glyph KubeGuard prints, with its ASCII fallback.
GLYPHS = {
    "✔": "+",  # ✔
    "✖": "x",  # ✖
    "⚠": "!",  # ⚠
    "━": "=",  # ━
    "─": "-",  # ─
    "│": "|",  # │
    "└": "`",  # └
    "├": "|",  # ├
    "•": "*",  # •
    "→": "->",  # →
    "▶": ">",  # ▶
    "…": "...",  # …
    "×": "x",  # ×
    "·": "-",  # ·
    "—": "-",  # —
    "–": "-",  # –
    "═": "=",  # ═
    "║": "|",  # ║
    "╔": "+",  # ╔
    "╗": "+",  # ╗
    "╚": "+",  # ╚
    "╝": "+",  # ╝
    "█": "#",  # █
    "░": ".",  # ░
    "\U0001f6a8": "[!]",  # 🚨
    "\U0001f6e1️": "",  # 🛡️
    "\U0001f6e1": "",  # 🛡
    "\U0001f512": "",  # 🔒
    "\U0001f50d": "",  # 🔍
    "\U0001f527": "",  # 🔧
    "\U0001f9ea": "",  # 🧪
    "\U0001f916": "",  # 🤖
    "\U0001f7e2": "(ok)",  # 🟢
    "\U0001f7e1": "(!)",  # 🟡
    "\U0001f534": "(X)",  # 🔴
    "✅": "[ok]",  # ✅
    "❌": "[x]",  # ❌
    "⏱️": "",  # ⏱️
    "⏱": "",  # ⏱
    "️": "",
}
_PROBE = "".join(k for k in GLYPHS if len(k) == 1)

_ANSI = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "grey": "90",
}


def can_encode(stream: Optional[IO[str]], sample: str = _PROBE) -> bool:
    enc = getattr(stream, "encoding", None) or "ascii"
    try:
        codecs.lookup(enc)
        sample.encode(enc)
        return True
    except (LookupError, UnicodeEncodeError):
        return False


def to_ascii(text: str) -> str:
    for glyph, repl in sorted(GLYPHS.items(), key=lambda kv: -len(kv[0])):
        if glyph in text:
            text = text.replace(glyph, repl)
    return text


def _enable_windows_vt() -> bool:  # pragma: no cover - Windows only
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def ensure_safe_stdio() -> None:
    """Make stdout/stderr replace unencodable characters instead of raising."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="replace")
        except (ValueError, OSError):  # pragma: no cover - detached streams
            pass


class Style:
    """Colour + glyph policy for one output stream."""

    def __init__(self, color: bool = False, unicode: bool = True) -> None:
        self.color = color
        self.unicode = unicode

    @classmethod
    def for_stream(cls, stream: Optional[IO[str]] = None, color: Optional[bool] = None) -> Style:
        stream = stream or sys.stdout
        if color is None:
            if os.environ.get("NO_COLOR"):
                color = False
            elif os.environ.get("FORCE_COLOR"):
                color = True
            else:
                isatty = getattr(stream, "isatty", lambda: False)
                try:
                    color = bool(isatty()) and os.environ.get("TERM") != "dumb"
                except ValueError:  # pragma: no cover - closed stream
                    color = False
                if color and os.name == "nt":  # pragma: no cover - Windows only
                    color = _enable_windows_vt()
        return cls(color=color, unicode=can_encode(stream))

    def paint(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        codes = ";".join(_ANSI[s] for s in styles if s in _ANSI)
        return f"\x1b[{codes}m{text}\x1b[0m"

    def bold(self, t: str) -> str:
        return self.paint(t, "bold")

    def dim(self, t: str) -> str:
        return self.paint(t, "grey")

    def red(self, t: str) -> str:
        return self.paint(t, "red")

    def green(self, t: str) -> str:
        return self.paint(t, "green")

    def yellow(self, t: str) -> str:
        return self.paint(t, "yellow")

    def cyan(self, t: str) -> str:
        return self.paint(t, "cyan")

    def magenta(self, t: str) -> str:
        return self.paint(t, "magenta")

    def verdict(self, verdict: str) -> str:
        icon = {"SAFE_READ": "✔", "APPROVAL_REQUIRED": "⚠", "BLOCKED_DESTRUCTIVE": "✖"}.get(verdict, "?")
        colour = {"SAFE_READ": "green", "APPROVAL_REQUIRED": "yellow", "BLOCKED_DESTRUCTIVE": "red"}.get(verdict)
        label = f"{icon} {verdict:<19}"
        return self.paint(label, colour, "bold") if colour else label

    def diff_line(self, line: str) -> str:
        if line.startswith(("+++", "---")):
            return self.paint(line, "bold")
        if line.startswith("+"):
            return self.paint(line, "green")
        if line.startswith("-"):
            return self.paint(line, "red")
        if line.startswith("@@"):
            return self.paint(line, "cyan")
        return line

    def finish(self, text: str) -> str:
        return text if self.unicode else to_ascii(text)


def write(text: str, stream: Optional[IO[str]] = None, style: Optional[Style] = None) -> None:
    """Write ``text`` to ``stream`` without ever raising ``UnicodeEncodeError``."""
    stream = stream or sys.stdout
    if style is not None:
        text = style.finish(text)
    elif not can_encode(stream):
        text = to_ascii(text)
    try:
        stream.write(text)
    except UnicodeEncodeError:
        enc = getattr(stream, "encoding", None) or "ascii"
        stream.write(text.encode(enc, errors="replace").decode(enc, errors="replace"))
    try:
        stream.flush()
    except (OSError, ValueError):  # pragma: no cover - closed pipe
        pass
