"""RE2-backed replacement for the subset of the stdlib ``re`` API used by the
detection engine.

RE2 matches in linear time with no catastrophic backtracking, so
attacker-controlled input cannot stall the event loop the way stdlib ``re``
can (ReDoS). It does **not** support backreferences or lookaround; patterns
using them raise :data:`error` at compile time.

Only the surface the detection engine needs is implemented. ``re``-style int
flags are translated to RE2 inline flags so existing call sites keep passing
``IGNORECASE | MULTILINE`` unchanged. This module is also the single typed
boundary to the untyped ``re2`` package.
"""

from collections.abc import Iterator
from typing import Any, Protocol

import re2

IGNORECASE = 1
MULTILINE = 2
DOTALL = 4

error = re2.error

_OPTIONS = re2.Options()
_OPTIONS.log_errors = False

_INLINE_FLAGS = ((IGNORECASE, "i"), (MULTILINE, "m"), (DOTALL, "s"))


class Match(Protocol):
    string: str

    def group(self, *args: int) -> str: ...

    def start(self, *args: int) -> int: ...

    def end(self, *args: int) -> int: ...


def _with_flags(pattern: str, flags: int) -> str:
    inline = "".join(char for bit, char in _INLINE_FLAGS if flags & bit)
    return f"(?{inline}){pattern}" if inline else pattern


class Pattern:
    """Thin wrapper over a compiled RE2 pattern.

    Exists for one reason: ``re``-style flags are injected as an inline
    ``(?ims)`` prefix, so the underlying RE2 object's ``.pattern`` carries that
    prefix. Callers (and result payloads/logs) expect the original source, so
    we keep it here and delegate everything else to RE2.
    """

    __slots__ = ("pattern", "_re")

    def __init__(self, pattern: str, compiled: Any) -> None:
        self.pattern = pattern
        self._re = compiled

    def search(self, text: str) -> "Match | None":
        match: Match | None = self._re.search(text)
        return match

    def match(self, text: str) -> "Match | None":
        match: Match | None = self._re.match(text)
        return match

    def fullmatch(self, text: str) -> "Match | None":
        match: Match | None = self._re.fullmatch(text)
        return match

    def finditer(self, text: str) -> "Iterator[Match]":
        matches: Iterator[Match] = self._re.finditer(text)
        return matches

    def findall(self, text: str) -> list[Any]:
        found: list[Any] = self._re.findall(text)
        return found

    def sub(self, repl: Any, text: str) -> str:
        result: str = self._re.sub(repl, text)
        return result


def compile(pattern: str, flags: int = 0) -> Pattern:
    return Pattern(pattern, re2.compile(_with_flags(pattern, flags), _OPTIONS))


def search(pattern: str, text: str, flags: int = 0) -> "Match | None":
    return compile(pattern, flags).search(text)


def finditer(pattern: str, text: str, flags: int = 0) -> "Iterator[Match]":
    return compile(pattern, flags).finditer(text)


def findall(pattern: str, text: str, flags: int = 0) -> list[Any]:
    return compile(pattern, flags).findall(text)


def sub(pattern: str, repl: Any, text: str, flags: int = 0) -> str:
    return compile(pattern, flags).sub(repl, text)


def escape(text: str) -> str:
    result: str = re2.escape(text)
    return result
