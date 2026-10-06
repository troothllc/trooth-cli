"""RFC 8785 (JCS) under the trooth.witness-statement.v3 profile: integers only.

The same rules as bin/lib/jcs.mjs and sdk/go/trooth/jcs.go, so all three
produce the same bytes or the same refusal.
"""

from __future__ import annotations

import json
from typing import Any

MAX_SAFE = 2**53 - 1


class CanonicalizationError(ValueError):
    """The value has no canonical form under the v3 profile."""


def _str(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise CanonicalizationError("a string holds a lone surrogate")
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(k: str) -> bytes:
    return k.encode("utf-16-be", "surrogatepass")


def canonicalize(value: Any) -> str:
    """The canonical JSON text of a parsed JSON value."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _str(value)
    if isinstance(value, int):
        if not -MAX_SAFE <= value <= MAX_SAFE:
            raise CanonicalizationError(f"the number {value} is outside -(2^53 - 1) to 2^53 - 1")
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")) or not value.is_integer():
            raise CanonicalizationError(f"the number {value} is not an integer")
        return canonicalize(int(value))
    if isinstance(value, list):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys(), key=_utf16_key)
        return "{" + ",".join(_str(k) + ":" + canonicalize(value[k]) for k in keys) + "}"
    raise CanonicalizationError(f"a {type(value).__name__} has no JSON form")


def is_canonical(text: str) -> bool:
    """Whether text is already the canonical form of the JSON it holds."""
    if not isinstance(text, str):
        return False
    try:
        parsed = json.loads(text)
    except ValueError:
        return False
    try:
        return canonicalize(parsed) == text
    except CanonicalizationError:
        return False
