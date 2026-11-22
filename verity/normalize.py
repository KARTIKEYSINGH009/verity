"""Text normalization and sliding-window slicing for inbound LLM messages.

This module does NOT detect attacks. It only normalizes and windows text
for the existing rules + classifier. No scoring, blocking, or policy
decisions happen here.
"""

import re
import unicodedata
from urllib.parse import unquote

_STRIP_CHARS_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\ufeff]")
_HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
_MAX_DECODE_PASSES = 2
_SHORT_INPUT_LIMIT = 4096


def _strip_and_fold(text: str) -> str:
    folded = unicodedata.normalize("NFKC", text)
    return _STRIP_CHARS_RE.sub("", folded)


def _decode_hex_escapes(text: str) -> str:
    return _HEX_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)


def harden_normalize(text: str) -> str:
    """Apply NFKC folding, strip zero-width/bidi chars, and run <=2 URL/hex decode passes."""
    current = _strip_and_fold(text)
    for _ in range(_MAX_DECODE_PASSES):
        decoded = unquote(current)
        decoded = _decode_hex_escapes(decoded)
        decoded = _strip_and_fold(decoded)
        if decoded == current:
            break
        current = decoded
    return current


def scan_windows(text: str, window: int = 2048) -> list[str]:
    """Return overlapping windows covering head, tail, and strided middles.

    Short inputs (<= 4 KiB) are returned unchanged as a single window.
    """
    if len(text) <= _SHORT_INPUT_LIMIT:
        return [text]
    step = max(1, window // 2)
    windows: list[str] = []
    pos = 0
    while pos < len(text):
        windows.append(text[pos : pos + window])
        if pos + window >= len(text):
            break
        pos += step
    tail = text[-window:]
    if windows and windows[-1] != tail:
        windows.append(tail)
    return windows
