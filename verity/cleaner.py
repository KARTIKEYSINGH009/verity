"""Input cleaner/sanitizer (AEGIS restructure, 2026-10-27, local).

Makes explicit what the guard already did implicitly: the text fed to
the language and action layers is NFKC-normalized (the guard's
`normalize`, which folds homoglyphs and leetspeak and strips zero-width
characters) with lone surrogates removed (the gateway's `_db_text`
behaviour, which previously fixed a 500 on surrogate input). Model input
is unchanged — the cleaner only prepares the text the safety layers
judge, so cleaning can never alter an answer, only a verdict.
"""
import re

from .injection_classifier import normalize

_SURROGATE = re.compile(r"[\ud800-\udfff]")


def sanitize(text: str) -> str:
    if not text:
        return ""
    return _SURROGATE.sub("", normalize(text))
