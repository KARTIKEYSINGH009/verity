"""Input cleaner/sanitizer (AEGIS restructure, 2026-10-27, local).

Makes explicit what the guard already did implicitly: the text fed to
the language and action layers is NFKC-normalized (the guard's
`normalize`, which folds homoglyphs and leetspeak and strips zero-width
characters) with lone surrogates removed (the gateway's `_db_text`
behaviour, which previously fixed a 500 on surrogate input). Model input
is unchanged — the cleaner only prepares the text the safety layers
judge, so cleaning can never alter an answer, only a verdict.

Phase 3 (2026-11-07): added outbound secret/PII DLP scanning for API
keys, Bearer tokens, AWS keys, Postgres URIs, and system-prompt markers
in model responses.
"""
import re

from .injection_classifier import normalize

_SURROGATE = re.compile(r"[\ud800-\udfff]")


def sanitize(text: str) -> str:
    if not text:
        return ""
    return _SURROGATE.sub("", normalize(text))


# ---------------------------------------------------------------------------
# Outbound Secret & PII DLP (Phase 3, 2026-11-07).
# ---------------------------------------------------------------------------
_SECRET_PATTERNS = [
    # OpenAI-style API keys
    re.compile(r"\bsk-[A-Za-z0-9]{20,}"),
    # Groq API keys
    re.compile(r"\bgsk_[A-Za-z0-9]{20,}"),
    # AWS access keys
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    # AWS secret keys (40-char base64)
    re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"),
    # Bearer tokens in text
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]{20,}", re.IGNORECASE),
    # Postgres connection URIs
    re.compile(r"postgres(?:ql)?://[^\s]{10,}"),
    # Generic long hex secrets (64+ hex chars, like SHA-256 hashes used as keys)
    re.compile(r"\b[0-9a-f]{64,}\b", re.IGNORECASE),
]

_SYSTEM_PROMPT_LEAK = re.compile(
    r"(?:system prompt|system instructions|my instructions|"
    r"my initial prompt|my original instructions|"
    r"here (?:is|are) my (?:system |initial |original )?(?:prompt|instructions))",
    re.IGNORECASE)


def detect_leaked_secrets(text: str) -> list[str]:
    """Return a list of secret-type tags found in the text."""
    if not text:
        return []
    found = []
    for rx in _SECRET_PATTERNS:
        if rx.search(text):
            found.append("leaked_secret")
            break
    if _SYSTEM_PROMPT_LEAK.search(text):
        found.append("system_prompt_leak")
    return found


def has_leaked_secrets(text: str) -> bool:
    """True if the text contains any leaked secrets or system prompt markers."""
    return bool(detect_leaked_secrets(text))
