"""Language detection + routing (AEGIS restructure, 2026-10-27, local).

The tag is routing/telemetry, never a block by itself: the action layer
checks every language's lexicon on every input, so a detection miss can
never cause a bypass miss — it only makes the trace tag wrong. The one
fail-closed rule lives in the gateway: an *unknown* script (outside Latin
and Devanagari) combined with a script-independent risky indicator
(currency, email/phone/digit-run, or a Latin action word) is blocked,
never silently allowed. Unknown alone — a plain question in another
script — passes with a `lang:unknown` trace flag.

Phase 2 (2026-11-07): added fail-closed mode for unknown scripts when a
policy_context or high-security mode is active. When the message is
predominantly unsupported script AND cannot be verified as benign,
fail-closed blocks it rather than letting it pass silently.
"""
import re
import unicodedata

_DEVA_RANGE = range(0x0900, 0x0980)

# Roman-Hindi function words with no common English collision. Short
# ambiguous words (to, me, se, ka, ki) are deliberately excluded: "main"
# in English is not Hindi "main", and "to"/"me" would tag English text
# as Hinglish.
_HINGLISH_WORDS = frozenset(
    "meri mera mujhe tumhara hai nahi mat bhej bhejo karo raha rahi hun "
    "gaya kaise kya kab tak mere apna apne dusre dost bhai behen maa "
    "jaldi abhi bas".split())


def _counts(text: str) -> tuple[int, int, int]:
    deva = latin = other = 0
    for ch in text or "":
        if unicodedata.category(ch)[0] != "L":
            continue
        o = ord(ch)
        if o in _DEVA_RANGE:
            deva += 1
        elif ch.isascii():
            latin += 1
        else:
            other += 1
    return deva, latin, other


def detect_language(text: str) -> str:
    """Return 'en', 'hinglish', 'hi-deva', or 'unknown'.

    - Devanagari present, no other script -> 'hi-deva' (Hindi/English
      code-mix such as 'OTP माँगे बिना' still routes to Hindi).
    - Latin only -> 'hinglish' when a Roman-Hindi function word appears,
      else 'en'.
    - Any other script present -> 'unknown'.
    - No letters at all -> 'unknown' (harmless: no action either).
    """
    deva, latin, other = _counts(text)
    if other > 0:
        return "unknown"
    if deva > 0:
        return "hi-deva"
    if latin > 0:
        words = set(re.findall(r"[a-z]+", (text or "").lower()))
        if words & _HINGLISH_WORDS:
            return "hinglish"
        return "en"
    return "unknown"


def is_known(code: str) -> bool:
    return code in ("en", "hinglish", "hi-deva")


def is_predominantly_unsupported(text: str) -> bool:
    """True when the message text is predominantly in an unsupported script.

    A message is 'predominantly unsupported' when:
    - It has non-Latin, non-Devanagari letters (other > 0), AND
    - Those letters make up the majority of all letter characters
      (other > latin + deva).

    This is used by the fail-closed check in the gateway to block
    unsupported-script messages under policy contexts.
    """
    deva, latin, other = _counts(text)
    if other <= 0:
        return False
    return other > (latin + deva)
