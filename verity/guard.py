"""Prompt-injection guard, heuristic v0 + trained classifier (milestone 3).

Screens user input for known jailbreak / injection patterns before the
request reaches the model. `detect_injection` runs the rule list (classic
injection plus impersonation, data exfiltration, fraud coaching, and
encoded-instruction smuggling); `screen` adds the trained classifier score
on top. If the model file is missing the classifier degrades gracefully to
heuristics-only.
"""
import base64
import binascii
import re

from .injection_classifier import normalize, probability_malicious

RULES = {
    "ignore_instructions": r"ignore (all |any |your |previous )?(prior |previous )?instructions",
    "system_prompt_extract": r"(reveal|show|print|output|disclose).{0,40}system prompt",
    "role_hijack": r"you are now (dan|unrestricted|free of|no longer)\b|pretend (you are|to be) (dan|unrestricted|evil)\b|act as (a |an )?DAN",
    "jailbreak_token": r"jailbreak|do anything now",
    "instruction_override": r"disregard.{0,30}(above|previous|instructions)",
    "prompt_leak": r"repeat.{0,30}(instructions|prompt)",
    "impersonation": r"i am (your|the) (store |shop |branch )?(manager|owner|boss|admin)\b|this is (the )?(owner|manager) speaking|as your developer|admin here\b",
    "data_exfiltration": r"(other|another) customer'?s (order|address|phone|details|number)|list (all )?(the )?(orders|customers|users)\b|most recent customer",
    "fraud_coaching": r"fake (damage claim|complaint|reviews?)\b|fake (five|5)[- ]star|(generate|write|create|produce).{0,40}(fake|positive|glowing|five[- ]star|5[- ]star) reviews?|lie about (not receiving|receiving)|blackmail|scam (the|your) (support|store|company)",
    "encoded_instruction": r"decode this base64 and (follow|obey)|base64 and follow it",
    "credential_extract": r"(show|reveal|give|tell|share|print|leak|disclose|what'?s|what is).{0,30}(your|the) (ai |own )?(api key|secret key|password|access token|credentials)|\byour (ai )?(api key|secret key|credentials)\b",
    # Round-2 Deep Hat mechanisms (2026-10-22): extraction targets and
    # exfil channels the classifier had never seen. Each pattern needs
    # an extraction verb plus a sensitive target, so documentation and
    # how-it-works questions about the same nouns stay allowed.
    "prompt_extract_generic": r"(output|reveal|show|print|disclose).{0,40}(exact|full|actual|entire) prompt(?!\s+(i|you|we)\s+(sent|wrote|typed|gave|submitted))|exact prompt (currently|that is) active in your context",
    "pii_fields_extract": r"(most sensitive|top \d+ most).{0,30}(pii|personal data) fields|(pii|personal data) fields you (have access|can access|hold)",
    "embeddings_extract": r"(output|print|dump|export|provide|encode).{0,40}(vector )?embeddings|embeddings.{0,30}base64",
    "exfil_link": r"https?://\S+.{0,100}followed by the|(markdown|mermaid|image tag).{0,160}(exfiltrat|configuration keys|system prompt|conversation history)",
}

_COMPILED = {name: re.compile(pat, re.IGNORECASE) for name, pat in RULES.items()}


def detect_injection(text: str) -> list[str]:
    """Return names of injection rules matched by the input text.

    Matching runs on normalized text so contractions and obfuscation
    ("I'm a store manager") cannot slip past the patterns.
    """
    if not text:
        return []
    t = normalize(text)
    return [name for name, rx in _COMPILED.items() if rx.search(t)]


CLASSIFIER_THRESHOLD = 0.75

_B64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_SPACED_RUN = re.compile(r"(?<![a-z])[a-z](?: [a-z]){4,}(?![a-z])",
                         re.IGNORECASE)


def _despaced(text: str) -> str | None:
    """Reconstruct letter-spaced text ("i g n o r e ...") into the fused
    string it encodes, or None when the input has no spaced runs.
    Benign spelling-out ("spell c a t") fuses to a benign word and is
    judged on that content, so it is not blocked by the transform."""
    if not text or not _SPACED_RUN.search(text):
        return None
    return _SPACED_RUN.sub(lambda m: m.group(0).replace(" ", ""), text)


def _decoded_payloads(text: str) -> list[str]:
    """Extract and decode base64-looking runs from the input.

    Only payloads that decode to clean, printable UTF-8 are returned —
    random hashes and binary blobs decode to gibberish and are ignored,
    so a benign "please decode this for me" request is judged by what
    the payload actually says, never by the mere presence of base64.
    """
    out: list[str] = []
    for m in _B64_RUN.finditer(text or ""):
        s = m.group(0)
        if len(s) % 4 == 1:
            continue
        try:
            raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
            dec = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if dec.strip() and all(c.isprintable() or c in "\n\t" for c in dec):
            out.append(dec)
    return out


_COMMON_WORDS = frozenset(
    "the and you your me my show give ignore instructions system prompt "
    "rules all reveal send list what this that with from have are was "
    "not but they them then than its it is in on of to a an as at be by "
    "do does did will would can could should now please tell".split()
)


def _common_word_hits(text: str) -> int:
    words = re.findall(r"[a-z]+", (text or "").lower())
    return sum(1 for w in words if w in _COMMON_WORDS)


def _decoded_transforms(text: str) -> list[str]:
    """Whole-text reversible transforms an attacker may hide behind:
    ROT13, full reversal, and per-word reversal.

    A transform is only re-screened when decoding produces clearly more
    ordinary English than the raw text — a real encoded attack decodes
    INTO readable words, while the transform of a benign message stays
    gibberish and is never judged (its character n-grams could otherwise
    trip the classifier by coincidence).
    """
    if not text or len(text) < 12:
        return []
    base_hits = _common_word_hits(text)
    candidates: list[str] = []
    try:
        import codecs

        rot = codecs.decode(text, "rot_13")
        if rot != text:
            candidates.append(rot)
    except Exception:
        pass
    rev = text[::-1]
    if rev != text:
        candidates.append(rev)
    words = text.split(" ")
    if len(words) > 2:
        per_word = " ".join(w[::-1] for w in words)
        if per_word != text:
            candidates.append(per_word)
    return [c for c in candidates
            if _common_word_hits(c) >= 2 and _common_word_hits(c) > base_hits]


def screen(text: str) -> dict:
    """Full guard verdict: heuristics plus the trained classifier.

    Returns {"blocked", "signals", "heuristic_hits", "classifier_score"}.
    "classifier_score" is None when the model file is unavailable, in
    which case the verdict falls back to heuristics only.

    Encoded forms are re-screened with the same rules + classifier
    (decode-and-rescreen): base64 payloads are decoded, and letter-spaced
    runs ("i g n o r e ...") are fused back together. An attack smuggled
    in an encoded form is judged by its reconstructed content.
    """
    heuristic_hits = detect_injection(text)
    score = probability_malicious(text) if text else None
    signals = list(heuristic_hits)
    if score is not None and score >= CLASSIFIER_THRESHOLD:
        signals.append("ml_classifier")
    variants = _decoded_payloads(text)
    fused = _despaced(text)
    if fused is not None:
        variants.append(fused)
    if not signals:
        # Nothing found yet: also try whole-text reversible transforms
        # (ROT13 / reversed). Judged by decoded content, like base64.
        variants.extend(_decoded_transforms(text))
    for payload in variants:
        sub_hits = detect_injection(payload)
        sub_score = probability_malicious(payload)
        if sub_hits or (sub_score is not None
                        and sub_score >= CLASSIFIER_THRESHOLD):
            if "encoded_instruction" not in signals:
                signals.append("encoded_instruction")
            for hit in sub_hits:
                if hit not in signals:
                    signals.append(hit)
            if (sub_score is not None and sub_score >= CLASSIFIER_THRESHOLD
                    and "ml_classifier" not in signals):
                signals.append("ml_classifier")
    return {
        "blocked": bool(signals),
        "signals": signals,
        "heuristic_hits": heuristic_hits,
        "classifier_score": score,
    }
