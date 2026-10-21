"""Prompt-injection guard, heuristic v0 + trained classifier (milestone 3).

Screens user input for known jailbreak / injection patterns before the
request reaches the model. `detect_injection` runs the rule list (classic
injection plus impersonation, data exfiltration, fraud coaching, and
encoded-instruction smuggling); `screen` adds the trained classifier score
on top. If the model file is missing the classifier degrades gracefully to
heuristics-only.
"""
import re

from .injection_classifier import normalize, probability_malicious

RULES = {
    "ignore_instructions": r"ignore (all |any |your |previous )?(prior |previous )?instructions",
    "system_prompt_extract": r"(reveal|show|print|output|disclose).{0,40}system prompt",
    "role_hijack": r"you are now (dan|unrestricted|free of|no longer)\b|pretend (you are|to be) (dan|unrestricted|evil)\b|act as (a |an )?DAN",
    "jailbreak_token": r"\bDAN\b|jailbreak|do anything now",
    "instruction_override": r"disregard.{0,30}(above|previous|instructions)",
    "prompt_leak": r"repeat.{0,30}(instructions|prompt)",
    "impersonation": r"i am (your|the) (store |shop |branch )?(manager|owner|boss|admin)\b|this is (the )?(owner|manager) speaking|as your developer|admin here\b",
    "data_exfiltration": r"(other|another) customer'?s (order|address|phone|details|number)|list (all )?(the )?(orders|customers|users)\b|most recent customer",
    "fraud_coaching": r"fake (damage claim|complaint|reviews?)\b|fake (five|5)[- ]star|lie about (not receiving|receiving)|blackmail|scam (the|your) (support|store|company)",
    "encoded_instruction": r"decode this base64 and (follow|obey)|base64 and follow it",
    "credential_extract": r"(show|reveal|give|tell|share|print|leak|disclose|what'?s|what is).{0,30}(your|the) (ai |own )?(api key|secret key|password|access token|credentials)|\byour (ai )?(api key|secret key|credentials)\b",
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


def screen(text: str) -> dict:
    """Full guard verdict: heuristics plus the trained classifier.

    Returns {"blocked", "signals", "heuristic_hits", "classifier_score"}.
    "classifier_score" is None when the model file is unavailable, in
    which case the verdict falls back to heuristics only.
    """
    heuristic_hits = detect_injection(text)
    score = probability_malicious(text) if text else None
    signals = list(heuristic_hits)
    if score is not None and score >= CLASSIFIER_THRESHOLD:
        signals.append("ml_classifier")
    return {
        "blocked": bool(signals),
        "signals": signals,
        "heuristic_hits": heuristic_hits,
        "classifier_score": score,
    }
