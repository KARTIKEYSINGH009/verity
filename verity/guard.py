"""Prompt-injection guard, heuristic v0.

Screens user input for known jailbreak / injection patterns before the
request reaches the model. Returns the list of matched rule names.
A fine-tuned classifier replaces this in a later milestone.
"""
import re

RULES = {
    "ignore_instructions": r"ignore (all |any |your |previous )?(prior |previous )?instructions",
    "system_prompt_extract": r"(reveal|show|print|output|disclose).{0,40}system prompt",
    "role_hijack": r"you are now|pretend (you are|to be)|act as (a |an )?DAN",
    "jailbreak_token": r"\bDAN\b|jailbreak|do anything now",
    "instruction_override": r"disregard.{0,30}(above|previous|instructions)",
    "prompt_leak": r"repeat.{0,30}(instructions|prompt)",
}

_COMPILED = {name: re.compile(pat, re.IGNORECASE) for name, pat in RULES.items()}


def detect_injection(text: str) -> list[str]:
    """Return names of injection rules matched by the input text."""
    if not text:
        return []
    return [name for name, rx in _COMPILED.items() if rx.search(text)]
