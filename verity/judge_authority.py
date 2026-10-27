"""Staged judge authority (AEGIS restructure, 2026-10-27, local).

The shadow judge already records verdicts without changing outcomes.
This module is the *only* place a judge verdict may become a block,
and only at the first stage:

  enforce_high: judge verdict is "attack" with confidence >= 0.90
                on an escalated case -> block.

Wider stages (lower bar, more cases) need fresh measurement and a
separate founder approval each; they are not implemented here.

Enforcement gate (NOT code): judge enforcement in production needs
shadow evidence first — false alarms <= 5%, catch >= 80%, error < 2%
(2026-10-25 judge rule; review Sun 2026-11-08 or >= 500 shadow verdicts,
whichever later) — and readable traces. Until that evidence exists,
JUDGE_AUTHORITY_MODE stays "off" and this module changes nothing.
"""
import re

ENFORCE_HIGH_CONFIDENCE = 0.90

_JUDGE_FLAG = re.compile(r"judge:attack:([0-9]*\.?[0-9]+)")


def authority_decision(verdict_attack: bool, confidence: float,
                       mode: str) -> dict:
    """Pure decision: does a judge verdict block at this stage?"""
    if mode != "enforce_high":
        return {"blocked": False, "stage": None, "reason": ""}
    if verdict_attack and confidence >= ENFORCE_HIGH_CONFIDENCE:
        return {"blocked": True, "stage": "enforce_high",
                "reason": f"judge verdict attack at confidence "
                          f"{confidence:.2f} (>= 0.90)"}
    return {"blocked": False, "stage": None, "reason": ""}


def decision_from_flags(flags: list[str], mode: str) -> dict:
    """Read the shadow judge's verdict out of the gateway trace flags
    (``judge:attack:<confidence>``) and apply the staged rule. No new
    judge call is made — authority reuses the shadow verdict already
    computed for the escalated case, or does nothing when there is none.
    """
    for f in flags or []:
        m = _JUDGE_FLAG.match(f)
        if m:
            return authority_decision(True, float(m.group(1)), mode)
    return {"blocked": False, "stage": None, "reason": ""}
