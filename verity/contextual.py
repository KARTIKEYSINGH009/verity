"""Contextual decision layer — EXPERIMENT (Context Mission, 2026-10-23).

Not wired into the gateway. This module tests one hypothesis on frozen
evaluation sets: a deterministic context analysis on top of screen() can
distinguish *discussing/transforming* an attack from *requesting its
execution*, releasing the former without releasing the latter.

Decision policy (documented, no silent choices):
- Base passes -> candidate passes (this layer never adds a block; it can
  only recommend escalation for unresolved-reference messages).
- Base blocks -> keep the block UNLESS all of these hold:
  (a) a discussion/transformation frame is present (an operation verb
      aimed at supplied text, or a concept question),
  (b) NO execution intent is detected (no ask to obey/follow/apply the
      embedded instructions, in any covered language),
  (c) the text with quoted spans masked screens clean (no rule hits and
      classifier score below threshold) — i.e. the block's evidence
      lives inside the quotation, not in the request itself.
- Execution intent always keeps the block, whatever the frame.
"""
from __future__ import annotations

import re

from .guard import CLASSIFIER_THRESHOLD, detect_injection, screen
from .injection_classifier import probability_malicious

_QUOTED = re.compile(r"'([^']{4,})'|\"([^\"]{4,})\"|«([^»]{4,})»|“([^”]{4,})”")
_TRANSFORM_VERBS = re.compile(
    r"translat|summar|classif|quote|paraphras|rewrite|analyse|analyze|"
    r"anuvaad|bhashantar|classify karo|"
    r"traduce|traduc|übersetz|traduis|résume|zusammenfass",
    re.IGNORECASE)
_DISCUSSION_FRAME = re.compile(
    r"what (is|does|are)|why (do|does|did)|how (do|does|can) .{0,40}"
    r"(work|stop|prevent|hide|refuse)|explain|meaning of|samjhao|"
    r"kya hota hai|kyun|erklär|pourquoi|por qué|¿qué es",
    re.IGNORECASE)
_EXECUTION_INTENT = re.compile(
    r"(and|then|now)\s+(then\s+)?(do|follow|obey|execute|apply|act on)\b|"
    r"do (exactly )?(what|everything|all) (it|this|the \w+) (says|asks|contains)|"
    r"just (obey|follow) it|follow (any |the )?instructions (inside|in it)|"
    r"obey it|live by it|"
    r"aur phir .{0,30}(karo|kar do|waisa hi)|khud bhi waisa|"
    r"फिर .{0,20}(करो|वैसा ही)|स्वयं भी वैसा|"
    r"luego haz|haz exactamente|puis exécute|dann befolge|befolge (sie|es)",
    re.IGNORECASE)
_PERSONA_FRAME = re.compile(
    r"pretend (you are|to be)|you are now\b|act as\b|roleplay|"
    r"imagine you are", re.IGNORECASE)
_OWN_TARGET = re.compile(
    r"your (system prompt|instructions|prompt|rules|guidelines)|"
    r"(system prompt|instructions) you (were|was|have been) given",
    re.IGNORECASE)


def _release_blocked_by_persona_or_own_target(text: str) -> bool:
    return bool(_PERSONA_FRAME.search(text) or _OWN_TARGET.search(text))


_UNRESOLVED_REF = re.compile(
    r"the (list|document|file|access|one) (we|you) (discussed|talked about|"
    r"saw|showed)|same way (you|we) did|like last time|handle it the same|"
    r"^approve it\.?$|us wala|wo wala|jo kal dekha",
    re.IGNORECASE)


def _mask_quotes(text: str) -> str:
    return _QUOTED.sub(" quotedtext ", text or "")


def _has_quoted_span(text: str) -> bool:
    return bool(_QUOTED.search(text or ""))


def context_screen(text: str, base: dict | None = None) -> dict:
    """screen() + contextual analysis. Returns the base verdict fields
    plus context_class, released (bool), escalate (bool), reasons.
    Pass a precomputed screen() result as `base` to avoid re-screening
    (the gateway does this)."""
    if base is None:
        base = screen(text)
    out = dict(base)
    out.update({"context_class": None, "released": False,
                "escalate": False, "reasons": []})
    if not text:
        return out
    execution = bool(_EXECUTION_INTENT.search(text))
    frame = bool(_TRANSFORM_VERBS.search(text)) or bool(
        _DISCUSSION_FRAME.search(text))
    if not base["blocked"]:
        if _UNRESOLVED_REF.search(text):
            out["escalate"] = True
            out["context_class"] = "AMBIGUOUS"
            out["reasons"].append("unresolved_reference")
        return out
    # Base blocked: consider a context release.
    if execution:
        out["reasons"].append("execution_intent_keeps_block")
        return out
    if not frame:
        out["reasons"].append("no_discussion_or_transform_frame")
        return out
    masked = _mask_quotes(text)
    masked_hits = detect_injection(masked)
    masked_score = probability_malicious(masked)
    if masked_hits or (masked_score is not None
                       and masked_score >= CLASSIFIER_THRESHOLD):
        # C1b path: a *classifier-only* block (no rule fired anywhere)
        # under a pure discussion frame, with no execution intent and
        # no rule evidence even unmasked, may be a meta-discussion FP.
        if (not base["heuristic_hits"] and not execution
                and _DISCUSSION_FRAME.search(text)
                and not _TRANSFORM_VERBS.search(text)
                and not _release_blocked_by_persona_or_own_target(text)):
            out["blocked"] = False
            out["released"] = True
            out["context_class"] = "BENIGN_DISCUSSION"
            out["reasons"].append("discussion_frame_classifier_only")
            return out
        out["reasons"].append("evidence_outside_quotes_keeps_block")
        return out
    out["blocked"] = False
    out["released"] = True
    out["context_class"] = ("BENIGN_TRANSFORMATION"
                            if _TRANSFORM_VERBS.search(text)
                            else "BENIGN_DISCUSSION")
    out["reasons"].append("frame_no_execution_masked_clean")
    return out
