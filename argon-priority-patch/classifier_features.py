"""
Verity Classifier Feature Extractors (Priorities 1, 2, and 4).
Produces deterministic feature dictionaries/vectors to concatenate with Verity's
local 568-example classifier features.
"""
import re
from typing import Dict, List, Optional
from policy import (
    AFFECTIVE_URGENCY_LEXICON,
    BENIGN_COMMITMENT_INQUIRY_RE,
    EXECUTION_DEMAND_RE,
    META_DISCUSSION_FRAME_RE,
    PRIOR_COMMITMENT_CLAIM_RE,
    VERIFICATION_TARGET_LEXICON,
    check_coercive_empathy_bypass,
    normalize_bypass_lemmas,
)


def extract_has_affect_plus_exception(text: str, window_size: int = 25) -> int:
    """
    Priority 1 Feature: Returns 1 if the message combines affective distress/grief
    with a normalized policy/verification exception request within `window_size` tokens.
    Returns 0 for benign grief messages that ask how to follow verification steps.
    """
    res = check_coercive_empathy_bypass(text, window_size=window_size)
    return 1 if res.triggered else 0


def extract_claims_prior_assistant_commitment(
    text: str,
    turn_index: int = 0,
    session_history: Optional[List[Dict[str, str]]] = None,
) -> int:
    """
    Priority 2 Feature: Returns 1 if the user claims the assistant/support/system
    already agreed to or approved an action and demands immediate fulfillment,
    especially when turn_index == 0 or session_history lacks verification.
    """
    if BENIGN_COMMITMENT_INQUIRY_RE.search(text):
        return 0

    has_claim = bool(PRIOR_COMMITMENT_CLAIM_RE.search(text))
    has_demand = bool(EXECUTION_DEMAND_RE.search(text))

    if not (has_claim and has_demand):
        return 0

    if turn_index == 0 or not session_history:
        return 1

    for msg in session_history:
        if msg.get("role") == "assistant" and msg.get("commitment_verified") is True:
            return 0

    return 1


def extract_verity_priority_features(
    text: str,
    turn_index: int = 0,
    session_history: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, float]:
    """
    Master feature extractor returning a dictionary of engineered features
    ready to append to Verity's local classifier input vector.
    """
    lower_text = text.lower()
    norm_text = normalize_bypass_lemmas(lower_text)
    tokens = re.findall(r"\w+", norm_text)

    has_affect_plus_exception = extract_has_affect_plus_exception(text)
    claims_prior_commitment = extract_claims_prior_assistant_commitment(
        text, turn_index=turn_index, session_history=session_history
    )

    bypass_verb_count = sum(1 for t in tokens if t.upper() == "BYPASS_VERB")
    affect_term_count = sum(1 for phrase in AFFECTIVE_URGENCY_LEXICON if phrase in lower_text)
    verification_target_count = sum(1 for t in tokens if t in VERIFICATION_TARGET_LEXICON)
    is_meta_discussion = 1 if META_DISCUSSION_FRAME_RE.search(text) else 0
    is_first_turn_commitment_claim = 1 if (claims_prior_commitment == 1 and turn_index == 0) else 0

    return {
        "has_affect_plus_exception": float(has_affect_plus_exception),
        "claims_prior_assistant_commitment": float(claims_prior_commitment),
        "is_first_turn_commitment_claim": float(is_first_turn_commitment_claim),
        "normalized_bypass_verb_count": float(bypass_verb_count),
        "affect_urgency_term_count": float(affect_term_count),
        "verification_target_count": float(verification_target_count),
        "is_meta_discussion_frame": float(is_meta_discussion),
    }
