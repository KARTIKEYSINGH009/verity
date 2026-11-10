"""
Verity Gateway Request Flow Additions (Priority 3: Two-Threshold Gray-Zone Routing
+ Integration of Priority 1, 2, 4, 5 Policy Gates and Shadow Judge Logging).
"""
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from classifier_features import extract_verity_priority_features
from policy import (
    RuleResult,
    check_coercive_empathy_bypass,
    check_unicode_script_and_multilingual_gate,
    check_unverified_prior_agreement,
    evaluate_meta_vs_imperative,
)
from store import GrayZoneDisagreementRecord, VerityStore


@dataclass
class GatewayDecision:
    action: str  # "ALLOW" | "ALLOW_READ_ONLY_TOOLS" | "BLOCK"
    band: str    # "LOW_PASS" | "GRAY_ZONE" | "HIGH_BLOCK" | "DETERMINISTIC_GATE"
    classifier_prob: float
    triggered_rules: List[str] = field(default_factory=list)
    allowed_mcp_tools: List[str] = field(default_factory=list)
    shadow_judge_verdict: Optional[str] = None
    shadow_disagreement_logged: bool = False
    requires_human_review_flag: bool = False
    reason: str = ""


READ_ONLY_TOOL_PREFIXES = ("get_", "list_", "read_", "search_", "fetch_", "describe_", "check_")


def filter_read_only_mcp_tools(available_tools: List[str]) -> List[str]:
    """
    Strips write/mutation/destructive MCP tools for gray-zone turns, retaining
    only read-only inspection tools.
    """
    return [
        tool for tool in available_tools
        if tool.lower().startswith(READ_ONLY_TOOL_PREFIXES)
    ]


class VerityPriorityGateway:
    """
    Drop-in request router for gateway.py implementing two-threshold gray-zone
    routing, deterministic policy gates, and non-enforcing shadow judge logging.
    """

    def __init__(
        self,
        local_classifier_fn: Callable[[str, Dict[str, float]], float],
        shadow_judge_fn: Optional[Callable[[str], str]] = None,
        store: Optional[VerityStore] = None,
        tau_low: float = 0.35,
        tau_high: float = 0.75,
        enforce_human_flagged_rules: bool = True,
    ):
        if not (0.0 <= tau_low < tau_high <= 1.0):
            raise ValueError("Thresholds must satisfy 0.0 <= tau_low < tau_high <= 1.0")
        self.local_classifier_fn = local_classifier_fn
        self.shadow_judge_fn = shadow_judge_fn
        self.store = store or VerityStore()
        self.tau_low = tau_low
        self.tau_high = tau_high
        self.enforce_human_flagged_rules = enforce_human_flagged_rules

    def evaluate_request(
        self,
        request_id: str,
        user_text: str,
        available_mcp_tools: List[str],
        mcp_tool_requested: bool = False,
        turn_index: int = 0,
        session_history: Optional[List[Dict[str, str]]] = None,
        verified_commitments: Optional[List[str]] = None,
        keyword_rule_hit: bool = False,
    ) -> GatewayDecision:
        triggered_rules: List[str] = []
        needs_human_flag = False

        # 1. Priority 5: Unicode Script-Ratio Fail-Closed Gate & Devanagari Lexicon
        p5_res: RuleResult = check_unicode_script_and_multilingual_gate(user_text)
        if p5_res.triggered:
            triggered_rules.append(p5_res.rule_id)
            needs_human_flag = p5_res.needs_human_review_before_enforce
            if self.enforce_human_flagged_rules or not p5_res.needs_human_review_before_enforce:
                return GatewayDecision(
                    action="BLOCK",
                    band="DETERMINISTIC_GATE",
                    classifier_prob=1.0,
                    triggered_rules=triggered_rules,
                    allowed_mcp_tools=[],
                    requires_human_review_flag=needs_human_flag,
                    reason=p5_res.reason,
                )

        # 2. Priority 4: Meta-Discussion vs. Imperative Split
        p4_res: RuleResult = evaluate_meta_vs_imperative(
            user_text, mcp_tool_requested=mcp_tool_requested
        )
        if p4_res.triggered and p4_res.action == "BLOCK":
            triggered_rules.append(p4_res.rule_id)
            return GatewayDecision(
                action="BLOCK",
                band="DETERMINISTIC_GATE",
                classifier_prob=1.0,
                triggered_rules=triggered_rules,
                allowed_mcp_tools=[],
                requires_human_review_flag=p4_res.needs_human_review_before_enforce,
                reason=p4_res.reason,
            )

        downgraded_keyword_hit = (
            keyword_rule_hit
            and p4_res.triggered
            and p4_res.action == "DOWNGRADE_TO_CLASSIFIER"
        )
        if downgraded_keyword_hit:
            triggered_rules.append(p4_res.rule_id)
            needs_human_flag = True

        # 3. Priority 1: Coercive Empathy + Bypass Verb Co-occurrence
        p1_res: RuleResult = check_coercive_empathy_bypass(user_text)
        if p1_res.triggered:
            triggered_rules.append(p1_res.rule_id)
            needs_human_flag = p1_res.needs_human_review_before_enforce
            if self.enforce_human_flagged_rules or not p1_res.needs_human_review_before_enforce:
                return GatewayDecision(
                    action="BLOCK",
                    band="DETERMINISTIC_GATE",
                    classifier_prob=1.0,
                    triggered_rules=triggered_rules,
                    allowed_mcp_tools=[],
                    requires_human_review_flag=needs_human_flag,
                    reason=p1_res.reason,
                )

        # 4. Priority 2: Unverified Prior-Agreement Gate
        p2_res: RuleResult = check_unverified_prior_agreement(
            user_text,
            session_history=session_history,
            verified_commitments=verified_commitments,
        )
        if p2_res.triggered:
            triggered_rules.append(p2_res.rule_id)
            needs_human_flag = p2_res.needs_human_review_before_enforce
            if self.enforce_human_flagged_rules or not p2_res.needs_human_review_before_enforce:
                return GatewayDecision(
                    action="BLOCK",
                    band="DETERMINISTIC_GATE",
                    classifier_prob=1.0,
                    triggered_rules=triggered_rules,
                    allowed_mcp_tools=[],
                    requires_human_review_flag=needs_human_flag,
                    reason=p2_res.reason,
                )

        # 5. Priority 3: Local Classifier + Two-Threshold Gray-Zone Routing
        features = extract_verity_priority_features(
            user_text, turn_index=turn_index, session_history=session_history
        )
        prob = float(self.local_classifier_fn(user_text, features))

        # Shadow judge runs passively (never enforces)
        shadow_verdict = None
        if self.shadow_judge_fn is not None:
            shadow_verdict = self.shadow_judge_fn(user_text)  # "ATTACK" or "BENIGN"

        # Band A: High-confidence Attack (p >= tau_high)
        if prob >= self.tau_high:
            return GatewayDecision(
                action="BLOCK",
                band="HIGH_BLOCK",
                classifier_prob=prob,
                triggered_rules=triggered_rules,
                allowed_mcp_tools=[],
                shadow_judge_verdict=shadow_verdict,
                requires_human_review_flag=needs_human_flag,
                reason=f"Classifier probability {prob:.3f} >= tau_high ({self.tau_high}).",
            )

        # Band B: Low-confidence / Benign (p < tau_low)
        if prob < self.tau_low:
            return GatewayDecision(
                action="ALLOW",
                band="LOW_PASS",
                classifier_prob=prob,
                triggered_rules=triggered_rules,
                allowed_mcp_tools=list(available_mcp_tools),
                shadow_judge_verdict=shadow_verdict,
                requires_human_review_flag=needs_human_flag,
                reason=f"Classifier probability {prob:.3f} < tau_low ({self.tau_low}).",
            )

        # Band C: Gray Zone (tau_low <= p < tau_high)
        # Strip write/mutation MCP tools and log shadow-judge disagreements for human curation
        read_only_tools = filter_read_only_mcp_tools(available_mcp_tools)
        disagreement_logged = False
        if shadow_verdict is not None:
            record = GrayZoneDisagreementRecord(
                request_id=request_id,
                user_text=user_text,
                classifier_prob=prob,
                shadow_judge_verdict=shadow_verdict,
                triggered_rules=triggered_rules,
                features=features,
                needs_human_review=True,
            )
            self.store.log_gray_zone_event(record)
            disagreement_logged = True

        return GatewayDecision(
            action="ALLOW_READ_ONLY_TOOLS",
            band="GRAY_ZONE",
            classifier_prob=prob,
            triggered_rules=triggered_rules + ["P3_GRAY_ZONE_READ_ONLY_GATE"],
            allowed_mcp_tools=read_only_tools,
            shadow_judge_verdict=shadow_verdict,
            shadow_disagreement_logged=disagreement_logged,
            requires_human_review_flag=True,
            reason=(
                f"Classifier probability {prob:.3f} in gray zone "
                f"[{self.tau_low}, {self.tau_high}); write/mutation MCP tools stripped."
            ),
        )
