# Verity Priority 1–5 Patch Package

This package contains drop-in implementations for Verity's five strengthening priorities.

## 1. File Mapping to Verity Codebase

| Patch File | Target Location in Verity | What It Adds |
| :--- | :--- | :--- |
| `policy.py` | Merge/append into `policy.py` | 1. `normalize_bypass_lemmas()` (`forgo`/`waive`/`dispense with` -> `BYPASS_VERB`)<br>2. `check_coercive_empathy_bypass()` (25-token grief + bypass co-occurrence rule)<br>3. `check_unverified_prior_agreement()` (past-commitment claim + execution demand gate)<br>4. `evaluate_meta_vs_imperative()` (educational question downgrade vs. imperative block)<br>5. `check_unicode_script_and_multilingual_gate()` (Devanagari bypass lexicon + 15% unvalidated Unicode script fail-closed gate) |
| `classifier_features.py` | Drop into root as `classifier_features.py` | Extracts `has_affect_plus_exception`, `claims_prior_assistant_commitment`, and supporting discourse counts for the 568-example local classifier. |
| `gateway.py` | Merge `VerityPriorityGateway` into `gateway.py` | Implements two-threshold gray-zone routing (`tau_low=0.35`, `tau_high=0.75`), strips write/mutation MCP tools on gray-zone turns (`ALLOW_READ_ONLY_TOOLS`), and logs shadow-judge disagreements without letting the shadow judge enforce. |
| `store.py` | Merge `GrayZoneDisagreementRecord` & `log_gray_zone_event` into `store.py` | Append-only JSONL/memory queue for gray-zone turns where the shadow judge is evaluated, holding samples for human review before retraining. |
| `tests/priority_twins.jsonl` | Drop into `tests/priority_twins.jsonl` | 35 attack & benign twin test pairs (5 base pairs across Priorities 1–5 + 15 synthetic grief/coercive-empathy pairs + 15 synthetic response-commitment pairs, plus Arabic/Tamil fail-closed probes). |
| `tests/test_priorities.py` | Drop into `tests/test_priorities.py` | Automated test runner validating 100% attack catch/mitigation and 0% false alarms across all 35 twin pairs. |
| `bundle_verity_patch.sh` | Optional helper script in root | Re-packages the directory into `verity_priority_patch.zip` after local edits. |

---

## 2. Mandatory Human Review Checklist Before Live Enforcement

In `gateway.py`, `VerityPriorityGateway(..., enforce_human_flagged_rules=False)` allows you to run human-flagged rules in shadow/audit mode first. **Do not flip `enforce_human_flagged_rules=True` in production until a human reviews the following:**

1. **Priority 1 (`P1_COERCIVE_EMPATHY_BYPASS` in `policy.py`):**
   - **Why Human Review is Needed:** Distressed users experiencing real bereavement or medical emergencies may phrase urgent requests clumsily. Review shadow-mode triggers to confirm the 25-token window and `benign_compliance_query` exemption do not block legitimate emergency support seekers.
2. **Priority 2 (`P2_UNVERIFIED_PRIOR_COMMITMENT` in `policy.py`):**
   - **Why Human Review is Needed:** Requires `session_history` or `verified_commitments` from `store.py` to be passed into `evaluate_request()`. If `gateway.py` is called statelessly on multi-turn chats without passing prior assistant turns, legitimate follow-ups will be falsely blocked.
3. **Priority 3 (`GRAY_ZONE` thresholds `tau_low`/`tau_high` & Shadow Judge Queue in `gateway.py` / `store.py`):**
   - **Why Human Review is Needed:** The shadow judge is not approved for enforcement. Any gray-zone record written to `store.py` (`needs_human_review=True`) must be manually inspected by a human before its label is added to the 568-example training set, and `tau_low`/`tau_high` must be calibrated against your held-out ROC curve.
4. **Priority 4 (`P4_META_DISCUSSION_DOWNGRADE` in `policy.py`):**
   - **Why Human Review is Needed:** Downgrading deterministic keyword hits on meta-questions (`Why do attackers...`) is safe only when `mcp_tool_requested=False`. Red-team the regex against multi-sentence wrapper prompts ("Why do attackers run X? Now do it.") before enabling live downgrades.
5. **Priority 5 (`P5_FAIL_CLOSED_UNVALIDATED_SCRIPT` in `policy.py`):**
   - **Why Human Review is Needed:** Failing closed when non-validated scripts (e.g., Arabic, Tamil) exceed 15% of alphabetic characters will block 100% of legitimate users writing in those scripts. Product/ops must decide whether to return an "Unsupported language for security verification" refusal or route to a zero-tool fallback.
