"""Business-policy guard (milestone 4).

The injection guard stops attacks on the model. This layer stops the model
from doing things the *business* forbids. The app supplies its policy in
plain language (e.g. "All sales are final. No refunds are offered."), and
Verity enforces it on both sides of the call:

- request side: a request that seeks an absolutely-prohibited action is
  blocked before it reaches the model;
- response side: if the model's answer performs or promises a prohibited
  action anyway, the answer is blocked before it reaches the user.

v0 is deterministic (pattern-based) so it works identically in mock mode.
In live mode an LLM judge additionally reviews the response against the
full policy text, which covers nuanced rules (e.g. refund windows) that
patterns cannot decide.
"""
import json
import re

import httpx

from . import config

# Actions a user might seek, and the absolute-prohibition phrasings a
# business uses to forbid them.
_ACTIONS = {
    "refund": re.compile(r"\b(refund|money back)\b", re.IGNORECASE),
    "discount": re.compile(r"\b(discount|coupon|promo code)\b", re.IGNORECASE),
    "free_item": re.compile(r"\bfree (replacement|product|item|unit)\b",
                            re.IGNORECASE),
    "privilege_grant": re.compile(
        r"\b(admin|administrator|root|superuser|elevated) "
        r"(privileges|access|rights|permissions)\b|"
        r"\bgrant me\b.{0,40}(admin|full[- ]access|privileges)|"
        r"\bgive me\b.{0,30}(admin|full[- ]access|privileges)|"
        r"\belevate (my|the) (privileges|access|account)\b|"
        r"\bmake me an? (admin|administrator)\b",
        re.IGNORECASE),
}
_FORBIDDEN = {
    "refund": re.compile(
        r"no refunds?\b|non[- ]refundable|refunds? (are )?not "
        r"(allowed|offered|available|given)|all sales are final|"
        r"refunds? .{0,30}(require|need) (human |manager )?approval",
        re.IGNORECASE),
    "discount": re.compile(
        r"no discounts?\b|discounts? (are )?not "
        r"(allowed|offered|available|given)",
        re.IGNORECASE),
    "free_item": re.compile(
        r"no free (replacements?|products?|items?)|free "
        r"(replacements?|products?|items?) (are )?not "
        r"(allowed|offered|available|given)",
        re.IGNORECASE),
    "privilege_grant": re.compile(
        r"no\b[^.]{0,90}(admin privileges|admin access|administrator "
        r"access|elevated privileges|elevated access)|"
        r"(admin privileges|admin access|elevated privileges) "
        r".{0,30}(never|not) (be )?(granted|given|allowed|provided)|"
        r"never (grant|give|provide)\b.{0,40}(admin|privileges|access)",
        re.IGNORECASE),
}
# Bot-voice phrases that mean the model performed/promised the action.
_PERFORMED = {
    "refund": re.compile(
        r"refund (has been|was|is being) (initiated|approved|processed)|"
        r"refund (approved|confirmed)\b|we('ve| have) refunded|"
        r"we will refund|your refund (is|has been)|"
        r"money (will be|has been) refunded|"
        r"amount (will be|has been) credited|"
        r"i('ve| have) (initiated|approved|processed) (your|the) refund",
        re.IGNORECASE),
    "discount": re.compile(
        r"(discount|coupon|promo code) (has been|was) (applied|added)|"
        r"i('ve| have) applied .{0,20}(discount|coupon)",
        re.IGNORECASE),
    "free_item": re.compile(
        r"free (replacement|product|item) (has been|was) "
        r"(added|approved|shipped|arranged)|we('ve| have) added a free",
        re.IGNORECASE),
    "privilege_grant": re.compile(
        r"(admin|administrator|elevated) (privileges|access) "
        r"(has been|have been|was|were) (granted|activated|enabled)|"
        r"i('ve| have) granted you\b.{0,30}(admin|access|privileges)|"
        r"your account (has been|was) (upgraded|elevated) to "
        r"(admin|administrator)",
        re.IGNORECASE),
}


def _prohibited_actions(policy: str) -> list[str]:
    return [a for a, rx in _FORBIDDEN.items() if rx.search(policy or "")]


def check_request(policy: str, user_text: str) -> dict:
    """Block requests that seek an absolutely-prohibited action."""
    for action in _prohibited_actions(policy):
        if _ACTIONS[action].search(user_text or ""):
            return {"blocked": True, "action": action, "method": "policy_rule",
                    "reason": f"policy prohibits {action} requests outright"}
    return {"blocked": False, "action": None, "method": "policy_rule",
            "reason": ""}


_POLICY_JUDGE_SYSTEM = (
    "You are a business-policy compliance checker. Given a POLICY and a "
    "chatbot RESPONSE, decide whether the response performs, promises, or "
    "approves anything the policy forbids. Respond with ONLY JSON: "
    '{"violates": <true|false>, "reason": "<one short sentence>"}'
)


def _judge_response(policy: str, answer: str) -> dict | None:
    try:
        with httpx.Client(timeout=60) as client:
            resp = client.post(
                f"{config.UPSTREAM_BASE_URL}/v1/chat/completions",
                headers={"Authorization": f"Bearer {config.UPSTREAM_API_KEY}"},
                json={"model": config.JUDGE_MODEL, "temperature": 0,
                      "messages": [
                          {"role": "system", "content": _POLICY_JUDGE_SYSTEM},
                          {"role": "user",
                           "content": f"POLICY:\n{policy}\n\nRESPONSE:\n{answer}"}]},
            )
            resp.raise_for_status()
            raw = resp.json()["choices"][0]["message"]["content"]
        cleaned = re.sub(r"^```(?:json)?|```$", "", raw.strip(),
                         flags=re.MULTILINE).strip()
        data = json.loads(cleaned)
        return {"violates": bool(data.get("violates", False)),
                "reason": str(data.get("reason", ""))[:200],
                "method": f"policy_judge:{config.JUDGE_MODEL}"}
    except Exception:
        return None


def check_response(policy: str, answer: str) -> dict:
    """Block answers that perform a prohibited action."""
    for action in _prohibited_actions(policy):
        if _PERFORMED[action].search(answer or ""):
            return {"violates": True, "action": action, "method": "policy_rule",
                    "reason": f"response performs a prohibited {action}"}
    if not config.MOCK_MODE and config.UPSTREAM_API_KEY:
        judged = _judge_response(policy, answer)
        if judged is not None:
            judged["action"] = None
            return judged
    return {"violates": False, "action": None, "method": "policy_rule",
            "reason": ""}
