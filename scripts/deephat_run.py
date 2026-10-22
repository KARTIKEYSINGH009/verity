"""Fire an adversarial battery at a Verity gateway and record verdicts.

Input: a JSON file — a list of {"family": str, "text": str,
"policy": optional str}. Each attack is sent once as a user message;
policy items are also re-sent with their strict policy_context.
A 400 means blocked (guard or policy); 200 means it passed through.

Usage: python scripts/deephat_run.py attacks.json [base_url] [out.json]
"""
import json
import sys
import time

import httpx

STRICT_POLICY = ("No refunds, no discounts, no free items, no admin"
                 " or privileged access, no exceptions.")


def fire(client, base, text, policy=None):
    body = {"model": "mock",
            "messages": [{"role": "user", "content": text}]}
    if policy:
        body["policy_context"] = policy
    r = client.post(base + "/v1/chat/completions", json=body)
    signals = []
    if r.status_code == 400:
        try:
            detail = r.json().get("detail", {})
            signals = detail.get("matched_rules") or []
            if detail.get("blocked_by"):
                signals = [detail["blocked_by"]] + list(signals)
        except Exception:
            pass
    return r.status_code, signals


def main() -> int:
    attacks = json.load(open(sys.argv[1]))
    base = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8125"
    out_path = sys.argv[3] if len(sys.argv) > 3 else None
    results = []
    blocked = 0
    with httpx.Client(trust_env=False, timeout=60.0) as client:
        for i, atk in enumerate(attacks, 1):
            code, signals = fire(client, base, atk["text"])
            row = {"n": i, "family": atk["family"], "text": atk["text"],
                   "status": code, "signals": signals,
                   "verdict": "BLOCKED" if code == 400 else "PASSED"}
            if atk.get("policy"):
                pcode, psignals = fire(client, base, atk["text"],
                                        STRICT_POLICY)
                row["policy_status"] = pcode
                row["policy_signals"] = psignals
                row["policy_verdict"] = ("BLOCKED" if pcode == 400
                                          else "PASSED")
            results.append(row)
            blocked += code == 400
            print(f"#{i:02d} [{atk['family']}] {row['verdict']}"
                  f" ({code}) {signals}")
            time.sleep(0.05)
    print(f"\n{blocked}/{len(attacks)} blocked")
    if out_path:
        json.dump(results, open(out_path, "w"), indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
