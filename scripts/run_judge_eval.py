"""Judge-escalation evaluation harness (Step 4, 2026-10-23).

Runs the frozen language-stratified eval set (judge-eval v1) through
screen() + shadow observe() and reports, per stratum and overall:
classifier recall / FPR, escalation coverage, judge recall / FPR on the
escalated subset, disagreement rate, judge error rate, latency, and a
rough token-cost estimate.

The judge is used only when a key is configured (VERITY_INJECTION_JUDGE_*
env); without one, judge metrics are reported as unavailable and the
error rate reflects that honestly. This harness never trains on the
eval set and never changes request outcomes (shadow semantics).
"""
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from verity.escalation import injection_judge, observe  # noqa: E402
from verity.guard import screen  # noqa: E402

EVAL_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "goals",
    "verity-ai-firewall-startup", "files", "judge-eval-v1.jsonl")


def main() -> None:
    rows = [json.loads(l) for l in open(EVAL_PATH, encoding="utf-8")
            if l.strip()]
    judge = (lambda t: injection_judge(t))  # noqa: E731
    stats = {}
    lat = []
    chars = 0
    for r in rows:
        s = stats.setdefault(r["stratum"], dict(
            atk=0, atk_blocked=0, atk_esc=0, atk_judge_caught=0,
            ben=0, ben_blocked=0, ben_esc=0, ben_judge_flagged=0,
            judge_errors=0, esc_total=0, disagreements=0))
        base = screen(r["text"])
        t0 = time.perf_counter()
        flags = observe(r["text"], base, judge=judge, mode="shadow")
        lat.append((time.perf_counter() - t0) * 1000)
        chars += len(r["text"])
        mal = r["label"] == "malicious"
        esc = any(f.startswith("esc:") for f in flags)
        jerr = "judge_error" in flags
        jatk = any(f.startswith("judge:attack:") for f in flags)
        if esc:
            s["esc_total"] += 1
            if jerr:
                s["judge_errors"] += 1
            if "judge_disagree" in flags:
                s["disagreements"] += 1
        if mal:
            s["atk"] += 1
            s["atk_blocked"] += int(base["blocked"])
            s["atk_esc"] += int(esc)
            s["atk_judge_caught"] += int(esc and jatk)
        else:
            s["ben"] += 1
            s["ben_blocked"] += int(base["blocked"])
            s["ben_esc"] += int(esc)
            s["ben_judge_flagged"] += int(esc and jatk)

    def line(name, s):
        rec = s["atk_blocked"] / s["atk"] if s["atk"] else float("nan")
        fpr = s["ben_blocked"] / s["ben"] if s["ben"] else float("nan")
        print(f"{name:>10}: atk {s['atk']:>3} recall {rec:.2f} | "
              f"ben {s['ben']:>3} FPR {fpr:.2f} | esc {s['esc_total']:>3} "
              f"(atk caught-by-judge {s['atk_judge_caught']}, "
              f"ben flagged {s['ben_judge_flagged']}, "
              f"errors {s['judge_errors']}, disagree {s['disagreements']})")

    tot = {k: sum(s[k] for s in stats.values()) for k in
           next(iter(stats.values()))}
    for name in sorted(stats):
        line(name, stats[name])
    line("TOTAL", tot)
    esc_n = tot["esc_total"]
    print(f"escalated: {esc_n}/{len(rows)} | judge error rate on "
          f"escalated: {tot['judge_errors']}/{esc_n} | observe latency "
          f"p50 {statistics.median(lat):.0f} ms (incl. judge call when "
          f"configured) | eval chars {chars} (~{chars // 4} prompt "
          f"tokens + fixed judge system prompt per call)")


if __name__ == "__main__":
    main()
