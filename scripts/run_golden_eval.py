"""Locked 400-prompt golden eval set — measure the guard, do not eyeball it.

Usage (from the repo root):
    python scripts/run_golden_eval.py

Loads tests/data/golden_eval_20261122.json, screens every prompt the way
the gateway does it now (harden_normalize -> scan_windows -> screen each
window, blocked if any window blocks), and prints per-category catch and
false-alarm rates plus the miss lists. Single-turn only: session risk is
not exercised here. Exit code 0 always — this is a measurement, not a
gate. Write the numbers down before changing thresholds.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from verity.guard import screen  # noqa: E402
from verity.normalize import harden_normalize, scan_windows  # noqa: E402

DATA = ROOT / "tests" / "data" / "golden_eval_20261122.json"
REPORT = ROOT / "tests" / "data" / "golden_eval_last_run.json"


def guard_blocked(text: str) -> dict:
    normalized = harden_normalize(text)
    blocked = False
    signals: list[str] = []
    best = None
    for window in scan_windows(normalized):
        v = screen(window)
        if v["blocked"]:
            blocked = True
        for s in v["signals"]:
            if s not in signals:
                signals.append(s)
        if v["classifier_score"] is not None and (
            best is None or v["classifier_score"] > best
        ):
            best = v["classifier_score"]
    return {"blocked": blocked, "signals": signals, "score": best}


def main() -> None:
    cases = json.loads(DATA.read_text())
    by_cat: dict[str, dict] = defaultdict(
        lambda: {"total": 0, "caught": 0, "misses": [], "false_alarms": []}
    )
    for case in cases:
        cat = case["category"]
        by_cat[cat]["total"] += 1
        got = guard_blocked(case["text"])
        want_block = case["expected"] == "block"
        if want_block and got["blocked"]:
            by_cat[cat]["caught"] += 1
        elif want_block and not got["blocked"]:
            by_cat[cat]["misses"].append(
                {"id": case["id"], "score": got["score"],
                 "signals": got["signals"], "text": case["text"]}
            )
        elif not want_block and got["blocked"]:
            by_cat[cat]["false_alarms"].append(
                {"id": case["id"], "score": got["score"],
                 "signals": got["signals"], "text": case["text"]}
            )
        else:
            by_cat[cat]["caught"] += 1
    print(f"golden eval: {len(cases)} prompts")
    for cat in ("emotional", "fraud", "hinglish", "benign"):
        s = by_cat[cat]
        if cat == "benign":
            fa = len(s["false_alarms"])
            print(f"  {cat:10s} false alarms {fa}/{s['total']} "
                  f"({fa / s['total']:.1%})")
        else:
            print(f"  {cat:10s} caught {s['caught']}/{s['total']} "
                  f"({s['caught'] / s['total']:.1%}), "
                  f"missed {len(s['misses'])}")
    for cat in ("emotional", "fraud", "hinglish", "benign"):
        s = by_cat[cat]
        for kind, label in (("misses", "MISS"), ("false_alarms", "FALSE_ALARM")):
            for m in s[kind]:
                print(f"  {label} {m['id']} "
                      f"score={m['score']} signals={m['signals']}")
    REPORT.write_text(json.dumps(
        {cat: {"total": s["total"], "caught": s["caught"],
               "misses": s["misses"], "false_alarms": s["false_alarms"]}
         for cat, s in sorted(by_cat.items())},
        indent=2))
    print(f"report written to {REPORT}")


if __name__ == "__main__":
    main()
