"""Run the held-out benchmark and publish the results (audit response).

Measures the guard three ways on scripts/eval_set.py — examples disjoint
from all training data:
  * rules_only       heuristic patterns alone
  * classifier_only  trained model alone (threshold 0.75)
  * combined         the production screen() verdict

Reports recall, precision, false-positive rate, per-category recall for
the combined mode, and average screening latency. Writes the results to
site/benchmarks.json (served by the gateway) and prints a summary.

Usage: python scripts/run_benchmarks.py
"""
import json
import os
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from eval_set import EVAL_SET  # noqa: E402
from injection_dataset import DATASET  # noqa: E402
from train_injection_classifier import load_corrections  # noqa: E402

from verity.guard import CLASSIFIER_THRESHOLD, detect_injection, screen  # noqa: E402
from verity.injection_classifier import probability_malicious  # noqa: E402
from verity.scoring import faithfulness_score  # noqa: E402

# Faithfulness mini-eval for the heuristic scorer (the judge's fallback).
# (context, answer, expected verdict family: grounded | hallucination)
FAITHFULNESS_EVAL = [
    ("Our refund policy allows returns within 30 days of purchase.",
     "You can return your purchase within 30 days.", "grounded"),
    ("The hotel check-in time is 2 PM and check-out is 11 AM.",
     "Check-in is at 2 PM and check-out is at 11 AM.", "grounded"),
    ("The battery lasts up to 20 hours on a single charge.",
     "Battery life is up to 20 hours per charge.", "grounded"),
    ("The museum is open Tuesday to Sunday, closed on Mondays.",
     "The museum is closed on Mondays and open Tuesday to Sunday.", "grounded"),
    ("Our refund policy allows returns within 30 days of purchase.",
     "You can return your purchase within 90 days and get a free gift card.", "hallucination"),
    ("The hotel check-in time is 2 PM and check-out is 11 AM.",
     "Check-in is at noon and the hotel offers free airport pickup.", "hallucination"),
    ("The battery lasts up to 20 hours on a single charge.",
     "The battery lasts 48 hours and charges via solar power.", "hallucination"),
    ("The museum is open Tuesday to Sunday, closed on Mondays.",
     "The museum hosts night tours every Friday with free entry.", "hallucination"),
]

OUT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "site", "benchmarks.json")


def _metrics(rows: list[tuple[bool, bool]]) -> dict:
    tp = sum(1 for p, a in rows if p and a)
    fp = sum(1 for p, a in rows if p and not a)
    fn = sum(1 for p, a in rows if not p and a)
    tn = sum(1 for p, a in rows if not p and not a)
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "recall": round(tp / (tp + fn), 3) if tp + fn else None,
        "precision": round(tp / (tp + fp), 3) if tp + fp else None,
        "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else None,
        "accuracy": round((tp + tn) / len(rows), 3) if rows else None,
    }


if __name__ == "__main__":
    # Disjointness guardrail: no eval text may appear in training data.
    trained = {t.strip().lower() for t, _ in DATASET + load_corrections()}
    overlap = [t for t, _, _ in EVAL_SET if t.strip().lower() in trained]
    assert not overlap, f"eval examples leaked into training: {overlap}"

    modes = {"rules_only": [], "classifier_only": [], "combined": []}
    per_category: dict[str, list[tuple[bool, bool]]] = defaultdict(list)
    latencies = []
    misses, false_alarms = [], []

    for text, label, category in EVAL_SET:
        actual = label == "malicious"
        started = time.perf_counter()
        verdict = screen(text)
        latencies.append((time.perf_counter() - started) * 1000)

        rules_hit = bool(detect_injection(text))
        score = probability_malicious(text)
        clf_hit = score is not None and score >= CLASSIFIER_THRESHOLD
        combined = verdict["blocked"]

        modes["rules_only"].append((rules_hit, actual))
        modes["classifier_only"].append((clf_hit, actual))
        modes["combined"].append((combined, actual))
        per_category[category].append((combined, actual))
        if actual and not combined:
            misses.append({"text": text, "category": category})
        if not actual and combined:
            false_alarms.append({"text": text, "category": category,
                                 "signals": verdict["signals"]})

    faith_rows = []
    for context, answer, expected in FAITHFULNESS_EVAL:
        verdict = faithfulness_score(context, answer)["verdict"]
        got = "grounded" if verdict == "grounded" else "hallucination"
        faith_rows.append(got == expected)
    faithfulness = {
        "cases": len(FAITHFULNESS_EVAL),
        "verdict_accuracy": round(sum(faith_rows) / len(faith_rows), 3),
        "method": "deterministic heuristic scorer (the LLM judge's offline "
                  "fallback); the live-mode judge itself is not measured "
                  "here because it depends on the operator's model and key.",
    }

    results = {
        "dataset": {
            "total": len(EVAL_SET),
            "malicious": sum(1 for _, l, _ in EVAL_SET if l == "malicious"),
            "benign": sum(1 for _, l, _ in EVAL_SET if l == "benign"),
            "held_out": True,
            "note": "Fresh phrasings disjoint from all training data; "
                    "benign split is deliberately hard near-misses.",
        },
        "modes": {name: _metrics(rows) for name, rows in modes.items()},
        "combined_per_category": {
            cat: _metrics(rows) for cat, rows in sorted(per_category.items())
        },
        "avg_screen_latency_ms_local": round(sum(latencies) / len(latencies), 2),
        "faithfulness_heuristic": faithfulness,
        "misses": misses,
        "false_alarms": false_alarms,
        "methodology": "Rules = verity.guard.detect_injection; classifier = "
                       "Naive Bayes (word + char n-grams) at threshold "
                       f"{CLASSIFIER_THRESHOLD}; combined = production "
                       "screen() verdict. Latency measured locally, "
                       "screening only (excludes model provider call).",
    }
    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    print(json.dumps(results, indent=2))
