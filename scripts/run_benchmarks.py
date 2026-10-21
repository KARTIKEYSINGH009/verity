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
