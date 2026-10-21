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
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision and recall else None)
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "recall": round(recall, 3) if recall is not None else None,
        "precision": round(precision, 3) if precision is not None else None,
        "f1": round(f1, 3) if f1 is not None else None,
        "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else None,
        "accuracy": round((tp + tn) / len(rows), 3) if rows else None,
    }


def _pct(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, int(q * len(sorted_vals)))
    return round(sorted_vals[idx], 2)


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
    # Precision/recall for unsupported-answer detection (positive class =
    # hallucination; strict prediction = verdict hallucination_risk).
    f_tp = f_fp = f_fn = 0
    for context, answer, expected in FAITHFULNESS_EVAL:
        verdict = faithfulness_score(context, answer)["verdict"]
        pred_unsup = verdict == "hallucination_risk"
        actual_unsup = expected == "hallucination"
        if pred_unsup and actual_unsup:
            f_tp += 1
        elif pred_unsup and not actual_unsup:
            f_fp += 1
        elif not pred_unsup and actual_unsup:
            f_fn += 1
    f_prec = f_tp / (f_tp + f_fp) if f_tp + f_fp else None
    f_rec = f_tp / (f_tp + f_fn) if f_tp + f_fn else None
    faithfulness = {
        "cases": len(FAITHFULNESS_EVAL),
        "verdict_accuracy": round(sum(faith_rows) / len(faith_rows), 3),
        "unsupported_precision": round(f_prec, 3) if f_prec is not None else None,
        "unsupported_recall": round(f_rec, 3) if f_rec is not None else None,
        "method": "deterministic heuristic scorer (the LLM judge's offline "
                  "fallback), 8 hand-labelled cases — small-sample signal, "
                  "not a production SLA. The live-mode judge itself is not "
                  "measured here because it depends on the operator's model "
                  "and key.",
    }

    # Threshold sweep on the VALIDATION set only (never the test set).
    from validation_set import VALIDATION_SET
    sweep = {}
    for thr in (0.5, 0.65, 0.75, 0.85, 0.9):
        rows = []
        for text, label in VALIDATION_SET:
            p = probability_malicious(text)
            rows.append(((p is not None and p >= thr),
                         label == "malicious"))
        m = _metrics(rows)
        sweep[str(thr)] = {"recall": m["recall"],
                           "false_positive_rate": m["false_positive_rate"]}

    import subprocess
    from datetime import datetime, timezone
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True,
            cwd=os.path.join(os.path.dirname(__file__), "..")).stdout.strip()
    except Exception:
        commit = "unknown"
    lat_sorted = sorted(latencies)
    meta = {
        "commit": commit,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "classifier": "naive-bayes word(1,2)+char(3,4) n-grams, normalized input",
        "threshold": CLASSIFIER_THRESHOLD,
        "train_examples": len(DATASET) + len(load_corrections()),
        "validation_examples": len(VALIDATION_SET),
        "test_examples": len(EVAL_SET),
        "latency_ms": {"p50": _pct(lat_sorted, 0.5),
                       "p95": _pct(lat_sorted, 0.95),
                       "p99": _pct(lat_sorted, 0.99),
                       "mean": round(sum(latencies) / len(latencies), 2)},
        "threshold_sweep_on_validation": sweep,
    }

    results = {
        "meta": meta,
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
