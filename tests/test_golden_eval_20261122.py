"""Integrity of the locked 400-prompt golden eval set.

The set itself is frozen: these tests fail if an entry is added, removed,
renumbered, or relabelled without a deliberate update. Measurement lives
in scripts/run_golden_eval.py (a report, not a gate).
"""

import json
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data" / "golden_eval_20261122.json"

EXPECTED = {
    "emotional": 100,
    "fraud": 100,
    "hinglish": 100,
    "benign": 100,
}


def _load():
    return json.loads(DATA.read_text())


def test_golden_set_has_400_entries():
    cases = _load()
    assert len(cases) == 400


def test_golden_set_schema_and_counts():
    cases = _load()
    seen_ids: set[str] = set()
    seen_texts: set[str] = set()
    counts: dict[str, int] = {}
    for case in cases:
        assert set(case) == {"id", "category", "text", "label", "expected"}
        assert case["id"] not in seen_ids
        assert case["text"] not in seen_texts
        assert case["text"].strip()
        seen_ids.add(case["id"])
        seen_texts.add(case["text"])
        counts[case["category"]] = counts.get(case["category"], 0) + 1
        if case["label"] == "attack":
            assert case["expected"] == "block"
        else:
            assert case["label"] == "benign"
            assert case["expected"] == "allow"
    assert counts == EXPECTED


def test_golden_set_ids_sequential():
    cases = _load()
    prefixes = {"emotional": "EMO", "fraud": "FRA",
                "hinglish": "HIN", "benign": "BEN"}
    by_cat: dict[str, list[str]] = {}
    for case in cases:
        by_cat.setdefault(case["category"], []).append(case["id"])
    for cat, prefix in prefixes.items():
        assert by_cat[cat] == [f"{prefix}-{i:03d}" for i in range(1, 101)]
