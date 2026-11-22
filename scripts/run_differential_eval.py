"""Differential + counterfactual eval for Verity — read-only harness.

Runs every prompt in the locked golden set through each guard stage
separately (raw vs normalized, rules/policy, classifier score, session
risk) and replays the same scenario through the whole path
(normalization -> policy -> classifier -> session risk -> egress
against a recorded upstream reply). Every bypass and every false block
is reproducible with a named failing stage.

Counterfactuals: one word swapped, a spelling change, a punctuation
change, and an English<->Hinglish switch. Only measured results are
reported — no invented numbers.

Read-only: imports and calls the guard functions, never modifies the
locked data, the gateway, or production code. No new dependencies,
no network calls, no secrets.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "tests" / "data" / "golden_eval_20261122.json"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from verity.egress import scan_output  # noqa: E402
from verity.guard import CLASSIFIER_THRESHOLD, RULES, screen  # noqa: E402
from verity.normalize import harden_normalize, scan_windows  # noqa: E402
from verity.session_risk import SessionRisk  # noqa: E402

TENANT_ID = "differential-eval"

STAGE_NAMES = ("raw", "normalization", "rules", "classifier", "session_risk", "egress")

_WILSON_Z = 1.959963984540054

_WORD_SWAPS: tuple[tuple[str, str], ...] = (
    ("please", "plz"),
    ("money", "paisa"),
    ("send", "bhejo"),
    ("account", "khata"),
    ("help", "madad"),
    ("urgent", "turant"),
    ("verify", "jaanch"),
    ("code", "otp"),
    ("now", "abhi"),
    ("friend", "yaar"),
    ("rules", "niyam"),
    ("niyam", "rules"),
)

_HINGLISH_MARKERS = frozenset(
    "bina jaanch bhai yaar karo nahi mujhe mera mere tum abhi chahiye paisa "
    "wapas batao bhejo karke chhodo bhool saare purani hidayat niyam madad".split()
)

_STOPWORDS = frozenset(
    "the and you your for that this with from have are was not but they them "
    "can will just please right now here there what when where who how why "
    "all any our out get got had has his her she him its into over than then "
    "about would could should been being were".split()
)


def wilson_ci(successes: int, total: int, z: float = _WILSON_Z) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion (95% by default)."""
    if total <= 0:
        return 0.0, 0.0
    p = successes / total
    z2 = z * z
    denominator = 1 + z2 / total
    center = (p + z2 / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z2 / (4 * total)) / total) / denominator
    lo = max(0.0, center - margin)
    hi = min(1.0, center + margin)
    # Exact edges: floating-point residue must not leak past the bounds.
    if successes == 0:
        lo = 0.0
    if successes == total:
        hi = 1.0
    return lo, hi


def _screen_windows(text: str) -> dict[str, Any]:
    """Screen every scan window; merge with max classifier score and union of signals."""
    merged: dict[str, Any] | None = None
    for window in scan_windows(text):
        wv = screen(window)
        if merged is None:
            merged = {
                "blocked": bool(wv.get("blocked", wv.get("block", False))),
                "signals": list(wv.get("signals", [])),
                "heuristic_hits": list(wv.get("heuristic_hits", [])),
                "classifier_score": float(wv.get("classifier_score", 0.0) or 0.0),
            }
        else:
            merged["blocked"] = merged["blocked"] or bool(wv.get("blocked", wv.get("block", False)))
            merged["signals"] = sorted(set(merged["signals"]) | set(wv.get("signals", [])))
            merged["heuristic_hits"] = sorted(set(merged["heuristic_hits"]) | set(wv.get("heuristic_hits", [])))
            merged["classifier_score"] = max(merged["classifier_score"], float(wv.get("classifier_score", 0.0) or 0.0))
    return merged if merged is not None else {"blocked": False, "signals": [], "heuristic_hits": [], "classifier_score": 0.0}


def _extract_matched_tokens(normalized_text: str, signals: list[str]) -> list[dict[str, str]]:
    """Map fired rule signals back to the tokens in the normalized text that triggered them."""
    found: list[dict[str, str]] = []
    lowered = normalized_text.lower()
    for sig in signals:
        pat = RULES.get(sig)
        if pat is None:
            continue
        for match in re.finditer(pat, lowered):
            found.append({"rule": sig, "token": match.group(0)})
    return found


def replay_prompt(
    text: str,
    expected: str,
    prompt_id: str = "",
    upstream_reply: str = "",
    canaries: tuple[str, ...] = (),
    session_risk: SessionRisk | None = None,
    session_id: str = "",
) -> dict[str, Any]:
    """Replay one prompt through every stage, then the whole path."""
    normalized = harden_normalize(text)
    raw_verdict = _screen_windows(text)
    norm_verdict = _screen_windows(normalized)
    text_changed_by_normalize = normalized != text

    raw_blocked = bool(raw_verdict["blocked"])
    norm_blocked = bool(norm_verdict["blocked"])
    classifier_score = norm_verdict["classifier_score"]
    rules_signals = [s for s in norm_verdict["signals"] if s != "ml_classifier"]
    rules_blocked = bool(rules_signals)
    classifier_blocked = (
        classifier_score is not None and classifier_score >= CLASSIFIER_THRESHOLD
    ) or "ml_classifier" in norm_verdict["signals"]

    sr = session_risk
    sid = session_id
    tenant_id = TENANT_ID
    session_ema: float | None = None
    session_blocked = False
    if sr is not None and sid:
        session_ema = sr.add(tenant_id, sid, classifier_score, normalized)
        if classifier_score is not None:
            session_blocked = (
                classifier_score >= CLASSIFIER_THRESHOLD
                or (0.6 * classifier_score + 0.4 * session_ema) >= 0.75
            )

    if upstream_reply:
        egress_result = scan_output(upstream_reply, canaries=canaries)
    else:
        egress_result = {"action": "allow"}
    egress_blocked = egress_result["action"] == "block"

    final_blocked = norm_blocked or session_blocked or egress_blocked

    want_block = expected == "block"
    outcome = "caught" if want_block else "correct_allow"
    failing_stage = None
    if want_block and final_blocked:
        outcome = "caught"
    elif want_block and not final_blocked:
        outcome = "miss"
        if text_changed_by_normalize and not norm_blocked:
            failing_stage = "normalization"
        elif rules_blocked:
            failing_stage = "rules"
        else:
            failing_stage = "rules+classifier+session_risk"
    elif not want_block and final_blocked:
        outcome = "false_block"
        if egress_blocked and not (norm_blocked or session_blocked):
            failing_stage = "egress"
        elif session_blocked and not norm_blocked:
            failing_stage = "session_risk"
        elif text_changed_by_normalize and not raw_blocked:
            failing_stage = "normalization"
        elif rules_blocked and classifier_blocked:
            failing_stage = "rules+classifier"
        elif rules_blocked:
            failing_stage = "rules"
        else:
            failing_stage = "classifier"
    else:
        outcome = "correct_allow"
        failing_stage = None

    return {
        "id": prompt_id,
        "text": text,
        "normalized": normalized,
        "text_changed_by_normalize": text_changed_by_normalize,
        "raw_verdict": raw_verdict,
        "norm_verdict": norm_verdict,
        "classifier_score": classifier_score,
        "session_ema": session_ema,
        "stages": {
            "raw": raw_blocked,
            "normalization": norm_blocked and not raw_blocked,
            "rules": rules_blocked,
            "classifier": classifier_blocked,
            "session_risk": session_blocked,
            "egress": egress_blocked,
        },
        "final_blocked": final_blocked,
        "expected": expected,
        "outcome": outcome,
        "failing_stage": failing_stage,
        "matched_tokens": _extract_matched_tokens(normalized, rules_signals),
    }


def _word_swap_edit(text: str) -> tuple[str, str]:
    """Swap the first word that has an English<->Hinglish pair in _WORD_SWAPS."""
    words = text.split()
    for idx, word in enumerate(words):
        stripped = word.strip(".,!?;:'\"()")
        for src, dst in _WORD_SWAPS:
            if stripped.lower() == src:
                new_words = words[:]
                new_words[idx] = word.replace(stripped, dst)
                return " ".join(new_words), f"{src}->{dst}"
    return text, "no-swap"


def _spelling_edit(text: str) -> tuple[str, str]:
    """Swap two adjacent letters in the longest content word."""
    words = text.split()
    target_idx = -1
    target = ""
    for idx, word in enumerate(words):
        core = word.strip(".,!?;:'\"()")
        if len(core) >= 4 and core.lower() not in _STOPWORDS and len(core) > len(target):
            target_idx = idx
            target = core
    if target_idx < 0:
        return text, "no-spelling-edit"
    chars = list(target)
    chars[1], chars[2] = chars[2], chars[1]
    edited = "".join(chars)
    new_words = words[:]
    new_words[target_idx] = words[target_idx].replace(target, edited)
    return " ".join(new_words), f"{target}->{edited}"


def _hinglish_edit(text: str) -> tuple[str, str]:
    """English<->Hinglish switch: Hinglish marker -> English, else English -> Hinglish."""
    words = text.split()
    for idx, word in enumerate(words):
        core = word.strip(".,!?;:'\"()")
        if core.lower() in _HINGLISH_MARKERS:
            for src, dst in _WORD_SWAPS:
                if src == core.lower():
                    new_words = words[:]
                    new_words[idx] = word.replace(core, dst)
                    return " ".join(new_words), f"{src}->{dst}"
    for idx, word in enumerate(words):
        core = word.strip(".,!?;:'\"()")
        for src, dst in _WORD_SWAPS:
            if core.lower() == src:
                new_words = words[:]
                new_words[idx] = word.replace(core, dst)
                return " ".join(new_words), f"{src}->{dst}"
    return text, "no-hinglish-swap"


def generate_counterfactuals(text: str, category: str = "") -> list[dict[str, str]]:
    """Generate one small edit of each kind; the original prompt is never modified."""
    ws_text, ws_detail = _word_swap_edit(text)
    sp_text, sp_detail = _spelling_edit(text)
    if text.endswith("."):
        punct_text, punct_detail = text[:-1] + "!", ".->!"
    elif text.endswith("!"):
        punct_text, punct_detail = text[:-1] + ".", "!->."
    else:
        punct_text, punct_detail = text + "!", "append-!"
    hl_text, hl_detail = _hinglish_edit(text)
    return [
        {"kind": "word_swap", "detail": ws_detail, "text": ws_text},
        {"kind": "spelling_change", "detail": sp_detail, "text": sp_text},
        {"kind": "punctuation_change", "detail": punct_detail, "text": punct_text},
        {"kind": "en_hinglish_switch", "detail": hl_detail, "text": hl_text},
    ]


def evaluate_dataset(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Evaluate every case and its counterfactuals; aggregate rates and disagreements."""
    session = SessionRisk()
    results: list[dict[str, Any]] = []
    misses: list[dict[str, Any]] = []
    false_blocks: list[dict[str, Any]] = []
    counterfactual_flips: list[dict[str, Any]] = []
    stage_disagreements: dict[str, int] = {name: 0 for name in STAGE_NAMES}
    per_category: dict[str, dict[str, int]] = {}
    for case in cases:
        category = str(case.get("category", "unknown"))
        expected = str(case.get("expected", "allow"))
        res = replay_prompt(
            str(case["text"]),
            expected=expected,
            prompt_id=str(case.get("id", "")),
            upstream_reply=str(case.get("upstream_reply", "")),
            canaries=tuple(case.get("canaries", ())),
            session_risk=session,
            session_id=str(case.get("session_id", "")),
        )
        res["category"] = category
        results.append(res)
        counts = per_category.setdefault(category, {"total": 0, "caught": 0})
        counts["total"] += 1
        if res["outcome"] == "caught":
            counts["caught"] += 1
        if res["outcome"] == "miss":
            misses.append(res)
        elif res["outcome"] == "false_block":
            false_blocks.append(res)
        for stage, blocked in res["stages"].items():
            if blocked != res["final_blocked"]:
                stage_disagreements[stage] += 1
        for cf in generate_counterfactuals(str(case["text"]), category):
            cf_res = replay_prompt(
                cf["text"],
                expected=expected,
                prompt_id=f"{res['id']}-cf-{cf['kind']}",
            )
            if cf_res["final_blocked"] != res["final_blocked"]:
                flipped_stages = [s for s in STAGE_NAMES if cf_res["stages"][s] != res["stages"][s]]
                counterfactual_flips.append(
                    {
                        "id": res["id"],
                        "category": category,
                        "kind": cf["kind"],
                        "detail": cf["detail"],
                        "orig_text": str(case["text"]),
                        "cf_text": cf["text"],
                        "orig_blocked": res["final_blocked"],
                        "cf_blocked": cf_res["final_blocked"],
                        "flipped_stages": flipped_stages,
                        "orig_signals": res["norm_verdict"]["signals"],
                        "cf_signals": cf_res["norm_verdict"]["signals"],
                    }
                )
    category_rates: dict[str, dict[str, float | int]] = {}
    for category, counts in per_category.items():
        lo, hi = wilson_ci(counts["caught"], counts["total"])
        category_rates[category] = {
            "total": counts["total"],
            "caught": counts["caught"],
            "rate": (counts["caught"] / counts["total"]) if counts["total"] else 0.0,
            "ci_low": lo,
            "ci_high": hi,
        }
    return {
        "total_prompts": len(results),
        "results": results,
        "misses": misses,
        "false_blocks": false_blocks,
        "counterfactual_flips": counterfactual_flips,
        "stage_disagreements": stage_disagreements,
        "per_category": category_rates,
    }


def format_report(report: dict[str, Any]) -> str:
    """Render the plain-text report: rates with Wilson 95% CI, disagreements, misses/false blocks, flips."""
    lines: list[str] = []
    lines.append(f"differential eval: {report['total_prompts']} prompts")
    lines.append("")
    lines.append("PER-CATEGORY RATES (Wilson 95% CI):")
    for category, stats in sorted(report["per_category"].items()):
        lines.append(
            f"  {category}: {stats['caught']}/{stats['total']} = {stats['rate']:.2%} "
            f"(95% CI {stats['ci_low']:.2%}–{stats['ci_high']:.2%})"
        )
    lines.append("")
    lines.append("STAGE-LEVEL DISAGREEMENTS WITH FINAL VERDICT:")
    for stage, count in sorted(report["stage_disagreements"].items()):
        lines.append(f"  {stage}: {count}")
    lines.append("")
    lines.append("MISSES (expected block, not blocked):")
    for m in report["misses"]:
        lines.append(
            f"  [{m['id']}] {m['category']} failing_stage={m['failing_stage']} "
            f"score={m['classifier_score']} signals={m['norm_verdict']['signals']} text={m['text']!r}"
        )
    lines.append("")
    lines.append("FALSE BLOCKS (expected allow, blocked):")
    for fb in report["false_blocks"]:
        lines.append(
            f"  [{fb['id']}] {fb['category']} failing_stage={fb['failing_stage']} "
            f"score={fb['classifier_score']} signals={fb['norm_verdict']['signals']} text={fb['text']!r}"
        )
        for tok in fb["matched_tokens"]:
            lines.append(f"      matched token: {tok['rule']} -> {tok['token']!r}")
    lines.append("")
    lines.append("COUNTERFACTUAL VERDICT FLIPS:")
    for fl in report["counterfactual_flips"]:
        lines.append(
            f"  [{fl['id']}] {fl['category']} {fl['kind']} ({fl['detail']}): "
            f"blocked {fl['orig_blocked']} -> {fl['cf_blocked']} flipped_stages={fl['flipped_stages']} cf_text={fl['cf_text']!r}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """CLI: python scripts/run_differential_eval.py [--data PATH]."""
    parser = argparse.ArgumentParser(description="Run Verity differential + counterfactual eval.")
    parser.add_argument("--data", type=Path, default=DATA, help="Path to golden eval JSON.")
    args = parser.parse_args(argv)

    cases = json.loads(args.data.read_text(encoding="utf-8"))
    report = evaluate_dataset(cases)
    print(format_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
