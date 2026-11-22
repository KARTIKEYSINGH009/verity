"""Three-way verdict engine (allow / gray / block) for Verity.

Pure decision logic with no FastAPI imports. It is unit-testable in
isolation and never raises HTTP errors. The gateway calls it after
screening each message; the verdict only decides how the turn is
handled (block / proceed-throttled / proceed normally).

Reconciled 2026-11-22: Gemini's draft verdict.py and its test file
disagreed on the API (reason names, the EMA parameter name, the
per-category table accessor, and the gray-band field names). This file
follows the test contract: short reason codes, `session_ema` as the
parameter name, `get_category_thresholds()` / `get_thresholds()`, and
`gray_score_min` / `gray_score_max` as the band edges.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import config


@dataclass(frozen=True)
class VerdictThresholds:
    block_score: float = 0.85
    session_block: float = 0.75
    gray_score_min: float = 0.50
    gray_score_max: float = 0.85
    obfuscation_delta: float = 0.25
    ema_gray: float = 0.40


def _thresholds_from_config() -> VerdictThresholds:
    """Read thresholds from config on every call, so env overrides and
    test monkeypatches take effect without a restart."""
    return VerdictThresholds(
        block_score=float(getattr(config, "VERDICT_BLOCK_SCORE", 0.85)),
        session_block=float(getattr(config, "VERDICT_SESSION_BLOCK", 0.75)),
        gray_score_min=float(getattr(config, "VERDICT_GRAY_SCORE_MIN", 0.50)),
        gray_score_max=float(getattr(config, "VERDICT_GRAY_SCORE_MAX", 0.85)),
        obfuscation_delta=float(
            getattr(config, "VERDICT_OBFUSCATION_DELTA", 0.25)),
        ema_gray=float(getattr(config, "VERDICT_EMA_GRAY", 0.40)),
    )


def get_category_thresholds() -> dict[str, VerdictThresholds]:
    """Per-category threshold table. All categories share the defaults
    for now — no tuned per-category numbers exist yet; the differential
    harness measures first, calibration comes later."""
    base = _thresholds_from_config()
    return {
        "default": base,
        "emotional": base,
        "fraud": base,
        "hinglish": base,
        "benign": base,
    }


def get_thresholds(category: str | None) -> VerdictThresholds:
    table = get_category_thresholds()
    if not category:
        return table["default"]
    return table.get(category.strip().lower(), table["default"])


def compute_verdict(
    screen: dict[str, Any] | None,
    score: float | None,
    session_ema: float | None = 0.0,
    obfuscation_delta: float | None = 0.0,
    category: str | None = None,
    thresholds: VerdictThresholds | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Decide allow / gray / block for one screened message.

    Block when a hard (non-ml_classifier) rule signal fired, when the
    single-turn score reaches the block bar, or when the session-combined
    score (0.6 * current + 0.4 * EMA) reaches the session bar. Gray when
    there is no hard signal but the score sits in the mid-band, the
    normalized score jumped well above the raw score (obfuscation delta),
    or the session EMA is elevated. Otherwise allow.
    """
    # `ema=` is accepted as an alias for `session_ema` (older call sites).
    if "ema" in kwargs:
        session_ema = kwargs.pop("ema")
    if kwargs:
        raise TypeError(f"unexpected keyword arguments: {sorted(kwargs)}")
    t = thresholds or get_thresholds(category)
    score = 0.0 if score is None else max(0.0, min(1.0, float(score)))
    ema = 0.0 if session_ema is None else max(0.0, min(1.0, float(session_ema)))
    delta = 0.0 if obfuscation_delta is None else max(0.0, float(obfuscation_delta))
    combined = 0.6 * score + 0.4 * ema
    signals = list((screen or {}).get("signals") or [])
    hard_signals = [s for s in signals if str(s).strip().lower() != "ml_classifier"]
    reasons: list[str] = []
    verdict = "allow"
    if hard_signals:
        verdict, reasons = "block", ["hard_rule"]
    elif score >= t.block_score:
        verdict, reasons = "block", ["score_threshold"]
    elif combined >= t.session_block:
        verdict, reasons = "block", ["session_combined"]
    else:
        if t.gray_score_min <= score < t.gray_score_max:
            verdict, reasons = "gray", ["mid_band_score"]
        if delta >= t.obfuscation_delta:
            verdict = "gray"
            if "obfuscation_delta" not in reasons:
                reasons.append("obfuscation_delta")
        if ema >= t.ema_gray:
            verdict = "gray"
            if "elevated_ema" not in reasons:
                reasons.append("elevated_ema")
    return {
        "verdict": verdict,
        "reason": reasons[0] if reasons else "clean",
        "reasons": reasons,
        "category": category,
        "score": score,
        "session_ema": ema,
        "combined_score": combined,
        "obfuscation_delta": delta,
        "hard_signals": hard_signals,
    }
