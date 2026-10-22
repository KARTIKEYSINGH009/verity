"""LLM-as-judge faithfulness scoring (milestone 2).

Instead of counting shared words (see scoring.py v0), we ask a language
model to act as a strict grader: given the source context and the answer,
it returns a structured verdict on whether the answer is grounded.

In mock mode (no upstream API key) the judge gracefully falls back to the
heuristic scorer so the whole pipeline stays exercisable offline.
"""
import json
import re

import httpx

from . import config
from .scoring import faithfulness_score as heuristic_score

JUDGE_SYSTEM = (
    "You are a strict factuality grader. Given a SOURCE CONTEXT and an ANSWER, "
    "decide how faithful the answer is to the context. "
    "Respond with ONLY a JSON object of this exact shape, no other text:\n"
    '{"score": <float 0.0-1.0>, '
    '"verdict": "<grounded|partially_grounded|hallucination_risk>", '
    '"rationale": "<one sentence explaining the verdict>"}'
)


def build_judge_prompt(context: str, answer: str) -> list[dict]:
    return [
        {"role": "system", "content": JUDGE_SYSTEM},
        {"role": "user",
         "content": f"SOURCE CONTEXT:\n{context}\n\nANSWER:\n{answer}"},
    ]


def parse_judge_response(text: str) -> dict:
    """Parse the judge's JSON, tolerating markdown fences and stray text."""
    cleaned = re.sub(r"^```(?:json)?|```$", "", (text or "").strip(),
                     flags=re.MULTILINE).strip()
    try:
        data = json.loads(cleaned)
    except (json.JSONDecodeError, ValueError):
        return {"score": 0.0, "verdict": "hallucination_risk",
                "rationale": "judge returned unparseable output"}
    try:
        score = float(data.get("score", 0.0))
    except (TypeError, ValueError):
        score = 0.0
    score = max(0.0, min(1.0, score))
    verdict = data.get("verdict", "hallucination_risk")
    if verdict not in ("grounded", "partially_grounded", "hallucination_risk"):
        verdict = "hallucination_risk" if score < 0.4 else (
            "partially_grounded" if score < 0.7 else "grounded")
    return {"score": round(score, 3), "verdict": verdict,
            "rationale": str(data.get("rationale", ""))[:300]}


def _call_judge_model(messages: list[dict]) -> str:
    with httpx.Client(timeout=60) as client:
        resp = client.post(
            f"{config.UPSTREAM_BASE_URL}/v1/chat/completions",
            headers={"Authorization": f"Bearer {config.UPSTREAM_API_KEY}"},
            json={"model": config.JUDGE_MODEL, "messages": messages,
                  "temperature": 0},
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


def judge_faithfulness(context: str, answer: str) -> dict:
    """Grade answer groundedness. Returns score/verdict/method/rationale."""
    if not context or not answer:
        return {"score": 0.0, "verdict": "hallucination_risk",
                "method": "none", "rationale": "no context or answer"}
    if config.MOCK_MODE or not config.UPSTREAM_API_KEY:
        base = heuristic_score(context, answer)
        base["method"] = "heuristic (mock mode)"
        base["rationale"] = (
            f"{base['grounded_sentences']}/{base['total_sentences']} "
            "sentences are at least half-supported by the context")
        return base
    try:
        raw = _call_judge_model(build_judge_prompt(context, answer))
    except Exception:
        # Audit #21: a judge outage (429/timeout/5xx) must never 500 a
        # completion that already succeeded — fall back to the
        # heuristic scorer, and say so in the method label.
        base = heuristic_score(context, answer)
        base["method"] = "heuristic (judge unavailable)"
        base["rationale"] = (
            "judge model call failed; heuristic fallback used")
        return base
    result = parse_judge_response(raw)
    result["method"] = f"llm_judge:{config.JUDGE_MODEL}"
    return result
