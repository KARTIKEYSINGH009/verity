"""Faithfulness scorer, grounding-check v0.

Given the context the model was allowed to use and the answer it produced,
estimates how grounded the answer is: what fraction of the answer's
sentences share meaningful content words with the context.

This is intentionally naive — it establishes the scoring interface.
Milestone 2 replaces it with LLM-as-judge, milestone 3 with a fine-tuned
natural-language-inference model.
"""
import re

_WORD = re.compile(r"[a-z0-9]{3,}")
_STOP = frozenset(
    "the a an and or for with from that this these those are was were been "
    "has have had will would can could should into than then they them their "
    "its you your our".split()
)


def _keywords(text: str) -> set[str]:
    return set(_WORD.findall(text.lower())) - _STOP


def _sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+", text.strip())
    return [p for p in parts if p]


def faithfulness_score(context: str, answer: str) -> dict:
    """Score answer groundedness against context. Returns score + detail."""
    if not context or not answer:
        return {"score": 0.0, "verdict": "no_context_or_answer",
                "grounded_sentences": 0, "total_sentences": 0}
    ctx_words = _keywords(context)
    sents = _sentences(answer)
    grounded = sum(1 for s in sents if _keywords(s) & ctx_words)
    score = grounded / len(sents) if sents else 0.0
    verdict = ("grounded" if score >= 0.7
               else "partially_grounded" if score >= 0.4
               else "hallucination_risk")
    return {"score": round(score, 3), "verdict": verdict,
            "grounded_sentences": grounded, "total_sentences": len(sents)}
