"""Faithfulness scorer, grounding-check v1.

Given the context the model was allowed to use and the answer it produced,
estimates how grounded the answer is: for each answer sentence, what
fraction of its content words are supported by the context; a sentence
counts as grounded when at least half of its content words are supported.

This is a deterministic heuristic. In live mode the LLM-as-judge
(milestone 2) is the primary scorer and this remains the offline fallback.
(v0 counted a sentence as grounded on ANY shared word, which scored even
invented answers as fully grounded — fixed in v1.)
"""
import re

_WORD = re.compile(r"[a-z0-9]{3,}")
_STOP = frozenset(
    "the a an and or for with from that this these those are was were been "
    "has have had will would can could should into than then they them their "
    "its you your our".split()
)


def _stem(word: str) -> str:
    return word[:-1] if len(word) > 3 and word.endswith("s") else word


def _keywords(text: str) -> set[str]:
    return {_stem(w) for w in _WORD.findall(text.lower())} - _STOP


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

    def supported_fraction(sentence: str) -> float:
        words = _keywords(sentence)
        if not words:
            return 0.0
        return len(words & ctx_words) / len(words)

    grounded = sum(1 for s in sents if supported_fraction(s) >= 0.5)
    score = grounded / len(sents) if sents else 0.0
    verdict = ("grounded" if score >= 0.7
               else "partially_grounded" if score >= 0.4
               else "hallucination_risk")
    return {"score": round(score, 3), "verdict": verdict,
            "grounded_sentences": grounded, "total_sentences": len(sents)}
