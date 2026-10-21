"""Trained prompt-injection classifier (milestones 3 + 5).

A learned model layered with the regex heuristics in guard.py: multinomial
Naive Bayes over word unigrams + bigrams AND character n-grams, trained on
scripts/injection_dataset.py plus any field corrections in
scripts/corrections.jsonl.

Milestone 5 hardening: input is normalized first (contractions expanded,
obfuscation characters removed), and character n-grams make the model
robust to respellings and letter-tricks ("1gnore", "i-g-n-o-r-e") that a
pure word model misses.

The trained weights ship in verity/data/injection_model.json so inference
needs zero training dependencies. If the model file is missing or corrupt,
`probability_malicious` returns None and the guard falls back to heuristics
only (same graceful-degradation pattern as the milestone-2 judge).
"""
import json
import math
import os
import re

CLASSES = ("malicious", "benign")
_TOKEN = re.compile(r"[a-z]+")
_MODEL_PATH = os.path.join(os.path.dirname(__file__), "data", "injection_model.json")

_CONTRACTIONS = {
    "i'm": "i am", "you're": "you are", "we're": "we are",
    "don't": "do not", "doesn't": "does not", "didn't": "did not",
    "can't": "cannot", "cannot": "cannot", "won't": "will not",
    "it's": "it is", "that's": "that is", "let's": "let us",
    "ain't": "is not", "isn't": "is not", "aren't": "are not",
    "what's": "what is", "i'll": "i will", "you'll": "you will",
}
_ZERO_WIDTH = re.compile(r"[​-‏﻿]")

_MODEL: dict | None = None
_MODEL_TRIED = False


def normalize(text: str) -> str:
    """Lowercase, expand contractions, strip zero-width/obfuscation chars."""
    t = _ZERO_WIDTH.sub("", (text or "").lower())
    for k, v in _CONTRACTIONS.items():
        t = t.replace(k, v)
    return re.sub(r"\s+", " ", t).strip()


def features(text: str) -> list[str]:
    t = normalize(text)
    words = _TOKEN.findall(t)
    grams = list(words)
    grams += [f"{a} {b}" for a, b in zip(words, words[1:])]
    padded = f"  {t}  "
    for n in (3, 4, 5):
        grams += [f"c:{padded[i:i + n]}" for i in range(len(padded) - n + 1)]
    return grams


def train_model(examples: list[tuple[str, str]], alpha: float = 0.5) -> dict:
    """Fit Naive Bayes log-probabilities; returns a JSON-serializable model."""
    counts = {c: {} for c in CLASSES}
    totals = {c: 0 for c in CLASSES}
    docs = {c: 0 for c in CLASSES}
    for text, label in examples:
        if label not in counts:
            raise ValueError(f"unknown label: {label!r}")
        docs[label] += 1
        for f in features(text):
            counts[label][f] = counts[label].get(f, 0) + 1
            totals[label] += 1
    vocab = set(counts["malicious"]) | set(counts["benign"])
    n_docs = docs["malicious"] + docs["benign"]
    v = len(vocab)
    model = {
        "alpha": alpha,
        "vocab_size": v,
        "log_prior": {c: math.log(docs[c] / n_docs) for c in CLASSES},
        "log_prob": {c: {} for c in CLASSES},
        "log_prob_oov": {},
    }
    for c in CLASSES:
        denom = totals[c] + alpha * v
        model["log_prob"][c] = {
            f: math.log((counts[c].get(f, 0) + alpha) / denom) for f in vocab
        }
        model["log_prob_oov"][c] = math.log(alpha / denom)
    return model


def model_available(path: str | None = None) -> bool:
    return load_model(path) is not None


def load_model(path: str | None = None) -> dict | None:
    """Load the trained weights once; returns None on any failure."""
    global _MODEL, _MODEL_TRIED
    if path is not None:
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None
    if _MODEL_TRIED:
        return _MODEL
    _MODEL_TRIED = True
    try:
        with open(_MODEL_PATH, encoding="utf-8") as fh:
            _MODEL = json.load(fh)
    except (OSError, ValueError):
        _MODEL = None
    return _MODEL


def probability_malicious(text: str, model: dict | None = None) -> float | None:
    """Posterior P(malicious | text). None when no trained model is available."""
    model = model if model is not None else load_model()
    if model is None:
        return None
    if not text or not text.strip():
        # No signal: return the base rate rather than guessing.
        return round(math.exp(model["log_prior"]["malicious"]), 4)
    scores = {}
    for c in CLASSES:
        s = model["log_prior"][c]
        lp = model["log_prob"][c]
        oov = model["log_prob_oov"][c]
        for f in features(text):
            s += lp.get(f, oov)
        scores[c] = s
    # softmax over the two class log-scores
    m = max(scores.values())
    exps = {c: math.exp(s - m) for c, s in scores.items()}
    total = exps["malicious"] + exps["benign"]
    return round(exps["malicious"] / total, 4)


def save_model(model: dict, path: str) -> None:
    """Write weights with rounded floats — keeps the shipped JSON compact."""
    compact = {
        **model,
        "log_prior": {c: round(v, 4) for c, v in model["log_prior"].items()},
        "log_prob": {
            c: {f: round(v, 4) for f, v in probs.items()}
            for c, probs in model["log_prob"].items()
        },
        "log_prob_oov": {c: round(v, 4)
                         for c, v in model["log_prob_oov"].items()},
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(compact, fh)
