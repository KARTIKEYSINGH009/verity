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
import unicodedata

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
# Unicode lookalikes (Cyrillic / Greek homoglyphs and friends) folded to
# their Latin twins: an attacker spelling "ignore" with a Cyrillic о
# must not slip past token-based detection. Keys are escapes so the
# mapping is unambiguous in source.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p",
    "с": "c", "х": "x", "у": "y", "і": "i",
    "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d",
    "α": "a", "ε": "e", "ο": "o", "ρ": "p",
    "τ": "t", "χ": "x", "ı": "i",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a",
                       "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"})
_MIXED_TOKEN = re.compile(r"[a-z0-9@$]+")


def _leet_fold(t: str) -> str:
    """Fold leetspeak back to letters inside mixed letter+digit tokens
    ("5y573m" -> "system"). Pure numbers and pure words are untouched, so
    benign text with amounts, times, or order numbers is not distorted."""
    def fold(m: re.Match) -> str:
        tok = m.group(0)
        if any(c.isalpha() for c in tok) and any(c.isdigit() for c in tok):
            return tok.translate(_LEET)
        return tok
    return _MIXED_TOKEN.sub(fold, t)

_MODEL: dict | None = None
_MODEL_TRIED = False


def normalize(text: str) -> str:
    """Lowercase, expand contractions, strip zero-width/obfuscation chars,
    fold Unicode homoglyphs (NFKC + confusables) to Latin, and fold
    leetspeak digit substitutions back to letters."""
    t = _ZERO_WIDTH.sub("", (text or "").lower())
    t = unicodedata.normalize("NFKC", t).translate(_CONFUSABLES)
    for k, v in _CONTRACTIONS.items():
        t = t.replace(k, v)
    t = _leet_fold(t)
    return re.sub(r"\s+", " ", t).strip()


def features(text: str) -> list[str]:
    t = normalize(text)
    words = _TOKEN.findall(t)
    grams = list(words)
    grams += [f"{a} {b}" for a, b in zip(words, words[1:])]
    padded = f"  {t}  "
    for n in (3, 4):
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
        return _load_with_sibling(path)
    if _MODEL_TRIED:
        return _MODEL
    _MODEL_TRIED = True
    _MODEL = _load_with_sibling(_MODEL_PATH)
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


def _to_file_format(model: dict) -> dict:
    """Compact on-disk form: one shared vocab list + aligned weight arrays
    (storing every feature key twice, once per class, doubled the file)."""
    vocab = sorted(model["log_prob"]["malicious"].keys())
    return {
        "format": 2,
        "meta": model.get("meta", {}),
        "alpha": model["alpha"],
        "vocab_size": len(vocab),
        "vocab": vocab,
        "log_prior": {c: round(v, 4) for c, v in model["log_prior"].items()},
        "log_prob": {
            c: [round(model["log_prob"][c][f], 4) for f in vocab]
            for c in CLASSES
        },
        "log_prob_oov": {c: round(v, 4)
                         for c, v in model["log_prob_oov"].items()},
    }


def _from_file_format(raw: dict) -> dict:
    if raw.get("format") != 2:
        return raw  # legacy dict format
    vocab = raw["vocab"]
    return {
        "meta": raw.get("meta", {}),
        "alpha": raw["alpha"],
        "vocab_size": raw["vocab_size"],
        "log_prior": raw["log_prior"],
        "log_prob": {
            c: dict(zip(vocab, raw["log_prob"][c])) for c in CLASSES
        },
        "log_prob_oov": raw["log_prob_oov"],
    }


def _sibling_path(path: str) -> str:
    return path[:-5] + "_part2.json" if path.endswith(".json") else path


def _load_one(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return _from_file_format(json.load(fh))
    except (OSError, ValueError):
        return None


def _load_with_sibling(path: str) -> dict | None:
    """Load a model, merging its _partN siblings when present.

    The trained weights ship split across several files so each stays
    small enough for the connector push cap; the merge is transparent
    to callers and older two-part models still load (parts are merged
    in order until one is missing).
    """
    model = _load_one(path)
    if model is None:
        return None
    if path.endswith(".json"):
        n = 2
        while True:
            sibling = path[:-5] + f"_part{n}.json"
            extra = _load_one(sibling)
            if extra is None:
                break
            for c in CLASSES:
                model["log_prob"][c].update(extra["log_prob"][c])
            n += 1
        model["vocab_size"] = len(model["log_prob"]["malicious"])
    return model


def save_model(model: dict, path: str) -> None:
    """Write weights in the compact array format (rounded floats), split
    across the main file and _part2/_part3 siblings so each file stays
    under the connector push cap."""
    fmt = _to_file_format(model)
    n = len(fmt["vocab"])
    third = (n + 2) // 3

    def part(idxs: list[int]) -> dict:
        return {
            "format": 2,
            "meta": fmt.get("meta", {}),
            "alpha": fmt["alpha"],
            "vocab_size": len(idxs),
            "vocab": [fmt["vocab"][i] for i in idxs],
            "log_prior": fmt["log_prior"],
            "log_prob": {c: [fmt["log_prob"][c][i] for i in idxs]
                         for c in CLASSES},
            "log_prob_oov": fmt["log_prob_oov"],
        }

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(part(list(range(0, third))), fh)
    with open(_sibling_path(path), "w", encoding="utf-8") as fh:
        json.dump(part(list(range(third, 2 * third))), fh)
    part3 = path[:-5] + "_part3.json" if path.endswith(".json") else path
    with open(part3, "w", encoding="utf-8") as fh:
        json.dump(part(list(range(2 * third, n))), fh)
