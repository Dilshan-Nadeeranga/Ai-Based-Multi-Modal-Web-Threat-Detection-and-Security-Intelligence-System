"""Language identification per text segment and per page (tasks 7-9).

Part 5: Multilingual scam content analyzer.

Why this exists: Part 6 reports results per language (en / si / ta) and the
dataset metadata only has a quick Part 1 hint (``utils/script_detect.py``, which
calls every Latin-script page "English"). This module is the AUTHORITATIVE
language for Part 5 onwards. It is explainable step by step:

1. Unicode script ratios (ranges in configs/languages.yaml): Sinhala
   U+0D80-0DFF, Tamil U+0B80-0BFF, Latin, other letters. Sinhala and Tamil have
   their own scripts, so a Sinhala segment is recognised with certainty, even a
   one-word button. If the second script has more than ``mixed_min_share`` of the
   letters the segment is "mixed".
2. Latin-script text, first the Singlish / Tanglish lexicon: Sri Lankan scams
   often write Sinhala / Tamil in Latin letters ("oya mage account eka verify
   karanna"). A few very frequent romanized words that are not English words
   give ``si_latn`` / ``ta_latn``. Known gap: XLM-R handles these poorly, so they
   are flagged separately rather than being called "en".
3. Then English vs other Latin-script languages with an OFFLINE model: fastText
   lid.176.ftz if the file is there (models/langid/), else langdetect with a
   fixed seed (reproducible), else "en" with low confidence (``script_only``).
   Latin segments shorter than ``short_segment_chars`` ("OK", "Login") are too
   short for any model and inherit the page language.
4. Page language = languages weighted by characters over the visible segments;
   "mixed" if the second language has more than ``mixed_min_share``.

Every guess carries a confidence (0..1) and the method used.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Protocol

from c2_analyzer.config import load_yaml_config, resolve_path
from c2_analyzer.schemas.content import LanguageGuess, PageLanguage

SCRIPTS = ("si", "ta", "latin", "other")
WORD = re.compile(r"[a-z]+")


@dataclass(frozen=True)
class LanguageSettings:
    """configs/languages.yaml -> language_id (+ the Unicode ranges of si / ta)."""

    ranges: dict[str, tuple[tuple[int, int], ...]]
    min_letters: int
    mixed_min_share: float
    short_segment_chars: int
    backend_order: tuple[str, ...]
    fasttext_model: Path
    langdetect_seed: int
    other_min_confidence: float
    en_close_ratio: float
    romanized: dict[str, frozenset[str]]
    romanized_min_hits: int
    romanized_min_ratio: float


@lru_cache
def settings() -> LanguageSettings:
    config = load_yaml_config("languages")
    lid = config["language_id"]
    ranges = {
        code: tuple((int(start, 16), int(end, 16)) for start, end in info["unicode_ranges"])
        for code, info in config["languages"].items()
        if "unicode_ranges" in info
    }
    romanized = lid["romanized"]
    return LanguageSettings(
        ranges=ranges,
        min_letters=int(lid["min_letters"]),
        mixed_min_share=float(lid["mixed_min_share"]),
        short_segment_chars=int(lid["short_segment_chars"]),
        backend_order=tuple(lid["backend_order"]),
        fasttext_model=resolve_path(Path(lid["fasttext_model"])),
        langdetect_seed=int(lid["langdetect_seed"]),
        other_min_confidence=float(lid["other_min_confidence"]),
        en_close_ratio=float(lid["en_close_ratio"]),
        romanized={
            label: frozenset(word.lower() for word in romanized[label])
            for label in ("si_latn", "ta_latn")
        },
        romanized_min_hits=int(romanized["min_hits"]),
        romanized_min_ratio=float(romanized["min_ratio"]),
    )


# ---- Step 1: Unicode script ratios -------------------------------------------------


def _is_latin(point: int) -> bool:
    """Basic Latin, Latin-1, Latin Extended-A/B and Latin Extended Additional letters."""
    return point < 0x0250 or 0x1E00 <= point <= 0x1EFF


def script_counts(text: str) -> dict[str, int]:
    """Letters per script: si, ta, latin, other. Digits / punctuation / ZWJ are not letters.

    Every character inside the Sinhala / Tamil blocks counts (vowel signs and the
    virama are combining marks, not "alpha", but they are clearly that script).
    """
    ranges = settings().ranges
    counts = dict.fromkeys(SCRIPTS, 0)
    for char in text:
        point = ord(char)
        for code, code_ranges in ranges.items():
            if any(start <= point <= end for start, end in code_ranges):
                counts[code] += 1
                break
        else:
            if char.isalpha():
                counts["latin" if _is_latin(point) else "other"] += 1
    return counts


def ratios(counts: dict[str, int]) -> dict[str, float]:
    total = sum(counts.values())
    return {code: round(counts[code] / total, 4) if total else 0.0 for code in SCRIPTS}


def script_ratios(text: str) -> dict[str, float]:
    """Share of Sinhala / Tamil / Latin / other letters in ``text`` (0 for empty text)."""
    return ratios(script_counts(text))


# ---- Step 2: Singlish / Tanglish lexicon ----------------------------------------------


def romanized_language(text: str) -> tuple[str, float] | None:
    """(si_latn | ta_latn, confidence) if enough frequent romanized words occur, else None."""
    config = settings()
    words = WORD.findall(text.lower())
    if not words:
        return None
    best = None
    for label, lexicon in config.romanized.items():
        hits = sum(1 for word in words if word in lexicon)
        ratio = hits / len(words)
        if hits >= config.romanized_min_hits and ratio >= config.romanized_min_ratio:
            if best is None or ratio > best[1]:
                best = (label, ratio)
    if best is None:
        return None
    return best[0], round(min(1.0, 0.5 + best[1]), 4)


# ---- Step 3: English vs other Latin-script languages (offline model) -------------------


class LatinBackend(Protocol):
    name: str

    def predict(self, text: str) -> list[tuple[str, float]]:
        """Top language guesses as (ISO code, probability), best first."""


class FastTextBackend:
    """fastText lid.176.ftz (176 languages, ~1 MB). Loaded once per process."""

    name = "fasttext"

    def __init__(self, model_path: Path) -> None:
        import fasttext  # fasttext-predict (inference only); ImportError -> next backend

        if not model_path.is_file():
            raise FileNotFoundError(f"fastText model not found: {model_path}")
        self.model = fasttext.load_model(str(model_path))

    def predict(self, text: str) -> list[tuple[str, float]]:
        # fastText reads one line; the batch (list) API of fasttext-predict is not
        # used because it fails on some builds - one string at a time is safe.
        labels, probs = self.model.predict(" ".join(text.split()), k=3)
        pairs = zip(labels, probs, strict=False)
        return [(label.replace("__label__", ""), float(prob)) for label, prob in pairs]


class LangdetectBackend:
    """langdetect (port of Google's language-detection) with a FIXED seed.

    langdetect is random by design; without ``DetectorFactory.seed`` the same
    text can get different answers on different runs.
    """

    name = "langdetect"

    def __init__(self, seed: int) -> None:
        from langdetect import DetectorFactory, detect_langs
        from langdetect.lang_detect_exception import LangDetectException

        DetectorFactory.seed = seed
        self._detect = detect_langs
        self._error = LangDetectException

    def predict(self, text: str) -> list[tuple[str, float]]:
        try:
            return [(guess.lang, float(guess.prob)) for guess in self._detect(text)[:3]]
        except self._error:  # no usable features (only symbols, digits ...)
            return []


class NoBackend:
    """Neither model available: Latin text is called English with low confidence."""

    name = "none"

    def predict(self, text: str) -> list[tuple[str, float]]:
        return []


@lru_cache
def latin_backend() -> LatinBackend:
    """The first backend of ``backend_order`` that loads (cached per process)."""
    config = settings()
    for name in config.backend_order:
        try:
            if name == "fasttext":
                return FastTextBackend(config.fasttext_model)
            if name == "langdetect":
                return LangdetectBackend(config.langdetect_seed)
        except (ImportError, OSError, ValueError):
            continue  # not installed / model file missing -> try the next one
    return NoBackend()


def reset_caches() -> None:
    """Forget settings and the loaded backend (tests switch the model file)."""
    settings.cache_clear()
    latin_backend.cache_clear()


def latin_language(text: str, backend: LatinBackend | None = None) -> LanguageGuess:
    """English vs another Latin-script language for Latin text (no lexicon, no length rule)."""
    backend = backend or latin_backend()
    guesses = backend.predict(text)
    if not guesses:  # no model, or the model found no usable features
        if backend.name == "none":
            return LanguageGuess(language="en", confidence=0.5, method="script_only")
        return LanguageGuess(language="en", confidence=0.3, method=backend.name)
    top, probability = guesses[0]
    if top == "en":
        return LanguageGuess(language="en", confidence=round(probability, 4), method=backend.name)
    config = settings()
    if probability >= config.other_min_confidence:
        return LanguageGuess(
            language="other", confidence=round(probability, 4), method=backend.name
        )
    # A weak non-English guess: English text with brand names / short menu words
    # often looks like this, so English wins if it is a close second.
    english = next((p for code, p in guesses if code == "en"), 0.0)
    if english >= config.en_close_ratio * probability:
        return LanguageGuess(language="en", confidence=round(english, 4), method=backend.name)
    return LanguageGuess(language="other", confidence=round(probability, 4), method=backend.name)


# ---- One segment -------------------------------------------------------------------


@dataclass
class SegmentLanguage:
    guess: LanguageGuess
    script_mix: dict[str, float]
    counts: dict[str, int]
    inherit: bool = False  # short Latin text: take the page language afterwards


def detect_segment(text: str, backend: LatinBackend | None = None) -> SegmentLanguage:
    """Language of one text segment (steps 1-3 of the module docstring)."""
    config = settings()
    counts = script_counts(text)
    mix = ratios(counts)
    letters = sum(counts.values())
    if letters < config.min_letters:
        return SegmentLanguage(LanguageGuess(method="script"), mix, counts)

    ranked = sorted(SCRIPTS, key=lambda code: mix[code], reverse=True)
    top, second = ranked[0], ranked[1]
    if mix[second] > config.mixed_min_share:
        confidence = round(mix[top] + mix[second], 4)
        return SegmentLanguage(
            LanguageGuess(language="mixed", confidence=confidence, method="script"), mix, counts
        )
    if top in ("si", "ta"):
        return SegmentLanguage(
            LanguageGuess(language=top, confidence=mix[top], method="script"), mix, counts
        )
    if top == "other":
        return SegmentLanguage(
            LanguageGuess(language="other", confidence=mix[top], method="script"), mix, counts
        )

    romanized = romanized_language(text)
    if romanized is not None:
        label, confidence = romanized
        return SegmentLanguage(
            LanguageGuess(language=label, confidence=confidence, method="lexicon"), mix, counts
        )
    if len(text.strip()) < config.short_segment_chars:
        return SegmentLanguage(LanguageGuess(method="inherited"), mix, counts, inherit=True)
    guess = latin_language(text, backend)
    guess.confidence = round(guess.confidence * mix["latin"], 4)  # a few foreign letters lower it
    return SegmentLanguage(guess, mix, counts)


# ---- The page ------------------------------------------------------------------------

# Where the characters of a "mixed" segment go when the page is weighted.
SCRIPT_TO_LANGUAGE = {"si": "si", "ta": "ta", "latin": "en", "other": "other"}


def page_language(
    items: list[tuple[str, SegmentLanguage]],
    lang_attr: str | None = None,
    backend: LatinBackend | None = None,
) -> PageLanguage:
    """Character-weighted page language over (text, result) of the VISIBLE segments.

    Segments marked ``inherit`` do not vote. If nothing else is left (a tiny
    login page: "Sign in", "Email", "Password"), their texts are joined and
    judged together - together they are long enough for the model.
    """
    config = settings()
    backend = backend or latin_backend()
    weights: dict[str, float] = {}
    confidence_mass: dict[str, float] = {}
    methods: dict[str, dict[str, float]] = {}
    total_counts = dict.fromkeys(SCRIPTS, 0)

    def vote(language: str, chars: float, confidence: float, method: str) -> None:
        weights[language] = weights.get(language, 0.0) + chars
        confidence_mass[language] = confidence_mass.get(language, 0.0) + chars * confidence
        per_method = methods.setdefault(language, {})
        per_method[method] = per_method.get(method, 0.0) + chars

    for _text, result in items:
        for code in SCRIPTS:
            total_counts[code] += result.counts[code]
        guess = result.guess
        letters = sum(result.counts.values())
        if result.inherit or guess.language == "unknown" or letters == 0:
            continue
        if guess.language == "mixed":  # split the segment's letters by script
            for code, count in result.counts.items():
                if count:
                    vote(SCRIPT_TO_LANGUAGE[code], count, guess.confidence, "script")
        else:
            vote(guess.language, letters, guess.confidence, guess.method)

    if not weights:
        short_texts = [text for text, result in items if result.inherit]
        if short_texts:
            joined = " . ".join(short_texts)
            romanized = romanized_language(joined)
            if romanized is not None:
                guess = LanguageGuess(language=romanized[0], confidence=romanized[1],
                                      method="lexicon")  # fmt: skip
            else:
                guess = latin_language(joined, backend)
            letters = sum(sum(result.counts.values()) for _, result in items if result.inherit)
            vote(guess.language, letters, guess.confidence, guess.method)

    page = PageLanguage(
        backend=backend.name, script_ratios=ratios(total_counts), lang_attr=lang_attr
    )
    total = sum(weights.values())
    if not total:
        page.method = "script"
        return page
    shares = {code: weight / total for code, weight in weights.items()}
    page.shares = {code: round(share, 4) for code, share in sorted(shares.items())}
    ranked = sorted(shares, key=shares.get, reverse=True)
    top = ranked[0]
    second_share = shares[ranked[1]] if len(ranked) > 1 else 0.0
    if second_share > config.mixed_min_share:
        page.language = "mixed"
        page.confidence = round(shares[top] + second_share, 4)
        page.method = "weighted"
        return page
    page.language = top
    page.confidence = round(confidence_mass[top] / weights[top] * shares[top], 4)
    page.method = max(methods[top], key=methods[top].get)  # the method behind most characters
    return page


def inherited(result: SegmentLanguage, page: PageLanguage) -> LanguageGuess:
    """The guess for a short Latin segment: the page language (unknown page -> unknown)."""
    if not result.inherit:
        return result.guess
    return LanguageGuess(language=page.language, confidence=page.confidence, method="inherited")


def detect_language(text: str) -> str:
    """Language label of a whole text (convenience: one segment, then one page)."""
    result = detect_segment(text)
    if not result.inherit:
        return result.guess.language
    return page_language([(text, result)]).language


def letter_count(text: str) -> int:
    """Letters in any script (combining marks of Sinhala / Tamil included)."""
    return sum(1 for char in text if char.isalpha() or unicodedata.category(char).startswith("M"))
