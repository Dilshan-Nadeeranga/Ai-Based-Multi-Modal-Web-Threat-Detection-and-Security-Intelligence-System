"""Quick language hint from the writing system (script) of a page's visible text.

Part 1: Multilingual dataset preparation (used while collecting samples).

Why: when a sample comes from a feed we do not know its language, but the
metadata needs one. Sinhala and Tamil use their own Unicode blocks, so simply
counting characters per block is a cheap, explainable first guess:

    Sinhala letters  U+0D80-U+0DFF     Tamil letters  U+0B80-U+0BFF
    Latin letters    a-z / A-Z  (counted as English)

NOTE: this is only a heuristic for data collection. Part 5 replaces it with
real language identification (it cannot tell English from other Latin-script
languages, for example). Thresholds live in configs/languages.yaml.
"""

from __future__ import annotations

from functools import lru_cache

from bs4 import BeautifulSoup

from c2_analyzer.config import load_yaml_config

# Tags whose text is never shown to the visitor.
INVISIBLE_TAGS = ("script", "style", "noscript", "template", "head")


@lru_cache
def _settings() -> tuple[dict[str, list[tuple[int, int]]], dict[str, float]]:
    """Unicode ranges per native script + thresholds, read once from languages.yaml."""
    config = load_yaml_config("languages")
    ranges = {
        code: [(int(start, 16), int(end, 16)) for start, end in info["unicode_ranges"]]
        for code, info in config["languages"].items()
        if "unicode_ranges" in info
    }
    return ranges, config["script_detect"]


def visible_text(html: str) -> str:
    """Text a visitor would see: everything except scripts, styles, etc."""
    soup = BeautifulSoup(html, "lxml")
    # The <title> is shown in the browser tab, so keep it before dropping <head>.
    title = soup.title.get_text(" ") if soup.title else ""
    for tag in soup(INVISIBLE_TAGS):
        tag.decompose()
    return f"{title} {soup.get_text(' ')}"


def count_letters(text: str) -> dict[str, int]:
    """Count letters per script: one key per native language (si, ta) plus "latin"."""
    ranges, _ = _settings()
    counts = {code: 0 for code in ranges} | {"latin": 0}
    for char in text:
        if "a" <= char.lower() <= "z":
            counts["latin"] += 1
            continue
        point = ord(char)
        for code, code_ranges in ranges.items():
            if any(start <= point <= end for start, end in code_ranges):
                counts[code] += 1
                break
    return counts


def detect_language(text: str) -> str:
    """Return "si", "ta", "en", "mixed" or "unknown" for plain text.

    Rules (in order):
    1. too few letters                              -> unknown
    2. exactly one native script >= native_min_share -> that language
       (Sinhala/Tamil pages often have English menus, so this share is low)
    3. both native scripts >= native_min_share       -> mixed
    4. Latin share >= english_min_share              -> en
    5. otherwise                                     -> mixed
    """
    _, thresholds = _settings()
    counts = count_letters(text)
    total = sum(counts.values())
    if total < thresholds["min_letters"]:
        return "unknown"

    shares = {script: count / total for script, count in counts.items()}
    natives = [
        code
        for code, share in shares.items()
        if code != "latin" and share >= thresholds["native_min_share"]
    ]
    if len(natives) == 1:
        return natives[0]
    if len(natives) > 1:
        return "mixed"
    if shares["latin"] >= thresholds["english_min_share"]:
        return "en"
    return "mixed"


def detect_html_language(html: str) -> str:
    """``detect_language`` applied to the visible text of an HTML page."""
    return detect_language(visible_text(html))
