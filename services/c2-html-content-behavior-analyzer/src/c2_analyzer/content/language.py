"""Language identification for en / si / ta (Unicode-range + langdetect).

Part 5: Multilingual scam content analyzer.
"""

from __future__ import annotations


def script_ratios(text: str) -> dict[str, float]:
    """Share of Sinhala / Tamil / Latin characters (ranges from configs/languages.yaml)."""
    raise NotImplementedError


def detect_language(text: str) -> str:
    """Return ``en``, ``si``, ``ta`` or ``unknown``."""
    raise NotImplementedError
