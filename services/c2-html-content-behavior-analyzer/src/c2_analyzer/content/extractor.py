"""Collect classifier-ready text: title, headings, paragraphs, buttons/CTAs, form labels.

Part 5: Multilingual scam content analyzer.
"""

from __future__ import annotations

from c2_analyzer.schemas.parsed_page import ParsedPage


def extract_content_text(page: ParsedPage) -> dict[str, list[str]]:
    """Group page text by role (title, headings, paragraphs, cta, form_labels)."""
    raise NotImplementedError


def to_model_input(content: dict[str, list[str]], max_chars: int | None = None) -> str:
    """Concatenate content segments into a single model input string."""
    raise NotImplementedError
