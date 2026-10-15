"""Text normalization that is safe for Sinhala and Tamil.

Part 2: HTML preprocessing pipeline.

Why: the text from Part 2 feeds the multilingual models (Parts 5-6), so it
must be clean and consistent, but "cleaning" can easily break Sinhala:
ශ්‍රී (Sri) is written with a ZERO WIDTH JOINER (U+200D) between ් and ර.
Removing every invisible character - a common recipe - turns it into a
different glyph sequence. So the rules are:

- Unicode NFC normalization (one canonical form for the same characters);
- KEEP U+200D (ZWJ) and U+200C (ZWNJ) - needed for Sinhala/Tamil;
- REMOVE other zero-width characters (U+200B, U+FEFF, U+2060, U+180E) and
  control characters (C0/C1) except newline and tab;
- collapse runs of spaces; keep one newline per block (paragraph, list item,
  heading, table row, <br>) so the text reads sentence by sentence.
"""

from __future__ import annotations

import re
import unicodedata

ZERO_WIDTH_REMOVE = {"​", "﻿", "⁠", "᠎"}
KEEP_CONTROLS = {"\n", "\t"}


def _drop(char: str) -> bool:
    if char in ZERO_WIDTH_REMOVE:
        return True
    return unicodedata.category(char) == "Cc" and char not in KEEP_CONTROLS


def clean_chars(text: str) -> str:
    """NFC + remove unwanted invisible/control characters (ZWJ/ZWNJ are kept)."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = unicodedata.normalize("NFC", text)
    if text.isascii() and text.isprintable():
        return text  # fast path: nothing to remove
    return "".join(char for char in text if not _drop(char))


# Whitespace except newline. Python's \s also matches Unicode spaces such as
# NBSP (U+00A0), which display as normal spaces - fine to collapse. ZWJ and
# ZWNJ are not whitespace, so they survive.
SPACES = re.compile(r"[^\S\n]+")


def normalize_inline(text: str | None) -> str:
    """One-line text (titles, headings, labels): every whitespace run -> one space."""
    if not text:
        return ""
    return re.sub(r"\s+", " ", clean_chars(text)).strip()


def normalize_block(text: str | None) -> str:
    """Multi-line text: spaces collapsed inside lines, one newline between blocks."""
    if not text:
        return ""
    text = SPACES.sub(" ", clean_chars(text))
    lines = (line.strip() for line in text.split("\n"))
    return "\n".join(line for line in lines if line)


def truncate(text: str | None, limit: int) -> str | None:
    """Cut ``text`` to ``limit`` characters (None stays None)."""
    if text is None or len(text) <= limit:
        return text
    return text[:limit]
