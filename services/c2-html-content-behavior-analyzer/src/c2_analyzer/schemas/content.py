"""PageText (text_v1): a page's text, split into labelled segments with languages.

Part 5: Multilingual scam content analyzer.

Why: the NLP model (Part 6) must read the SAME text for a dataset sample and for
an API request, and it should know WHERE each piece of text came from - "Verify
now" on a button carries more scam intent than the same words in a footer. So
Part 5 turns a ParsedPage into:

- ``segments``: one entry per distinct piece of text, with its field (title,
  heading, cta, form_label, ...), document order and language;
- ``language``: the page language (en / si / ta / si_latn / ta_latn / mixed /
  other / unknown) with confidence and the method used;
- ``page_text``: one model-ready string with field markers ("[TITLE] ... [CTA] ..."),
  cut to a fixed length by field priority.

Part 5 does NOT classify the page (no scam score here). ``ContentResult`` below
is the Part 6 output stub and is unchanged.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

TEXT_SCHEMA_VERSION = "text_v1"

SegmentField = Literal[
    "title",
    "meta_description",
    "heading",
    "paragraph",
    "cta",
    "form_label",
    "placeholder",
    "alert_banner",
    "visible_other",
    "hidden",
]
LanguageLabel = Literal["en", "si", "ta", "si_latn", "ta_latn", "mixed", "other", "unknown"]


class LanguageGuess(BaseModel):
    """Language of one piece of text and how it was decided."""

    language: LanguageLabel = "unknown"
    confidence: float = 0.0  # 0..1
    # script (Unicode ranges) | fasttext | langdetect | script_only (no model available)
    # | lexicon (Singlish / Tanglish words) | inherited (short Latin text -> page language)
    # | weighted (page level: characters over segments) | none
    method: str = "none"


class TextSegment(BaseModel):
    """One distinct piece of page text (repeats are merged, see ``count``)."""

    segment_id: str  # "s0001", ... in document order within the page
    field: SegmentField
    level: int | None = None  # heading level (h1 = 1)
    text: str  # normalized (NFC, ZWJ/ZWNJ kept) and PII-masked
    order: int  # position in the page (0 = first); title / description come first
    chars: int
    count: int = 1  # how many times this text occurred (menus / footers repeat)
    language: LanguageLabel = "unknown"
    lang_confidence: float = 0.0
    lang_method: str = "none"
    script_mix: dict[str, float] = Field(default_factory=dict)  # si / ta / latin / other shares


class PageLanguage(BaseModel):
    """Page-level language: weighted by characters over the visible segments."""

    language: LanguageLabel = "unknown"
    confidence: float = 0.0
    method: str = "none"
    backend: str = "none"  # the Latin-script model used: fasttext | langdetect | none
    shares: dict[str, float] = Field(default_factory=dict)  # language -> share of characters
    script_ratios: dict[str, float] = Field(default_factory=dict)  # si / ta / latin / other
    lang_attr: str | None = None  # <html lang="..."> as written (a hint only, never trusted)


class PageTextMeta(BaseModel):
    """Where the text came from and how extraction went (no URLs: corpus files are shared)."""

    sample_id: str | None = None
    dataset_version: str | None = None
    schema_version: str = TEXT_SCHEMA_VERSION
    rules_hash: str = ""  # content.yaml + languages.yaml + extractor version + backend
    source_sha256: str | None = None  # of the HTML (same as ParsedPage.meta.source_sha256)
    cta_source: Literal["html", "parsed_page"] = "parsed_page"  # raw HTML available for CTAs?
    processing_ms: float = 0.0
    truncated: bool = False
    truncation_reasons: list[str] = Field(default_factory=list)
    dropped: dict[str, int] = Field(default_factory=dict)  # junk / duplicate / cap counts
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class PageText(BaseModel):
    """Everything Part 6 needs to read a page (text_v1)."""

    meta: PageTextMeta = Field(default_factory=PageTextMeta)
    language: PageLanguage = Field(default_factory=PageLanguage)
    segments: list[TextSegment] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)  # field -> number of segments
    chars: int = 0  # all visible segments (hidden excluded)
    has_cta: bool = False
    has_form_labels: bool = False
    empty: bool = True  # no visible text at all
    page_text: str = ""  # model-ready string with field markers
    page_text_chars: int = 0
    page_text_truncated: bool = False

    def by_field(self, field: str) -> list[TextSegment]:
        return [segment for segment in self.segments if segment.field == field]


class ContentResult(BaseModel):
    """Language + social-engineering intent prediction for a page's text (Part 6 stub)."""

    language: str | None = None
    intent: str | None = None
    intent_scores: dict[str, float] = Field(default_factory=dict)
    threat_scores: dict[str, float] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
