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


CORPUS_SCHEMA_VERSION = "corpus_v1"
SourceType = Literal["page_segment", "real_message", "synthetic_template", "machine_translation"]
SplitName = Literal["train", "val", "test"]


class CorpusRow(BaseModel):
    """One row of the scam-text corpus (corpus_v1, Part 5 Batch B).

    Research integrity: every row says where it came from (``source_type``,
    ``source_ref``) and whether it is synthetic. Synthetic templates and machine
    translations are TRAIN-ONLY augmentation; val / test hold only real text.
    ``group_id`` keeps related rows (one page cluster, one template, a message and
    its near-copies) in the same split. Review decisions (verified / excluded /
    changed intents) are stored separately and re-applied on every build.
    """

    text_id: str  # pg_ / rm_ / sy_ / mt_ + 12 hex chars; stable across rebuilds
    text: str  # NFC, PII-masked
    language: LanguageLabel  # detected (Part 5A language.py) or set by the reviewer
    language_given: str = ""  # as the source said (page metadata / CSV column)
    intents: list[str]  # taxonomy ids, priority order; first = primary_intent
    primary_intent: str
    cue_intents: list[str] = Field(default_factory=list)  # what the cue words alone suggest
    intent_source: Literal["weak_cue", "given", "reviewer"] = "weak_cue"
    source_type: SourceType
    source_ref: str  # sample_id:segment_id, or file:row
    field: str = ""  # page segments: title / cta / form_label / ...
    page_label: str = ""  # page segments: the page's threat class
    is_synthetic: bool
    group_id: str
    split: SplitName
    dup_count: int = 1  # near-identical copies merged into this row
    needs_review: bool = False
    verified: bool = False
    verified_by: str = ""
    verified_at: str = ""
    excluded: bool = False
    exclusion_reason: str = ""
    notes: str = ""


class ContentResult(BaseModel):
    """Language + social-engineering intent prediction for a page's text (Part 6 stub)."""

    language: str | None = None
    intent: str | None = None
    intent_scores: dict[str, float] = Field(default_factory=dict)
    threat_scores: dict[str, float] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
