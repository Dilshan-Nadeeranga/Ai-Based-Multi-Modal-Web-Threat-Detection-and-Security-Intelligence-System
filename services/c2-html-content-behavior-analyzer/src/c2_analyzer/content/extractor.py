"""Structured page text for the NLP model: segments, languages, page_text (tasks 1-6).

Part 5: Multilingual scam content analyzer.

Principles (viva):
- Part 5 prepares TEXT for the NLP model (Part 6). It does not classify scams.
- It REUSES Part 2's ParsedPage (title, meta description, headings, paragraphs,
  visible / hidden text, form labels and placeholders) and Part 2's text
  normalization (NFC, ZWJ / ZWNJ kept - ශ්‍රී stays intact). The raw HTML is
  re-parsed only for CTA / alert facts Part 2 does not store (``content/cta.py``).
- One entry point for dataset samples and the API: ``extract_content(page, html)``
  (``content_for_html`` = Part 2 + Part 5 on an HTML string).

What happens to a page:
1. Candidates per field: title, meta_description, heading (with level), cta,
   form_label (label_text, which already includes aria-label), placeholder,
   alert_banner (role=alert, or a SHORT paragraph / line with an urgency marker),
   paragraph, visible_other (lines of the visible text not covered by the
   fields above, e.g. text in <div>s) and hidden (text the visitor cannot see).
2. Fields are filled in PRIORITY order (configs/content.yaml): a text already
   taken by an earlier field is not repeated later ("Sign in" stays a CTA, not
   also a line of visible text). Repeats inside a field (menus, footers) are
   merged into one segment with ``count``.
3. Junk is dropped: no letters, or only a number / date / price / URL / email.
4. PII (emails, phone numbers, NIC, card numbers - Part 2's ``mask_pii``) is
   replaced by tokens; the rest of the wording is kept because the model needs it.
5. Caps: segments per field, characters per segment, characters per page.
6. Language per segment and per page (``content/language.py``).
7. ``page_text``: "[TITLE] ... [CTA] ... [LABEL] ..." in priority order, cut to
   ``max_chars`` - title, CTAs, form labels, headings and alerts first because
   they carry the scam intent; long body text last.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from functools import lru_cache

from c2_analyzer.config import load_yaml_config
from c2_analyzer.content import cta as cta_finder
from c2_analyzer.content.language import (
    detect_segment,
    inherited,
    latin_backend,
    letter_count,
    page_language,
)
from c2_analyzer.preprocessing.loader import from_string
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.preprocessing.text_utils import normalize_inline
from c2_analyzer.schemas.content import PageText, PageTextMeta, TextSegment
from c2_analyzer.schemas.parsed_page import ParsedPage
from c2_analyzer.utils.pii import TOKENS, mask_pii

# Bump when the extraction logic changes meaning (the rules hash changes -> redo).
EXTRACTOR_VERSION = "5a.1"

FIELDS = (
    "title", "meta_description", "heading", "paragraph", "cta", "form_label",
    "placeholder", "alert_banner", "visible_other", "hidden",
)  # fmt: skip
HIDDEN_ORDER = 10**9  # hidden text is listed after everything visible
UNPLACED_ORDER = 10**8  # texts not found in visible_text (placeholders, input values)


@dataclass(frozen=True)
class ContentRules:
    """configs/content.yaml, validated and compiled once."""

    raw: dict
    text_set_version: str
    min_letters: int
    max_segment_chars: int
    junk: tuple[re.Pattern, ...]
    per_field: dict[str, int]
    total_chars: int
    priority: tuple[str, ...]
    alert_markers: tuple[str, ...]
    alert_max_chars: int
    page_fields: tuple[str, ...]
    page_max_chars: int
    markers: dict[str, str]
    joiner: str
    min_tail_chars: int


@lru_cache
def content_rules() -> ContentRules:
    config = load_yaml_config("content")
    priority = tuple(config["field_priority"])
    if sorted(priority) != sorted(FIELDS):
        raise ValueError(f"content.yaml field_priority must list exactly {FIELDS}")
    page = config["page_text"]
    unknown = set(page["fields"]) - set(FIELDS)
    if unknown or "hidden" in page["fields"]:
        raise ValueError(f"content.yaml page_text.fields: bad field(s) {unknown or {'hidden'}}")
    markers = config["alert"]["markers"]
    return ContentRules(
        raw=config,
        text_set_version=config["text_set_version"],
        min_letters=int(config["cleaning"]["min_letters"]),
        max_segment_chars=int(config["cleaning"]["max_segment_chars"]),
        junk=tuple(re.compile(p, re.IGNORECASE) for p in config["cleaning"]["junk_patterns"]),
        per_field={name: int(config["caps"]["per_field"][name]) for name in FIELDS},
        total_chars=int(config["caps"]["total_chars"]),
        priority=priority,
        alert_markers=tuple(
            marker.lower() for code in ("en", "si", "ta") for marker in markers.get(code, [])
        ),
        alert_max_chars=int(config["alert"]["max_chars"]),
        page_fields=tuple(page["fields"]),
        page_max_chars=int(page["max_chars"]),
        markers={name: page["markers"][name] for name in page["fields"]},
        joiner=page["joiner"],
        min_tail_chars=int(page["min_tail_chars"]),
    )


@lru_cache
def rules_hash() -> str:
    """content.yaml + languages.yaml + extractor version + the Latin language backend.

    The backend is part of it because fastText and langdetect can disagree:
    installing the fastText model must redo the stored results.
    """
    payload = {
        "content": load_yaml_config("content"),
        "languages": load_yaml_config("languages"),
        "extractor": EXTRACTOR_VERSION,
        "backend": latin_backend().name,
    }
    text = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def reset_caches() -> None:
    """Forget compiled rules (tests change configs / the language backend)."""
    content_rules.cache_clear()
    rules_hash.cache_clear()
    cta_finder.cta_rules.cache_clear()


# ---- Cleaning --------------------------------------------------------------------


def _key(text: str) -> str:
    """Dedup key: case-folded, single spaces (ZWJ kept, so Sinhala words stay distinct)."""
    return " ".join(text.casefold().split())


def is_junk(text: str, rules: ContentRules) -> bool:
    """No letters, or only a number / date / price / URL / email / PII token."""
    stripped = text.strip(" .,:;!?-–—|•·*#()[]{}\"'")
    if any(pattern.fullmatch(stripped) for pattern in rules.junk):
        return True
    without_tokens = mask_pii(stripped)
    for token in TOKENS:
        without_tokens = without_tokens.replace(token, " ")
    return letter_count(without_tokens) < rules.min_letters


def _cut(text: str, limit: int) -> str:
    """Cut at the last space before ``limit`` (or hard at ``limit`` for one long word)."""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    space = cut.rfind(" ")
    return cut[:space] if space > limit // 2 else cut


def _only_covered(key: str, taken: dict[str, dict], rules: ContentRules) -> bool:
    """True if a visible line is made only of texts other fields already took.

    A form row is one line of visible text ("Email or username Password Sign in")
    but every piece of it is already a label or a CTA segment.
    """
    rest = key
    for other in sorted(taken, key=len, reverse=True):
        if other in rest:
            rest = rest.replace(other, " ")
    return rest != key and letter_count(rest) < rules.min_letters


def has_urgency(text: str, rules: ContentRules) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in rules.alert_markers)


# ---- Candidates (Part 2 fields + CTA / alerts) ----------------------------------------


@dataclass
class Candidate:
    field: str
    text: str
    level: int | None = None


def _lines(text: str) -> list[str]:
    return [line for line in (normalize_inline(raw) for raw in text.split("\n")) if line]


def collect_candidates(
    page: ParsedPage, html: str | None, rules: ContentRules, errors: list[str]
) -> tuple[dict[str, list[Candidate]], str]:
    """Candidate texts per field (document order inside a field) + where CTAs came from."""
    found: dict[str, list[Candidate]] = {name: [] for name in FIELDS}

    def add(field: str, texts, level: int | None = None) -> None:
        for text in texts:
            text = normalize_inline(text)
            if text:
                found[field].append(Candidate(field, text, level))

    add("title", [page.title or ""])
    add("meta_description", [page.meta_description or ""])
    for heading in page.headings:
        add("heading", [heading.text], heading.level)

    html_found = None
    cta_source = "parsed_page"
    if html is not None:
        try:
            html_found = cta_finder.from_html(html)
            cta_source = "html"
        except Exception as error:  # noqa: BLE001 - fall back to Part 2's buttons / links
            errors.append(f"cta: {type(error).__name__}: {error}")
    if html_found is None:
        html_found = cta_finder.from_parsed_page(page)
    add("cta", html_found.ctas)

    for field_input in page.all_inputs:
        if field_input.hidden or field_input.type == "hidden":
            continue
        add("form_label", [field_input.label_text or ""])
        add("placeholder", [field_input.placeholder or ""])

    visible_lines = _lines(page.visible_text)
    paragraphs = [normalize_inline(p) for p in page.paragraphs]
    banners = list(html_found.alerts) + [
        text
        for text in paragraphs + visible_lines
        if len(text) <= rules.alert_max_chars and has_urgency(text, rules)
    ]
    # A banner sentence is also a paragraph AND a visible line: that is one text
    # seen through two Part 2 fields, not a repeat - keep it once.
    unique_banners, seen = [], set()
    for text in banners:
        if _key(text) not in seen:
            seen.add(_key(text))
            unique_banners.append(text)
    add("alert_banner", unique_banners)
    add("paragraph", paragraphs)
    add("visible_other", visible_lines)
    add("hidden", _lines(page.hidden_text))
    return found, cta_source


# ---- Segments ------------------------------------------------------------------------


def _order_key(field: str, raw_text: str, visible: str, index: int) -> int:
    """Approximate document position: where the text first appears in the visible text."""
    if field == "title":
        return -2
    if field == "meta_description":
        return -1
    if field == "hidden":
        return HIDDEN_ORDER + index
    position = visible.find(raw_text)
    return position if position >= 0 else UNPLACED_ORDER + index


def build_segments(
    found: dict[str, list[Candidate]], page: ParsedPage, rules: ContentRules
) -> tuple[list[dict], dict[str, int], list[str]]:
    """Dedup, clean, mask and cap the candidates -> (segments as dicts, dropped, reasons)."""
    dropped: dict[str, int] = {}
    reasons: list[str] = []
    taken: dict[str, dict] = {}  # dedup key -> segment (across all fields)
    segments: list[dict] = []
    total = 0
    visible_folded = " ".join(page.visible_text.split())

    def drop(reason: str) -> None:
        dropped[reason] = dropped.get(reason, 0) + 1

    for field in rules.priority:
        kept = 0
        for index, candidate in enumerate(found[field]):
            key = _key(candidate.text)
            if key in taken:
                if taken[key]["field"] == field:
                    taken[key]["count"] += 1  # repeated menu / footer text
                    drop("duplicate")
                else:
                    drop("covered_by_other_field")
                continue
            if field == "visible_other" and _only_covered(key, taken, rules):
                drop("covered_by_other_field")  # "Email Password Sign in" = labels + CTA
                continue
            if is_junk(candidate.text, rules):
                drop("junk")
                continue
            if kept >= rules.per_field[field]:
                drop(f"cap_{field}")
                if f"per_field_cap:{field}" not in reasons:
                    reasons.append(f"per_field_cap:{field}")
                continue
            text = mask_pii(candidate.text)
            if len(text) > rules.max_segment_chars:
                text = _cut(text, rules.max_segment_chars)
                drop("segment_cut")
            if total + len(text) > rules.total_chars:
                drop("total_chars")
                if "total_chars" not in reasons:
                    reasons.append("total_chars")
                continue
            segment = {
                "field": field,
                "level": candidate.level,
                "text": text,
                "count": 1,
                "order_key": _order_key(field, candidate.text, visible_folded, index),
            }
            taken[key] = segment
            segments.append(segment)
            kept += 1
            total += len(text)
    segments.sort(key=lambda s: (s["order_key"], rules.priority.index(s["field"])))
    return segments, dropped, reasons


# ---- page_text (model input) -------------------------------------------------------


def build_page_text(segments: list[TextSegment], rules: ContentRules) -> tuple[str, bool]:
    """Marked, priority-ordered, length-capped text for Part 6 -> (text, truncated).

    Segments of one field are joined with ``joiner``; fields that share a marker
    (form_label + placeholder = [LABEL]) form one group. Whole segments are added
    in priority order; the first one that does not fit is cut at a word boundary
    (if at least ``min_tail_chars`` remain) and nothing after it is added.
    """
    groups: list[tuple[str, list[str]]] = []
    for field in rules.page_fields:
        texts = [segment.text for segment in segments if segment.field == field]
        if not texts:
            continue
        marker = rules.markers[field]
        if groups and groups[-1][0] == marker:
            groups[-1][1].extend(texts)
        else:
            groups.append((marker, texts))

    limit = rules.page_max_chars
    out = ""
    for marker, texts in groups:
        for position, text in enumerate(texts):
            if position == 0:  # a new group: newline + marker
                prefix = ("\n" if out else "") + marker + " "
            else:
                prefix = rules.joiner
            if len(out) + len(prefix) + len(text) <= limit:
                out += prefix + text
                continue
            room = limit - len(out) - len(prefix)
            if room >= rules.min_tail_chars:
                out += prefix + _cut(text, room)
            return out, True
    return out, False


# ---- Entry points ----------------------------------------------------------------


def extract_content(page: ParsedPage, html: str | None = None) -> PageText:
    """Part 5 for one page (never raises for page content).

    ``html`` is the same decoded, size-capped HTML the ParsedPage was made from
    (only used for CTA / alert candidates). Without it, CTAs come from Part 2's
    buttons and links and ``meta.cta_source`` says "parsed_page".
    """
    started = time.perf_counter()
    rules = content_rules()
    errors: list[str] = []
    found, cta_source = collect_candidates(page, html, rules, errors)
    raw_segments, dropped, reasons = build_segments(found, page, rules)

    # Language: each segment, then the page from the visible ones, then short
    # Latin segments inherit the page language.
    results = []
    for raw in raw_segments:
        try:
            results.append(detect_segment(raw["text"]))
        except Exception as error:  # noqa: BLE001 - a language failure must not lose the text
            errors.append(f"language: {type(error).__name__}: {error}")
            results.append(detect_segment(""))
    visible = [
        (raw["text"], result)
        for raw, result in zip(raw_segments, results, strict=True)
        if raw["field"] != "hidden"
    ]
    language = page_language(visible, lang_attr=page.lang_attr)

    segments = []
    for number, (raw, result) in enumerate(zip(raw_segments, results, strict=True)):
        guess = inherited(result, language)
        segments.append(
            TextSegment(
                segment_id=f"s{number + 1:04d}",
                field=raw["field"],
                level=raw["level"],
                text=raw["text"],
                order=number,
                chars=len(raw["text"]),
                count=raw["count"],
                language=guess.language,
                lang_confidence=guess.confidence,
                lang_method=guess.method,
                script_mix=result.script_mix,
            )
        )

    page_text, page_text_truncated = build_page_text(segments, rules)
    visible_segments = [s for s in segments if s.field != "hidden"]
    counts = {name: 0 for name in FIELDS}
    for segment in segments:
        counts[segment.field] += 1
    warnings = []
    if cta_source == "parsed_page":
        warnings.append("CTA candidates from the ParsedPage only (raw HTML not available)")
    return PageText(
        meta=PageTextMeta(
            sample_id=page.meta.sample_id,
            dataset_version=page.meta.dataset_version,
            rules_hash=rules_hash(),
            source_sha256=page.meta.source_sha256,
            cta_source=cta_source,
            processing_ms=round((time.perf_counter() - started) * 1000, 2),
            truncated=bool(reasons),
            truncation_reasons=reasons,
            dropped=dict(sorted(dropped.items())),
            errors=errors,
            warnings=warnings,
        ),
        language=language,
        segments=segments,
        counts=counts,
        chars=sum(s.chars for s in visible_segments),
        has_cta=counts["cta"] > 0,
        has_form_labels=counts["form_label"] + counts["placeholder"] > 0,
        empty=not visible_segments,
        page_text=page_text,
        page_text_chars=len(page_text),
        page_text_truncated=page_text_truncated,
    )


def content_for_html(html: str, url: str | None = None) -> tuple[ParsedPage, PageText]:
    """The API path (Part 9): HTML string -> Part 2 -> Part 5, on the same capped HTML."""
    raw = from_string(html, url)
    page = preprocess(raw)
    return page, extract_content(page, raw.html)
