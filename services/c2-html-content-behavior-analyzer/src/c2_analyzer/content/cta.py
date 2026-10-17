"""Find call-to-action (CTA) and alert-banner text in the raw HTML (task 5).

Part 5: Multilingual scam content analyzer.

Why this exists: Part 2's ParsedPage already has form buttons and link texts,
but not the facts that make a link LOOK like a button - its class ("btn",
"cta"), its ``role="button"``, or ``role="alert"`` on a banner. Scam kits put
their main action ("Verify now", "Claim your prize", "තහවුරු කරන්න") exactly
there. So this is the ONLY place Part 5 re-parses the HTML (with Part 2's
``parse_html`` and visibility helpers, so hidden elements are skipped the same
way). Without the HTML (a stored ParsedPage only) ``from_parsed_page`` gives a
smaller set from Part 2's buttons and links.

Rules (configs/content.yaml -> cta / alert):
- every visible <button>, and <input type=submit|button|image> (value / alt);
- elements with role=button, or a class word btn / button / cta ... (a / span /
  div only when they contain no other link / button / input);
- a plain <a> whose text is short (<= ``link_max_words``) and contains an
  imperative verb (English whole words; Sinhala / Tamil as substrings because
  the verb is inflected and Sinhala puts it at the end of the phrase);
- alerts: role=alert / alertdialog or aria-live=assertive.
Icon-only buttons fall back to aria-label / title.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache

from bs4 import Tag

from c2_analyzer.config import load_yaml_config
from c2_analyzer.preprocessing.parser import parse_html
from c2_analyzer.preprocessing.text_utils import normalize_inline
from c2_analyzer.preprocessing.visibility import is_hidden_in_tree
from c2_analyzer.schemas.parsed_page import ParsedPage

SKIP_TAGS = {"script", "style", "template", "head", "noscript", "svg"}
BUTTON_INPUT_TYPES = {"submit", "button", "image"}
CLASS_SPLIT = re.compile(r"[-_\s]+")


@dataclass(frozen=True)
class CtaRules:
    class_words: frozenset[str]
    roles: frozenset[str]
    link_max_words: int
    latin_verbs: re.Pattern
    native_verbs: tuple[str, ...]
    max_chars: int
    alert_roles: frozenset[str]
    alert_live: frozenset[str]


@lru_cache
def cta_rules() -> CtaRules:
    config = load_yaml_config("content")
    cta, alert = config["cta"], config["alert"]
    verbs = cta["imperative_verbs"]
    latin = sorted((v.lower() for v in verbs.get("en", [])), key=len, reverse=True)
    # whole words / phrases only ("get" must not match "target"); "log in" also matches "log  in"
    alternatives = "|".join(re.escape(verb).replace(r"\ ", r"\s+") for verb in latin)
    pattern = r"(?<![\w])(?:" + alternatives + r")(?![\w])"
    native = tuple(v for code in ("si", "ta") for v in verbs.get(code, []))
    return CtaRules(
        class_words=frozenset(w.lower() for w in cta["class_words"]),
        roles=frozenset(r.lower() for r in cta["roles"]),
        link_max_words=int(cta["link_max_words"]),
        latin_verbs=re.compile(pattern, re.IGNORECASE),
        native_verbs=native,
        max_chars=int(cta["max_chars"]),
        alert_roles=frozenset(r.lower() for r in alert["roles"]),
        alert_live=frozenset(v.lower() for v in alert["aria_live"]),
    )


def has_imperative(text: str) -> bool:
    """True if ``text`` contains a configured imperative verb (en / si / ta)."""
    rules = cta_rules()
    return bool(rules.latin_verbs.search(text)) or any(v in text for v in rules.native_verbs)


def is_short_imperative(text: str) -> bool:
    """A link text that reads like an action: short and with an imperative verb."""
    words = text.split()
    return 0 < len(words) <= cta_rules().link_max_words and has_imperative(text)


@dataclass
class Candidates:
    """Texts found in the HTML, in document order."""

    ctas: list[str] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)


def _attr(tag: Tag, name: str) -> str:
    value = tag.get(name)
    if isinstance(value, list):
        value = " ".join(value)
    return (value or "").strip()


def _class_match(tag: Tag, words: frozenset[str]) -> bool:
    classes = tag.get("class") or []
    if isinstance(classes, str):
        classes = classes.split()
    return any(part in words for name in classes for part in CLASS_SPLIT.split(name.lower()))


def _label(tag: Tag) -> str:
    """Visible text, else value / alt (inputs), else aria-label / title (icon buttons)."""
    if tag.name == "input":
        text = _attr(tag, "value") or _attr(tag, "alt")
    else:
        text = tag.get_text(" ")
    text = normalize_inline(text)
    return text or normalize_inline(_attr(tag, "aria-label") or _attr(tag, "title"))


def _cta_kind(tag: Tag, rules: CtaRules) -> str | None:
    """Why this element is a CTA candidate (None = it is not)."""
    name = tag.name
    if name == "button":
        return "button"
    if name == "input":
        return "input" if _attr(tag, "type").lower() in BUTTON_INPUT_TYPES else None
    if _attr(tag, "role").lower() in rules.roles:
        return "role"
    if name in ("a", "span", "div") and _class_match(tag, rules.class_words):
        # a wrapper ("btn-group") holding real buttons/links: the inner ones count instead
        if name != "a" and tag.find(["a", "button", "input"]) is not None:
            return None
        return "class"
    if name == "a":
        return "link"  # still needs the short-imperative test on its text
    return None


def from_html(html: str) -> Candidates:
    """CTA and alert texts from the raw HTML (visible elements only)."""
    rules = cta_rules()
    soup = parse_html(html).soup
    hidden_cache: dict[int, bool] = {}
    found = Candidates()
    for tag in soup.find_all(True):
        if tag.name in SKIP_TAGS:
            continue
        role = _attr(tag, "role").lower()
        live = _attr(tag, "aria-live").lower()
        is_alert = role in rules.alert_roles or live in rules.alert_live
        kind = _cta_kind(tag, rules)
        if not is_alert and kind is None:
            continue  # cheap tests first: most elements stop here
        if tag.find_parent(SKIP_TAGS) is not None or is_hidden_in_tree(tag, cache=hidden_cache):
            continue
        text = _label(tag)
        if not text:
            continue
        if is_alert:
            found.alerts.append(text)
        if kind is None or len(text) > rules.max_chars:
            continue
        if kind == "link" and not is_short_imperative(text):
            continue
        found.ctas.append(text)
    return found


def from_parsed_page(page: ParsedPage) -> Candidates:
    """Fallback without raw HTML: Part 2's form buttons + short imperative link texts."""
    rules = cta_rules()
    found = Candidates()
    for form in page.forms:
        for button in form.buttons:
            text = normalize_inline(button.text or button.value or "")
            if text and len(text) <= rules.max_chars:
                found.ctas.append(text)
    for link in page.links:
        text = normalize_inline(link.text)
        if text and len(text) <= rules.max_chars and is_short_imperative(text):
            found.ctas.append(text)
    return found
