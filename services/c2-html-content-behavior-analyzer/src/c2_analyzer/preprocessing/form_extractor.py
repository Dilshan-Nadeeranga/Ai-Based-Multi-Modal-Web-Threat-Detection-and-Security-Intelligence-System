"""Extract forms, their input fields, labels and buttons (Task 8).

Part 2: HTML preprocessing pipeline.

Why: credential theft happens through forms - what is asked (email,
password, card number), and where the data is sent (the form action).
This module records both as facts; Part 3 turns them into features.

Details handled here:
- the action is resolved like a browser does: relative to <base href>, an
  empty/missing action means "this page", "#..." also stays on this page,
  "javascript:..." has no target URL (action_abs = None);
- labels come from <label for="id">, a <label> wrapping the input, or aria-label;
- inputs OUTSIDE any <form> are collected too (many kits submit them with
  JavaScript) - except those linked to a form with form="id";
- prefilled values are PII-masked; a prefilled password is never stored.
"""

from __future__ import annotations

from bs4 import BeautifulSoup, Tag

from c2_analyzer.preprocessing.settings import PreprocessSettings
from c2_analyzer.preprocessing.text_utils import normalize_inline, truncate
from c2_analyzer.preprocessing.visibility import is_hidden_in_tree
from c2_analyzer.schemas.parsed_page import Button, Form, InputField
from c2_analyzer.utils.pii import mask_pii, mask_url
from c2_analyzer.utils.url import is_external, registrable_domain, resolve_url

FIELD_TAGS = ["input", "select", "textarea"]
BUTTON_INPUT_TYPES = {"submit", "button", "reset", "image"}
NO_TARGET_SCHEMES = ("javascript:", "about:", "data:")


def _attr(tag: Tag, name: str) -> str | None:
    value = tag.get(name)
    if isinstance(value, list):
        value = " ".join(value)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _maxlength(tag: Tag) -> int | None:
    value = _attr(tag, "maxlength")
    return int(value) if value and value.isdigit() and len(value) < 10 else None


def resolve_action(raw: str | None, base_url: str | None, page_url: str | None) -> str | None:
    """Where the form sends its data (None = no URL, e.g. javascript:)."""
    if raw is None or not raw.strip() or raw.strip().startswith("#"):
        return page_url  # empty action or a fragment: the page itself
    if raw.strip().lower().startswith(NO_TARGET_SCHEMES):
        return None
    return resolve_url(raw, base_url)


class LabelIndex:
    """Label lookups for one page, built once: <label for="id"> texts and, for
    every field inside a <label>, its nearest wrapping label (so no field has to
    walk up through all its ancestors). Also holds the page's hidden-check cache.
    """

    def __init__(self, soup: BeautifulSoup) -> None:
        self.by_id: dict[str, str] = {}
        self.wrapper: dict[int, Tag] = {}  # id(field) -> nearest <label> around it
        self.hidden_cache: dict[int, bool] = {}  # see visibility.is_hidden_in_tree
        for label in soup.find_all("label"):
            target = _attr(label, "for")
            if target and target not in self.by_id:
                self.by_id[target] = normalize_inline(label.get_text(" "))
            # Document order: an inner label comes later and overwrites the outer one.
            for field in label.find_all(FIELD_TAGS):
                self.wrapper[id(field)] = label

    def label_for(self, field: Tag) -> str | None:
        field_id = _attr(field, "id")
        if field_id and self.by_id.get(field_id):
            return self.by_id[field_id]
        wrapper = self.wrapper.get(id(field))
        if wrapper is not None:
            text = normalize_inline(wrapper.get_text(" "))
            if text:
                return text
        return normalize_inline(_attr(field, "aria-label")) or None


def _value(field: Tag) -> str | None:
    if field.name == "textarea":
        return field.get_text() or None
    if field.name == "select":
        chosen = field.find("option", selected=True)
        return (_attr(chosen, "value") or normalize_inline(chosen.get_text())) if chosen else None
    return field.get("value") if isinstance(field.get("value"), str) else None


def input_field(field: Tag, labels: LabelIndex, settings: PreprocessSettings) -> InputField:
    """One input/select/textarea as an InputField."""
    kind = (_attr(field, "type") or "text").lower() if field.name == "input" else field.name
    value = _value(field)
    present = bool(value and value.strip())
    if not present:
        masked = None
    elif kind == "password":
        masked = "[REDACTED]"  # a prefilled password is never stored
    else:
        masked = truncate(mask_pii(value.strip()), settings.max_value_chars)
    return InputField(
        tag=field.name,
        type=kind,
        name=_attr(field, "name"),
        id=_attr(field, "id"),
        placeholder=normalize_inline(_attr(field, "placeholder")) or None,
        autocomplete=_attr(field, "autocomplete"),
        required=field.has_attr("required"),
        hidden=kind == "hidden" or is_hidden_in_tree(field, cache=labels.hidden_cache),
        maxlength=_maxlength(field),
        label_text=labels.label_for(field),
        value_present=present,
        value_masked=masked,
    )


def _button(tag: Tag) -> Button:
    if tag.name == "button":
        kind = (_attr(tag, "type") or "submit").lower()
        return Button(
            type=kind, text=normalize_inline(tag.get_text(" ")), value=_attr(tag, "value")
        )
    kind = (_attr(tag, "type") or "submit").lower()
    return Button(type=kind, text=normalize_inline(_attr(tag, "value") or _attr(tag, "alt")))


def _is_button(tag: Tag) -> bool:
    return tag.name == "button" or (
        tag.name == "input" and (_attr(tag, "type") or "").lower() in BUTTON_INPUT_TYPES
    )


def extract_forms(
    soup: BeautifulSoup,
    base_url: str | None,
    page_url: str | None,
    settings: PreprocessSettings,
) -> tuple[list[Form], list[InputField]]:
    """Return (forms, inputs outside any form)."""
    labels = LabelIndex(soup)
    forms_by_id = {}
    forms = []
    in_a_form: set[int] = set()  # id() of every field/button inside some <form>
    for index, form in enumerate(soup.find_all("form")):
        raw = form.get("action") if isinstance(form.get("action"), str) else None
        action = resolve_action(raw, base_url, page_url)
        method = (_attr(form, "method") or "GET").upper()
        record = Form(
            index=index,
            action_raw=truncate(mask_url(raw), settings.max_url_chars),
            action_abs=truncate(mask_url(action), settings.max_url_chars),
            action_domain=registrable_domain(action),
            is_external_action=is_external(action, page_url),
            method=method,
            enctype=_attr(form, "enctype"),
            id=_attr(form, "id"),
            name=_attr(form, "name"),
        )
        for tag in form.find_all(["input", "select", "textarea", "button"]):
            in_a_form.add(id(tag))
            if _is_button(tag):
                record.buttons.append(_button(tag))
            elif tag.name in FIELD_TAGS:
                record.inputs.append(input_field(tag, labels, settings))
        if record.id:
            forms_by_id.setdefault(record.id, record)
        forms.append(record)

    outside = []
    for tag in soup.find_all(["input", "select", "textarea", "button"]):
        if id(tag) in in_a_form:
            continue
        owner = forms_by_id.get(_attr(tag, "form") or "")  # <input form="login"> belongs to it
        if _is_button(tag):
            if owner is not None:
                owner.buttons.append(_button(tag))
            continue
        field = input_field(tag, labels, settings)
        (owner.inputs if owner is not None else outside).append(field)
    return forms, outside
