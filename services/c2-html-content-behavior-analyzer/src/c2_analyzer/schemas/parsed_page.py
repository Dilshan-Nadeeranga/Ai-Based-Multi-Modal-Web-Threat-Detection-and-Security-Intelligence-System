"""ParsedPage: the structured output of the HTML preprocessing pipeline (schema 1.0).

Part 2: HTML preprocessing pipeline.

Why: Parts 3 (DOM), 5 (content) and 7/8 (JavaScript) all start from the same
page. This model is the contract between Part 2 and those parts: everything
they need is extracted ONCE, in a fixed shape, and saved as JSON. Only facts
are stored here - nothing in this file says whether a page is suspicious.

``schema_version`` changes whenever a field changes meaning, so saved JSON
files from an older version are re-processed instead of being misread.

Two field names are Python keywords, so they use aliases in the JSON:
``ExternalScript.is_async`` -> "async", ``SkeletonNode.class_`` -> "class".
Save with ``page.model_dump_json(by_alias=True)`` (see pipeline.to_json).
"""

from __future__ import annotations

from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    model_serializer,
)

SCHEMA_VERSION = "1.0"


class _Model(BaseModel):
    # populate_by_name: accept both "is_async" and the alias "async" when loading.
    model_config = ConfigDict(populate_by_name=True)


class PageMeta(_Model):
    """Where the page came from and how processing went."""

    sample_id: str | None = None
    page_url: str | None = None  # final_url > source_url > the URL given with an HTML string
    base_url: str | None = None  # <base href> > page_url (used to resolve relative links)
    dataset_version: str | None = None
    schema_version: str = SCHEMA_VERSION
    parser_used: str = "lxml"
    processing_ms: float = 0.0
    step_ms: dict[str, float] = Field(default_factory=dict)  # time per pipeline step
    html_size_bytes: int = 0  # size of the input before any truncation
    source_sha256: str | None = None  # sha256 of the input bytes (skip if unchanged)
    encoding: str | None = None
    domain_method: str | None = None  # "tldextract-offline" or "builtin-rule" (utils/url.py)
    truncated: bool = False
    truncation_reasons: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)  # one entry per failed step


class MetaTag(_Model):
    name: str | None = None
    property: str | None = None
    http_equiv: str | None = None
    content: str | None = None
    redirect_url: str | None = None  # only for http-equiv="refresh", resolved + PII-masked


class Heading(_Model):
    level: int = Field(ge=1, le=6)
    text: str


class Link(_Model):
    """One <a href>."""

    href_raw: str
    href_abs: str | None = None
    text: str = ""
    domain: str | None = None  # registrable domain (http/https only)
    is_external: bool = False
    rel: str | None = None
    target: str | None = None


class InputField(_Model):
    """One <input>, <select> or <textarea>."""

    tag: Literal["input", "select", "textarea"]
    type: str  # input type ("text" if missing); "select" / "textarea" for those tags
    name: str | None = None
    id: str | None = None
    placeholder: str | None = None
    autocomplete: str | None = None
    required: bool = False
    hidden: bool = False  # type=hidden, or hidden by attribute/inline style (also via a parent)
    maxlength: int | None = None
    label_text: str | None = None  # <label for=id>, a wrapping <label>, or aria-label
    value_present: bool = False
    value_masked: str | None = None  # prefilled value with PII replaced; passwords never kept


class Button(_Model):
    type: str
    text: str = ""
    value: str | None = None


class Form(_Model):
    index: int
    action_raw: str | None = None
    action_abs: str | None = None  # empty action -> page URL; javascript: -> None
    action_domain: str | None = None
    is_external_action: bool = False
    method: str = "GET"
    enctype: str | None = None
    id: str | None = None
    name: str | None = None
    inputs: list[InputField] = Field(default_factory=list)
    buttons: list[Button] = Field(default_factory=list)


class Stylesheet(_Model):
    href_abs: str | None = None
    domain: str | None = None
    is_external: bool = False


class CssSummary(_Model):
    """CSS is summarised, not kept. style="" attributes stay in the DOM for Part 3."""

    inline_style_blocks_count: int = 0
    inline_style_total_chars: int = 0
    style_attribute_count: int = 0
    external_stylesheets: list[Stylesheet] = Field(default_factory=list)


class CommentSummary(_Model):
    """HTML comments are removed from the content but counted (kits often leave some)."""

    count: int = 0
    total_chars: int = 0
    samples: list[str] = Field(default_factory=list)


class InlineScript(_Model):
    index: int
    type: str | None = None
    chars: int  # full length, even if content was capped
    content: str
    content_truncated: bool = False
    position: Literal["head", "body"]


class DataBlock(_Model):
    """A <script> that is data, not code: JSON-LD, JSON, or an HTML template."""

    type: str
    chars: int
    content: str


class EventHandler(_Model):
    tag: str
    attribute: str  # onclick, onsubmit, onload, ...
    code: str


class JavascriptUrl(_Model):
    tag: str
    attribute: str  # href, src, action, formaction, ...
    code: str  # the part after "javascript:"


class ExternalScript(_Model):
    src_raw: str
    src_abs: str | None = None
    domain: str | None = None
    is_external: bool = False
    is_async: bool = Field(default=False, alias="async")
    defer: bool = False
    type: str | None = None
    has_integrity: bool = False
    crossorigin: str | None = None


class Embedded(_Model):
    """<iframe>, <frame>, <object> or <embed>."""

    tag: str
    src_abs: str | None = None
    domain: str | None = None
    is_external: bool = False
    width: str | None = None
    height: str | None = None
    hidden: bool = False  # width/height 0, or hidden by attribute/inline style


class SkeletonNode(_Model):
    tag: str
    id: str | None = None
    class_: list[str] | None = Field(default=None, alias="class")  # first 2 classes
    type: str | None = None
    name: str | None = None
    href_domain: str | None = None
    children: list[SkeletonNode] = Field(default_factory=list)

    @model_serializer(mode="wrap")
    def _drop_empty(self, handler: SerializerFunctionWrapHandler) -> dict:
        """Leave out null attributes and empty children (a skeleton has thousands
        of nodes; this makes the JSON ~3x smaller). Loading fills the defaults back."""
        return {key: value for key, value in handler(self).items() if value not in (None, [])}


class DomSummary(_Model):
    node_count: int = 0  # elements + non-empty text nodes
    element_count: int = 0
    max_depth: int = 0
    tag_counts: dict[str, int] = Field(default_factory=dict)
    skeleton: SkeletonNode | None = None


class ParsedPage(_Model):
    """Everything later parts need from one HTML page (facts only, no judgements)."""

    meta: PageMeta = Field(default_factory=PageMeta)
    title: str | None = None
    meta_description: str | None = None
    meta_keywords: str | None = None
    lang_attr: str | None = None
    charset_declared: str | None = None
    meta_tags: list[MetaTag] = Field(default_factory=list)
    headings: list[Heading] = Field(default_factory=list)
    paragraphs: list[str] = Field(default_factory=list)
    visible_text: str = ""
    hidden_text: str = ""
    links: list[Link] = Field(default_factory=list)
    forms: list[Form] = Field(default_factory=list)
    inputs_outside_forms: list[InputField] = Field(default_factory=list)
    css: CssSummary = Field(default_factory=CssSummary)
    comments: CommentSummary = Field(default_factory=CommentSummary)
    scripts_inline: list[InlineScript] = Field(default_factory=list)
    structured_data: list[DataBlock] = Field(default_factory=list)  # JSON-LD / JSON
    templates: list[DataBlock] = Field(default_factory=list)  # text/template, handlebars, ...
    event_handlers: list[EventHandler] = Field(default_factory=list)
    javascript_urls: list[JavascriptUrl] = Field(default_factory=list)
    scripts_external: list[ExternalScript] = Field(default_factory=list)
    embedded: list[Embedded] = Field(default_factory=list)
    dom: DomSummary = Field(default_factory=DomSummary)

    @property
    def all_inputs(self) -> list[InputField]:
        """Inputs inside forms plus inputs outside any form."""
        return [field for form in self.forms for field in form.inputs] + self.inputs_outside_forms

    @property
    def meta_refresh(self) -> MetaTag | None:
        return next((tag for tag in self.meta_tags if tag.http_equiv == "refresh"), None)
