"""Static JavaScript analysis output (schema js_v1).

Part 7: Static JavaScript intent analyzer.

Why so much location detail: Part 7 only DETECTS API usage. Part 8 decides
intent by connecting sources to sinks (``pwd = #password.value`` ... ``fetch(
external, {body: pwd})``), so every detection carries what Part 8 needs to do
that without re-parsing: the script and byte range, the enclosing function,
the variable the value is assigned to, the identifiers used in the arguments,
literal URLs (PII-masked) and whether they leave the page's site.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "js_v1"

Source = Literal["inline", "event_handler", "javascript_url"]
Access = Literal["call", "read", "write", "assign", "construct", "listener"]
ArgKind = Literal["string_literal", "template", "identifier", "member", "call", "other", "none"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DetectionArgs(_Model):
    """What a call / assignment was given (the first argument, or the assigned value)."""

    first_arg_kind: ArgKind = "none"
    literal_value: str | None = None  # string value (<= 200 chars, PII / URL masked)
    concatenated: bool = False  # literal_value is only the leading literal of "..." + x
    url: str | None = None  # the URL argument resolved against the page's base URL (masked)
    url_domain: str | None = None
    url_is_external: bool | None = None  # None = no literal URL (dynamic)
    http_method: str | None = None  # xhr.open / fetch options / $.ajax type
    identifiers_used: list[str] = Field(default_factory=list)  # variables in the arguments


class Detection(_Model):
    """One API usage found in a script (evidence only - no verdict)."""

    api: str  # id from configs/js_rules.yaml (e.g. "eval", "document.cookie")
    category: str
    source: Source
    script_index: int  # index into JsAnalysisResult.scripts
    line: int  # 1-based, inside that script
    column: int  # 1-based, in characters
    end_line: int
    start_byte: int  # byte range inside the analysed script text (UTF-8)
    end_byte: int
    access: Access
    snippet: str  # single line, <= 200 chars, PII-masked, never HTML
    callee: str | None = None  # how it was written, normalized ("window['eval']" -> "window.eval")
    member: str | None = None  # method / property used (getItem, setItem, href, ...)
    args: DetectionArgs | None = None
    selector: str | None = None  # literal element selector ("#password", "input[type=password]")
    target: str | None = None  # receiver: element selector, variable or frame (top / parent)
    event_type: str | None = None  # listeners: keydown, submit, copy, ...
    assigned_to: str | None = None  # "pwd" in: var pwd = ....value
    enclosing_function: str | None = None  # name, or "<callback: addEventListener submit>"
    credential_hint: bool = False  # selector / name looks like a credential field
    in_library: bool = False  # inside a well-known library script (not page-own)
    confidence: Literal["high", "low"] = "high"  # low = lexical fallback / inside a parse error
    node_type: str | None = None  # tree-sitter node type (None for lexical matches)


class ObfuscationStats(_Model):
    """Descriptive statistics of one script (Part 8 judges, Part 7 only measures)."""

    chars: int
    lines: int
    avg_line_length: float
    max_line_length: int
    whitespace_ratio: float
    entropy: float  # Shannon entropy, bits per character
    non_alnum_ratio: float  # punctuation / symbols among non-whitespace characters
    escape_ratio: float  # chars in \xHH / \uHHHH escapes that hide ASCII letters / digits / spaces
    max_string_length: int
    identifier_count: int
    avg_identifier_length: float
    single_char_identifier_ratio: float
    hex_identifier_ratio: float  # _0x1a2b style names (obfuscator.io)
    string_array_size: int  # largest array literal made of strings
    minified: bool  # looks machine-compressed (long lines, little whitespace)
    signatures: list[str] = Field(default_factory=list)  # obfuscation indicators found


class ScriptInfo(_Model):
    """One analysed piece of JavaScript (an inline script, a handler or a javascript: URL)."""

    index: int
    source: Source
    origin: str  # "script #3 (body)", "onclick on <a>", "href on <a>"
    part2_index: int | None = None  # ParsedPage.scripts_inline index (inline scripts)
    chars: int  # full length before any cap
    analyzed_chars: int
    truncated: bool = False
    parser: Literal["tree-sitter", "lexical", "skipped"] = "tree-sitter"
    parsed_ok: bool = True  # tree-sitter gave a usable tree
    has_error: bool = False
    error_ratio: float = 0.0  # share of the script inside ERROR nodes
    timed_out: bool = False
    depth_capped: bool = False
    parse_ms: float = 0.0
    library: str | None = None
    detections: int = 0
    obfuscation: ObfuscationStats | None = None
    note: str | None = None


class ExternalScriptInfo(_Model):
    """A <script src> reference. Its CONTENT is never fetched (static mode)."""

    index: int
    src: str  # as Part 2 stored it (absolute when possible, PII-masked)
    domain: str | None = None
    is_external: bool = False
    is_async: bool = False
    defer: bool = False
    has_integrity: bool = False
    known_cdn: bool = False
    library: str | None = None
    flags: list[str] = Field(default_factory=list)  # raw_ip, free_hosting, data_url, insecure_http
    suspicious_host: bool = False


class ApiCount(_Model):
    api: str
    category: str
    page_own: int = 0
    library: int = 0


class JsMeta(_Model):
    schema_version: str = SCHEMA_VERSION
    sample_id: str | None = None
    dataset_version: str | None = None
    page_url: str | None = None
    base_url: str | None = None
    source_sha256: str | None = None
    rules_hash: str
    parser: str  # "tree-sitter 0.25.2 / tree-sitter-javascript 0.25.0" or "lexical only"
    processing_ms: float = 0.0
    step_ms: dict[str, float] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class JsSummary(_Model):
    """Counts and yes/no flags over PAGE-OWN detections (library code excluded)."""

    scripts_analyzed: int = 0
    scripts_lexical: int = 0  # tree-sitter could not be used
    library_scripts: int = 0
    detections_total: int = 0
    detections_page_own: int = 0
    detections_stored: int = 0  # the list may be cut (limits.max_detections_per_page)
    categories_page_own: dict[str, int] = Field(default_factory=dict)
    categories_library: dict[str, int] = Field(default_factory=dict)
    flags: dict[str, bool] = Field(default_factory=dict)
    libraries: list[str] = Field(default_factory=list)


class JsAnalysisResult(_Model):
    """Part 7 output for one page: what its JavaScript uses, where, and how."""

    meta: JsMeta
    feature_set_version: str
    features: dict[str, float | int]  # fixed order of configs/js_features.yaml
    summary: JsSummary
    scripts: list[ScriptInfo] = Field(default_factory=list)
    external_scripts: list[ExternalScriptInfo] = Field(default_factory=list)
    detections: list[Detection] = Field(default_factory=list)
    counts: list[ApiCount] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
