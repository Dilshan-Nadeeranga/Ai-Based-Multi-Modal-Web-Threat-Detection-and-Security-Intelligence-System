"""Sensitive sources and dangerous sinks of one page (tasks 1-2).

Part 8: Behavioral intent mapping (sources -> sinks).

Sources and sinks are recognised from PART 7's DETECTIONS (api ids from
configs/js_rules.yaml, listed per source / sink in configs/sources_sinks.yaml);
Part 8 only adds the few sources Part 7 does not record (event.key in key
listeners, navigator / screen fingerprint properties, location.href reads,
jQuery serialize()).

Credential fields: ``#password.value`` is a credential because Part 3 says the
page's field with id "password" is a password field (Part 3's field rules:
HTML type, autocomplete, name/id/placeholder/label patterns in en/si/ta) - the
selector is looked up in Part 2's forms / inputs. When the element is not in
the HTML (built by code) Part 7's credential-like name hint decides. A
FormData / serialize() of a form is a credential source when that form has
credential fields, otherwise "form_data_generic".

Sink destinations: a request / redirect / form action is external, internal
or unknown from its URL - Part 7's literal URL, or a string constant the URL
variable was set to in the same script (``var api = "https://..."``). A sink
whose URL (or a string in the same script) points to a known data-collection
service (Telegram bot API, Discord webhook, Formspree ...) is marked
``known_exfil_endpoint``.
Library scripts produce neither sources nor sinks.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urlsplit

from c2_analyzer.behavior.code_index import FunctionInfo, NodeKey, ScriptCtx
from c2_analyzer.behavior.rules import BehaviorRules
from c2_analyzer.behavior.triggers import Trigger, TriggerResolver
from c2_analyzer.dom.dictionary import load_dictionary
from c2_analyzer.dom.form_features import classify_field
from c2_analyzer.js_analyzer import syntax as sx
from c2_analyzer.js_analyzer.detectors import PageUrls, mask_literal, safe_snippet, url_facts
from c2_analyzer.schemas.js import Detection
from c2_analyzer.schemas.parsed_page import Form, InputField, ParsedPage
from c2_analyzer.utils.url import is_external, registrable_domain

URL_IN_STRING = re.compile(r"(?:https?:)?//[A-Za-z0-9.-]+(?:/[^\s'\"`<>]*)?", re.IGNORECASE)
SELECTOR_TOKEN = re.compile(r"[^\s>+~,]+$")
ATTRIBUTE = re.compile(r"\[\s*([\w-]+)\s*[*^$|~]?=\s*['\"]?([^'\"\]]*)['\"]?\s*\]")
REFRESH_DELAY = re.compile(r"^\s*(\d+(?:\.\d+)?)")
LEXICAL_LOOKUP = re.compile(
    r"(getElementById|querySelector|getElementsByName|\$)\(\s*['\"]([^'\"]{1,120})['\"]"
)
HELPER_LOOKUP = re.compile(r"^[\w$.]{1,40}\(\s*['\"]([\w:-]{1,60})['\"]\s*\)\s*\.\s*value$")
NETWORK_DATA_ALL = {"fetch", "navigator.sendBeacon", "jquery.ajax", "xhr.send", "websocket.send"}


@dataclass
class SourceRef:
    id: int
    source_id: str
    sensitivity: str
    api: str
    ctx: ScriptCtx | None
    node: Any | None
    line: int
    column: int
    code: str
    detail: str | None = None
    confidence: str = "high"
    secret: bool = False  # password / card / OTP-PIN (not only email / username)
    preview: str | None = (
        None  # decoded_string: the decoded literal, when it can be read statically
    )


@dataclass
class SinkRef:
    id: int
    sink_id: str
    api: str
    ctx: ScriptCtx | None
    node: Any | None
    line: int
    column: int
    code: str
    data_nodes: list[Any] = field(default_factory=list)
    url: str | None = None
    url_domain: str | None = None
    is_external: bool | None = None
    endpoint: str | None = None
    trigger: Trigger | None = None
    confidence: str = "high"
    detection: Detection | None = None
    note: str | None = None  # extra facts for the patterns (filename, delay, ...)


@dataclass
class Catalogue:
    sources: list[SourceRef] = field(default_factory=list)
    sinks: list[SinkRef] = field(default_factory=list)
    source_at: dict[NodeKey, list[int]] = field(default_factory=lambda: defaultdict(list))
    sink_at: dict[NodeKey, list[int]] = field(default_factory=lambda: defaultdict(list))
    key_callbacks: list[tuple[ScriptCtx, Any | None, str | None, str | None]] = field(
        default_factory=list
    )
    mentioned_endpoints: dict[int, list[tuple[str, str]]] = field(default_factory=dict)


# ---- decoded literals ------------------------------------------------------------------


def decoded_preview(api: str, node: Any, limit: int = 4000) -> str | None:
    """The decoded text of ``atob("...")`` / ``unescape("%3C...")`` /
    ``String.fromCharCode(60, 115, ...)`` / an escape-heavy literal. Decoding a LITERAL is
    static (nothing runs). None when the argument is not a literal."""
    try:
        if api == "escape_heavy_string":
            return (sx.string_value(node) or "")[:limit] or None
        args = sx.named_args(node)
        if api == "String.fromCharCode":
            codes = [sx.text(arg, 12) for arg in args[:limit]]
            if codes and all(code.isdigit() for code in codes):
                return "".join(chr(int(code)) for code in codes if int(code) < 0x110000)
            return None
        value = sx.string_value(args[0]) if args else None
        if value is None:
            return None
        value = value[: limit * 2]
        if api == "atob":
            data = value.strip()
            data += "=" * (-len(data) % 4)
            decoded = base64.b64decode(data, validate=False)
            return decoded.decode("utf-8", errors="replace")[:limit]
        if api == "unescape":
            return unquote(value)[:limit]
    except (ValueError, binascii.Error):
        return None
    return None


# ---- page fields (Part 3 field classes) -------------------------------------------------


class PageFields:
    """Look up a JS selector ("#password", "[name=email]", "forms[login]") in the page's HTML."""

    def __init__(self, page: ParsedPage) -> None:
        dictionary = load_dictionary()
        self.by_id: dict[str, set[str | None]] = defaultdict(set)
        self.by_name: dict[str, set[str | None]] = defaultdict(set)
        self.by_type: dict[str, set[str | None]] = defaultdict(set)
        self.forms: dict[str, set[str | None]] = {}
        self.form_list: list[set[str | None]] = []

        def add(item: InputField) -> str | None:
            kind = classify_field(item, dictionary)
            if item.id:
                self.by_id[item.id.lower()].add(kind)
            if item.name:
                self.by_name[item.name.lower()].add(kind)
            self.by_type[(item.type or "").lower()].add(kind)
            return kind

        for form in page.forms:
            classes = {add(item) for item in form.inputs}
            self.form_list.append(classes)
            for key in self._form_keys(form):
                self.forms[key] = classes
        for item in page.inputs_outside_forms:
            add(item)

    @staticmethod
    def _form_keys(form: Form) -> list[str]:
        keys = [str(form.index)]
        keys += [value.lower() for value in (form.id, form.name) if value]
        return keys

    def field_classes(self, selector: str | None) -> set[str | None] | None:
        """Classes of the input(s) a selector points to (None = not found in the HTML)."""
        if not selector:
            return None
        selector = selector.strip()
        if selector.startswith("forms["):
            return self.form_classes(selector)
        token = SELECTOR_TOKEN.search(selector)
        token = token.group() if token else selector
        found: set[str | None] = set()
        ident = re.search(r"#([\w:.-]+)", token)
        if ident and ident.group(1).lower() in self.by_id:
            found |= self.by_id[ident.group(1).lower()]
        for attribute, value in ATTRIBUTE.findall(token):
            attribute, value = attribute.lower(), value.lower()
            if attribute == "name" and value in self.by_name:
                found |= self.by_name[value]
            elif attribute == "type" and value in self.by_type:
                found |= self.by_type[value]
            elif attribute == "id" and value in self.by_id:
                found |= self.by_id[value]
        if not found and re.fullmatch(r"[\w-]+", token):  # getElementsByName("x") style
            found |= self.by_name.get(token.lower(), set()) | self.by_id.get(token.lower(), set())
        return found or None

    def form_classes(self, selector: str | None) -> set[str | None] | None:
        """Classes of all fields of the form a selector / forms[...] points to."""
        if not selector:
            return None
        match = re.fullmatch(r"forms\[['\"]?([^'\"\]]+)['\"]?\]", selector.strip())
        key = match.group(1) if match else None
        if key is None:
            ident = re.search(r"#([\w:.-]+)", selector)
            name = re.search(r"\[name=['\"]?([^'\"\]]+)", selector)
            key = (ident or name).group(1) if (ident or name) else None
        if key is None and selector.strip().lower() == "form" and len(self.form_list) == 1:
            return self.form_list[0]
        return self.forms.get(key.lower()) if key else None

    def any_credential_form(self, credential: set[str]) -> bool:
        return any(classes & credential for classes in self.form_list)


# ---- builder ---------------------------------------------------------------------------


class CatalogueBuilder:
    """Turns detections + Part 8 matchers into SourceRef / SinkRef lists."""

    def __init__(
        self,
        rules: BehaviorRules,
        page: ParsedPage,
        urls: PageUrls,
        contexts: list[ScriptCtx],
        registry: dict[str, list[FunctionInfo]],
        triggers: TriggerResolver,
    ) -> None:
        self.rules = rules
        self.page = page
        self.urls = urls
        self.contexts = contexts
        self.registry = registry
        self.triggers = triggers
        self.fields = PageFields(page)
        sources = rules.sources
        credential = sources["credential_input"]
        self.credential_classes = set(credential.get("field_classes") or [])
        self.secret_classes = set(credential.get("secret_classes") or [])
        self.extra_words = tuple(credential.get("extra_words") or [])
        self.secret_words = tuple(credential.get("secret_words") or [])
        self.key_apis = set(sources["keystrokes"].get("listener_apis") or [])
        self.event_props = set(sources["keystrokes"].get("event_properties") or [])
        self.page_paths = set(sources["page_url"].get("paths") or [])
        self.fingerprint_paths = set(sources["fingerprint"].get("paths") or [])
        self.decoders = set(sources["decoded_string"].get("apis") or [])
        self.code_chars = int(rules.limit("step_code_chars"))
        self.sink_by_api: dict[str, list[tuple[str, Any]]] = defaultdict(list)
        for sink_id, spec in rules.sinks.items():
            destination = spec.get("destination")
            if isinstance(destination, str):
                destination = [destination]
            for api in spec.get("apis") or []:
                self.sink_by_api[api].append((sink_id, destination))
        self.catalogue = Catalogue()

    # ---- helpers ------------------------------------------------------------------

    def _where(self, ctx: ScriptCtx, node: Any | None, detection: Detection | None):
        if node is not None:
            line, column = ctx.position(node)
            return line, column, ctx.code(node, self.code_chars)
        if detection is not None:
            snippet = detection.snippet
            if len(snippet) > self.code_chars:
                snippet = snippet[: self.code_chars - 3] + "..."
            return detection.line, detection.column, snippet
        return 1, 1, safe_snippet(ctx.unit.text, self.code_chars)

    def add_source(
        self,
        source_id: str,
        api: str,
        ctx: ScriptCtx,
        node: Any | None,
        detection: Detection | None = None,
        detail: str | None = None,
        secret: bool = False,
        preview: str | None = None,
    ) -> None:
        if node is not None:
            key = ctx.key(node)
            if any(
                self.catalogue.sources[i].source_id == source_id
                for i in self.catalogue.source_at.get(key, [])
            ):
                return  # the same node already is this source
        line, column, code = self._where(ctx, node, detection)
        low = ctx.lexical or (detection is not None and detection.confidence == "low")
        ref = SourceRef(
            id=len(self.catalogue.sources),
            source_id=source_id,
            sensitivity=self.rules.sensitivity(source_id),
            api=api,
            ctx=ctx,
            node=node,
            line=line,
            column=column,
            code=code,
            detail=detail,
            confidence="low" if low else "high",
            secret=secret,
            preview=preview,
        )
        self.catalogue.sources.append(ref)
        if node is not None:
            self.catalogue.source_at[ctx.key(node)].append(ref.id)

    def add_sink(self, ref: SinkRef) -> None:
        ref.id = len(self.catalogue.sinks)
        if ref.trigger is None and ref.ctx is not None:
            ref.trigger = self.triggers.for_node(ref.ctx, ref.node)
        self.catalogue.sinks.append(ref)
        if ref.node is not None and ref.ctx is not None:
            self.catalogue.sink_at[ref.ctx.key(ref.node)].append(ref.id)

    def endpoint(self, url: str | None) -> str | None:
        if not url:
            return None
        value = url if "//" in url[:12] else None
        if value is None:
            return None
        if value.startswith("//"):
            value = "https:" + value
        try:
            parts = urlsplit(value)
        except ValueError:
            return None
        host = (parts.hostname or "").lower()
        for endpoint in self.rules.endpoints:
            if host == endpoint.host or host.endswith("." + endpoint.host):
                if not endpoint.path or parts.path.startswith(endpoint.path):
                    return endpoint.name
        return None

    def mentioned(self, ctx: ScriptCtx) -> list[tuple[str, str]]:
        """Known endpoints named in any string literal of the script ((name, url) pairs)."""
        if ctx.index not in self.catalogue.mentioned_endpoints:
            found = []
            hosts = [endpoint.host for endpoint in self.rules.endpoints]
            for _, value in ctx.strings:
                lowered = value.lower()
                if not any(host in lowered for host in hosts):
                    continue
                for match in URL_IN_STRING.finditer(value):
                    name = self.endpoint(match.group())
                    if name:
                        found.append((name, mask_literal(match.group(), 300)))
            if ctx.lexical:
                for match in URL_IN_STRING.finditer(ctx.unit.text[:600_000]):
                    name = self.endpoint(match.group())
                    if name:
                        found.append((name, mask_literal(match.group(), 300)))
            self.catalogue.mentioned_endpoints[ctx.index] = found
        return self.catalogue.mentioned_endpoints[ctx.index]

    def const_url(self, ctx: ScriptCtx, node: Any | None):
        """URL facts of a variable holding a single string constant (else None)."""
        if node is None or ctx.lexical:
            return None
        node, _ = sx.unwrap(node)
        if node is None:
            return None
        literal, concatenated = sx.literal_prefix(node)
        if literal is None and node.type == "identifier":
            values = ctx.const_values(ctx.resolve(sx.text(node, 60), node))
            distinct = {value for value, _ in values}
            if len(distinct) == 1:
                literal, concatenated = values[0]
        elif node.type == "template_string" and not literal:
            # `${base}/collect`: the leading substitution's constant decides the host
            first = node.named_children[0] if node.named_child_count else None
            inner = (
                first.named_children[0] if first is not None and first.named_child_count else None
            )
            if first is not None and first.type == "template_substitution" and inner is not None:
                if inner.type == "identifier":
                    values = ctx.const_values(ctx.resolve(sx.text(inner, 60), inner))
                    if len({value for value, _ in values}) == 1:
                        literal, concatenated = values[0][0], True
        elif literal is None and node.type == "binary_expression":
            # url = base + "/collect": the leading identifier's constant decides the host
            left = node
            while left is not None and left.type == "binary_expression":
                left = sx.field(left, "left")
            if left is not None and left.type == "identifier":
                values = ctx.const_values(ctx.resolve(sx.text(left, 60), left))
                if len({value for value, _ in values}) == 1:
                    literal, concatenated = values[0][0], True
        if literal is None:
            return None
        return url_facts(literal, self.urls, concatenated)

    # ---- sources -------------------------------------------------------------------

    def _is_credential(self, detection: Detection, selector: str | None) -> tuple[bool, bool, str]:
        """(credential?, secret?, detail) of an input value read."""
        if selector is None and detection.node_type is None:
            # regex-only script: read the selector out of the matched text
            lookup = LEXICAL_LOOKUP.search(detection.snippet or "")
            if lookup:
                kind, value = lookup.group(1), lookup.group(2)
                selector = sx.SELECTOR_FUNCTIONS.get(kind, "{}").format(value)
        if selector is None:
            # a page helper around getElementById: getEl("password").value
            helper = HELPER_LOOKUP.match(detection.snippet or "")
            if helper and self.fields.field_classes(f"#{helper.group(1)}") is not None:
                selector = f"#{helper.group(1)}"
        classes = self.fields.field_classes(selector)
        if classes is not None:
            hit = sorted(c for c in classes if c in self.credential_classes)
            if hit:
                secret = bool(set(hit) & self.secret_classes)
                return True, secret, f"{selector} = {'/'.join(hit)} field"
            words = sx.name_tokens(selector or "")
            if any(token.startswith(self.extra_words) for token in words):
                return True, True, f"{selector} (credential name)"
            return False, False, f"{selector} = not a credential field"
        if detection.credential_hint:
            code = (detection.snippet or "")[:60]
            name = selector or (code[:-6] if code.endswith(".value") else None)
            name = name or detection.target or detection.assigned_to
            text = " ".join(v for v in (selector, detection.target, detection.assigned_to) if v)
            secret = any(token.startswith(self.secret_words) for token in sx.name_tokens(text))
            return True, secret, f"{name} (credential-like name)"
        return False, False, selector or detection.target or ""

    def _in_key_callback(self, ctx: ScriptCtx, node: Any | None) -> tuple[bool, str | None]:
        if node is None:
            unit = ctx.unit
            if unit.source == "event_handler" and (unit.attribute or "")[2:] in (
                "keydown",
                "keyup",
                "keypress",
                "input",
            ):
                return True, None
            return False, None
        for cb_ctx, function, _param, selector in self.catalogue.key_callbacks:
            if cb_ctx is ctx and function is None and ctx.unit.source == "event_handler":
                return True, selector
            if cb_ctx is ctx and function is not None:
                if function.start_byte <= node.start_byte and node.end_byte <= function.end_byte:
                    return True, selector
        return False, None

    def _form_source(
        self, api: str, ctx: ScriptCtx, node: Any | None, detection: Detection | None, selector
    ) -> None:
        """FormData / serialize(): a credential source only when THE form (resolved by its
        selector, or the form of the surrounding submit listener) has a password, card or
        OTP / PIN field. An email-only form (newsletter, contact) or an unresolved form is
        "form_data_generic"."""
        classes = self.fields.form_classes(selector) if selector else None
        if classes is None and node is not None:
            # new FormData(this) / (e.target) inside a submit listener: the listener's form
            for function in ctx.function_chain(node):
                listener = ctx.listeners.get(ctx.key(function))
                if listener and listener[0] == "submit" and listener[1]:
                    classes = self.fields.form_classes(listener[1])
                    selector = listener[1]
                    break
        if classes is None:
            self.add_source("form_data_generic", api, ctx, node, detection, "form not resolved")
            return
        secret = sorted(c for c in classes if c in self.secret_classes)
        found = sorted(c for c in classes if c in self.credential_classes)
        if secret:
            detail = f"form {selector}: {'/'.join(found)}"
            self.add_source("credential_input", api, ctx, node, detection, detail, secret=True)
        else:
            detail = f"form {selector}: " + ("/".join(found) if found else "no credential fields")
            self.add_source("form_data_generic", api, ctx, node, detection, detail)

    def _key_callbacks(self, ctx: ScriptCtx) -> None:
        for position, detection in enumerate(ctx.detections):
            if detection.api not in self.key_apis or detection.access != "listener":
                continue
            node = ctx.node_of.get(position)
            if node is None:
                if ctx.unit.source == "event_handler":
                    self.catalogue.key_callbacks.append((ctx, None, "event", detection.selector))
                continue
            functions: list[tuple[ScriptCtx, Any]] = []
            values = sx.named_args(node) if node.type == "call_expression" else []
            if node.type in ("assignment_expression",):
                right = sx.field(node, "right")
                values = [right] if right is not None else []
            for value in values:
                if value.type in sx.FUNCTION_TYPES:
                    functions.append((ctx, value))
                elif value.type == "identifier":
                    for info in self.registry.get(sx.text(value, 60), []):
                        target = next((c for c in self.contexts if c.index == info.script), None)
                        if target is not None:
                            functions.append((target, info.node))
            for target, function in functions:
                info = target.functions.get(target.key(function))
                param = info.params[0][0] if info and info.params and info.params[0] else None
                self.catalogue.key_callbacks.append(
                    (target, function, param, detection.selector or detection.target)
                )

    def sources(self, ctx: ScriptCtx) -> None:
        apis = self.rules.sources
        for position, detection in enumerate(ctx.detections):
            if detection.in_library:
                continue
            node = ctx.node_of.get(position)
            api, access = detection.api, detection.access
            if api == "input.value":
                # the whole typed value (also inside an input listener, e.g. search-as-you-type)
                # is input; per-key capture (event.key ...) is the keystrokes source below
                credential, secret, detail = self._is_credential(detection, detection.selector)
                if credential:
                    self.add_source(
                        "credential_input", api, ctx, node, detection, detail, secret=secret
                    )
                else:
                    in_keys, _ = self._in_key_callback(ctx, node)
                    detail = (detail + " (typed value)") if in_keys and detail else detail
                    self.add_source("user_input", api, ctx, node, detection, detail or None)
            elif api == "FormData":
                self._form_source(api, ctx, node, detection, detection.selector)
            elif api in apis["cookie_read"]["apis"] and access == "read":
                detail = f"{api}.{detection.member}" if detection.member else api
                self.add_source("cookie_read", api, ctx, node, detection, detail)
            elif api in apis["storage_read"]["apis"] and access == "read":
                self.add_source(
                    "storage_read", api, ctx, node, detection, f"{api}.{detection.member or '[]'}"
                )
            elif api in apis["clipboard_read"]["apis"] and access == "read":
                self.add_source("clipboard_read", api, ctx, node, detection, detection.member)
            elif api == "location_read":
                kind = "referrer" if detection.member == "referrer" else "page_url"
                self.add_source(kind, api, ctx, node, detection, detection.callee)
            elif api in self.decoders:
                preview = decoded_preview(api, node) if node is not None else None
                self.add_source("decoded_string", api, ctx, node, detection, api, preview=preview)
        if ctx.lexical:
            return
        # Part 8's own matchers
        for node in ctx.calls.get("serialize", []):
            function = sx.field(node, "function")
            receiver = sx.field(function, "object") if function is not None else None
            selector = sx.selector_of(receiver) if receiver is not None else None
            self._form_source("part8:serialize", ctx, node, None, selector)
        for node, path in ctx.member_reads:
            name = sx.fmt_path(path)
            if name in self.page_paths:
                self.add_source("page_url", f"part8:{name}", ctx, node, None, name)
            elif name in self.fingerprint_paths:
                self.add_source("fingerprint", f"part8:{name}", ctx, node, None, name)
        for node in ctx.calls.get("fingerprint", []):
            self.add_source("fingerprint", "part8:timezone", ctx, node, None, "timezone")
        for node in ctx.calls.get("location_string", []):
            self.add_source("page_url", "part8:location.toString", ctx, node, None, "location")
        for node, obj, prop in ctx.event_reads:
            for cb_ctx, function, param, selector in self.catalogue.key_callbacks:
                if cb_ctx is not ctx:
                    continue
                inside = function is None or (
                    function.start_byte <= node.start_byte and node.end_byte <= function.end_byte
                )
                if inside and (obj == param or obj == "event"):
                    where = f" on {selector}" if selector else ""
                    self.add_source(
                        "keystrokes", f"part8:event.{prop}", ctx, node, None, f"event.{prop}{where}"
                    )
                    break

    # ---- sinks ---------------------------------------------------------------------

    def _data_nodes(self, api: str, node: Any) -> tuple[list[Any], Any | None]:
        """(nodes carrying the data, the URL node) of a sink node."""
        args = sx.named_args(node) if node.type in ("call_expression", "new_expression") else []
        right = sx.field(node, "right") if "assignment" in node.type else None
        first = args[0] if args else None
        if node.type == "call_expression" and api in (
            "form.action",
            "download_attribute",
            "srcdoc",
        ):
            return args[1:], args[1] if len(args) > 1 else None  # setAttribute(name, value)
        if api in NETWORK_DATA_ALL:
            url = first
            if api == "jquery.ajax" and first is not None and first.type == "object":
                url = None
                for pair in first.named_children:
                    key = sx.field(pair, "key") if pair.type == "pair" else None
                    if key is not None and sx.text(key, 10).strip("'\"") == "url":
                        url = sx.field(pair, "value")
            if api in ("xhr.send", "websocket.send"):
                url = None
            return args, url
        if api == "xhr.open":
            return args[1:2], args[1] if len(args) > 1 else None
        if api in (
            "WebSocket",
            "EventSource",
            "location.assign",
            "location.replace",
            "window.open",
        ):
            return args[:1], first
        if api in ("image_beacon", "location.href", "form.action"):
            return ([right] if right is not None else []), right
        if api in ("clipboardData.setData", "insertAdjacentHTML"):
            return args[1:], None
        if api in ("setTimeout_string", "setInterval_string"):
            return args[:1], None
        if api == "localStorage" or api == "sessionStorage":
            return (args[1:] if args else ([right] if right is not None else [])), None
        if right is not None:
            return [right], None
        return args, None

    def _xhr_url(self, ctx: ScriptCtx, node: Any):
        """URL facts of the xhr.open() that belongs to this xhr.send()."""
        function = sx.field(node, "function")
        receiver = sx.field(function, "object") if function is not None else None
        name = sx.text(receiver, 60) if receiver is not None else None
        best = None
        for sink in self.catalogue.sinks:
            if sink.ctx is not ctx or sink.api != "xhr.open" or sink.node is None:
                continue
            if sink.node.start_byte > node.start_byte:
                break
            target = sink.detection.target if sink.detection is not None else None
            if name is None or target == name or best is None:
                best = sink
        return best

    def _destination(self, sink_ids: list[tuple[str, Any]], external: bool | None) -> str:
        wanted = "unknown" if external is None else ("external" if external else "internal")
        for sink_id, destinations in sink_ids:
            if destinations is None or wanted in destinations:
                return sink_id
        return sink_ids[0][0]

    def sinks(self, ctx: ScriptCtx) -> None:
        for position, detection in enumerate(ctx.detections):
            if detection.in_library:
                continue
            api, access = detection.api, detection.access
            candidates = self.sink_by_api.get(api)
            if not candidates:
                continue
            if api in ("localStorage", "sessionStorage", "document.cookie", "cookieStore"):
                if access != "write":
                    continue
            if api == "document.execCommand" and access != "write":
                continue
            if api.startswith("navigator.clipboard.") and access != "write":
                continue
            if api.startswith("clipboardData.") and access != "write":
                continue
            node = ctx.node_of.get(position)
            line, column, code = self._where(ctx, node, detection)
            data, url_node = self._data_nodes(api, node) if node is not None else ([], None)
            args = detection.args
            url = args.url if args else None
            domain = args.url_domain if args else None
            external = args.url_is_external if args else None
            if url is None and external is None and node is not None:
                facts = self.const_url(ctx, url_node)
                if api == "xhr.send":
                    opened = self._xhr_url(ctx, node)
                    if opened is not None:
                        facts = (opened.url, opened.url_domain, opened.is_external)
                if facts is not None:
                    url, domain, external = facts
            endpoint = self.endpoint(url)
            note = None
            has_destination = any(d is not None for _, d in candidates)
            if (
                has_destination
                and endpoint is None
                and external is None
                and api in self.sink_by_api
            ):
                network = any(s.startswith("network") for s, _ in candidates)
                mentioned = self.mentioned(ctx) if network else []
                if mentioned:
                    endpoint, url = mentioned[0]
                    external = True
                    domain = registrable_domain(url if "//" in url[:8] else "https:" + url)
                    note = "destination taken from a string in the same script"
            sink_id = (
                self._destination(candidates, external) if has_destination else candidates[0][0]
            )
            low = ctx.lexical or detection.confidence == "low" or note is not None
            self.add_sink(
                SinkRef(
                    id=0,
                    sink_id=sink_id,
                    api=api,
                    ctx=ctx,
                    node=node,
                    line=line,
                    column=column,
                    code=code,
                    data_nodes=data,
                    url=url,
                    url_domain=domain,
                    is_external=external,
                    endpoint=endpoint,
                    confidence="low" if low else "high",
                    detection=detection,
                    note=note,
                )
            )
        if ctx.lexical:
            return
        self._websocket_sends(ctx)

    def _websocket_sends(self, ctx: ScriptCtx) -> None:
        sockets = {
            d.assigned_to: d for d in ctx.detections if d.api == "WebSocket" and d.assigned_to
        }
        if not sockets:
            return
        for node in ctx.calls.get("send", []):
            function = sx.field(node, "function")
            receiver = sx.field(function, "object") if function is not None else None
            name = sx.text(receiver, 60) if receiver is not None else None
            socket = sockets.get(name)
            if socket is None:
                continue
            args = socket.args
            external = args.url_is_external if args else None
            sink_ids = self.sink_by_api["websocket.send"]
            line, column = ctx.position(node)
            self.add_sink(
                SinkRef(
                    id=0,
                    sink_id=self._destination(sink_ids, external),
                    api="websocket.send",
                    ctx=ctx,
                    node=node,
                    line=line,
                    column=column,
                    code=ctx.code(node, self.code_chars),
                    data_nodes=sx.named_args(node),
                    url=args.url if args else None,
                    url_domain=args.url_domain if args else None,
                    is_external=external,
                    endpoint=self.endpoint(args.url if args else None),
                )
            )

    def html_sinks(self) -> None:
        """<meta http-equiv="refresh" content="0; url=..."> in the HTML (Part 2 resolved it)."""
        for tag in self.page.meta_tags:
            if (tag.http_equiv or "").lower() != "refresh" or not tag.redirect_url:
                continue
            site = self.urls.site()
            external = is_external(tag.redirect_url, site) if site else True
            delay = REFRESH_DELAY.match(tag.content or "")
            sink_id = "redirect_external" if external else "redirect_internal"
            self.add_sink(
                SinkRef(
                    id=0,
                    sink_id=sink_id,
                    api="meta_refresh_tag",
                    ctx=None,
                    node=None,
                    line=0,
                    column=0,
                    code=safe_snippet(
                        f'<meta http-equiv="refresh" content="{tag.content or ""}">',
                        self.code_chars,
                    ),
                    url=tag.redirect_url,
                    url_domain=registrable_domain(tag.redirect_url),
                    is_external=external,
                    endpoint=self.endpoint(tag.redirect_url),
                    trigger=Trigger("auto", "meta refresh in the HTML (no user action)", "load"),
                    note=delay.group(1) if delay else "0",
                )
            )

    def build(self) -> Catalogue:
        for ctx in self.contexts:
            if not ctx.lexical:
                self._key_callbacks(ctx)
        for ctx in self.contexts:
            self.sources(ctx)
            self.sinks(ctx)
        self.html_sinks()
        return self.catalogue
