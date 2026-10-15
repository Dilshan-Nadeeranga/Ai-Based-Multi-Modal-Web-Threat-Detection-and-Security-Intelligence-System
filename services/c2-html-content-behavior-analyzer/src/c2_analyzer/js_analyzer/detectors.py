"""Dangerous / interesting API detectors on the AST (tasks 5-15).

Part 7: Static JavaScript intent analyzer.

One pass over the tree (``visitor.AstWalker``) with a handler per node type:
calls, ``new``, assignments, member reads, variable declarations (for
aliases), strings (escape-heavy literals) and identifiers / arrays (for the
obfuscation statistics). Every hit becomes a ``schemas.js.Detection`` with
its exact place (line, column, byte range), how it was written (``callee``),
read vs write (``access``), what it was given (``args``: literal value, URL,
whether the URL leaves the page's site, identifiers used), the enclosing
function and the variable it is assigned to - so Part 8 can connect sources
to sinks without parsing again.

What is covered (aliases included, see syntax.py):
  5  eval, window/self/globalThis/top eval, window["eval"], (0, eval)(), eval.call,
     execScript, var e = eval; e(), setTimeout / setInterval with a STRING
  6  new Function, Function(), x.constructor("code"), Function.prototype.constructor
  7  document.write / writeln
  8  innerHTML / outerHTML (= and +=), insertAdjacentHTML, srcdoc (property or setAttribute)
  9  fetch, navigator.sendBeacon, new WebSocket, new EventSource, image beacons
 10  new XMLHttpRequest (ActiveXObject), xhr.open(method, url), xhr.send(body), $.ajax/post/get
 11  form.submit(), requestSubmit(), document.forms[..].submit(), form.action =,
     setAttribute("action"), dispatchEvent(new Event("submit")), $(f).trigger("submit")
 12  location = / location.href = / assign / replace (window/document/top/parent/self),
     window.open, history.pushState to an EXTERNAL URL, meta refresh made from code
 13  document.cookie READ vs WRITE (+ cookieStore)
 14  localStorage / sessionStorage getItem/setItem/removeItem/clear, property and bracket access
 15  navigator.clipboard.*, execCommand copy/cut/paste, copy/cut/paste listeners, clipboardData
 + credential sources (x.value, $(..).val(), FormData), listeners (key*, input, submit,
   beforeunload, contextmenu), decoders (atob, unescape, fromCharCode ...), escape-heavy
   strings, downloads (a.download, createObjectURL, msSaveBlob, Blob), location.search/hash reads.

Limits (documented for the viva): aliases are tracked per script, in source
order, without scopes; values computed at run time (``window[a + b]``) are
not resolved - static analysis cannot know them without running the code,
which Part 7 never does.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from c2_analyzer.dataset.page_view import terminal_safe
from c2_analyzer.js_analyzer import syntax as sx
from c2_analyzer.js_analyzer.obfuscation import ObfuscationCollector
from c2_analyzer.js_analyzer.rules import Rules
from c2_analyzer.js_analyzer.visitor import AstWalker
from c2_analyzer.schemas.js import Detection, DetectionArgs
from c2_analyzer.utils.pii import mask_pii, mask_url
from c2_analyzer.utils.url import is_external, registrable_domain, resolve_url

WANTED = frozenset(
    {
        "call_expression",
        "new_expression",
        "assignment_expression",
        "augmented_assignment_expression",
        "variable_declarator",
        "member_expression",
        "subscript_expression",
        "string",
        "identifier",
        "array",
    }
)
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
STORAGE = ("localStorage", "sessionStorage")
STORAGE_READ = {"getItem": "read", "key": "read"}
STORAGE_WRITE = {"setItem": "write", "removeItem": "write", "clear": "write"}
READ_PROPERTIES = frozenset({"cookie", "value", "search", "hash", "referrer"})
JQUERY = ("$", "jQuery")
JQUERY_SHORTHAND = {"keydown", "keypress", "keyup", "contextmenu", "submit", "input"}
URL_IN_TEXT = re.compile(r"(?:(?:https?|wss?):)?//[^\s'\"`<>()\\]+", re.IGNORECASE)
IMAGE_NAMES = re.compile(r"img|image|pixel|beacon", re.IGNORECASE)
# alias markers for objects created in the script (var x = new XMLHttpRequest())
XHR, IMAGE, ANCHOR, META, SOCKET = "<xhr>", "<image>", "<anchor>", "<meta>", "<websocket>"
ELEMENT = "<el {}>"  # var p = document.getElementById("password") -> "<el #password>"
# x.value is only recorded on something that is clearly an element (or has a
# credential-like name): in minified bundles "e.value" is usually a Map entry,
# an iterator result or framework state, not an input field.
DOM_RECEIVERS = frozenset({"target", "currentTarget", "srcElement", "elements", "forms"})


@dataclass
class PageUrls:
    """Where the page lives: base_url resolves relative URLs, page_url decides 'external'."""

    page_url: str | None
    base_url: str | None

    def site(self) -> str | None:
        return self.page_url or self.base_url


def safe_snippet(value: str, limit: int = 200) -> str:
    """One line, PII-masked (URLs: query / fragment values), control characters removed."""
    line = " ".join(value[: limit * 3].split())
    line = URL_IN_TEXT.sub(lambda match: mask_url(match.group()) or "", line)
    line = terminal_safe(mask_pii(line))
    return line if len(line) <= limit else line[: limit - 3].rstrip() + "..."


def mask_literal(value: str, limit: int = 200) -> str:
    if value.lower().startswith(("http:", "https:", "//", "ws:", "wss:", "/", "?")):
        value = mask_url(value) or value
    value = terminal_safe(mask_pii(value))
    return value if len(value) <= limit else value[: limit - 3] + "..."


SCHEME_HOST = re.compile(r"^(?:[a-z][a-z0-9+.-]*:)?//([^/?#]*)(.?)", re.IGNORECASE)


def url_facts(
    literal: str | None, urls: PageUrls, concatenated: bool = False
) -> tuple[str | None, str | None, bool | None]:
    """(absolute masked URL, registrable domain, is_external) of a literal URL argument.

    Relative URLs are resolved against the page's base URL (``<base href>`` >
    page URL); "external" compares with the page's own site, like Part 2/3. With
    no page URL every absolute URL counts as external (Part 2's rule).
    For a concatenation (``"https://" + host`` or ``"https://ab" + x + ".com"``) the
    host is only trusted when the literal part already ends it (a / ? # follows).
    """
    if literal is None:
        return None, None, None
    value = literal.strip()
    lowered = value.lower()
    if not value or lowered.startswith(("javascript:", "#", "data:", "blob:", "about:", "mailto:")):
        return None, None, None
    host = SCHEME_HOST.match(value)
    if host is not None and (not host.group(1) or (concatenated and not host.group(2))):
        return None, None, None  # the host is built at run time - unknown
    if value.startswith("//"):
        value = "https:" + value
    absolute = resolve_url(value, urls.base_url) or value
    web = re.sub(r"^ws(s?)://", r"http\1://", absolute, flags=re.IGNORECASE)
    domain = registrable_domain(web)
    if domain is None:
        # not a web URL (e.g. relative with no known page): unknown, unless the page is known
        return mask_literal(absolute, 300), None, (False if urls.site() else None)
    return mask_literal(absolute, 300), domain, is_external(web, urls.site())


@dataclass
class ScriptDetector:
    """Runs every detector over one parsed script."""

    rules: Rules
    script_index: int
    source: str  # inline | event_handler | javascript_url
    src: bytes
    urls: PageUrls
    in_library: bool = False
    aliases: dict[str, list[str]] = field(default_factory=dict)
    detections: list[Detection] = field(default_factory=list)
    obfuscation: ObfuscationCollector = field(default_factory=ObfuscationCollector)
    depth_capped: bool = False

    def __post_init__(self) -> None:
        lists = self.rules.lists
        self.global_aliases = frozenset(lists.get("global_aliases") or [])
        self.listener_events = dict(lists.get("listener_events") or {})
        self.credential_words = tuple(w.lower() for w in lists.get("credential_words") or [])
        self.ignored = frozenset(lists.get("ignored_identifiers") or [])
        self.snippet_chars = int(self.rules.limits.get("snippet_chars", 200))
        self.literal_chars = int(self.rules.limits.get("literal_chars", 200))
        self.max_identifiers = int(self.rules.limits.get("max_identifiers_used", 20))

    # ---- driver -------------------------------------------------------------------

    def run(self, tree: Any, max_depth: int) -> list[Detection]:
        walker = AstWalker(WANTED, max_depth)
        handlers = {
            "call_expression": self.on_call,
            "new_expression": self.on_new,
            "assignment_expression": self.on_assign,
            "augmented_assignment_expression": self.on_assign,
            "variable_declarator": self.on_declarator,
            "member_expression": self.on_member,
            "subscript_expression": self.on_member,
            "string": self.on_string,
            "identifier": self.on_identifier,
            "array": self.on_array,
        }
        for node, in_error in walker.walk(tree.root_node):
            self.in_error = in_error
            handlers[node.type](node)
        self.depth_capped = walker.depth_capped
        return self.detections

    # ---- helpers ------------------------------------------------------------------

    def path(self, node: Any) -> tuple[list[str], str | None]:
        raw = sx.raw_path(node) or ["?"]
        if raw and raw[0] in self.aliases and len(raw) <= sx.MAX_SEGMENTS:
            raw = self.aliases[raw[0]] + raw[1:]
        return sx.normalize(raw, self.global_aliases)

    def args_info(
        self,
        values: list[Any],
        url_node: Any | None = None,
        method: str | None = None,
        url_literal: str | None = None,
    ) -> DetectionArgs:
        first = values[0] if values else None
        literal, concatenated = sx.literal_prefix(first)
        url_concatenated = False
        if url_literal is None and url_node is not None:
            url_literal, url_concatenated = sx.literal_prefix(url_node)
        url, domain, external = url_facts(url_literal, self.urls, url_concatenated)
        return DetectionArgs(
            first_arg_kind=sx.arg_kind(first),
            literal_value=mask_literal(literal, self.literal_chars) if literal else None,
            concatenated=concatenated,
            url=url,
            url_domain=domain,
            url_is_external=external,
            http_method=method,
            identifiers_used=sx.identifiers_in(values, self.ignored, self.max_identifiers),
        )

    def emit(self, api: str, node: Any, access: str, **extra: Any) -> None:
        row, column_bytes = node.start_point
        line_start = node.start_byte - column_bytes
        column = len(self.src[line_start : node.start_byte].decode("utf-8", errors="replace")) + 1
        receiver_text = extra.pop("receiver_text", None)
        credential = extra.pop("credential", None)
        if credential is None:
            credential = False
        elif credential == "auto":
            credential = sx.looks_like_credential(
                self.credential_words,
                extra.get("selector"),
                receiver_text,
                extra.get("assigned_to"),
            )
        self.detections.append(
            Detection(
                api=api,
                category=self.rules.category(api),
                source=self.source,
                script_index=self.script_index,
                line=row + 1,
                column=column,
                end_line=node.end_point[0] + 1,
                start_byte=node.start_byte,
                end_byte=node.end_byte,
                access=access,
                snippet=safe_snippet(sx.text(node, self.snippet_chars * 3), self.snippet_chars),
                enclosing_function=sx.enclosing_function(node),
                credential_hint=bool(credential),
                in_library=self.in_library,
                confidence="low" if self.in_error else "high",
                node_type=node.type,
                **extra,
            )
        )

    def options_value(self, node: Any | None, *keys: str) -> Any | None:
        """The value node of {key: value} in an object literal argument."""
        if node is None or node.type != "object":
            return None
        for pair in node.named_children:
            if pair.type != "pair":
                continue
            key = sx.field(pair, "key")
            name = sx.string_value(key) if key is not None and key.type == "string" else None
            name = name if name is not None else (sx.text(key, 40) if key is not None else "")
            if name in keys:
                return sx.field(pair, "value")
        return None

    def literal_upper(self, node: Any | None) -> str | None:
        value = sx.string_value(node) if node is not None else None
        return value.strip().upper()[:10] if value else None

    def receiver_label(
        self, receiver: Any | None, path: list[str]
    ) -> tuple[str | None, str | None]:
        """(selector, target) of the object a method is called on."""
        if receiver is None:
            return None, None
        selector = sx.selector_of(receiver)
        if selector is None and path and path[0].startswith("<el "):
            selector = path[0][4:-1]  # an element alias
        target = selector or sx.fmt_path(path[:-1]) or None
        return selector, target

    # ---- calls ----------------------------------------------------------------------

    def on_call(self, node: Any) -> None:
        function = sx.field(node, "function")
        if function is None:
            return
        unwrapped, indirect = sx.unwrap(function)
        path, frame = self.path(function)
        name = path[-1]
        args = sx.named_args(node)
        raw = sx.raw_path(function) or path
        callee = sx.fmt_path(raw)
        if raw and raw[0] in self.aliases:
            callee += f" (alias of {sx.fmt_path(self.aliases[raw[0]])})"
        if indirect:
            callee = f"(0, {callee})"
        receiver = sx.field(unwrapped, "object") if unwrapped is not None else None
        first = args[0] if args else None
        n = len(path)

        # task 5: eval and its aliases
        if path in (["eval"], ["eval", "call"], ["eval", "apply"]):
            values = args[1:] if n == 2 else args
            self.emit("eval", node, "call", callee=callee, args=self.args_info(values))
            return
        if path == ["execScript"]:
            self.emit("execScript", node, "call", callee=callee, args=self.args_info(args))
            return
        if path in (["setTimeout"], ["setInterval"]) and sx.is_stringish(first):
            api = f"{path[0]}_string"
            self.emit(api, node, "call", callee=callee, args=self.args_info(args[:1]))
            return
        # task 6: Function constructor
        # x.constructor("code") only with a string (this.constructor(a, b) builds an object)
        constructor_call = name == "constructor" and n >= 2 and args
        constructor_call = constructor_call and (
            sx.is_stringish(first) or path[-2] == "constructor"
        )
        if path in (["Function"], ["Function", "call"], ["Function", "apply"]) or constructor_call:
            self.emit("Function", node, "call", callee=callee, args=self.args_info(args))
            return
        # task 7: document.write
        if path in (["document", "write"], ["document", "writeln"]):
            api = f"document.{name}"
            self.emit(api, node, "call", callee=callee, args=self.args_info(args))
            return
        # task 8: insertAdjacentHTML
        if name == "insertAdjacentHTML" and n >= 2:
            selector, target = self.receiver_label(receiver, path)
            self.emit(
                "insertAdjacentHTML",
                node,
                "call",
                callee=callee,
                args=self.args_info(args[1:]),
                selector=selector,
                target=target,
            )
            return
        # task 9: fetch / beacon
        if path == ["fetch"]:
            options = args[1] if len(args) > 1 else None
            method = self.literal_upper(self.options_value(options, "method")) or "GET"
            self.emit(
                "fetch",
                node,
                "call",
                callee=callee,
                assigned_to=sx.assigned_to(node),
                args=self.args_info(args, url_node=first, method=method),
            )
            return
        if path == ["navigator", "sendBeacon"]:
            self.emit(
                "navigator.sendBeacon",
                node,
                "call",
                callee=callee,
                args=self.args_info(args, url_node=first, method="POST"),
            )
            return
        # task 10: XMLHttpRequest and jQuery ajax
        if name == "open" and n == 2 and len(args) >= 2:
            receiver_is_xhr = path[0] == XHR
            method = self.literal_upper(first)
            if receiver_is_xhr or method in HTTP_METHODS:
                self.emit(
                    "xhr.open",
                    node,
                    "call",
                    callee=callee,
                    target=raw[0],
                    args=self.args_info(args, url_node=args[1], method=method),
                )
                return
        if name == "send" and n == 2 and path[0] == XHR:
            self.emit("xhr.send", node, "call", callee=callee, args=self.args_info(args))
            return
        if n == 2 and path[0] in JQUERY and name in ("ajax", "post", "get", "getJSON"):
            settings = first if first is not None and first.type == "object" else None
            url_node = self.options_value(settings, "url") if settings is not None else first
            method = self.literal_upper(self.options_value(settings, "type", "method"))
            method = method or ("POST" if name == "post" else "GET")
            self.emit(
                "jquery.ajax",
                node,
                "call",
                callee=callee,
                member=name,
                args=self.args_info(args, url_node=url_node, method=method),
            )
            return
        # task 12: redirects
        if path in (["location", "assign"], ["location", "replace"]):
            self.emit(
                f"location.{name}",
                node,
                "call",
                callee=callee,
                target=frame,
                args=self.args_info(args, url_node=first),
            )
            return
        if path == ["open"]:
            self.emit(
                "window.open",
                node,
                "call",
                callee=callee,
                target=frame,
                args=self.args_info(args, url_node=first),
            )
            return
        if path in (["history", "pushState"], ["history", "replaceState"]) and len(args) >= 3:
            info = self.args_info(args[2:], url_node=args[2])
            if info.url_is_external:
                self.emit("history.pushState", node, "call", callee=callee, member=name, args=info)
            return
        # task 11: form submission
        if name in ("submit", "requestSubmit") and n >= 2:
            selector, target = self.receiver_label(receiver, path)
            if name == "submit" and first is not None and first.type in sx.FUNCTION_TYPES:
                self.emit(
                    "submit_listener",
                    node,
                    "listener",
                    callee=callee,
                    event_type="submit",
                    selector=selector,
                    target=target,
                )
                return
            api = "form.submit" if name == "submit" else "form.requestSubmit"
            self.emit(api, node, "call", callee=callee, selector=selector, target=target)
            return
        if name == "dispatchEvent" and first is not None and first.type == "new_expression":
            ctor = sx.field(first, "constructor")
            event_args = sx.named_args(first)
            event = sx.string_value(event_args[0]) if event_args else None
            if ctor is not None and sx.text(ctor) in ("Event", "SubmitEvent") and event == "submit":
                selector, target = self.receiver_label(receiver, path)
                self.emit(
                    "submit_event",
                    node,
                    "call",
                    callee=callee,
                    event_type="submit",
                    selector=selector,
                    target=target,
                )
            return
        if name in ("trigger", "triggerHandler") and n >= 2 and sx.string_value(first) == "submit":
            selector, target = self.receiver_label(receiver, path)
            self.emit(
                "submit_event",
                node,
                "call",
                callee=callee,
                event_type="submit",
                selector=selector,
                target=target,
            )
            return
        # task 15: clipboard
        if path == ["document", "execCommand"]:
            command = (sx.string_value(first) or "").lower()
            if command in ("copy", "cut", "paste"):
                access = "read" if command == "paste" else "write"
                self.emit(
                    "document.execCommand",
                    node,
                    access,
                    callee=callee,
                    member=command,
                    args=self.args_info(args),
                )
            return
        if (
            n >= 2
            and path[-2] == "clipboard"
            and name in ("writeText", "write", "readText", "read")
        ):
            access = "write" if name.startswith("write") else "read"
            self.emit(
                f"navigator.clipboard.{name}",
                node,
                access,
                callee=callee,
                assigned_to=sx.assigned_to(node),
                args=self.args_info(args),
            )
            return
        if name in ("setData", "getData") and "clipboardData" in path:
            access = "write" if name == "setData" else "read"
            self.emit(
                f"clipboardData.{name}",
                node,
                access,
                callee=callee,
                assigned_to=sx.assigned_to(node),
                args=self.args_info(args),
            )
            return
        # tasks 13-14: storage and cookieStore methods
        if n == 2 and path[0] in STORAGE and name in {**STORAGE_READ, **STORAGE_WRITE}:
            access = STORAGE_READ.get(name) or STORAGE_WRITE[name]
            self.emit(
                path[0],
                node,
                access,
                callee=callee,
                member=name,
                assigned_to=sx.assigned_to(node) if access == "read" else None,
                args=self.args_info(args),
            )
            return
        if n == 2 and path[0] == "cookieStore" and name in ("get", "getAll", "set", "delete"):
            access = "read" if name.startswith("get") else "write"
            self.emit("cookieStore", node, access, callee=callee, member=name)
            return
        # listeners (addEventListener, jQuery .on / shorthand)
        if name == "addEventListener" or (name in ("on", "one", "bind") and n >= 2):
            events = (sx.string_value(first) or "").lower().split()
            selector, target = self.receiver_label(receiver, path)
            for event in events:
                api = self.listener_events.get(event)
                if api:
                    self.emit(
                        api,
                        node,
                        "listener",
                        callee=callee,
                        event_type=event,
                        selector=selector,
                        target=target,
                    )
            return
        if (
            name in JQUERY_SHORTHAND
            and n >= 2
            and first is not None
            and first.type in sx.FUNCTION_TYPES
        ):
            api = self.listener_events.get(name)
            if api:
                selector, target = self.receiver_label(receiver, path)
                self.emit(
                    api,
                    node,
                    "listener",
                    callee=callee,
                    event_type=name,
                    selector=selector,
                    target=target,
                )
            return
        # setAttribute: action / download / srcdoc / http-equiv refresh
        if name == "setAttribute" and len(args) >= 2:
            attribute = (sx.string_value(first) or "").lower()
            selector, target = self.receiver_label(receiver, path)
            if attribute == "action":
                self.emit(
                    "form.action",
                    node,
                    "assign",
                    callee=callee,
                    member="action",
                    selector=selector,
                    target=target,
                    args=self.args_info(args[1:], url_node=args[1]),
                )
            elif attribute == "download":
                self.emit("download_attribute", node, "assign", callee=callee, target=target)
            elif attribute == "srcdoc":
                self.emit("srcdoc", node, "assign", callee=callee, args=self.args_info(args[1:]))
            elif attribute == "http-equiv" and (sx.string_value(args[1]) or "").lower() == (
                "refresh"
            ):
                self.emit("meta_refresh", node, "assign", callee=callee, target=target)
            return
        # input values through jQuery: $("#pass").val()
        if name == "val" and n >= 2 and not args:
            selector, target = self.receiver_label(receiver, path)
            assigned = sx.assigned_to(node)
            self.emit(
                "input.value",
                node,
                "read",
                callee=callee,
                member="val",
                selector=selector,
                target=target,
                assigned_to=assigned,
                credential="auto",
                receiver_text=sx.text(receiver, 80) if receiver is not None else None,
            )
            return
        # decoders and downloads
        if path in (["atob"], ["unescape"], ["decodeURIComponent"], ["decodeURI"]):
            self.emit(
                path[0],
                node,
                "call",
                callee=callee,
                assigned_to=sx.assigned_to(node),
                args=self.args_info(args),
            )
            return
        if path[:2] == ["String", "fromCharCode"]:
            self.emit(
                "String.fromCharCode",
                node,
                "call",
                callee=callee,
                assigned_to=sx.assigned_to(node),
                args=self.args_info(args),
            )
            return
        if path in (["URL", "createObjectURL"], ["webkitURL", "createObjectURL"]):
            self.emit("URL.createObjectURL", node, "call", callee=callee)
            return
        if path in (["navigator", "msSaveBlob"], ["navigator", "msSaveOrOpenBlob"]):
            self.emit("msSaveBlob", node, "call", callee=callee, member=name)
            return

    # ---- new -------------------------------------------------------------------------

    def on_new(self, node: Any) -> None:
        constructor = sx.field(node, "constructor")
        if constructor is None:
            return
        path, _ = self.path(constructor)
        args = sx.named_args(node)
        first = args[0] if args else None
        callee = "new " + sx.fmt_path(path)
        if path == ["XMLHttpRequest"] or (
            path == ["ActiveXObject"] and "xmlhttp" in (sx.string_value(first) or "").lower()
        ):
            self.emit(
                "XMLHttpRequest", node, "construct", callee=callee, assigned_to=sx.assigned_to(node)
            )
        elif path in (["WebSocket"], ["EventSource"]):
            self.emit(
                path[0],
                node,
                "construct",
                callee=callee,
                assigned_to=sx.assigned_to(node),
                args=self.args_info(args, url_node=first),
            )
        elif path == ["Function"]:
            self.emit("Function", node, "construct", callee=callee, args=self.args_info(args))
        elif path == ["FormData"]:
            selector = sx.selector_of(first) if first is not None else None
            self.emit(
                "FormData",
                node,
                "construct",
                callee=callee,
                selector=selector,
                assigned_to=sx.assigned_to(node),
                args=self.args_info(args),
            )
        elif path == ["Blob"]:
            self.emit("Blob", node, "construct", callee=callee, assigned_to=sx.assigned_to(node))

    # ---- assignments -----------------------------------------------------------------

    def object_marker(self, value: Any | None) -> list[str] | None:
        """What a variable now refers to, for alias tracking (None = nothing we track)."""
        if value is None:
            return None
        value, _ = sx.unwrap(value)
        if value is None:
            return None
        if value.type == "new_expression":
            constructor = sx.field(value, "constructor")
            name = sx.text(constructor, 40) if constructor is not None else ""
            name = name.rsplit(".", 1)[-1]
            return {"XMLHttpRequest": [XHR], "Image": [IMAGE], "WebSocket": [SOCKET]}.get(name)
        if value.type == "call_expression":
            function = sx.field(value, "function")
            path, _ = self.path(function) if function is not None else (["?"], None)
            if path == ["document", "createElement"]:
                args = sx.named_args(value)
                tag = (sx.string_value(args[0]) or "").lower() if args else ""
                return {"img": [IMAGE], "a": [ANCHOR], "meta": [META]}.get(tag)
            if path and path[-1] in sx.SELECTOR_FUNCTIONS:
                selector = sx.selector_of(value)
                return [ELEMENT.format(selector)] if selector else None
            return None
        if value.type in ("identifier", "member_expression", "subscript_expression"):
            path, _ = self.path(value)
            if len(path) >= 2 and path[-2] == "forms":
                selector = sx.selector_of(value)
                return [ELEMENT.format(selector)] if selector else None
            if path in (["eval"], ["localStorage"], ["sessionStorage"], ["location"], ["document"]):
                return path
            if path in (["navigator", "clipboard"], ["history"], ["navigator"]):
                return path
            if len(path) == 1 and (
                path[0] in (XHR, IMAGE, ANCHOR, META, SOCKET) or path[0].startswith("<el ")
            ):
                return path
        return None

    def on_declarator(self, node: Any) -> None:
        name = sx.field(node, "name")
        if name is None or name.type != "identifier":
            return
        marker = self.object_marker(sx.field(node, "value"))
        if marker is not None:
            self.aliases[sx.text(name, 60)] = marker

    def on_assign(self, node: Any) -> None:
        left = sx.field(node, "left")
        right = sx.field(node, "right")
        if left is None:
            return
        callee = sx.fmt_path(sx.raw_path(left) or ["?"])
        if left.type == "identifier":
            target = sx.text(left, 60)
            marker = self.object_marker(right)
            if marker is not None:
                self.aliases[target] = marker
            if target == "location" and node.type == "assignment_expression":
                self.emit(
                    "location.href",
                    node,
                    "assign",
                    callee=callee,
                    member="location",
                    args=self.args_info([right] if right else [], url_node=right),
                )
            elif target.startswith("on") and target[2:].lower() in self.listener_events:
                event = target[2:].lower()
                self.emit(
                    self.listener_events[event],
                    node,
                    "listener",
                    callee=callee,
                    event_type=event,
                    target="window",
                )
            return
        if left.type not in ("member_expression", "subscript_expression"):
            return
        path, frame = self.path(left)
        name = path[-1]
        receiver = sx.field(left, "object")
        values = [right] if right is not None else []
        n = len(path)
        if name in ("innerHTML", "outerHTML") and n >= 2:
            selector, target = self.receiver_label(receiver, path)
            self.emit(
                name,
                node,
                "assign",
                callee=callee,
                member=name,
                selector=selector,
                target=target,
                args=self.args_info(values),
            )
        elif name == "srcdoc" and n >= 2:
            self.emit("srcdoc", node, "assign", callee=callee, args=self.args_info(values))
        elif path in (["location"], ["location", "href"]) and node.type == "assignment_expression":
            self.emit(
                "location.href",
                node,
                "assign",
                callee=callee,
                member=name,
                target=frame,
                args=self.args_info(values, url_node=right),
            )
        elif path == ["document", "cookie"]:
            self.emit("document.cookie", node, "write", callee=callee, args=self.args_info(values))
        elif n == 2 and path[0] in STORAGE:
            member = None if name == "[]" else name
            self.emit(
                path[0], node, "write", callee=callee, member=member, args=self.args_info(values)
            )
        elif name == "action" and n >= 2 and node.type == "assignment_expression":
            selector, target = self.receiver_label(receiver, path)
            self.emit(
                "form.action",
                node,
                "assign",
                callee=callee,
                member="action",
                selector=selector,
                target=target,
                args=self.args_info(values, url_node=right),
            )
        elif name == "src" and n >= 2 and node.type == "assignment_expression":
            # an image whose URL carries data: new Image().src = "https://x/c?d=" + v
            # (a plain img.src = "/logo.png" preload is not a beacon)
            literal, concatenated = sx.literal_prefix(right)
            imageish = path[-2].startswith("new Image") or path[-2] == IMAGE
            imageish = imageish or bool(IMAGE_NAMES.search(path[-2]))
            if imageish and (concatenated or (literal is not None and "?" in literal)):
                self.emit(
                    "image_beacon",
                    node,
                    "assign",
                    callee=callee,
                    member="src",
                    target=path[-2] if path[-2] not in (IMAGE,) else "new Image()",
                    args=self.args_info(values, url_node=right, method="GET"),
                )
        elif name == "download" and n >= 2:
            self.emit("download_attribute", node, "assign", callee=callee, member="download")
        elif name == "httpEquiv" and (sx.string_value(right) or "").lower() == "refresh":
            self.emit("meta_refresh", node, "assign", callee=callee, member="httpEquiv")
        elif name.startswith("on") and name[2:].lower() in self.listener_events:
            # window.onbeforeunload -> path ["onbeforeunload"] (the global object is dropped)
            event = name[2:].lower()
            selector, target = self.receiver_label(receiver, path)
            target = target or "window"
            self.emit(
                self.listener_events[event],
                node,
                "listener",
                callee=callee,
                event_type=event,
                selector=selector,
                target=target,
            )

    # ---- reads ---------------------------------------------------------------------

    def _role(self, node: Any) -> str:
        """How the parent uses this node: call target, assignment target, constructor, other."""
        parent = node.parent
        if parent is None:
            return "other"
        kind = parent.type
        if kind == "call_expression" and sx.field(parent, "function") == node:
            return "call"
        if kind in ("assignment_expression", "augmented_assignment_expression"):
            if sx.field(parent, "left") == node:
                return "assign"
        if kind == "new_expression" and sx.field(parent, "constructor") == node:
            return "call"
        if kind in ("update_expression", "unary_expression") and sx.text(parent, 7).startswith(
            "delete"
        ):
            return "assign"
        return "other"

    def on_member(self, node: Any) -> None:
        obj = sx.field(node, "object")
        if node.type == "member_expression":
            prop = sx.field(node, "property")
            prop_name = sx.text(prop, 40) if prop is not None else ""
        else:
            prop_name = "[]"
        # cheap filter first: most member expressions are not interesting
        if prop_name not in READ_PROPERTIES:
            if obj is None:
                return
            if obj.type == "identifier":
                name = sx.text(obj, 40)
                if name not in STORAGE and name not in self.aliases:
                    return
            elif obj.type == "member_expression":
                inner = sx.field(obj, "property")
                if inner is None or sx.text(inner, 40) not in STORAGE:
                    return
            else:
                return
        if self._role(node) != "other":
            return
        path, _ = self.path(node)
        n = len(path)
        if path == ["document", "cookie"]:
            self.emit(
                "document.cookie",
                node,
                "read",
                callee=sx.fmt_path(path),
                assigned_to=sx.assigned_to(node),
            )
        elif n == 2 and path[0] in STORAGE:
            member = None if path[1] == "[]" else path[1]
            if member in STORAGE_WRITE:
                return  # a method reference (localStorage.setItem.bind ...) - not a read
            self.emit(
                path[0],
                node,
                "read",
                callee=sx.fmt_path(path),
                member=member,
                assigned_to=sx.assigned_to(node),
            )
        elif path in (["location", "search"], ["location", "hash"], ["document", "referrer"]):
            self.emit(
                "location_read",
                node,
                "read",
                callee=sx.fmt_path(path),
                member=path[-1],
                assigned_to=sx.assigned_to(node),
            )
        elif prop_name == "value" and n >= 2:
            if n >= 3 and path[-2] == sx.CALL and path[-3] == "next":
                return  # iterator.next().value is not an input
            selector, target = self.receiver_label(obj, path)
            assigned = sx.assigned_to(node)
            receiver_text = sx.text(obj, 80) if obj is not None else None
            credential = sx.looks_like_credential(
                self.credential_words, selector, receiver_text, assigned
            )
            element = selector is not None or any(s in DOM_RECEIVERS for s in path[:-1])
            element = element or (self.source == "event_handler" and path[0] == "this")
            if not (element or credential):
                return
            self.emit(
                "input.value",
                node,
                "read",
                callee=sx.fmt_path(path),
                member="value",
                selector=selector,
                target=target,
                assigned_to=assigned,
                credential=credential,
            )

    # ---- strings, identifiers, arrays (obfuscation statistics) -------------------------

    def on_string(self, node: Any) -> None:
        length = node.end_byte - node.start_byte - 2
        self.obfuscation.string(length)
        if length < 20:
            return
        # escapes that HIDE plain ASCII ("eval" = "eval"); "ا..." (Arabic)
        # or "/" (an escaped slash) is just how JSON writes normal text
        escapes = escaped = hidden = 0
        for child in node.named_children:
            if child.type == "escape_sequence":
                escapes += 1
                escaped += child.end_byte - child.start_byte
                char = sx.decode_escape(sx.text(child, 12))
                if len(char) == 1 and char.isascii() and (char.isalnum() or char == " "):
                    hidden += 1
        if escapes >= 8 and escaped >= 0.5 * length and hidden >= 0.6 * escapes:
            self.emit(
                "escape_heavy_string",
                node,
                "read",
                assigned_to=sx.assigned_to(node),
                args=DetectionArgs(first_arg_kind="string_literal", literal_value=None),
            )

    def on_identifier(self, node: Any) -> None:
        self.obfuscation.identifier(self.src[node.start_byte : node.end_byte])

    def on_array(self, node: Any) -> None:
        count = node.named_child_count
        if count < 30:
            return
        strings = sum(1 for child in node.named_children if child.type == "string")
        if strings >= 0.9 * count:
            self.obfuscation.string_array(strings)
