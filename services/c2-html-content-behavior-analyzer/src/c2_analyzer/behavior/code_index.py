"""Re-parse the page's own scripts with Part 7's parser and index what Part 8 needs.

Part 8: Behavioral intent mapping (sources -> sinks).

Part 8 does not parse JavaScript itself and does not detect APIs a second
time. For every script Part 7 analysed it:
1. takes the same code unit (Part 7's ``collect_scripts``, same order = same
   ``script_index``) and re-parses it with Part 7's ``parse_js`` under the same
   limits - the result is the same tree, so Part 7's byte ranges point at the
   same nodes;
2. maps every Part 7 detection back to its AST node (``node_of``);
3. walks the tree ONCE (iterative, Part 7's ``AstWalker``) to index what the
   taint analysis and the patterns need and Part 7 does not store:
   - scopes: names declared per function (parameters, var / let / const,
     function declarations). Block scopes are not modelled (``let`` in a block
     counts for the whole function) - a documented simplification;
   - functions (name, parameters) and every place a name is used (call,
     callback argument, ``x.onclick = f``) - for parameter passing and for
     "who triggers this code" (triggers.py);
   - string constants (``var api = "https://api.telegram.org/bot" + t``) so a
     sink whose URL is a variable still gets a destination;
   - small things for the patterns: preventDefault(), ``debugger``,
     ``.click()``, ``.href = "...exe"``, pushState / popstate,
     outerWidth - innerWidth checks, event.key style reads.
Library scripts (Part 7 ``library``) are not indexed: patterns ignore them.
Scripts Part 7 could only scan with regexes ("lexical") have no tree; Part 8
uses their detections as low-confidence evidence only.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from c2_analyzer.js_analyzer import syntax as sx
from c2_analyzer.js_analyzer.ast_parser import parse_js
from c2_analyzer.js_analyzer.detectors import PageUrls, ScriptDetector
from c2_analyzer.js_analyzer.extractor import CodeUnit
from c2_analyzer.js_analyzer.lexical_scanner import scan
from c2_analyzer.js_analyzer.rules import Rules
from c2_analyzer.js_analyzer.visitor import AstWalker
from c2_analyzer.schemas.js import Detection, ScriptInfo

GLOBAL = ("global",)  # the page-wide scope shared by all scripts and handlers
NodeKey = tuple[int, int, int, str]  # (script_index, start_byte, end_byte, node type)
MAX_PARENT_CLIMB = 400
MAX_CONSTS_PER_NAME = 5
INDEX_TYPES = frozenset(
    {
        *sx.FUNCTION_TYPES,
        "variable_declarator",
        "assignment_expression",
        "augmented_assignment_expression",
        "call_expression",
        "member_expression",
        "return_statement",
        "debugger_statement",
        "binary_expression",
        "string",
        "template_string",
    }
)
LISTENER_METHODS = frozenset({"addEventListener", "on", "one", "bind", "live", "delegate"})
JQUERY_EVENT_METHODS = frozenset(
    {
        "click",
        "dblclick",
        "submit",
        "change",
        "keydown",
        "keyup",
        "keypress",
        "input",
        "mousedown",
        "mouseup",
        "ready",
        "load",
        "contextmenu",
        "copy",
        "cut",
        "paste",
        "focus",
        "blur",
        "scroll",
        "resize",
        "hover",
        "mouseover",
        "mouseenter",
    }
)


def node_key(script: int, node: Any) -> NodeKey:
    return (script, node.start_byte, node.end_byte, node.type)


def pattern_names(node: Any | None) -> list[str]:
    """Identifiers bound by a declaration target: ``a``, ``{a, b: c}``, ``[a, ...b]``."""
    if node is None:
        return []
    if node.type in ("identifier", "shorthand_property_identifier_pattern"):
        return [sx.text(node, 60)]
    names: list[str] = []
    stack = [node]
    seen = 0
    while stack and seen < 200:
        current = stack.pop()
        seen += 1
        kind = current.type
        if kind in ("identifier", "shorthand_property_identifier_pattern"):
            names.append(sx.text(current, 60))
            continue
        if kind == "pair_pattern":
            value = sx.field(current, "value")
            if value is not None:
                stack.append(value)
            continue
        if kind == "assignment_pattern":
            left = sx.field(current, "left")
            if left is not None:
                stack.append(left)
            continue
        if kind in ("object_pattern", "array_pattern", "rest_pattern"):
            stack.extend(reversed(current.named_children))
    return names


def parameters(function: Any) -> list[list[str]]:
    """Parameter names by position (a destructured parameter binds several names)."""
    single = sx.field(function, "parameter")  # x => ...
    if single is not None:
        return [pattern_names(single)]
    params = sx.field(function, "parameters")
    if params is None:
        return []
    return [pattern_names(child) for child in params.named_children if child.type != "comment"]


@dataclass
class FunctionInfo:
    key: NodeKey
    node: Any
    script: int
    name: str | None  # declared / assigned name (``function f``, ``var f = ...``, ``window.f =``)
    params: list[list[str]]


@dataclass
class Use:
    """A place a function name is used: called, passed as a callback or set as a handler."""

    script: int
    node: Any  # the call (kind "call") / the identifier argument / the assignment
    kind: str  # call | callback | handler


@dataclass
class ScriptCtx:
    """One page-own script: its unit, tree (or None) and the index built from it."""

    index: int
    info: ScriptInfo
    unit: CodeUnit
    tree: Any | None
    src: bytes
    detections: list[Detection]
    node_of: dict[int, Any] = field(default_factory=dict)  # position in detections -> node
    declared: dict[Any, set[str]] = field(default_factory=lambda: defaultdict(set))
    functions: dict[NodeKey, FunctionInfo] = field(default_factory=dict)
    consts: dict[tuple, list[tuple[str, bool]]] = field(default_factory=dict)
    prevent_default: set[NodeKey] = field(default_factory=set)  # functions calling it
    listeners: dict[NodeKey, tuple[str, str | None]] = field(default_factory=dict)
    member_reads: list[tuple[Any, list[str]]] = field(default_factory=list)  # (node, path)
    event_reads: list[tuple[Any, str, str]] = field(default_factory=list)  # (node, object, prop)
    calls: dict[str, list[Any]] = field(default_factory=lambda: defaultdict(list))
    href_assigns: list[tuple[Any, str]] = field(default_factory=list)
    debugger_nodes: list[Any] = field(default_factory=list)
    devtools_checks: list[Any] = field(default_factory=list)
    strings: list[tuple[Any, str]] = field(default_factory=list)  # long-ish literal values
    depth_capped: bool = False
    _function_of: dict[NodeKey, Any] = field(default_factory=dict)

    @property
    def lexical(self) -> bool:
        return self.tree is None

    def key(self, node: Any) -> NodeKey:
        return node_key(self.index, node)

    def function_of(self, node: Any) -> Any | None:
        """The nearest enclosing function node (None = top level of the script)."""
        key = self.key(node)
        if key in self._function_of:
            return self._function_of[key]
        current = node.parent
        found = None
        for _ in range(MAX_PARENT_CLIMB):
            if current is None:
                break
            if current.type in sx.FUNCTION_TYPES:
                found = current
                break
            current = current.parent
        self._function_of[key] = found
        return found

    def function_chain(self, node: Any) -> list[Any]:
        """Enclosing functions, innermost first."""
        chain = []
        current = self.function_of(node)
        while current is not None and len(chain) < 50:
            chain.append(current)
            current = self.function_of(current)
        return chain

    def scope_of(self, node: Any) -> Any:
        function = self.function_of(node)
        return GLOBAL if function is None else self.key(function)

    def resolve(self, name: str, node: Any) -> tuple:
        """(scope, name) the identifier refers to: the innermost function declaring it,
        else the page-wide global scope."""
        for function in self.function_chain(node):
            key = self.key(function)
            if name in self.declared.get(key, ()):
                return (key, name)
        return (GLOBAL, name)

    def code(self, node: Any, limit: int = 120) -> str:
        from c2_analyzer.js_analyzer.detectors import safe_snippet

        return safe_snippet(sx.text(node, limit * 3), limit)

    def position(self, node: Any) -> tuple[int, int]:
        """(line, column) 1-based, column in characters (like Part 7)."""
        row, column_bytes = node.start_point
        line_start = node.start_byte - column_bytes
        column = len(self.src[line_start : node.start_byte].decode("utf-8", errors="replace"))
        return row + 1, column + 1

    def const_values(self, scope_name: tuple) -> list[tuple[str, bool]]:
        return self.consts.get(scope_name, [])


def find_node(tree: Any, detection: Detection) -> Any | None:
    """The AST node a Part 7 detection was emitted for (same byte range and type)."""
    root = tree.root_node
    try:
        node = root.descendant_for_byte_range(detection.start_byte, detection.end_byte)
    except (ValueError, TypeError):
        return None
    fallback = None
    for _ in range(MAX_PARENT_CLIMB):
        if node is None:
            break
        if node.start_byte == detection.start_byte and node.end_byte == detection.end_byte:
            if node.type == detection.node_type:
                return node
            fallback = fallback or node
        elif node.start_byte < detection.start_byte or node.end_byte > detection.end_byte:
            break
        node = node.parent
    return fallback


def _function_name(function: Any, global_aliases: frozenset[str]) -> str | None:
    """``function f`` / ``var f = function`` / ``f = () => ...`` / ``window.f = ...`` -> "f"."""
    own = sx.field(function, "name")
    if own is not None and function.type == "function_declaration":
        return sx.text(own, 60)
    parent = function.parent
    while parent is not None and parent.type == "parenthesized_expression":
        parent = parent.parent
    if parent is not None and parent.type == "variable_declarator":
        target = sx.field(parent, "name")
        if target is not None and target.type == "identifier":
            return sx.text(target, 60)
    if parent is not None and parent.type == "assignment_expression":
        left = sx.field(parent, "left")
        if left is not None and left.type == "identifier":
            return sx.text(left, 60)
        if left is not None:
            path, _ = sx.normalize(sx.raw_path(left) or ["?"], global_aliases)
            if len(path) == 1:
                return path[0]
    if own is not None and function.type == "function_expression":
        return sx.text(own, 60)
    return None


class Indexer:
    """Builds a ScriptCtx for every page-own script."""

    def __init__(
        self,
        rules: Rules,
        urls: PageUrls,
        event_properties: frozenset[str],
        watched_paths: frozenset[str],
    ) -> None:
        self.rules = rules
        self.urls = urls
        self.event_properties = event_properties
        self.watched_paths = watched_paths  # "navigator.userAgent", "location.href", ...
        self.watched_last = frozenset(path.rsplit(".", 1)[-1] for path in watched_paths)
        self.global_aliases = frozenset(rules.lists.get("global_aliases") or [])

    # ---- building ---------------------------------------------------------------------

    def build(
        self, index: int, info: ScriptInfo, unit: CodeUnit, detections: list[Detection]
    ) -> ScriptCtx:
        limits = self.rules.limits
        tree, src = None, unit.text.encode("utf-8", errors="replace")
        if info.parser == "tree-sitter":
            outcome = parse_js(
                unit.text,
                max_bytes=int(limits["max_script_bytes"]),
                timeout_ms=int(limits["parse_timeout_ms"]),
                max_error_ratio=float(limits["max_error_ratio"]),
            )
            if outcome.usable and outcome.tree is not None:
                tree, src = outcome.tree, outcome.source
        ctx = ScriptCtx(index=index, info=info, unit=unit, tree=tree, src=src, detections=[])
        if tree is None:
            if info.parser == "tree-sitter" or detections is None:
                # Part 7 had a tree and the re-parse did not, or its list was cut: scan again
                detections = scan(unit.text, self.rules, index, unit.source, self.urls)
            ctx.detections = detections
            return ctx
        if detections is None:  # Part 7's stored list was cut: detect this script again
            detector = ScriptDetector(self.rules, index, unit.source, src, self.urls)
            detections = detector.run(tree, int(limits["max_ast_depth"]))
        ctx.detections = detections
        for position, detection in enumerate(detections):
            if detection.node_type is None:
                continue
            node = find_node(tree, detection)
            if node is not None:
                ctx.node_of[position] = node
        self._index(ctx)
        return ctx

    def _index(self, ctx: ScriptCtx) -> None:
        walker = AstWalker(INDEX_TYPES, int(self.rules.limits["max_ast_depth"]))
        declarators, assignments = [], []
        for node, _ in walker.walk(ctx.tree.root_node):
            kind = node.type
            if kind in sx.FUNCTION_TYPES:
                self._on_function(ctx, node)
            elif kind == "variable_declarator":
                declarators.append(node)
                scope = ctx.scope_of(node)
                ctx.declared[scope].update(pattern_names(sx.field(node, "name")))
            elif kind in ("assignment_expression", "augmented_assignment_expression"):
                assignments.append(node)
                self._on_assign(ctx, node)
            elif kind == "call_expression":
                self._on_call(ctx, node)
            elif kind == "member_expression":
                self._on_member(ctx, node)
            elif kind == "return_statement":
                value = node.named_children[0] if node.named_child_count else None
                if value is not None and value.type == "false":
                    function = ctx.function_of(node)
                    if function is not None:
                        ctx.prevent_default.add(ctx.key(function))
            elif kind == "debugger_statement":
                ctx.debugger_nodes.append(node)
            elif kind == "binary_expression":
                self._on_binary(ctx, node)
            elif kind in ("string", "template_string"):
                value, _ = sx.literal_prefix(node)
                if value and len(value) >= 8 and len(ctx.strings) < 2000:
                    ctx.strings.append((node, value[:2000]))
        ctx.depth_capped = walker.depth_capped
        # constants need the declarations of the whole script first
        for node in declarators:
            name = sx.field(node, "name")
            if name is not None and name.type == "identifier":
                self._const(ctx, ctx.resolve(sx.text(name, 60), node), sx.field(node, "value"))
        for node in assignments:
            left = sx.field(node, "left")
            if (
                left is not None
                and left.type == "identifier"
                and node.type == "assignment_expression"
            ):
                self._const(ctx, ctx.resolve(sx.text(left, 60), node), sx.field(node, "right"))

    def _const(self, ctx: ScriptCtx, target: tuple, value: Any | None) -> None:
        if value is None:
            return
        literal, concatenated = sx.literal_prefix(value)
        if literal is None:
            return
        values = ctx.consts.setdefault(target, [])
        if (literal, concatenated) not in values and len(values) < MAX_CONSTS_PER_NAME:
            values.append((literal[:2000], concatenated))

    def _on_function(self, ctx: ScriptCtx, node: Any) -> None:
        key = ctx.key(node)
        params = parameters(node)
        for names in params:
            ctx.declared[key].update(names)
        name = _function_name(node, self.global_aliases)
        if node.type == "function_declaration" and name:
            ctx.declared[ctx.scope_of(node)].add(name)
        ctx.functions[key] = FunctionInfo(key, node, ctx.index, name, params)

    def _on_assign(self, ctx: ScriptCtx, node: Any) -> None:
        left, right = sx.field(node, "left"), sx.field(node, "right")
        if left is None or right is None or left.type not in ("member_expression",):
            return
        prop = sx.field(left, "property")
        name = sx.text(prop, 40) if prop is not None else ""
        if name == "href":
            path, _ = sx.normalize(sx.raw_path(left) or ["?"], self.global_aliases)
            if path[:1] != ["location"]:
                literal, _ = sx.literal_prefix(right)
                if literal:
                    ctx.href_assigns.append((node, literal))
        if name.startswith("on") and right.type in sx.FUNCTION_TYPES:
            ctx.listeners[ctx.key(right)] = (name[2:].lower(), sx.selector_of(left))
        if name in ("onselectstart", "ondragstart"):
            ctx.calls["selection"].append(node)
        if name == "onpopstate":
            ctx.calls["popstate"].append(node)

    def _on_call(self, ctx: ScriptCtx, node: Any) -> None:
        function = sx.field(node, "function")
        if function is None:
            return
        path, _ = sx.normalize(sx.raw_path(function) or ["?"], self.global_aliases)
        name = path[-1]
        args = sx.named_args(node)
        if name == "preventDefault":
            enclosing = ctx.function_of(node)
            if enclosing is not None:
                ctx.prevent_default.add(ctx.key(enclosing))
        elif name in ("serialize", "serializeArray") and len(path) >= 2:
            ctx.calls["serialize"].append(node)
        elif name == "send" and len(path) == 2:
            ctx.calls["send"].append(node)
        elif name in ("pushState", "replaceState") and path[:1] == ["history"]:
            ctx.calls["history"].append(node)
        elif name == "click" and not args and len(path) >= 2:
            ctx.calls["click"].append(node)
        elif name in ("getTimezoneOffset", "resolvedOptions"):
            ctx.calls["fingerprint"].append(node)
        elif name == "toString" and path[:1] == ["location"]:
            ctx.calls["location_string"].append(node)
        # listener registrations: function callbacks -> (event, selector)
        event = None
        if name in LISTENER_METHODS and args:
            event = (sx.string_value(args[0]) or "").lower().split()
            event = event[0] if event else None
        elif name in JQUERY_EVENT_METHODS and len(path) >= 2:
            event = name
        elif path in (["$"], ["jQuery"]) and args and args[0].type in sx.FUNCTION_TYPES:
            ctx.listeners[ctx.key(args[0])] = ("ready", None)
        if event:
            receiver = (
                sx.field(function, "object") if function.type == "member_expression" else None
            )
            selector = sx.selector_of(receiver) if receiver is not None else None
            if selector is None and receiver is not None:
                selector = sx.text(receiver, 60)
            for arg in args:
                if arg.type in sx.FUNCTION_TYPES:
                    ctx.listeners[ctx.key(arg)] = (event, selector)
            if event in ("popstate",):
                ctx.calls["popstate"].append(node)
            if event in ("selectstart", "dragstart"):
                ctx.calls["selection"].append(node)

    def _on_member(self, ctx: ScriptCtx, node: Any) -> None:
        prop = sx.field(node, "property")
        obj = sx.field(node, "object")
        if prop is None or obj is None:
            return
        name = sx.text(prop, 40)
        parent = node.parent
        # assignment targets and called methods are not reads
        if parent is not None:
            if parent.type in ("assignment_expression", "augmented_assignment_expression"):
                if sx.field(parent, "left") == node:
                    return
            if parent.type == "call_expression" and sx.field(parent, "function") == node:
                return
        if name in self.event_properties:
            if obj.type == "identifier":
                ctx.event_reads.append((node, sx.text(obj, 60), name))
            elif obj.type == "member_expression":  # window.event.keyCode
                inner = sx.field(obj, "property")
                if inner is not None and sx.text(inner, 20) == "event":
                    ctx.event_reads.append((node, "event", name))
        if name in self.watched_last:
            path, _ = sx.normalize(sx.raw_path(node) or ["?"], self.global_aliases)
            if sx.fmt_path(path) in self.watched_paths:
                ctx.member_reads.append((node, path))

    def _on_binary(self, ctx: ScriptCtx, node: Any) -> None:
        operator = sx.field(node, "operator")
        if operator is None or sx.text(operator) != "-":
            return
        value = sx.text(node, 200)
        if ("outerWidth" in value and "innerWidth" in value) or (
            "outerHeight" in value and "innerHeight" in value
        ):
            ctx.devtools_checks.append(node)


def page_uses(contexts: list[ScriptCtx]) -> dict[str, list[Use]]:
    """Every place a name is called, passed as a callback or set as a handler (all scripts)."""
    uses: dict[str, list[Use]] = defaultdict(list)
    for ctx in contexts:
        if ctx.tree is None:
            continue
        walker = AstWalker(frozenset({"call_expression", "assignment_expression"}), 1500)
        for node, _ in walker.walk(ctx.tree.root_node):
            if node.type == "call_expression":
                function = sx.field(node, "function")
                if function is not None:
                    path = sx.raw_path(function) or []
                    while len(path) > 1 and path[0] in ("window", "self", "globalThis", "top"):
                        path = path[1:]
                    if len(path) == 1 and function.type in ("identifier", "member_expression"):
                        uses[path[0]].append(Use(ctx.index, node, "call"))
                for arg in sx.named_args(node):
                    if arg.type == "identifier":
                        uses[sx.text(arg, 60)].append(Use(ctx.index, arg, "callback"))
            else:
                right = sx.field(node, "right")
                left = sx.field(node, "left")
                if right is not None and right.type == "identifier" and left is not None:
                    prop = sx.field(left, "property") if left.type == "member_expression" else left
                    if prop is not None and sx.text(prop, 40).startswith("on"):
                        uses[sx.text(right, 60)].append(Use(ctx.index, node, "handler"))
    return uses


def functions_by_name(contexts: list[ScriptCtx]) -> dict[str, list[FunctionInfo]]:
    """Page-wide function registry (functions are matched by NAME, across scripts)."""
    registry: dict[str, list[FunctionInfo]] = defaultdict(list)
    for ctx in contexts:
        for info in ctx.functions.values():
            if info.name:
                registry[info.name].append(info)
    return registry
