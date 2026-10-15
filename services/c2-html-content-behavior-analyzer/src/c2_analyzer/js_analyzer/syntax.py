"""Small helpers that read meaning out of tree-sitter nodes (shared by the detectors).

Part 7: Static JavaScript intent analyzer.

Why aliases matter: attackers rarely write ``eval(x)``. They write
``window["ev" + "al"]``, ``self['eval']``, ``(0, eval)(x)``, ``var e = eval;
e(x)`` or ``top.location.href = url`` - exactly to slip past simple text
searches. ``callee_path`` turns all of these into one normalized path
(``["eval"]``, ``["location", "href"]``):
- member access ``a.b`` and bracket access with a literal ``a["b"]`` both
  become segments ``a``, ``b`` (a non-literal index becomes ``[]``);
- ``(0, eval)`` - a parenthesized comma expression - is its last element;
- a leading global object (window, self, globalThis, top, parent, frames) is
  dropped, ``document.location`` is ``location``;
- simple aliases recorded earlier in the same script (``var s =
  window.localStorage``) are substituted.
Everything is iterative and capped (a hostile ``a.b.c.d...`` chain cannot
blow the stack).
"""

from __future__ import annotations

import re
from typing import Any

MAX_SEGMENTS = 16
CALL = "()"
FUNCTION_TYPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "function",
        "arrow_function",
        "method_definition",
        "generator_function_declaration",
        "generator_function",
    }
)
ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z])(?=[A-Z])")


def text(node: Any, limit: int | None = None) -> str:
    """The node's source text (decoded; optionally cut)."""
    raw = node.text or b""
    if limit is not None:
        raw = raw[: limit * 4]
    value = raw.decode("utf-8", errors="replace")
    return value[:limit] if limit is not None else value


def field(node: Any, name: str) -> Any | None:
    return node.child_by_field_name(name)


def named_args(call: Any) -> list[Any]:
    """The argument nodes of a call / new expression (comments skipped)."""
    arguments = field(call, "arguments")
    if arguments is None or arguments.type != "arguments":
        return []
    return [child for child in arguments.named_children if child.type != "comment"]


def decode_escape(sequence: str) -> str:
    """One JavaScript escape sequence -> its character (best effort)."""
    body = sequence[1:]
    try:
        if body.startswith("x") and len(body) == 3:
            return chr(int(body[1:], 16))
        if body.startswith("u{"):
            return chr(int(body[2:-1], 16))
        if body.startswith("u") and len(body) == 5:
            return chr(int(body[1:], 16))
    except ValueError:
        return sequence
    if body and body[0] in ESCAPES and len(body) == 1:
        return ESCAPES[body[0]]
    return body[:1] if body[:1] not in ("\n", "\r") else ""


def string_value(node: Any) -> str | None:
    """Value of a string literal or a template without ${...}; None for anything else."""
    if node is None:
        return None
    if node.type == "string":
        parts = []
        for child in node.named_children:
            if child.type == "string_fragment":
                parts.append(text(child))
            elif child.type == "escape_sequence":
                parts.append(decode_escape(text(child)))
        return "".join(parts)
    if node.type == "template_string":
        parts = []
        for child in node.named_children:
            if child.type == "template_substitution":
                return None
            if child.type == "string_fragment":
                parts.append(text(child))
            elif child.type == "escape_sequence":
                parts.append(decode_escape(text(child)))
        return "".join(parts)
    return None


def literal_prefix(node: Any) -> tuple[str | None, bool]:
    """(literal text, concatenated) for a string, a template or a "..." + x chain.

    ``"https://x.test/?p=" + pwd`` -> ("https://x.test/?p=", True): the leading
    literal is enough to know where the data goes.
    """
    if node is None:
        return None, False
    value = string_value(node)
    if value is not None:
        return value, False
    if node.type == "template_string":
        lead = []
        for child in node.named_children:
            if child.type == "template_substitution":
                break
            if child.type == "string_fragment":
                lead.append(text(child))
            elif child.type == "escape_sequence":
                lead.append(decode_escape(text(child)))
        return "".join(lead), True
    if node.type == "binary_expression":
        # flatten the left spine of a + chain: ((("a" + b) + "c") + d)
        spine, current = [], node
        while current is not None and current.type == "binary_expression":
            operator = field(current, "operator")
            if operator is None or text(operator) != "+":
                return None, False
            spine.append(field(current, "right"))
            current = field(current, "left")
        pieces = [current, *reversed(spine)]
        lead = []
        for piece in pieces:
            value = string_value(piece)
            if value is None:
                break
            lead.append(value)
        if lead:
            return "".join(lead), True
        return None, False
    if node.type == "parenthesized_expression" and node.named_child_count == 1:
        return literal_prefix(node.named_children[0])
    return None, False


def is_stringish(node: Any) -> bool:
    """A string, a template or a concatenation that starts with / contains a string."""
    if node is None:
        return False
    if node.type in ("string", "template_string"):
        return True
    if node.type == "binary_expression":
        stack, seen = [node], 0
        while stack and seen < 200:
            current = stack.pop()
            seen += 1
            if current.type in ("string", "template_string"):
                return True
            if current.type == "binary_expression":
                stack.extend(
                    child for child in (field(current, "left"), field(current, "right")) if child
                )
    return False


def arg_kind(node: Any | None) -> str:
    """first_arg_kind of the schema."""
    if node is None:
        return "none"
    kind = node.type
    if kind == "string":
        return "string_literal"
    if kind == "template_string":
        return "template"
    if kind in ("identifier", "shorthand_property_identifier"):
        return "identifier"
    if kind in ("member_expression", "subscript_expression"):
        return "member"
    if kind in ("call_expression", "new_expression"):
        return "call"
    return "other"


def unwrap(node: Any) -> tuple[Any, bool]:
    """Strip parentheses; ``(0, eval)`` -> ``eval`` (indirect=True)."""
    indirect = False
    for _ in range(MAX_SEGMENTS):
        if node is None or node.type != "parenthesized_expression":
            break
        inner = [child for child in node.named_children if child.type != "comment"]
        if not inner:
            break
        node = inner[-1]
        if node.type == "sequence_expression":
            indirect = True
            items = [child for child in node.named_children if child.type != "comment"]
            node = items[-1] if items else node
    return node, indirect


def raw_path(node: Any) -> list[str] | None:
    """Segments of an expression as written, outermost last ("window", "eval")."""
    segments: list[str] = []
    current = node
    for _ in range(MAX_SEGMENTS):
        current, _ = unwrap(current)
        if current is None:
            return None
        kind = current.type
        if kind in ("member_expression",):
            prop = field(current, "property")
            segments.append(text(prop, 80) if prop is not None else "?")
            current = field(current, "object")
        elif kind == "subscript_expression":
            index = field(current, "index")
            value = string_value(index)
            segments.append(value[:80] if value is not None else "[]")
            current = field(current, "object")
        elif kind == "call_expression":
            segments.append(CALL)
            current = field(current, "function")
        elif kind in ("identifier", "property_identifier", "shorthand_property_identifier"):
            segments.append(text(current, 80))
            break
        elif kind == "this":
            segments.append("this")
            break
        elif kind == "new_expression":
            constructor = field(current, "constructor")
            name = text(constructor, 40) if constructor is not None else "?"
            segments.append(f"new {name}()")
            break
        elif kind == "array":
            segments.append("[...]")
            break
        elif kind in ("string", "template_string"):
            segments.append("'...'")
            break
        else:
            segments.append("?")
            break
    else:
        segments.append("?")
    segments.reverse()
    return segments


def normalize(segments: list[str], global_aliases: frozenset[str]) -> tuple[list[str], str | None]:
    """Drop leading global objects (keeping a frame target like top/parent) and
    ``document.location`` -> ``location``. Returns (path, frame)."""
    path = list(segments)
    frame = None
    while len(path) > 1 and path[0] in global_aliases:
        if path[0] in ("top", "parent", "opener") and frame is None:
            frame = path[0]
        path.pop(0)
    if len(path) > 1 and path[0] == "document" and path[1] == "location":
        path.pop(0)
    if len(path) > 2 and path[0] == "document" and path[1] == "defaultView":
        path = path[2:]
    return path, frame


def fmt_path(path: list[str]) -> str:
    """["document", "getElementById", "()", "value"] -> "document.getElementById().value"."""
    out = ""
    for segment in path:
        if segment in (CALL, "[]"):
            out += segment
        elif not out:
            out = segment
        else:
            out += "." + segment
    return out[:160]


def enclosing_function(node: Any) -> str | None:
    """Name of the nearest enclosing function, or how an anonymous one is used."""
    current = node.parent
    for _ in range(400):
        if current is None:
            return None
        if current.type in FUNCTION_TYPES:
            return function_name(current)
        current = current.parent
    return None


def function_name(function: Any) -> str:
    name = field(function, "name")
    if name is not None:
        return text(name, 60)
    parent = function.parent
    while parent is not None and parent.type == "parenthesized_expression":
        parent = parent.parent
    if parent is None:
        return "<anonymous>"
    if parent.type == "variable_declarator":
        target = field(parent, "name")
        return text(target, 60) if target is not None else "<anonymous>"
    if parent.type in ("assignment_expression", "augmented_assignment_expression"):
        target = field(parent, "left")
        return text(target, 60) if target is not None else "<anonymous>"
    if parent.type == "pair":
        key = field(parent, "key")
        return text(key, 60) if key is not None else "<anonymous>"
    if parent.type == "arguments" and parent.parent is not None:
        call = parent.parent
        callee = field(call, "function") if call.type == "call_expression" else None
        path = raw_path(callee) if callee is not None else None
        label = path[-1] if path else "call"
        args = named_args(call)
        event = string_value(args[0]) if args else None
        return f"<callback: {label} {event}>" if event else f"<callback: {label}>"
    return "<anonymous>"


def assigned_to(node: Any) -> str | None:
    """'pwd' in ``var pwd = <node>`` / ``pwd = <node>``; 'key:p' in ``{p: <node>}``."""
    child, parent = node, node.parent
    for _ in range(6):
        if parent is None:
            return None
        if parent.type in ("parenthesized_expression", "await_expression"):
            child, parent = parent, parent.parent
            continue
        break
    if parent is None:
        return None
    if parent.type == "variable_declarator" and field(parent, "value") == child:
        name = field(parent, "name")
        return text(name, 60) if name is not None else None
    if parent.type in ("assignment_expression", "augmented_assignment_expression"):
        if field(parent, "right") == child:
            left = field(parent, "left")
            return text(left, 60) if left is not None else None
    if parent.type == "pair" and field(parent, "value") == child:
        key = field(parent, "key")
        return f"key:{text(key, 40)}" if key is not None else None
    return None


SELECTOR_FUNCTIONS = {
    "getElementById": "#{}",
    "getElementsByName": "[name={}]",
    "getElementsByClassName": ".{}",
    "getElementsByTagName": "{}",
    "querySelector": "{}",
    "querySelectorAll": "{}",
    "closest": "{}",
    "$": "{}",
    "jQuery": "{}",
}


def selector_of(node: Any) -> str | None:
    """The literal element selector somewhere in an expression's receiver chain.

    ``document.getElementById("password").value`` -> "#password";
    ``$("input[type=password]").val()`` -> "input[type=password]";
    ``document.forms["login"].submit()`` -> "forms[login]".
    """
    current = node
    for _ in range(MAX_SEGMENTS):
        current, _ = unwrap(current)
        if current is None:
            return None
        kind = current.type
        if kind == "call_expression":
            function = field(current, "function")
            path = raw_path(function) if function is not None else None
            if path and path[-1] in SELECTOR_FUNCTIONS:
                args = named_args(current)
                value = string_value(args[0]) if args else None
                if value is not None:
                    return SELECTOR_FUNCTIONS[path[-1]].format(value)[:120]
            current = function
        elif kind == "subscript_expression":
            obj = field(current, "object")
            if obj is not None and obj.type == "member_expression":
                prop = field(obj, "property")
                if prop is not None and text(prop) == "forms":
                    index = field(current, "index")
                    value = string_value(index)
                    return f"forms[{value if value is not None else text(index, 40)}]"
            current = obj
        elif kind == "member_expression":
            obj = field(current, "object")
            if obj is not None and obj.type == "member_expression":
                prop = field(obj, "property")
                if prop is not None and text(prop) == "forms":
                    return f"forms[{text(field(current, 'property'), 40)}]"
            current = obj
        else:
            return None
    return None


def identifiers_in(nodes: list[Any], ignored: frozenset[str], cap: int = 20) -> list[str]:
    """Distinct variable names used inside some nodes (properties excluded), in order."""
    found: list[str] = []
    seen: set[str] = set()
    stack = list(reversed(nodes))
    visited = 0
    while stack and visited < 3000 and len(found) < cap:
        current = stack.pop()
        visited += 1
        if current.type in ("identifier", "shorthand_property_identifier"):
            name = text(current, 60)
            if name not in seen and name not in ignored:
                seen.add(name)
                found.append(name)
            continue
        if current.type in FUNCTION_TYPES:
            continue  # a callback's body is not "data given to the call"
        stack.extend(reversed(current.named_children))
    return found


def name_tokens(value: str) -> list[str]:
    """'loginPassword' / 'txt_pass' -> ['login', 'password'] / ['txt', 'pass'] (lower case)."""
    return [token.lower() for token in TOKEN_SPLIT.split(value) if token]


def looks_like_credential(words: tuple[str, ...], *values: str | None) -> bool:
    """True if any name token starts with a credential word (pass, pwd, pin, card, email ...)."""
    for value in values:
        if not value:
            continue
        for token in name_tokens(value):
            if any(token.startswith(word) for word in words):
                return True
    return False
