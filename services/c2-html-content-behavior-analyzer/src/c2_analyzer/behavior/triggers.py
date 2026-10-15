"""Who triggers a piece of code: the page itself ("auto") or the user ("user")?

Part 8: Behavioral intent mapping (sources -> sinks).

Why it matters: ``location.replace("https://other.site")`` inside a button's
click handler is navigation the user asked for; the same line at the top of
a script runs the moment the page loads - a forced redirect. A download of
an .exe after a click is a download; without a click it is a drive-by. So
every sink gets a trigger:

- top level of an inline script ............................ auto ("runs on page load")
- callback of addEventListener / jQuery .on / .click / x.onclick = ...:
  the event decides - click, submit, keydown ... = user; load,
  DOMContentLoaded, readystatechange, mousemove, scroll ... = auto
  (configs/sources_sinks.yaml ``events``); $(fn) / $(document).ready = auto;
- setTimeout / setInterval / requestAnimationFrame callbacks, promise
  callbacks (.then / .done), immediately invoked functions and other
  callbacks inherit the trigger of the place they are set up from
  (a setTimeout at top level is auto, inside a click handler it is user);
- a named function: the trigger of the places it is called / registered
  (any auto use -> auto, else any user use -> user); functions are matched by
  NAME across the page's scripts and HTML handlers (``onclick="pay()"``);
- an HTML handler attribute: its event (onload = auto, onclick = user);
  a ``javascript:`` URL in href / action = user, in src = auto.
Anything else is "unknown" (an object method, a function never called in the
page - maybe by an external script Part 7 cannot see). Recursion is capped and
cycles return "unknown".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from c2_analyzer.behavior.code_index import (
    JQUERY_EVENT_METHODS,
    LISTENER_METHODS,
    FunctionInfo,
    ScriptCtx,
    Use,
)
from c2_analyzer.js_analyzer import syntax as sx

MAX_DEPTH = 8


@dataclass(frozen=True)
class Trigger:
    kind: str  # auto | user | unknown
    reason: str
    event: str | None = None  # the deciding event (click, load, submit, ...)


UNKNOWN = Trigger("unknown", "not called from page code (maybe by an external script)")


def combine(triggers: list[Trigger]) -> Trigger:
    """Any auto use -> auto; else any user use -> user; else unknown."""
    for kind in ("auto", "user"):
        for trigger in triggers:
            if trigger.kind == kind:
                return trigger
    return triggers[0] if triggers else UNKNOWN


class TriggerResolver:
    """Resolves triggers for nodes of a page's scripts (memoized per function)."""

    def __init__(
        self,
        contexts: dict[int, ScriptCtx],
        registry: dict[str, list[FunctionInfo]],
        uses: dict[str, list[Use]],
        events: dict[str, frozenset[str]],
    ) -> None:
        self.contexts = contexts
        self.registry = registry
        self.uses = uses
        self.user_events = events.get("user", frozenset())
        self.auto_events = events.get("auto", frozenset())
        self.timers = events.get("timers", frozenset())
        self.memo: dict[tuple, Trigger] = {}
        self.active: set[tuple] = set()

    def classify_event(self, event: str | None, how: str) -> Trigger:
        event = (event or "").lower()
        if event in {e.lower() for e in self.user_events}:
            return Trigger("user", f"{how} '{event}' (user action)", event)
        if event in {e.lower() for e in self.auto_events}:
            return Trigger("auto", f"{how} '{event}' (no user action)", event)
        return Trigger("unknown", f"{how} '{event}'", event or None)

    # ---- entry points -----------------------------------------------------------------

    def for_node(self, ctx: ScriptCtx, node: Any | None, depth: int = 0) -> Trigger:
        """The trigger of the code at ``node`` (None = the script as a whole)."""
        function = ctx.function_of(node) if node is not None else None
        if function is None:
            return self.top_level(ctx)
        return self.for_function(ctx, function, depth)

    def top_level(self, ctx: ScriptCtx) -> Trigger:
        unit = ctx.unit
        if unit.source == "event_handler" and unit.attribute:
            return self.classify_event(unit.attribute[2:], f"HTML {unit.attribute} on <{unit.tag}>")
        if unit.source == "javascript_url":
            if unit.attribute in ("src", "data"):
                return Trigger("auto", f"javascript: URL in {unit.attribute} (loads by itself)")
            return Trigger("user", f"javascript: URL in {unit.attribute} (runs on click)", "click")
        return Trigger("auto", "top-level script code (runs on page load)", "load")

    def for_function(self, ctx: ScriptCtx, function: Any, depth: int = 0) -> Trigger:
        key = ctx.key(function)
        if key in self.memo:
            return self.memo[key]
        if depth > MAX_DEPTH or key in self.active:
            return UNKNOWN
        self.active.add(key)
        try:
            trigger = self._function(ctx, function, depth)
        finally:
            self.active.discard(key)
        self.memo[key] = trigger
        return trigger

    # ---- rules ------------------------------------------------------------------------

    def _function(self, ctx: ScriptCtx, function: Any, depth: int) -> Trigger:
        listener = ctx.listeners.get(ctx.key(function))
        if listener is not None:
            event, selector = listener
            if event == "ready":
                return Trigger("auto", "jQuery ready handler (no user action)", "ready")
            where = f" on {selector}" if selector else ""
            return self.classify_event(event, f"listener{where} for")
        parent = function.parent
        while parent is not None and parent.type == "parenthesized_expression":
            parent = parent.parent
        if parent is not None and parent.type == "arguments" and parent.parent is not None:
            return self._callback(ctx, parent.parent, depth)
        if parent is not None and parent.type == "call_expression":  # (function(){...})()
            inherited = self.for_node(ctx, parent, depth + 1)
            return Trigger(
                inherited.kind, f"immediately invoked; {inherited.reason}", inherited.event
            )
        info = ctx.functions.get(ctx.key(function))
        name = info.name if info is not None else None
        if not name:
            return Trigger("unknown", "method / anonymous function not called in page code")
        return self._named(name, ctx.index, function, depth)

    def _callback(self, ctx: ScriptCtx, call: Any, depth: int) -> Trigger:
        callee = sx.field(call, "function")
        path, _ = sx.normalize(sx.raw_path(callee) or ["?"], frozenset({"window", "self", "top"}))
        name = path[-1]
        args = sx.named_args(call)
        if name in LISTENER_METHODS and args:
            events = (sx.string_value(args[0]) or "").lower().split()
            return self.classify_event(events[0] if events else None, "listener for")
        if name in JQUERY_EVENT_METHODS and len(path) >= 2:
            if name == "ready":
                return Trigger("auto", "jQuery ready handler (no user action)", "ready")
            return self.classify_event(name, "jQuery handler for")
        if path in (["$"], ["jQuery"]):
            return Trigger("auto", "jQuery ready handler (no user action)", "ready")
        inherited = self.for_node(ctx, call, depth + 1)
        if name in self.timers:
            return Trigger(inherited.kind, f"{name} callback; {inherited.reason}", inherited.event)
        return Trigger(inherited.kind, f"callback of {name}(); {inherited.reason}", inherited.event)

    def _named(self, name: str, script: int, function: Any, depth: int) -> Trigger:
        found = []
        for use in self.uses.get(name, []):
            ctx = self.contexts.get(use.script)
            if ctx is None:
                continue
            inside = (
                use.script == script
                and function.start_byte <= use.node.start_byte
                and use.node.end_byte <= function.end_byte
            )
            if inside:  # a recursive call inside the function itself says nothing
                continue
            if use.kind == "call":
                trigger = self.for_node(ctx, use.node, depth + 1)
            elif use.kind == "callback":
                trigger = self._callback(ctx, use.node.parent.parent, depth + 1)
            else:  # x.onclick = f
                left = sx.field(use.node, "left")
                prop = (
                    sx.field(left, "property")
                    if left is not None and left.type == "member_expression"
                    else left
                )
                event = sx.text(prop, 40)[2:] if prop is not None else ""
                trigger = self.classify_event(event, f"handler {sx.text(prop, 40)} =")
            found.append(
                Trigger(trigger.kind, f"{name}() called from: {trigger.reason}", trigger.event)
            )
        if not found:
            return Trigger("unknown", f"{name}() is never called in page code")
        return combine(found)
