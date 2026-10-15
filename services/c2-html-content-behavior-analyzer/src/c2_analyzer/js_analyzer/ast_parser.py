"""Parse JavaScript into a syntax tree with tree-sitter (tasks 3-4).

Part 7: Static JavaScript intent analyzer.

Why an AST and not regular expressions: a regex sees characters, an AST sees
code. ``"eval("`` inside a string or a comment is not a call; ``window["eval"]``
and ``(0, eval)(x)`` are calls although no regex for ``eval(`` matches them;
``document.cookie = x`` (write) and ``x = document.cookie`` (read) differ only
in where the expression sits. The tree gives every node's role and exact
position, which Part 8 needs to follow data from sources to sinks.

Why tree-sitter (not esprima): it is error-tolerant - broken or truncated code
still gives a tree with ERROR nodes around the bad part instead of nothing -
it understands modern syntax (optional chaining, class fields, async/await,
JSX-like text) and it ships as offline pip wheels with a C parser (fast).

Safety (the analysed page is hostile):
- the code is only PARSED, never run, and nothing is downloaded;
- each script is capped at ``limits.max_script_bytes`` (500 KB; the rest is not
  analysed and the script is marked truncated);
- each parse has a time limit (``limits.parse_timeout_ms``). tree-sitter checks
  it inside its own C loop, so it works the same on Windows (no signals, no
  threads to kill). Its newer progress-callback API crashed the interpreter on
  Windows in tests, so the older ``timeout_micros`` setting is used;
- a tree with more than ``limits.max_error_ratio`` of its text inside ERROR
  nodes is "unusable" and the lexical scanner takes over (confidence=low).
  So does a missing tree-sitter install - the analyzer never crashes for it.
"""

from __future__ import annotations

import time
import warnings
from dataclasses import dataclass
from functools import lru_cache
from importlib import metadata
from typing import Any


@dataclass
class ParseOutcome:
    """The tree (or None) plus everything the analyzer reports about the parse."""

    text: str  # the analysed text (after the size cap)
    source: bytes  # the same text as UTF-8 (tree-sitter positions are byte offsets)
    tree: Any | None
    truncated: bool = False
    timed_out: bool = False
    has_error: bool = False
    error_ratio: float = 0.0
    usable: bool = False
    parse_ms: float = 0.0
    error: str | None = None


@lru_cache
def _language() -> Any | None:
    try:
        import tree_sitter
        import tree_sitter_javascript
    except ImportError:
        return None
    return tree_sitter.Language(tree_sitter_javascript.language())


@lru_cache
def _parser() -> Any | None:
    language = _language()
    if language is None:
        return None
    import tree_sitter

    return tree_sitter.Parser(language)


def parser_available() -> bool:
    """True when tree-sitter and its JavaScript grammar are installed."""
    return _parser() is not None


@lru_cache
def parser_version() -> str:
    """'tree-sitter 0.25.2 / tree-sitter-javascript 0.25.0' (stored with every result)."""
    if not parser_available():
        return "lexical only (tree-sitter not installed)"
    versions = []
    for package in ("tree-sitter", "tree-sitter-javascript"):
        try:
            versions.append(f"{package} {metadata.version(package)}")
        except metadata.PackageNotFoundError:
            versions.append(f"{package} ?")
    return " / ".join(versions)


def cap_text(text: str, max_bytes: int) -> tuple[str, bytes, bool]:
    """(text, utf-8 bytes, truncated) with at most ``max_bytes`` bytes (cut at a char boundary)."""
    source = text.encode("utf-8", errors="replace")
    if len(source) <= max_bytes:
        return text, source, False
    cut = source[:max_bytes].decode("utf-8", errors="ignore")
    return cut, cut.encode("utf-8"), True


def error_bytes(root: Any) -> int:
    """Bytes covered by the OUTERMOST error / missing nodes (only error subtrees are visited)."""
    total, stack = 0, [root]
    while stack:
        node = stack.pop()
        if node.type == "ERROR" or node.is_missing:
            total += max(node.end_byte - node.start_byte, 1)
            continue
        stack.extend(child for child in node.children if child.has_error or child.is_missing)
    return total


def _set_timeout(parser: Any, micros: int) -> None:
    # Deprecated in tree-sitter 0.25 in favour of progress_callback, which crashed
    # on Windows (see the module docstring). Without the attribute: no timeout,
    # the size cap still bounds the work.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        if hasattr(parser, "timeout_micros"):
            parser.timeout_micros = micros


def parse_js(
    text: str,
    max_bytes: int = 500_000,
    timeout_ms: int = 3000,
    max_error_ratio: float = 0.5,
) -> ParseOutcome:
    """Parse one script. Never raises: problems are reported in the outcome."""
    text, source, truncated = cap_text(text, max_bytes)
    outcome = ParseOutcome(text=text, source=source, tree=None, truncated=truncated)
    parser = _parser()
    if parser is None:
        outcome.error = "tree-sitter not installed"
        return outcome
    started = time.perf_counter()
    _set_timeout(parser, max(int(timeout_ms * 1000), 1))
    try:
        tree = parser.parse(source)
    except ValueError:  # tree-sitter's "Parsing failed" = the time limit was hit
        parser.reset()
        outcome.timed_out = True
        outcome.error = f"parse timeout (> {timeout_ms} ms)"
        tree = None
    except Exception as error:  # noqa: BLE001 - a parser bug must not stop the page
        parser.reset()
        outcome.error = f"parser error: {type(error).__name__}: {error}"
        tree = None
    if tree is not None:
        _accept(outcome, tree, source, max_error_ratio)
        if truncated and outcome.has_error:  # cut inside a string / statement
            _retry_at_boundary(outcome, parser, timeout_ms, max_error_ratio)
    outcome.parse_ms = round((time.perf_counter() - started) * 1000, 2)
    return outcome


def _accept(outcome: ParseOutcome, tree: Any, source: bytes, max_error_ratio: float) -> None:
    root = tree.root_node
    outcome.tree = tree
    outcome.has_error = bool(root.has_error)
    outcome.error_ratio = 0.0
    if outcome.has_error and source:
        outcome.error_ratio = round(min(error_bytes(root) / len(source), 1.0), 4)
    outcome.usable = outcome.error_ratio <= max_error_ratio
    outcome.error = (
        None if outcome.usable else (f"{outcome.error_ratio:.0%} of the script is unparsable")
    )


def _retry_at_boundary(
    outcome: ParseOutcome, parser: Any, timeout_ms: int, max_error_ratio: float
) -> None:
    """A script cut by the size limit often ends inside a string, which turns
    everything from that string on into ERROR. Cut the text back to the last
    line / statement end BEFORE the first error and parse that prefix (the
    analysed text is then the prefix; the rest is reported as truncated)."""
    root = outcome.tree.root_node if outcome.tree is not None else None
    first_error = next(
        (child.start_byte for child in (root.children if root else []) if child.has_error),
        len(outcome.source),
    )
    prefix = outcome.source[:first_error].decode("utf-8", errors="ignore")
    for boundary in ("\n", ";", "}"):
        cut = prefix.rfind(boundary)
        if cut <= 0:
            continue
        candidate = prefix[: cut + 1]
        source = candidate.encode("utf-8", errors="replace")
        _set_timeout(parser, max(int(timeout_ms * 1000), 1))
        try:
            tree = parser.parse(source)
        except Exception:  # noqa: BLE001 - timeout / parser error: keep the first result
            parser.reset()
            return
        retry = ParseOutcome(text=candidate, source=source, tree=None, truncated=True)
        _accept(retry, tree, source, max_error_ratio)
        if retry.usable and (not outcome.usable or retry.error_ratio < outcome.error_ratio):
            outcome.text, outcome.source = candidate, source
            outcome.tree, outcome.has_error = retry.tree, retry.has_error
            outcome.error_ratio, outcome.usable, outcome.error = retry.error_ratio, True, None
            return
