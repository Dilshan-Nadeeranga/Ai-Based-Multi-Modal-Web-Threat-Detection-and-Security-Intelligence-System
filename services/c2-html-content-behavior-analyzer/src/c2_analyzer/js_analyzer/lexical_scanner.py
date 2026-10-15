"""Regex / token fallback scanner for scripts the AST parser cannot use (task 4 fallback).

Part 7: Static JavaScript intent analyzer.

Why a fallback at all: some pages carry JavaScript so broken (cut off by a
size limit, half-templated, deliberately malformed) that tree-sitter returns a
tree that is mostly ERROR nodes - or tree-sitter is not installed, or a parse
hits the time limit. Reporting "nothing found" would hide exactly the
suspicious pages, so this scanner looks for the same APIs with the regular
expressions in configs/js_rules.yaml (``apis.<id>.lexical``).

Why its detections are confidence="low": a regex cannot tell code from text
(``"eval("`` inside a string matches) and cannot see aliases or the
difference between ``x = document.cookie`` and ``document.cookie = x`` as
reliably as the tree. The results are still useful evidence; Part 8 can weigh
them lower.
"""

from __future__ import annotations

import bisect
import re

from c2_analyzer.js_analyzer.detectors import PageUrls, mask_literal, safe_snippet, url_facts
from c2_analyzer.js_analyzer.rules import Rules
from c2_analyzer.schemas.js import Detection, DetectionArgs

QUOTED = re.compile(r"([\"'`])((?:\\.|(?!\1)[^\\\n]){0,500})\1")
TOKEN = re.compile(r"[\"'`]|//|/\*")


def _closing(text: str, quote: str, start: int, newlines: list[int]) -> int | None:
    """Index of the unescaped closing quote (strings end at a line break, templates do not)."""
    limit = len(text)
    if quote != "`":
        line = bisect.bisect_left(newlines, start)
        limit = newlines[line] if line < len(newlines) else len(text)
    cursor = start
    while True:
        close = text.find(quote, cursor, limit)
        if close == -1:
            return None
        backslashes = 0
        while close - backslashes - 1 >= start and text[close - backslashes - 1] == "\\":
            backslashes += 1
        if backslashes % 2 == 0:
            return close
        cursor = close + 1


def blank_comments(text: str) -> str:
    """Replace // and /* */ comments by spaces (same length, newlines kept), so
    "eval(" in a comment is not reported and every offset stays valid. Strings
    are skipped over ("http://x" is not a comment). Regex literals are not
    recognised - a ``//`` inside one blanks the rest of that line (the fallback
    is best effort anyway). Linear time; an unclosed quote is skipped."""
    newlines = [index for index, char in enumerate(text) if char == "\n"]
    dead = {'"': -1, "'": -1, "`": -1}  # a quote with no partner before this offset
    pieces: list[str] = []
    last = position = 0
    while True:
        match = TOKEN.search(text, position)
        if match is None:
            break
        token, start = match.group(), match.start()
        if token in dead and start <= dead[token]:
            position = start + 1
            continue
        if token == "//":
            end = text.find("\n", start)
            end = len(text) if end == -1 else end
        elif token == "/*":
            end = text.find("*/", start + 2)
            end = len(text) if end == -1 else end + 2
        else:
            close = _closing(text, token, start + 1, newlines)
            if close is None:
                line = bisect.bisect_left(newlines, start)
                line_end = newlines[line] if line < len(newlines) else len(text)
                dead[token] = len(text) if token == "`" else line_end
                position = start + 1
            else:
                position = close + 1
            continue
        pieces.append(text[last:start])
        pieces.append(re.sub(r"[^\n]", " ", text[start:end]))
        last = position = end
    pieces.append(text[last:])
    return "".join(pieces)


EVENT = re.compile(r"[\"']([A-Za-z]+)[\"']|\bon([a-z]+)\s*=")
URL_CATEGORIES = {"network_fetch", "network_xhr", "redirect", "form_submission"}


class LineIndex:
    """Character offset -> (line, column, byte offset) without re-encoding the whole text."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.starts = [0]
        self.byte_starts = [0]
        position, byte_position = 0, 0
        for line in text.split("\n"):
            position += len(line) + 1
            byte_position += len(line.encode("utf-8", errors="replace")) + 1
            self.starts.append(position)
            self.byte_starts.append(byte_position)

    def locate(self, offset: int) -> tuple[int, int, int]:
        line = bisect.bisect_right(self.starts, offset) - 1
        start = self.starts[line]
        column = offset - start
        prefix = self.text[start:offset].encode("utf-8", errors="replace")
        return line + 1, column + 1, self.byte_starts[line] + len(prefix)


def scan(
    text: str,
    rules: Rules,
    script_index: int,
    source: str,
    urls: PageUrls,
    in_library: bool = False,
) -> list[Detection]:
    """Every lexical match of every API rule, in source order (confidence="low")."""
    index = LineIndex(text)
    code = blank_comments(text)  # same offsets as text, comments are spaces
    limit = int(rules.limits.get("max_lexical_matches_per_api", 200))
    snippet_chars = int(rules.limits.get("snippet_chars", 200))
    literal_chars = int(rules.limits.get("literal_chars", 200))
    listener_events = rules.lists.get("listener_events") or {}
    found: list[Detection] = []
    for rule in rules.lexical:
        category = rules.category(rule.api)
        for count, match in enumerate(rule.pattern.finditer(code)):
            if count >= limit:
                break
            start, end = match.span()
            line, column, start_byte = index.locate(start)
            end_line, _, end_byte = index.locate(end)
            window = code[start : start + 400]
            literal = QUOTED.search(window[: max(end - start, 0) + 40])
            value = literal.group(2) if literal else None
            args = None
            if value is not None:
                url, domain, external = (
                    url_facts(value, urls) if category in URL_CATEGORIES else (None, None, None)
                )
                args = DetectionArgs(
                    first_arg_kind="string_literal",
                    literal_value=mask_literal(value, literal_chars),
                    url=url,
                    url_domain=domain,
                    url_is_external=external,
                )
            event_type = None
            if rule.access == "listener":
                event = EVENT.search(match.group())
                name = (event.group(1) or event.group(2)).lower() if event else None
                event_type = name if name in listener_events else None
            found.append(
                Detection(
                    api=rule.api,
                    category=category,
                    source=source,
                    script_index=script_index,
                    line=line,
                    column=column,
                    end_line=end_line,
                    start_byte=start_byte,
                    end_byte=end_byte,
                    access=rule.access,
                    snippet=safe_snippet(window[:snippet_chars], snippet_chars),
                    callee=safe_snippet(match.group(), 120),
                    args=args,
                    event_type=event_type,
                    in_library=in_library,
                    confidence="low",
                )
            )
    found.sort(key=lambda d: (d.start_byte, d.api))
    return found
