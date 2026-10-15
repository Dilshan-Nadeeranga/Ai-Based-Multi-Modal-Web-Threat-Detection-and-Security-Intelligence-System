"""Obfuscation statistics per script (descriptive only - Part 8 judges).

Part 7: Static JavaScript intent analyzer.

Why two kinds of indicators: almost every benign site ships MINIFIED code
(jQuery, bundles): long lines, little whitespace, one-letter names. That is
compression, not hiding. OBFUSCATION tries to hide what the code does:
packers (``eval(function(p,a,c,k,e,d)...)``), JSFuck (only ``[]()!+``),
aaencode / jjencode, huge arrays of encoded strings read by index with
``_0x1a2b``-style names (obfuscator.io), strings written as ``\\x41\\u0042``
escapes, long base64 blobs, ``eval(atob(...))``. ``minified`` and
``signatures`` are therefore reported separately; a minified library must
not look "obfuscated".

Numbers come from the source text (entropy, whitespace, escapes, lines) and,
when the AST is usable, from the walk the detectors already make
(identifiers, string literals, string arrays) - no second parse. Without an
AST, identifiers and strings are found with regular expressions.
Thresholds: ``obfuscation`` in configs/js_rules.yaml.
"""

from __future__ import annotations

import bisect
import math
import re
from collections import Counter
from dataclasses import dataclass, field

from c2_analyzer.schemas.js import ObfuscationStats

ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}|\\u\{[0-9a-fA-F]{1,6}\}|\\u[0-9a-fA-F]{4}")
HEX_NAME = re.compile(rb"_0x[0-9a-fA-F]{3,}")
IDENTIFIER = re.compile(r"(?<![\w$.])[A-Za-z_$][\w$]*")
QUOTE = re.compile(r"[\"']")
KEYWORDS = frozenset(
    "var let const function return if else for while do switch case break continue new "
    "this typeof instanceof in of try catch finally throw delete void null true false "
    "undefined class extends super import export default async await yield".split()
)
SIGNATURE_PATTERNS = {
    "packer": re.compile(
        r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[rd]"
    ),
    "jjencode": re.compile(r"\$\s*=\s*~\s*\[\s*\]\s*;"),
    "aaencode": re.compile("ﾟωﾟ|ﾟДﾟ|ﾟΘﾟ"),
    "eval_of_decoded": re.compile(
        r"\beval\s*\(\s*(?:window\.)?(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\("
    ),
    "base64_blob": re.compile(r"[\"'][A-Za-z0-9+/]{2000,}={0,2}[\"']"),
}
JSFUCK_CHARS = frozenset("[]()!+")
DEFAULTS = {
    "min_chars": 200,
    "minified_min_chars": 1000,
    "minified_max_line": 500,
    "minified_avg_line": 200,
    "minified_max_whitespace": 0.15,
    "jsfuck_min_chars": 500,
    "jsfuck_share": 0.95,
    "hex_identifier_ratio": 0.2,
    "hex_identifier_min": 20,
    "string_array_min": 100,
    "string_array_with_hex_min": 50,
    "escape_ratio": 0.3,
}


@dataclass
class ObfuscationCollector:
    """Filled by the AST walk (detectors.ScriptDetector)."""

    identifiers: int = 0
    identifier_chars: int = 0
    single_char: int = 0
    hex_names: int = 0
    max_string: int = 0
    max_string_array: int = 0
    seen_ast: bool = field(default=False)

    def identifier(self, name: bytes) -> None:
        self.seen_ast = True
        self.identifiers += 1
        self.identifier_chars += len(name)
        if len(name) == 1:
            self.single_char += 1
        elif name[:3] == b"_0x" and HEX_NAME.fullmatch(name):
            self.hex_names += 1

    def string(self, length: int) -> None:
        self.seen_ast = True
        if length > self.max_string:
            self.max_string = length

    def string_array(self, size: int) -> None:
        if size > self.max_string_array:
            self.max_string_array = size


def _lexical_collector(text: str) -> ObfuscationCollector:
    """Identifier / string statistics without an AST (regular expressions, capped)."""
    collector = ObfuscationCollector()
    for count, match in enumerate(IDENTIFIER.finditer(text)):
        if count >= 200_000:
            break
        name = match.group()
        if name in KEYWORDS:
            continue
        collector.identifier(name.encode("utf-8", errors="replace"))
    for length in string_lengths(text):
        collector.string(length)
    collector.seen_ast = False
    return collector


def string_lengths(text: str, cap: int = 50_000) -> list[int]:
    """Lengths of '...' / "..." literals, in linear time.

    A regular expression for strings backtracks badly on broken code (an
    unclosed quote on a 500 KB single line made it quadratic: 26 s for one
    page). This jumps from quote to quote with str.find instead. A string may
    not cross a line break (a syntax error in JavaScript), so an unclosed
    quote only costs the rest of its line.
    """
    newlines = [index for index, char in enumerate(text) if char == "\n"]
    lengths: list[int] = []
    # quote char -> offset up to which it has no unescaped partner (found by an
    # earlier failed search): later quotes of that kind there are skipped at once
    dead = {'"': -1, "'": -1}
    position = 0
    while len(lengths) < cap:
        match = QUOTE.search(text, position)
        if match is None:
            break
        quote, start = match.group(), match.end()
        if start <= dead[quote]:
            position = start
            continue
        line = bisect.bisect_left(newlines, start)
        line_end = newlines[line] if line < len(newlines) else len(text)
        cursor, end = start, None
        while True:
            close = text.find(quote, cursor, line_end)
            if close == -1:
                break
            backslashes = 0
            while close - backslashes - 1 >= start and text[close - backslashes - 1] == "\\":
                backslashes += 1
            if backslashes % 2 == 0:
                end = close
                break
            cursor = close + 1
        if end is None:  # unclosed on this line: not a string start
            dead[quote] = line_end
            position = start
            continue
        lengths.append(end - start)
        position = end + 1
    return lengths


def _hides_ascii(escape: str) -> bool:
    """True for an escape of an ASCII letter, digit or space - writing "eval" as
    four escapes hides it. Escaped non-ASCII text (Arabic, Sinhala ...) and
    escaped punctuation (JSON's "<" and "/" escapes) are normal serializer output."""
    digits = escape[2:].strip("{}")
    try:
        char = chr(int(digits, 16))
    except ValueError:
        return False
    return char.isascii() and (char.isalnum() or char == " ")


def shannon_entropy(counts: Counter, total: int) -> float:
    if total <= 0:
        return 0.0
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def compute_stats(
    text: str, collector: ObfuscationCollector | None, thresholds: dict | None = None
) -> ObfuscationStats:
    """All statistics + the minified flag + the obfuscation signatures of one script."""
    limits = {**DEFAULTS, **(thresholds or {})}
    if collector is None or not collector.seen_ast:
        collector = _lexical_collector(text)
    chars = len(text)
    line_lengths = [len(line) for line in text.split("\n")] if text else [0]
    counts = Counter(text)
    whitespace = sum(n for char, n in counts.items() if char.isspace())
    visible = chars - whitespace
    alnum = sum(n for char, n in counts.items() if char.isalnum())
    escaped = sum(len(match) for match in ESCAPE.findall(text) if _hides_ascii(match))
    stats = {
        "chars": chars,
        "lines": len(line_lengths),
        "avg_line_length": round(chars / len(line_lengths), 1),
        "max_line_length": max(line_lengths),
        "whitespace_ratio": round(whitespace / chars, 4) if chars else 0.0,
        "entropy": round(shannon_entropy(counts, chars), 4),
        "non_alnum_ratio": round((visible - alnum) / visible, 4) if visible else 0.0,
        "escape_ratio": round(escaped / chars, 4) if chars else 0.0,
        "max_string_length": max(collector.max_string, 0),
        "identifier_count": collector.identifiers,
        "avg_identifier_length": (
            round(collector.identifier_chars / collector.identifiers, 2)
            if collector.identifiers
            else 0.0
        ),
        "single_char_identifier_ratio": (
            round(collector.single_char / collector.identifiers, 4)
            if collector.identifiers
            else 0.0
        ),
        "hex_identifier_ratio": (
            round(collector.hex_names / collector.identifiers, 4) if collector.identifiers else 0.0
        ),
        "string_array_size": collector.max_string_array,
    }
    signatures = [name for name, pattern in SIGNATURE_PATTERNS.items() if pattern.search(text)]
    if chars >= limits["jsfuck_min_chars"] and visible:
        jsfuck = sum(n for char, n in counts.items() if char in JSFUCK_CHARS)
        if jsfuck / visible >= limits["jsfuck_share"]:
            signatures.append("jsfuck")
    if (
        stats["hex_identifier_ratio"] >= limits["hex_identifier_ratio"]
        and collector.hex_names >= limits["hex_identifier_min"]
    ):
        signatures.append("hex_identifiers")
    array = collector.max_string_array
    if array >= limits["string_array_min"] or (
        array >= limits["string_array_with_hex_min"] and collector.hex_names > 0
    ):
        signatures.append("string_array")
    if stats["escape_ratio"] >= limits["escape_ratio"] and chars >= limits["min_chars"]:
        signatures.append("escape_heavy")
    minified = (
        chars >= limits["minified_min_chars"]
        and (
            stats["max_line_length"] >= limits["minified_max_line"]
            or stats["avg_line_length"] >= limits["minified_avg_line"]
        )
        and stats["whitespace_ratio"] <= limits["minified_max_whitespace"]
    )
    return ObfuscationStats(**stats, minified=minified, signatures=signatures)
