"""Collect the JavaScript of a page from Part 2's ParsedPage (tasks 1-2).

Part 7: Static JavaScript intent analyzer.

Why reuse Part 2: Part 2 already found every place JavaScript hides in the
HTML and kept DATA blocks apart (JSON-LD / templates are in
``structured_data`` / ``templates``, not in ``scripts_inline``). Re-extracting
here could disagree with Part 2, so this module only turns ParsedPage fields
into code units:
- ``scripts_inline``  -> source="inline" (Part 2 capped each at 500 KB);
- ``event_handlers``  -> source="event_handler" (``onclick="..."`` is code too);
- ``javascript_urls`` -> source="javascript_url" (``href="javascript:..."``;
  percent-escapes are decoded like a browser does before running it).

External scripts (task 2) are REFERENCE-LEVEL ONLY: src, domain, same site or
not, async/defer, integrity, a known-CDN flag, a library guess from the file
name and suspicious-host flags (raw IP, free hosting, data: URL, plain http).
Their CONTENT is never downloaded - static mode does not touch the network -
so what an external script does is a documented blind spot of Part 7.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from c2_analyzer.js_analyzer.libraries import identify_src
from c2_analyzer.js_analyzer.rules import Rules
from c2_analyzer.schemas.js import ExternalScriptInfo
from c2_analyzer.schemas.parsed_page import ParsedPage


@dataclass
class CodeUnit:
    """One piece of JavaScript to analyse."""

    source: str  # inline | event_handler | javascript_url
    origin: str  # human-readable: "script #2 (head)", "onclick on <button>"
    text: str
    chars: int  # length before Part 2's cap
    capped_by_part2: bool = False
    part2_index: int | None = None
    attribute: str | None = None  # for handlers: onclick / onsubmit ...; for URLs: href ...
    tag: str | None = None


def collect_scripts(page: ParsedPage) -> list[CodeUnit]:
    """Inline scripts, then event handlers, then javascript: URLs (document order within each)."""
    units = [
        CodeUnit(
            source="inline",
            origin=f"script #{script.index} ({script.position})",
            text=script.content,
            chars=script.chars,
            capped_by_part2=script.content_truncated,
            part2_index=script.index,
            tag="script",
        )
        for script in page.scripts_inline
    ]
    for handler in page.event_handlers:
        if handler.code.strip():
            units.append(
                CodeUnit(
                    source="event_handler",
                    origin=f"{handler.attribute} on <{handler.tag}>",
                    text=handler.code,
                    chars=len(handler.code),
                    attribute=handler.attribute.lower(),
                    tag=handler.tag,
                )
            )
    for url in page.javascript_urls:
        code = unquote(url.code)
        if code.strip():
            units.append(
                CodeUnit(
                    source="javascript_url",
                    origin=f"{url.attribute} on <{url.tag}>",
                    text=code,
                    chars=len(code),
                    attribute=url.attribute,
                    tag=url.tag,
                )
            )
    return units


def _host(url: str | None) -> str:
    if not url:
        return ""
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _matches(host: str, domains: list[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def external_scripts(page: ParsedPage, rules: Rules) -> list[ExternalScriptInfo]:
    """Reference-level facts for every <script src> (nothing is fetched)."""
    cdns = [d.lower() for d in rules.lists.get("known_cdns") or []]
    free = [d.lower() for d in rules.lists.get("free_hosting") or []]
    infos = []
    for index, script in enumerate(page.scripts_external):
        src = script.src_abs or script.src_raw
        host = _host(src)
        flags = []
        if script.src_raw.strip().lower().startswith("data:"):
            flags.append("data_url")
        if host and _is_ip(host):
            flags.append("raw_ip")
        if host and _matches(host, free):
            flags.append("free_hosting")
        if src.lower().startswith("http://"):
            flags.append("insecure_http")
        infos.append(
            ExternalScriptInfo(
                index=index,
                src=src,
                domain=script.domain,
                is_external=script.is_external,
                is_async=script.is_async,
                defer=script.defer,
                has_integrity=script.has_integrity,
                known_cdn=bool(host) and _matches(host, cdns),
                library=identify_src(src, rules),
                flags=flags,
                # plain http is reported but is not a "suspicious host" by itself
                suspicious_host=any(f in flags for f in ("data_url", "raw_ip", "free_hosting")),
            )
        )
    return infos
