"""Defanging: make URLs and domains NON-clickable before they are shown to people.

Part 9: Batch B-2 - read APIs for the team frontend.

Why (viva): the scan history is full of live phishing / malware links. If the dashboard
showed ``https://paypa1-login.com/`` as text, a browser, a chat app or a markdown renderer
could turn it into a clickable link - one mis-click infects an analyst. Threat-intel
practice is to "defang" every indicator: ``hxxps://paypa1-login[.]com/``. A person can
still read (and deliberately re-fang) it; no software will follow it.

Rules:
- scheme ``http`` / ``https`` -> ``hxxp`` / ``hxxps`` (``ftp`` -> ``fxp``); inside free
  text the host of a URL with ANY scheme is defanged too;
- every dot of the HOST -> ``[.]`` (the path / query are left readable);
- bare domains inside free text (finding messages such as "sends the password to
  api.telegram.org") are defanged when their ending is a real public suffix (tldextract's
  offline list) or a reserved test TLD, so rule ids like ``behavior.clickfix`` or file
  names like ``config.yaml`` stay as they are.
Applying the function twice changes nothing (``[.]`` is not a dot any more).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from c2_analyzer.utils.url import _tld_extractor

# Test / reserved names (RFC 2606 / 6761) are not on the public-suffix list.
RESERVED_TLDS = frozenset({"example", "test", "local", "invalid", "localhost", "onion"})

URL_IN_TEXT = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*)://([^\s/?#\"'<>\\]+)")
SCHEME_DEFANG = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "ftps": "fxps"}
DOMAIN_IN_TEXT = re.compile(
    r"(?i)(?<![\w.\[@/-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62})"
    r"(?![\w\[-])"
)


def defang_host(host: str | None) -> str | None:
    """``login.bank.com`` -> ``login[.]bank[.]com`` (IP addresses too)."""
    if not host:
        return host
    return host.replace("[.]", ".").replace(".", "[.]")


def defang_url(url: str | None) -> str | None:
    """``https://a.example.com/x?y=1`` -> ``hxxps://a[.]example[.]com/x?y=1``.

    Anything that is not an http(s) URL is defanged as free text.
    """
    if not url:
        return url
    text = url.strip()
    try:
        parts = urlsplit(text)
    except ValueError:
        return defang_text(text)
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
        return defang_text(text)
    scheme = "hxxps" if parts.scheme.lower() == "https" else "hxxp"
    rest = text.split("://", 1)[1]
    end = min((i for i in (rest.find(c) for c in "/?#") if i >= 0), default=len(rest))
    return f"{scheme}://{defang_host(rest[:end])}{rest[end:]}"


def _looks_like_domain(candidate: str) -> bool:
    last = candidate.rsplit(".", 1)[-1].lower()
    if last in RESERVED_TLDS:
        return True
    extractor = _tld_extractor()
    if extractor is None:
        return last.isalpha() and 2 <= len(last) <= 6  # built-in fallback
    result = extractor(candidate)
    return bool(result.suffix and result.domain)


def defang_text(text: str | None) -> str | None:
    """Defang every http(s) URL and every real-looking domain inside free text."""
    if not text:
        return text

    def url(match: re.Match) -> str:
        scheme, host = match.groups()
        return f"{SCHEME_DEFANG.get(scheme.lower(), scheme)}://{defang_host(host)}"

    text = URL_IN_TEXT.sub(url, text)
    return DOMAIN_IN_TEXT.sub(
        lambda m: defang_host(m.group(1)) if _looks_like_domain(m.group(1)) else m.group(1),
        text,
    )


# Fields of a stored AnalysisResponse that hold human-readable text (may name domains).
_TEXT_KEYS = frozenset(
    {"title", "detail", "evidence", "summary", "text", "status_reason", "code", "note"}
)
_URL_KEYS = frozenset({"submitted_url", "final_url"})


def defang_analysis(response: dict[str, Any]) -> dict[str, Any]:
    """A copy of an AnalysisResponse dict that is safe to show in a browser.

    URLs and hosts are defanged; human-readable text fields (finding title / detail /
    evidence, modality summaries and top evidence, warnings, feature texts, status
    reason) get ``defang_text``. Identifiers (rule ids, arm names, versions) are kept.
    """

    def walk(value: Any, key: str | None = None) -> Any:
        if isinstance(value, dict):
            return {k: walk(v, k) for k, v in value.items()}
        if isinstance(value, list):
            if key == "redirect_hosts":
                return [defang_host(item) if isinstance(item, str) else item for item in value]
            if key in ("top_evidence", "warnings"):
                return [defang_text(item) if isinstance(item, str) else item for item in value]
            return [walk(item) for item in value]
        if isinstance(value, str):
            if key in _URL_KEYS:
                return defang_url(value)
            if key in _TEXT_KEYS:
                return defang_text(value)
        return value

    return walk(response)
