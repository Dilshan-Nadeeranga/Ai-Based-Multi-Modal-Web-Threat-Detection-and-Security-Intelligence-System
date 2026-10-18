"""Safe live fetch for ``POST /api/v1/analyze`` (url mode).

Part 9: Batch B-1 - end-to-end URL analysis engine.

Why C2 fetches the page itself (viva): ThreatRadar and the frontend only have a URL, and
a page copied by the caller could be anything. But the URL is attacker-controlled, so
fetching it is the riskiest thing C2 does. The rules, all inherited from Part 1's
``StaticFetcher`` (never a second fetcher):

- static mode only: ONE GET, no JavaScript, no forms submitted, no images / scripts /
  CSS downloaded, http / https only;
- server-side request forgery guard: localhost, private, link-local and reserved
  addresses are refused - for the submitted URL, for every redirect hop and for every
  address a hostname RESOLVES to (``resolve_dns``);
- hard limits: timeout, at most N redirects, 5 MB streamed and aborted early, HTML
  content types only.

On top of that, this module decides what a non-page answer MEANS for the verdict:
- the URL path (or final URL) ends in an executable / archive / installer extension
  (configs/url_filters.yaml lists), or the response is such a content type / an
  attachment -> the body is NOT downloaded; status "download", a strong
  malware_delivery signal (fetch.executable_download evidence-floor rule);
- other non-HTML (image, JSON, PDF ...) -> "not_html" (inconclusive);
- DNS / timeout / refused / TLS / HTTP 4xx-5xx -> "unreachable" (no verdict);
- refused by the SSRF guard -> "blocked" (no verdict).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

import httpx

from c2_analyzer.config import load_yaml_config
from c2_analyzer.dataset.feeds import _urlhaus_rules
from c2_analyzer.dataset.fetcher import FetchSettings, StaticFetcher, mime_type
from c2_analyzer.utils.pii import mask_url

FetchStatus = Literal["ok", "download", "not_html", "unreachable", "blocked"]


@lru_cache
def analyze_config() -> dict:
    """configs/analyze.yaml, read once."""
    return load_yaml_config("analyze")


@lru_cache
def download_extensions() -> frozenset[str]:
    """url_filters.yaml urlhaus.drop_extensions minus analyze.yaml downloads.not_downloads."""
    _, drop_extensions, _ = _urlhaus_rules()
    keep = {str(e).lower() for e in analyze_config()["downloads"].get("not_downloads", [])}
    return frozenset(drop_extensions - keep)


def download_content_types() -> frozenset[str]:
    return frozenset(
        str(t).lower() for t in analyze_config()["downloads"]["download_content_types"]
    )


def url_download_kind(url: str | None) -> str | None:
    """'.exe' if the URL's last path segment is a download type (Part 1's rule), else None."""
    if not url:
        return None
    segments = [segment for segment in urlsplit(url).path.split("/") if segment]
    last = segments[-1].lower() if segments else ""
    extension = last.rsplit(".", 1)[1] if "." in last else ""
    if extension and extension in download_extensions():
        return f".{extension}"
    if last in download_extensions():  # /bins/x86_64 (Mirai-style builds)
        return last
    return None


def response_download_kind(content_type: str | None, disposition: str | None) -> str | None:
    """'application/x-msdownload' / 'attachment' if the headers announce a file download."""
    mime = mime_type(content_type)
    if mime in download_content_types():
        return mime
    if disposition and disposition.strip().lower().startswith("attachment"):
        return "attachment"
    return None


@dataclass
class FetchOutcome:
    """What the live fetch produced (the html only for status "ok")."""

    status: FetchStatus
    submitted_url: str
    reason: str | None = None
    html: str | None = None
    final_url: str | None = None
    redirect_hosts: list[str] = field(default_factory=list)
    http_status: int | None = None
    content_type: str | None = None
    download_kind: str | None = None
    fetch_ms: float = 0.0

    @property
    def masked_final_url(self) -> str | None:
        return mask_url(self.final_url)


def api_fetch_settings() -> FetchSettings:
    """Part 1's FetchSettings with the API's own limits (configs/analyze.yaml fetch:)."""
    return FetchSettings.from_config(**analyze_config()["fetch"])


class LiveFetcher:
    """Thin policy layer over Part 1's StaticFetcher (one shared httpx client)."""

    def __init__(
        self, settings: FetchSettings | None = None, transport: httpx.BaseTransport | None = None
    ) -> None:
        self.settings = settings or api_fetch_settings()
        self.fetcher = StaticFetcher(self.settings, transport=transport)

    def fetch(self, url: str) -> FetchOutcome:
        kind = url_download_kind(url)
        if kind:
            # Not requested at all: the name already says it is a file, and there is
            # nothing to gain from downloading a possible payload.
            return FetchOutcome(
                "download",
                url,
                reason=f"URL points to a {kind} file",
                final_url=url,
                redirect_hosts=[(urlsplit(url).hostname or "").lower()],
                download_kind=kind,
            )
        result = self.fetcher.fetch(url)
        outcome = FetchOutcome(
            "ok",
            url,
            reason=result.reason,
            final_url=result.final_url,
            redirect_hosts=list(result.redirect_hosts),
            http_status=result.http_status,
            content_type=result.content_type,
            fetch_ms=result.fetch_ms,
        )
        if result.blocked:
            outcome.status = "blocked"
            return outcome
        # The headers / final URL can reveal a download even when the request failed or
        # was skipped as "not HTML" - in that case the body was never read.
        kind = response_download_kind(result.content_type, result.content_disposition)
        kind = kind or url_download_kind(result.final_url)
        if kind and result.http_status is not None and result.http_status < 400:
            outcome.status = "download"
            outcome.download_kind = kind
            outcome.reason = f"URL serves a {kind} file instead of a web page"
            return outcome
        if result.outcome == "ok":
            outcome.html = result.html
            return outcome
        # skipped = reachable but not a usable page (not HTML, or larger than max_bytes);
        # failed = network / HTTP problem.
        outcome.status = "not_html" if result.outcome == "skipped" else "unreachable"
        return outcome

    def close(self) -> None:
        self.fetcher.close()
