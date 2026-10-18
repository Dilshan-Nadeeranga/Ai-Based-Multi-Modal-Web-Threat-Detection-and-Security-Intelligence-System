"""Safe page fetchers: download a candidate URL's HTML (stage 2 of collection).

Part 1: Multilingual dataset preparation (Batch B).

Why: the dataset needs the real HTML of live scam pages, but those pages are
hostile. The fetchers therefore do as little as possible:

static (default, httpx)
    One GET request - no JavaScript runs, no forms are submitted, no images,
    scripts or other linked resources are downloaded. Hard limits on time
    (15 s), redirects (5) and size (5 MB, streamed and aborted early). Only
    text/html or application/xhtml+xml responses are kept.

rendered (Playwright, optional)
    A headless Chromium that DOES run the page's JavaScript (needed for pages
    that build their content with JS). Downloads, media, fonts, websockets and
    permissions are blocked - but because JS runs, this mode must only be used
    inside the Docker container (docker/fetcher.Dockerfile).

Both modes refuse URLs that point to this computer or the local network, wait
politely between requests and report final_url / http_status / content_type.

The live /api/v1/analyze (Part 9 Batch B-1) reuses the STATIC fetcher with
``resolve_dns=True``: a hostname is resolved and refused when ANY of its addresses
is private / loopback / link-local / reserved - before the first request and before
every redirect hop. The dataset collector keeps the old behaviour (no DNS lookup).
"""

from __future__ import annotations

import codecs
import ipaddress
import os
import re
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import httpx

from c2_analyzer.config import load_yaml_config
from c2_analyzer.utils.url import extract_domain

HTML_TYPES = ("text/html", "application/xhtml+xml")

# Content types that mean "this is a file download, not a page" (rendered mode).
DOWNLOAD_TYPES = (
    "application/octet-stream",
    "application/zip",
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/vnd.android.package-archive",
    "application/java-archive",
    "application/x-rar-compressed",
    "application/x-7z-compressed",
    "application/pdf",
)

RENDERED_WARNING = """\
WARNING: rendered mode runs the JavaScript of untrusted (possibly malicious) pages
in a real browser. Only run it inside the Docker container (docker/fetcher.Dockerfile),
never directly on your own computer."""

# <meta charset="x"> or <meta http-equiv="Content-Type" content="text/html; charset=x">
META_CHARSET = re.compile(rb"""<meta[^>]+charset\s*=\s*["']?\s*([A-Za-z0-9_.:-]+)""", re.IGNORECASE)


class BlockedHostError(Exception):
    """Raised when a URL (or a redirect) points to localhost or a private network."""


@dataclass
class FetchSettings:
    """Fetch limits; defaults come from the ``collection`` section of configs/config.yaml."""

    rate_per_second: float
    per_host_delay_seconds: float
    timeout_seconds: float
    max_redirects: int
    max_bytes: int
    rendered_timeout_ms: int
    rendered_wait_ms: int
    user_agent: str
    accept_language: str
    resolve_dns: bool = False  # Part 9 API: also refuse hostnames resolving to private IPs
    # Part 9 API: whole-download cap (httpx's timeout is per network read, so a server
    # trickling 1 byte every 9 s would otherwise never time out). None = no cap.
    total_timeout_seconds: float | None = None

    @classmethod
    def from_config(cls, **overrides: object) -> FetchSettings:
        config = load_yaml_config("config")["collection"]
        # Fields with a default (resolve_dns) are optional in configs/config.yaml.
        values = {name: config[name] for name in cls.__dataclass_fields__ if name in config}
        values.update({key: value for key, value in overrides.items() if value is not None})
        return cls(**values)


@dataclass
class FetchResult:
    """Outcome of fetching one URL.

    outcome: "ok" (html is set), "skipped" (not usable, do not retry) or
             "failed" (network/HTTP problem, may be retried).
    """

    outcome: Literal["ok", "skipped", "failed"]
    url: str
    reason: str | None = None
    html: str | None = None
    final_url: str | None = None
    http_status: int | None = None
    content_type: str | None = None
    encoding: str | None = None
    # Added for the live /analyze (Part 9 B-1); the collector ignores them.
    redirect_hosts: list[str] = field(default_factory=list)  # every hop's host, in order
    content_disposition: str | None = None  # "attachment; filename=..." = a download
    blocked: bool = False  # refused because a URL / redirect / DNS answer is not public
    fetch_ms: float = 0.0


# ---- helpers -----------------------------------------------------------------------


def _is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """False for loopback, private, link-local, reserved, multicast ... (not is_global)."""
    address = getattr(address, "ipv4_mapped", None) or address  # ::ffff:127.0.0.1
    return address.is_global and not address.is_multicast


def resolve_addresses(host: str, port: int | None) -> list[str]:
    """Every IP address ``host`` resolves to (getaddrinfo, the resolver httpx uses too)."""
    infos = socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]).split("%")[0] for info in infos})


def check_host_allowed(url: str, resolve: bool = False) -> None:
    """Refuse localhost and private/link-local IP addresses (e.g. your router at 192.168.1.1).

    A malicious feed entry or redirect could otherwise make the collector send
    requests into your own network. With ``resolve=True`` (the live API) the
    hostname is also resolved and refused if ANY address is not public - this
    catches ``evil.example -> 10.0.0.5`` and numeric tricks like ``http://2130706433/``.
    Residual risk (documented): DNS rebinding between this lookup and httpx's own
    connect; the short timeout and the GET-only, no-JS policy limit what it could do.
    A name that does not resolve is left to httpx (it then fails as "unreachable").
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost") or not host:
        raise BlockedHostError(f"blocked host {host or '(none)'!r}")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None  # a normal hostname
    if address is not None:
        if not _is_public(address):
            raise BlockedHostError(f"blocked non-public address {host}")
        return
    if not resolve:
        return
    try:
        port = parts.port
    except ValueError:
        port = None
    try:
        resolved = resolve_addresses(host, port)
    except (OSError, UnicodeError):
        return
    for value in resolved:
        if not _is_public(ipaddress.ip_address(value)):
            raise BlockedHostError(f"blocked: {host} resolves to non-public address {value}")


def mime_type(content_type: str | None) -> str:
    """'text/html; charset=UTF-8' -> 'text/html'."""
    return (content_type or "").split(";")[0].strip().lower()


def charset_from_header(content_type: str | None) -> str | None:
    """'text/html; charset=UTF-8' -> 'UTF-8' (None if no charset is given)."""
    for part in (content_type or "").split(";")[1:]:
        key, _, value = part.partition("=")
        if key.strip().lower() == "charset":
            return value.strip().strip("\"'") or None
    return None


def decode_html(body: bytes, content_type: str | None = None) -> tuple[str, str]:
    """Turn raw bytes into text. Returns (text, encoding_used).

    Order: byte-order mark -> charset from the HTTP header -> <meta charset>
    in the first 4 KB -> UTF-8 with replacement characters (never crashes).
    An unknown or wrong charset is skipped instead of producing an error.
    """
    if body.startswith(codecs.BOM_UTF8):
        return body[len(codecs.BOM_UTF8) :].decode("utf-8", errors="replace"), "utf-8"

    meta = META_CHARSET.search(body[:4096])
    declared = [charset_from_header(content_type), meta.group(1).decode("ascii") if meta else None]
    for name in declared:
        if not name:
            continue
        try:
            encoding = codecs.lookup(name).name
            return body.decode(encoding), encoding
        except (LookupError, UnicodeDecodeError):
            continue  # unknown name, or the page lied about its charset
    return body.decode("utf-8", errors="replace"), "utf-8"


def in_docker() -> bool:
    """True inside a container (Docker creates /.dockerenv; our image also sets C2_IN_DOCKER)."""
    return os.environ.get("C2_IN_DOCKER") == "1" or Path("/.dockerenv").exists()


@dataclass
class RateLimiter:
    """Politeness: at most ``rate_per_second`` requests overall and at least
    ``per_host_delay`` seconds between two requests to the same host.

    ``clock`` and ``sleep`` can be replaced in tests so nothing really waits.
    """

    rate_per_second: float
    per_host_delay: float
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    _last_request: float = float("-inf")
    _last_by_host: dict[str, float] = field(default_factory=dict)

    def wait(self, host: str) -> float:
        """Sleep until a request to ``host`` is allowed; returns seconds waited."""
        now = self.clock()
        ready = max(
            self._last_request + 1 / self.rate_per_second,
            self._last_by_host.get(host, float("-inf")) + self.per_host_delay,
        )
        waited = max(0.0, ready - now)
        if waited:
            self.sleep(waited)
        self._last_request = self._last_by_host[host] = now + waited
        return waited


# ---- static mode ---------------------------------------------------------------------


class StaticFetcher:
    """Download a page's HTML with a single GET request (no JavaScript)."""

    mode = "static"

    def __init__(
        self,
        settings: FetchSettings | None = None,
        transport: httpx.BaseTransport | None = None,
        limiter: RateLimiter | None = None,
    ) -> None:
        self.settings = settings or FetchSettings.from_config()
        s = self.settings
        self.limiter = limiter or RateLimiter(s.rate_per_second, s.per_host_delay_seconds)
        self.client = httpx.Client(
            follow_redirects=True,
            max_redirects=s.max_redirects,
            timeout=s.timeout_seconds,
            headers={
                "User-Agent": s.user_agent,
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
                "Accept-Language": s.accept_language,
            },
            # Runs before every request, including each redirect hop.
            event_hooks={
                "request": [
                    lambda request: check_host_allowed(str(request.url), resolve=s.resolve_dns)
                ]
            },
            transport=transport,  # tests pass httpx.MockTransport here
        )

    def fetch(self, url: str) -> FetchResult:
        started = time.perf_counter()
        result = self._fetch(url)
        result.fetch_ms = round((time.perf_counter() - started) * 1000, 1)
        return result

    def _fetch(self, url: str) -> FetchResult:
        try:
            check_host_allowed(url, resolve=self.settings.resolve_dns)
            self.limiter.wait(extract_domain(url) or url)
            total = self.settings.total_timeout_seconds
            deadline = time.perf_counter() + total if total else None
            with self.client.stream("GET", url) as response:
                return self._read(url, response, deadline)
        except BlockedHostError as error:
            return FetchResult("skipped", url, reason=str(error), blocked=True)
        except httpx.TooManyRedirects:
            return FetchResult(
                "failed", url, reason=f"more than {self.settings.max_redirects} redirects"
            )
        except httpx.TimeoutException:
            return FetchResult(
                "failed", url, reason=f"timeout after {self.settings.timeout_seconds}s"
            )
        except (httpx.HTTPError, httpx.InvalidURL) as error:
            return FetchResult("failed", url, reason=f"{type(error).__name__}: {error}")

    def _read(
        self, url: str, response: httpx.Response, deadline: float | None = None
    ) -> FetchResult:
        content_type = response.headers.get("content-type")
        hops = [*response.history, response]
        info = {
            "final_url": str(response.url),
            "http_status": response.status_code,
            "content_type": content_type,
            "redirect_hosts": [hop.url.host for hop in hops],
            "content_disposition": response.headers.get("content-disposition"),
        }
        if not response.is_success:
            return FetchResult("failed", url, reason=f"HTTP {response.status_code}", **info)
        if mime_type(content_type) not in HTML_TYPES:
            reason = f"not HTML (content-type: {mime_type(content_type) or 'missing'})"
            return FetchResult("skipped", url, reason=reason, **info)

        limit = self.settings.max_bytes
        too_large = FetchResult("skipped", url, reason=f"larger than {limit} bytes", **info)
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            return too_large  # the server told us the size up front

        body = bytearray()
        for chunk in response.iter_bytes():  # streamed: stop as soon as it is too big
            body += chunk
            if len(body) > limit:
                return too_large
            if deadline is not None and time.perf_counter() > deadline:
                reason = f"timeout: body not received within {self.settings.total_timeout_seconds}s"
                return FetchResult("failed", url, reason=reason, **info)

        html, encoding = decode_html(bytes(body), content_type)
        return FetchResult("ok", url, html=html, encoding=encoding, **info)

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> StaticFetcher:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


# ---- rendered mode (optional Playwright) ----------------------------------------------


class RenderedFetcher:
    """Load the page in headless Chromium, run its JS, then save the resulting DOM."""

    mode = "rendered"

    def __init__(self, settings: FetchSettings | None = None) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise RuntimeError(
                "Rendered mode needs Playwright, which is only installed in the fetcher "
                "Docker image. See README 'How to collect samples'."
            ) from None

        print(RENDERED_WARNING)
        if not in_docker():
            print("WARNING: you do not appear to be inside Docker!")

        self.settings = settings or FetchSettings.from_config()
        s = self.settings
        self.limiter = RateLimiter(s.rate_per_second, s.per_host_delay_seconds)
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=True)
        self._context = self._browser.new_context(
            accept_downloads=False,  # downloads are cancelled
            permissions=[],  # no camera, location, notifications, clipboard...
            user_agent=s.user_agent,
            extra_http_headers={"Accept-Language": s.accept_language},
        )
        self._context.route("**/*", self._filter_request)

    def _filter_request(self, route) -> None:
        """Block media/fonts/websockets, local-network hosts and file-download responses."""
        request = route.request
        if request.resource_type in ("media", "font", "websocket"):
            route.abort()
            return
        try:
            check_host_allowed(request.url)
        except BlockedHostError:
            route.abort()
            return
        response = route.fetch()
        disposition = response.headers.get("content-disposition", "").lower()
        if mime_type(response.headers.get("content-type")) in DOWNLOAD_TYPES or (
            "attachment" in disposition
        ):
            route.abort()
            return
        route.fulfill(response=response)

    def fetch(self, url: str) -> FetchResult:
        from playwright.sync_api import Error as PlaywrightError

        try:
            check_host_allowed(url)
        except BlockedHostError as error:
            return FetchResult("skipped", url, reason=str(error))
        self.limiter.wait(extract_domain(url) or url)

        page = self._context.new_page()
        try:
            response = page.goto(
                url, wait_until="domcontentloaded", timeout=self.settings.rendered_timeout_ms
            )
            if response is None:
                return FetchResult("failed", url, reason="no response")
            content_type = response.headers.get("content-type")
            info = {
                "final_url": page.url,
                "http_status": response.status,
                "content_type": content_type,
            }
            if not 200 <= response.status < 300:
                return FetchResult("failed", url, reason=f"HTTP {response.status}", **info)
            if mime_type(content_type) not in HTML_TYPES:
                reason = f"not HTML (content-type: {mime_type(content_type) or 'missing'})"
                return FetchResult("skipped", url, reason=reason, **info)

            page.wait_for_timeout(self.settings.rendered_wait_ms)  # let scripts build the page
            html = page.content()
            info["final_url"] = page.url  # JS may have redirected meanwhile
            if len(html.encode("utf-8")) > self.settings.max_bytes:
                return FetchResult("skipped", url, reason="rendered page too large", **info)
            return FetchResult("ok", url, html=html, encoding="utf-8", **info)
        except PlaywrightError as error:
            return FetchResult("failed", url, reason=f"browser error: {error}".splitlines()[0])
        finally:
            page.close()

    def close(self) -> None:
        self._context.close()
        self._browser.close()
        self._playwright.stop()

    def __enter__(self) -> RenderedFetcher:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def make_fetcher(mode: str = "static", rate: float | None = None):
    """Create the fetcher for ``mode`` ("static" or "rendered")."""
    settings = FetchSettings.from_config(rate_per_second=rate)
    if mode == "static":
        return StaticFetcher(settings)
    if mode == "rendered":
        return RenderedFetcher(settings)
    raise ValueError(f"unknown mode {mode!r}; use 'static' or 'rendered'")
