"""Decide whether a destination may be opened by the capture browser.

:meth:`UrlSafetyPolicy.check` validates a URL before it is opened, and
:meth:`UrlSafetyPolicy.connect_address` is used by the capture proxy for every
connection the browser makes (redirects and sub-resources included), so a scam
page cannot reach the local network (SSRF) or social-media platforms (scraping
them is out of scope). Host names are resolved only to apply this check and to
connect; the addresses are not stored.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.schemas.capture_schema import CaptureErrorCode
from app.utils.url_utils import normalize_evidence_url, url_hostname

SOCIAL_MEDIA_DOMAINS = frozenset({
    "facebook.com", "fb.com", "fb.me", "fb.watch", "messenger.com",
    "instagram.com", "threads.net", "x.com", "twitter.com",
    "tiktok.com", "linkedin.com", "youtube.com", "youtu.be",
    "reddit.com", "redd.it", "whatsapp.com", "wa.me", "t.me", "telegram.org", "telegram.me",
})
_LOCAL_NAMES = (".localhost", ".local", ".internal", ".home.arpa", ".lan")

Resolver = Callable[..., list]


@dataclass(frozen=True)
class UrlVerdict:
    url: str
    allowed: bool
    code: CaptureErrorCode | None = None
    message: str | None = None


@dataclass(frozen=True)
class HostDecision:
    address: str | None
    code: CaptureErrorCode | None = None
    message: str | None = None

    @property
    def allowed(self) -> bool:
        return self.code is None


def is_social_media_host(host: str) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in SOCIAL_MEDIA_DOMAINS)


class UrlSafetyPolicy:
    def __init__(
        self,
        *,
        allow_private: bool = False,
        private_allowlist: frozenset[str] = frozenset(),
        block_social_media: bool = True,
        resolver: Resolver | None = None,
    ) -> None:
        self.allow_private = allow_private
        self.private_allowlist = frozenset(host.lower() for host in private_allowlist)
        self.block_social_media = block_social_media
        self._resolver = resolver or socket.getaddrinfo

    @classmethod
    def from_settings(cls, settings) -> "UrlSafetyPolicy":
        return cls(
            allow_private=settings.web_capture_allow_private_hosts,
            block_social_media=settings.web_capture_block_social_media,
        )

    def check(self, url: str, *, resolve: bool = True) -> UrlVerdict:
        """Validate a URL to be opened; with ``resolve`` the host must resolve to public addresses."""
        scheme = urlsplit(url).scheme.lower() if isinstance(url, str) else ""
        if scheme and scheme not in ("http", "https"):
            return UrlVerdict(url, False, CaptureErrorCode.UNSUPPORTED_SCHEME, f"scheme '{scheme}' is not opened")
        try:
            url = normalize_evidence_url(url)
            parts = urlsplit(url)
            port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
        except ValueError as exc:
            return UrlVerdict(str(url), False, CaptureErrorCode.INVALID_URL, str(exc))
        if parts.username or parts.password:
            return UrlVerdict(url, False, CaptureErrorCode.INVALID_URL, "URLs with embedded credentials are not opened")
        decision = self._decide(url_hostname(url) or "", port, resolve)
        return UrlVerdict(url, decision.allowed, decision.code, decision.message)

    def connect_address(self, host: str, port: int) -> HostDecision:
        """Address to connect to for ``host:port``, or the reason the connection is refused."""
        return self._decide(host.strip("[]").rstrip(".").lower(), port, resolve=True)

    def _decide(self, host: str, port: int, resolve: bool) -> HostDecision:
        if self.block_social_media and is_social_media_host(host):
            return HostDecision(None, CaptureErrorCode.SOCIAL_MEDIA_URL,
                                f"{host} is a social-media platform; it is not captured")
        trusted = self.allow_private or host in self.private_allowlist
        if not trusted and (host == "localhost" or host.endswith(_LOCAL_NAMES)):
            return HostDecision(None, CaptureErrorCode.PRIVATE_ADDRESS, f"{host} is a local host name")

        literal = _ip_literal(host)
        if literal is not None:
            if not trusted and not literal.is_global:
                return HostDecision(None, CaptureErrorCode.PRIVATE_ADDRESS, f"{host} is not a public address")
            return HostDecision(str(literal))
        if not resolve:
            return HostDecision(None)

        try:
            infos = self._resolver(host, port, type=socket.SOCK_STREAM)
        except (socket.gaierror, UnicodeError, OSError) as exc:
            return HostDecision(None, CaptureErrorCode.NAME_NOT_RESOLVED, f"{host} could not be resolved ({exc})")
        addresses = [_ip_literal(str(info[4][0]).split("%", 1)[0]) for info in infos]
        if not addresses or any(a is None for a in addresses):
            return HostDecision(None, CaptureErrorCode.NAME_NOT_RESOLVED, f"{host} could not be resolved")
        if not trusted and any(not a.is_global for a in addresses):
            return HostDecision(None, CaptureErrorCode.PRIVATE_ADDRESS, f"{host} resolves to a non-public address")
        return HostDecision(str(addresses[0]))


def _ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None
