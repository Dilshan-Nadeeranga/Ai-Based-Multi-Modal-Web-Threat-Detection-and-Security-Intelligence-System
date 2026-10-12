from __future__ import annotations

import socket

import pytest

from app.schemas.capture_schema import CaptureErrorCode
from app.services.url_safety import UrlSafetyPolicy, is_social_media_host


def resolver_for(answers: dict[str, list[str]]):
    """Fake getaddrinfo: no DNS traffic in tests."""

    def resolve(host, port, **kwargs):
        if host not in answers:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in answers[host]]

    return resolve


POLICY = UrlSafetyPolicy(resolver=resolver_for({
    "example.com": ["93.184.215.14"],
    "rebind.example.org": ["93.184.215.14", "10.0.0.5"],
    "internal.example.net": ["192.168.1.10"],
}))


def test_public_url_allowed() -> None:
    verdict = POLICY.check("https://example.com/login")
    assert verdict.allowed and verdict.code is None


@pytest.mark.parametrize(("url", "code"), [
    ("ftp://example.com/file", CaptureErrorCode.UNSUPPORTED_SCHEME),
    ("javascript:alert(1)", CaptureErrorCode.UNSUPPORTED_SCHEME),
    ("file:///C:/Windows/win.ini", CaptureErrorCode.UNSUPPORTED_SCHEME),
    ("https://", CaptureErrorCode.INVALID_URL),
    ("https://user:secret@example.com/", CaptureErrorCode.INVALID_URL),
    ("https://www.facebook.com/somepage", CaptureErrorCode.SOCIAL_MEDIA_URL),
    ("https://m.youtube.com/watch?v=x", CaptureErrorCode.SOCIAL_MEDIA_URL),
    ("http://localhost:8000/", CaptureErrorCode.PRIVATE_ADDRESS),
    ("http://printer.local/", CaptureErrorCode.PRIVATE_ADDRESS),
    ("http://127.0.0.1/", CaptureErrorCode.PRIVATE_ADDRESS),
    ("http://169.254.169.254/latest/meta-data", CaptureErrorCode.PRIVATE_ADDRESS),
    ("http://[::1]/", CaptureErrorCode.PRIVATE_ADDRESS),
    ("http://10.1.2.3/", CaptureErrorCode.PRIVATE_ADDRESS),
    ("https://internal.example.net/", CaptureErrorCode.PRIVATE_ADDRESS),
    ("https://rebind.example.org/", CaptureErrorCode.PRIVATE_ADDRESS),
    ("https://no-such-host.example.invalid/", CaptureErrorCode.NAME_NOT_RESOLVED),
])
def test_refused_urls(url: str, code: CaptureErrorCode) -> None:
    verdict = POLICY.check(url)
    assert not verdict.allowed
    assert verdict.code is code


def test_check_without_resolving_skips_dns() -> None:
    assert POLICY.check("https://no-such-host.example.invalid/", resolve=False).allowed
    assert not POLICY.check("http://192.168.0.1/", resolve=False).allowed


def test_connect_address_returns_checked_ip() -> None:
    decision = POLICY.connect_address("example.com", 443)
    assert decision.allowed and decision.address == "93.184.215.14"
    assert POLICY.connect_address("[::1]", 80).code is CaptureErrorCode.PRIVATE_ADDRESS
    assert POLICY.connect_address("WWW.FACEBOOK.COM.", 443).code is CaptureErrorCode.SOCIAL_MEDIA_URL


def test_allowlist_and_switches() -> None:
    allow_loopback = UrlSafetyPolicy(private_allowlist=frozenset({"127.0.0.1"}))
    assert allow_loopback.check("http://127.0.0.1:9000/").allowed
    assert not allow_loopback.check("http://localhost:9000/").allowed
    social_ok = UrlSafetyPolicy(block_social_media=False, resolver=resolver_for({"www.facebook.com": ["157.240.1.35"]}))
    assert social_ok.check("https://www.facebook.com/").allowed


def test_social_media_hosts() -> None:
    assert is_social_media_host("web.facebook.com")
    assert is_social_media_host("t.me")
    assert not is_social_media_host("notfacebook.com")
    assert not is_social_media_host("example.com")
