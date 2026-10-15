from __future__ import annotations

import httpx

from app.services.link_expander import expand_short_link
from app.services.url_safety import UrlSafetyPolicy
from tests.test_url_safety import resolver_for

POLICY = UrlSafetyPolicy(resolver=resolver_for({
    "bit.ly": ["67.199.248.10"],
    "meta.ly": ["67.199.248.11"],
    "landing.example.com": ["93.184.215.14"],
    "evil.example.net": ["10.0.0.7"],
}))

ROUTES = {
    "https://bit.ly/abc": (301, {"location": "https://landing.example.com/login"}, b""),
    "https://landing.example.com/login": (200, {"content-type": "text/html"}, b"<html>login</html>"),
    "https://meta.ly/x": (200, {"content-type": "text/html"},
                          b'<html><meta http-equiv="refresh" content="0; url=https://landing.example.com/login"></html>'),
    "https://bit.ly/private": (302, {"location": "https://evil.example.net/"}, b""),
    "https://bit.ly/challenge": (403, {"content-type": "text/html"}, b"<title>Just a moment...</title>"),
}


def transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        status, headers, body = ROUTES[str(request.url)]
        return httpx.Response(status, headers=headers, content=body)

    return httpx.MockTransport(handler)


def test_follows_http_redirect() -> None:
    result = expand_short_link("https://bit.ly/abc", POLICY, transport=transport())
    assert result["resolved"] and result["expanded_url"] == "https://landing.example.com/login"
    assert [hop["status"] for hop in result["hops"]] == [301, 200]


def test_follows_meta_refresh() -> None:
    result = expand_short_link("https://meta.ly/x", POLICY, transport=transport())
    assert result["expanded_url"] == "https://landing.example.com/login"


def test_stops_before_private_address() -> None:
    result = expand_short_link("https://bit.ly/private", POLICY, transport=transport())
    assert result["expanded_url"] == "https://evil.example.net/"
    assert result["hops"] == [{"url": "https://bit.ly/private", "status": 302}]
    assert "PRIVATE_ADDRESS" in result["stopped_reason"]


def test_unresolved_when_shortener_blocks() -> None:
    result = expand_short_link("https://bit.ly/challenge", POLICY, transport=transport())
    assert not result["resolved"] and result["expanded_url"] is None
    assert "403" in result["stopped_reason"]
