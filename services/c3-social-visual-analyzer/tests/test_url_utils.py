from __future__ import annotations

import pytest

from app.utils.url_utils import extract_urls, registered_domain, unwrap_link, url_hostname


def test_extract_urls_from_post_text() -> None:
    text = ("Claim your prize at https://prize.example.com/win?id=1. Also see www.example.org/info, "
            "(http://example.net/a) and again https://prize.example.com/win?id=1")
    assert extract_urls(text) == [
        "https://prize.example.com/win?id=1",
        "https://www.example.org/info",
        "http://example.net/a",
    ]


@pytest.mark.parametrize("text", [None, "", "no links here", "ftp://example.com/file", "mailto:a@example.com"])
def test_extract_urls_ignores_non_links(text) -> None:
    assert extract_urls(text) == []


def test_unwrap_facebook_click_tracker() -> None:
    wrapped = "https://l.facebook.com/l.php?u=https%3A%2F%2Fshop.example.com%2Foffer%3Fa%3D1&h=AT0"
    assert unwrap_link(wrapped) == "https://shop.example.com/offer?a=1"


@pytest.mark.parametrize("url", [
    "https://example.com/l.php?u=https%3A%2F%2Fother.example.org",
    "https://l.facebook.com/other?u=https%3A%2F%2Fexample.org",
    "https://l.facebook.com/l.php?u=javascript%3Aalert(1)",
])
def test_unwrap_leaves_other_links(url: str) -> None:
    assert unwrap_link(url) == url


def test_hostname_and_registered_domain() -> None:
    assert url_hostname("https://Login.Example.CO.UK.:8443/x") == "login.example.co.uk"
    assert registered_domain("login.example.co.uk") == "example.co.uk"
    assert registered_domain("a.b.example.com") == "example.com"
    assert registered_domain("203.0.113.5") == "203.0.113.5"
    assert registered_domain(None) is None
