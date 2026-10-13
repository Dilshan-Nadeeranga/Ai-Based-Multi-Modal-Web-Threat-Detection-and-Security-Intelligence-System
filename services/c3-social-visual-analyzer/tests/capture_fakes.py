"""Fake browser and resolver for web-capture tests (no browser, no network)."""

from __future__ import annotations

import socket

from PIL import Image

from app.schemas.capture_schema import CaptureErrorCode, RedirectHop
from app.services.browser_capture import PageCaptureResult
from app.services.url_safety import UrlSafetyPolicy
from tests.conftest import image_bytes

PUBLIC_IP = "93.184.215.14"


def fake_resolver(host, port, **kwargs):
    if host.endswith(".invalid"):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    ip = "10.0.0.7" if host.startswith("intranet.") else PUBLIC_IP
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]


def safe_policy() -> UrlSafetyPolicy:
    return UrlSafetyPolicy(resolver=fake_resolver)


def png(size: tuple[int, int] = (1366, 900)) -> bytes:
    return image_bytes(Image.new("RGB", size, (250, 250, 250)), "PNG")


class FakeCapturer:
    """Context manager standing in for PlaywrightCapturer."""

    instances: list["FakeCapturer"] = []

    def __init__(self, results: dict[str, PageCaptureResult] | None = None) -> None:
        self.results = results or {}
        self.opened: list[str] = []
        self.entered = False
        FakeCapturer.instances.append(self)

    def __enter__(self) -> "FakeCapturer":
        self.entered = True
        return self

    def __exit__(self, *exc) -> None:
        self.entered = False

    def capture(self, url: str) -> PageCaptureResult:
        self.opened.append(url)
        if url in self.results:
            return self.results[url]
        final = url.replace("://", "://www.", 1) if "://www." not in url else url
        return PageCaptureResult(
            final_url=final, http_status=200, title="Example Domain", png=png(),
            redirect_chain=[RedirectHop(url=url, status=301), RedirectHop(url=final, status=200)],
            browser="chromium test",
        )


def failure(code: CaptureErrorCode, message: str) -> PageCaptureResult:
    return PageCaptureResult(error_code=code, error_message=message, browser="chromium test")
