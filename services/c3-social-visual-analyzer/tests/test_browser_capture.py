"""Real headless Chromium against a local test server on 127.0.0.1 (no external sites).

Skipped when Playwright or its Chromium build is not installed.
"""

from __future__ import annotations

import io
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from PIL import Image

from app.config import Settings
from app.exceptions import BrowserUnavailableError
from app.schemas.capture_schema import CaptureErrorCode
from app.services.browser_capture import PlaywrightCapturer
from app.services.url_safety import UrlSafetyPolicy

pytest.importorskip("playwright.sync_api")

PAGES: dict[str, tuple[int, dict[str, str], str]] = {
    "/ok": (200, {}, "<html><head><title>Example OK Page</title></head><body><h1>Hello</h1></body></html>"),
    "/missing": (404, {}, "<html><head><title>Not Found</title></head><body>404</body></html>"),
    "/download": (200, {"Content-Type": "application/octet-stream",
                        "Content-Disposition": "attachment; filename=setup.exe"}, "MZ-not-a-real-program"),
    "/js-redirect": (200, {}, "<html><head><title>Wait</title></head><body>"
                              "<script>location.replace('/ok')</script></body></html>"),
    "/meta-refresh": (200, {}, "<html><head><meta http-equiv='refresh' content='0;url=/ok'>"
                               "<title>Refresh</title></head><body></body></html>"),
    "/tall": (200, {}, "<html><head><title>Tall</title></head>"
                       "<body style='margin:0'><div style='height:9000px;background:#ccd'></div></body></html>"),
    "/popup": (200, {}, "<html><head><title>Popup page</title></head><body>"
                        "<script>window.open('/ok'); alert('You won!');</script>text</body></html>"),
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        port = self.server.server_address[1]
        redirects = {
            "/redirect": "/hop2",
            "/hop2": "/ok",
            "/loop": "/loop",
            "/to-localhost": f"http://localhost:{port}/ok",
            "/to-social": "https://www.facebook.com/some.page",
        }
        if self.path in redirects:
            self.send_response(302 if self.path != "/hop2" else 301)
            self.send_header("Location", redirects[self.path])
            self.end_headers()
            return
        if self.path == "/slow":
            time.sleep(4)
        if self.path == "/iframe-private":
            body = (f"<html><head><title>Has iframe</title></head><body>"
                    f"<iframe src='http://localhost:{port}/ok'></iframe></body></html>")
            status, headers = 200, {}
        else:
            status, headers, body = PAGES.get(self.path, (200, {}, "<html><title>Slow</title></html>"))
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", headers.get("Content-Type", "text/html; charset=utf-8"))
        for name, value in headers.items():
            if name != "Content-Type":
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _unresolvable(*args, **kwargs):
    raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")


@pytest.fixture(scope="module")
def capturer(tmp_path_factory):
    settings = Settings(_env_file=None, data_dir=Path(tmp_path_factory.mktemp("cap")) / "data",
                        web_capture_timeout_seconds=3, web_capture_settle_seconds=0.2,
                        web_capture_max_height=3000)
    policy = UrlSafetyPolicy(private_allowlist=frozenset({"127.0.0.1"}), resolver=_unresolvable)
    try:
        with PlaywrightCapturer(settings, policy) as active:
            yield active
    except BrowserUnavailableError:
        pytest.skip("Chromium for Playwright is not installed (python -m playwright install chromium)")


def _png_size(png: bytes) -> tuple[int, int]:
    with Image.open(io.BytesIO(png)) as image:
        assert image.format == "PNG"
        return image.size


def test_plain_page(capturer, server) -> None:
    result = capturer.capture(f"{server}/ok")
    assert result.error_code is None
    assert result.final_url == f"{server}/ok"
    assert result.http_status == 200
    assert result.title == "Example OK Page"
    assert _png_size(result.png)[0] == 1366
    assert result.browser.startswith("chromium ")


def test_http_redirect_chain_recorded(capturer, server) -> None:
    result = capturer.capture(f"{server}/redirect")
    assert result.final_url == f"{server}/ok"
    assert [(hop.url, hop.status) for hop in result.redirect_chain] == [
        (f"{server}/redirect", 302), (f"{server}/hop2", 301), (f"{server}/ok", 200)]
    assert result.title == "Example OK Page"


@pytest.mark.parametrize("path", ["/js-redirect", "/meta-refresh"])
def test_client_side_redirects_followed(capturer, server, path: str) -> None:
    result = capturer.capture(f"{server}{path}")
    assert result.final_url == f"{server}/ok"
    assert result.title == "Example OK Page"


def test_redirect_into_private_host_is_blocked(capturer, server) -> None:
    result = capturer.capture(f"{server}/to-localhost")
    assert result.png is None
    assert result.error_code is CaptureErrorCode.PRIVATE_ADDRESS
    port = server.rsplit(":", 1)[1]
    assert [(hop.url, hop.status) for hop in result.redirect_chain] == [
        (f"{server}/to-localhost", 302), (f"http://localhost:{port}/ok", 403)]


def test_redirect_onto_social_media_is_not_followed(capturer, server) -> None:
    result = capturer.capture(f"{server}/to-social")
    assert result.png is None
    assert result.error_code is CaptureErrorCode.SOCIAL_MEDIA_URL


def test_http_404_still_screenshotted(capturer, server) -> None:
    result = capturer.capture(f"{server}/missing")
    assert result.http_status == 404
    assert result.png is not None and result.title == "Not Found"


def test_download_is_blocked(capturer, server) -> None:
    result = capturer.capture(f"{server}/download")
    assert result.png is None
    assert result.error_code is CaptureErrorCode.DOWNLOAD_BLOCKED


def test_tall_page_is_truncated(capturer, server) -> None:
    result = capturer.capture(f"{server}/tall")
    assert result.truncated is True
    assert _png_size(result.png) == (1366, 3000)


def test_popup_and_alert_do_not_block_capture(capturer, server) -> None:
    result = capturer.capture(f"{server}/popup")
    assert result.error_code is None
    assert result.title == "Popup page"


def test_private_iframe_is_refused_but_page_captured(capturer, server) -> None:
    result = capturer.capture(f"{server}/iframe-private")
    assert result.error_code is None and result.title == "Has iframe"
    assert result.blocked_requests >= 1


def test_non_http_scheme_never_opened(capturer) -> None:
    result = capturer.capture("file:///C:/Windows/win.ini")
    assert result.png is None
    assert result.error_code is CaptureErrorCode.UNSUPPORTED_SCHEME


def test_redirect_loop(capturer, server) -> None:
    result = capturer.capture(f"{server}/loop")
    assert result.png is None
    assert result.error_code is CaptureErrorCode.TOO_MANY_REDIRECTS


def test_timeout(capturer, server) -> None:
    result = capturer.capture(f"{server}/slow")
    assert result.png is None
    assert result.error_code is CaptureErrorCode.TIMEOUT


def test_connection_refused(capturer) -> None:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    result = capturer.capture(f"http://127.0.0.1:{port}/")
    assert result.png is None
    assert result.error_code is CaptureErrorCode.CONNECTION_FAILED


def test_unresolvable_host(capturer) -> None:
    result = capturer.capture("https://no-such-host.example.invalid/")
    assert result.png is None
    assert result.error_code is CaptureErrorCode.NAME_NOT_RESOLVED
