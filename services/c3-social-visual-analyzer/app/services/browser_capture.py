"""Open one destination URL in an isolated headless browser and capture it.

Isolation:

* all browser traffic goes through :class:`GuardProxy`, which checks every
  connection (redirect hops, pop-ups, iframes and sub-resources included)
  against :class:`UrlSafetyPolicy`, so pages cannot reach the local network or
  social-media platforms; WebRTC is limited to proxied connections;
* a fresh browser context per URL (no cookies, storage or cache shared between
  URLs), closed afterwards;
* downloads refused, no permissions granted, service workers blocked, pop-up
  windows closed, JavaScript dialogs dismissed;
* the page is never typed into, clicked or submitted.

Run real scam URLs only from a disposable VM or Windows Sandbox.
"""

from __future__ import annotations

import logging
import re
import time
from contextlib import ExitStack
from dataclasses import dataclass, field
from types import TracebackType
from typing import Protocol

from app.config import Settings
from app.exceptions import BrowserUnavailableError
from app.schemas.capture_schema import CaptureErrorCode, RedirectHop
from app.services.capture_proxy import PROXY_HEADER, GuardProxy
from app.services.url_safety import UrlSafetyPolicy
from app.utils.url_utils import url_hostname

logger = logging.getLogger(__name__)

_LAUNCH_ARGS = [
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-default-apps",
    "--no-first-run",
    "--mute-audio",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--disable-features=Translate,MediaRouter,OptimizationHints,DnsOverHttps",
]
_NETWORK_IDLE_MS = 5000
_PROXY_FAILURES = re.compile(r"ERR_TUNNEL_CONNECTION_FAILED|ERR_PROXY|ERR_EMPTY_RESPONSE|ERR_CONNECTION_CLOSED")
_BROWSER_ERRORS: list[tuple[re.Pattern[str], CaptureErrorCode]] = [
    (re.compile(r"ERR_NAME_NOT_RESOLVED|ENOTFOUND|EAI_AGAIN|getaddrinfo", re.I), CaptureErrorCode.NAME_NOT_RESOLVED),
    (re.compile(r"ERR_CERT|ERR_SSL|certificate|self[- ]signed|SSL|TLS|EPROTO", re.I), CaptureErrorCode.TLS_ERROR),
    (re.compile(r"ERR_TOO_MANY_REDIRECTS|redirect", re.I), CaptureErrorCode.TOO_MANY_REDIRECTS),
    (re.compile(r"ERR_TIMED_OUT|ETIMEDOUT|Timeout .*exceeded|timed out", re.I), CaptureErrorCode.TIMEOUT),
    (re.compile(r"ERR_CONNECTION|ERR_ADDRESS|ERR_EMPTY_RESPONSE|ERR_NETWORK|ERR_INTERNET|ERR_TUNNEL|ERR_PROXY|"
                r"ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|socket hang up", re.I),
     CaptureErrorCode.CONNECTION_FAILED),
    (re.compile(r"ERR_UNSAFE_PORT|ERR_INVALID_URL", re.I), CaptureErrorCode.INVALID_URL),
    (re.compile(r"Download is starting|ERR_ABORTED", re.I), CaptureErrorCode.DOWNLOAD_BLOCKED),
]


@dataclass
class PageCaptureResult:
    final_url: str | None = None
    http_status: int | None = None
    title: str | None = None
    png: bytes | None = None
    truncated: bool = False
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    blocked_requests: int = 0
    error_code: CaptureErrorCode | None = None
    error_message: str | None = None
    browser: str | None = None


class PageCapturer(Protocol):
    def capture(self, url: str) -> PageCaptureResult: ...


def classify_browser_error(message: str) -> CaptureErrorCode:
    for pattern, code in _BROWSER_ERRORS:
        if pattern.search(message):
            return code
    return CaptureErrorCode.BROWSER_ERROR


def short_error(message: str, limit: int = 300) -> str:
    """First line of a browser error, without Playwright's call log."""
    first = (message or "").strip().splitlines()[0] if (message or "").strip() else "unknown error"
    return first[:limit]


class PlaywrightCapturer:
    """Context manager owning the guard proxy and one Chromium process; one fresh context per URL."""

    def __init__(self, settings: Settings, policy: UrlSafetyPolicy | None = None) -> None:
        self.settings = settings
        self.policy = policy or UrlSafetyPolicy.from_settings(settings)
        self._stack: ExitStack | None = None
        self._proxy: GuardProxy | None = None
        self._browser = None
        self.browser_name: str | None = None

    def __enter__(self) -> "PlaywrightCapturer":
        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise BrowserUnavailableError() from exc
        stack = ExitStack()
        try:
            self._proxy = stack.enter_context(GuardProxy(self.policy, self.settings.web_capture_timeout_seconds))
            playwright = stack.enter_context(sync_playwright())
            self._browser = playwright.chromium.launch(
                headless=True,
                chromium_sandbox=True,
                args=_LAUNCH_ARGS,
                proxy={"server": self._proxy.url, "bypass": "<-loopback>"},
            )
            stack.callback(self._browser.close)
        except PlaywrightError as exc:
            logger.error("Could not start the capture browser: %s", short_error(str(exc)))
            stack.close()
            self._browser = None
            raise BrowserUnavailableError() from exc
        self._stack = stack
        self.browser_name = f"chromium {self._browser.version}"
        logger.info("Capture browser started: %s", self.browser_name)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        stack, self._stack, self._browser, self._proxy = self._stack, None, None, None
        if stack is not None:
            stack.close()

    # ------------------------------------------------------------------ capture

    def capture(self, url: str) -> PageCaptureResult:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeout

        if self._browser is None or self._proxy is None:
            raise BrowserUnavailableError("The capture browser is not started.")
        result = PageCaptureResult(browser=self.browser_name)
        verdict = self.policy.check(url, resolve=False)
        if not verdict.allowed:
            return self._failed(result, verdict.code, verdict.message or "URL refused")

        settings = self.settings
        timeout_ms = int(settings.web_capture_timeout_seconds * 1000)
        deadline = time.monotonic() + settings.web_capture_timeout_seconds
        self._proxy.reset_events()
        context = self._browser.new_context(
            viewport={"width": settings.web_capture_viewport_width, "height": settings.web_capture_viewport_height},
            accept_downloads=False,
            java_script_enabled=settings.web_capture_javascript,
            service_workers="block",
            permissions=[],
            ignore_https_errors=False,
            user_agent=settings.web_capture_user_agent or None,
            locale="en-US",
        )
        try:
            context.set_default_timeout(timeout_ms)
            page = context.new_page()
            context.on("page", lambda popup: popup.close() if popup is not page else None)
            page.on("dialog", lambda dialog: dialog.dismiss())

            try:
                response = page.goto(verdict.url, wait_until="domcontentloaded", timeout=timeout_ms)
            except PlaywrightTimeout as exc:
                return self._failed(result, CaptureErrorCode.TIMEOUT, short_error(str(exc)))
            except PlaywrightError as exc:
                return self._navigation_error(result, short_error(str(exc)))

            refused = self._refused_by_proxy(response)
            if refused is not None:
                result.redirect_chain = _redirect_chain(response)
                return self._failed(result, *refused)

            self._settle(page, deadline, PlaywrightError)
            final_url = page.url
            if final_url.startswith("chrome-error://"):
                return self._navigation_error(result, "the page failed to load after navigation")

            result.redirect_chain = _redirect_chain(response)
            result.http_status = response.status if response is not None else None
            result.final_url = final_url
            try:
                result.title = (page.title() or "").strip()[: settings.web_capture_max_title_length] or None
            except PlaywrightError:
                result.title = None
            try:
                result.png, result.truncated = self._screenshot(page, deadline)
            except PlaywrightError as exc:
                result.png = None
                result.error_code = CaptureErrorCode.SCREENSHOT_FAILED
                result.error_message = short_error(str(exc))
            result.blocked_requests = len(self._proxy.events())
            return result
        finally:
            context.close()

    def _refused_by_proxy(self, response) -> tuple[CaptureErrorCode, str] | None:
        if response is None:
            return None
        code = response.headers.get(PROXY_HEADER.lower())
        if not code:
            return None
        event = self._proxy.event_for(url_hostname(response.url))
        try:
            error = CaptureErrorCode(code)
        except ValueError:
            error = CaptureErrorCode.CONNECTION_FAILED
        return error, event.message if event else f"refused by the capture proxy ({code})"

    def _navigation_error(self, result: PageCaptureResult, message: str) -> PageCaptureResult:
        if _PROXY_FAILURES.search(message) or "chrome-error" in message or "failed to load" in message:
            event = self._proxy.event_for(None)
            if event is not None:
                return self._failed(result, event.code, event.message)
        return self._failed(result, classify_browser_error(message), message)

    @staticmethod
    def _failed(result: PageCaptureResult, code: CaptureErrorCode, message: str) -> PageCaptureResult:
        result.error_code = code
        result.error_message = message[:500]
        result.png = None
        return result

    def _settle(self, page, deadline: float, error_type: type[Exception]) -> None:
        for state, cap_ms in (("load", None), ("networkidle", _NETWORK_IDLE_MS)):
            remaining = int((deadline - time.monotonic()) * 1000)
            if remaining <= 0:
                return
            try:
                page.wait_for_load_state(state, timeout=min(remaining, cap_ms) if cap_ms else remaining)
            except error_type:
                continue
        settle_ms = int(self.settings.web_capture_settle_seconds * 1000)
        remaining = int((deadline - time.monotonic()) * 1000)
        if settle_ms and remaining > 0:
            page.wait_for_timeout(min(settle_ms, remaining))

    def _screenshot(self, page, deadline: float) -> tuple[bytes, bool]:
        settings = self.settings
        timeout_ms = max(5000, int((deadline - time.monotonic()) * 1000))
        try:
            height = int(page.evaluate(
                "() => Math.max(document.documentElement ? document.documentElement.scrollHeight : 0,"
                " document.body ? document.body.scrollHeight : 0)"
            ))
        except Exception:  # noqa: BLE001 - page may forbid script evaluation
            height = 0
        if height > settings.web_capture_max_height:
            clip = {"x": 0, "y": 0, "width": settings.web_capture_viewport_width,
                    "height": settings.web_capture_max_height}
            return page.screenshot(full_page=True, clip=clip, type="png", animations="disabled",
                                   timeout=timeout_ms), True
        return page.screenshot(full_page=True, type="png", animations="disabled", timeout=timeout_ms), False


def _redirect_chain(response) -> list[RedirectHop]:
    """HTTP redirect hops of the last main-frame navigation, first request first."""
    if response is None:
        return []
    hops: list[RedirectHop] = []
    request = response.request
    while request is not None:
        hop_response = request.response()
        hops.append(RedirectHop(url=request.url, status=hop_response.status if hop_response else None))
        request = request.redirected_from
    hops.reverse()
    return hops
