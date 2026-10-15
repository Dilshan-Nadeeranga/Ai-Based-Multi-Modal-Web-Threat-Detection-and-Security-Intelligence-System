"""HTTP-level safety nets for the API: request size limit and security headers.

Part 9 groundwork (added with the developer inspector, after Part 2).

Why: C2 receives HTML from strangers. Two cheap protections apply to every
request, before any route code runs:

* ``BodySizeLimitMiddleware`` - a body larger than the limit (5 MB) gets
  ``413`` without being read into memory. Both the ``Content-Length`` header
  and the bytes actually received are checked, because a client can send a
  chunked body without a length (or lie about it).
* ``SecurityHeadersMiddleware`` - ``X-Content-Type-Options: nosniff`` (the
  browser must never guess that a JSON/text response is HTML and render it)
  and ``Referrer-Policy: no-referrer`` on every response, unless the route
  already set them.

Both are plain ASGI middlewares (no request buffering, no extra dependencies).
"""

from __future__ import annotations

import json

from fastapi import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

DEFAULT_HEADERS = {
    b"x-content-type-options": b"nosniff",
    b"referrer-policy": b"no-referrer",
}


async def _send_413(send: Send, max_bytes: int) -> None:
    body = json.dumps(
        {"detail": f"request body larger than {max_bytes // (1024 * 1024)} MB"}
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                *DEFAULT_HEADERS.items(),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class BodySizeLimitMiddleware:
    """Reject request bodies larger than ``max_bytes`` with 413."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_bytes:
            await _send_413(send, self.max_bytes)  # refused before reading anything
            return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    # HTTPException passes through FastAPI's body parsing unchanged
                    # (other errors would be turned into a 400 there).
                    raise HTTPException(status_code=413)
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except HTTPException as error:
            if error.status_code != 413 or response_started:
                raise
            await _send_413(send, self.max_bytes)


class SecurityHeadersMiddleware:
    """Add nosniff + no-referrer to every HTTP response that does not set them."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                headers += [(k, v) for k, v in DEFAULT_HEADERS.items() if k not in present]
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)
