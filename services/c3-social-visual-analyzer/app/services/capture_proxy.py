"""Local guard proxy: every connection of the capture browser goes through it.

The browser is launched with this proxy (loopback included), so each request
-- the first navigation, every redirect hop, pop-ups, iframes, images,
scripts and XHR -- is checked with :meth:`UrlSafetyPolicy.connect_address`
before a connection is made, and the proxy connects to the exact address it
checked (no second DNS lookup by the browser). Refused or failed connections
are answered with an ``X-ScamTrace-Proxy: <code>`` header and recorded, so the
capturer can report why a page could not be loaded.

HTTPS is tunnelled with ``CONNECT`` (the proxy never sees page content);
plain HTTP is forwarded one request per connection.
"""

from __future__ import annotations

import logging
import selectors
import socket
import socketserver
import threading
from dataclasses import dataclass
from types import TracebackType
from urllib.parse import urlsplit

from app.schemas.capture_schema import CaptureErrorCode
from app.services.url_safety import UrlSafetyPolicy

logger = logging.getLogger(__name__)

PROXY_HEADER = "X-ScamTrace-Proxy"
_MAX_HEAD_BYTES = 64 * 1024
_CHUNK = 64 * 1024
_HOP_HEADERS = ("proxy-connection:", "proxy-authorization:", "connection:", "keep-alive:")


@dataclass(frozen=True)
class ProxyEvent:
    host: str
    port: int
    code: CaptureErrorCode
    message: str


class GuardProxy:
    def __init__(self, policy: UrlSafetyPolicy, connect_timeout: float, idle_timeout: float = 30.0) -> None:
        self.policy = policy
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self._events: list[ProxyEvent] = []
        self._lock = threading.Lock()
        self._server: socketserver.ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        if self._server is None:
            raise RuntimeError("proxy is not running")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "GuardProxy":
        proxy = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                proxy._handle(self.request)

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = False

        self._server = Server(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, name="capture-proxy", daemon=True)
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        self._server = None

    # ------------------------------------------------------------------ events

    def reset_events(self) -> None:
        with self._lock:
            self._events.clear()

    def events(self) -> list[ProxyEvent]:
        with self._lock:
            return list(self._events)

    def event_for(self, host: str | None) -> ProxyEvent | None:
        """Latest refusal/failure for ``host`` (or the latest of all when ``host`` is None)."""
        events = self.events()
        if host:
            matching = [e for e in events if e.host == host.strip("[]").rstrip(".").lower()]
            return matching[-1] if matching else None
        return events[-1] if events else None

    def _record(self, host: str, port: int, code: CaptureErrorCode, message: str) -> None:
        with self._lock:
            self._events.append(ProxyEvent(host.strip("[]").rstrip(".").lower(), port, code, message))
        logger.info("Capture proxy refused %s:%d (%s)", host, port, code.value)

    # ------------------------------------------------------------------ handling

    def _handle(self, client: socket.socket) -> None:
        client.settimeout(self.idle_timeout)
        try:
            head, rest = _read_head(client)
        except OSError:
            return
        if not head:
            return
        lines = head.decode("latin-1").split("\r\n")
        try:
            method, target, version = lines[0].split(" ", 2)
        except ValueError:
            _reply(client, 400, CaptureErrorCode.INVALID_URL, "malformed request")
            return

        connect = method.upper() == "CONNECT"
        if connect:
            host, _, port_text = target.rpartition(":")
            if not host or not port_text.isdigit():
                _reply(client, 400, CaptureErrorCode.INVALID_URL, "malformed CONNECT target")
                return
            port, path = int(port_text), ""
        else:
            parts = urlsplit(target)
            if parts.scheme.lower() != "http" or not parts.hostname:
                _reply(client, 400, CaptureErrorCode.UNSUPPORTED_SCHEME, "only http:// and https:// are proxied")
                return
            host = parts.hostname
            try:
                port = parts.port or 80
            except ValueError:
                _reply(client, 400, CaptureErrorCode.INVALID_URL, "invalid port")
                return
            path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")

        decision = self.policy.connect_address(host, port)
        if not decision.allowed:
            self._record(host, port, decision.code, decision.message or "refused")
            blocked = decision.code in (CaptureErrorCode.PRIVATE_ADDRESS, CaptureErrorCode.SOCIAL_MEDIA_URL)
            _reply(client, 403 if blocked else 502, decision.code, decision.message or "refused")
            return
        try:
            upstream = socket.create_connection((decision.address, port), timeout=self.connect_timeout)
        except TimeoutError:
            self._record(host, port, CaptureErrorCode.TIMEOUT, f"connection to {host}:{port} timed out")
            _reply(client, 504, CaptureErrorCode.TIMEOUT, "upstream connection timed out")
            return
        except OSError as exc:
            self._record(host, port, CaptureErrorCode.CONNECTION_FAILED, f"cannot connect to {host}:{port} ({exc})")
            _reply(client, 502, CaptureErrorCode.CONNECTION_FAILED, "upstream connection failed")
            return

        with upstream:
            upstream.settimeout(self.idle_timeout)
            try:
                if connect:
                    client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    if rest:
                        upstream.sendall(rest)
                    _pump(client, upstream, self.idle_timeout)
                else:
                    self._forward_http(client, upstream, method, path, version, lines[1:], rest)
            except OSError:
                return

    def _forward_http(self, client, upstream, method, path, version, headers, rest) -> None:
        kept = [h for h in headers if h and not h.lower().startswith(_HOP_HEADERS)]
        head = "\r\n".join([f"{method} {path} {version}", *kept, "Connection: close"]) + "\r\n\r\n"
        upstream.sendall(head.encode("latin-1"))
        lowered = [h.lower() for h in kept]
        if any(h.startswith("transfer-encoding:") and "chunked" in h for h in lowered):
            if rest:
                upstream.sendall(rest)
            _pump(client, upstream, self.idle_timeout)
            return
        length = next((int(h.split(":", 1)[1]) for h in lowered
                       if h.startswith("content-length:") and h.split(":", 1)[1].strip().isdigit()), 0)
        body = rest[:length]
        upstream.sendall(body)
        while len(body) < length:
            chunk = client.recv(min(_CHUNK, length - len(body)))
            if not chunk:
                break
            body += chunk
            upstream.sendall(chunk)
        while True:
            chunk = upstream.recv(_CHUNK)
            if not chunk:
                return
            client.sendall(chunk)


def _read_head(sock: socket.socket) -> tuple[bytes, bytes]:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            return b"", b""
        data += chunk
        if len(data) > _MAX_HEAD_BYTES:
            return b"", b""
    head, _, rest = data.partition(b"\r\n\r\n")
    return head, rest


def _reply(sock: socket.socket, status: int, code: CaptureErrorCode, message: str) -> None:
    body = message.encode("utf-8", "replace")
    head = (f"HTTP/1.1 {status} Refused by capture proxy\r\n{PROXY_HEADER}: {code.value}\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n")
    try:
        sock.sendall(head.encode("latin-1") + body)
    except OSError:
        return


def _pump(a: socket.socket, b: socket.socket, idle_timeout: float) -> None:
    with selectors.DefaultSelector() as selector:
        selector.register(a, selectors.EVENT_READ, b)
        selector.register(b, selectors.EVENT_READ, a)
        while True:
            ready = selector.select(timeout=idle_timeout)
            if not ready:
                return
            for key, _ in ready:
                try:
                    data = key.fileobj.recv(_CHUNK)
                except OSError:
                    return
                if not data:
                    return
                key.data.sendall(data)
