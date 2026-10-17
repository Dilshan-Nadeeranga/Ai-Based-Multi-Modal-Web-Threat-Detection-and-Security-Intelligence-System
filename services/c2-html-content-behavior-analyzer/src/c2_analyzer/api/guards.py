"""Result cache and per-client rate limit for ``POST /api/v1/analyze``.

Part 9: Batch B-1 - end-to-end URL analysis engine.

Why (viva):
- cache: the frontend and ThreatRadar often re-check the same link (a viral scam URL is
  submitted by many users). Re-fetching it each time is slow, loads the suspect server
  and re-runs every model. Results are kept in memory per NORMALIZED URL (scheme/host
  lower-case, default port and #fragment dropped) for a short TTL; both the submitted
  and the final (after redirects) URL point to the entry. Only url-mode results with a
  page verdict are cached ("unreachable" may be a hiccup, so it is retried).
- rate limit: every url-mode request makes C2 send a request to a third-party server.
  A per-client sliding window stops one caller from turning C2 into a crawler / DoS tool.

Both are in-process (single worker), which is what the team deployment runs; a shared
store (Redis) would be needed with several workers - stated as a limitation.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit

DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_url(url: str | None) -> str | None:
    """Cache key: lower-case scheme + host, no default port, no fragment, path '/' if empty."""
    if not url:
        return None
    try:
        parts = urlsplit(url.strip())
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return None
    if not host:
        return None
    netloc = host if port in (None, DEFAULT_PORTS.get(scheme)) else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


class ResultCache:
    """TTL + LRU cache: key -> stored response dict (thread-safe)."""

    def __init__(
        self, ttl_seconds: float, max_entries: int, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.ttl = float(ttl_seconds)
        self.max_entries = int(max_entries)
        self.clock = clock
        self._data: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, url: str | None) -> dict | None:
        key = normalize_url(url)
        if key is None or self.ttl <= 0:
            return None
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            stored_at, value = entry
            if self.clock() - stored_at > self.ttl:
                self._data.pop(key, None)
                return None
            self._data.move_to_end(key)
            return value

    def put(self, value: dict, *urls: str | None) -> None:
        if self.ttl <= 0:
            return
        now = self.clock()
        with self._lock:
            for key in {normalize_url(url) for url in urls} - {None}:
                self._data[key] = (now, value)
                self._data.move_to_end(key)
            while len(self._data) > self.max_entries:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


class RateLimiter:
    """At most ``requests`` per ``per_seconds`` per client (sliding window, thread-safe)."""

    def __init__(
        self, requests: int, per_seconds: float, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.requests = int(requests)
        self.window = float(per_seconds)
        self.clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, client: str) -> float | None:
        """None if allowed (and counted), else seconds until the next request is allowed."""
        if self.requests <= 0:
            return None
        now = self.clock()
        with self._lock:
            hits = self._hits.setdefault(client, deque())
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            if len(hits) >= self.requests:
                return max(0.0, self.window - (now - hits[0]))
            hits.append(now)
            if len(self._hits) > 10_000:  # forget idle clients (memory bound)
                for key in [k for k, v in self._hits.items() if not v][:5_000]:
                    del self._hits[key]
            return None
