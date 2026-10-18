"""Live feed: an in-process publish / subscribe bus + the Server-Sent Events stream.

Part 9: Batch B-2 - automatic ThreatRadar ingestion.

Why SSE (viva): the dashboard only needs C2 -> browser messages ("a scan finished").
Server-Sent Events are plain HTTP (works through proxies and CORS, the browser's
``EventSource`` reconnects by itself), unlike WebSockets which need a second protocol
for a one-way feed. Each event is small (id, defanged URL, verdict, class, risk, time):
the page fetches details from /api/v1/scans/{id} only when someone clicks.

Scans finish in worker tasks and in request threads (user /analyze checks), so
``publish`` is thread-safe: it hands the event to each subscriber's event loop with
``call_soon_threadsafe``. A slow browser cannot block C2: each subscriber has a bounded
queue and the OLDEST event is dropped when it is full.
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import AsyncIterator, Awaitable, Callable

QUEUE_SIZE = 100


class EventBus:
    """Fan-out of finished-scan events to every connected live-feed client."""

    def __init__(self) -> None:
        self._subscribers: dict[asyncio.Queue, asyncio.AbstractEventLoop] = {}
        self._lock = threading.Lock()
        self.published = 0

    def subscribe(self) -> asyncio.Queue:
        """Must be called from a running event loop (the SSE request)."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_SIZE)
        with self._lock:
            self._subscribers[queue] = asyncio.get_running_loop()
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        with self._lock:
            self._subscribers.pop(queue, None)

    @property
    def subscribers(self) -> int:
        with self._lock:
            return len(self._subscribers)

    def publish(self, event: dict) -> None:
        """Send ``event`` to every subscriber (from any thread, never blocks)."""
        self.published += 1
        with self._lock:
            targets = list(self._subscribers.items())
        for queue, loop in targets:
            try:
                loop.call_soon_threadsafe(_offer, queue, event)
            except RuntimeError:  # that loop is closed: the client is gone
                self.unsubscribe(queue)


def _offer(queue: asyncio.Queue, event: dict) -> None:
    if queue.full():
        queue.get_nowait()  # drop the oldest, keep the newest
    queue.put_nowait(event)


def format_sse(event: dict, name: str = "scan") -> str:
    """One SSE message: ``id`` (lets EventSource resume), ``event`` name, JSON ``data``."""
    return f"id: {event.get('id', '')}\nevent: {name}\ndata: {json.dumps(event)}\n\n"


async def sse_stream(
    bus: EventBus,
    is_disconnected: Callable[[], Awaitable[bool]],
    heartbeat_seconds: float = 15.0,
) -> AsyncIterator[str]:
    """Yield SSE text for every published event, with a keep-alive comment when idle."""
    queue = bus.subscribe()
    try:
        yield "retry: 5000\n: connected\n\n"
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=heartbeat_seconds)
            except TimeoutError:
                if await is_disconnected():
                    return
                yield ": ping\n\n"  # comment line: keeps proxies from closing the stream
                continue
            yield format_sse(event)
    finally:
        bus.unsubscribe(queue)
