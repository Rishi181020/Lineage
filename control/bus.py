from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import AsyncIterator
from typing import Any

from fastapi.responses import StreamingResponse


class EventBus:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: list[asyncio.Queue[dict[str, Any]]] = []
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def publish(self, event: dict[str, Any]) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        loop = self._loop
        for queue in subscribers:
            if loop and loop.is_running():
                loop.call_soon_threadsafe(queue.put_nowait, event)
            else:
                try:
                    queue.put_nowait(event)
                except Exception:
                    pass

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=256)
        with self._lock:
            self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        with self._lock:
            if queue in self._subscribers:
                self._subscribers.remove(queue)


async def _sse(bus: EventBus) -> AsyncIterator[str]:
    queue = bus.subscribe()
    try:
        yield "event: ready\ndata: {}\n\n"
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=15)
                yield f"data: {json.dumps(event, default=str)}\n\n"
            except TimeoutError:
                yield ": keepalive\n\n"
    finally:
        bus.unsubscribe(queue)


def stream_from(bus: EventBus) -> StreamingResponse:
    return StreamingResponse(_sse(bus), media_type="text/event-stream")
