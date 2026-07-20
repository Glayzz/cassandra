"""Tiny async TTL cache. Cuts latency and rate-limit pressure on repeat reads.

Stores even negative results (None) briefly so a failing/empty upstream isn't
hammered. In-process only - fine for a single-machine deploy; swap for Redis if
you scale horizontally.
"""
from __future__ import annotations

import asyncio
import time
from typing import Awaitable, Callable


class TTLCache:
    def __init__(self, ttl: float = 300.0, maxsize: int = 4000) -> None:
        self._ttl = ttl
        self._max = maxsize
        self._d: dict[str, tuple[float, object]] = {}
        self._lock = asyncio.Lock()

    async def get_or_set(self, key: str, factory: Callable[[], Awaitable], ttl: float | None = None):
        now = time.time()
        hit = self._d.get(key)
        if hit and hit[0] > now:
            return hit[1]
        # single-flight per key
        async with self._lock:
            hit = self._d.get(key)
            if hit and hit[0] > now:
                return hit[1]
            val = await factory()
            self._d[key] = (now + (ttl if ttl is not None else self._ttl), val)
            if len(self._d) > self._max:
                self._evict()
            return val

    def _evict(self) -> None:
        items = sorted(self._d.items(), key=lambda kv: kv[1][0])
        for k, _ in items[: max(1, len(items) // 10)]:
            self._d.pop(k, None)
