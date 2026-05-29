# Copyright (c) 2025 Carlos-Projects
# SPDX-License-Identifier: MIT

"""Redis-backed memory store for production deployments."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from memmark.store import MemoryStore

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

_DEFAULT_URL = "redis://localhost:6379/0"


class RedisMemoryStore(MemoryStore):
    """Memory store backed by Redis.

    Supports connection pooling, key prefixes, TTL,
    and graceful error handling on connection failures.

    Args:
        url: Redis connection URL.
        key_prefix: Prefix for Redis keys.
        ttl: Time-to-live in seconds.
        kw: Additional arguments for redis.Redis().
    """

    def __init__(
        self,
        url: str | None = None,
        key_prefix: str = "memmark-memories",
        ttl: int | None = None,
        **kw: Any,
    ) -> None:
        try:
            import redis as rmod
        except ImportError as exc:
            raise RuntimeError("Install redis: pip install redis") from exc

        self._redis = rmod
        self._url = url or _DEFAULT_URL
        self._key = key_prefix + ":memories"
        self._ttl = ttl
        self._client = rmod.Redis(
            url=self._url,
            decode_responses=True,
            **kw,
        )
        try:
            self._client.ping()
        except (rmod.ConnectionError, rmod.TimeoutError) as exc:
            logger.warning("Redis unavailable: %s", exc)

    @property
    def client(self) -> Any:
        return self._client

    def read(self) -> list[dict[str, Any]]:
        try:
            data = self._client.get(self._key)
        except (self._redis.ConnectionError, self._redis.TimeoutError) as exc:
            raise ConnectionError("Redis read failed") from exc
        if data is None:
            return []
        try:
            parsed = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return []
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return parsed.get("memories", parsed.get("entries", [parsed]))
        return []

    def write(self, memories: list[dict[str, Any]]) -> None:
        payload = json.dumps(memories, ensure_ascii=False)
        try:
            if self._ttl is not None:
                self._client.setex(self._key, self._ttl, payload)
            else:
                self._client.set(self._key, payload)
        except (self._redis.ConnectionError, self._redis.TimeoutError) as exc:
            raise ConnectionError("Redis write failed") from exc

    def append(self, entry: dict[str, Any]) -> None:
        try:
            data = self._client.get(self._key)
            memories: list[dict[str, Any]] = []
            if data is not None:
                try:
                    parsed = json.loads(data)
                    if isinstance(parsed, list):
                        memories = parsed
                    elif isinstance(parsed, dict):
                        memories = parsed.get("memories", parsed.get("entries", [parsed]))
                except (json.JSONDecodeError, TypeError):
                    pass
            memories.append(entry)
            payload = json.dumps(memories, ensure_ascii=False)
            if self._ttl is not None:
                self._client.setex(self._key, self._ttl, payload)
            else:
                self._client.set(self._key, payload)
        except (self._redis.ConnectionError, self._redis.TimeoutError) as exc:
            raise ConnectionError("Redis append failed") from exc

    def clear(self) -> None:
        try:
            self._client.delete(self._key)
        except (self._redis.ConnectionError, self._redis.TimeoutError) as exc:
            raise ConnectionError("Redis clear failed") from exc

    def size(self) -> int:
        try:
            data = self._client.get(self._key)
            if data is None:
                return 0
            parsed = json.loads(data)
            if isinstance(parsed, list):
                return len(parsed)
            return 0
        except (self._redis.ConnectionError, self._redis.TimeoutError, json.JSONDecodeError, TypeError):
            return 0
