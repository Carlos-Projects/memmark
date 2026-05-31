# Copyright (c) 2025 Carlos-Projects
# SPDX-License-Identifier: MIT

"""Tests for RedisMemoryStore."""

from __future__ import annotations

import json
import types
from unittest.mock import patch

import pytest

from memmark.store import MemoryStore
from memmark.store.redis_store import RedisMemoryStore

fakeredis = pytest.importorskip("fakeredis")


def _make_fake_redis_module():
    """Create a fake redis module with real exception types."""
    mod = types.ModuleType("redis")
    mod.ConnectionError = type("ConnectionError", (Exception,), {})
    mod.TimeoutError = type("TimeoutError", (Exception,), {})
    return mod


@pytest.fixture
def fake_redis():
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.fixture
def store(fake_redis):
    """Create a RedisMemoryStore with fakeredis."""
    s = object.__new__(RedisMemoryStore)
    s._redis = _make_fake_redis_module()
    s._client = fake_redis
    s._key = "test-memories"
    s._ttl = None
    return s


class TestRedisMemoryStore:
    """Tests for the Redis memory store."""

    def test_read_empty(self, store):
        assert store.read() == []

    def test_write_and_read(self, store):
        memories = [
            {"id": "m1", "content": "hello"},
            {"id": "m2", "content": "world"},
        ]
        store.write(memories)
        assert store.read() == memories

    def test_append(self, store):
        store.write([{"id": "m1"}])
        store.append({"id": "m2"})
        result = store.read()
        assert len(result) == 2
        assert result[0]["id"] == "m1"
        assert result[1]["id"] == "m2"

    def test_append_to_empty(self, store):
        store.append({"id": "m1"})
        result = store.read()
        assert len(result) == 1

    def test_write_overwrites(self, store):
        store.write([{"id": "old"}])
        store.write([{"id": "new"}])
        assert store.read() == [{"id": "new"}]

    def test_clear(self, store):
        store.write([{"id": "m1"}, {"id": "m2"}])
        store.clear()
        assert store.read() == []

    def test_size(self, store):
        assert store.size() == 0
        store.write([{"id": "m1"}, {"id": "m2"}])
        assert store.size() == 2

    def test_read_dict_memories_key(self, store):
        data = json.dumps({"memories": [{"id": "m1"}]})
        store._client.set(store._key, data)
        assert store.read() == [{"id": "m1"}]

    def test_read_dict_entries_key(self, store):
        data = json.dumps({"entries": [{"id": "m1"}]})
        store._client.set(store._key, data)
        assert store.read() == [{"id": "m1"}]

    def test_read_corrupted_data(self, store):
        store._client.set(store._key, "not-json")
        assert store.read() == []

    def test_read_connection_error(self, store):
        err_cls = store._redis.ConnectionError
        with patch.object(store._client, "get", side_effect=err_cls("fail")), pytest.raises(ConnectionError):
                store.read()

    def test_write_connection_error(self, store):
        err_cls = store._redis.ConnectionError
        with patch.object(store._client, "set", side_effect=err_cls("fail")), pytest.raises(ConnectionError):
                store.write([{"id": "m1"}])

    def test_append_connection_error(self, store):
        err_cls = store._redis.ConnectionError
        with patch.object(store._client, "get", side_effect=err_cls("fail")), pytest.raises(ConnectionError):
                store.append({"id": "m1"})

    def test_clear_connection_error(self, store):
        err_cls = store._redis.ConnectionError
        with patch.object(store._client, "delete", side_effect=err_cls("fail")), pytest.raises(ConnectionError):
                store.clear()

    def test_size_on_error(self, store):
        err_cls = store._redis.ConnectionError
        with patch.object(store._client, "get", side_effect=err_cls("fail")):
            assert store.size() == 0

    def test_ttl_write(self, fake_redis):
        s = object.__new__(RedisMemoryStore)
        s._redis = _make_fake_redis_module()
        s._client = fake_redis
        s._key = "test-ttl"
        s._ttl = 300
        s.write([{"id": "m1"}])
        ttl = fake_redis.ttl("test-ttl")
        assert ttl is not None and ttl > 0

    def test_append_corrupted_ignores(self, store):
        store._client.set(store._key, "bad-json")
        store.append({"id": "new"})
        result = store.read()
        assert len(result) == 1
        assert result[0]["id"] == "new"

    def test_is_memory_store_subclass(self):
        assert issubclass(RedisMemoryStore, MemoryStore)


class TestRedisMemoryStoreInit:
    """Tests for RedisMemoryStore initialization."""

    def test_requires_redis_package(self):
        with patch.dict("sys.modules", {"redis": None}), pytest.raises(RuntimeError, match="Install redis"):
                RedisMemoryStore()
