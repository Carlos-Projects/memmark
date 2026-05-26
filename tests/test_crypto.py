"""Tests for the crypto utility module."""

import tempfile
from pathlib import Path

from memmark.utils.crypto import (
    hash_memory_entry,
    hash_memory_state,
    hmac_sign,
    hmac_verify,
    sha256_file,
    sha256_hash,
)


class TestSha256:
    def test_hash_string(self) -> None:
        h = sha256_hash("hello")
        assert isinstance(h, str)
        assert len(h) == 64

    def test_hash_bytes(self) -> None:
        h = sha256_hash(b"hello")
        assert isinstance(h, str)
        assert len(h) == 64

    def hash_deterministic_string(self) -> None:
        assert sha256_hash("test") == sha256_hash("test")

    def test_hash_different(self) -> None:
        assert sha256_hash("abc") != sha256_hash("xyz")

    def test_hash_file(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("test content")
            path = f.name
        try:
            h = sha256_file(path)
            assert isinstance(h, str)
            assert len(h) == 64
        finally:
            Path(path).unlink()

    def test_hash_file_deterministic(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("same content")
            p1 = f.name
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("same content")
            p2 = f.name
        try:
            assert sha256_file(p1) == sha256_file(p2)
        finally:
            Path(p1).unlink()
            Path(p2).unlink()


class TestHmac:
    def test_sign(self) -> None:
        sig = hmac_sign("data", "key")
        assert isinstance(sig, str)
        # 32 hex chars for salt + 64 hex chars for HMAC = 96
        assert len(sig) == 96

    def test_verify_valid(self) -> None:
        sig = hmac_sign("data", "key")
        assert hmac_verify("data", "key", sig)

    def test_verify_invalid_key(self) -> None:
        sig = hmac_sign("data", "key1")
        assert not hmac_verify("data", "key2", sig)

    def test_verify_invalid_data(self) -> None:
        sig = hmac_sign("data1", "key")
        assert not hmac_verify("data2", "key", sig)

    def test_verify_invalid_salt(self) -> None:
        assert not hmac_verify("data", "key", "tooshort")

    def test_sign_with_salt(self) -> None:
        salt = b"\x00" * 16
        sig = hmac_sign("data", "key", salt=salt)
        assert isinstance(sig, str)
        assert len(sig) == 96
        # Salt portion should be 32 hex zeros
        assert sig[:32] == "0" * 32

    def test_verify_with_fixed_salt(self) -> None:
        salt = b"\x01" * 16
        sig = hmac_sign("data", "key", salt=salt)
        assert hmac_verify("data", "key", sig)


class TestMemoryHash:
    def test_hash_memory_entry(self) -> None:
        entry = {"id": "mem-001", "content": "hello"}
        h = hash_memory_entry(entry)
        assert isinstance(h, str)
        assert len(h) == 64

    def test_hash_memory_entry_deterministic(self) -> None:
        entry = {"id": "mem-001", "content": "hello"}
        assert hash_memory_entry(entry) == hash_memory_entry(entry)

    def test_hash_memory_entry_sort_keys(self) -> None:
        e1 = {"b": 2, "a": 1}
        e2 = {"a": 1, "b": 2}
        assert hash_memory_entry(e1) == hash_memory_entry(e2)

    def test_hash_state(self) -> None:
        memories = [{"id": "mem-001"}, {"id": "mem-002"}]
        h = hash_memory_state(memories)
        assert isinstance(h, str)
        assert len(h) == 64

    def test_hash_state_deterministic(self) -> None:
        m = [{"id": "mem-001", "content": "hello"}]
        assert hash_memory_state(m) == hash_memory_state(m)

    def test_hash_state_different(self) -> None:
        m1 = [{"id": "mem-001", "content": "hello"}]
        m2 = [{"id": "mem-001", "content": "world"}]
        assert hash_memory_state(m1) != hash_memory_state(m2)
