"""Tests for the public API exposed by memmark."""

import memmark


class TestPublicAPI:
    def test_version(self) -> None:
        assert isinstance(memmark.__version__, str)
        assert memmark.__version__ == "0.1.0"

    def test_has_finding(self) -> None:
        assert hasattr(memmark, "Finding")

    def test_has_finding_type(self) -> None:
        assert hasattr(memmark, "FindingType")

    def test_has_severity(self) -> None:
        assert hasattr(memmark, "Severity")

    def test_has_scan_result(self) -> None:
        assert hasattr(memmark, "ScanResult")

    def test_has_memory_scanner(self) -> None:
        assert hasattr(memmark, "MemoryScanner")

    def test_has_run_full_scan(self) -> None:
        assert hasattr(memmark, "run_full_scan")

    def test_has_sha256_hash(self) -> None:
        assert hasattr(memmark, "sha256_hash")

    def test_has_hmac_sign(self) -> None:
        assert hasattr(memmark, "hmac_sign")

    def test_has_hmac_verify(self) -> None:
        assert hasattr(memmark, "hmac_verify")

    def test_has_hash_memory_entry(self) -> None:
        assert hasattr(memmark, "hash_memory_entry")

    def test_has_hash_memory_state(self) -> None:
        assert hasattr(memmark, "hash_memory_state")

    def test_all_defined(self) -> None:
        assert len(memmark.__all__) == 11

    def test_import_all(self) -> None:
        for name in memmark.__all__:
            assert hasattr(memmark, name), f"Missing {name} from __all__"
