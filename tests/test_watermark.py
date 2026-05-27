"""Tests for the watermark module."""

from memmark.watermark.detector import WatermarkDetector
from memmark.watermark.injector import WatermarkInjector
from memmark.watermark.robustness import WatermarkRobustnessTester

SAMPLE_MEMORIES = [
    {"id": "mem-001", "content": "User prefers dark mode", "source": "preference"},
    {
        "id": "mem-002",
        "content": "Project deadline is March 15",
        "source": "conversation",
    },
    {
        "id": "mem-003",
        "content": "Python and TypeScript experience",
        "source": "profile",
    },
]


class TestWatermarkInjector:
    def test_init_custom_key(self) -> None:
        injector = WatermarkInjector(secret_key="custom")
        assert injector.secret_key == "custom"

    def test_init_empty_key_raises(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="must not be empty"):
            WatermarkInjector(secret_key="")

    def test_inject_adds_watermark(self) -> None:
        injector = WatermarkInjector(secret_key="test-key")
        result = injector.inject(SAMPLE_MEMORIES)
        assert len(result) == 3

    def test_inject_adds_signature(self) -> None:
        injector = WatermarkInjector(secret_key="test-key")
        result = injector.inject(SAMPLE_MEMORIES)
        for entry in result:
            assert WatermarkInjector.SIGNATURE_KEY in entry

    def test_inject_adds_watermark_key(self) -> None:
        injector = WatermarkInjector(secret_key="test-key")
        result = injector.inject(SAMPLE_MEMORIES)
        for entry in result:
            assert WatermarkInjector.WATERMARK_KEY in entry

    def test_inject_preserves_original(self) -> None:
        injector = WatermarkInjector(secret_key="test-key")
        result = injector.inject(SAMPLE_MEMORIES)
        for i, entry in enumerate(result):
            assert entry["id"] == SAMPLE_MEMORIES[i]["id"]

    def test_watermark_format(self) -> None:
        injector = WatermarkInjector(secret_key="test-key")
        result = injector.inject([{"id": "mem-001", "content": "test"}])
        wm = result[0][WatermarkInjector.WATERMARK_KEY]
        assert wm["version"] == "1.0"
        assert wm["algorithm"] == "hmac-sha256"

    def test_generate_token(self) -> None:
        injector = WatermarkInjector(secret_key="key")
        token = injector.generate_watermark_token("content")
        assert isinstance(token, str)
        assert len(token) == 16

    def test_generate_token_deterministic(self) -> None:
        injector = WatermarkInjector(secret_key="key")
        assert injector.generate_watermark_token(
            "c"
        ) == injector.generate_watermark_token("c")

    def test_inject_skips_non_dict(self) -> None:
        injector = WatermarkInjector(secret_key="key")
        result = injector.inject([{"id": "mem-001", "content": "ok"}, "not-a-dict", 42])
        assert len(result) == 3
        assert WatermarkInjector.SIGNATURE_KEY in result[0]
        assert not isinstance(result[1], dict)
        assert result[2] == 42


class TestWatermarkDetector:
    def test_init_empty_key_raises(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="must not be empty"):
            WatermarkDetector(secret_key="")

    def test_detect_no_watermarks(self) -> None:
        detector = WatermarkDetector(secret_key="test-key")
        results = detector.detect(SAMPLE_MEMORIES)
        assert all(not r["valid"] for r in results)

    def test_detect_after_inject(self) -> None:
        injector = WatermarkInjector(secret_key="test-key")
        detector = WatermarkDetector(secret_key="test-key")
        watermarked = injector.inject(SAMPLE_MEMORIES)
        results = detector.detect(watermarked)
        assert all(r["valid"] for r in results)

    def test_detect_wrong_key(self) -> None:
        injector = WatermarkInjector(secret_key="correct")
        detector = WatermarkDetector(secret_key="wrong")
        watermarked = injector.inject(SAMPLE_MEMORIES)
        results = detector.detect(watermarked)
        assert all(not r["valid"] for r in results)

    def test_verify_provenance_valid(self) -> None:
        injector = WatermarkInjector(secret_key="key")
        detector = WatermarkDetector(secret_key="key")
        watermarked = injector.inject(SAMPLE_MEMORIES)
        result = detector.verify_provenance(watermarked, "test")
        assert result["provenance_confirmed"]

    def test_verify_provenance_no_watermarks(self) -> None:
        detector = WatermarkDetector(secret_key="test-key")
        result = detector.verify_provenance(SAMPLE_MEMORIES, "test")
        assert not result["provenance_confirmed"]

    def test_detect_entry_no_watermark(self) -> None:
        detector = WatermarkDetector(secret_key="test-key")
        result = detector._detect_entry({"id": "mem-001", "content": "test"})
        assert not result["valid"]
        assert result["reason"] == "no_watermark_found"

    def test_detect_entry_invalid_signature(self) -> None:
        detector = WatermarkDetector(secret_key="key")
        entry = {"id": "mem-001", "content": "test"}
        entry[WatermarkInjector.WATERMARK_KEY] = {
            "version": "1.0",
            "algorithm": "hmac-sha256",
        }
        entry[WatermarkInjector.SIGNATURE_KEY] = "invalid"
        result = detector._detect_entry(entry)
        assert not result["valid"]
        assert result["reason"] == "signature_mismatch"

    def test_detect_entry_legacy_signature(self) -> None:
        from memmark.watermark.detector import _legacy_hmac_sign

        detector = WatermarkDetector(secret_key="key")
        entry = {"id": "mem-001", "content": "test"}
        entry[WatermarkInjector.WATERMARK_KEY] = {
            "version": "1.0",
            "algorithm": "hmac-sha256",
        }
        sig = _legacy_hmac_sign(detector.injector._canonicalize(entry), "key")
        entry[WatermarkInjector.SIGNATURE_KEY] = sig
        result = detector._detect_entry(entry)
        assert result["valid"]
        assert result["reason"] == "verified"

    def test_detect_entry_legacy_mismatch(self) -> None:
        detector = WatermarkDetector(secret_key="key")
        entry = {"id": "mem-001", "content": "test"}
        entry[WatermarkInjector.WATERMARK_KEY] = {
            "version": "1.0",
            "algorithm": "hmac-sha256",
        }
        entry[WatermarkInjector.SIGNATURE_KEY] = "a" * 64
        result = detector._detect_entry(entry)
        assert not result["valid"]

    def test_detect_entry_unknown_format(self) -> None:
        detector = WatermarkDetector(secret_key="key")
        entry = {"id": "mem-001", "content": "test"}
        entry[WatermarkInjector.WATERMARK_KEY] = {
            "version": "1.0",
            "algorithm": "hmac-sha256",
        }
        entry[WatermarkInjector.SIGNATURE_KEY] = "short"
        result = detector._detect_entry(entry)
        assert not result["valid"]


class TestWatermarkRobustness:
    def test_robustness_reorder(self) -> None:
        tester = WatermarkRobustnessTester(secret_key="test")
        results = tester.test_robustness(SAMPLE_MEMORIES, transformations=["reorder"])
        trans = results["transformations"]["reorder"]
        assert "valid_before" in trans
        assert "valid_after" in trans
        assert "retention_rate" in trans

    def test_robustness_truncate(self) -> None:
        tester = WatermarkRobustnessTester(secret_key="test")
        results = tester.test_robustness(SAMPLE_MEMORIES, transformations=["truncate"])
        trans = results["transformations"]["truncate"]
        assert trans["valid_after"] == trans["valid_before"] - 1

    def test_robustness_score(self) -> None:
        tester = WatermarkRobustnessTester(secret_key="test")
        results = tester.test_robustness(
            SAMPLE_MEMORIES, transformations=["reorder", "truncate"]
        )
        score = tester.compute_robustness_score(results)
        assert 0.0 <= score <= 1.0

    def test_all_transformations_default(self) -> None:
        tester = WatermarkRobustnessTester(secret_key="test")
        results = tester.test_robustness(SAMPLE_MEMORIES)
        assert len(results["transformations"]) == 3

    def test_paraphrase_simulated(self) -> None:
        tester = WatermarkRobustnessTester(secret_key="test")
        results = tester.test_robustness(
            SAMPLE_MEMORIES, transformations=["paraphrase_simulated"]
        )
        assert "paraphrase_simulated" in results["transformations"]
