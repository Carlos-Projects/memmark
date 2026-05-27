"""Tests for the public API exposed by memmark."""

import memmark


class TestPublicAPI:
    def test_version(self) -> None:
        assert isinstance(memmark.__version__, str)
        assert memmark.__version__ == "0.1.0"

    def test_all_defined(self) -> None:
        assert len(memmark.__all__) == 39

    def test_import_all(self) -> None:
        for name in memmark.__all__:
            assert hasattr(memmark, name), f"Missing {name} from __all__"
