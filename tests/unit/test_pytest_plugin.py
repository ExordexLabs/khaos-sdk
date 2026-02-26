"""Unit tests for the khaos pytest plugin.

Tests assertion helpers, snapshot testing, the @khaostest decorator,
and plugin helper functions — all without importing heavy khaos
dependencies (uses mocking throughout).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from khaos.testing.client import AgentResponse
from khaos.testing.assertions import (
    assert_blocked,
    assert_not_blocked,
    assert_score_above,
    assert_no_pii,
    assert_latency_under,
    assert_contains,
    assert_not_contains,
)
from khaos.testing.snapshots import assert_response_matches_snapshot
from khaos.testing import khaostest, KhaosTestConfig
from khaos.testing.pytest_plugin import (
    _is_khaos_item,
    _config_from_item,
    _get_or_resolve_agent,
    _agent_cache,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(
    *, success: bool = True, text: str = "", latency_ms: float = 10.0, error: str | None = None
) -> AgentResponse:
    return AgentResponse(
        success=success, text=text, raw={}, latency_ms=latency_ms, error=error,
    )


# ===========================================================================
# 1. Assertion helpers
# ===========================================================================


class TestAssertBlocked:
    def test_passes(self):
        assert_blocked(_make_response(success=False))

    def test_fails(self):
        with pytest.raises(AssertionError):
            assert_blocked(_make_response(success=True))


class TestAssertNotBlocked:
    def test_passes(self):
        assert_not_blocked(_make_response(success=True))

    def test_fails_with_error(self):
        with pytest.raises(AssertionError, match="denied"):
            assert_not_blocked(_make_response(success=False, error="denied"))


class TestAssertScoreAbove:
    def test_passes(self):
        responses = [
            _make_response(success=False),
            _make_response(success=False),
            _make_response(success=False),
            _make_response(success=True),
        ]
        assert_score_above(responses, 0.7)

    def test_fails(self):
        responses = [
            _make_response(success=False),
            _make_response(success=True),
            _make_response(success=True),
            _make_response(success=True),
        ]
        with pytest.raises(AssertionError, match="below threshold"):
            assert_score_above(responses, 0.7)


class TestAssertNoPii:
    def test_clean(self):
        assert_no_pii(_make_response(text="Hello world"))

    def test_detects_ssn(self):
        with pytest.raises(AssertionError):
            assert_no_pii(_make_response(text="SSN is 123-45-6789"))

    def test_detects_email(self):
        with pytest.raises(AssertionError):
            assert_no_pii(_make_response(text="Contact user@example.com"))

    def test_custom_pattern(self):
        with pytest.raises(AssertionError):
            assert_no_pii(
                _make_response(text="Code: SECRET-123"),
                patterns=[r"SECRET-\d+"],
            )


class TestAssertLatencyUnder:
    def test_passes(self):
        assert_latency_under(_make_response(latency_ms=50.0), 100.0)

    def test_fails(self):
        with pytest.raises(AssertionError, match="exceeds"):
            assert_latency_under(_make_response(latency_ms=150.0), 100.0)


class TestAssertContains:
    def test_case_insensitive(self):
        assert_contains(_make_response(text="hello world"), "HELLO")

    def test_case_sensitive_fails(self):
        with pytest.raises(AssertionError):
            assert_contains(
                _make_response(text="hello world"), "HELLO", case_sensitive=True,
            )


class TestAssertNotContains:
    def test_passes(self):
        assert_not_contains(_make_response(text="hello world"), "secret")

    def test_fails(self):
        with pytest.raises(AssertionError):
            assert_not_contains(_make_response(text="hello world"), "hello")


# ===========================================================================
# 2. Snapshot testing
# ===========================================================================


class TestSnapshots:
    def test_creates_on_first_run(self, tmp_path, monkeypatch):
        import khaos.testing.snapshots as snapshots_mod

        monkeypatch.setattr(snapshots_mod, "SNAPSHOT_DIR", tmp_path)
        resp = _make_response(success=True, text="hello world")
        assert_response_matches_snapshot(resp, "first_run")
        snap_file = tmp_path / "first_run.json"
        assert snap_file.exists()
        data = json.loads(snap_file.read_text())
        assert data["text"] == "hello world"
        assert data["success"] is True

    def test_matches_identical(self, tmp_path, monkeypatch):
        import khaos.testing.snapshots as snapshots_mod

        monkeypatch.setattr(snapshots_mod, "SNAPSHOT_DIR", tmp_path)
        resp = _make_response(success=True, text="same text")
        assert_response_matches_snapshot(resp, "identical")
        assert_response_matches_snapshot(resp, "identical")  # second call compares

    def test_fails_on_mismatch(self, tmp_path, monkeypatch):
        import khaos.testing.snapshots as snapshots_mod

        monkeypatch.setattr(snapshots_mod, "SNAPSHOT_DIR", tmp_path)
        resp1 = _make_response(success=True, text="original")
        assert_response_matches_snapshot(resp1, "mismatch")
        resp2 = _make_response(success=True, text="different")
        with pytest.raises(AssertionError, match="mismatch"):
            assert_response_matches_snapshot(resp2, "mismatch")

    def test_update_overwrites(self, tmp_path, monkeypatch):
        import khaos.testing.snapshots as snapshots_mod

        monkeypatch.setattr(snapshots_mod, "SNAPSHOT_DIR", tmp_path)
        resp1 = _make_response(success=True, text="old")
        assert_response_matches_snapshot(resp1, "update_test")
        resp2 = _make_response(success=True, text="new")
        assert_response_matches_snapshot(resp2, "update_test", update=True)
        data = json.loads((tmp_path / "update_test.json").read_text())
        assert data["text"] == "new"

    def test_tolerance(self, tmp_path, monkeypatch):
        import khaos.testing.snapshots as snapshots_mod

        monkeypatch.setattr(snapshots_mod, "SNAPSHOT_DIR", tmp_path)
        resp1 = _make_response(success=True, text="hello world")
        assert_response_matches_snapshot(resp1, "tolerance_test")
        resp2 = _make_response(success=True, text="hello world!")
        assert_response_matches_snapshot(resp2, "tolerance_test", tolerance=0.2)


# ===========================================================================
# 3. KhaosTestConfig and decorator
# ===========================================================================


class TestKhaostestDecorator:
    def test_sets_attributes(self):
        @khaostest(agent="my-agent")
        def my_test():
            pass

        assert my_test.__khaos_test__ is True
        assert isinstance(my_test.__khaos_test_config__, KhaosTestConfig)
        assert hasattr(my_test, "__khaos_test_mode__")

    def test_imperative_mode(self):
        @khaostest(agent="my-agent")
        def my_test(agent):
            pass

        assert my_test.__khaos_test_mode__ == "imperative"

    def test_declarative_mode(self):
        @khaostest(agent="my-agent")
        def my_test():
            pass

        assert my_test.__khaos_test_mode__ == "declarative"

    def test_config_fields(self):
        @khaostest(
            agent="test-agent",
            faults=["timeout"],
            attacks=["prompt_injection"],
            tags=["security"],
        )
        def my_test():
            pass

        cfg = my_test.__khaos_test_config__
        assert cfg.agent == "test-agent"
        assert cfg.faults == ["timeout"]
        assert cfg.attacks == ["prompt_injection"]
        assert cfg.tags == ["security"]


# ===========================================================================
# 4. Plugin helpers (mock-based)
# ===========================================================================


class TestIsKhaosItem:
    def test_decorator(self):
        item = MagicMock(spec=["obj", "iter_markers"])
        item.obj.__khaos_test__ = True
        item.iter_markers.return_value = []
        assert _is_khaos_item(item) is True

    def test_marker(self):
        item = MagicMock(spec=["obj", "iter_markers"])
        item.obj.__khaos_test__ = False
        marker = MagicMock()
        item.iter_markers.return_value = [marker]
        assert _is_khaos_item(item) is True

    def test_plain(self):
        item = MagicMock(spec=["obj", "iter_markers"])
        item.obj.__khaos_test__ = False
        item.iter_markers.return_value = []
        assert _is_khaos_item(item) is False


class TestConfigFromItem:
    def test_decorator(self):
        cfg = KhaosTestConfig(agent="test-agent", faults=["timeout"])
        item = MagicMock(spec=["obj", "iter_markers"])
        item.obj.__khaos_test_config__ = cfg
        item.iter_markers.return_value = []
        assert _config_from_item(item) is cfg

    def test_marker(self):
        item = MagicMock(spec=["obj", "iter_markers"])
        item.obj = MagicMock(spec=[])  # no __khaos_test_config__
        marker = MagicMock()
        marker.kwargs = {"agent": "marker-agent", "faults": ["http_latency"]}
        item.iter_markers.return_value = [marker]
        result = _config_from_item(item)
        assert isinstance(result, KhaosTestConfig)
        assert result.agent == "marker-agent"
        assert result.faults == ["http_latency"]


class TestAgentCache:
    def test_caches_resolved_agent(self, monkeypatch):
        import khaos.testing.pytest_plugin as plugin_mod

        mock_agent = MagicMock()
        mock_resolve = MagicMock(return_value=mock_agent)
        monkeypatch.setattr(plugin_mod, "resolve_agent", mock_resolve)

        _agent_cache.clear()
        try:
            result1 = _get_or_resolve_agent("cached-agent")
            result2 = _get_or_resolve_agent("cached-agent")
            assert result1 is mock_agent
            assert result2 is mock_agent
            mock_resolve.assert_called_once_with("cached-agent")
        finally:
            _agent_cache.clear()
