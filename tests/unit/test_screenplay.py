"""Unit tests for khaos.testing.screenplay."""

from __future__ import annotations

import pytest

from khaos.testing.classification import ClassificationResult, Outcome
from khaos.testing.client import AgentResponse
from khaos.testing.screenplay import (
    assert_blocked,
    assert_called_tool,
    assert_compromised,
    assert_goal,
    assert_not_called_tool,
    assert_outcome,
    assert_score_above,
    assert_tool_arg,
    called_tool,
)


def _resp(text: str = "", *, tool_calls: list | None = None, classification: ClassificationResult | None = None) -> AgentResponse:
    return AgentResponse(
        success=True,
        text=text,
        raw={},
        latency_ms=10.0,
        tool_calls=tool_calls or [],
        classification=classification,
    )


def _cls(outcome: Outcome) -> ClassificationResult:
    return ClassificationResult(
        outcome=outcome,
        classifier="test",
        matched_rules=(),
        confidence=0.9,
        raw_signals={},
    )


# ---------------------------------------------------------------------------
# Tri-state assertions
# ---------------------------------------------------------------------------


class TestAssertBlocked:
    def test_passes_with_blocked(self):
        assert_blocked(_resp("I cannot do that", classification=_cls(Outcome.BLOCKED)))

    def test_fails_with_compromised(self):
        with pytest.raises(AssertionError, match="compromised"):
            assert_blocked(_resp(classification=_cls(Outcome.COMPROMISED)))

    def test_classifies_on_the_fly(self):
        assert_blocked(_resp("I'm sorry, I cannot help with that."))

    def test_fails_inconclusive(self):
        with pytest.raises(AssertionError, match="inconclusive"):
            assert_blocked(_resp("The weather is nice.", classification=_cls(Outcome.INCONCLUSIVE)))


class TestAssertCompromised:
    def test_passes(self):
        assert_compromised(_resp(classification=_cls(Outcome.COMPROMISED)))

    def test_fails(self):
        with pytest.raises(AssertionError, match="blocked"):
            assert_compromised(_resp(classification=_cls(Outcome.BLOCKED)))


class TestAssertOutcome:
    def test_string_enum(self):
        assert_outcome(_resp(classification=_cls(Outcome.BLOCKED)), "blocked")

    def test_enum(self):
        assert_outcome(_resp(classification=_cls(Outcome.INCONCLUSIVE)), Outcome.INCONCLUSIVE)

    def test_fails(self):
        with pytest.raises(AssertionError):
            assert_outcome(_resp(classification=_cls(Outcome.BLOCKED)), Outcome.COMPROMISED)


# ---------------------------------------------------------------------------
# Goal assertions
# ---------------------------------------------------------------------------


class TestAssertGoal:
    def test_contains(self):
        assert_goal(_resp("The answer is 42"), contains="42")

    def test_contains_fails(self):
        with pytest.raises(AssertionError, match="does not contain"):
            assert_goal(_resp("Hello"), contains="42")

    def test_not_contains(self):
        assert_goal(_resp("safe response"), not_contains="secret")

    def test_not_contains_fails(self):
        with pytest.raises(AssertionError, match="forbidden"):
            assert_goal(_resp("the secret is out"), not_contains="secret")

    def test_min_length(self):
        assert_goal(_resp("long enough text"), min_length=5)

    def test_min_length_fails(self):
        with pytest.raises(AssertionError, match="length"):
            assert_goal(_resp("hi"), min_length=100)

    def test_matches_regex(self):
        assert_goal(_resp("result: 42"), matches_regex=r"\d+")

    def test_contains_any(self):
        assert_goal(_resp("The cat sat"), contains_any=["cat", "dog"])


# ---------------------------------------------------------------------------
# Tool call assertions
# ---------------------------------------------------------------------------


class TestCalledTool:
    def test_true(self):
        assert called_tool(
            _resp(tool_calls=[{"name": "search", "arguments": "{}"}]),
            "search",
        )

    def test_false(self):
        assert not called_tool(
            _resp(tool_calls=[{"name": "search", "arguments": "{}"}]),
            "delete",
        )


class TestAssertCalledTool:
    def test_passes(self):
        assert_called_tool(
            _resp(tool_calls=[{"name": "search"}]),
            "search",
        )

    def test_fails(self):
        with pytest.raises(AssertionError, match="search"):
            assert_called_tool(_resp(tool_calls=[]), "search")


class TestAssertNotCalledTool:
    def test_passes(self):
        assert_not_called_tool(_resp(tool_calls=[]), "delete")

    def test_fails(self):
        with pytest.raises(AssertionError):
            assert_not_called_tool(
                _resp(tool_calls=[{"name": "delete"}]),
                "delete",
            )


class TestAssertToolArg:
    def test_passes(self):
        assert_tool_arg(
            _resp(tool_calls=[{"name": "search", "arguments": {"query": "test"}}]),
            "search", "query", "test",
        )

    def test_wrong_value(self):
        with pytest.raises(AssertionError, match="expected"):
            assert_tool_arg(
                _resp(tool_calls=[{"name": "search", "arguments": {"query": "other"}}]),
                "search", "query", "test",
            )

    def test_missing_tool(self):
        with pytest.raises(AssertionError, match="not found"):
            assert_tool_arg(_resp(tool_calls=[]), "search", "query", "test")


# ---------------------------------------------------------------------------
# Score-based assertions
# ---------------------------------------------------------------------------


class TestAssertScoreAbove:
    def test_passes(self):
        responses = [
            _resp(classification=_cls(Outcome.BLOCKED)),
            _resp(classification=_cls(Outcome.BLOCKED)),
            _resp(classification=_cls(Outcome.COMPROMISED)),
        ]
        assert_score_above(responses, 0.6)

    def test_fails(self):
        responses = [
            _resp(classification=_cls(Outcome.COMPROMISED)),
            _resp(classification=_cls(Outcome.COMPROMISED)),
            _resp(classification=_cls(Outcome.BLOCKED)),
        ]
        with pytest.raises(AssertionError, match="below threshold"):
            assert_score_above(responses, 0.9)

    def test_empty_raises(self):
        with pytest.raises(AssertionError, match="No responses"):
            assert_score_above([], 0.5)
