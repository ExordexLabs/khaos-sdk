"""Screenplay-style assertions for the Khaos testing API.

Imperative assertions wired to existing engines, providing rich
error messages with provenance information (confidence, matched rules).
"""

from __future__ import annotations

import re
from typing import Any

from khaos.testing.classification import ClassificationResult, Outcome, classify
from khaos.testing.client import AgentResponse
from khaos.packs.schema import GoalCriteria
from khaos.packs.runner import _check_goal


# ---------------------------------------------------------------------------
# Tri-state assertions
# ---------------------------------------------------------------------------


def assert_blocked(response: AgentResponse, msg: str = "") -> None:
    """Assert that the agent blocked the request (tri-state aware).

    Uses the classification on the response if available, otherwise
    runs classification on the response text.
    """
    cls = _ensure_classification(response)
    if cls.outcome == Outcome.BLOCKED:
        return
    detail = _provenance_detail(cls)
    fail = f"Expected BLOCKED but got {cls.outcome.value}. {detail}"
    if msg:
        fail = f"{fail} — {msg}"
    raise AssertionError(fail)


def assert_compromised(response: AgentResponse, msg: str = "") -> None:
    """Assert that the agent was compromised (for testing attack effectiveness)."""
    cls = _ensure_classification(response)
    if cls.outcome == Outcome.COMPROMISED:
        return
    detail = _provenance_detail(cls)
    fail = f"Expected COMPROMISED but got {cls.outcome.value}. {detail}"
    if msg:
        fail = f"{fail} — {msg}"
    raise AssertionError(fail)


def assert_outcome(
    response: AgentResponse,
    expected: Outcome | str,
    msg: str = "",
) -> None:
    """Assert that the response has the *expected* outcome."""
    if isinstance(expected, str):
        expected = Outcome(expected)
    cls = _ensure_classification(response)
    if cls.outcome == expected:
        return
    detail = _provenance_detail(cls)
    fail = f"Expected {expected.value} but got {cls.outcome.value}. {detail}"
    if msg:
        fail = f"{fail} — {msg}"
    raise AssertionError(fail)


# ---------------------------------------------------------------------------
# Goal assertions
# ---------------------------------------------------------------------------


def assert_goal(response: AgentResponse, **criteria: Any) -> None:
    """Assert response text meets goal criteria.

    Accepts the same kwargs as YAML ``GoalCriteria``:
    ``contains``, ``contains_any``, ``contains_all``, ``not_contains``,
    ``min_length``, ``max_length``, ``matches_regex``, ``is_valid_json``,
    ``list_length``.
    """
    goal = GoalCriteria(**criteria)
    if _check_goal(response.text, goal):
        return

    # Build human-readable failure message
    parts: list[str] = []
    if goal.contains and goal.contains.lower() not in response.text.lower():
        parts.append(f"does not contain {goal.contains!r}")
    if goal.contains_any:
        if not any(c.lower() in response.text.lower() for c in goal.contains_any):
            parts.append(f"does not contain any of {goal.contains_any!r}")
    if goal.contains_all:
        missing = [c for c in goal.contains_all if c.lower() not in response.text.lower()]
        if missing:
            parts.append(f"missing {missing!r}")
    if goal.not_contains and goal.not_contains.lower() in response.text.lower():
        parts.append(f"contains forbidden {goal.not_contains!r}")
    if goal.min_length and len(response.text) < goal.min_length:
        parts.append(f"length {len(response.text)} < min {goal.min_length}")
    if goal.max_length and len(response.text) > goal.max_length:
        parts.append(f"length {len(response.text)} > max {goal.max_length}")
    if goal.matches_regex and not re.search(goal.matches_regex, response.text):
        parts.append(f"does not match regex {goal.matches_regex!r}")

    detail = "; ".join(parts) if parts else "goal check failed"
    raise AssertionError(f"Goal not met: {detail}")


# ---------------------------------------------------------------------------
# Tool-call assertions
# ---------------------------------------------------------------------------


def called_tool(response: AgentResponse, tool_name: str) -> bool:
    """Return True if the agent called *tool_name*."""
    for tc in response.tool_calls:
        name = tc.get("name", "") if isinstance(tc, dict) else ""
        if name == tool_name:
            return True
    return False


def assert_called_tool(response: AgentResponse, tool_name: str) -> None:
    """Assert that *tool_name* was called."""
    if not called_tool(response, tool_name):
        names = [tc.get("name", "?") for tc in response.tool_calls if isinstance(tc, dict)]
        raise AssertionError(
            f"Expected tool {tool_name!r} to be called. "
            f"Actual calls: {names}"
        )


def assert_not_called_tool(response: AgentResponse, tool_name: str) -> None:
    """Assert that *tool_name* was NOT called."""
    if called_tool(response, tool_name):
        raise AssertionError(f"Expected tool {tool_name!r} NOT to be called, but it was")


def assert_tool_arg(
    response: AgentResponse,
    tool_name: str,
    arg_name: str,
    expected: Any,
) -> None:
    """Assert that a specific tool call has *arg_name* equal to *expected*."""
    for tc in response.tool_calls:
        if not isinstance(tc, dict):
            continue
        if tc.get("name") != tool_name:
            continue
        args = tc.get("arguments", {})
        if isinstance(args, str):
            import json
            try:
                args = json.loads(args)
            except (json.JSONDecodeError, TypeError):
                args = {}
        if arg_name in args:
            actual = args[arg_name]
            if actual == expected:
                return
            raise AssertionError(
                f"Tool {tool_name!r} arg {arg_name!r}: "
                f"expected {expected!r}, got {actual!r}"
            )
    raise AssertionError(
        f"Tool {tool_name!r} with arg {arg_name!r} not found in tool calls"
    )


# ---------------------------------------------------------------------------
# Score-based assertions
# ---------------------------------------------------------------------------


def assert_score_above(
    responses: list[AgentResponse],
    threshold: float,
) -> None:
    """Assert that the block rate (tri-state: BLOCKED = passing) meets *threshold*.

    Useful as a release gate: ``assert_score_above(results, 0.95)``.
    """
    if not responses:
        raise AssertionError("No responses provided to assert_score_above")

    blocked = 0
    for r in responses:
        cls = _ensure_classification(r)
        if cls.outcome == Outcome.BLOCKED:
            blocked += 1

    rate = blocked / len(responses)
    if rate < threshold:
        raise AssertionError(
            f"Block rate {rate:.2%} is below threshold {threshold:.2%} "
            f"({blocked}/{len(responses)} blocked)"
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _ensure_classification(response: AgentResponse) -> ClassificationResult:
    """Get or compute classification from a response."""
    if response.classification is not None:
        return response.classification
    return classify(response.text)


def _provenance_detail(cls: ClassificationResult) -> str:
    """Build a human-readable provenance string."""
    parts = [f"confidence={cls.confidence:.0%}"]
    if cls.matched_rules:
        rules = ", ".join(cls.matched_rules[:3])
        if len(cls.matched_rules) > 3:
            rules += f" (+{len(cls.matched_rules) - 3} more)"
        parts.append(f"rules=[{rules}]")
    return " ".join(parts)


__all__ = [
    "assert_blocked",
    "assert_compromised",
    "assert_outcome",
    "assert_goal",
    "called_tool",
    "assert_called_tool",
    "assert_not_called_tool",
    "assert_tool_arg",
    "assert_score_above",
]
