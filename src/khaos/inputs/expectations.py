"""Expectation DSL for evaluating agent outputs.

Provides simple, readable assertions for test cases:
- contains: Output contains substring(s)
- not_contains: Output does not contain substring(s)
- regex: Output matches regex pattern(s)
- equals: Output exactly equals value
- min_turns: Minimum conversation turns
- max_turns: Maximum conversation turns
- tools_called: Specific tools were called
- no_tools: No tools were called
- min_tokens: Minimum token usage
- max_tokens: Maximum token usage
- latency_ms: Maximum response latency
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from khaos.inputs.schema import Expectation


@dataclass
class ExpectationResult:
    """Result of evaluating an expectation."""

    passed: bool
    expectation_type: str
    message: str
    expected: Any = None
    actual: Any = None
    details: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return f"[{status}] {self.expectation_type}: {self.message}"


def _normalize_to_list(value: Any) -> list[Any]:
    """Convert value to list if not already."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _check_contains(output: str, expected: str | list[str], case_sensitive: bool = False) -> ExpectationResult:
    """Check if output contains expected substring(s)."""
    expected_list = _normalize_to_list(expected)
    if not expected_list:
        return ExpectationResult(
            passed=True,
            expectation_type="contains",
            message="No contains expectations",
        )

    check_output = output if case_sensitive else output.lower()
    missing = []

    for exp in expected_list:
        check_exp = exp if case_sensitive else exp.lower()
        if check_exp not in check_output:
            missing.append(exp)

    if missing:
        return ExpectationResult(
            passed=False,
            expectation_type="contains",
            message=f"Output missing: {missing}",
            expected=expected_list,
            actual=output[:200] + "..." if len(output) > 200 else output,
        )

    return ExpectationResult(
        passed=True,
        expectation_type="contains",
        message=f"Output contains all expected: {expected_list}",
        expected=expected_list,
    )


def _check_not_contains(output: str, forbidden: str | list[str], case_sensitive: bool = False) -> ExpectationResult:
    """Check if output does not contain forbidden substring(s)."""
    forbidden_list = _normalize_to_list(forbidden)
    if not forbidden_list:
        return ExpectationResult(
            passed=True,
            expectation_type="not_contains",
            message="No not_contains expectations",
        )

    check_output = output if case_sensitive else output.lower()
    found = []

    for exp in forbidden_list:
        check_exp = exp if case_sensitive else exp.lower()
        if check_exp in check_output:
            found.append(exp)

    if found:
        return ExpectationResult(
            passed=False,
            expectation_type="not_contains",
            message=f"Output contains forbidden: {found}",
            expected=f"NOT: {forbidden_list}",
            actual=output[:200] + "..." if len(output) > 200 else output,
        )

    return ExpectationResult(
        passed=True,
        expectation_type="not_contains",
        message=f"Output does not contain: {forbidden_list}",
    )


def _check_regex(output: str, patterns: str | list[str]) -> ExpectationResult:
    """Check if output matches regex pattern(s)."""
    pattern_list = _normalize_to_list(patterns)
    if not pattern_list:
        return ExpectationResult(
            passed=True,
            expectation_type="regex",
            message="No regex expectations",
        )

    failed = []
    for pattern in pattern_list:
        try:
            if not re.search(pattern, output, re.IGNORECASE | re.DOTALL):
                failed.append(pattern)
        except re.error as e:
            return ExpectationResult(
                passed=False,
                expectation_type="regex",
                message=f"Invalid regex pattern '{pattern}': {e}",
                expected=pattern,
            )

    if failed:
        return ExpectationResult(
            passed=False,
            expectation_type="regex",
            message=f"Output does not match patterns: {failed}",
            expected=pattern_list,
            actual=output[:200] + "..." if len(output) > 200 else output,
        )

    return ExpectationResult(
        passed=True,
        expectation_type="regex",
        message=f"Output matches all patterns",
        expected=pattern_list,
    )


def _check_equals(output: str, expected: str) -> ExpectationResult:
    """Check if output exactly equals expected value."""
    if expected is None:
        return ExpectationResult(
            passed=True,
            expectation_type="equals",
            message="No equals expectation",
        )

    passed = output.strip() == expected.strip()
    return ExpectationResult(
        passed=passed,
        expectation_type="equals",
        message="Output equals expected" if passed else "Output does not equal expected",
        expected=expected,
        actual=output,
    )


def _check_turns(actual_turns: int, min_turns: int | None, max_turns: int | None) -> ExpectationResult:
    """Check if turn count is within expected range."""
    if min_turns is None and max_turns is None:
        return ExpectationResult(
            passed=True,
            expectation_type="turns",
            message="No turn expectations",
        )

    if min_turns is not None and actual_turns < min_turns:
        return ExpectationResult(
            passed=False,
            expectation_type="min_turns",
            message=f"Too few turns: {actual_turns} < {min_turns}",
            expected=min_turns,
            actual=actual_turns,
        )

    if max_turns is not None and actual_turns > max_turns:
        return ExpectationResult(
            passed=False,
            expectation_type="max_turns",
            message=f"Too many turns: {actual_turns} > {max_turns}",
            expected=max_turns,
            actual=actual_turns,
        )

    return ExpectationResult(
        passed=True,
        expectation_type="turns",
        message=f"Turn count {actual_turns} within range",
        actual=actual_turns,
    )


def _check_tools(tools_called: list[str], expected: list[str] | None, no_tools: bool) -> ExpectationResult:
    """Check tool call expectations."""
    if no_tools:
        if tools_called:
            return ExpectationResult(
                passed=False,
                expectation_type="no_tools",
                message=f"Expected no tools but got: {tools_called}",
                expected=[],
                actual=tools_called,
            )
        return ExpectationResult(
            passed=True,
            expectation_type="no_tools",
            message="No tools called as expected",
        )

    if expected is None:
        return ExpectationResult(
            passed=True,
            expectation_type="tools_called",
            message="No tool expectations",
        )

    missing = [t for t in expected if t not in tools_called]
    if missing:
        return ExpectationResult(
            passed=False,
            expectation_type="tools_called",
            message=f"Missing expected tools: {missing}",
            expected=expected,
            actual=tools_called,
        )

    return ExpectationResult(
        passed=True,
        expectation_type="tools_called",
        message=f"All expected tools called: {expected}",
        expected=expected,
        actual=tools_called,
    )


def _check_tokens(actual: int, min_tokens: int | None, max_tokens: int | None) -> ExpectationResult:
    """Check token usage is within expected range."""
    if min_tokens is None and max_tokens is None:
        return ExpectationResult(
            passed=True,
            expectation_type="tokens",
            message="No token expectations",
        )

    if min_tokens is not None and actual < min_tokens:
        return ExpectationResult(
            passed=False,
            expectation_type="min_tokens",
            message=f"Too few tokens: {actual} < {min_tokens}",
            expected=min_tokens,
            actual=actual,
        )

    if max_tokens is not None and actual > max_tokens:
        return ExpectationResult(
            passed=False,
            expectation_type="max_tokens",
            message=f"Too many tokens: {actual} > {max_tokens}",
            expected=max_tokens,
            actual=actual,
        )

    return ExpectationResult(
        passed=True,
        expectation_type="tokens",
        message=f"Token count {actual} within range",
        actual=actual,
    )


def _check_latency(actual_ms: float, max_ms: float | None) -> ExpectationResult:
    """Check latency is within expected limit."""
    if max_ms is None:
        return ExpectationResult(
            passed=True,
            expectation_type="latency",
            message="No latency expectation",
        )

    if actual_ms > max_ms:
        return ExpectationResult(
            passed=False,
            expectation_type="latency_ms",
            message=f"Too slow: {actual_ms:.1f}ms > {max_ms}ms",
            expected=max_ms,
            actual=actual_ms,
        )

    return ExpectationResult(
        passed=True,
        expectation_type="latency_ms",
        message=f"Latency {actual_ms:.1f}ms within limit",
        expected=max_ms,
        actual=actual_ms,
    )


def evaluate_expectation(
    expectation: Expectation,
    output: str,
    turns: int = 1,
    tools_called: list[str] | None = None,
    total_tokens: int = 0,
    latency_ms: float = 0.0,
) -> list[ExpectationResult]:
    """Evaluate an expectation against actual results.

    Args:
        expectation: The expectation to evaluate
        output: The agent's output text
        turns: Number of conversation turns
        tools_called: List of tool names that were called
        total_tokens: Total tokens used
        latency_ms: Total latency in milliseconds

    Returns:
        List of ExpectationResult for each check performed
    """
    results = []

    # Content checks
    if expectation.contains:
        results.append(_check_contains(output, expectation.contains))

    if expectation.not_contains:
        results.append(_check_not_contains(output, expectation.not_contains))

    if expectation.regex:
        results.append(_check_regex(output, expectation.regex))

    if expectation.equals is not None:
        results.append(_check_equals(output, expectation.equals))

    # Turn checks
    if expectation.min_turns or expectation.max_turns:
        results.append(_check_turns(turns, expectation.min_turns, expectation.max_turns))

    # Tool checks
    if expectation.tools_called or expectation.no_tools:
        results.append(_check_tools(tools_called or [], expectation.tools_called, expectation.no_tools))

    # Token checks
    if expectation.min_tokens or expectation.max_tokens:
        results.append(_check_tokens(total_tokens, expectation.min_tokens, expectation.max_tokens))

    # Latency checks
    if expectation.latency_ms:
        results.append(_check_latency(latency_ms, expectation.latency_ms))

    return results


def evaluate_expectations(
    expectation: Expectation,
    output: str,
    **kwargs: Any,
) -> tuple[bool, list[ExpectationResult]]:
    """Evaluate all expectations and return overall pass/fail.

    Args:
        expectation: The expectation to evaluate
        output: The agent's output text
        **kwargs: Additional context (turns, tools_called, etc.)

    Returns:
        Tuple of (all_passed, list of results)
    """
    results = evaluate_expectation(expectation, output, **kwargs)
    all_passed = all(r.passed for r in results) if results else True
    return all_passed, results
