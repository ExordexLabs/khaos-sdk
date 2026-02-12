"""Assertion evaluation utilities with trace-based assertion support."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from collections.abc import Iterable
import re

from khaos.chaos.scenario import AssertionDefinition

@dataclass(slots=True)
class AssertionResult:
    """Outcome of a single assertion evaluation."""

    name: str
    passed: bool
    actual: Any
    expected: Any
    message: str
    target: str = "final_response"  # Which target was evaluated

def _extract_value(payload: Any, path: str) -> Any:
    """Extract nested value from payload following dot-delimited path."""

    current: Any = payload
    for part in path.split('.'):
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, (list, tuple)):
            try:
                index = int(part)
            except ValueError:
                return None
            if index >= len(current):
                return None
            current = current[index]
        else:
            return None
    return current

def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, bytes)):
        return value.decode() if isinstance(value, bytes) else value
    return str(value)

def _is_tool_event(event: dict[str, Any]) -> bool:
    """Check if a trace event represents a tool/MCP call."""
    event_type = event.get("event", "")
    return any(pattern in event_type.lower() for pattern in [
        "tool", "mcp", "function_call", "tool_call"
    ])

def _is_llm_event(event: dict[str, Any]) -> bool:
    """Check if a trace event represents an LLM call."""
    event_type = event.get("event", "")
    return any(pattern in event_type.lower() for pattern in [
        "llm", "completion", "chat", "generate", "anthropic", "openai"
    ])

def _filter_events(
    trace: list[dict[str, Any]],
    event_filter: str | None,
) -> list[dict[str, Any]]:
    """Filter trace events by event type pattern."""
    if not event_filter:
        return trace
    return [
        event for event in trace
        if event_filter.lower() in event.get("event", "").lower()
    ]

def _get_tool_calls(trace: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract all tool/MCP calls from trace."""
    return [event for event in trace if _is_tool_event(event)]

def _get_llm_calls(trace: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract all LLM calls from trace."""
    return [event for event in trace if _is_llm_event(event)]

def _extract_target_payload(
    definition: AssertionDefinition,
    final_response: dict[str, Any] | None,
    trace: list[dict[str, Any]] | None,
) -> tuple[Any, str]:
    """
    Extract the payload to evaluate based on assertion target.

    Returns:
        Tuple of (payload_to_evaluate, description_of_what_was_evaluated)
    """
    target = definition.target
    trace = trace or []

    if target == "final_response":
        return final_response or {}, "final_response"

    elif target == "last_tool_call":
        tool_calls = _get_tool_calls(trace)
        tool_calls = _filter_events(tool_calls, definition.event_filter)
        if tool_calls:
            return tool_calls[-1], f"last_tool_call (of {len(tool_calls)})"
        return None, "last_tool_call (none found)"

    elif target == "first_tool_call":
        tool_calls = _get_tool_calls(trace)
        tool_calls = _filter_events(tool_calls, definition.event_filter)
        if tool_calls:
            return tool_calls[0], f"first_tool_call (of {len(tool_calls)})"
        return None, "first_tool_call (none found)"

    elif target == "nth_tool_call":
        index = definition.target_index or 0
        tool_calls = _get_tool_calls(trace)
        tool_calls = _filter_events(tool_calls, definition.event_filter)
        if index < len(tool_calls):
            return tool_calls[index], f"tool_call[{index}] (of {len(tool_calls)})"
        return None, f"tool_call[{index}] (only {len(tool_calls)} found)"

    elif target == "any_tool_call":
        # Special case: returns list of all tool calls for "any" matching
        tool_calls = _get_tool_calls(trace)
        tool_calls = _filter_events(tool_calls, definition.event_filter)
        return tool_calls, f"any_tool_call ({len(tool_calls)} candidates)"

    elif target == "last_llm_call":
        llm_calls = _get_llm_calls(trace)
        llm_calls = _filter_events(llm_calls, definition.event_filter)
        if llm_calls:
            return llm_calls[-1], f"last_llm_call (of {len(llm_calls)})"
        return None, "last_llm_call (none found)"

    elif target == "first_llm_call":
        llm_calls = _get_llm_calls(trace)
        llm_calls = _filter_events(llm_calls, definition.event_filter)
        if llm_calls:
            return llm_calls[0], f"first_llm_call (of {len(llm_calls)})"
        return None, "first_llm_call (none found)"

    elif target == "any_trace_event":
        # Special case: returns filtered trace for "any" matching
        filtered = _filter_events(trace, definition.event_filter)
        return filtered, f"any_trace_event ({len(filtered)} candidates)"

    # Unknown target - should be caught by validation, but fallback to empty
    return None, f"unknown_target:{target}"

def run_assertions(
    *,
    assertions: Iterable[AssertionDefinition],
    final_response: dict[str, Any] | None,
    trace: list[dict[str, Any]] | None = None,
) -> list[AssertionResult]:
    """Evaluate scenario assertions against the final response and/or trace.

    Args:
        assertions: Assertion definitions from the scenario
        final_response: The final agent output payload
        trace: Optional list of trace events for intermediate assertions

    Returns:
        List of assertion results
    """

    results: list[AssertionResult] = []

    for definition in assertions:
        payload, target_desc = _extract_target_payload(
            definition, final_response, trace
        )

        # Handle "any" targets - check if ANY item in the list passes
        if definition.target in ("any_tool_call", "any_trace_event"):
            if isinstance(payload, list) and payload:
                # Check each candidate - pass if ANY matches
                any_passed = False
                actual_values = []
                for candidate in payload:
                    actual_value = _extract_value(candidate, definition.path)
                    actual_values.append(actual_value)
                    if _evaluate_assertion(definition, actual_value):
                        any_passed = True
                        break

                passed = any_passed
                actual_value = actual_values[0] if actual_values else None
                message = "passed" if passed else _failure_message(
                    definition, actual_value, f" (checked {len(payload)} events)"
                )
            else:
                # No candidates found
                passed = False
                actual_value = None
                message = f"No matching events found for {definition.target}"
        else:
            # Standard single-target assertion
            actual_value = _extract_value(payload, definition.path) if payload else None
            passed = _evaluate_assertion(definition, actual_value)
            message = "passed" if passed else _failure_message(definition, actual_value)

        results.append(
            AssertionResult(
                name=definition.name,
                passed=passed,
                actual=actual_value,
                expected=definition.expected,
                message=message,
                target=target_desc,
            )
        )

    return results

def _evaluate_assertion(definition: AssertionDefinition, actual_value: Any) -> bool:
    """Evaluate a single assertion against an actual value."""
    expected = definition.expected
    ignore_case = definition.ignore_case
    actual_text = _to_text(actual_value)
    expected_text = expected if not ignore_case else expected.lower()
    compare_value = actual_text if not ignore_case else actual_text.lower()

    assertion_type = definition.type

    if assertion_type == "equals":
        return compare_value == expected_text

    if assertion_type == "not_equals":
        return compare_value != expected_text

    if assertion_type == "contains":
        return expected_text in compare_value

    if assertion_type == "not_contains":
        return expected_text not in compare_value

    if assertion_type == "exists":
        # Pass if the value exists and is not None/empty
        return actual_value is not None and actual_text != ""

    if assertion_type == "regex":
        flags = re.IGNORECASE if ignore_case else 0
        try:
            return re.search(expected, actual_text, flags) is not None
        except re.error:
            return False

    return False

def _failure_message(
    definition: AssertionDefinition,
    actual_value: Any,
    suffix: str = "",
) -> str:
    """Generate a human-readable failure message."""
    actual_text = _to_text(actual_value)
    # Truncate long values for readability
    if len(actual_text) > 100:
        actual_text = actual_text[:100] + "..."

    return (
        f"Assertion '{definition.name}' failed: expected {definition.type} "
        f"'{definition.expected}' at path '{definition.path}' "
        f"but got '{actual_text}'{suffix}"
    )
