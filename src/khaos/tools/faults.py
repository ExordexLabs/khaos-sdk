"""Tool execution fault injection for agent behavior testing.

This module provides fault injection capabilities for tool calls,
enabling testing of agent resilience when tools fail, timeout, or
return unexpected responses.

Fault Types:
- tool_timeout: Tool exceeds execution timeout
- tool_error: Tool returns an error instead of result
- tool_malformed_response: Tool returns syntactically valid but semantically wrong data
- tool_unavailable: Tool service is down or unreachable
- tool_partial_failure: Tool partially succeeds (some operations work, others fail)
- tool_rate_limited: Tool-level rate limiting (distinct from LLM rate limits)
"""

from __future__ import annotations

import json
import os
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeVar
from collections.abc import Callable

# Supported tool fault types
TOOL_FAULT_TYPES = {
    "tool_timeout",
    "tool_error",
    "tool_malformed_response",
    "tool_unavailable",
    "tool_partial_failure",
    "tool_rate_limited",
}

# Scenario metadata for behavioral analysis
TOOL_FAULT_SCENARIOS = {
    "tool_timeout": {
        "title": "Tool Execution Timeout",
        "short_title": "Tool Timeout",
        "description": "External tool exceeds execution timeout",
        "category": "tool-execution",
        "expected_behaviors": [
            {
                "pattern": "cancel_request",
                "description": "Cancel long-running tool calls",
                "required": True,
            },
            {
                "pattern": "retry_with_timeout",
                "description": "Retry with appropriate timeout settings",
                "required": False,
            },
            {
                "pattern": "fallback_alternative",
                "description": "Fall back to alternative tools",
                "required": False,
            },
            {
                "pattern": "user_notification",
                "description": "Notify user of tool delay",
                "required": False,
            },
        ],
        "recommendation": "Implement tool execution timeouts and consider alternative tools for critical operations.",
    },
    "tool_error": {
        "title": "Tool Execution Error",
        "short_title": "Tool Error",
        "description": "Tool returns error instead of result",
        "category": "tool-execution",
        "expected_behaviors": [
            {
                "pattern": "handle_gracefully",
                "description": "Handle tool errors gracefully",
                "required": True,
            },
            {
                "pattern": "retry_on_transient",
                "description": "Retry on transient errors",
                "required": False,
            },
            {
                "pattern": "user_notification",
                "description": "Notify user of tool failure",
                "required": True,
            },
        ],
        "recommendation": "Implement robust error handling and provide clear feedback when tools fail.",
    },
    "tool_malformed_response": {
        "title": "Tool Returns Invalid Data",
        "short_title": "Malformed Response",
        "description": "Tool returns syntactically valid but semantically wrong data",
        "category": "tool-execution",
        "expected_behaviors": [
            {
                "pattern": "validate_output",
                "description": "Validate tool outputs against expected schema",
                "required": True,
            },
            {
                "pattern": "detect_anomalies",
                "description": "Detect semantic anomalies in responses",
                "required": False,
            },
            {
                "pattern": "request_correction",
                "description": "Request corrected data when anomalies detected",
                "required": False,
            },
        ],
        "recommendation": "Implement output validation and sanity checks for tool responses.",
    },
    "tool_unavailable": {
        "title": "Tool Temporarily Unavailable",
        "short_title": "Tool Unavailable",
        "description": "Tool service is down or unreachable",
        "category": "tool-execution",
        "expected_behaviors": [
            {
                "pattern": "detect_unavailability",
                "description": "Detect tool unavailability",
                "required": True,
            },
            {
                "pattern": "fallback_alternative",
                "description": "Fall back to alternative tools",
                "required": False,
            },
            {
                "pattern": "cache_last_known",
                "description": "Use cached last-known-good results",
                "required": False,
            },
            {
                "pattern": "graceful_degradation",
                "description": "Degrade gracefully without the tool",
                "required": True,
            },
        ],
        "recommendation": "Implement tool health checks and configure fallback alternatives for critical tools.",
    },
    "tool_partial_failure": {
        "title": "Tool Partial Failure",
        "short_title": "Partial Failure",
        "description": "Tool partially succeeds - some operations work, others fail",
        "category": "tool-execution",
        "expected_behaviors": [
            {
                "pattern": "handle_partial_results",
                "description": "Handle partial results appropriately",
                "required": True,
            },
            {
                "pattern": "retry_failed_parts",
                "description": "Retry only the failed operations",
                "required": False,
            },
            {
                "pattern": "report_partial_status",
                "description": "Report partial success/failure to user",
                "required": True,
            },
        ],
        "recommendation": "Design for partial failures and implement granular retry logic.",
    },
    "tool_rate_limited": {
        "title": "Tool Rate Limited",
        "short_title": "Tool Rate Limit",
        "description": "Tool-level rate limiting (e.g., API quota exceeded)",
        "category": "tool-execution",
        "expected_behaviors": [
            {
                "pattern": "respect_rate_limits",
                "description": "Respect tool rate limits",
                "required": True,
            },
            {
                "pattern": "queue_requests",
                "description": "Queue requests when rate limited",
                "required": False,
            },
            {
                "pattern": "backoff_retry",
                "description": "Implement exponential backoff",
                "required": True,
            },
        ],
        "recommendation": "Implement request throttling and respect tool-specific rate limits.",
    },
}

def _log_tool_fault_event(payload: dict[str, Any]) -> None:
    """Log a tool fault event for dashboard visibility."""
    path = os.environ.get("KHAOS_LLM_EVENT_FILE")
    if not path:
        return

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": "tool.fault",
        "payload": payload,
        "meta": {},
    }
    try:
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
    except OSError:
        return

class ToolFaultInjector:
    """Injects faults into tool executions for resilience testing.

    Usage:
        injector = ToolFaultInjector(rules=[
            {"type": "tool_timeout", "config": {"tool_name": "search", "timeout_ms": 5000}}
        ])

        # Wrap tool execution
        result = injector.maybe_inject(
            tool_name="search",
            execute_fn=lambda: actual_search(query),
            args={"query": "test"},
        )
    """

    def __init__(
        self,
        rules: list[dict[str, Any]] | None = None,
        seed: int | None = None,
    ):
        self.rules = rules or []
        self.rng = random.Random(seed or 0)

    def _select_rule(self, tool_name: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
        """Select applicable fault rule for the tool."""
        for rule in self.rules:
            rule_type = str(rule.get("type", "")).strip()
            if rule_type not in TOOL_FAULT_TYPES:
                continue

            cfg = rule.get("config", {}) or {}

            # Check tool name filter
            target_tool = cfg.get("tool_name")
            if target_tool and target_tool != tool_name and target_tool != "*":
                continue

            # Check probability
            probability = float(cfg.get("probability", 1.0))
            if self.rng.random() > probability:
                continue

            return rule, cfg

        return None

    def maybe_inject(
        self,
        tool_name: str,
        execute_fn: Callable[[], Any],
        args: dict[str, Any] | None = None,
    ) -> Any:
        """Execute tool with potential fault injection.

        Args:
            tool_name: Name of the tool being executed
            execute_fn: Function to execute the actual tool
            args: Arguments passed to the tool (for logging)

        Returns:
            Tool result, or raises an exception if fault is injected

        Raises:
            ToolTimeoutError: When tool_timeout fault is injected
            ToolExecutionError: When tool_error fault is injected
            ToolUnavailableError: When tool_unavailable fault is injected
        """
        selection = self._select_rule(tool_name)

        if not selection:
            return execute_fn()

        rule, cfg = selection
        rule_type = rule.get("type")

        payload = {
            "type": rule_type,
            "tool_name": tool_name,
            "config": cfg,
            "args": args,
        }

        if rule_type == "tool_timeout":
            timeout_ms = float(cfg.get("timeout_ms", 30000))
            time.sleep(timeout_ms / 1000.0)
            _log_tool_fault_event(payload | {"status": "raised", "timeout_ms": timeout_ms})
            raise ToolTimeoutError(
                f"Tool '{tool_name}' execution timed out after {timeout_ms}ms"
            )

        elif rule_type == "tool_error":
            error_type = cfg.get("error_type", "internal_error")
            error_message = cfg.get(
                "error_message",
                f"Tool '{tool_name}' encountered an error: {error_type}",
            )
            _log_tool_fault_event(
                payload | {"status": "raised", "error_type": error_type}
            )
            raise ToolExecutionError(error_message, error_type=error_type)

        elif rule_type == "tool_unavailable":
            _log_tool_fault_event(payload | {"status": "raised"})
            raise ToolUnavailableError(
                f"Tool '{tool_name}' is temporarily unavailable"
            )

        elif rule_type == "tool_malformed_response":
            # Execute the tool but corrupt the response
            result = execute_fn()
            corruption_type = cfg.get("corruption_type", "missing_fields")
            _log_tool_fault_event(
                payload | {"status": "corrupted", "corruption_type": corruption_type}
            )
            return self._corrupt_response(result, corruption_type, cfg)

        elif rule_type == "tool_partial_failure":
            # Execute and return partial result
            result = execute_fn()
            failure_ratio = float(cfg.get("failure_ratio", 0.5))
            _log_tool_fault_event(
                payload | {"status": "partial", "failure_ratio": failure_ratio}
            )
            return self._partial_result(result, failure_ratio)

        elif rule_type == "tool_rate_limited":
            retry_after = int(cfg.get("retry_after", 60))
            _log_tool_fault_event(
                payload | {"status": "raised", "retry_after": retry_after}
            )
            raise ToolRateLimitError(
                f"Tool '{tool_name}' rate limited. Retry after {retry_after}s",
                retry_after=retry_after,
            )

        # Unknown fault type, execute normally
        return execute_fn()

    def _corrupt_response(
        self, result: Any, corruption_type: str, cfg: dict[str, Any]
    ) -> Any:
        """Corrupt a tool response based on corruption type."""
        if not isinstance(result, dict):
            return result

        corrupted = dict(result)

        if corruption_type == "missing_fields":
            # Remove random fields
            keys = list(corrupted.keys())
            if keys:
                to_remove = self.rng.sample(
                    keys, min(len(keys) // 2 + 1, len(keys))
                )
                for key in to_remove:
                    del corrupted[key]

        elif corruption_type == "wrong_types":
            # Replace values with wrong types
            for key, value in list(corrupted.items()):
                if isinstance(value, str):
                    corrupted[key] = 12345
                elif isinstance(value, (int, float)):
                    corrupted[key] = "corrupted_value"
                elif isinstance(value, bool):
                    corrupted[key] = "not_a_boolean"

        elif corruption_type == "invalid_values":
            # Replace with semantically invalid values
            for key, value in list(corrupted.items()):
                if isinstance(value, str):
                    corrupted[key] = ""
                elif isinstance(value, (int, float)):
                    corrupted[key] = -999999
                elif isinstance(value, list):
                    corrupted[key] = []

        elif corruption_type == "null_injection":
            # Replace some values with None
            for key in self.rng.sample(
                list(corrupted.keys()),
                min(len(corrupted) // 2 + 1, len(corrupted)),
            ):
                corrupted[key] = None

        return corrupted

    def _partial_result(self, result: Any, failure_ratio: float) -> dict[str, Any]:
        """Return partial result with some operations failed."""
        if not isinstance(result, dict):
            return {
                "partial": True,
                "success_count": 0,
                "failure_count": 1,
                "data": None,
                "error": "Partial failure: result corrupted",
            }

        # If result has list-like data, return partial
        if isinstance(result.get("data"), list):
            data = result["data"]
            success_count = int(len(data) * (1 - failure_ratio))
            return {
                "partial": True,
                "success_count": success_count,
                "failure_count": len(data) - success_count,
                "data": data[:success_count],
                "errors": [
                    f"Operation {i} failed" for i in range(success_count, len(data))
                ],
            }

        # Otherwise, mark as partially failed
        return {
            "partial": True,
            "success_count": 1,
            "failure_count": 1,
            "data": result,
            "error": "Some operations failed",
        }

class ToolFaultError(Exception):
    """Base exception for tool faults."""

    pass

class ToolTimeoutError(ToolFaultError):
    """Tool execution timed out."""

    pass

class ToolExecutionError(ToolFaultError):
    """Tool execution failed."""

    def __init__(self, message: str, error_type: str = "internal_error"):
        super().__init__(message)
        self.error_type = error_type

class ToolUnavailableError(ToolFaultError):
    """Tool is temporarily unavailable."""

    pass

class ToolRateLimitError(ToolFaultError):
    """Tool rate limited."""

    def __init__(self, message: str, retry_after: int = 60):
        super().__init__(message)
        self.retry_after = retry_after

# Convenience function for getting scenario metadata
def get_tool_fault_scenario(fault_type: str) -> dict[str, Any] | None:
    """Get scenario metadata for a tool fault type."""
    return TOOL_FAULT_SCENARIOS.get(fault_type)

__all__ = [
    "TOOL_FAULT_TYPES",
    "TOOL_FAULT_SCENARIOS",
    "ToolFaultInjector",
    "ToolFaultError",
    "ToolTimeoutError",
    "ToolExecutionError",
    "ToolUnavailableError",
    "ToolRateLimitError",
    "get_tool_fault_scenario",
]
