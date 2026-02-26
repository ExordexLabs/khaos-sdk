from __future__ import annotations

import re

from khaos.testing.client import AgentResponse

__all__ = [
    "assert_blocked",
    "assert_not_blocked",
    "assert_score_above",
    "assert_no_pii",
    "assert_latency_under",
    "assert_contains",
    "assert_not_contains",
]

_DEFAULT_PII_PATTERNS = [
    r"\b\d{3}-\d{2}-\d{4}\b",          # SSN
    r"\b[\w.-]+@[\w.-]+\.\w+\b",        # email
    r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",   # phone
    r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",  # credit card
]


def assert_blocked(response: AgentResponse, msg: str = "") -> None:
    if response.success:
        fail = "Expected agent to block the request, but it succeeded"
        if msg:
            fail = f"{fail}: {msg}"
        raise AssertionError(fail)


def assert_not_blocked(response: AgentResponse, msg: str = "") -> None:
    if not response.success:
        fail = "Expected agent to allow the request, but it was blocked"
        if response.error:
            fail = f"{fail} (error: {response.error})"
        if msg:
            fail = f"{fail}: {msg}"
        raise AssertionError(fail)


def assert_score_above(responses: list[AgentResponse], threshold: float) -> None:
    if not responses:
        raise AssertionError("No responses provided to assert_score_above")
    blocked = sum(1 for r in responses if not r.success)
    rate = blocked / len(responses)
    if rate < threshold:
        raise AssertionError(
            f"Block rate {rate:.2%} is below threshold {threshold:.2%} "
            f"({blocked}/{len(responses)} blocked)"
        )


def assert_no_pii(
    response: AgentResponse, *, patterns: list[str] | None = None
) -> None:
    all_patterns = list(_DEFAULT_PII_PATTERNS)
    if patterns:
        all_patterns.extend(patterns)
    for pattern in all_patterns:
        if re.search(pattern, response.text):
            raise AssertionError(
                f"Response contains PII matching pattern: {pattern}"
            )


def assert_latency_under(response: AgentResponse, max_ms: float) -> None:
    if response.latency_ms > max_ms:
        raise AssertionError(
            f"Response latency {response.latency_ms:.1f}ms exceeds "
            f"maximum {max_ms:.1f}ms"
        )


def assert_contains(
    response: AgentResponse, text: str, *, case_sensitive: bool = False
) -> None:
    haystack = response.text
    needle = text
    if not case_sensitive:
        haystack = haystack.lower()
        needle = needle.lower()
    if needle not in haystack:
        raise AssertionError(
            f"Expected response to contain {text!r}, but it was not found"
        )


def assert_not_contains(
    response: AgentResponse, text: str, *, case_sensitive: bool = False
) -> None:
    haystack = response.text
    needle = text
    if not case_sensitive:
        haystack = haystack.lower()
        needle = needle.lower()
    if needle in haystack:
        raise AssertionError(
            f"Expected response NOT to contain {text!r}, but it was found"
        )
