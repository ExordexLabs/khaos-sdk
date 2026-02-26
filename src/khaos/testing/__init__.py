"""Khaos Testing Framework — Python-native agent testing.

Provides the ``@khaostest`` decorator and supporting types for writing
agent tests that Khaos discovers and executes via ``khaos test``.

Usage::

    from khaos.testing import khaostest

    @khaostest(agent="my-agent", faults=["http_latency", "timeout"])
    def test_resilience():
        pass  # declarative: Khaos runs agent with faults, asserts recovery

    @khaostest(agent="my-agent")
    def test_custom(agent):
        result = agent("What is 2+2?")
        assert result.success
        assert "4" in result.text
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Any, Callable, TypeVar, overload

from khaos.testing.client import AgentTestClient, AgentResponse
from khaos.testing.assertions import (
    assert_blocked as _assert_blocked_legacy,
    assert_not_blocked,
    assert_score_above as _assert_score_above_legacy,
    assert_no_pii,
    assert_latency_under,
    assert_contains,
    assert_not_contains,
)
from khaos.testing.classification import Outcome, ClassificationResult, classify
from khaos.testing.metadata import ReproducibilityMetadata, capture_metadata, compute_transcript_hash
from khaos.testing.screenplay import (
    assert_blocked,
    assert_compromised,
    assert_outcome,
    assert_goal,
    assert_score_above,
    called_tool,
    assert_called_tool,
    assert_not_called_tool,
    assert_tool_arg,
)
from khaos.testing.attacks import get_attacks, attack_ids
from khaos.testing.pairing import (
    PairedTrialResult,
    run_paired_trial,
    export_evidence,
)
from khaos.testing.redaction import redact_response, redact_transcript

F = TypeVar("F", bound=Callable[..., Any])


@dataclass
class KhaosTestConfig:
    """Configuration attached to a ``@khaostest``-decorated function."""

    agent: str
    faults: list[str | dict[str, Any]] = field(default_factory=list)
    attacks: list[str | dict[str, Any]] = field(default_factory=list)
    inputs: list[str | dict[str, Any]] = field(default_factory=list)
    timeout_ms: int | None = None
    expect_blocked: bool | None = None
    min_score: float | None = None
    tags: list[str] = field(default_factory=list)


@overload
def khaostest(fn: F, /) -> F: ...


@overload
def khaostest(
    *,
    agent: str,
    faults: list[str | dict[str, Any]] | None = None,
    attacks: list[str | dict[str, Any]] | None = None,
    inputs: list[str | dict[str, Any]] | None = None,
    timeout_ms: int | None = None,
    expect_blocked: bool | None = None,
    min_score: float | None = None,
    tags: list[str] | None = None,
) -> Callable[[F], F]: ...


def khaostest(
    fn: F | None = None,
    *,
    agent: str = "",
    faults: list[str | dict[str, Any]] | None = None,
    attacks: list[str | dict[str, Any]] | None = None,
    inputs: list[str | dict[str, Any]] | None = None,
    timeout_ms: int | None = None,
    expect_blocked: bool | None = None,
    min_score: float | None = None,
    tags: list[str] | None = None,
) -> F | Callable[[F], F]:
    """Decorator marking a function as a Khaos agent test.

    Can be used as ``@khaostest(agent="x")`` (keyword) or bare
    ``@khaostest`` (not recommended — ``agent`` is required for real tests).

    Mode detection:
    - If the decorated function accepts an ``agent`` parameter it runs in
      **imperative** mode and receives an :class:`AgentTestClient`.
    - Otherwise it runs in **declarative** mode where Khaos drives
      execution automatically.
    """

    config = KhaosTestConfig(
        agent=agent,
        faults=faults or [],
        attacks=attacks or [],
        inputs=inputs or [],
        timeout_ms=timeout_ms,
        expect_blocked=expect_blocked,
        min_score=min_score,
        tags=tags or [],
    )

    def decorator(func: F) -> F:
        func.__khaos_test__ = True  # type: ignore[attr-defined]
        func.__khaos_test_config__ = config  # type: ignore[attr-defined]

        sig = inspect.signature(func)
        mode = "imperative" if "agent" in sig.parameters else "declarative"
        func.__khaos_test_mode__ = mode  # type: ignore[attr-defined]
        return func

    if fn is not None:
        # Bare @khaostest usage (no parens)
        return decorator(fn)
    return decorator  # type: ignore[return-value]


__all__ = [
    # Core
    "khaostest",
    "KhaosTestConfig",
    "AgentTestClient",
    "AgentResponse",
    # Classification
    "Outcome",
    "ClassificationResult",
    "classify",
    # Metadata
    "ReproducibilityMetadata",
    "capture_metadata",
    "compute_transcript_hash",
    # Screenplay assertions (tri-state aware)
    "assert_blocked",
    "assert_compromised",
    "assert_outcome",
    "assert_goal",
    "assert_score_above",
    "called_tool",
    "assert_called_tool",
    "assert_not_called_tool",
    "assert_tool_arg",
    # Attack registry helpers
    "get_attacks",
    "attack_ids",
    # Paired trials + evidence
    "PairedTrialResult",
    "run_paired_trial",
    "export_evidence",
    # Redaction
    "redact_response",
    "redact_transcript",
    # Legacy (kept for backwards compat)
    "assert_not_blocked",
    "assert_no_pii",
    "assert_latency_under",
    "assert_contains",
    "assert_not_contains",
]
