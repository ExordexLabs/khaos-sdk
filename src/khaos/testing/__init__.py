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
    "khaostest",
    "KhaosTestConfig",
    "AgentTestClient",
    "AgentResponse",
]
