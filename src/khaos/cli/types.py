"""Type definitions for the Khaos CLI.

Provides proper type aliases and protocols to replace `Any` usage
throughout the CLI codebase. This improves:
1. IDE support and autocompletion
2. Static type checking
3. Code documentation
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import (
    Any,
    Protocol,
    TypedDict,
    runtime_checkable,
)
from collections.abc import Callable

# ---------------------------------------------------------------------------
# Agent Invoker Types
# ---------------------------------------------------------------------------

@runtime_checkable
class AgentInvoker(Protocol):
    """Protocol for agent invoker functions."""

    def __call__(self, input_text: str) -> str:
        """Invoke the agent with input and return output."""
        ...

    # Optional metadata attached by invoker
    __khaos_last_metadata__: dict[str, Any]

@runtime_checkable
class MultiTurnInvoker(Protocol):
    """Protocol for multi-turn agent invoker functions."""

    def __call__(
        self,
        messages: list[dict[str, str]],
        turn_index: int,
    ) -> str:
        """Invoke the agent with conversation history."""
        ...

# ---------------------------------------------------------------------------
# Event Types
# ---------------------------------------------------------------------------

class TraceEvent(TypedDict, total=False):
    """A telemetry trace event."""

    event: str  # Event type (e.g., "llm.call", "http.request")
    ts: str  # ISO timestamp
    payload: dict[str, Any]
    context: dict[str, Any]

class SecurityEvent(TypedDict, total=False):
    """A security test event."""

    event: str  # "security.attack"
    timestamp: float
    payload: SecurityEventPayload

class SecurityEventPayload(TypedDict, total=False):
    """Payload for security events."""

    attack_id: str
    attack_type: str
    response: str
    injection_mode: str
    multi_turn: bool
    conversation: list[dict[str, str]]
    tool_calls: list[dict[str, Any]]

# ---------------------------------------------------------------------------
# Attack Configuration Types
# ---------------------------------------------------------------------------

class AttackConfig(TypedDict, total=False):
    """Configuration for a security attack."""

    attack_id: str
    attack_type: str
    payload: str
    forbidden_keywords: list[str]
    forbidden_tool_names: list[str]
    forbidden_tool_arg_markers: list[str]
    context_system: str | None
    severity: str  # "critical", "high", "medium", "low"
    category: str
    is_canary: bool
    turns: list[dict[str, str]]
    required_capability: str | None

# ---------------------------------------------------------------------------
# Capability Types
# ---------------------------------------------------------------------------

class AgentCapabilities(TypedDict, total=False):
    """Agent capability flags."""

    llm: bool
    http: bool
    mcp: bool
    tool_calling: bool
    multi_turn: bool
    rag: bool
    sources: CapabilitySources

class CapabilitySources(TypedDict, total=False):
    """Sources used to infer capabilities."""

    decorator_capabilities: list[str]
    probe_events: bool

# ---------------------------------------------------------------------------
# Result Types
# ---------------------------------------------------------------------------

@dataclass
class TestResult:
    """Result of a single test within a phase."""

    input_id: str
    passed: bool
    latency_ms: float = 0.0
    error: str | None = None

@dataclass
class PhaseProgress:
    """Progress tracking for a phase."""

    name: str
    total: int
    completed: int = 0
    started: bool = False
    finished: bool = False

# ---------------------------------------------------------------------------
# Message Types
# ---------------------------------------------------------------------------

class Message(TypedDict, total=False):
    """An LLM message."""

    role: str  # "user", "assistant", "system"
    content: str
    token_count: int | None
    timestamp: str | None
    tool_calls: list[ToolCall] | None
    model: str | None
    latency_ms: float | None

class ToolCall(TypedDict, total=False):
    """A tool/function call."""

    id: str
    name: str
    arguments: str
    result: str | None

# ---------------------------------------------------------------------------
# Fault Types
# ---------------------------------------------------------------------------

class FaultRule(TypedDict, total=False):
    """A fault injection rule."""

    type: str
    config: dict[str, Any]
    probability: float

# ---------------------------------------------------------------------------
# Report Types (Protocols for duck typing)
# ---------------------------------------------------------------------------

@runtime_checkable
class EvaluationReportProtocol(Protocol):
    """Protocol for evaluation reports."""

    run_id: str
    pack_name: str | None
    pack_version: str | None
    overall_score: float
    seed: int | None

    @property
    def baseline(self) -> Any | None:
        ...

    @property
    def resilience(self) -> Any | None:
        ...

    @property
    def security(self) -> Any | None:
        ...

    @property
    def input_results(self) -> list[Any]:
        ...

    @property
    def agent(self) -> Any | None:
        ...

    def to_dict(self) -> dict[str, Any]:
        ...

    def compute_overall_score(self) -> float:
        ...

@runtime_checkable
class SecurityMetricsProtocol(Protocol):
    """Protocol for security metrics."""

    score: float
    attacks_tested: int
    attacks_blocked: int
    attacks_passed: int
    attacks_inconclusive: int
    vulnerabilities: list[Any]
    vulnerable_categories: list[str]

@runtime_checkable
class ResilienceMetricsProtocol(Protocol):
    """Protocol for resilience metrics."""

    score: float
    recovery_rate: float
    degradation_percent: float
    error_rate: float

# ---------------------------------------------------------------------------
# Callback Types
# ---------------------------------------------------------------------------

ProgressCallback = Callable[[str, int, int], None]
"""Callback for progress updates: (phase_name, current, total)"""

ResultCallback = Callable[[str, str, bool, float, str | None], None]
"""Callback for test results: (phase, input_id, passed, latency_ms, error)"""

InputStartCallback = Callable[[str], None]
"""Callback when starting an input: (input_id)"""

# ---------------------------------------------------------------------------
# CLI Option Types
# ---------------------------------------------------------------------------

class RunOptions(TypedDict, total=False):
    """Options for the run command."""

    target: str
    handler: str | None
    scenario: str | None
    pack: str | None
    quick: bool
    security: bool
    attacks: str | None
    inputs: str | None
    json_output: bool
    verbose: bool
    quiet: bool
    timeout: float
    env: list[str]
    python: str
    name: str | None
    compare: str | None
    sync_cloud: bool
    seed: int | None

class CIOptions(TypedDict, total=False):
    """Options for the ci command."""

    target: str
    pack: str
    security_threshold: int
    resilience_threshold: int
    format: str
    output_file: str | None
    json_file: str | None
    baseline: str | None
    save_baseline: str | None
    fail_on_regression: bool
    python: str
    env: list[str]
    timeout: float
    quiet: bool
    verbose: bool
    sync_cloud: bool

# ---------------------------------------------------------------------------
# Type Aliases for Common Patterns
# ---------------------------------------------------------------------------

# Environment dictionary
EnvDict = dict[str, str]

# JSON-serializable data
JsonData = dict[str, Any] | list[Any] | str | int | float | bool | None

# Path-like types
PathLike = str | "Path"  # noqa: F821

__all__ = [
    # Protocols
    "AgentInvoker",
    "MultiTurnInvoker",
    "EvaluationReportProtocol",
    "SecurityMetricsProtocol",
    "ResilienceMetricsProtocol",
    # TypedDicts
    "TraceEvent",
    "SecurityEvent",
    "SecurityEventPayload",
    "AttackConfig",
    "AgentCapabilities",
    "CapabilitySources",
    "Message",
    "ToolCall",
    "FaultRule",
    "RunOptions",
    "CIOptions",
    # Dataclasses
    "TestResult",
    "PhaseProgress",
    # Callbacks
    "ProgressCallback",
    "ResultCallback",
    "InputStartCallback",
    # Type Aliases
    "EnvDict",
    "JsonData",
    "PathLike",
]
