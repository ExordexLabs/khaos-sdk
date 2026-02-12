"""Pack execution context - replaces global mutable state.

This module provides a context class that holds all state needed during
pack evaluation, replacing the previous global variables like:
- _security_events
- _attack_configs

Using a context object makes the code:
1. Thread-safe
2. Testable (can create isolated contexts)
3. Easier to understand (explicit state passing)
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from khaos.agent import AgentMetadata


@dataclass
class PackExecutionContext:
    """Context for a single pack execution run.

    Holds all mutable state that was previously stored in module-level globals.
    Pass this context through the call chain instead of relying on global state.
    """

    # Security testing state
    security_events: list[dict[str, Any]] = field(default_factory=list)
    attack_configs: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Trace collection
    trace_events: list[dict[str, Any]] = field(default_factory=list)
    trace_lock: threading.Lock = field(default_factory=threading.Lock)

    # Capability probing
    probe_events: list[dict[str, Any]] = field(default_factory=list)
    capabilities: dict[str, Any] = field(default_factory=dict)

    # Agent metadata
    agent_metadata: AgentMetadata | None = None
    security_mode: str = "agent_input"

    # Progress tracking (using lists for mutability in closures)
    current_phase: list[str] = field(default_factory=lambda: [""])
    current_input_id: list[str] = field(default_factory=lambda: [""])
    current_progress: list[int] = field(default_factory=lambda: [0, 0])

    # Test results (thread-safe)
    test_results_lock: threading.Lock = field(default_factory=threading.Lock)
    test_results: dict[str, list[Any]] = field(default_factory=dict)

    def clear_security_state(self) -> None:
        """Clear security events and attack configs for a new run."""
        self.security_events = []
        self.attack_configs = {}

    def add_security_event(self, event: dict[str, Any]) -> None:
        """Add a security event (thread-safe)."""
        self.security_events.append(event)

    def register_attack_config(self, attack_id: str, config: dict[str, Any]) -> None:
        """Register an attack configuration for evaluation."""
        self.attack_configs[attack_id] = config

    def add_trace_event(self, event: dict[str, Any]) -> None:
        """Add a trace event (thread-safe)."""
        with self.trace_lock:
            self.trace_events.append(event)

    def add_trace_events(self, events: list[dict[str, Any]]) -> None:
        """Add multiple trace events (thread-safe)."""
        with self.trace_lock:
            self.trace_events.extend(events)

    def add_test_result(self, phase: str, result: Any) -> None:
        """Add a test result (thread-safe)."""
        with self.test_results_lock:
            if phase not in self.test_results:
                self.test_results[phase] = []
            self.test_results[phase].append(result)


def create_pack_context(
    agent_metadata: AgentMetadata | None = None,
    security_mode: str = "agent_input",
) -> PackExecutionContext:
    """Create a new pack execution context.

    Args:
        agent_metadata: Optional agent metadata from discovery
        security_mode: Security testing mode ("agent_input" or "llm")

    Returns:
        Fresh PackExecutionContext instance
    """
    return PackExecutionContext(
        agent_metadata=agent_metadata,
        security_mode=security_mode,
    )


__all__ = ["PackExecutionContext", "create_pack_context"]
