"""Autogen adapter that emits structured telemetry during agent execution.

Provides instrumentation for Microsoft Autogen conversable agents, capturing
message flow, chat initiation, and conversation telemetry.
"""

from __future__ import annotations

import time
from typing import Any, Protocol
from collections.abc import Callable

from ..contract import make_envelope, normalize_payload
from ..telemetry import get_runtime_emitter

class TelemetryEmitter(Protocol):
    def __call__(self, event: str, envelope: dict[str, Any]) -> None:
        ...

class AutogenAdapter:
    """Minimal wrapper around an Autogen ConversableAgent instance.

    Wraps the core communication methods (send, receive, initiate_chat)
    to emit telemetry events for observability and fault injection.
    """

    def __init__(self, agent: Any, emit: TelemetryEmitter):
        self._agent = agent
        self._emit = emit
        self._emit("framework.autogen.bound", make_envelope("framework.autogen.bound", {"status": "ok"}))

    def send(self, message: Any, recipient: Any, *args: Any, **kwargs: Any) -> Any:
        """Send a message to another agent."""
        start = time.perf_counter()
        try:
            result = self._agent.send(message, recipient, *args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.autogen.send",
                make_envelope(
                    "framework.autogen.send",
                    {
                        "status": "ok",
                        "elapsed_ms": elapsed_ms,
                        "recipient": _get_agent_name(recipient),
                        "message_type": type(message).__name__,
                    },
                ),
            )
            _emit_message_telemetry(self._emit, "send", message, result)
            return result
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.autogen.error",
                make_envelope(
                    "framework.autogen.error",
                    {
                        "status": "error",
                        "elapsed_ms": elapsed_ms,
                        "error": str(exc),
                        "method": "send",
                    },
                ),
            )
            raise

    def receive(self, message: Any, sender: Any, *args: Any, **kwargs: Any) -> Any:
        """Receive and process a message from another agent."""
        start = time.perf_counter()
        try:
            result = self._agent.receive(message, sender, *args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.autogen.receive",
                make_envelope(
                    "framework.autogen.receive",
                    {
                        "status": "ok",
                        "elapsed_ms": elapsed_ms,
                        "sender": _get_agent_name(sender),
                        "message_type": type(message).__name__,
                    },
                ),
            )
            _emit_message_telemetry(self._emit, "receive", message, result)
            return result
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.autogen.error",
                make_envelope(
                    "framework.autogen.error",
                    {
                        "status": "error",
                        "elapsed_ms": elapsed_ms,
                        "error": str(exc),
                        "method": "receive",
                    },
                ),
            )
            raise

    def initiate_chat(self, recipient: Any, *args: Any, **kwargs: Any) -> Any:
        """Initiate a chat conversation with another agent."""
        start = time.perf_counter()
        try:
            result = self._agent.initiate_chat(recipient, *args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.autogen.initiate_chat",
                make_envelope(
                    "framework.autogen.initiate_chat",
                    {
                        "status": "ok",
                        "elapsed_ms": elapsed_ms,
                        "recipient": _get_agent_name(recipient),
                        "kwargs": {k: str(v)[:100] for k, v in kwargs.items()},  # Truncate for safety
                    },
                ),
            )
            _emit_chat_telemetry(self._emit, result)
            return result
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.autogen.error",
                make_envelope(
                    "framework.autogen.error",
                    {
                        "status": "error",
                        "elapsed_ms": elapsed_ms,
                        "error": str(exc),
                        "method": "initiate_chat",
                    },
                ),
            )
            raise

    async def a_initiate_chat(self, recipient: Any, *args: Any, **kwargs: Any) -> Any:
        """Async variant: Initiate a chat conversation with another agent."""
        start = time.perf_counter()
        try:
            result = await self._agent.a_initiate_chat(recipient, *args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.autogen.a_initiate_chat",
                make_envelope(
                    "framework.autogen.a_initiate_chat",
                    {
                        "status": "ok",
                        "elapsed_ms": elapsed_ms,
                        "recipient": _get_agent_name(recipient),
                        "kwargs": {k: str(v)[:100] for k, v in kwargs.items()},
                    },
                ),
            )
            _emit_chat_telemetry(self._emit, result)
            return result
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.autogen.error",
                make_envelope(
                    "framework.autogen.error",
                    {
                        "status": "error",
                        "elapsed_ms": elapsed_ms,
                        "error": str(exc),
                        "method": "a_initiate_chat",
                    },
                ),
            )
            raise

    async def a_send(self, message: Any, recipient: Any, *args: Any, **kwargs: Any) -> Any:
        """Async variant: Send a message to another agent."""
        start = time.perf_counter()
        try:
            result = await self._agent.a_send(message, recipient, *args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.autogen.a_send",
                make_envelope(
                    "framework.autogen.a_send",
                    {
                        "status": "ok",
                        "elapsed_ms": elapsed_ms,
                        "recipient": _get_agent_name(recipient),
                        "message_type": type(message).__name__,
                    },
                ),
            )
            _emit_message_telemetry(self._emit, "a_send", message, result)
            return result
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.autogen.error",
                make_envelope(
                    "framework.autogen.error",
                    {
                        "status": "error",
                        "elapsed_ms": elapsed_ms,
                        "error": str(exc),
                        "method": "a_send",
                    },
                ),
            )
            raise

    async def a_receive(self, message: Any, sender: Any, *args: Any, **kwargs: Any) -> Any:
        """Async variant: Receive and process a message from another agent."""
        start = time.perf_counter()
        try:
            result = await self._agent.a_receive(message, sender, *args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.autogen.a_receive",
                make_envelope(
                    "framework.autogen.a_receive",
                    {
                        "status": "ok",
                        "elapsed_ms": elapsed_ms,
                        "sender": _get_agent_name(sender),
                        "message_type": type(message).__name__,
                    },
                ),
            )
            _emit_message_telemetry(self._emit, "a_receive", message, result)
            return result
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.autogen.error",
                make_envelope(
                    "framework.autogen.error",
                    {
                        "status": "error",
                        "elapsed_ms": elapsed_ms,
                        "error": str(exc),
                        "method": "a_receive",
                    },
                ),
            )
            raise

    def __getattr__(self, item: str) -> Any:
        return getattr(self._agent, item)

def wrap_autogen(agent: Any, emit: TelemetryEmitter | None = None) -> AutogenAdapter:
    """Return a telemetry-instrumented wrapper for an Autogen ConversableAgent.

    Args:
        agent: An Autogen ConversableAgent instance to wrap
        emit: Optional telemetry emitter; uses runtime emitter if not provided

    Returns:
        AutogenAdapter wrapping the agent with instrumentation
    """
    return AutogenAdapter(agent, emit or get_runtime_emitter() or (lambda _e, _p: None))

def _get_agent_name(agent: Any) -> str:
    """Extract agent name from an Autogen agent instance."""
    if agent is None:
        return "unknown"
    return str(getattr(agent, "name", type(agent).__name__))

def _emit_message_telemetry(emit: TelemetryEmitter, method: str, message: Any, result: Any) -> None:
    """Emit telemetry for message content when available."""
    payload: dict[str, Any] = {"method": method}

    # Extract message content if it's a dict
    if isinstance(message, dict):
        payload["message_content_type"] = message.get("role", "unknown")
        if "content" in message:
            content = message["content"]
            payload["content_length"] = len(content) if isinstance(content, str) else 0
    elif isinstance(message, str):
        payload["content_length"] = len(message)

    # Extract result info if available
    if isinstance(result, dict):
        payload["result_keys"] = list(result.keys())[:10]  # Cap at 10 keys

    emit("framework.autogen.message", make_envelope("framework.autogen.message", normalize_payload(payload)))

def _emit_chat_telemetry(emit: TelemetryEmitter, result: Any) -> None:
    """Emit telemetry for chat conversation results."""
    payload: dict[str, Any] = {"status": "ok"}

    if result is None:
        emit("framework.autogen.chat", make_envelope("framework.autogen.chat", normalize_payload(payload)))
        return

    # ChatResult object attributes
    if hasattr(result, "chat_history"):
        history = result.chat_history
        if isinstance(history, list):
            payload["message_count"] = len(history)
            # Count messages by role
            role_counts: dict[str, int] = {}
            for msg in history:
                if isinstance(msg, dict):
                    role = msg.get("role", "unknown")
                    role_counts[role] = role_counts.get(role, 0) + 1
            if role_counts:
                payload["role_counts"] = role_counts

    if hasattr(result, "summary"):
        summary = result.summary
        if isinstance(summary, str):
            payload["summary_length"] = len(summary)

    if hasattr(result, "cost"):
        cost = result.cost
        if isinstance(cost, dict):
            payload["cost"] = cost

    emit("framework.autogen.chat", make_envelope("framework.autogen.chat", normalize_payload(payload)))
