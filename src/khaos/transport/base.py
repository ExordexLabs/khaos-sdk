"""Core transport abstractions shared across adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol


@dataclass(slots=True)
class TransportMessage:
    """Structured payload exchanged with agent transports."""

    name: str
    payload: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)


class AgentTransport(Protocol):
    """Protocol describing the runtime's transport contract."""

    async def send(self, message: TransportMessage) -> None: ...

    async def receive(self, timeout: float | None = None) -> TransportMessage: ...

    async def close(self) -> None: ...


class TransportError(Exception):
    """Base error for transport-level failures."""


class TransportTimeout(TransportError):
    """Raised when a transport receive/send exceeds the allowed time."""


class TransportProtocolError(TransportError):
    """Raised when the agent violates protocol expectations."""


class TransportExit(TransportError):
    """Raised when the agent transport exits unexpectedly."""


@dataclass(slots=True)
class TransportEvent:
    """Observability record emitted by transports and injectors."""

    ts: datetime
    run_id: str
    agent_id: str
    event: str
    payload: dict[str, Any]
    meta: dict[str, Any]

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        agent_id: str,
        event: str,
        payload: dict[str, Any],
        meta: dict[str, Any],
        timestamp: datetime | None = None,
    ) -> "TransportEvent":
        """Helper to build an event with sensible defaults."""

        ts = timestamp or datetime.now(timezone.utc)
        return cls(ts=ts, run_id=run_id, agent_id=agent_id, event=event, payload=payload, meta=meta)
