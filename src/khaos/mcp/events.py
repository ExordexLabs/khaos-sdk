"""Utilities for emitting MCP-related transport events."""

from __future__ import annotations

from collections import deque
from typing import Any

from khaos.transport import TransportEvent

class MCPEventBuffer:
    """Collects transport events emitted by MCP wrappers."""

    def __init__(self, run_id: str, agent_id: str) -> None:
        self._run_id = run_id
        self._agent_id = agent_id
        self._events: deque[TransportEvent] = deque()

    def emit(self, event: str, payload: dict[str, Any], meta: dict[str, Any] | None = None) -> None:
        meta = meta or {}
        self._events.append(
            TransportEvent.create(
                run_id=self._run_id,
                agent_id=self._agent_id,
                event=event,
                payload=payload,
                meta=meta,
            )
        )

    def drain(self) -> list[TransportEvent]:
        items = list(self._events)
        self._events.clear()
        return items
