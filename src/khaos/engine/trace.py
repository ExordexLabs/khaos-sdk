"""Trace event helper utilities."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class TraceEvent:
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
    ) -> "TraceEvent":
        return cls(
            ts=datetime.now(timezone.utc),
            run_id=run_id,
            agent_id=agent_id,
            event=event,
            payload=payload,
            meta=meta,
        )
