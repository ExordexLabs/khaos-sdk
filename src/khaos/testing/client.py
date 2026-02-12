"""AgentTestClient — callable wrapper for invoking agents in tests."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from khaos.output import extract_output_text


@dataclass
class AgentResponse:
    """Result of a single agent invocation in a test."""

    success: bool
    text: str
    raw: dict[str, Any]
    latency_ms: float
    tokens_in: int = 0
    tokens_out: int = 0
    error: str | None = None


class AgentTestClient:
    """Callable wrapper for invoking an agent under test.

    In imperative test mode the runner creates one of these and passes it as
    the ``agent`` parameter to the test function.  The user calls it with a
    prompt string and gets back an :class:`AgentResponse`.
    """

    def __init__(
        self,
        agent_fn: Callable[..., Any],
        config: Any,
    ) -> None:
        self._agent_fn = agent_fn
        self._config = config
        self._calls: list[AgentResponse] = []

    @property
    def call_history(self) -> list[AgentResponse]:
        """All responses collected during the test."""
        return list(self._calls)

    def __call__(self, prompt: str, **kwargs: Any) -> AgentResponse:
        """Invoke the agent with *prompt* and return a structured response."""
        message: dict[str, Any] = {
            "name": "test",
            "payload": {"text": prompt, **kwargs},
        }
        start = time.perf_counter()
        try:
            raw = self._agent_fn(message)
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000
            resp = AgentResponse(
                success=False,
                text="",
                raw={},
                latency_ms=elapsed,
                error=str(exc),
            )
            self._calls.append(resp)
            return resp

        if not isinstance(raw, dict):
            raw = {"payload": {"text": str(raw)}}

        elapsed = (time.perf_counter() - start) * 1000
        payload = raw.get("payload", {})
        metadata = raw.get("metadata", {})

        resp = AgentResponse(
            success=payload.get("status") != "error",
            text=extract_output_text(raw),
            raw=raw,
            latency_ms=elapsed,
            tokens_in=metadata.get("tokens_in", 0),
            tokens_out=metadata.get("tokens_out", 0),
            error=payload.get("error"),
        )
        self._calls.append(resp)
        return resp


__all__ = ["AgentResponse", "AgentTestClient"]
