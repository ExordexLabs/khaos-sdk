"""AgentTestClient — callable wrapper for invoking agents in tests."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from khaos.output import extract_output_text

if TYPE_CHECKING:
    from khaos.testing.classification import ClassificationResult
    from khaos.testing.metadata import ReproducibilityMetadata


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

    # Enriched fields (populated when classification is available)
    classification: ClassificationResult | None = None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    llm_events: list[dict[str, Any]] = field(default_factory=list)
    metadata: ReproducibilityMetadata | None = None

    @property
    def blocked(self) -> bool:
        """True if the response was classified as BLOCKED."""
        if self.classification is not None:
            from khaos.testing.classification import Outcome
            return self.classification.outcome == Outcome.BLOCKED
        return not self.success

    @property
    def compromised(self) -> bool:
        """True if the response was classified as COMPROMISED."""
        if self.classification is not None:
            from khaos.testing.classification import Outcome
            return self.classification.outcome == Outcome.COMPROMISED
        return False

    @property
    def inconclusive(self) -> bool:
        """True if the response was classified as INCONCLUSIVE."""
        if self.classification is not None:
            from khaos.testing.classification import Outcome
            return self.classification.outcome == Outcome.INCONCLUSIVE
        return False


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
        raw_metadata = raw.get("metadata", {})

        # Extract tool calls from raw response
        tool_calls: list[dict[str, Any]] = []
        raw_tool_calls = raw_metadata.get("tool_calls") or payload.get("tool_calls")
        if isinstance(raw_tool_calls, list):
            tool_calls = [tc for tc in raw_tool_calls if isinstance(tc, dict)]

        resp = AgentResponse(
            success=payload.get("status") != "error",
            text=extract_output_text(raw),
            raw=raw,
            latency_ms=elapsed,
            tokens_in=raw_metadata.get("tokens_in", 0),
            tokens_out=raw_metadata.get("tokens_out", 0),
            error=payload.get("error"),
            tool_calls=tool_calls,
        )
        self._calls.append(resp)
        return resp


__all__ = ["AgentResponse", "AgentTestClient"]
