"""CrewAI adapter that emits structured telemetry during crew execution."""

from __future__ import annotations

import time
from typing import Any, Protocol
from collections.abc import Callable

from ..contract import make_envelope, normalize_payload
from ..telemetry import get_runtime_emitter

class TelemetryEmitter(Protocol):
    def __call__(self, event: str, envelope: dict[str, Any]) -> None:
        ...

class CrewAIAdapter:
    """Minimal wrapper around a CrewAI Crew instance."""

    def __init__(self, crew: Any, emit: TelemetryEmitter):
        self._crew = crew
        self._emit = emit
        self._emit("framework.crewai.bound", make_envelope("framework.crewai.bound", {"status": "ok"}))

    def run(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - exercised in tests
        start = time.perf_counter()
        try:
            result = self._crew.run(*args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.crewai.run",
                make_envelope("framework.crewai.run", {"status": "ok", "elapsed_ms": elapsed_ms, "kwargs": kwargs}),
            )
            _emit_result_telemetry(self._emit, result)
            return result
        except Exception as exc:  # pragma: no cover - defensive
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.crewai.error",
                make_envelope(
                    "framework.crewai.error",
                    {"status": "error", "elapsed_ms": elapsed_ms, "error": str(exc), "kwargs": kwargs},
                ),
            )
            raise

    async def kickoff_async(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
        start = time.perf_counter()
        try:
            result = await self._crew.kickoff_async(*args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.crewai.kickoff_async",
                make_envelope("framework.crewai.kickoff_async", {"status": "ok", "elapsed_ms": elapsed_ms, "kwargs": kwargs}),
            )
            _emit_result_telemetry(self._emit, result)
            return result
        except Exception as exc:  # pragma: no cover - defensive
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.crewai.error",
                make_envelope(
                    "framework.crewai.error",
                    {"status": "error", "elapsed_ms": elapsed_ms, "error": str(exc), "kwargs": kwargs},
                ),
            )
            raise

    def kickoff(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
        start = time.perf_counter()
        try:
            result = self._crew.kickoff(*args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.crewai.kickoff",
                make_envelope("framework.crewai.kickoff", {"status": "ok", "elapsed_ms": elapsed_ms, "kwargs": kwargs}),
            )
            _emit_result_telemetry(self._emit, result)
            return result
        except Exception as exc:  # pragma: no cover - defensive
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.crewai.error",
                make_envelope(
                    "framework.crewai.error",
                    {"status": "error", "elapsed_ms": elapsed_ms, "error": str(exc), "kwargs": kwargs},
                ),
            )
            raise

    def __getattr__(self, item: str) -> Any:
        return getattr(self._crew, item)

def wrap_crewai(crew: Any, emit: TelemetryEmitter | None = None) -> CrewAIAdapter:
    """Return a telemetry-instrumented wrapper for a CrewAI Crew."""

    return CrewAIAdapter(crew, emit or get_runtime_emitter() or (lambda _e, _p: None))

def _emit_result_telemetry(emit: TelemetryEmitter, result: Any) -> None:
    """Emit task/LLM/tool telemetry when present on CrewAI results."""

    if isinstance(result, dict):
        tasks = result.get("tasks") or result.get("task_results")
        if isinstance(tasks, list):
            for task in tasks:
                payload = normalize_payload(
                    {
                        "status": task.get("status", "ok"),
                        "reason": task.get("reason"),
                        "output": task.get("output"),
                        "agent": task.get("agent"),
                        "tool_name": task.get("tool_name"),
                        "elapsed_ms": task.get("elapsed_ms"),
                        "attempt": task.get("attempt"),
                    }
                )
                emit("framework.crewai.task", make_envelope("framework.crewai.task", payload))
        llm = result.get("llm")
        if isinstance(llm, dict):
            payload = normalize_payload(
                {
                    "status": llm.get("status", "ok"),
                    "prompt_tokens": llm.get("prompt_tokens"),
                    "completion_tokens": llm.get("completion_tokens"),
                    "latency_ms": llm.get("latency_ms"),
                    "model": llm.get("model"),
                }
            )
            emit("framework.crewai.llm", make_envelope("framework.crewai.llm", payload))
