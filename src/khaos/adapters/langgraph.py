"""LangGraph adapter that emits structured telemetry while preserving behavior."""

from __future__ import annotations

import time
from typing import Any, Protocol
from collections.abc import Callable

from ..contract import make_envelope, normalize_payload
from ..telemetry import get_runtime_emitter

class TelemetryEmitter(Protocol):
    def __call__(self, event: str, envelope: dict[str, Any]) -> None:
        ...

class LangGraphAdapter:
    """Thin wrapper around a LangGraph compiled graph."""

    def __init__(self, graph: Any, emit: TelemetryEmitter):
        if getattr(graph, "__khaos_wrapped__", False):
            # Already wrapped; avoid double instrumentation
            self._graph = graph
            self._emit = emit
            return
        self._graph = graph
        self._emit = emit
        setattr(graph, "__khaos_wrapped__", True)
        self._emit("framework.langgraph.bound", make_envelope("framework.langgraph.bound", {"status": "ok"}))

    def invoke(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - exercised in tests
        start = time.perf_counter()
        try:
            result = self._graph.invoke(*args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.langgraph.invoke",
                make_envelope(
                    "framework.langgraph.invoke",
                    {
                        "status": "ok",
                        "elapsed_ms": elapsed_ms,
                        "inputs": args[0] if args else None,
                        "kwargs": kwargs,
                    },
                ),
            )
            _emit_result_telemetry(self._emit, result)
            return result
        except Exception as exc:  # pragma: no cover - defensive
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.langgraph.error",
                make_envelope(
                    "framework.langgraph.error",
                    {
                        "status": "error",
                        "elapsed_ms": elapsed_ms,
                        "error": str(exc),
                        "kwargs": kwargs,
                    },
                ),
            )
            raise

    async def ainvoke(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
        start = time.perf_counter()
        try:
            result = await self._graph.ainvoke(*args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.langgraph.ainvoke",
                make_envelope(
                    "framework.langgraph.ainvoke",
                    {
                        "status": "ok",
                        "elapsed_ms": elapsed_ms,
                        "inputs": args[0] if args else None,
                        "kwargs": kwargs,
                    },
                ),
            )
            _emit_result_telemetry(self._emit, result)
            return result
        except Exception as exc:  # pragma: no cover - defensive
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.langgraph.error",
                make_envelope(
                    "framework.langgraph.error",
                    {
                        "status": "error",
                        "elapsed_ms": elapsed_ms,
                        "error": str(exc),
                        "kwargs": kwargs,
                    },
                ),
            )
            raise

    def __getattr__(self, item: str) -> Any:
        return getattr(self._graph, item)

def wrap_langgraph(graph: Any, emit: TelemetryEmitter | None = None) -> LangGraphAdapter:
    """Return a telemetry-instrumented wrapper for a compiled LangGraph."""

    if getattr(graph, "__khaos_wrapped__", False) and isinstance(graph, LangGraphAdapter):
        return graph
    return LangGraphAdapter(graph, emit or get_runtime_emitter() or (lambda _e, _p: None))

def _emit_result_telemetry(emit: TelemetryEmitter, result: Any) -> None:
    """Best-effort extraction of tool/LLM metadata from graph results."""

    if isinstance(result, dict):
        if "state" in result:
            emit(
                "framework.langgraph.state",
                make_envelope(
                    "framework.langgraph.state",
                    {
                        "status": "ok",
                        "state": normalize_payload(result.get("state")),
                    },
                ),
            )
        if "tool_calls" in result and isinstance(result["tool_calls"], list):
            for call in result["tool_calls"]:
                payload = normalize_payload(
                    {
                        "status": call.get("status", "ok"),
                        "tool_name": call.get("name") or call.get("tool"),
                        "args": call.get("args"),
                        "elapsed_ms": call.get("elapsed_ms"),
                    }
                )
                emit("framework.langgraph.tool", make_envelope("framework.langgraph.tool", payload))
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
            emit("framework.langgraph.llm", make_envelope("framework.langgraph.llm", payload))
