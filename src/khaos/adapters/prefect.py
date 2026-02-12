"""Prefect adapter that emits structured telemetry while preserving behavior."""

from __future__ import annotations

import time
from typing import Any, Protocol

from ..contract import make_envelope
from ..telemetry import get_runtime_emitter


class TelemetryEmitter(Protocol):
    def __call__(self, event: str, envelope: dict[str, Any]) -> None: ...


class PrefectAdapter:
    """Lightweight wrapper around a Prefect Flow-like object."""

    def __init__(self, flow: Any, emit: TelemetryEmitter):
        self._flow = flow
        self._emit = emit
        self._emit("framework.prefect.bound", make_envelope("framework.prefect.bound", {"status": "ok"}))

    def __call__(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - exercised in tests
        start = time.perf_counter()
        try:
            result = self._flow(*args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.prefect.run",
                make_envelope(
                    "framework.prefect.run",
                    {
                        "status": "ok",
                        "elapsed_ms": elapsed_ms,
                        "kwargs": kwargs,
                    },
                ),
            )
            return result
        except Exception as exc:  # pragma: no cover - defensive
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.prefect.error",
                make_envelope(
                    "framework.prefect.error",
                    {"status": "error", "elapsed_ms": elapsed_ms, "error": str(exc)},
                ),
            )
            raise

    def __getattr__(self, item: str) -> Any:
        return getattr(self._flow, item)


def wrap_prefect(flow: Any, emit: TelemetryEmitter | None = None) -> PrefectAdapter:
    """Return a telemetry-instrumented wrapper for a Prefect Flow-like callable."""

    return PrefectAdapter(flow, emit or get_runtime_emitter() or (lambda _e, _p: None))
