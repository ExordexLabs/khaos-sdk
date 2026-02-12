"""Dagster adapter that emits structured telemetry while preserving behavior."""

from __future__ import annotations

import time
from typing import Any, Protocol

from ..contract import make_envelope
from ..telemetry import get_runtime_emitter


class TelemetryEmitter(Protocol):
    def __call__(self, event: str, envelope: dict[str, Any]) -> None: ...


class DagsterAdapter:
    """Lightweight wrapper around a Dagster job-like callable."""

    def __init__(self, job_callable: Any, emit: TelemetryEmitter):
        self._job_callable = job_callable
        self._emit = emit
        self._emit("framework.dagster.bound", make_envelope("framework.dagster.bound", {"status": "ok"}))

    def __call__(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - exercised in tests
        start = time.perf_counter()
        try:
            result = self._job_callable(*args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.dagster.run",
                make_envelope(
                    "framework.dagster.run",
                    {"status": "ok", "elapsed_ms": elapsed_ms, "kwargs": kwargs},
                ),
            )
            return result
        except Exception as exc:  # pragma: no cover - defensive
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.dagster.error",
                make_envelope(
                    "framework.dagster.error",
                    {"status": "error", "elapsed_ms": elapsed_ms, "error": str(exc)},
                ),
            )
            raise

    def __getattr__(self, item: str) -> Any:
        return getattr(self._job_callable, item)


def wrap_dagster(job_callable: Any, emit: TelemetryEmitter | None = None) -> DagsterAdapter:
    """Return a telemetry-instrumented wrapper for a Dagster job callable."""

    return DagsterAdapter(job_callable, emit or get_runtime_emitter() or (lambda _e, _p: None))
