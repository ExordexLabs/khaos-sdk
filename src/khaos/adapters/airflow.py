"""Airflow adapter that emits structured telemetry while preserving behavior."""

from __future__ import annotations

import time
from typing import Any, Protocol

from ..contract import make_envelope
from ..telemetry import get_runtime_emitter


class TelemetryEmitter(Protocol):
    def __call__(self, event: str, envelope: dict[str, Any]) -> None: ...


class AirflowAdapter:
    """Lightweight wrapper around a callable representing a DAG run."""

    def __init__(self, dag_callable: Any, emit: TelemetryEmitter):
        self._dag_callable = dag_callable
        self._emit = emit
        self._emit("framework.airflow.bound", make_envelope("framework.airflow.bound", {"status": "ok"}))

    def __call__(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - exercised in tests
        start = time.perf_counter()
        try:
            result = self._dag_callable(*args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.airflow.run",
                make_envelope(
                    "framework.airflow.run",
                    {"status": "ok", "elapsed_ms": elapsed_ms, "kwargs": kwargs},
                ),
            )
            return result
        except Exception as exc:  # pragma: no cover - defensive
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "framework.airflow.error",
                make_envelope(
                    "framework.airflow.error",
                    {"status": "error", "elapsed_ms": elapsed_ms, "error": str(exc)},
                ),
            )
            raise

    def __getattr__(self, item: str) -> Any:
        return getattr(self._dag_callable, item)


def wrap_airflow(dag_callable: Any, emit: TelemetryEmitter | None = None) -> AirflowAdapter:
    """Return a telemetry-instrumented wrapper for an Airflow DAG callable."""

    return AirflowAdapter(dag_callable, emit or get_runtime_emitter() or (lambda _e, _p: None))
