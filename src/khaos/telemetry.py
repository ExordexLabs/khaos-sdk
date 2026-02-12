"""Global telemetry emitter registry used by framework adapters."""

from __future__ import annotations
from collections.abc import Callable

TelemetryEmitter = Callable[[str, dict], None]

_EMITTER: TelemetryEmitter | None = None

def set_runtime_emitter(emitter: TelemetryEmitter) -> None:
    """Register a runtime-scoped emitter for framework adapters."""

    global _EMITTER
    _EMITTER = emitter

def clear_runtime_emitter() -> None:
    """Remove any runtime-scoped emitter."""

    global _EMITTER
    _EMITTER = None

def get_runtime_emitter() -> TelemetryEmitter | None:
    """Return the currently registered emitter, if any."""

    return _EMITTER
