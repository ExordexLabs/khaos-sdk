"""Server instrumentation for long-running LLM agents.

Provides telemetry capture for:
- FastAPI / Starlette applications
- Flask applications
- Generic WSGI/ASGI servers

Example usage:

    # Automatic instrumentation
    khaos instrument "uvicorn app:main"

    # Programmatic instrumentation
    from khaos.server import instrument_app

    app = FastAPI()
    instrument_app(app)  # Adds telemetry middleware

    # With sampling
    instrument_app(app, sample_rate=0.1)  # 10% of requests

Key features:
- Request correlation (group LLM calls by request ID)
- Sampling configuration for production
- Background telemetry collection (non-blocking)
- Sidecar mode for K8s/Docker
"""

from khaos.server.instrumentation import (
    instrument_app,
    instrument_fastapi,
    instrument_flask,
    KhaosMiddleware,
    RequestContext,
    get_current_request_id,
    set_request_context,
)

from khaos.server.sampling import (
    SamplingConfig,
    SamplingStrategy,
    should_sample_request,
    get_sampler,
)

from khaos.server.collector import (
    BackgroundCollector,
    get_collector,
    emit_event,
    flush_events,
)

from khaos.server.sidecar import (
    SidecarConfig,
    start_sidecar,
    stop_sidecar,
    is_sidecar_running,
)

__all__ = [
    # Instrumentation
    "instrument_app",
    "instrument_fastapi",
    "instrument_flask",
    "KhaosMiddleware",
    "RequestContext",
    "get_current_request_id",
    "set_request_context",
    # Sampling
    "SamplingConfig",
    "SamplingStrategy",
    "should_sample_request",
    "get_sampler",
    # Collector
    "BackgroundCollector",
    "get_collector",
    "emit_event",
    "flush_events",
    # Sidecar
    "SidecarConfig",
    "start_sidecar",
    "stop_sidecar",
    "is_sidecar_running",
]
