"""Server instrumentation and request correlation.

Provides middleware for web frameworks to:
- Generate and propagate request IDs
- Correlate LLM calls with HTTP requests
- Track request-level telemetry
"""

from __future__ import annotations

import contextvars
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from collections.abc import Callable

# Context variable for request tracking
_request_context: contextvars.ContextVar["RequestContext | None"] = contextvars.ContextVar(
    "khaos_request_context", default=None
)

@dataclass
class RequestContext:
    """Context for tracking a single HTTP request."""

    request_id: str
    path: str = ""
    method: str = ""
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: datetime | None = None
    status_code: int | None = None
    llm_calls: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    sampled: bool = True  # Whether this request is being sampled

    @property
    def duration_ms(self) -> float:
        """Request duration in milliseconds."""
        end = self.end_time or datetime.now(timezone.utc)
        return (end - self.start_time).total_seconds() * 1000

    @property
    def llm_call_count(self) -> int:
        return len(self.llm_calls)

    @property
    def total_tokens(self) -> int:
        total = 0
        for call in self.llm_calls:
            tokens = call.get("tokens", {})
            total += tokens.get("prompt", 0) + tokens.get("completion", 0)
        return total

    def add_llm_call(self, call_data: dict[str, Any]) -> None:
        """Record an LLM call made during this request."""
        call_data["request_id"] = self.request_id
        self.llm_calls.append(call_data)

    def add_tool_call(self, tool_data: dict[str, Any]) -> None:
        """Record a tool call made during this request."""
        tool_data["request_id"] = self.request_id
        self.tool_calls.append(tool_data)

    def add_error(self, error: Exception, context: str = "") -> None:
        """Record an error during this request."""
        self.errors.append({
            "request_id": self.request_id,
            "error_type": type(error).__name__,
            "message": str(error),
            "context": context,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def to_dict(self) -> dict[str, Any]:
        """Serialize context for API submission."""
        return {
            "request_id": self.request_id,
            "path": self.path,
            "method": self.method,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_ms": self.duration_ms,
            "status_code": self.status_code,
            "llm_call_count": self.llm_call_count,
            "total_tokens": self.total_tokens,
            "llm_calls": self.llm_calls,
            "tool_calls": self.tool_calls,
            "errors": self.errors,
            "metadata": self.metadata,
            "sampled": self.sampled,
        }

def get_current_request_id() -> str | None:
    """Get the current request ID from context."""
    ctx = _request_context.get()
    return ctx.request_id if ctx else None

def get_request_context() -> RequestContext | None:
    """Get the current request context."""
    return _request_context.get()

def set_request_context(ctx: RequestContext | None) -> contextvars.Token:
    """Set the current request context."""
    return _request_context.set(ctx)

def generate_request_id() -> str:
    """Generate a unique request ID."""
    return f"req_{uuid.uuid4().hex[:16]}"

class KhaosMiddleware:
    """Generic ASGI middleware for request correlation.

    Works with FastAPI, Starlette, and other ASGI frameworks.
    """

    def __init__(
        self,
        app: Any,
        *,
        sample_rate: float = 1.0,
        request_id_header: str = "X-Request-ID",
        on_request_complete: Callable[[RequestContext], None] | None = None,
    ):
        self.app = app
        self.sample_rate = sample_rate
        self.request_id_header = request_id_header
        self.on_request_complete = on_request_complete

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Check sampling
        import random
        sampled = random.random() < self.sample_rate

        # Extract or generate request ID
        headers = dict(scope.get("headers", []))
        request_id_bytes = headers.get(self.request_id_header.lower().encode())
        request_id = (
            request_id_bytes.decode() if request_id_bytes
            else generate_request_id()
        )

        # Create request context
        path = scope.get("path", "")
        method = scope.get("method", "")
        ctx = RequestContext(
            request_id=request_id,
            path=path,
            method=method,
            sampled=sampled,
        )

        # Capture status code from response
        status_code = 200

        async def send_wrapper(message: dict) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 200)
            await send(message)

        # Set context and run request
        token = set_request_context(ctx)
        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as e:
            ctx.add_error(e, "request_handling")
            raise
        finally:
            ctx.end_time = datetime.now(timezone.utc)
            ctx.status_code = status_code
            set_request_context(None)

            # Callback for telemetry collection
            if self.on_request_complete and ctx.sampled:
                try:
                    self.on_request_complete(ctx)
                except Exception:
                    pass  # Don't let telemetry errors break requests

def instrument_fastapi(
    app: Any,
    *,
    sample_rate: float = 1.0,
    request_id_header: str = "X-Request-ID",
    on_request_complete: Callable[[RequestContext], None] | None = None,
) -> Any:
    """Instrument a FastAPI application.

    Args:
        app: FastAPI application instance
        sample_rate: Fraction of requests to sample (0.0 to 1.0)
        request_id_header: Header name for request ID propagation
        on_request_complete: Callback when request completes

    Returns:
        The instrumented app
    """
    from khaos.server.collector import get_collector

    def default_callback(ctx: RequestContext) -> None:
        collector = get_collector()
        if collector:
            collector.emit_request(ctx)

    callback = on_request_complete or default_callback

    # Add middleware
    app.add_middleware(
        KhaosMiddleware,
        sample_rate=sample_rate,
        request_id_header=request_id_header,
        on_request_complete=callback,
    )

    return app

def instrument_flask(
    app: Any,
    *,
    sample_rate: float = 1.0,
    request_id_header: str = "X-Request-ID",
    on_request_complete: Callable[[RequestContext], None] | None = None,
) -> Any:
    """Instrument a Flask application.

    Args:
        app: Flask application instance
        sample_rate: Fraction of requests to sample (0.0 to 1.0)
        request_id_header: Header name for request ID propagation
        on_request_complete: Callback when request completes

    Returns:
        The instrumented app
    """
    import random
    from functools import wraps

    from khaos.server.collector import get_collector

    def default_callback(ctx: RequestContext) -> None:
        collector = get_collector()
        if collector:
            collector.emit_request(ctx)

    callback = on_request_complete or default_callback

    @app.before_request
    def before_request() -> None:
        from flask import request, g

        # Check sampling
        sampled = random.random() < sample_rate

        # Get or generate request ID
        request_id = request.headers.get(request_id_header) or generate_request_id()

        # Create context
        ctx = RequestContext(
            request_id=request_id,
            path=request.path,
            method=request.method,
            sampled=sampled,
        )

        g.khaos_context = ctx
        set_request_context(ctx)

    @app.after_request
    def after_request(response: Any) -> Any:
        from flask import g

        ctx = getattr(g, "khaos_context", None)
        if ctx:
            ctx.end_time = datetime.now(timezone.utc)
            ctx.status_code = response.status_code

            if ctx.sampled and callback:
                try:
                    callback(ctx)
                except Exception:
                    pass

            set_request_context(None)

        return response

    @app.teardown_request
    def teardown_request(exception: Exception | None) -> None:
        from flask import g

        ctx = getattr(g, "khaos_context", None)
        if ctx and exception:
            ctx.add_error(exception, "request_teardown")

    return app

def instrument_app(
    app: Any,
    *,
    sample_rate: float = 1.0,
    request_id_header: str = "X-Request-ID",
    on_request_complete: Callable[[RequestContext], None] | None = None,
) -> Any:
    """Auto-detect framework and instrument the application.

    Args:
        app: Web application instance (FastAPI, Flask, etc.)
        sample_rate: Fraction of requests to sample (0.0 to 1.0)
        request_id_header: Header name for request ID propagation
        on_request_complete: Callback when request completes

    Returns:
        The instrumented app
    """
    app_class = type(app).__name__

    if app_class == "FastAPI" or hasattr(app, "add_middleware"):
        return instrument_fastapi(
            app,
            sample_rate=sample_rate,
            request_id_header=request_id_header,
            on_request_complete=on_request_complete,
        )

    if app_class == "Flask" or hasattr(app, "before_request"):
        return instrument_flask(
            app,
            sample_rate=sample_rate,
            request_id_header=request_id_header,
            on_request_complete=on_request_complete,
        )

    raise ValueError(f"Unsupported application type: {app_class}")
