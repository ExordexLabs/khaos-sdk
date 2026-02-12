"""Public SDK hooks for integrating Python agents with Khaos.

The @khaosagent decorator provides:
- Automatic response normalization
- Error handling and capture
- Timing/latency tracking
- Input/output validation (optional)
- Pre/post processing hooks
- Flexible signature adaptation
- Metadata annotation for discovery

This is the unified decorator - it provides both runtime instrumentation
AND static metadata for discovery. Use @khaosagent, not @khaos_agent.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import inspect
import time
import os
import traceback
import warnings
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeVar, cast, overload
from collections.abc import AsyncIterator, Callable, Iterator

# Import output utilities for unified extraction/normalization
from khaos.output import (
    extract_output_text,
    extract_input_text,
    normalize_agent_output,
    is_envelope,
)

# Import capability normalization for consistent naming
from khaos.capabilities import (
    validate_capability,
    normalize_capability,
    CANONICAL_CAPABILITIES,
)

F = TypeVar("F", bound=Callable[..., Any])

class AgentCategory(str, Enum):
    """Agent category for discovery and classification."""

    LLM_INFERENCE = "llm_inference"
    TOOL_AGENT = "tool_agent"
    ORCHESTRATED = "orchestrated"
    WORKFLOW = "workflow"
    MULTIMODAL = "multimodal"
    CUSTOM = "custom"

@dataclass
class ToolDefinition:
    """Definition of a tool available to the agent.

    This metadata is used for:
    - Discovery and documentation
    - Playground UI display
    - Capability inference
    - Security testing (tool manipulation attacks)
    """

    name: str
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for serialization."""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
        }

@dataclass
class AgentConfig:
    """Configuration for a Khaos agent.

    This unified config supports both runtime behavior AND discovery metadata.

    Runtime Attributes:
        name: Agent name (defaults to function name)
        version: Agent version string
        metadata: Additional metadata to attach to telemetry
        strict: If True, normalize outputs to include required fields
        capture_errors: If True, catch exceptions and return error responses
        emit_telemetry: If True, emit LLM telemetry events automatically
        validate_input: If True, validate input message structure
        validate_output: If True, validate output message structure
        timeout_ms: Optional timeout in milliseconds (0 = no timeout)

    Discovery Attributes:
        description: Human-readable description of the agent
        category: Agent category for classification
        capabilities: List of capabilities (tool-calling, mcp, etc.)
        framework: Framework name (openai, anthropic, langgraph, etc.)
        tools: List of tools available to the agent

    Security Attributes:
        security_mode: How security attacks are injected during testing.
            - "agent_input": Attacks go through agent's normal input path (default).
              Tests the full security stack including any input filtering.
            - "llm": Attacks inject at the LLM SDK layer, bypassing agent code.
              Tests raw LLM defenses only.
    """

    # Identity
    name: str | None = None
    version: str = "1.0.0"
    description: str = ""

    # Runtime behavior
    metadata: dict[str, Any] = field(default_factory=dict)
    strict: bool = False
    capture_errors: bool = True
    emit_telemetry: bool = True
    validate_input: bool = False
    validate_output: bool = False
    timeout_ms: int = 0  # 0 = no timeout

    # Discovery metadata
    category: AgentCategory | str | None = None
    capabilities: list[str] = field(default_factory=list)
    framework: str | None = None
    tools: list[ToolDefinition | dict[str, Any]] = field(default_factory=list)

    # Security testing configuration
    security_mode: str = "agent_input"  # "agent_input" | "llm"

    # MCP integration
    mcp_servers: list[str] = field(default_factory=list)

    def to_static_config(self) -> dict[str, Any]:
        """Convert to static config dict for discovery (__khaos_agent_config__)."""
        config: dict[str, Any] = {}
        if self.name:
            config["name"] = self.name
        if self.version != "1.0.0":
            config["version"] = self.version
        if self.description:
            config["description"] = self.description
        if self.metadata:
            config["metadata"] = self.metadata
        if self.category:
            config["category"] = self.category.value if isinstance(self.category, AgentCategory) else self.category
        if self.capabilities:
            config["capabilities"] = list(self.capabilities)
        if self.framework:
            config["framework"] = self.framework
        if self.tools:
            config["tools"] = [
                t.to_dict() if isinstance(t, ToolDefinition) else t
                for t in self.tools
            ]
        if self.strict:
            config["strict_contract"] = True
        if self.security_mode != "agent_input":
            config["security_mode"] = self.security_mode
        if self.mcp_servers:
            config["mcp_servers"] = list(self.mcp_servers)
        return config

    def get_tools_list(self) -> list[dict[str, Any]]:
        """Get tools as a list of dicts for setting __khaos_tools__."""
        return [
            t.to_dict() if isinstance(t, ToolDefinition) else t
            for t in self.tools
        ]

@dataclass
class InvocationContext:
    """Context for a single agent invocation.

    Provides access to invocation metadata and utilities.
    """

    agent_name: str
    agent_version: str
    message: dict[str, Any]
    metadata: dict[str, Any]
    start_time: float = field(default_factory=time.perf_counter)

    @property
    def elapsed_ms(self) -> float:
        """Elapsed time since invocation start in milliseconds."""
        return (time.perf_counter() - self.start_time) * 1000

    @property
    def message_name(self) -> str:
        """Name of the incoming message."""
        return str(self.message.get("name", ""))

    @property
    def payload(self) -> dict[str, Any]:
        """Payload from the incoming message."""
        p = self.message.get("payload")
        return p if isinstance(p, dict) else {}

    def get_input(self, key: str, default: Any = None) -> Any:
        """Get a value from the payload."""
        return self.payload.get(key, default)

# Thread-safe context using contextvars (works with threads and asyncio)
_current_context: contextvars.ContextVar[InvocationContext | None] = contextvars.ContextVar(
    'khaos_invocation_context', default=None
)

def get_current_context() -> InvocationContext | None:
    """Get the current invocation context, if any.

    This is thread-safe and works correctly with:
    - Multi-threaded agents using ThreadPoolExecutor
    - Async agents using asyncio
    - Nested agent calls
    """
    return _current_context.get()

class AgentTimeoutError(Exception):
    """Raised when an agent exceeds its configured timeout.

    This exception is raised when:
    - A sync agent's execution exceeds timeout_ms
    - An async agent's awaitable exceeds timeout_ms

    The exception message includes the agent name and configured timeout.
    """

    def __init__(self, message: str, agent_name: str = "", timeout_ms: int = 0):
        super().__init__(message)
        self.agent_name = agent_name
        self.timeout_ms = timeout_ms

def _execute_with_timeout(
    func: Callable[[], Any],
    timeout_ms: int,
    agent_name: str,
) -> Any:
    """Execute a sync function with a timeout.

    Uses ThreadPoolExecutor to run the function in a separate thread and
    waits for completion with a timeout. If the timeout is exceeded, raises
    AgentTimeoutError.

    Note: This does NOT forcibly kill the underlying thread - Python threads
    cannot be safely terminated. The function will continue running in the
    background, but control returns to the caller with a timeout error.

    Args:
        func: Zero-argument callable to execute
        timeout_ms: Timeout in milliseconds
        agent_name: Agent name for error messages

    Returns:
        The result of func()

    Raises:
        AgentTimeoutError: If execution exceeds timeout_ms
    """
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(func)
        try:
            return future.result(timeout=timeout_ms / 1000.0)
        except FuturesTimeoutError:
            raise AgentTimeoutError(
                f"Agent '{agent_name}' exceeded timeout of {timeout_ms}ms",
                agent_name=agent_name,
                timeout_ms=timeout_ms,
            )

def _validate_input_message(message: Any) -> dict[str, Any]:
    """Validate and normalize input message structure."""
    if message is None:
        return {"name": "unknown", "payload": {}, "metadata": {}}

    if not isinstance(message, dict):
        return {"name": "unknown", "payload": {"value": message}, "metadata": {}}

    # Ensure required keys
    return {
        "name": str(message.get("name", "unknown")),
        "payload": message.get("payload") if isinstance(message.get("payload"), dict) else {},
        "metadata": message.get("metadata") if isinstance(message.get("metadata"), dict) else {},
    }

def _normalize_payload(payload: Any) -> dict[str, Any]:
    """Ensure payload is a dict with required keys present."""
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        payload = {"value": payload}
    payload.setdefault("status", "success")
    return payload

def _make_envelope(name: str, payload: Any, latency_ms: float | None = None) -> dict[str, Any]:
    """Wrap a payload in the envelope expected by transports."""
    envelope = {"name": name, "payload": _normalize_payload(payload)}
    if latency_ms is not None:
        envelope["metadata"] = {"latency_ms": round(latency_ms, 2)}
    return envelope

def _make_error_envelope(exc: Exception, latency_ms: float | None = None) -> dict[str, Any]:
    """Create an error response envelope from an exception.

    Includes full traceback information for debugging:
    - traceback: Full formatted traceback string
    - traceback_frames: Structured list of frame information
    """
    # Extract full traceback
    tb_string = traceback.format_exc()
    tb_frames: list[dict[str, Any]] = []

    if exc.__traceback__ is not None:
        for frame in traceback.extract_tb(exc.__traceback__):
            tb_frames.append({
                "file": frame.filename,
                "line": frame.lineno,
                "function": frame.name,
                "code": frame.line,
            })

    envelope: dict[str, Any] = {
        "name": "agent.error",
        "payload": {
            "status": "error",
            "error": str(exc),
            "error_type": type(exc).__name__,
            "traceback": tb_string,
            "traceback_frames": tb_frames,
        },
    }

    # Add timeout-specific info if applicable
    if isinstance(exc, AgentTimeoutError):
        envelope["payload"]["timeout_ms"] = exc.timeout_ms
        envelope["payload"]["agent_name"] = exc.agent_name

    if latency_ms is not None:
        envelope["metadata"] = {"latency_ms": round(latency_ms, 2)}

    return envelope

def _adapt_call(
    handler: Callable,
    message: dict[str, Any],
    context: InvocationContext,
) -> Any:
    """Adapt handler call based on its signature.

    Supports various signature patterns:
    - fn() -> called with no args
    - fn(msg) -> called with full message dict
    - fn(prompt: str) -> called with extracted prompt
    - fn(message, context) -> called with message and context
    - fn(**kwargs) -> called with payload as kwargs
    """
    try:
        sig = inspect.signature(handler)
    except (TypeError, ValueError):
        # Can't inspect, just pass the message
        return handler(message)

    params = list(sig.parameters.values())

    # No params: call with nothing
    if not params:
        return handler()

    # Check for context parameter
    context_param = None
    other_params = []
    for p in params:
        if p.annotation is InvocationContext or p.name == "context":
            context_param = p
        else:
            other_params.append(p)

    # Single param (excluding context)
    if len(other_params) == 1:
        param = other_params[0]

        # String annotation or name hint -> pass prompt
        if param.annotation is str or param.name.lower() in {
            "prompt", "text", "message", "input", "content", "query"
        }:
            prompt = _extract_prompt(message)
            if context_param:
                return handler(prompt, context)
            return handler(prompt)

        # Dict or generic -> pass full message
        if context_param:
            return handler(message, context)
        return handler(message)

    # Multiple params
    if len(other_params) == 0 and context_param:
        return handler(context)

    # Try keyword args from payload
    payload = message.get("payload", {})
    kwargs: dict[str, Any] = {}

    for param in other_params:
        name = param.name
        if name in payload:
            kwargs[name] = payload[name]
        elif param.default is not inspect.Parameter.empty:
            continue
        elif name == "message" or name == "msg":
            kwargs[name] = message

    if context_param:
        kwargs[context_param.name] = context

    if kwargs:
        return handler(**kwargs)

    # Fallback: pass message
    if context_param:
        return handler(message, context)
    return handler(message)

def _extract_prompt(message: dict[str, Any]) -> str:
    """Extract prompt text from a message dict."""
    payload = message.get("payload") if isinstance(message.get("payload"), dict) else {}

    # Try common keys in payload
    for key in ("text", "prompt", "input", "message", "content", "query", "value"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value

    # Try top-level message keys
    for key in ("text", "prompt", "input", "content"):
        value = message.get(key)
        if isinstance(value, str) and value.strip():
            return value

    # Fallback
    return str(payload) if payload else ""

def _wrap_sync_handler(
    handler: Callable,
    config: AgentConfig,
) -> Callable:
    """Wrap a sync handler with Khaos instrumentation.

    Features:
    - Thread-safe context using contextvars
    - Optional timeout enforcement
    - Full traceback capture on errors
    - Streaming response support
    """

    @functools.wraps(handler)
    def wrapper(message: dict[str, Any]) -> dict[str, Any]:
        start_time = time.perf_counter()
        agent_name = config.name or handler.__name__

        # If validate_input is enabled, validate first (so None becomes the canonical "unknown" envelope).
        # Otherwise, normalize non-dict inputs into an envelope to keep _adapt_call safe.
        if config.validate_input:
            message = _validate_input_message(message)
        elif not isinstance(message, dict):
            message = {
                "name": "invoke",
                "payload": {"text": message} if isinstance(message, str) else {"value": message},
                "metadata": {},
            }

        # Create context
        context = InvocationContext(
            agent_name=agent_name,
            agent_version=config.version,
            message=message,
            metadata=config.metadata.copy(),
            start_time=start_time,
        )

        # Set context using contextvars (thread-safe)
        token = _current_context.set(context)

        try:
            # Execute with optional timeout
            if config.timeout_ms > 0:
                result = _execute_with_timeout(
                    lambda: _adapt_call(handler, message, context),
                    config.timeout_ms,
                    agent_name,
                )
            else:
                result = _adapt_call(handler, message, context)

            # Handle streaming responses - pass through with metadata
            if isinstance(result, StreamingResponse):
                # Return streaming response directly - caller handles iteration
                # We can't collect latency until stream is consumed
                return result

            # Handle sync generators by collecting all results
            if inspect.isgenerator(result):
                result = _collect_generator(result)

            latency_ms = context.elapsed_ms

            # Use unified normalization for maximum flexibility
            envelope = normalize_agent_output(result)

            # Add latency metadata
            if "metadata" not in envelope:
                envelope["metadata"] = {}
            envelope["metadata"]["latency_ms"] = round(latency_ms, 2)

            if config.strict or config.validate_output:
                envelope["payload"] = _normalize_payload(envelope.get("payload"))

            return envelope

        except Exception as exc:
            latency_ms = (time.perf_counter() - start_time) * 1000
            if config.capture_errors:
                return _make_error_envelope(exc, latency_ms)
            raise

        finally:
            # Reset context (thread-safe)
            _current_context.reset(token)

    return wrapper

class StreamingResponse:
    """Preserves streaming semantics while capturing telemetry.

    This class wraps a generator to allow streaming responses while still
    capturing the full output for telemetry. Use this when you need to
    preserve real-time streaming behavior.

    Usage:
        @khaosagent
        def streaming_agent(message):
            def generate():
                for chunk in llm.stream(...):
                    yield chunk
            return StreamingResponse(generate())

        # Consumer can iterate and get chunks in real-time:
        for chunk in streaming_agent(msg):
            print(chunk)

    Attributes:
        chunks: List of collected chunks (available during/after iteration)
        collected: Full concatenated content (available after iteration completes)
        is_complete: Whether iteration has finished
    """

    def __init__(
        self,
        generator: Iterator[Any],
        on_chunk: Callable[[Any], None] | None = None,
        on_complete: Callable[[list[Any]], None] | None = None,
    ):
        """Initialize a streaming response.

        Args:
            generator: The underlying generator to wrap
            on_chunk: Optional callback called for each chunk
            on_complete: Optional callback called when iteration completes
        """
        self._generator = generator
        self._on_chunk = on_chunk
        self._on_complete = on_complete
        self._chunks: list[Any] = []
        self._is_complete = False

    def __iter__(self) -> Iterator[Any]:
        return self

    def __next__(self) -> Any:
        try:
            chunk = next(self._generator)
            self._chunks.append(chunk)
            if self._on_chunk:
                self._on_chunk(chunk)
            return chunk
        except StopIteration:
            self._is_complete = True
            if self._on_complete:
                self._on_complete(self._chunks)
            raise

    @property
    def chunks(self) -> list[Any]:
        """Get all collected chunks so far."""
        return self._chunks

    @property
    def is_complete(self) -> bool:
        """Check if streaming has completed."""
        return self._is_complete

    @property
    def collected(self) -> str:
        """Get the full collected content as a string.

        Best called after iteration is complete, but can be called
        during iteration to get content so far.
        """
        parts = []
        for item in self._chunks:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = extract_output_text(item)
                if text:
                    parts.append(text)
            else:
                parts.append(str(item))
        return "".join(parts)

class AsyncStreamingResponse:
    """Async version of StreamingResponse for async generators.

    Usage:
        @khaosagent
        async def streaming_agent(message):
            async def generate():
                async for chunk in llm.stream_async(...):
                    yield chunk
            return AsyncStreamingResponse(generate())

        # Consumer can iterate asynchronously:
        async for chunk in await streaming_agent(msg):
            print(chunk)
    """

    def __init__(
        self,
        generator: AsyncIterator[Any],
        on_chunk: Callable[[Any], None] | None = None,
        on_complete: Callable[[list[Any]], None] | None = None,
    ):
        """Initialize an async streaming response.

        Args:
            generator: The underlying async generator to wrap
            on_chunk: Optional callback called for each chunk
            on_complete: Optional callback called when iteration completes
        """
        self._generator = generator
        self._on_chunk = on_chunk
        self._on_complete = on_complete
        self._chunks: list[Any] = []
        self._is_complete = False

    def __aiter__(self) -> AsyncIterator[Any]:
        return self

    async def __anext__(self) -> Any:
        try:
            chunk = await self._generator.__anext__()
            self._chunks.append(chunk)
            if self._on_chunk:
                self._on_chunk(chunk)
            return chunk
        except StopAsyncIteration:
            self._is_complete = True
            if self._on_complete:
                self._on_complete(self._chunks)
            raise

    @property
    def chunks(self) -> list[Any]:
        """Get all collected chunks so far."""
        return self._chunks

    @property
    def is_complete(self) -> bool:
        """Check if streaming has completed."""
        return self._is_complete

    @property
    def collected(self) -> str:
        """Get the full collected content as a string."""
        parts = []
        for item in self._chunks:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = extract_output_text(item)
                if text:
                    parts.append(text)
            else:
                parts.append(str(item))
        return "".join(parts)

def _collect_generator(gen: Any) -> str:
    """Collect a generator/iterator into a single string output.

    This supports streaming-style agents that yield partial results.
    Note: For preserving streaming semantics, use StreamingResponse instead.
    """
    # If it's already a StreamingResponse, consume it and return collected
    if isinstance(gen, StreamingResponse):
        for _ in gen:
            pass
        return gen.collected

    parts = []
    for item in gen:
        if isinstance(item, str):
            parts.append(item)
        elif isinstance(item, dict):
            text = extract_output_text(item)
            if text:
                parts.append(text)
        else:
            parts.append(str(item))
    return "".join(parts)

async def _collect_async_generator(gen: Any) -> str:
    """Collect an async generator into a single string output.

    Note: For preserving streaming semantics, use AsyncStreamingResponse instead.
    """
    # If it's already an AsyncStreamingResponse, consume it and return collected
    if isinstance(gen, AsyncStreamingResponse):
        async for _ in gen:
            pass
        return gen.collected

    parts = []
    async for item in gen:
        if isinstance(item, str):
            parts.append(item)
        elif isinstance(item, dict):
            text = extract_output_text(item)
            if text:
                parts.append(text)
        else:
            parts.append(str(item))
    return "".join(parts)

def _wrap_async_handler(
    handler: Callable,
    config: AgentConfig,
) -> Callable:
    """Wrap an async handler with Khaos instrumentation.

    Features:
    - Thread-safe context using contextvars (works with asyncio)
    - Optional timeout enforcement via asyncio.wait_for
    - Full traceback capture on errors
    - Streaming response support
    """

    @functools.wraps(handler)
    async def wrapper(message: dict[str, Any]) -> dict[str, Any]:
        start_time = time.perf_counter()
        agent_name = config.name or handler.__name__

        if config.validate_input:
            message = _validate_input_message(message)
        elif not isinstance(message, dict):
            message = {
                "name": "invoke",
                "payload": {"text": message} if isinstance(message, str) else {"value": message},
                "metadata": {},
            }

        # Create context
        context = InvocationContext(
            agent_name=agent_name,
            agent_version=config.version,
            message=message,
            metadata=config.metadata.copy(),
            start_time=start_time,
        )

        # Set context using contextvars (works correctly with asyncio)
        token = _current_context.set(context)

        try:
            # Call handler with signature adaptation
            result = _adapt_call(handler, message, context)
            if inspect.isawaitable(result):
                # Apply timeout if configured
                if config.timeout_ms > 0:
                    try:
                        result = await asyncio.wait_for(
                            result,
                            timeout=config.timeout_ms / 1000.0
                        )
                    except asyncio.TimeoutError:
                        raise AgentTimeoutError(
                            f"Agent '{agent_name}' exceeded timeout of {config.timeout_ms}ms"
                        )
                else:
                    result = await result

            # Handle streaming responses - pass through with metadata
            if isinstance(result, (StreamingResponse, AsyncStreamingResponse)):
                # Return streaming response directly - caller handles iteration
                # We can't collect latency until stream is consumed
                return result

            # Handle async generators by collecting all results
            if inspect.isasyncgen(result):
                result = await _collect_async_generator(result)
            elif inspect.isgenerator(result):
                result = _collect_generator(result)

            latency_ms = context.elapsed_ms

            # Use unified normalization for maximum flexibility
            envelope = normalize_agent_output(result)

            # Add latency metadata
            if "metadata" not in envelope:
                envelope["metadata"] = {}
            envelope["metadata"]["latency_ms"] = round(latency_ms, 2)

            if config.strict or config.validate_output:
                envelope["payload"] = _normalize_payload(envelope.get("payload"))

            return envelope

        except Exception as exc:
            latency_ms = (time.perf_counter() - start_time) * 1000
            if config.capture_errors:
                return _make_error_envelope(exc, latency_ms)
            raise

        finally:
            # Reset context (thread-safe)
            _current_context.reset(token)

    return wrapper

@overload
def khaosagent(handler: F) -> F:
    """Simple decorator usage: @khaosagent"""
    ...

@overload
def khaosagent(
    *,
    name: str | None = None,
    version: str = "1.0.0",
    description: str = "",
    metadata: dict[str, Any] | None = None,
    strict: bool = False,
    capture_errors: bool = True,
    emit_telemetry: bool = True,
    validate_input: bool = False,
    validate_output: bool = False,
    timeout_ms: int = 0,
    category: AgentCategory | str | None = None,
    capabilities: list[str] | None = None,
    framework: str | None = None,
    tools: list[ToolDefinition | dict[str, Any]] | None = None,
    security_mode: str = "agent_input",
    mcp_servers: list[str] | None = None,
) -> Callable[[F], F]:
    """Decorator with options: @khaosagent(name="my-agent", version="2.0")"""
    ...

def khaosagent(
    handler: F | None = None,
    *,
    name: str | None = None,
    version: str = "1.0.0",
    description: str = "",
    metadata: dict[str, Any] | None = None,
    strict: bool = False,
    capture_errors: bool = True,
    emit_telemetry: bool = True,
    validate_input: bool = False,
    validate_output: bool = False,
    timeout_ms: int = 0,
    category: AgentCategory | str | None = None,
    capabilities: list[str] | None = None,
    framework: str | None = None,
    tools: list[ToolDefinition | dict[str, Any]] | None = None,
    security_mode: str = "agent_input",
    mcp_servers: list[str] | None = None,
) -> F | Callable[[F], F]:
    """Unified decorator for Khaos agents - provides runtime instrumentation AND discovery metadata.

    Can be used with or without arguments:

        @khaosagent
        def handle(message):
            return {"text": "response"}

        @khaosagent(name="my-agent", version="2.0", strict=True)
        def handle(message):
            return {"text": "response"}

    Signature Flexibility:
        The decorated callable can accept various signatures:
        - fn() -> called with no args
        - fn(msg: dict) -> called with full message dict
        - fn(prompt: str) -> called with extracted prompt text
        - fn(message, context: InvocationContext) -> message and context
        - fn(**kwargs) -> payload fields as keyword args

    Return Value Flexibility:
        The handler may return:
        - a dict payload (wrapped as {"name":"agent.response","payload": ...})
        - a (name, payload) tuple
        - a full {"name": ..., "payload": ...} envelope
        - a string (wrapped as {"value": str})
        - any value (wrapped as {"value": value})

    Args:
        name: Agent name (defaults to function name). Used for `khaos run <name>`.
        version: Agent version string
        description: Human-readable description of the agent
        metadata: Additional metadata to attach to telemetry
        strict: If True, normalize outputs to include required fields
        capture_errors: If True, catch exceptions and return error responses
        emit_telemetry: If True, emit LLM telemetry events automatically
        validate_input: If True, validate input message structure
        validate_output: If True, validate output message structure
        timeout_ms: Optional timeout in milliseconds (0 = no timeout)
        category: Agent category for classification (llm_inference, tool_agent, etc.)
        capabilities: List of capabilities (tool-calling, mcp, etc.)
        framework: Framework name (openai, anthropic, langgraph, etc.)
        tools: List of tools available to the agent (ToolDefinition or dict).
            Used for discovery, playground UI, and capability inference.
            Example: [ToolDefinition(name="search", description="Search the web")]
        security_mode: How security attacks are injected during testing.
            "agent_input" (default) tests the full stack including input filtering.
            "llm" tests raw LLM defenses only, bypassing agent code.
        mcp_servers: List of MCP server names this agent uses (e.g., ["sqlite", "filesystem"]).
            Used for auto-discovery and MCP fault injection configuration.
    """

    config = AgentConfig(
        name=name,
        version=version,
        description=description,
        metadata=metadata or {},
        strict=strict,
        capture_errors=capture_errors,
        emit_telemetry=emit_telemetry,
        validate_input=validate_input,
        validate_output=validate_output,
        timeout_ms=timeout_ms,
        category=category,
        capabilities=capabilities or [],
        framework=framework,
        tools=tools or [],
        security_mode=security_mode,
        mcp_servers=mcp_servers or [],
    )

    def decorator(fn: F) -> F:
        # Resolve agent name
        agent_name = config.name or fn.__name__

        # Auto-add "mcp" capability if mcp_servers specified
        if config.mcp_servers and "mcp" not in config.capabilities:
            config.capabilities.append("mcp")

        # Auto-add "tool-calling" capability if tools specified
        if config.tools and "tool-calling" not in config.capabilities:
            config.capabilities.append("tool-calling")

        # Normalize and validate all capabilities to canonical form
        # This ensures consistent capability names across the system
        normalized_caps = []
        for cap in config.capabilities:
            normalized, is_canonical = validate_capability(cap, warn=True)
            normalized_caps.append(normalized)
        # Deduplicate while preserving order
        seen = set()
        config.capabilities = [
            c for c in normalized_caps
            if c not in seen and not seen.add(c)  # type: ignore[func-returns-value]
        ]

        # Handle class-based agents: wrap the __call__ method
        if inspect.isclass(fn):
            return _wrap_class_agent(fn, config, agent_name)

        # Handle callable instances (objects with __call__)
        if not inspect.isfunction(fn) and not inspect.ismethod(fn) and hasattr(fn, "__call__"):
            # Wrap the callable instance
            call_method = fn.__call__
            if inspect.iscoroutinefunction(call_method):
                wrapped_call = _wrap_async_handler(call_method, config)
            else:
                wrapped_call = _wrap_sync_handler(call_method, config)

            # Create a wrapper that preserves the instance but uses wrapped __call__
            @functools.wraps(call_method)
            def instance_wrapper(message: dict[str, Any]) -> dict[str, Any]:
                return wrapped_call(message)

            wrapped = instance_wrapper
        # Wrap based on sync/async for regular functions
        elif inspect.iscoroutinefunction(fn):
            wrapped = _wrap_async_handler(fn, config)
        else:
            wrapped = _wrap_sync_handler(fn, config)

        # Set runtime marker attributes
        setattr(wrapped, "__khaos_agent__", True)
        setattr(wrapped, "__khaos_config__", config)
        setattr(wrapped, "__khaos_name__", agent_name)
        setattr(wrapped, "__khaos_version__", config.version)
        setattr(wrapped, "__khaos_security_mode__", config.security_mode)
        setattr(wrapped, "__khaos_mcp_servers__", config.mcp_servers)
        setattr(wrapped, "__khaos_tools__", config.get_tools_list())

        # Set static discovery metadata (for AST-based discovery)
        static_config = config.to_static_config()
        static_config["name"] = agent_name  # Ensure name is always set
        setattr(wrapped, "__khaos_agent_config__", static_config)

        # Preserve original function for introspection
        setattr(wrapped, "__wrapped__", fn)
        # Store function name for multi-agent file support
        setattr(wrapped, "__khaos_function_name__", fn.__name__)

        return cast(F, wrapped)

    # Handle both @khaosagent and @khaosagent() usage
    if handler is not None:
        return decorator(handler)

    return decorator

def _wrap_class_agent(cls: type, config: AgentConfig, agent_name: str) -> type:
    """Wrap a class-based agent by instrumenting its __call__ method.

    This allows developers to write agents as classes:

        @khaosagent(name="my-agent")
        class MyAgent:
            def __init__(self):
                self.state = {}

            def __call__(self, message: dict) -> dict:
                return {"text": "response"}

    The decorator wraps __call__ with the standard instrumentation while
    preserving the class structure and instance state.
    """
    original_init = cls.__init__
    original_call = getattr(cls, "__call__", None)

    if original_call is None:
        raise TypeError(
            f"Class {cls.__name__} must have a __call__ method to be used as a Khaos agent. "
            f"Add a __call__(self, message: dict) -> dict method."
        )

    # Determine if __call__ is async
    is_async = inspect.iscoroutinefunction(original_call)

    if is_async:
        @functools.wraps(original_call)
        async def wrapped_call(self: Any, message: dict[str, Any]) -> dict[str, Any]:
            # Use the instance's __call__ with proper binding
            handler = lambda msg: original_call(self, msg)
            wrapped = _wrap_async_handler(handler, config)
            return await wrapped(message)
    else:
        @functools.wraps(original_call)
        def wrapped_call(self: Any, message: dict[str, Any]) -> dict[str, Any]:
            handler = lambda msg: original_call(self, msg)
            wrapped = _wrap_sync_handler(handler, config)
            return wrapped(message)

    # Create a new class with the wrapped __call__
    new_cls = type(
        cls.__name__,
        cls.__bases__,
        {**cls.__dict__, "__call__": wrapped_call},
    )

    # Set runtime marker attributes on the class
    setattr(new_cls, "__khaos_agent__", True)
    setattr(new_cls, "__khaos_config__", config)
    setattr(new_cls, "__khaos_name__", agent_name)
    setattr(new_cls, "__khaos_version__", config.version)
    setattr(new_cls, "__khaos_security_mode__", config.security_mode)
    setattr(new_cls, "__khaos_mcp_servers__", config.mcp_servers)
    setattr(new_cls, "__khaos_tools__", config.get_tools_list())

    # Set static discovery metadata
    static_config = config.to_static_config()
    static_config["name"] = agent_name
    setattr(new_cls, "__khaos_agent_config__", static_config)

    # Preserve original class for introspection
    setattr(new_cls, "__wrapped__", cls)
    setattr(new_cls, "__khaos_function_name__", cls.__name__)

    return new_cls

def khaos_agent(
    handler: F | None = None,
    *,
    name: str | None = None,
    version: str = "1.0.0",
    description: str = "",
    metadata: dict[str, Any] | None = None,
    strict: bool = False,
    capture_errors: bool = True,
    emit_telemetry: bool = True,
    validate_input: bool = False,
    validate_output: bool = False,
    timeout_ms: int = 0,
    category: AgentCategory | str | None = None,
    capabilities: list[str] | None = None,
    framework: str | None = None,
    tools: list[ToolDefinition | dict[str, Any]] | None = None,
    security_mode: str = "agent_input",
    mcp_servers: list[str] | None = None,
) -> F | Callable[[F], F]:
    """Deprecated: use :func:`khaosagent` instead. Will be removed in v2.0."""
    warnings.warn(
        "@khaos_agent is deprecated since v1.0 and will be removed in v2.0. Use @khaosagent instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return khaosagent(
        handler,
        name=name,
        version=version,
        description=description,
        metadata=metadata,
        strict=strict,
        capture_errors=capture_errors,
        emit_telemetry=emit_telemetry,
        validate_input=validate_input,
        validate_output=validate_output,
        timeout_ms=timeout_ms,
        category=category,
        capabilities=capabilities,
        framework=framework,
        tools=tools,
        security_mode=security_mode,
        mcp_servers=mcp_servers,
    )
