"""Entry point invoker.

Handles invocation of different entry point types with signature adaptation.
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any
from collections.abc import Callable

from .detector import AgentEntryPoint, EntryPointType

class InvocationError(Exception):
    """Error during entry point invocation."""

    pass

def extract_prompt(message: dict[str, Any]) -> str:
    """Extract prompt text from a message dict."""
    payload = message.get("payload") if isinstance(message.get("payload"), dict) else {}

    # Try common keys
    for key in ("text", "prompt", "input", "message", "content", "query", "value"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value

    # Try top-level message keys
    for key in ("text", "prompt", "input", "content"):
        value = message.get(key)
        if isinstance(value, str) and value.strip():
            return value

    # Fallback to string representation
    return str(payload) if payload else ""

def adapt_signature(
    fn: Callable[..., Any],
    message: dict[str, Any],
) -> tuple[tuple[Any, ...], dict[str, Any]]:
    """Adapt message to match function signature.

    Returns (args, kwargs) to call the function with.
    """
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        # Can't inspect, just pass the message
        return (message,), {}

    params = list(sig.parameters.values())

    # No params: call with nothing
    if not params:
        return (), {}

    # Filter out self/cls for methods
    if params and params[0].name in ("self", "cls"):
        params = params[1:]

    if not params:
        return (), {}

    # Single param: detect type hint or name
    if len(params) == 1:
        param = params[0]
        annotation = param.annotation

        # String annotation -> pass prompt
        if annotation is str:
            return (extract_prompt(message),), {}

        # Name-based heuristics
        if param.name.lower() in {"prompt", "text", "message", "input", "content", "query"}:
            return (extract_prompt(message),), {}

        # Dict annotation or generic -> pass full message
        return (message,), {}

    # Multiple params: try to match by name
    kwargs: dict[str, Any] = {}
    payload = message.get("payload", {})

    for param in params:
        name = param.name.lower()

        if name in {"message", "msg"}:
            kwargs[param.name] = message
        elif name in {"payload", "data"}:
            kwargs[param.name] = payload
        elif name in {"prompt", "text", "input", "content", "query"}:
            kwargs[param.name] = extract_prompt(message)
        elif name == "name":
            kwargs[param.name] = message.get("name", "")
        elif param.default is not inspect.Parameter.empty:
            # Has default, skip
            continue
        else:
            # Try to find in payload
            if name in payload:
                kwargs[param.name] = payload[name]
            elif param.default is inspect.Parameter.empty:
                # Required param not found, pass message as first positional
                return (message,), {}

    return (), kwargs

async def invoke_entry_point(
    entry_point: AgentEntryPoint,
    module: Any,
    message: dict[str, Any],
) -> Any:
    """Invoke an entry point with a message.

    Handles:
    - Functions (sync and async)
    - Classes (instantiation + method call)
    - Methods on instances
    """
    target = getattr(module, entry_point.name, None)
    if target is None:
        raise InvocationError(f"Entry point '{entry_point.name}' not found in module")

    # Handle different entry point types
    if entry_point.entry_type in (
        EntryPointType.FUNCTION,
        EntryPointType.ASYNC_FUNCTION,
        EntryPointType.DECORATED_FUNCTION,
        EntryPointType.DECORATED_ASYNC_FUNCTION,
    ):
        return await _invoke_function(target, message, entry_point.is_async)

    elif entry_point.entry_type in (
        EntryPointType.CLASS,
        EntryPointType.DECORATED_CLASS,
        EntryPointType.CLASS_INSTANCE,
    ):
        return await _invoke_class(target, message, entry_point)

    else:
        raise InvocationError(f"Unsupported entry point type: {entry_point.entry_type}")

async def _invoke_function(
    fn: Callable[..., Any],
    message: dict[str, Any],
    is_async: bool,
) -> Any:
    """Invoke a function with signature adaptation."""
    args, kwargs = adapt_signature(fn, message)

    if kwargs:
        result = fn(**kwargs)
    elif args:
        result = fn(*args)
    else:
        result = fn()

    if inspect.isawaitable(result):
        result = await result

    return result

async def _invoke_class(
    cls: type,
    message: dict[str, Any],
    entry_point: AgentEntryPoint,
) -> Any:
    """Invoke a class by instantiating and calling invoke method."""
    # Instantiate the class
    try:
        instance = cls()
    except TypeError:
        # May need arguments
        try:
            instance = cls(message)
        except TypeError:
            raise InvocationError(
                f"Could not instantiate class '{entry_point.name}'. "
                "Consider adding a @khaos_agent decorator to a function instead."
            )

    # Find the invoke method
    method_name = entry_point.invoke_method
    if not method_name:
        # Try common patterns
        for name in ("__call__", "run", "invoke", "execute", "process", "handle"):
            if hasattr(instance, name) and callable(getattr(instance, name)):
                method_name = name
                break

    if not method_name:
        raise InvocationError(
            f"No invoke method found on class '{entry_point.name}'. "
            f"Expected one of: __call__, run, invoke, execute, process, handle"
        )

    method = getattr(instance, method_name)
    return await _invoke_function(method, message, entry_point.is_async)

def normalize_response(result: Any) -> dict[str, Any]:
    """Normalize any result to standard response format."""
    if result is None:
        return {"name": "agent-response", "payload": {}}

    # Already in correct format
    if isinstance(result, dict) and "name" in result and "payload" in result:
        return {
            "name": result.get("name") or "agent-response",
            "payload": result.get("payload") if isinstance(result.get("payload"), dict) else {},
        }

    # Tuple of (name, payload)
    if isinstance(result, tuple) and len(result) == 2:
        name, payload = result
        return {
            "name": str(name or "agent-response"),
            "payload": payload if isinstance(payload, dict) else {"value": payload},
        }

    # Plain dict -> wrap as payload
    if isinstance(result, dict):
        return {"name": "agent-response", "payload": result}

    # String -> wrap as value
    if isinstance(result, str):
        return {"name": "agent-response", "payload": {"value": result}}

    # Anything else -> wrap as value
    return {"name": "agent-response", "payload": {"value": result}}
