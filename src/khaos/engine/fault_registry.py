"""Fault injection helpers for the runtime.

This module provides built-in fault handlers and integrates with the
custom fault plugin system for extensibility.
"""

from __future__ import annotations

from typing import Any
from collections.abc import Awaitable, Callable

from .scheduler import SeededScheduler

FaultHandler = Callable[[dict[str, Any], SeededScheduler], Awaitable[dict[str, Any]]]

# ============================================================================
# Built-in Fault Handlers
# ============================================================================

async def handle_http_latency(config: dict[str, Any], scheduler: SeededScheduler) -> dict[str, Any]:
    delay_ms = float(config.get("delay_ms", 0.0))
    jitter_ms = float(config.get("jitter_ms", 0.0))
    await scheduler.sleep(delay_ms / 1000.0, jitter=jitter_ms / 1000.0)
    return {"latency_ms": delay_ms, "jitter_ms": jitter_ms}

async def handle_timeout(config: dict[str, Any], scheduler: SeededScheduler) -> dict[str, Any]:
    delay_ms = float(config.get("delay_ms", 0.0))
    timeout_ms = float(config.get("timeout_ms", delay_ms))
    await scheduler.sleep(delay_ms / 1000.0)
    return {"latency_ms": delay_ms, "timeout_ms": timeout_ms, "outcome": "timeout"}

async def handle_http_error(config: dict[str, Any], scheduler: SeededScheduler) -> dict[str, Any]:
    await scheduler.sleep(float(config.get("delay_ms", 0.0)) / 1000.0)
    return {
        "status_code": int(config.get("status_code", 500)),
        "body": config.get("body") or config.get("message") or "Injected error",
        "outcome": "http_error",
    }

async def handle_malformed_payload(config: dict[str, Any], scheduler: SeededScheduler) -> dict[str, Any]:
    await scheduler.sleep(float(config.get("delay_ms", 0.0)) / 1000.0)
    return {"schema": config.get("schema", "unknown"), "outcome": "malformed_payload"}

async def handle_prompt_ambiguity(config: dict[str, Any], scheduler: SeededScheduler) -> dict[str, Any]:
    await scheduler.sleep(float(config.get("delay_ms", 0.0)) / 1000.0)
    return {
        "noise": config.get("noise", "medium"),
        "outcome": "prompt_ambiguity",
    }

# Built-in handlers registry
_BUILTIN_HANDLERS: dict[str, FaultHandler] = {
    "http_latency": handle_http_latency,
    "timeout": handle_timeout,
    "http_error": handle_http_error,
    "malformed_payload": handle_malformed_payload,
    "prompt_ambiguity": handle_prompt_ambiguity,
}

# Legacy alias for backwards compatibility
FAULT_HANDLERS: dict[str, FaultHandler] = _BUILTIN_HANDLERS

# Faults handled outside the runtime loop (e.g., transport/LLM shims)
_TRANSPORT_ONLY_FAULT_TYPES: set[str] = {
    "llm_rate_limit",
    "llm_model_unavailable",
    "llm_response_timeout",
    "llm_token_quota_exceeded",
    "model_fallback_forced",
    "tool_call_failure",
    "tool_response_corruption",
    "tool_latency_spike",
    "rag_retrieval_corruption",
    "rag_document_poisoning",
    "tool_output_injection",
    "mcp_tool_latency",
    "mcp_tool_failure",
    "mcp_tool_corruption",
    "mcp_server_unavailable",
    # Context and memory faults (ADR-0010 phase 2)
    "context_window_overflow",
    "conversation_history_dropped",
    "embedding_service_failure",
}

# ============================================================================
# Unified Fault Resolution (Built-in + Custom Plugins)
# ============================================================================

def get_fault_handler(fault_type: str) -> FaultHandler | None:
    """Get a fault handler by type, checking built-in and custom plugins.
    
    Args:
        fault_type: The fault type identifier
        
    Returns:
        The fault handler function, or None if not found
    """
    # Check built-in handlers first
    if fault_type in _BUILTIN_HANDLERS:
        return _BUILTIN_HANDLERS[fault_type]
    
    # Check custom plugins
    try:
        from .fault_plugins import is_custom_fault, create_fault_handler
        if is_custom_fault(fault_type):
            return create_fault_handler(fault_type)
    except ImportError:
        pass
    
    return None

def is_known_fault_type(fault_type: str) -> bool:
    """Check if a fault type is known (built-in or custom plugin).
    
    Args:
        fault_type: The fault type identifier
        
    Returns:
        True if the fault type is registered
    """
    if fault_type in _BUILTIN_HANDLERS or fault_type in _TRANSPORT_ONLY_FAULT_TYPES:
        return True
    
    try:
        from .fault_plugins import is_custom_fault
        return is_custom_fault(fault_type)
    except ImportError:
        return False

def list_all_fault_types() -> list[str]:
    """List all available fault types (built-in + custom).
    
    Returns:
        List of fault type identifiers
    """
    fault_types = list(_BUILTIN_HANDLERS.keys()) + list(_TRANSPORT_ONLY_FAULT_TYPES)
    
    try:
        from .fault_plugins import get_registered_faults
        fault_types.extend(get_registered_faults().keys())
    except ImportError:
        pass
    
    return sorted(set(fault_types))
