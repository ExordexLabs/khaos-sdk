"""Unified output handling utilities for Khaos agents.

This module provides canonical functions for extracting and normalizing
agent output, reducing friction for developers using different frameworks
or return formats.

The key insight: different frameworks return outputs in different formats,
and developers shouldn't need to know the exact key names Khaos expects.
This module bridges that gap by supporting many common patterns.
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Keys to check for output text, in priority order.
# This covers common patterns across frameworks:
# - content: OpenAI, Anthropic message content
# - text: Generic text output, Anthropic blocks
# - message: Chat message content
# - value: Wrapped primitives
# - result: Function/tool results
# - response: Generic response field
# - output: Generic output field
# - answer: Q&A style outputs
OUTPUT_TEXT_KEYS = (
    "content",
    "text",
    "message",
    "value",
    "result",
    "response",
    "output",
    "answer",
)

# Keys for prompt/input extraction
INPUT_TEXT_KEYS = (
    "text",
    "prompt",
    "input",
    "message",
    "content",
    "query",
    "value",
    "question",
)

def extract_output_text(payload: Any) -> str:
    """Extract text content from an agent response payload.

    This function tries multiple common keys to find the output text,
    supporting various frameworks and return formats without requiring
    developers to use specific key names.

    Supported patterns:
    - Dict with common keys: {"content": "..."}, {"text": "..."}, etc.
    - String payloads: returned as-is
    - List of content blocks: extracts text from each block
    - Framework objects: attempts to extract from common attributes
    - Nested payloads: looks inside 'payload' key if present

    Args:
        payload: The agent response payload (dict, str, or other)

    Returns:
        Extracted text content, or JSON representation if no text found

    Examples:
        >>> extract_output_text({"content": "Hello"})
        'Hello'
        >>> extract_output_text({"text": "World"})
        'World'
        >>> extract_output_text("Direct string")
        'Direct string'
        >>> extract_output_text({"result": {"value": "Nested"}})
        'Nested'
    """
    if payload is None:
        return ""

    # String payloads are returned as-is
    if isinstance(payload, str):
        return payload

    # Handle dict payloads
    if isinstance(payload, dict):
        # Check if this is a wrapped envelope with nested payload
        if "payload" in payload and isinstance(payload["payload"], dict):
            inner = payload["payload"]
            result = _extract_from_dict(inner)
            if result:
                return result

        # Try direct extraction from this dict
        result = _extract_from_dict(payload)
        if result:
            return result

        # Fallback: serialize the dict
        try:
            return json.dumps(payload, sort_keys=True, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(payload)

    # Handle list payloads (e.g., Anthropic content blocks)
    if isinstance(payload, (list, tuple)):
        texts = []
        for item in payload:
            if isinstance(item, str):
                texts.append(item)
            elif isinstance(item, dict):
                # Check for content block format {"type": "text", "text": "..."}
                if item.get("type") == "text" and "text" in item:
                    texts.append(str(item["text"]))
                else:
                    extracted = _extract_from_dict(item)
                    if extracted:
                        texts.append(extracted)
            elif hasattr(item, "text"):
                texts.append(str(item.text))
        if texts:
            return "\n".join(texts)

    # Try framework object extraction
    result = _extract_from_object(payload)
    if result:
        return result

    # Final fallback
    return str(payload)

def _extract_from_dict(d: dict[str, Any]) -> str:
    """Extract text from a dict using known keys."""
    # Try each key in priority order
    for key in OUTPUT_TEXT_KEYS:
        value = d.get(key)
        if isinstance(value, str) and value.strip():
            return value
        # Handle nested dict with text
        if isinstance(value, dict):
            nested = _extract_from_dict(value)
            if nested:
                return nested

    # Check for error messages
    error = d.get("error")
    if isinstance(error, str) and error.strip():
        return f"Error: {error}"

    return ""

def _extract_from_object(obj: Any) -> str:
    """Extract text from framework objects using common attributes.

    Supports common framework patterns:
    - LangChain: AIMessage.content, BaseMessage.content
    - CrewAI: TaskOutput.raw, CrewOutput.raw
    - Pydantic AI: RunResult.data
    - Generic: .text, .content, .message, .output, .result
    """
    # Priority order of attributes to check
    attrs = ("content", "text", "raw", "message", "output", "result", "data", "response")

    for attr in attrs:
        if hasattr(obj, attr):
            value = getattr(obj, attr, None)
            if isinstance(value, str) and value.strip():
                return value
            # Handle nested extraction
            if value is not None and not isinstance(value, (str, int, float, bool)):
                nested = extract_output_text(value)
                if nested and nested != str(value):
                    return nested

    # Check for __str__ that's been customized
    str_repr = str(obj)
    if str_repr and not str_repr.startswith("<") and len(str_repr) < 10000:
        return str_repr

    return ""

def extract_input_text(message: dict[str, Any]) -> str:
    """Extract prompt/input text from an incoming message.

    This is used to extract the user's input from various message formats,
    supporting different ways agents might receive input.

    Args:
        message: The incoming message dict (may have name/payload/metadata structure)

    Returns:
        Extracted input text

    Examples:
        >>> extract_input_text({"payload": {"text": "Hello"}})
        'Hello'
        >>> extract_input_text({"prompt": "What is 2+2?"})
        'What is 2+2?'
    """
    if not isinstance(message, dict):
        return str(message) if message else ""

    # Check payload first if it exists
    payload = message.get("payload")
    if isinstance(payload, dict):
        for key in INPUT_TEXT_KEYS:
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value

    # Check top-level keys
    for key in INPUT_TEXT_KEYS:
        value = message.get(key)
        if isinstance(value, str) and value.strip():
            return value

    # Fallback to payload string representation
    if payload:
        try:
            return json.dumps(payload, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(payload)

    return ""

def normalize_agent_output(result: Any) -> dict[str, Any]:
    """Normalize any agent return value to the standard envelope format.

    This function handles the widest variety of return types, making it
    easy for developers to return whatever is natural for their framework
    while still conforming to the Khaos envelope contract.

    Supported return types:
    - None: Empty success response
    - str: Wrapped in {"text": str}
    - dict with name/payload: Treated as envelope, passed through
    - dict without name/payload: Treated as payload, wrapped in envelope
    - tuple (name, payload): Wrapped in envelope
    - Framework objects: Extracted and wrapped
    - Generators/iterators: Collected and joined
    - Any other type: Converted via extract_output_text

    Args:
        result: The agent's return value

    Returns:
        Dict in envelope format: {"name": str, "payload": dict}

    Examples:
        >>> normalize_agent_output("Hello")
        {'name': 'agent.response', 'payload': {'text': 'Hello', 'status': 'success'}}
        >>> normalize_agent_output({"data": 123})
        {'name': 'agent.response', 'payload': {'data': 123, 'status': 'success'}}
    """
    # None -> empty success
    if result is None:
        return {
            "name": "agent.response",
            "payload": {"status": "success"},
        }

    # Already an envelope
    if isinstance(result, dict) and "name" in result and "payload" in result:
        envelope = result.copy()
        payload = envelope.get("payload")
        if isinstance(payload, dict):
            payload.setdefault("status", "success")
        else:
            envelope["payload"] = {"value": payload, "status": "success"}
        return envelope

    # Tuple (name, payload)
    if isinstance(result, tuple) and len(result) == 2:
        name, payload = result
        if not isinstance(payload, dict):
            payload = {"value": payload}
        payload.setdefault("status", "success")
        return {
            "name": str(name) if name else "agent.response",
            "payload": payload,
        }

    # String -> wrap in text
    if isinstance(result, str):
        return {
            "name": "agent.response",
            "payload": {"text": result, "status": "success"},
        }

    # Dict payload (no name/payload keys) -> wrap
    if isinstance(result, dict):
        payload = result.copy()
        payload.setdefault("status", "success")
        return {
            "name": "agent.response",
            "payload": payload,
        }

    # List/tuple of results -> join text
    if isinstance(result, (list, tuple)):
        text = extract_output_text(result)
        return {
            "name": "agent.response",
            "payload": {"text": text, "status": "success"},
        }

    # Generator/iterator -> collect and join
    if hasattr(result, "__iter__") and hasattr(result, "__next__"):
        try:
            collected = list(result)
            text = extract_output_text(collected)
            return {
                "name": "agent.response",
                "payload": {"text": text, "status": "success"},
            }
        except Exception:
            logger.debug("Failed to consume generator result", exc_info=True)

    # Framework object -> extract content
    text = extract_output_text(result)
    if text:
        return {
            "name": "agent.response",
            "payload": {"text": text, "status": "success"},
        }

    # Final fallback
    return {
        "name": "agent.response",
        "payload": {"value": str(result), "status": "success"},
    }

def is_envelope(value: Any) -> bool:
    """Check if a value is already in envelope format.

    Args:
        value: The value to check

    Returns:
        True if value is a dict with both 'name' and 'payload' keys
    """
    return isinstance(value, dict) and "name" in value and "payload" in value
