"""Auto-emit LLM telemetry shim for OpenAI and Anthropic clients.

This module patches popular Python SDKs (OpenAI, Anthropic) inside the agent
process to automatically capture LLM call telemetry (model, tokens, latency).
Telemetry is emitted via `emit_llm_call` for Khaos to collect.

This shim is enabled by default via auto_wrap_shim.py, providing zero-code
telemetry capture for agents using these SDKs.

Supports both sync and async SDK methods, including streaming responses.

Compatibility:
- OpenAI: 1.0.0+ (tested with 1.0.0 - 1.x)
- Anthropic: 0.18.0+ (tested with 0.18.0 - 0.x)
"""

from __future__ import annotations

import logging
import os
import sys
import time
import warnings
from dataclasses import dataclass
from typing import Any
from collections.abc import AsyncIterator, Iterator

from khaos.llm.telemetry import emit_llm_call

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SDK Version Detection & Compatibility
# ---------------------------------------------------------------------------

@dataclass
class SDKInfo:
    """Information about an installed SDK."""

    name: str
    version: str | None
    installed: bool
    patched: bool
    compatible: bool
    error: str | None = None

# Minimum supported versions
MIN_OPENAI_VERSION = "1.0.0"
MIN_ANTHROPIC_VERSION = "0.18.0"
MIN_GOOGLE_GENAI_VERSION = "0.3.0"
MIN_COHERE_VERSION = "4.0.0"
MIN_MISTRAL_VERSION = "0.1.0"

def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse version string to tuple for comparison."""
    try:
        # Handle versions like "1.0.0", "1.2.3.post1", etc.
        parts = version_str.split(".")
        result = []
        for part in parts[:3]:  # Only first 3 parts
            # Extract numeric prefix
            num = ""
            for char in part:
                if char.isdigit():
                    num += char
                else:
                    break
            if num:
                result.append(int(num))
        return tuple(result) if result else (0,)
    except Exception:
        return (0,)

def _version_gte(version: str, minimum: str) -> bool:
    """Check if version >= minimum."""
    return _parse_version(version) >= _parse_version(minimum)

def get_openai_info() -> SDKInfo:
    """Get OpenAI SDK installation and compatibility info."""
    try:
        import openai
        version = getattr(openai, "__version__", "unknown")
        compatible = _version_gte(version, MIN_OPENAI_VERSION) if version != "unknown" else True

        # Check if we can import the classes we need to patch
        try:
            from openai.resources.chat.completions import Completions
            patched = getattr(Completions, "__khaos_telemetry_wrapped__", False)
        except ImportError:
            return SDKInfo(
                name="openai",
                version=version,
                installed=True,
                patched=False,
                compatible=False,
                error="Cannot import openai.resources.chat.completions.Completions",
            )

        return SDKInfo(
            name="openai",
            version=version,
            installed=True,
            patched=patched,
            compatible=compatible,
            error=None if compatible else f"Version {version} < {MIN_OPENAI_VERSION}",
        )
    except ImportError:
        return SDKInfo(
            name="openai",
            version=None,
            installed=False,
            patched=False,
            compatible=True,  # N/A but not an error
        )

def get_anthropic_info() -> SDKInfo:
    """Get Anthropic SDK installation and compatibility info."""
    try:
        import anthropic
        version = getattr(anthropic, "__version__", "unknown")
        compatible = _version_gte(version, MIN_ANTHROPIC_VERSION) if version != "unknown" else True

        # Check if we can import the classes we need to patch
        try:
            from anthropic.resources.messages import Messages
            patched = getattr(Messages, "__khaos_telemetry_wrapped__", False)
        except ImportError:
            return SDKInfo(
                name="anthropic",
                version=version,
                installed=True,
                patched=False,
                compatible=False,
                error="Cannot import anthropic.resources.messages.Messages",
            )

        return SDKInfo(
            name="anthropic",
            version=version,
            installed=True,
            patched=patched,
            compatible=compatible,
            error=None if compatible else f"Version {version} < {MIN_ANTHROPIC_VERSION}",
        )
    except ImportError:
        return SDKInfo(
            name="anthropic",
            version=None,
            installed=False,
            patched=False,
            compatible=True,  # N/A but not an error
        )

def get_google_genai_info() -> SDKInfo:
    """Get Google Generative AI SDK installation and compatibility info."""
    try:
        import google.generativeai as genai
        version = getattr(genai, "__version__", "unknown")
        compatible = _version_gte(version, MIN_GOOGLE_GENAI_VERSION) if version != "unknown" else True

        # Check if we can import the classes we need to patch
        try:
            from google.generativeai import GenerativeModel
            patched = getattr(GenerativeModel, "__khaos_telemetry_wrapped__", False)
        except ImportError:
            return SDKInfo(
                name="google-generativeai",
                version=version,
                installed=True,
                patched=False,
                compatible=False,
                error="Cannot import google.generativeai.GenerativeModel",
            )

        return SDKInfo(
            name="google-generativeai",
            version=version,
            installed=True,
            patched=patched,
            compatible=compatible,
            error=None if compatible else f"Version {version} < {MIN_GOOGLE_GENAI_VERSION}",
        )
    except ImportError:
        return SDKInfo(
            name="google-generativeai",
            version=None,
            installed=False,
            patched=False,
            compatible=True,
        )

def get_cohere_info() -> SDKInfo:
    """Get Cohere SDK installation and compatibility info."""
    try:
        import cohere
        version = getattr(cohere, "__version__", "unknown")
        compatible = _version_gte(version, MIN_COHERE_VERSION) if version != "unknown" else True

        # Check if we can import the classes we need to patch
        try:
            from cohere import Client
            patched = getattr(Client, "__khaos_telemetry_wrapped__", False)
        except ImportError:
            return SDKInfo(
                name="cohere",
                version=version,
                installed=True,
                patched=False,
                compatible=False,
                error="Cannot import cohere.Client",
            )

        return SDKInfo(
            name="cohere",
            version=version,
            installed=True,
            patched=patched,
            compatible=compatible,
            error=None if compatible else f"Version {version} < {MIN_COHERE_VERSION}",
        )
    except ImportError:
        return SDKInfo(
            name="cohere",
            version=None,
            installed=False,
            patched=False,
            compatible=True,
        )

def get_mistral_info() -> SDKInfo:
    """Get Mistral SDK installation and compatibility info."""
    try:
        from mistralai import Mistral
        # Get version from package metadata
        try:
            from importlib.metadata import version as get_version
            sdk_version = get_version("mistralai")
        except Exception:
            sdk_version = "unknown"

        compatible = _version_gte(sdk_version, MIN_MISTRAL_VERSION) if sdk_version != "unknown" else True
        patched = getattr(Mistral, "__khaos_telemetry_wrapped__", False)

        return SDKInfo(
            name="mistralai",
            version=sdk_version,
            installed=True,
            patched=patched,
            compatible=compatible,
            error=None if compatible else f"Version {sdk_version} < {MIN_MISTRAL_VERSION}",
        )
    except ImportError:
        return SDKInfo(
            name="mistralai",
            version=None,
            installed=False,
            patched=False,
            compatible=True,
        )

def get_sdk_compatibility() -> dict[str, SDKInfo]:
    """Get compatibility info for all supported SDKs."""
    return {
        "openai": get_openai_info(),
        "anthropic": get_anthropic_info(),
        "google-generativeai": get_google_genai_info(),
        "cohere": get_cohere_info(),
        "mistralai": get_mistral_info(),
    }

def check_compatibility(warn: bool = True) -> bool:
    """Check SDK compatibility and optionally warn about issues.

    Args:
        warn: If True, emit warnings for incompatible SDKs

    Returns:
        True if all installed SDKs are compatible
    """
    all_compatible = True
    info = get_sdk_compatibility()

    for name, sdk in info.items():
        if sdk.installed and not sdk.compatible:
            all_compatible = False
            if warn:
                warnings.warn(
                    f"Khaos: {name} SDK version {sdk.version} may not be fully compatible. "
                    f"Minimum supported: {MIN_OPENAI_VERSION if name == 'openai' else MIN_ANTHROPIC_VERSION}. "
                    f"Error: {sdk.error}",
                    UserWarning,
                    stacklevel=2,
                )

    return all_compatible

def _safe_int(value: Any) -> int:
    """Safely convert value to int, defaulting to 0."""
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def _safe_float(value: Any) -> float | None:
    """Safely convert value to float, returning None if not possible."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

def _extract_system_prompt_openai(kwargs: dict) -> str | None:
    """Extract system prompt from OpenAI-style messages array.

    Looks for messages with role='system' and concatenates their content.
    """
    messages = kwargs.get("messages", [])
    if not messages:
        return None

    system_parts = []
    for msg in messages:
        if isinstance(msg, dict) and msg.get("role") == "system":
            content = msg.get("content")
            if isinstance(content, str):
                system_parts.append(content)
            elif isinstance(content, list):
                # Handle multi-part content
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        system_parts.append(part.get("text", ""))
                    elif isinstance(part, str):
                        system_parts.append(part)

    return "\n".join(system_parts) if system_parts else None

def _extract_system_prompt_anthropic(kwargs: dict) -> str | None:
    """Extract system prompt from Anthropic API call.

    Anthropic uses a top-level 'system' parameter, not a message.
    """
    system = kwargs.get("system")
    if system is None:
        return None

    if isinstance(system, str):
        return system
    elif isinstance(system, list):
        # Handle list of content blocks
        parts = []
        for block in system:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts) if parts else None

    return None

def _extract_openai_tool_calls(resp: Any) -> list[dict[str, Any]] | None:
    """Extract tool calls from OpenAI response."""
    try:
        choices = getattr(resp, "choices", None)
        if not choices:
            return None

        tool_calls = []
        for choice in choices:
            message = getattr(choice, "message", None)
            if not message:
                continue

            calls = getattr(message, "tool_calls", None)
            if not calls:
                continue

            for call in calls:
                tool_call_data = {
                    "id": getattr(call, "id", None),
                    "type": getattr(call, "type", "function"),
                }
                fn = getattr(call, "function", None)
                if fn:
                    tool_call_data["function"] = {
                        "name": getattr(fn, "name", None),
                        "arguments": getattr(fn, "arguments", None),
                    }
                tool_calls.append(tool_call_data)

        return tool_calls if tool_calls else None
    except Exception:
        return None

def _emit_openai_telemetry(resp: Any, kwargs: dict, elapsed_ms: float) -> None:
    """Extract and emit telemetry from OpenAI response."""
    try:
        model = kwargs.get("model") or getattr(resp, "model", "openai")
        usage = getattr(resp, "usage", None)
        prompt_tokens = 0
        completion_tokens = 0
        if usage:
            prompt_tokens = _safe_int(getattr(usage, "prompt_tokens", 0))
            completion_tokens = _safe_int(getattr(usage, "completion_tokens", 0))

        metadata: dict[str, Any] = {"shim": "openai", "auto_captured": True}

        # Capture tool calls if present
        tool_calls = _extract_openai_tool_calls(resp)
        if tool_calls:
            metadata["tool_calls"] = tool_calls
            metadata["tool_call_count"] = len(tool_calls)

        # Capture finish reason
        try:
            choices = getattr(resp, "choices", None)
            if choices and len(choices) > 0:
                finish_reason = getattr(choices[0], "finish_reason", None)
                if finish_reason:
                    metadata["finish_reason"] = finish_reason
        except Exception:
            pass

        # ML Data Collection: Extract system prompt and hyperparameters
        system_prompt = _extract_system_prompt_openai(kwargs)
        temperature = _safe_float(kwargs.get("temperature"))
        max_tokens = kwargs.get("max_tokens")

        emit_llm_call(
            model=str(model),
            provider="openai",
            prompt=None,
            completion=None,
            tokens_in=prompt_tokens,
            tokens_out=completion_tokens,
            latency_ms=elapsed_ms,
            metadata=metadata,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=_safe_int(max_tokens) if max_tokens is not None else None,
        )
    except Exception:
        pass

def _extract_anthropic_tool_use(resp: Any) -> list[dict[str, Any]] | None:
    """Extract tool_use blocks from Anthropic response."""
    try:
        content = getattr(resp, "content", None)
        if not content:
            return None

        tool_uses = []
        for block in content:
            block_type = getattr(block, "type", None)
            if block_type == "tool_use":
                tool_use_data = {
                    "id": getattr(block, "id", None),
                    "type": "tool_use",
                    "name": getattr(block, "name", None),
                    "input": getattr(block, "input", None),
                }
                tool_uses.append(tool_use_data)

        return tool_uses if tool_uses else None
    except Exception:
        return None

def _extract_anthropic_thinking(resp: Any) -> str | None:
    """Extract thinking/reasoning content from Anthropic response (extended thinking)."""
    try:
        content = getattr(resp, "content", None)
        if not content:
            return None

        thinking_parts = []
        for block in content:
            block_type = getattr(block, "type", None)
            if block_type == "thinking":
                thinking_text = getattr(block, "thinking", None)
                if thinking_text:
                    thinking_parts.append(thinking_text)

        return "\n".join(thinking_parts) if thinking_parts else None
    except Exception:
        return None

def _emit_anthropic_telemetry(resp: Any, kwargs: dict, elapsed_ms: float) -> None:
    """Extract and emit telemetry from Anthropic response.

    Captures standard token counts, cache tokens, tool_use blocks, and thinking content.
    """
    try:
        model = kwargs.get("model") or getattr(resp, "model", "anthropic")
        usage = getattr(resp, "usage", None)
        prompt_tokens = 0
        completion_tokens = 0
        cache_creation_tokens = 0
        cache_read_tokens = 0
        if usage:
            prompt_tokens = _safe_int(getattr(usage, "input_tokens", 0))
            completion_tokens = _safe_int(getattr(usage, "output_tokens", 0))
            # Anthropic prompt caching tokens
            cache_creation_tokens = _safe_int(
                getattr(usage, "cache_creation_input_tokens", 0)
            )
            cache_read_tokens = _safe_int(
                getattr(usage, "cache_read_input_tokens", 0)
            )

        metadata: dict[str, Any] = {"shim": "anthropic", "auto_captured": True}
        if cache_creation_tokens or cache_read_tokens:
            metadata["cache_creation_tokens"] = cache_creation_tokens
            metadata["cache_read_tokens"] = cache_read_tokens

        # Capture tool_use blocks if present
        tool_uses = _extract_anthropic_tool_use(resp)
        if tool_uses:
            metadata["tool_uses"] = tool_uses
            metadata["tool_use_count"] = len(tool_uses)

        # Capture thinking/reasoning content if present (extended thinking)
        thinking = _extract_anthropic_thinking(resp)
        if thinking:
            # Store truncated version in metadata to avoid huge payloads
            metadata["has_thinking"] = True
            metadata["thinking_length"] = len(thinking)
            # Only include first 500 chars of thinking for lightweight capture
            if len(thinking) <= 500:
                metadata["thinking_preview"] = thinking
            else:
                metadata["thinking_preview"] = thinking[:500] + "..."

        # Capture stop reason
        stop_reason = getattr(resp, "stop_reason", None)
        if stop_reason:
            metadata["stop_reason"] = stop_reason

        # ML Data Collection: Extract system prompt and hyperparameters
        system_prompt = _extract_system_prompt_anthropic(kwargs)
        temperature = _safe_float(kwargs.get("temperature"))
        max_tokens = kwargs.get("max_tokens")

        emit_llm_call(
            model=str(model),
            provider="anthropic",
            prompt=None,
            completion=None,
            tokens_in=prompt_tokens,
            tokens_out=completion_tokens,
            latency_ms=elapsed_ms,
            metadata=metadata,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=_safe_int(max_tokens) if max_tokens is not None else None,
        )
    except Exception:
        pass

class _OpenAIStreamWrapper:
    """Wraps OpenAI sync streaming response to capture telemetry."""

    def __init__(self, stream: Iterator[Any], kwargs: dict, start_time: float):
        self._stream = stream
        self._kwargs = kwargs
        self._start_time = start_time
        self._chunks: list[Any] = []
        self._model: str = kwargs.get("model", "openai")
        self._completion_tokens = 0
        self._prompt_tokens = 0
        # ML Data Collection
        self._system_prompt = _extract_system_prompt_openai(kwargs)
        self._temperature = _safe_float(kwargs.get("temperature"))
        self._max_tokens = kwargs.get("max_tokens")

    def __iter__(self) -> Iterator[Any]:
        return self

    def __next__(self) -> Any:
        try:
            chunk = next(self._stream)
            self._process_chunk(chunk)
            return chunk
        except StopIteration:
            self._emit_telemetry()
            raise

    def _process_chunk(self, chunk: Any) -> None:
        """Extract data from a streaming chunk."""
        self._chunks.append(chunk)
        # OpenAI streams model name in chunks
        model = getattr(chunk, "model", None)
        if model:
            self._model = model
        # Check for usage in chunk (new OpenAI API returns usage in final chunk)
        usage = getattr(chunk, "usage", None)
        if usage:
            self._prompt_tokens = _safe_int(getattr(usage, "prompt_tokens", 0))
            self._completion_tokens = _safe_int(getattr(usage, "completion_tokens", 0))

    def _emit_telemetry(self) -> None:
        """Emit telemetry after stream completes."""
        elapsed_ms = (time.perf_counter() - self._start_time) * 1000
        metadata: dict[str, Any] = {
            "shim": "openai",
            "auto_captured": True,
            "streaming": True,
            "chunk_count": len(self._chunks),
        }
        # Extract finish reason from last chunk
        if self._chunks:
            last_chunk = self._chunks[-1]
            choices = getattr(last_chunk, "choices", None)
            if choices and len(choices) > 0:
                finish_reason = getattr(choices[0], "finish_reason", None)
                if finish_reason:
                    metadata["finish_reason"] = finish_reason

        emit_llm_call(
            model=str(self._model),
            provider="openai",
            prompt=None,
            completion=None,
            tokens_in=self._prompt_tokens,
            tokens_out=self._completion_tokens,
            latency_ms=elapsed_ms,
            metadata=metadata,
            system_prompt=self._system_prompt,
            temperature=self._temperature,
            max_tokens=_safe_int(self._max_tokens) if self._max_tokens is not None else None,
        )

class _OpenAIAsyncStreamWrapper:
    """Wraps OpenAI async streaming response to capture telemetry."""

    def __init__(self, stream: AsyncIterator[Any], kwargs: dict, start_time: float):
        self._stream = stream
        self._kwargs = kwargs
        self._start_time = start_time
        self._chunks: list[Any] = []
        self._model: str = kwargs.get("model", "openai")
        self._completion_tokens = 0
        self._prompt_tokens = 0
        # ML Data Collection
        self._system_prompt = _extract_system_prompt_openai(kwargs)
        self._temperature = _safe_float(kwargs.get("temperature"))
        self._max_tokens = kwargs.get("max_tokens")

    def __aiter__(self) -> AsyncIterator[Any]:
        return self

    async def __anext__(self) -> Any:
        try:
            chunk = await self._stream.__anext__()
            self._process_chunk(chunk)
            return chunk
        except StopAsyncIteration:
            self._emit_telemetry()
            raise

    def _process_chunk(self, chunk: Any) -> None:
        """Extract data from a streaming chunk."""
        self._chunks.append(chunk)
        model = getattr(chunk, "model", None)
        if model:
            self._model = model
        usage = getattr(chunk, "usage", None)
        if usage:
            self._prompt_tokens = _safe_int(getattr(usage, "prompt_tokens", 0))
            self._completion_tokens = _safe_int(getattr(usage, "completion_tokens", 0))

    def _emit_telemetry(self) -> None:
        """Emit telemetry after stream completes."""
        elapsed_ms = (time.perf_counter() - self._start_time) * 1000
        metadata: dict[str, Any] = {
            "shim": "openai",
            "auto_captured": True,
            "streaming": True,
            "chunk_count": len(self._chunks),
        }
        if self._chunks:
            last_chunk = self._chunks[-1]
            choices = getattr(last_chunk, "choices", None)
            if choices and len(choices) > 0:
                finish_reason = getattr(choices[0], "finish_reason", None)
                if finish_reason:
                    metadata["finish_reason"] = finish_reason

        emit_llm_call(
            model=str(self._model),
            provider="openai",
            prompt=None,
            completion=None,
            tokens_in=self._prompt_tokens,
            tokens_out=self._completion_tokens,
            latency_ms=elapsed_ms,
            metadata=metadata,
            system_prompt=self._system_prompt,
            temperature=self._temperature,
            max_tokens=_safe_int(self._max_tokens) if self._max_tokens is not None else None,
        )

class _AnthropicStreamWrapper:
    """Wraps Anthropic sync streaming response to capture telemetry."""

    def __init__(self, stream: Iterator[Any], kwargs: dict, start_time: float):
        self._stream = stream
        self._kwargs = kwargs
        self._start_time = start_time
        self._chunks: list[Any] = []
        self._model: str = kwargs.get("model", "anthropic")
        self._input_tokens = 0
        self._output_tokens = 0
        # ML Data Collection
        self._system_prompt = _extract_system_prompt_anthropic(kwargs)
        self._temperature = _safe_float(kwargs.get("temperature"))
        self._max_tokens = kwargs.get("max_tokens")

    def __iter__(self) -> Iterator[Any]:
        return self

    def __next__(self) -> Any:
        try:
            chunk = next(self._stream)
            self._process_chunk(chunk)
            return chunk
        except StopIteration:
            self._emit_telemetry()
            raise

    def _process_chunk(self, chunk: Any) -> None:
        """Extract data from a streaming chunk."""
        self._chunks.append(chunk)
        # Anthropic sends message_start with model and usage
        chunk_type = getattr(chunk, "type", None)
        if chunk_type == "message_start":
            message = getattr(chunk, "message", None)
            if message:
                model = getattr(message, "model", None)
                if model:
                    self._model = model
                usage = getattr(message, "usage", None)
                if usage:
                    self._input_tokens = _safe_int(getattr(usage, "input_tokens", 0))
        elif chunk_type == "message_delta":
            usage = getattr(chunk, "usage", None)
            if usage:
                self._output_tokens = _safe_int(getattr(usage, "output_tokens", 0))

    def _emit_telemetry(self) -> None:
        """Emit telemetry after stream completes."""
        elapsed_ms = (time.perf_counter() - self._start_time) * 1000
        metadata: dict[str, Any] = {
            "shim": "anthropic",
            "auto_captured": True,
            "streaming": True,
            "chunk_count": len(self._chunks),
        }
        # Extract stop reason from message_delta
        for chunk in reversed(self._chunks):
            if getattr(chunk, "type", None) == "message_delta":
                delta = getattr(chunk, "delta", None)
                if delta:
                    stop_reason = getattr(delta, "stop_reason", None)
                    if stop_reason:
                        metadata["stop_reason"] = stop_reason
                        break

        emit_llm_call(
            model=str(self._model),
            provider="anthropic",
            prompt=None,
            completion=None,
            tokens_in=self._input_tokens,
            tokens_out=self._output_tokens,
            latency_ms=elapsed_ms,
            metadata=metadata,
            system_prompt=self._system_prompt,
            temperature=self._temperature,
            max_tokens=_safe_int(self._max_tokens) if self._max_tokens is not None else None,
        )

class _AnthropicAsyncStreamWrapper:
    """Wraps Anthropic async streaming response to capture telemetry."""

    def __init__(self, stream: AsyncIterator[Any], kwargs: dict, start_time: float):
        self._stream = stream
        self._kwargs = kwargs
        self._start_time = start_time
        self._chunks: list[Any] = []
        self._model: str = kwargs.get("model", "anthropic")
        self._input_tokens = 0
        self._output_tokens = 0
        # ML Data Collection
        self._system_prompt = _extract_system_prompt_anthropic(kwargs)
        self._temperature = _safe_float(kwargs.get("temperature"))
        self._max_tokens = kwargs.get("max_tokens")

    def __aiter__(self) -> AsyncIterator[Any]:
        return self

    async def __anext__(self) -> Any:
        try:
            chunk = await self._stream.__anext__()
            self._process_chunk(chunk)
            return chunk
        except StopAsyncIteration:
            self._emit_telemetry()
            raise

    def _process_chunk(self, chunk: Any) -> None:
        """Extract data from a streaming chunk."""
        self._chunks.append(chunk)
        chunk_type = getattr(chunk, "type", None)
        if chunk_type == "message_start":
            message = getattr(chunk, "message", None)
            if message:
                model = getattr(message, "model", None)
                if model:
                    self._model = model
                usage = getattr(message, "usage", None)
                if usage:
                    self._input_tokens = _safe_int(getattr(usage, "input_tokens", 0))
        elif chunk_type == "message_delta":
            usage = getattr(chunk, "usage", None)
            if usage:
                self._output_tokens = _safe_int(getattr(usage, "output_tokens", 0))

    def _emit_telemetry(self) -> None:
        """Emit telemetry after stream completes."""
        elapsed_ms = (time.perf_counter() - self._start_time) * 1000
        metadata: dict[str, Any] = {
            "shim": "anthropic",
            "auto_captured": True,
            "streaming": True,
            "chunk_count": len(self._chunks),
        }
        for chunk in reversed(self._chunks):
            if getattr(chunk, "type", None) == "message_delta":
                delta = getattr(chunk, "delta", None)
                if delta:
                    stop_reason = getattr(delta, "stop_reason", None)
                    if stop_reason:
                        metadata["stop_reason"] = stop_reason
                        break

        emit_llm_call(
            model=str(self._model),
            provider="anthropic",
            prompt=None,
            completion=None,
            tokens_in=self._input_tokens,
            tokens_out=self._output_tokens,
            latency_ms=elapsed_ms,
            metadata=metadata,
            system_prompt=self._system_prompt,
            temperature=self._temperature,
            max_tokens=_safe_int(self._max_tokens) if self._max_tokens is not None else None,
        )

def _patch_openai_sync() -> None:
    """Patch sync OpenAI SDK to auto-emit telemetry (including streaming)."""
    try:
        from openai.resources.chat.completions import Completions  # type: ignore
    except Exception:
        return

    if getattr(Completions, "__khaos_telemetry_wrapped__", False):
        return

    original_create = getattr(Completions, "create", None)
    if original_create is None:
        return

    def wrapped_create(self: Any, *args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()
        resp = original_create(self, *args, **kwargs)
        # Check if streaming
        if kwargs.get("stream"):
            return _OpenAIStreamWrapper(resp, kwargs, start)
        elapsed_ms = (time.perf_counter() - start) * 1000
        _emit_openai_telemetry(resp, kwargs, elapsed_ms)
        return resp

    Completions.create = wrapped_create  # type: ignore
    setattr(Completions, "__khaos_telemetry_wrapped__", True)

def _patch_openai_async() -> None:
    """Patch async OpenAI SDK to auto-emit telemetry (including streaming)."""
    try:
        from openai.resources.chat.completions import AsyncCompletions  # type: ignore
    except Exception:
        return

    if getattr(AsyncCompletions, "__khaos_telemetry_wrapped__", False):
        return

    original_create = getattr(AsyncCompletions, "create", None)
    if original_create is None:
        return

    async def wrapped_create(self: Any, *args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()
        resp = await original_create(self, *args, **kwargs)
        # Check if streaming
        if kwargs.get("stream"):
            return _OpenAIAsyncStreamWrapper(resp, kwargs, start)
        elapsed_ms = (time.perf_counter() - start) * 1000
        _emit_openai_telemetry(resp, kwargs, elapsed_ms)
        return resp

    AsyncCompletions.create = wrapped_create  # type: ignore
    setattr(AsyncCompletions, "__khaos_telemetry_wrapped__", True)

def _patch_anthropic_sync() -> None:
    """Patch sync Anthropic SDK to auto-emit telemetry (including streaming)."""
    try:
        from anthropic.resources.messages import Messages  # type: ignore
    except Exception:
        return

    if getattr(Messages, "__khaos_telemetry_wrapped__", False):
        return

    original_create = getattr(Messages, "create", None)
    if original_create is None:
        return

    def wrapped_create(self: Any, *args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()
        resp = original_create(self, *args, **kwargs)
        # Check if streaming
        if kwargs.get("stream"):
            return _AnthropicStreamWrapper(resp, kwargs, start)
        elapsed_ms = (time.perf_counter() - start) * 1000
        _emit_anthropic_telemetry(resp, kwargs, elapsed_ms)
        return resp

    Messages.create = wrapped_create  # type: ignore
    setattr(Messages, "__khaos_telemetry_wrapped__", True)

    # Also patch the stream method if it exists
    original_stream = getattr(Messages, "stream", None)
    if original_stream and not getattr(Messages, "__khaos_stream_wrapped__", False):
        def wrapped_stream(self: Any, *args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            resp = original_stream(self, *args, **kwargs)
            return _AnthropicStreamWrapper(resp, kwargs, start)

        Messages.stream = wrapped_stream  # type: ignore
        setattr(Messages, "__khaos_stream_wrapped__", True)

def _patch_anthropic_async() -> None:
    """Patch async Anthropic SDK to auto-emit telemetry (including streaming)."""
    try:
        from anthropic.resources.messages import AsyncMessages  # type: ignore
    except Exception:
        return

    if getattr(AsyncMessages, "__khaos_telemetry_wrapped__", False):
        return

    original_create = getattr(AsyncMessages, "create", None)
    if original_create is None:
        return

    async def wrapped_create(self: Any, *args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()
        resp = await original_create(self, *args, **kwargs)
        # Check if streaming
        if kwargs.get("stream"):
            return _AnthropicAsyncStreamWrapper(resp, kwargs, start)
        elapsed_ms = (time.perf_counter() - start) * 1000
        _emit_anthropic_telemetry(resp, kwargs, elapsed_ms)
        return resp

    AsyncMessages.create = wrapped_create  # type: ignore
    setattr(AsyncMessages, "__khaos_telemetry_wrapped__", True)

    # Also patch the stream method if it exists
    original_stream = getattr(AsyncMessages, "stream", None)
    if original_stream and not getattr(AsyncMessages, "__khaos_stream_wrapped__", False):
        async def wrapped_stream(self: Any, *args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            resp = await original_stream(self, *args, **kwargs)
            return _AnthropicAsyncStreamWrapper(resp, kwargs, start)

        AsyncMessages.stream = wrapped_stream  # type: ignore
        setattr(AsyncMessages, "__khaos_stream_wrapped__", True)

# ---------------------------------------------------------------------------
# Google Generative AI (Gemini) Shim
# ---------------------------------------------------------------------------

def _emit_google_genai_telemetry(resp: Any, kwargs: dict, elapsed_ms: float) -> None:
    """Extract and emit telemetry from Google Generative AI response."""
    try:
        model = kwargs.get("model_name", "gemini")
        prompt_tokens = 0
        completion_tokens = 0

        # Try to get usage metadata from response
        usage_metadata = getattr(resp, "usage_metadata", None)
        if usage_metadata:
            prompt_tokens = _safe_int(getattr(usage_metadata, "prompt_token_count", 0))
            completion_tokens = _safe_int(getattr(usage_metadata, "candidates_token_count", 0))

        metadata: dict[str, Any] = {"shim": "google-generativeai", "auto_captured": True}

        # Capture finish reason if available
        candidates = getattr(resp, "candidates", None)
        if candidates and len(candidates) > 0:
            finish_reason = getattr(candidates[0], "finish_reason", None)
            if finish_reason:
                metadata["finish_reason"] = str(finish_reason)

        emit_llm_call(
            model=str(model),
            provider="google",
            prompt=None,
            completion=None,
            tokens_in=prompt_tokens,
            tokens_out=completion_tokens,
            latency_ms=elapsed_ms,
            metadata=metadata,
        )
    except Exception:
        pass

class _GoogleGenAIStreamWrapper:
    """Wraps Google Generative AI streaming response to capture telemetry."""

    def __init__(self, stream: Iterator[Any], model_name: str, start_time: float):
        self._stream = stream
        self._model_name = model_name
        self._start_time = start_time
        self._chunks: list[Any] = []
        self._prompt_tokens = 0
        self._completion_tokens = 0

    def __iter__(self) -> Iterator[Any]:
        return self

    def __next__(self) -> Any:
        try:
            chunk = next(self._stream)
            self._process_chunk(chunk)
            return chunk
        except StopIteration:
            self._emit_telemetry()
            raise

    def _process_chunk(self, chunk: Any) -> None:
        """Extract data from a streaming chunk."""
        self._chunks.append(chunk)
        # Try to get usage metadata from chunk
        usage_metadata = getattr(chunk, "usage_metadata", None)
        if usage_metadata:
            self._prompt_tokens = _safe_int(getattr(usage_metadata, "prompt_token_count", 0))
            self._completion_tokens = _safe_int(getattr(usage_metadata, "candidates_token_count", 0))

    def _emit_telemetry(self) -> None:
        """Emit telemetry after stream completes."""
        elapsed_ms = (time.perf_counter() - self._start_time) * 1000
        metadata: dict[str, Any] = {
            "shim": "google-generativeai",
            "auto_captured": True,
            "streaming": True,
            "chunk_count": len(self._chunks),
        }

        emit_llm_call(
            model=self._model_name,
            provider="google",
            prompt=None,
            completion=None,
            tokens_in=self._prompt_tokens,
            tokens_out=self._completion_tokens,
            latency_ms=elapsed_ms,
            metadata=metadata,
        )

class _GoogleGenAIAsyncStreamWrapper:
    """Wraps Google Generative AI async streaming response to capture telemetry."""

    def __init__(self, stream: AsyncIterator[Any], model_name: str, start_time: float):
        self._stream = stream
        self._model_name = model_name
        self._start_time = start_time
        self._chunks: list[Any] = []
        self._prompt_tokens = 0
        self._completion_tokens = 0

    def __aiter__(self) -> AsyncIterator[Any]:
        return self

    async def __anext__(self) -> Any:
        try:
            chunk = await self._stream.__anext__()
            self._process_chunk(chunk)
            return chunk
        except StopAsyncIteration:
            self._emit_telemetry()
            raise

    def _process_chunk(self, chunk: Any) -> None:
        """Extract data from a streaming chunk."""
        self._chunks.append(chunk)
        usage_metadata = getattr(chunk, "usage_metadata", None)
        if usage_metadata:
            self._prompt_tokens = _safe_int(getattr(usage_metadata, "prompt_token_count", 0))
            self._completion_tokens = _safe_int(getattr(usage_metadata, "candidates_token_count", 0))

    def _emit_telemetry(self) -> None:
        """Emit telemetry after stream completes."""
        elapsed_ms = (time.perf_counter() - self._start_time) * 1000
        metadata: dict[str, Any] = {
            "shim": "google-generativeai",
            "auto_captured": True,
            "streaming": True,
            "chunk_count": len(self._chunks),
        }

        emit_llm_call(
            model=self._model_name,
            provider="google",
            prompt=None,
            completion=None,
            tokens_in=self._prompt_tokens,
            tokens_out=self._completion_tokens,
            latency_ms=elapsed_ms,
            metadata=metadata,
        )

def _patch_google_genai() -> None:
    """Patch Google Generative AI SDK to auto-emit telemetry."""
    try:
        from google.generativeai import GenerativeModel
    except Exception:
        return

    if getattr(GenerativeModel, "__khaos_telemetry_wrapped__", False):
        return

    # Patch generate_content (sync)
    original_generate = getattr(GenerativeModel, "generate_content", None)
    if original_generate:
        def wrapped_generate(self: Any, *args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            model_name = getattr(self, "model_name", "gemini")
            resp = original_generate(self, *args, **kwargs)
            # Check if streaming
            if kwargs.get("stream"):
                return _GoogleGenAIStreamWrapper(resp, model_name, start)
            elapsed_ms = (time.perf_counter() - start) * 1000
            _emit_google_genai_telemetry(resp, {"model_name": model_name}, elapsed_ms)
            return resp

        GenerativeModel.generate_content = wrapped_generate  # type: ignore

    # Patch generate_content_async (async)
    original_generate_async = getattr(GenerativeModel, "generate_content_async", None)
    if original_generate_async:
        async def wrapped_generate_async(self: Any, *args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            model_name = getattr(self, "model_name", "gemini")
            resp = await original_generate_async(self, *args, **kwargs)
            # Check if streaming
            if kwargs.get("stream"):
                return _GoogleGenAIAsyncStreamWrapper(resp, model_name, start)
            elapsed_ms = (time.perf_counter() - start) * 1000
            _emit_google_genai_telemetry(resp, {"model_name": model_name}, elapsed_ms)
            return resp

        GenerativeModel.generate_content_async = wrapped_generate_async  # type: ignore

    setattr(GenerativeModel, "__khaos_telemetry_wrapped__", True)

# ---------------------------------------------------------------------------
# Cohere Shim
# ---------------------------------------------------------------------------

def _emit_cohere_telemetry(resp: Any, kwargs: dict, elapsed_ms: float) -> None:
    """Extract and emit telemetry from Cohere response."""
    try:
        model = kwargs.get("model", "cohere")
        prompt_tokens = 0
        completion_tokens = 0

        # Cohere v2 API uses meta.tokens
        meta = getattr(resp, "meta", None)
        if meta:
            tokens = getattr(meta, "tokens", None) or getattr(meta, "billed_units", None)
            if tokens:
                prompt_tokens = _safe_int(getattr(tokens, "input_tokens", 0))
                completion_tokens = _safe_int(getattr(tokens, "output_tokens", 0))

        metadata: dict[str, Any] = {"shim": "cohere", "auto_captured": True}

        # Capture finish reason
        finish_reason = getattr(resp, "finish_reason", None)
        if finish_reason:
            metadata["finish_reason"] = str(finish_reason)

        emit_llm_call(
            model=str(model),
            provider="cohere",
            prompt=None,
            completion=None,
            tokens_in=prompt_tokens,
            tokens_out=completion_tokens,
            latency_ms=elapsed_ms,
            metadata=metadata,
        )
    except Exception:
        pass

class _CohereStreamWrapper:
    """Wraps Cohere streaming response to capture telemetry."""

    def __init__(self, stream: Iterator[Any], kwargs: dict, start_time: float):
        self._stream = stream
        self._kwargs = kwargs
        self._start_time = start_time
        self._chunks: list[Any] = []
        self._model: str = kwargs.get("model", "cohere")
        self._prompt_tokens = 0
        self._completion_tokens = 0

    def __iter__(self) -> Iterator[Any]:
        return self

    def __next__(self) -> Any:
        try:
            chunk = next(self._stream)
            self._process_chunk(chunk)
            return chunk
        except StopIteration:
            self._emit_telemetry()
            raise

    def _process_chunk(self, chunk: Any) -> None:
        """Extract data from a streaming chunk."""
        self._chunks.append(chunk)
        # Cohere sends usage in the final chunk
        event_type = getattr(chunk, "event_type", None)
        if event_type == "stream-end":
            response = getattr(chunk, "response", None)
            if response:
                meta = getattr(response, "meta", None)
                if meta:
                    tokens = getattr(meta, "tokens", None) or getattr(meta, "billed_units", None)
                    if tokens:
                        self._prompt_tokens = _safe_int(getattr(tokens, "input_tokens", 0))
                        self._completion_tokens = _safe_int(getattr(tokens, "output_tokens", 0))

    def _emit_telemetry(self) -> None:
        """Emit telemetry after stream completes."""
        elapsed_ms = (time.perf_counter() - self._start_time) * 1000
        metadata: dict[str, Any] = {
            "shim": "cohere",
            "auto_captured": True,
            "streaming": True,
            "chunk_count": len(self._chunks),
        }

        emit_llm_call(
            model=self._model,
            provider="cohere",
            prompt=None,
            completion=None,
            tokens_in=self._prompt_tokens,
            tokens_out=self._completion_tokens,
            latency_ms=elapsed_ms,
            metadata=metadata,
        )

def _patch_cohere() -> None:
    """Patch Cohere SDK to auto-emit telemetry."""
    try:
        import cohere
        Client = getattr(cohere, "Client", None) or getattr(cohere, "ClientV2", None)
        if Client is None:
            return
    except Exception:
        return

    if getattr(Client, "__khaos_telemetry_wrapped__", False):
        return

    # Patch chat method (v2 API)
    original_chat = getattr(Client, "chat", None)
    if original_chat:
        def wrapped_chat(self: Any, *args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            resp = original_chat(self, *args, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000
            _emit_cohere_telemetry(resp, kwargs, elapsed_ms)
            return resp

        Client.chat = wrapped_chat  # type: ignore

    # Patch chat_stream method
    original_chat_stream = getattr(Client, "chat_stream", None)
    if original_chat_stream:
        def wrapped_chat_stream(self: Any, *args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            resp = original_chat_stream(self, *args, **kwargs)
            return _CohereStreamWrapper(resp, kwargs, start)

        Client.chat_stream = wrapped_chat_stream  # type: ignore

    setattr(Client, "__khaos_telemetry_wrapped__", True)

# ---------------------------------------------------------------------------
# Mistral Shim
# ---------------------------------------------------------------------------

def _emit_mistral_telemetry(resp: Any, kwargs: dict, elapsed_ms: float) -> None:
    """Extract and emit telemetry from Mistral response."""
    try:
        model = kwargs.get("model") or getattr(resp, "model", "mistral")
        prompt_tokens = 0
        completion_tokens = 0

        usage = getattr(resp, "usage", None)
        if usage:
            prompt_tokens = _safe_int(getattr(usage, "prompt_tokens", 0))
            completion_tokens = _safe_int(getattr(usage, "completion_tokens", 0))

        metadata: dict[str, Any] = {"shim": "mistral", "auto_captured": True}

        # Capture finish reason
        choices = getattr(resp, "choices", None)
        if choices and len(choices) > 0:
            finish_reason = getattr(choices[0], "finish_reason", None)
            if finish_reason:
                metadata["finish_reason"] = str(finish_reason)

        emit_llm_call(
            model=str(model),
            provider="mistral",
            prompt=None,
            completion=None,
            tokens_in=prompt_tokens,
            tokens_out=completion_tokens,
            latency_ms=elapsed_ms,
            metadata=metadata,
        )
    except Exception:
        pass

class _MistralStreamWrapper:
    """Wraps Mistral streaming response to capture telemetry."""

    def __init__(self, stream: Iterator[Any], kwargs: dict, start_time: float):
        self._stream = stream
        self._kwargs = kwargs
        self._start_time = start_time
        self._chunks: list[Any] = []
        self._model: str = kwargs.get("model", "mistral")
        self._prompt_tokens = 0
        self._completion_tokens = 0

    def __iter__(self) -> Iterator[Any]:
        return self

    def __next__(self) -> Any:
        try:
            chunk = next(self._stream)
            self._process_chunk(chunk)
            return chunk
        except StopIteration:
            self._emit_telemetry()
            raise

    def _process_chunk(self, chunk: Any) -> None:
        """Extract data from a streaming chunk."""
        self._chunks.append(chunk)
        # Get model from chunk
        model = getattr(chunk, "model", None)
        if model:
            self._model = model
        # Usage in final chunk
        usage = getattr(chunk, "usage", None)
        if usage:
            self._prompt_tokens = _safe_int(getattr(usage, "prompt_tokens", 0))
            self._completion_tokens = _safe_int(getattr(usage, "completion_tokens", 0))

    def _emit_telemetry(self) -> None:
        """Emit telemetry after stream completes."""
        elapsed_ms = (time.perf_counter() - self._start_time) * 1000
        metadata: dict[str, Any] = {
            "shim": "mistral",
            "auto_captured": True,
            "streaming": True,
            "chunk_count": len(self._chunks),
        }

        emit_llm_call(
            model=self._model,
            provider="mistral",
            prompt=None,
            completion=None,
            tokens_in=self._prompt_tokens,
            tokens_out=self._completion_tokens,
            latency_ms=elapsed_ms,
            metadata=metadata,
        )

class _MistralAsyncStreamWrapper:
    """Wraps Mistral async streaming response to capture telemetry."""

    def __init__(self, stream: AsyncIterator[Any], kwargs: dict, start_time: float):
        self._stream = stream
        self._kwargs = kwargs
        self._start_time = start_time
        self._chunks: list[Any] = []
        self._model: str = kwargs.get("model", "mistral")
        self._prompt_tokens = 0
        self._completion_tokens = 0

    def __aiter__(self) -> AsyncIterator[Any]:
        return self

    async def __anext__(self) -> Any:
        try:
            chunk = await self._stream.__anext__()
            self._process_chunk(chunk)
            return chunk
        except StopAsyncIteration:
            self._emit_telemetry()
            raise

    def _process_chunk(self, chunk: Any) -> None:
        """Extract data from a streaming chunk."""
        self._chunks.append(chunk)
        model = getattr(chunk, "model", None)
        if model:
            self._model = model
        usage = getattr(chunk, "usage", None)
        if usage:
            self._prompt_tokens = _safe_int(getattr(usage, "prompt_tokens", 0))
            self._completion_tokens = _safe_int(getattr(usage, "completion_tokens", 0))

    def _emit_telemetry(self) -> None:
        """Emit telemetry after stream completes."""
        elapsed_ms = (time.perf_counter() - self._start_time) * 1000
        metadata: dict[str, Any] = {
            "shim": "mistral",
            "auto_captured": True,
            "streaming": True,
            "chunk_count": len(self._chunks),
        }

        emit_llm_call(
            model=self._model,
            provider="mistral",
            prompt=None,
            completion=None,
            tokens_in=self._prompt_tokens,
            tokens_out=self._completion_tokens,
            latency_ms=elapsed_ms,
            metadata=metadata,
        )

def _patch_mistral_sync() -> None:
    """Patch sync Mistral SDK to auto-emit telemetry."""
    try:
        from mistralai import Mistral
    except Exception:
        logger.debug("Mistral SDK not available for sync telemetry patching", exc_info=True)
        return

    if getattr(Mistral, "__khaos_telemetry_wrapped__", False):
        return

    # The Mistral SDK uses client.chat.complete() pattern
    # We need to patch the chat.complete method
    original_init = getattr(Mistral, "__init__", None)
    if not original_init:
        return

    def patched_init(self: Any, *args: Any, **kwargs: Any) -> None:
        original_init(self, *args, **kwargs)
        # Patch the chat completions after init
        chat = getattr(self, "chat", None)
        if chat and not getattr(chat, "__khaos_patched__", False):
            original_complete = getattr(chat, "complete", None)
            if original_complete:
                def wrapped_complete(*cargs: Any, **ckwargs: Any) -> Any:
                    start = time.perf_counter()
                    resp = original_complete(*cargs, **ckwargs)
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    _emit_mistral_telemetry(resp, ckwargs, elapsed_ms)
                    return resp
                chat.complete = wrapped_complete

            original_stream = getattr(chat, "stream", None)
            if original_stream:
                def wrapped_stream(*cargs: Any, **ckwargs: Any) -> Any:
                    start = time.perf_counter()
                    resp = original_stream(*cargs, **ckwargs)
                    return _MistralStreamWrapper(resp, ckwargs, start)
                chat.stream = wrapped_stream

            setattr(chat, "__khaos_patched__", True)

    Mistral.__init__ = patched_init  # type: ignore
    setattr(Mistral, "__khaos_telemetry_wrapped__", True)

def _patch_mistral_async() -> None:
    """Patch async Mistral SDK to auto-emit telemetry."""
    try:
        from mistralai import Mistral
    except Exception:
        logger.debug("Mistral SDK not available for async telemetry patching", exc_info=True)
        return

    # Async methods are on the same client in mistralai
    # The async patching is handled in the sync patch via the chat.complete_async method
    # But we need to patch complete_async separately
    original_init = getattr(Mistral, "__init__", None)
    if not original_init:
        return

    # Check if already patched for async
    if getattr(Mistral, "__khaos_async_wrapped__", False):
        return

    _original_patched_init = Mistral.__init__

    def async_patched_init(self: Any, *args: Any, **kwargs: Any) -> None:
        _original_patched_init(self, *args, **kwargs)
        # Patch async methods
        chat = getattr(self, "chat", None)
        if chat and not getattr(chat, "__khaos_async_patched__", False):
            original_complete_async = getattr(chat, "complete_async", None)
            if original_complete_async:
                async def wrapped_complete_async(*cargs: Any, **ckwargs: Any) -> Any:
                    start = time.perf_counter()
                    resp = await original_complete_async(*cargs, **ckwargs)
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    _emit_mistral_telemetry(resp, ckwargs, elapsed_ms)
                    return resp
                chat.complete_async = wrapped_complete_async

            original_stream_async = getattr(chat, "stream_async", None)
            if original_stream_async:
                async def wrapped_stream_async(*cargs: Any, **ckwargs: Any) -> Any:
                    start = time.perf_counter()
                    resp = await original_stream_async(*cargs, **ckwargs)
                    return _MistralAsyncStreamWrapper(resp, ckwargs, start)
                chat.stream_async = wrapped_stream_async

            setattr(chat, "__khaos_async_patched__", True)

    Mistral.__init__ = async_patched_init  # type: ignore
    setattr(Mistral, "__khaos_async_wrapped__", True)

def enable_llm_shim(check_versions: bool = True) -> dict[str, SDKInfo]:
    """Enable auto-telemetry for supported LLM SDKs if installed.

    This function patches the following SDKs to automatically emit LLM call telemetry:
    - OpenAI (1.0.0+)
    - Anthropic (0.18.0+)
    - Google Generative AI / Gemini (0.3.0+)
    - Cohere (4.0.0+)
    - Mistral (0.1.0+)

    It is idempotent and safe to call multiple times.
    Patches both sync and async variants of the SDK methods.

    Called automatically by auto_wrap_shim.py when Khaos runs an agent.

    Args:
        check_versions: If True, check SDK versions and warn if incompatible

    Returns:
        Dict of SDK name -> SDKInfo with installation and patch status
    """
    # Check compatibility first
    if check_versions:
        check_compatibility(warn=True)

    # OpenAI
    _patch_openai_sync()
    _patch_openai_async()
    # Anthropic
    _patch_anthropic_sync()
    _patch_anthropic_async()
    # Google Generative AI (Gemini)
    _patch_google_genai()
    # Cohere
    _patch_cohere()
    # Mistral
    _patch_mistral_sync()
    _patch_mistral_async()

    # Return status
    return get_sdk_compatibility()

__all__ = [
    "enable_llm_shim",
    "SDKInfo",
    "get_sdk_compatibility",
    "get_openai_info",
    "get_anthropic_info",
    "get_google_genai_info",
    "get_cohere_info",
    "get_mistral_info",
    "check_compatibility",
    "MIN_OPENAI_VERSION",
    "MIN_ANTHROPIC_VERSION",
    "MIN_GOOGLE_GENAI_VERSION",
    "MIN_COHERE_VERSION",
    "MIN_MISTRAL_VERSION",
]
