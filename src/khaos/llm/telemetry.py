"""LLM telemetry helpers with comprehensive PII handling."""

from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Iterator

from .costs import estimate_cost, PricingNotFound, load_pricing_overrides

_PRICING_CACHE: dict[str, dict[str, tuple[float, float]]] | None = None
_PRICING_ENV_VALUE: str | None = None

# Import comprehensive PII detection
try:
    from khaos.pii import contains_pii as _pii_contains, mask_pii as _pii_mask, PIICategory
    _PII_AVAILABLE = True
except ImportError:
    _PII_AVAILABLE = False
    PIICategory = None  # type: ignore

    # Fallback to basic patterns if pii module not available
    import re
    _FALLBACK_PATTERNS = {
        "EMAIL": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        "PHONE": re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "SSN": re.compile(r"\b\d{3}-?\d{2}-?\d{4}\b"),
        "API_KEY": re.compile(r"sk-[A-Za-z0-9]{20,}"),
        "CREDIT_CARD": re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
    }

    def _pii_contains(text: str, categories=None) -> bool:
        return any(p.search(text) for p in _FALLBACK_PATTERNS.values())

    def _pii_mask(text: str, categories=None, mask_style: str = "label") -> str:
        result = text
        for label, pattern in _FALLBACK_PATTERNS.items():
            result = pattern.sub(f"<<{label}>>", result)
        return result

def emit_llm_call(
    *,
    model: str,
    provider: str,
    prompt: str | None = None,
    completion: str | None = None,
    tokens_in: int | None = None,
    tokens_out: int | None = None,
    cached_tokens: int | None = None,
    cache_read_tokens: int | None = None,
    cache_creation_tokens: int | None = None,
    cost_usd: float | None = None,
    latency_ms: float | None = None,
    metadata: dict[str, Any] | None = None,
    # ML Data Collection fields
    system_prompt: str | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
) -> None:
    """Record a single LLM call event if telemetry is enabled.

    Cache-aware token tracking:
    - cached_tokens: OpenAI-style cached prompt tokens (50% discount)
    - cache_read_tokens: Anthropic cache read tokens (90% discount)
    - cache_creation_tokens: Anthropic cache write tokens (25% premium)

    ML Data Collection fields:
    - system_prompt: The system instruction sent to the LLM
    - temperature: Sampling temperature used for generation
    - max_tokens: Maximum tokens limit for the response
    """

    event_file = os.environ.get("KHAOS_LLM_EVENT_FILE")
    if not event_file:
        return

    # ML DATA COLLECTION: Default to "mask" mode for ML-ready data collection.
    # This enables training ML models while still protecting sensitive PII.
    # Valid modes: "mask" (default, replaces PII with labels), "redact" (removes content), "raw" (full content)
    # Set KHAOS_LLM_PII_MODE=redact for maximum security if ML training is not needed.
    mode = (os.environ.get("KHAOS_LLM_PII_MODE") or "mask").strip().lower()
    if mode not in ("raw", "redact", "mask"):
        mode = "mask"  # Fail-safe to ML-ready option with PII protection
    sanitized_prompt, prompt_pii = _sanitize_content(prompt, mode)
    sanitized_completion, completion_pii = _sanitize_content(completion, mode)
    sanitized_system_prompt, system_prompt_pii = _sanitize_content(system_prompt, mode)

    overrides = _get_pricing_overrides()
    prompt_tokens = int(tokens_in or 0)
    completion_tokens = int(tokens_out or 0)
    cached = int(cached_tokens or 0)
    cache_read = int(cache_read_tokens or 0)
    cache_write = int(cache_creation_tokens or 0)

    prompt_cost_est = completion_cost_est = None
    estimated_total = None
    try:
        estimate = estimate_cost(
            provider=provider,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cached_tokens=cached,
            cache_read_tokens=cache_read,
            cache_creation_tokens=cache_write,
            pricing_overrides=overrides or None,
        )
        estimated_total = estimate.total_cost_usd
        prompt_cost_est = estimate.prompt_cost_usd
        completion_cost_est = estimate.completion_cost_usd
    except PricingNotFound:
        estimated_total = None

    total_cost = cost_usd if cost_usd is not None else (estimated_total or 0.0)

    # Build token breakdown including cache information
    tokens_data: dict[str, Any] = {
        "prompt": prompt_tokens,
        "completion": completion_tokens,
    }
    # Add cache breakdown if any caching occurred
    if cached > 0:
        tokens_data["cached"] = cached
        tokens_data["uncached"] = max(0, prompt_tokens - cached)
    if cache_read > 0:
        tokens_data["cache_read"] = cache_read
    if cache_write > 0:
        tokens_data["cache_creation"] = cache_write

    # Build content dict with ML data collection fields
    content_data: dict[str, Any] = {
        "prompt": sanitized_prompt,
        "completion": sanitized_completion,
        "mode": mode,
    }
    # Add system prompt if provided (for ML training)
    if sanitized_system_prompt is not None:
        content_data["system_prompt"] = sanitized_system_prompt

    payload = {
        "model": model,
        "provider": provider,
        "tokens": tokens_data,
        "cost_usd": _round_cost(total_cost),
        "latency_ms": float(latency_ms or 0.0),
        "content": content_data,
        "metadata": metadata or {},
    }

    # Add ML hyperparameters if provided
    if temperature is not None:
        payload["metadata"]["temperature"] = temperature
    if max_tokens is not None:
        payload["metadata"]["max_tokens"] = max_tokens
    if prompt_cost_est is None:
        prompt_cost_est = 0.0
    if completion_cost_est is None:
        completion_cost_est = 0.0
    payload["cost_prompt_usd"] = _round_cost(prompt_cost_est)
    payload["cost_completion_usd"] = _round_cost(completion_cost_est)

    meta = {
        "pii_detected": prompt_pii or completion_pii or system_prompt_pii,
    }

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": "llm.call",
        "payload": payload,
        "meta": meta,
    }

    _append_event(Path(event_file), entry)

@dataclass
class _Observation:
    model: str
    provider: str
    metadata: dict[str, Any] = field(default_factory=dict)
    prompt: str | None = None
    completion: str | None = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    cached_tokens: int | None = None
    cache_read_tokens: int | None = None
    cache_creation_tokens: int | None = None
    cost_usd: float | None = None
    # ML Data Collection fields
    system_prompt: str | None = None
    temperature: float | None = None
    max_tokens: int | None = None

@contextmanager
def observe_llm_call(
    *,
    model: str,
    provider: str,
    metadata: dict[str, Any] | None = None,
) -> Iterator[_Observation]:
    """Context manager to simplify logging of LLM calls."""

    obs = _Observation(model=model, provider=provider, metadata=metadata or {})
    start = time.perf_counter()
    try:
        yield obs
    finally:
        duration_ms = (time.perf_counter() - start) * 1000.0
        emit_llm_call(
            model=model,
            provider=provider,
            prompt=obs.prompt,
            completion=obs.completion,
            tokens_in=obs.tokens_in,
            tokens_out=obs.tokens_out,
            cached_tokens=obs.cached_tokens,
            cache_read_tokens=obs.cache_read_tokens,
            cache_creation_tokens=obs.cache_creation_tokens,
            cost_usd=obs.cost_usd,
            latency_ms=duration_ms,
            metadata=obs.metadata,
            system_prompt=obs.system_prompt,
            temperature=obs.temperature,
            max_tokens=obs.max_tokens,
        )

def _append_event(path: Path, entry: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
    except OSError:  # pragma: no cover - log best effort
        return

def _sanitize_content(text: str | None, mode: str) -> tuple[str | None, bool]:
    """Sanitize content based on PII handling mode.

    ML DATA COLLECTION: This function protects PII while preserving data for ML training.
    Default mode is "mask" to enable ML model training while protecting sensitive data.

    Modes:
        - mask (DEFAULT): Replace PII patterns with labels (<<EMAIL>>, <<SSN>>, etc.)
          This preserves conversation context for ML training while protecting PII.
          Recommended for most use cases.
        - redact: Completely remove content if ANY PII detected.
          Use this for maximum security when ML training is not needed.
        - raw: Return content unchanged, only detect PII for reporting.
          WARNING: Only use this in isolated test environments with
          synthetic data. Never use with real customer data.

    Returns:
        tuple: (sanitized_text, pii_detected_flag)
    """
    if not text:
        return (None if mode == "redact" else text, False)

    detected = _pii_contains(text)

    if mode == "raw":
        return text, detected
    if mode == "redact":
        return None, detected

    # mask mode - use comprehensive PII masking
    masked = _pii_mask(text, mask_style="label")
    return masked, detected

def _contains_pii(text: str) -> bool:
    """Check if text contains any PII patterns."""
    return _pii_contains(text)

def _round_cost(value: float | None) -> float:
    if value is None:
        return 0.0
    return round(float(value), 10)

def _get_pricing_overrides() -> dict[str, dict[str, tuple[float, float]]]:
    global _PRICING_CACHE, _PRICING_ENV_VALUE
    raw = os.environ.get("KHAOS_LLM_PRICING")
    if raw == _PRICING_ENV_VALUE and _PRICING_CACHE is not None:
        return _PRICING_CACHE
    try:
        overrides = load_pricing_overrides(raw)
    except ValueError:
        overrides = {}
    _PRICING_ENV_VALUE = raw
    _PRICING_CACHE = dict(overrides)
    return _PRICING_CACHE
