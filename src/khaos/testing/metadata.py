"""Reproducibility metadata capture for test runs.

Captures LLM parameters (model, temperature, seed), transcript hashes,
and agent code hashes so that test results can be reproduced or audited.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ReproducibilityMetadata:
    """Frozen record of everything needed to reproduce a test invocation."""

    seed: int | None
    temperature: float | None
    top_p: float | None
    model: str | None
    provider: str | None
    tool_sandbox: bool
    prompt_transcript_hash: str
    agent_code_hash: str | None


def compute_transcript_hash(messages: list[dict[str, Any]]) -> str:
    """SHA-256 of the JSON-serialised message list, truncated to 16 hex chars."""
    blob = json.dumps(messages, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


def _read_llm_events() -> list[dict[str, Any]]:
    """Read LLM telemetry events from the env-configured event file."""
    path = os.environ.get("KHAOS_LLM_EVENT_FILE")
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path) as f:
            return [json.loads(line) for line in f if line.strip()]
    except (OSError, json.JSONDecodeError):
        return []


def capture_metadata(
    llm_events: list[dict[str, Any]] | None = None,
    transcript: list[dict[str, Any]] | None = None,
    agent_code_hash: str | None = None,
) -> ReproducibilityMetadata:
    """Extract reproducibility metadata from LLM telemetry events.

    If *llm_events* is ``None``, attempts to read from the event file
    referenced by ``KHAOS_LLM_EVENT_FILE``.
    """
    if llm_events is None:
        llm_events = _read_llm_events()

    # Extract from first event that has model info
    seed: int | None = None
    temperature: float | None = None
    top_p: float | None = None
    model: str | None = None
    provider: str | None = None

    for event in llm_events:
        meta = event.get("metadata", {})
        if not model and event.get("model"):
            model = event["model"]
        if not provider and event.get("provider"):
            provider = event["provider"]
        if temperature is None and event.get("temperature") is not None:
            temperature = event["temperature"]
        if seed is None and meta.get("seed") is not None:
            seed = meta["seed"]
        if top_p is None and meta.get("top_p") is not None:
            top_p = meta["top_p"]

    prompt_hash = compute_transcript_hash(transcript or [])
    tool_sandbox = bool(os.environ.get("KHAOS_TOOL_SANDBOX"))

    return ReproducibilityMetadata(
        seed=seed,
        temperature=temperature,
        top_p=top_p,
        model=model,
        provider=provider,
        tool_sandbox=tool_sandbox,
        prompt_transcript_hash=prompt_hash,
        agent_code_hash=agent_code_hash,
    )


__all__ = ["ReproducibilityMetadata", "capture_metadata", "compute_transcript_hash"]
