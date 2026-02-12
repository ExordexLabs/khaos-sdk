"""Lightweight agent contract helpers for structured stdout envelopes."""

from __future__ import annotations

import functools
import json
from typing import Any
from collections.abc import Callable

Envelope = dict[str, Any]

REQUIRED_FIELDS = ("status",)
OPTIONAL_FIELDS = ("fault_type", "attack_type", "tool_name", "response", "metadata")

def normalize_payload(payload: Any) -> dict[str, Any]:
    """Ensure payload is a dict with required keys present (best-effort)."""

    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        try:
            payload = json.loads(payload) if isinstance(payload, str) else {"value": payload}
        except Exception:
            payload = {"value": payload}

    for field in REQUIRED_FIELDS:
        payload.setdefault(field, "unknown")
    for field in OPTIONAL_FIELDS:
        payload.setdefault(field, None)
    return payload

def make_envelope(name: str, payload: Any) -> Envelope:
    """Wrap a payload in the `{name, payload}` envelope expected by transports."""

    return {"name": name, "payload": normalize_payload(payload)}

def validate_envelope(envelope: Any) -> Envelope:
    """Validate a telemetry envelope, raising ValueError on malformed inputs."""

    if not isinstance(envelope, dict):
        raise ValueError("Envelope must be a mapping with name/payload fields.")
    name = envelope.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Envelope must include a non-empty 'name' field.")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("Envelope payload must be a mapping.")
    status = payload.get("status")
    if status is None or (isinstance(status, str) and not status.strip()):
        raise ValueError("Envelope payload must include a non-empty 'status'.")
    return envelope

def khaos_agent(strict: bool = False) -> Callable:
    """
    Decorator to normalize handler outputs into envelopes.

    If strict=True, required fields are injected when missing to avoid assertion/goal gaps.
    """

    def _decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def _wrapper(message: dict[str, Any]) -> Envelope:
            result = func(message)
            if strict:
                result = normalize_payload(result)
            if isinstance(result, dict) and "name" in result and "payload" in result:
                return result  # already wrapped
            return make_envelope("agent.response", result)

        return _wrapper

    return _decorator
