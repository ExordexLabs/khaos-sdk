"""Shared helpers for MCP proxies and transports."""

from __future__ import annotations

import json
from typing import Any

def extract_tool_name(message: dict[str, Any]) -> str | None:
    """Best-effort extraction of the MCP tool name from a message payload."""

    if "tool" in message and isinstance(message["tool"], str):
        return message["tool"]
    if "tool_name" in message and isinstance(message["tool_name"], str):
        return message["tool_name"]
    params = message.get("params")
    if isinstance(params, dict):
        if isinstance(params.get("tool"), str):
            return params["tool"]
        if isinstance(params.get("tool_name"), str):
            return params["tool_name"]
        tool = params.get("name") or params.get("toolName")
        if isinstance(tool, str):
            return tool
    payload = message.get("payload")
    if isinstance(payload, dict):
        return extract_tool_name(payload)
    return None

def build_failure_response(
    message: dict[str, Any],
    failure: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Construct a JSON response payload for injected failures."""

    response_id = message.get("id")
    error_payload = {
        "jsonrpc": "2.0",
        "id": response_id,
        "error": {
            "code": failure.get("status_code", -32000),
            "message": failure.get("error_message", "Injected MCP failure"),
            "data": {"khaos_failure_mode": failure.get("failure_mode", "execution_error")},
        },
    }
    return json.dumps(error_payload), error_payload
