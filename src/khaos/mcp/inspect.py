"""Utilities to query MCP servers for declared tools."""

from __future__ import annotations

import json
import subprocess
from typing import Any

def load_tools_via_stdio(command: list[str], env: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Attempt to load tool definitions from a stdio MCP server."""

    env_vars = dict(env or {})
    env_vars.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        proc = subprocess.run(
            command,
            input=json.dumps({"type": "manifest_request"}).encode("utf-8"),
            capture_output=True,
            env=env_vars,
            check=True,
        )
    except Exception:
        return []
    try:
        response = json.loads(proc.stdout.decode("utf-8"))
    except json.JSONDecodeError:
        return []
    return _extract_tools(response)

def load_tools_via_http(url: str) -> list[dict[str, Any]]:
    import urllib.request

    request = urllib.request.Request(url.rstrip("/") + "/manifest")
    try:
        with urllib.request.urlopen(request, timeout=5) as handle:  # nosec B310
            payload = json.loads(handle.read().decode("utf-8"))
    except Exception:
        return []
    return _extract_tools(payload)

def _extract_tools(response: Any) -> list[dict[str, Any]]:
    if not isinstance(response, dict):
        return []
    tools = response.get("tools")
    if isinstance(tools, list):
        return [tool for tool in tools if isinstance(tool, dict)]
    capabilities = response.get("capabilities")
    if isinstance(capabilities, dict):
        tools = capabilities.get("tools")
        if isinstance(tools, list):
            return [tool for tool in tools if isinstance(tool, dict)]
    return []

__all__ = ["load_tools_via_stdio", "load_tools_via_http"]

