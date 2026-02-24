"""Utilities for loading MCP server configuration for transports."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections.abc import Iterable

DEFAULT_USER_CONFIG = Path.home() / ".khaos" / "mcp.json"

class MCPConfigError(RuntimeError):
    """Raised when MCP configuration files are invalid."""

@dataclass(slots=True)
class MCPServerConfig:
    name: str
    payload: dict[str, Any]

    def as_mapping(self) -> dict[str, Any]:
        data = {"name": self.name}
        data.update(self.payload)
        return data

def _load_servers_from_file(path: Path) -> dict[str, dict[str, Any]]:
    try:
        raw = json.loads(path.read_text())
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise MCPConfigError(f"Failed to parse MCP config at {path}: {exc}") from exc

    entries_obj = raw.get("servers", raw) if isinstance(raw, dict) else raw
    entries: list[dict[str, Any]]
    if isinstance(entries_obj, dict):
        entries = []
        for name, payload in entries_obj.items():
            if not isinstance(payload, dict):
                raise MCPConfigError(
                    f"Server '{name}' in {path} must be an object, got {type(payload).__name__}"
                )
            entry = dict(payload)
            entry.setdefault("name", name)
            entries.append(entry)
    elif isinstance(entries_obj, list):
        entries = []
        for idx, item in enumerate(entries_obj):
            if not isinstance(item, dict):
                raise MCPConfigError(
                    f"Entry {idx} in {path} must be an object with a name field"
                )
            entries.append(dict(item))
    else:
        raise MCPConfigError(
            f"Unsupported MCP config format in {path}: expected object or list"
        )

    normalized: dict[str, dict[str, Any]] = {}
    for entry in entries:
        norm = _normalize_entry(entry, source=str(path))
        normalized[norm["name"]] = norm
    return normalized

def _normalize_entry(entry: dict[str, Any], *, source: str | None = None) -> dict[str, Any]:
    if "name" not in entry or not entry["name"]:
        raise MCPConfigError(
            f"MCP server definition missing 'name' field (source: {source or 'inline'})"
        )
    normalized = dict(entry)
    normalized["name"] = str(normalized["name"])
    transport = normalized.get("transport", "stdio")
    normalized["transport"] = str(transport).lower()
    env = normalized.get("env")
    if env is not None and not isinstance(env, dict):
        raise MCPConfigError(
            f"MCP server '{normalized['name']}' env must be an object (source: {source or 'inline'})"
        )
    return normalized

def load_server_registry(paths: Iterable[Path]) -> dict[str, dict[str, Any]]:
    registry: dict[str, dict[str, Any]] = {}
    for path in paths:
        if path is None:
            continue
        resolved = _load_servers_from_file(path)
        registry.update(resolved)
    return registry

def parse_server_argument(value: str) -> dict[str, Any] | None:
    text = value.strip()
    if not text:
        return None
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise MCPConfigError(f"Invalid inline MCP server JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise MCPConfigError("Inline MCP server definition must be a JSON object")
        return _normalize_entry(data)
    return None

def resolve_mcp_servers(
    requested: list[str],
    *,
    config_paths: Iterable[Path],
) -> list[dict[str, Any]]:
    registry = load_server_registry(config_paths)
    resolved: list[dict[str, Any]] = []
    for item in requested:
        inline = parse_server_argument(item)
        if inline is not None:
            resolved.append(inline)
            continue
        key = item.strip()
        if not key:
            continue
        if key not in registry:
            raise MCPConfigError(f"Unknown MCP server '{key}'. Define it in an MCP config file.")
        resolved.append(registry[key])
    return resolved

def discover_default_config_paths(project_root: Path | None = None) -> list[Path]:
    paths = [DEFAULT_USER_CONFIG]
    if project_root is None:
        project_root = Path.cwd()
    project_config = project_root / ".khaos" / "mcp.json"
    paths.append(project_config)
    return paths


# ---------------------------------------------------------------------------
# Claude Desktop config support
# ---------------------------------------------------------------------------

import platform

CLAUDE_DESKTOP_CONFIG_PATHS: list[Path] = [
    # macOS
    Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
    # Linux
    Path.home() / ".config" / "claude" / "claude_desktop_config.json",
    # Windows
    Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
]


def detect_claude_desktop_config() -> Path | None:
    """Auto-detect the Claude Desktop config file path.

    Checks platform-specific paths and returns the first one that exists,
    or None if no config is found.
    """
    for path in CLAUDE_DESKTOP_CONFIG_PATHS:
        if path.exists():
            return path
    return None


def parse_claude_desktop_config(
    path: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Parse a Claude Desktop ``claude_desktop_config.json`` file.

    The Claude Desktop format stores MCP servers under ``mcpServers``::

        {
          "mcpServers": {
            "filesystem": {
              "command": "npx",
              "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
              "env": {"VAR": "value"}
            }
          }
        }

    Returns a dict mapping server name → config dict with ``name``,
    ``command``, ``args``, ``env``, and ``transport`` keys.
    """
    if path is None:
        path = detect_claude_desktop_config()
    if path is None:
        raise MCPConfigError(
            "Claude Desktop config not found. "
            "Checked: " + ", ".join(str(p) for p in CLAUDE_DESKTOP_CONFIG_PATHS)
        )

    try:
        raw = json.loads(path.read_text())
    except FileNotFoundError:
        raise MCPConfigError(f"Claude Desktop config not found at {path}")
    except json.JSONDecodeError as exc:
        raise MCPConfigError(f"Failed to parse Claude Desktop config at {path}: {exc}") from exc

    mcp_servers = raw.get("mcpServers", {})
    if not isinstance(mcp_servers, dict):
        raise MCPConfigError(
            f"'mcpServers' in {path} must be an object, got {type(mcp_servers).__name__}"
        )

    result: dict[str, dict[str, Any]] = {}
    for name, server_config in mcp_servers.items():
        if not isinstance(server_config, dict):
            raise MCPConfigError(
                f"Server '{name}' in {path} must be an object"
            )
        entry: dict[str, Any] = {
            "name": name,
            "transport": "stdio",
        }
        if "command" in server_config:
            entry["command"] = server_config["command"]
        if "args" in server_config:
            entry["args"] = server_config["args"]
        if "env" in server_config:
            entry["env"] = server_config["env"]
        if "url" in server_config:
            entry["transport"] = "sse"
            entry["url"] = server_config["url"]
        result[name] = entry

    return result
