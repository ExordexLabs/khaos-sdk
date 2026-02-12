"""Agent configuration capture utilities for ML data collection.

This module provides utilities for capturing comprehensive agent
configuration snapshots at runtime, enabling ML model training
on agent behavior data.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from typing import Any
from collections.abc import Callable

from khaos.sessions.models import AgentConfigSnapshot, ToolSnapshot

def compute_system_prompt_hash(system_prompt: str | None) -> str | None:
    """Compute SHA256 hash of system prompt for deduplication.

    This allows tracking unique system prompts without storing
    the actual content (useful for privacy-sensitive scenarios).

    Args:
        system_prompt: The system prompt text

    Returns:
        SHA256 hex digest or None if prompt is None/empty
    """
    if not system_prompt:
        return None
    return hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()

def infer_tool_categories(tools: list[dict[str, Any]]) -> list[str]:
    """Infer tool categories from tool definitions.

    Categorizes tools based on their names and descriptions to
    help with ML feature extraction.

    Categories:
        - shell: Shell/command execution tools
        - file: File system operations
        - network: HTTP/API/network tools
        - database: Database operations
        - mcp: MCP server tools
        - search: Search/retrieval tools
        - code: Code execution/analysis
        - other: Uncategorized

    Args:
        tools: List of tool definition dicts

    Returns:
        List of unique category strings
    """
    categories = set()

    # Category detection patterns
    shell_patterns = ["shell", "bash", "command", "exec", "terminal", "cli"]
    file_patterns = ["file", "read", "write", "path", "directory", "folder", "fs"]
    network_patterns = ["http", "api", "request", "fetch", "url", "web", "download"]
    database_patterns = ["sql", "database", "db", "query", "postgres", "mysql", "sqlite"]
    mcp_patterns = ["mcp", "server"]
    search_patterns = ["search", "find", "lookup", "retrieve", "query"]
    code_patterns = ["python", "code", "execute", "eval", "run", "script"]

    for tool in tools:
        name = tool.get("name", "").lower()
        desc = tool.get("description", "").lower()
        combined = f"{name} {desc}"

        if any(p in combined for p in shell_patterns):
            categories.add("shell")
        if any(p in combined for p in file_patterns):
            categories.add("file")
        if any(p in combined for p in network_patterns):
            categories.add("network")
        if any(p in combined for p in database_patterns):
            categories.add("database")
        if any(p in combined for p in mcp_patterns):
            categories.add("mcp")
        if any(p in combined for p in search_patterns):
            categories.add("search")
        if any(p in combined for p in code_patterns):
            categories.add("code")

        # If no category matched, mark as other
        if not any(p in combined for patterns in [
            shell_patterns, file_patterns, network_patterns,
            database_patterns, mcp_patterns, search_patterns, code_patterns
        ] for p in patterns):
            categories.add("other")

    return sorted(categories)

def _sanitize_system_prompt(system_prompt: str | None) -> str | None:
    """Sanitize system prompt based on PII mode setting.

    Uses the same PII handling as LLM telemetry.
    """
    if not system_prompt:
        return None

    # Import PII handling from telemetry
    try:
        from khaos.llm.telemetry import _sanitize_content
        mode = (os.environ.get("KHAOS_LLM_PII_MODE") or "mask").strip().lower()
        if mode not in ("raw", "redact", "mask"):
            mode = "mask"
        sanitized, _ = _sanitize_content(system_prompt, mode)
        return sanitized
    except ImportError:
        # Fallback: return as-is if telemetry module not available
        return system_prompt

def capture_agent_config_snapshot(
    agent_func: Callable[..., Any] | None = None,
    *,
    agent_name: str | None = None,
    agent_version: str = "1.0.0",
    description: str = "",
    system_prompt: str | None = None,
    default_model: str | None = None,
    default_temperature: float | None = None,
    default_max_tokens: int | None = None,
    tools: list[dict[str, Any]] | None = None,
    mcp_servers: list[str] | None = None,
    category: str | None = None,
    capabilities: list[str] | None = None,
    framework: str | None = None,
    security_mode: str = "agent_input",
    metadata: dict[str, Any] | None = None,
) -> AgentConfigSnapshot:
    """Capture a comprehensive agent configuration snapshot.

    This function creates an AgentConfigSnapshot from either:
    1. A decorated agent function (extracts config from __khaos_* attributes)
    2. Explicit parameters

    The snapshot is suitable for ML training and includes:
    - Agent identity and version
    - System prompt (sanitized for PII)
    - LLM hyperparameters
    - Tool definitions and categories
    - MCP server configuration
    - Capability flags

    Args:
        agent_func: Optional decorated agent function to extract config from
        agent_name: Agent name (required if agent_func not provided)
        agent_version: Agent version string
        description: Human-readable description
        system_prompt: The system prompt/instruction (will be PII-sanitized)
        default_model: Default LLM model name
        default_temperature: Default sampling temperature
        default_max_tokens: Default max tokens limit
        tools: List of tool definition dicts
        mcp_servers: List of MCP server names
        category: Agent category
        capabilities: List of capability strings
        framework: Framework name
        security_mode: Security testing mode
        metadata: Additional metadata

    Returns:
        AgentConfigSnapshot with all captured configuration

    Example:
        # From decorator:
        snapshot = capture_agent_config_snapshot(my_agent)

        # From explicit params:
        snapshot = capture_agent_config_snapshot(
            agent_name="my-agent",
            system_prompt="You are a helpful assistant",
            tools=[{"name": "search", "description": "Search the web"}],
        )
    """
    # Extract from decorated function if provided
    if agent_func is not None:
        khaos_config = getattr(agent_func, "__khaos_config__", None)
        if khaos_config is not None:
            # Extract from AgentConfig
            agent_name = agent_name or getattr(agent_func, "__khaos_name__", agent_func.__name__)
            agent_version = khaos_config.version
            description = description or khaos_config.description
            tools = tools or khaos_config.get_tools_list()
            mcp_servers = mcp_servers or khaos_config.mcp_servers
            category = category or (
                khaos_config.category.value
                if hasattr(khaos_config.category, "value")
                else khaos_config.category
            )
            capabilities = capabilities or khaos_config.capabilities
            framework = framework or khaos_config.framework
            security_mode = security_mode or khaos_config.security_mode
            metadata = metadata or khaos_config.metadata
        else:
            # Fallback to function name
            agent_name = agent_name or agent_func.__name__

    # Ensure agent_name is set
    if not agent_name:
        raise ValueError("agent_name is required when agent_func is not provided")

    # Process tools
    tools = tools or []
    tool_snapshots = [
        ToolSnapshot(
            name=t.get("name", ""),
            description=t.get("description", ""),
            parameters=t.get("parameters", {}),
        )
        for t in tools
    ]

    # Infer tool categories
    tool_categories = infer_tool_categories(tools)

    # Sanitize system prompt
    sanitized_system_prompt = _sanitize_system_prompt(system_prompt)
    system_prompt_hash = compute_system_prompt_hash(system_prompt)

    # Infer behavioral hints from capabilities
    capabilities = capabilities or []
    has_retry_logic = False  # Would need code analysis
    has_error_handling = False  # Would need code analysis
    has_fallback_tools = len(tools) > 1  # Simple heuristic
    is_stateful = "stateful" in capabilities
    is_streaming = "streaming" in capabilities
    supports_multimodal = "multimodal-io" in capabilities or "multimodal" in capabilities

    return AgentConfigSnapshot(
        agent_name=agent_name,
        agent_version=agent_version,
        description=description,
        system_prompt=sanitized_system_prompt,
        system_prompt_hash=system_prompt_hash,
        default_model=default_model,
        default_temperature=default_temperature,
        default_max_tokens=default_max_tokens,
        tools=tool_snapshots,
        tool_count=len(tool_snapshots),
        tool_categories=tool_categories,
        mcp_servers=mcp_servers or [],
        category=category,
        capabilities=capabilities,
        framework=framework,
        security_mode=security_mode,
        has_retry_logic=has_retry_logic,
        has_error_handling=has_error_handling,
        has_fallback_tools=has_fallback_tools,
        is_stateful=is_stateful,
        is_streaming=is_streaming,
        supports_multimodal=supports_multimodal,
        metadata=metadata or {},
        captured_at=datetime.now(timezone.utc),
    )
