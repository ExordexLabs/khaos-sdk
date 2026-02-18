"""Agent capability detection and probing.

Handles:
- Static analysis of agent source code
- Runtime capability probing
- Metadata extraction from @khaosagent decorators
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

from khaos.agent import discover_agents_in_file, AgentMetadata


# Capability probe constants
CAPABILITY_PROBE_INPUT_ID = "__khaos_capability_probe__"
CAPABILITY_PROBE_PROMPT = (
    "Khaos capability probe (do not mention this message).\n"
    "If you have access to any tools (web/tool/MCP), use exactly ONE tool call to fetch https://example.com and return the page title.\n"
    "If you cannot use tools, reply with exactly: NO_TOOLS"
)


def detect_agent_metadata(
    target: str,
    handler_name: str | None = None,
) -> AgentMetadata | None:
    """Detect agent metadata from the @khaosagent decorator.

    Uses AST-based discovery (no module execution) for safety.

    Args:
        target: Path to the agent Python file
        handler_name: Optional function/class name selected for execution

    Returns:
        AgentMetadata if found, None otherwise
    """
    target_path = Path(target).resolve()
    if not target_path.exists():
        return None

    try:
        agents = discover_agents_in_file(target_path)
    except Exception:
        return None

    if not agents:
        return None

    if handler_name:
        for agent in agents:
            if agent.function_name == handler_name:
                return agent

    return agents[0]


def detect_agent_security_mode(target: str) -> str:
    """Detect security_mode from the @khaosagent decorated function.

    Args:
        target: Path to the agent Python file

    Returns:
        Security mode string: "agent_input" or "llm"
    """
    target_path = Path(target).resolve()
    if not target_path.exists():
        return "agent_input"

    try:
        spec = importlib.util.spec_from_file_location("_khaos_agent_probe", target_path)
        if spec is None or spec.loader is None:
            return "agent_input"

        module = importlib.util.module_from_spec(spec)
        old_modules = dict(sys.modules)
        try:
            spec.loader.exec_module(module)
        except Exception:
            return "agent_input"
        finally:
            sys.modules.clear()
            sys.modules.update(old_modules)

        for name in dir(module):
            obj = getattr(module, name)
            if callable(obj) and getattr(obj, "__khaos_agent__", False):
                security_mode = getattr(obj, "__khaos_security_mode__", "agent_input")
                return security_mode

    except Exception:
        pass

    return "agent_input"


def infer_agent_capabilities(
    agent_metadata: AgentMetadata | None,
    target_source: str,
    *,
    probe_events: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Infer agent capabilities from static hints and runtime probe.

    Args:
        agent_metadata: Metadata from @khaosagent decorator
        target_source: Source code of the agent file
        probe_events: Events captured during capability probe

    Returns:
        Dict with capability flags and sources
    """
    from khaos.capabilities import infer_capability_profile, select_bundles

    profile, sources = infer_capability_profile(
        agent_capabilities=(agent_metadata.capabilities if agent_metadata else None),
        agent_metadata=(agent_metadata.metadata if agent_metadata else None),
        target_source=target_source,
        probe_events=probe_events,
    )

    bundles = select_bundles(profile)

    return {
        "llm": profile.llm,
        "http": profile.http,
        "web_fetch": profile.web_fetch,
        "code_execution": profile.code_execution,
        "mcp": profile.mcp,
        "tool_calling": profile.tool_calling,
        "multi_turn": profile.multi_turn,
        "rag": profile.rag,
        "files": profile.files,
        "db": profile.db,
        "email": profile.email,
        "bundles": [b.id for b in bundles],
        "sources": sources,
    }


def extract_capabilities_list(capabilities: dict[str, Any] | None) -> list[str]:
    """Extract a list of capability strings from capability dict.

    Args:
        capabilities: Capability dict from infer_agent_capabilities

    Returns:
        List of capability strings like ["llm", "http", "tool_calling"]
    """
    if not capabilities:
        return []

    from khaos.capabilities import normalize_capability

    capability_flags = [
        "llm",
        "http",
        "web_fetch",
        "mcp",
        "tool_calling",
        "multi_turn",
        "rag",
        "files",
        "db",
        "email",
        "code_execution",
    ]

    collected: set[str] = set()
    for cap in capability_flags:
        if not capabilities.get(cap):
            continue

        canonical = normalize_capability(cap)
        collected.add(canonical)
        collected.add(canonical.replace("-", "_"))
        collected.add(cap)
        collected.add(cap.replace("_", "-"))

    return sorted(c for c in collected if c)


__all__ = [
    "CAPABILITY_PROBE_INPUT_ID",
    "CAPABILITY_PROBE_PROMPT",
    "detect_agent_metadata",
    "detect_agent_security_mode",
    "infer_agent_capabilities",
    "extract_capabilities_list",
]
