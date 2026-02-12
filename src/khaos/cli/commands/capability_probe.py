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
    source_lower = (target_source or "").lower()
    caps_from_decorator = set()
    if agent_metadata and getattr(agent_metadata, "capabilities", None):
        caps_from_decorator = {str(c).lower() for c in agent_metadata.capabilities}

    # Analyze probe events
    trace_has_llm = False
    trace_has_http = False
    trace_has_mcp = False
    trace_has_tool_calls = False

    if probe_events:
        for event in probe_events:
            if not isinstance(event, dict):
                continue
            name = str(event.get("event", ""))
            if name == "llm.call":
                trace_has_llm = True
                payload = event.get("payload", {})
                if isinstance(payload, dict):
                    meta = payload.get("metadata", {})
                    if isinstance(meta, dict) and meta.get("tool_calls"):
                        trace_has_tool_calls = True
            if name == "http.request":
                trace_has_http = True
            if name.startswith("mcp."):
                trace_has_mcp = True

    # Static heuristics (fallback)
    llm_keywords = ("openai", "anthropic", "claude", "gpt", "llm")
    http_keywords = ("requests.", "import requests", "httpx.", "import httpx", "urllib")
    static_has_llm = any(k in source_lower for k in llm_keywords)
    static_has_http = any(k in source_lower for k in http_keywords)
    static_has_mcp = "mcp" in source_lower or "khaos_mcp" in source_lower or "KHAOS_MCP" in target_source

    # Combine all signals
    tool_calling = ("tool-calling" in caps_from_decorator) or trace_has_tool_calls or ("tool_calls" in source_lower)
    mcp = ("mcp" in caps_from_decorator) or trace_has_mcp or static_has_mcp
    llm = trace_has_llm or static_has_llm
    http = trace_has_http or static_has_http

    # Check for multi-turn capability
    multi_turn = ("multi-turn" in caps_from_decorator) or ("multi_turn" in caps_from_decorator)

    # Check for RAG capability
    rag_keywords = ("vector", "embedding", "retrieval", "chromadb", "pinecone", "faiss", "qdrant")
    rag = ("rag" in caps_from_decorator) or any(k in source_lower for k in rag_keywords)

    return {
        "llm": llm,
        "http": http,
        "mcp": mcp,
        "tool_calling": tool_calling,
        "multi_turn": multi_turn,
        "rag": rag,
        "sources": {
            "decorator_capabilities": sorted(caps_from_decorator),
            "probe_events": bool(probe_events),
        },
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

    caps_list = []
    if capabilities.get("llm"):
        caps_list.append("llm")
    if capabilities.get("http"):
        caps_list.append("http")
    if capabilities.get("mcp"):
        caps_list.append("mcp")
    if capabilities.get("tool_calling"):
        caps_list.append("tool_calling")
    if capabilities.get("multi_turn"):
        caps_list.append("multi_turn")
    if capabilities.get("rag"):
        caps_list.append("rag")

    return caps_list


__all__ = [
    "CAPABILITY_PROBE_INPUT_ID",
    "CAPABILITY_PROBE_PROMPT",
    "detect_agent_metadata",
    "detect_agent_security_mode",
    "infer_agent_capabilities",
    "extract_capabilities_list",
]
