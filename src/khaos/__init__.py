"""Khaos SDK package.

This module exposes the public API surface for integrating chaos experiments
into AI agent workflows. Implementation details remain in subpackages to keep
interfaces stable as the engine matures.
"""

import os

from .agent import (
    AgentMetadata,
    discover_agent_metadata,
    find_agent_record,
    list_local_agents,
    record_agent_run,
)
from .llm import emit_llm_call, observe_llm_call
from .agent_sdk import (
    khaosagent,       # Primary unified decorator
    khaos_agent,      # Deprecated alias for khaosagent
    AgentConfig,
    AgentCategory,
    AgentTimeoutError,
    InvocationContext,
    StreamingResponse,
    AsyncStreamingResponse,
    ToolDefinition,   # For defining tools available to an agent
    get_current_context,
)
from .output import (
    extract_output_text,
    extract_input_text,
    normalize_agent_output,
)
from .testing import khaostest, KhaosTestConfig, AgentTestClient, AgentResponse
from .runtime_hooks import install_runtime_discovery as enable_runtime_discovery

# Ensure runtime discovery honors environment flags when the package is imported.
if os.environ.get("KHAOS_RUNTIME_DISCOVERY"):
    enable_runtime_discovery()

__all__ = [
    "__version__",
    # Primary decorator
    "khaosagent",
    "khaos_agent",  # Deprecated alias
    # Configuration classes
    "AgentConfig",
    "AgentCategory",
    "AgentTimeoutError",
    "InvocationContext",
    "StreamingResponse",
    "AsyncStreamingResponse",
    "ToolDefinition",
    "get_current_context",
    # Output utilities (for framework integration)
    "extract_output_text",
    "extract_input_text",
    "normalize_agent_output",
    # Registry/discovery
    "AgentMetadata",
    "discover_agent_metadata",
    "record_agent_run",
    "list_local_agents",
    "find_agent_record",
    # LLM telemetry
    "emit_llm_call",
    "observe_llm_call",
    # Testing framework
    "khaostest",
    "KhaosTestConfig",
    "AgentTestClient",
    "AgentResponse",
    # Runtime discovery
    "enable_runtime_discovery",
]

__version__ = "1.0.6"
