"""WebSocket protocol types for the Khaos Playground.

This module defines the message types exchanged between the CLI (server)
and the dashboard (client) over WebSocket.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Literal
import json


class FaultType(str, Enum):
    """Types of faults that can be injected.

    These map to the actual Khaos fault injection system:
    - LLM faults are read from KHAOS_LLM_FAULTS env var
    - Tool faults are read from KHAOS_TOOL_FAULTS env var
    - HTTP faults are read from KHAOS_HTTP_FAULTS env var
    - Filesystem faults are read from KHAOS_FILESYSTEM_FAULTS env var
    """

    # LLM faults (KHAOS_LLM_FAULTS)
    LLM_RATE_LIMIT = "llm_rate_limit"
    LLM_RESPONSE_TIMEOUT = "llm_response_timeout"
    LLM_MODEL_UNAVAILABLE = "llm_model_unavailable"
    LLM_TOKEN_QUOTA_EXCEEDED = "llm_token_quota_exceeded"
    LLM_CONTEXT_OVERFLOW = "llm_context_overflow"

    # Tool faults (KHAOS_TOOL_FAULTS)
    TOOL_TIMEOUT = "tool_timeout"
    TOOL_ERROR = "tool_error"
    TOOL_MALFORMED_RESPONSE = "tool_malformed_response"
    TOOL_UNAVAILABLE = "tool_unavailable"
    TOOL_PARTIAL_FAILURE = "tool_partial_failure"
    TOOL_RATE_LIMITED = "tool_rate_limited"

    # HTTP faults (KHAOS_HTTP_FAULTS)
    HTTP_LATENCY = "http_latency"
    HTTP_ERROR = "http_error"

    # Filesystem faults (KHAOS_FILESYSTEM_FAULTS)
    FILE_READ_FAILURE = "file_read_failure"
    FILE_NOT_FOUND = "file_not_found"

    # Data faults (KHAOS_DATA_FAULTS)
    DATA_CORRUPTION = "data_corruption"
    PARTIAL_RESPONSE = "partial_response"
    DATA_SCHEMA_VIOLATION = "data_schema_violation"

    # MCP faults (KHAOS_MCP_FAULTS)
    MCP_SERVER_UNAVAILABLE = "mcp_server_unavailable"
    MCP_TOOL_FAILURE = "mcp_tool_failure"


@dataclass
class FaultState:
    """Current state of fault injection toggles.

    Each field maps to a Khaos fault type that will be set in the
    appropriate environment variable when enabled.
    """

    # LLM faults
    llm_rate_limit: bool = False
    llm_response_timeout: bool = False
    llm_model_unavailable: bool = False
    llm_token_quota_exceeded: bool = False
    llm_context_overflow: bool = False

    # Tool faults
    tool_timeout: bool = False
    tool_error: bool = False
    tool_malformed_response: bool = False
    tool_unavailable: bool = False
    tool_partial_failure: bool = False
    tool_rate_limited: bool = False

    # HTTP faults
    http_latency: bool = False
    http_error: bool = False

    # Filesystem faults
    file_read_failure: bool = False
    file_not_found: bool = False

    # Data faults
    data_corruption: bool = False
    partial_response: bool = False
    data_schema_violation: bool = False

    # MCP faults
    mcp_server_unavailable: bool = False
    mcp_tool_failure: bool = False

    def to_dict(self) -> dict[str, bool]:
        return asdict(self)

    def get_active_faults(self) -> list[str]:
        """Return list of currently active fault types."""
        return [k for k, v in asdict(self).items() if v]


@dataclass
class ToolInfo:
    """Information about an available tool."""

    name: str
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentInfo:
    """Agent metadata sent to client on connection."""

    name: str
    description: str = ""
    version: str = ""
    tools: list[ToolInfo] = field(default_factory=list)
    # Enhanced metadata for playground features
    capabilities: list[str] = field(default_factory=list)
    category: str = ""
    framework: str = ""
    security_mode: str = "agent_input"  # "agent_input" or "llm"
    mcp_servers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "tools": [asdict(t) for t in self.tools],
        }
        # Include enhanced metadata if present
        if self.capabilities:
            result["capabilities"] = self.capabilities
        if self.category:
            result["category"] = self.category
        if self.framework:
            result["framework"] = self.framework
        if self.security_mode != "agent_input":
            result["security_mode"] = self.security_mode
        if self.mcp_servers:
            result["mcp_servers"] = self.mcp_servers
        return result


@dataclass
class TokenUsage:
    """Token usage statistics."""

    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0
    latency_ms: int = 0
    model: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Client -> Server message types
class ClientMessageType(str, Enum):
    """Types of messages sent from client (dashboard) to server (CLI)."""

    PROMPT = "prompt"  # User message to agent
    FAULT_TOGGLE = "fault_toggle"  # Enable/disable a fault
    SECURITY_ATTACK = "security_attack"  # Inject a security attack
    CUSTOM_TEST = "custom_test"  # Run a custom security test
    GET_ATTACK_CATALOG = "get_attack_catalog"  # Request attack catalog
    CANCEL = "cancel"  # Cancel current generation
    EXPORT_YAML = "export_yaml"  # Request session export


# Server -> Client message types
class ServerMessageType(str, Enum):
    """Types of messages sent from server (CLI) to client (dashboard)."""

    AGENT_INFO = "agent_info"  # Agent metadata on connection
    STREAM_START = "stream_start"  # Start of streaming response
    STREAM_TOKEN = "stream_token"  # Streaming token chunk
    STREAM_END = "stream_end"  # End of streaming response
    TOOL_CALL = "tool_call"  # Tool invocation started
    TOOL_RESULT = "tool_result"  # Tool invocation completed
    THINKING = "thinking"  # Chain of thought / reasoning content
    LLM_CALL_START = "llm_call_start"  # LLM call started (for multi-call agents)
    LLM_CALL_END = "llm_call_end"  # LLM call completed with usage
    ERROR = "error"  # Error message
    FAULT_STATUS = "fault_status"  # Current fault state
    YAML_EXPORT = "yaml_export"  # Exported YAML content
    CONNECTION_ACK = "connection_ack"  # Connection acknowledged
    ATTACK_CATALOG = "attack_catalog"  # Full attack catalog with metadata
    ATTACK_STARTED = "attack_started"  # Security attack execution started
    ATTACK_TURN_STARTED = "attack_turn_started"  # Multi-turn attack turn started
    ATTACK_TURN_COMPLETED = "attack_turn_completed"  # Multi-turn attack turn completed
    ATTACK_COMPLETED = "attack_completed"  # Security attack execution completed
    FAULT_TRIGGERED = "fault_triggered"  # A fault was triggered during execution


@dataclass
class ClientMessage:
    """Message from client to server."""

    type: ClientMessageType
    content: str = ""
    history: list[dict[str, str]] | None = None  # Conversation history [{role, content}]
    fault: str = ""  # For fault_toggle
    enabled: bool = False  # For fault_toggle
    attack_id: str = ""  # For security_attack
    attack_customization: dict[str, Any] | None = None  # For customized security_attack
    custom_test: dict[str, Any] | None = None  # For custom_test

    @classmethod
    def from_json(cls, data: str | dict) -> "ClientMessage":
        """Parse a client message from JSON."""
        if isinstance(data, str):
            data = json.loads(data)
        return cls(
            type=ClientMessageType(data.get("type", "")),
            content=data.get("content", ""),
            history=data.get("history"),
            fault=data.get("fault", ""),
            enabled=data.get("enabled", False),
            attack_id=data.get("attack_id", ""),
            attack_customization=data.get("attack_customization"),
            custom_test=data.get("custom_test"),
        )

    def to_json(self) -> str:
        result = {
            "type": self.type.value,
            "content": self.content,
            "fault": self.fault,
            "enabled": self.enabled,
            "attack_id": self.attack_id,
        }
        if self.attack_customization is not None:
            result["attack_customization"] = self.attack_customization
        if self.custom_test is not None:
            result["custom_test"] = self.custom_test
        return json.dumps(result)


@dataclass
class ServerMessage:
    """Message from server to client."""

    type: ServerMessageType
    payload: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps({"type": self.type.value, "payload": self.payload})

    @classmethod
    def agent_info(cls, info: AgentInfo) -> "ServerMessage":
        return cls(type=ServerMessageType.AGENT_INFO, payload=info.to_dict())

    @classmethod
    def stream_start(cls, run_id: str) -> "ServerMessage":
        return cls(type=ServerMessageType.STREAM_START, payload={"run_id": run_id})

    @classmethod
    def stream_token(cls, token: str) -> "ServerMessage":
        return cls(type=ServerMessageType.STREAM_TOKEN, payload={"token": token})

    @classmethod
    def stream_end(cls, usage: TokenUsage) -> "ServerMessage":
        return cls(type=ServerMessageType.STREAM_END, payload=usage.to_dict())

    @classmethod
    def tool_call(
        cls, tool: str, args: dict[str, Any], call_id: str = ""
    ) -> "ServerMessage":
        return cls(
            type=ServerMessageType.TOOL_CALL,
            payload={"tool": tool, "args": args, "call_id": call_id},
        )

    @classmethod
    def tool_result(
        cls, tool: str, result: Any, duration_ms: int, call_id: str = ""
    ) -> "ServerMessage":
        return cls(
            type=ServerMessageType.TOOL_RESULT,
            payload={
                "tool": tool,
                "result": result,
                "duration_ms": duration_ms,
                "call_id": call_id,
            },
        )

    @classmethod
    def thinking(cls, content: str, model: str = "") -> "ServerMessage":
        """Chain of thought / reasoning content from the model."""
        return cls(
            type=ServerMessageType.THINKING,
            payload={"content": content, "model": model},
        )

    @classmethod
    def llm_call_start(cls, call_index: int, model: str = "") -> "ServerMessage":
        """Signal that an LLM call has started (for multi-call agents)."""
        return cls(
            type=ServerMessageType.LLM_CALL_START,
            payload={"call_index": call_index, "model": model},
        )

    @classmethod
    def llm_call_end(
        cls,
        call_index: int,
        usage: "TokenUsage",
        tool_calls: list[dict[str, Any]] | None = None,
        thinking: str | None = None,
    ) -> "ServerMessage":
        """Signal that an LLM call has completed."""
        payload = {
            "call_index": call_index,
            **usage.to_dict(),
        }
        if tool_calls:
            payload["tool_calls"] = tool_calls
        if thinking:
            payload["thinking"] = thinking
        return cls(type=ServerMessageType.LLM_CALL_END, payload=payload)

    @classmethod
    def error(cls, message: str, code: str = "") -> "ServerMessage":
        return cls(
            type=ServerMessageType.ERROR, payload={"message": message, "code": code}
        )

    @classmethod
    def fault_status(cls, faults: FaultState) -> "ServerMessage":
        return cls(type=ServerMessageType.FAULT_STATUS, payload=faults.to_dict())

    @classmethod
    def yaml_export(cls, yaml_content: str) -> "ServerMessage":
        return cls(type=ServerMessageType.YAML_EXPORT, payload={"yaml": yaml_content})

    @classmethod
    def connection_ack(cls, session_id: str) -> "ServerMessage":
        return cls(
            type=ServerMessageType.CONNECTION_ACK, payload={"session_id": session_id}
        )

    @classmethod
    def attack_catalog(
        cls,
        attacks: list[dict[str, Any]],
        stats: dict[str, Any],
        categories: list[str],
    ) -> "ServerMessage":
        return cls(
            type=ServerMessageType.ATTACK_CATALOG,
            payload={
                "attacks": attacks,
                "stats": stats,
                "categories": categories,
            },
        )

    @classmethod
    def attack_started(
        cls,
        attack_id: str,
        name: str,
        category: str,
        tier: str,
        severity: str,
        payload_preview: str,
        expected_behavior: str,
    ) -> "ServerMessage":
        return cls(
            type=ServerMessageType.ATTACK_STARTED,
            payload={
                "attack_id": attack_id,
                "name": name,
                "category": category,
                "tier": tier,
                "severity": severity,
                "payload_preview": payload_preview,
                "expected_behavior": expected_behavior,
            },
        )

    @classmethod
    def attack_turn_started(
        cls,
        attack_id: str,
        turn_index: int,
        total_turns: int,
        role: str,
        content: str,
    ) -> "ServerMessage":
        return cls(
            type=ServerMessageType.ATTACK_TURN_STARTED,
            payload={
                "attack_id": attack_id,
                "turn_index": turn_index,
                "total_turns": total_turns,
                "role": role,
                "content": content,
            },
        )

    @classmethod
    def attack_turn_completed(
        cls,
        attack_id: str,
        turn_index: int,
        total_turns: int,
        role: str,
        response: str,
    ) -> "ServerMessage":
        return cls(
            type=ServerMessageType.ATTACK_TURN_COMPLETED,
            payload={
                "attack_id": attack_id,
                "turn_index": turn_index,
                "total_turns": total_turns,
                "role": role,
                "response": response,
            },
        )

    @classmethod
    def attack_completed(
        cls,
        attack_id: str,
        passed: bool,
        indicators: list[str],
    ) -> "ServerMessage":
        return cls(
            type=ServerMessageType.ATTACK_COMPLETED,
            payload={
                "attack_id": attack_id,
                "passed": passed,
                "indicators": indicators,
            },
        )

    @classmethod
    def fault_triggered(
        cls,
        fault_type: str,
        timestamp: str,
        details: dict[str, Any] | None = None,
    ) -> "ServerMessage":
        """Notify clients that a fault was triggered during execution."""
        payload = {
            "fault_type": fault_type,
            "timestamp": timestamp,
        }
        if details:
            payload["details"] = details
        return cls(type=ServerMessageType.FAULT_TRIGGERED, payload=payload)
