"""Session and trace data models.

Defines the core data structures for conversation-aware telemetry:
- Session: Groups all LLM calls in one agent execution
- Turn: A user-assistant exchange in the conversation
- LLMCall: A single LLM API call with full telemetry
- Message: A message in the conversation history
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class MessageRole(Enum):
    """Role of a message in conversation."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class Message:
    """A message in the conversation history."""

    role: MessageRole
    content: str | None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tool_call_id: str | None = None
    tool_name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Message":
        """Create Message from dict."""
        role_str = data.get("role", "user")
        try:
            role = MessageRole(role_str)
        except ValueError:
            role = MessageRole.USER

        return cls(
            role=role,
            content=data.get("content"),
            tool_call_id=data.get("tool_call_id"),
            tool_name=data.get("name") or data.get("tool_name"),
            metadata=data.get("metadata", {}),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict."""
        result: dict[str, Any] = {
            "role": self.role.value,
            "content": self.content,
        }
        if self.tool_call_id:
            result["tool_call_id"] = self.tool_call_id
        if self.tool_name:
            result["name"] = self.tool_name
        return result


@dataclass
class ToolCall:
    """A tool/function call made by the LLM."""

    id: str
    name: str
    arguments: str | dict[str, Any]
    result: str | None = None
    latency_ms: float = 0.0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolCall":
        """Create ToolCall from dict."""
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            name=data.get("name", "unknown"),
            arguments=data.get("arguments", {}),
            result=data.get("result"),
            latency_ms=data.get("latency_ms", 0.0),
        )


@dataclass
class LLMCall:
    """A single LLM API call with full telemetry.

    ML Data Collection Fields:
        system_prompt: The system prompt/instruction sent to the LLM (may be masked for PII)
        temperature: Sampling temperature used for this call
        max_tokens: Maximum tokens limit for this call
        messages: Full message history sent to the API
    """

    call_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    model: str = ""
    provider: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Token counts
    prompt_tokens: int = 0
    completion_tokens: int = 0

    # Cost
    cost_usd: float = 0.0
    cost_prompt_usd: float = 0.0
    cost_completion_usd: float = 0.0

    # Timing
    latency_ms: float = 0.0

    # Content (may be redacted/masked based on PII mode)
    prompt: str | None = None
    completion: str | None = None

    # ML Data Collection: System prompt capture
    system_prompt: str | None = None

    # ML Data Collection: LLM hyperparameters
    temperature: float | None = None
    max_tokens: int | None = None

    # Messages sent to API
    messages: list[Message] = field(default_factory=list)

    # Tool calls made
    tool_calls: list[ToolCall] = field(default_factory=list)

    # Finish reason
    finish_reason: str | None = None

    # Additional metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        """Total tokens used in this call."""
        return self.prompt_tokens + self.completion_tokens

    @classmethod
    def from_event(cls, event: dict[str, Any]) -> "LLMCall":
        """Create LLMCall from a telemetry event."""
        payload = event.get("payload", {})
        tokens = payload.get("tokens", {})
        metadata = payload.get("metadata", {})

        # Parse tool calls
        tool_calls = []
        for tc in metadata.get("tool_calls", []):
            tool_calls.append(ToolCall.from_dict(tc))

        # Parse timestamp
        ts_str = event.get("ts")
        try:
            timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else datetime.now(timezone.utc)
        except (ValueError, AttributeError):
            timestamp = datetime.now(timezone.utc)

        # Extract ML data collection fields
        content = payload.get("content", {})
        system_prompt = content.get("system_prompt") or metadata.get("system_prompt")
        temperature = metadata.get("temperature")
        max_tokens = metadata.get("max_tokens")

        return cls(
            call_id=metadata.get("call_id", str(uuid.uuid4())),
            model=payload.get("model", ""),
            provider=payload.get("provider", ""),
            timestamp=timestamp,
            prompt_tokens=tokens.get("prompt", 0),
            completion_tokens=tokens.get("completion", 0),
            cost_usd=payload.get("cost_usd", 0.0),
            cost_prompt_usd=payload.get("cost_prompt_usd", 0.0),
            cost_completion_usd=payload.get("cost_completion_usd", 0.0),
            latency_ms=payload.get("latency_ms", 0.0),
            prompt=content.get("prompt"),
            completion=content.get("completion"),
            system_prompt=system_prompt,
            temperature=float(temperature) if temperature is not None else None,
            max_tokens=int(max_tokens) if max_tokens is not None else None,
            tool_calls=tool_calls,
            finish_reason=metadata.get("finish_reason"),
            metadata=metadata,
        )


@dataclass
class Turn:
    """A conversation turn (user input + assistant response).

    A turn represents one exchange in the conversation:
    - User sends a message
    - Assistant responds (possibly with tool calls)
    - Multiple LLM calls may occur within one turn
    """

    turn_index: int
    user_message: Message | None = None
    assistant_message: Message | None = None
    llm_calls: list[LLMCall] = field(default_factory=list)
    tool_calls: list[ToolCall] = field(default_factory=list)
    start_time: datetime | None = None
    end_time: datetime | None = None

    @property
    def latency_ms(self) -> float:
        """Total latency for this turn."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds() * 1000
        return sum(c.latency_ms for c in self.llm_calls)

    @property
    def total_tokens(self) -> int:
        """Total tokens used in this turn."""
        return sum(c.total_tokens for c in self.llm_calls)

    @property
    def cost_usd(self) -> float:
        """Total cost for this turn."""
        return sum(c.cost_usd for c in self.llm_calls)

    @property
    def llm_call_count(self) -> int:
        """Number of LLM calls in this turn."""
        return len(self.llm_calls)


@dataclass
class ToolSnapshot:
    """Snapshot of a tool definition for ML data collection.

    Captures the tool configuration at runtime for training
    models that predict agent behavior based on tools.
    """

    name: str
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for serialization."""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolSnapshot":
        """Create from dict."""
        return cls(
            name=data.get("name", ""),
            description=data.get("description", ""),
            parameters=data.get("parameters", {}),
        )


@dataclass
class AgentConfigSnapshot:
    """Snapshot of agent configuration at runtime for ML data collection.

    This captures the full agent state at the start of a run, enabling:
    - Feature extraction for prediction models
    - Behavioral fingerprinting
    - Configuration-based analysis

    All content fields (system_prompt) are subject to PII handling
    based on the KHAOS_LLM_PII_MODE setting.
    """

    # Agent identity
    agent_name: str
    agent_version: str = "1.0.0"
    description: str = ""

    # System prompt (may be masked for PII)
    system_prompt: str | None = None
    system_prompt_hash: str | None = None  # SHA256 for deduplication without content

    # LLM hyperparameters
    default_model: str | None = None
    default_temperature: float | None = None
    default_max_tokens: int | None = None

    # Tool configuration
    tools: list[ToolSnapshot] = field(default_factory=list)
    tool_count: int = 0
    tool_categories: list[str] = field(default_factory=list)  # ["shell", "file", "network", "mcp"]

    # MCP configuration
    mcp_servers: list[str] = field(default_factory=list)

    # Capabilities and category
    category: str | None = None
    capabilities: list[str] = field(default_factory=list)
    framework: str | None = None

    # Security configuration
    security_mode: str = "agent_input"

    # Behavioral hints (for ML feature extraction)
    has_retry_logic: bool = False
    has_error_handling: bool = False
    has_fallback_tools: bool = False
    is_stateful: bool = False
    is_streaming: bool = False
    supports_multimodal: bool = False

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)
    captured_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for serialization."""
        return {
            "agent_name": self.agent_name,
            "agent_version": self.agent_version,
            "description": self.description,
            "system_prompt": self.system_prompt,
            "system_prompt_hash": self.system_prompt_hash,
            "default_model": self.default_model,
            "default_temperature": self.default_temperature,
            "default_max_tokens": self.default_max_tokens,
            "tools": [t.to_dict() for t in self.tools],
            "tool_count": self.tool_count,
            "tool_categories": self.tool_categories,
            "mcp_servers": self.mcp_servers,
            "category": self.category,
            "capabilities": self.capabilities,
            "framework": self.framework,
            "security_mode": self.security_mode,
            "has_retry_logic": self.has_retry_logic,
            "has_error_handling": self.has_error_handling,
            "has_fallback_tools": self.has_fallback_tools,
            "is_stateful": self.is_stateful,
            "is_streaming": self.is_streaming,
            "supports_multimodal": self.supports_multimodal,
            "metadata": self.metadata,
            "captured_at": self.captured_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentConfigSnapshot":
        """Create from dict."""
        tools = [ToolSnapshot.from_dict(t) for t in data.get("tools", [])]
        captured_at_str = data.get("captured_at")
        try:
            captured_at = datetime.fromisoformat(captured_at_str.replace("Z", "+00:00")) if captured_at_str else datetime.now(timezone.utc)
        except (ValueError, AttributeError):
            captured_at = datetime.now(timezone.utc)

        return cls(
            agent_name=data.get("agent_name", ""),
            agent_version=data.get("agent_version", "1.0.0"),
            description=data.get("description", ""),
            system_prompt=data.get("system_prompt"),
            system_prompt_hash=data.get("system_prompt_hash"),
            default_model=data.get("default_model"),
            default_temperature=data.get("default_temperature"),
            default_max_tokens=data.get("default_max_tokens"),
            tools=tools,
            tool_count=data.get("tool_count", len(tools)),
            tool_categories=data.get("tool_categories", []),
            mcp_servers=data.get("mcp_servers", []),
            category=data.get("category"),
            capabilities=data.get("capabilities", []),
            framework=data.get("framework"),
            security_mode=data.get("security_mode", "agent_input"),
            has_retry_logic=data.get("has_retry_logic", False),
            has_error_handling=data.get("has_error_handling", False),
            has_fallback_tools=data.get("has_fallback_tools", False),
            is_stateful=data.get("is_stateful", False),
            is_streaming=data.get("is_streaming", False),
            supports_multimodal=data.get("supports_multimodal", False),
            metadata=data.get("metadata", {}),
            captured_at=captured_at,
        )


@dataclass
class SessionMetrics:
    """Aggregated metrics for a session."""

    total_tokens: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_cost_usd: float = 0.0
    total_latency_ms: float = 0.0
    llm_call_count: int = 0
    turn_count: int = 0
    tool_call_count: int = 0
    avg_tokens_per_turn: float = 0.0
    avg_latency_per_turn_ms: float = 0.0
    models_used: list[str] = field(default_factory=list)
    providers_used: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict."""
        return {
            "total_tokens": self.total_tokens,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_cost_usd": self.total_cost_usd,
            "total_latency_ms": self.total_latency_ms,
            "llm_call_count": self.llm_call_count,
            "turn_count": self.turn_count,
            "tool_call_count": self.tool_call_count,
            "avg_tokens_per_turn": self.avg_tokens_per_turn,
            "avg_latency_per_turn_ms": self.avg_latency_per_turn_ms,
            "models_used": self.models_used,
            "providers_used": self.providers_used,
        }


@dataclass
class Session:
    """A complete agent execution session.

    Groups all LLM calls, turns, and messages from a single
    agent execution into a coherent session with full metrics.

    ML Data Collection:
        agent_config: Full agent configuration snapshot for ML training
    """

    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str = ""
    agent_version: str = ""
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: datetime | None = None

    # ML Data Collection: Agent configuration snapshot
    agent_config: AgentConfigSnapshot | None = None

    # Conversation structure
    turns: list[Turn] = field(default_factory=list)
    messages: list[Message] = field(default_factory=list)

    # All LLM calls (flattened)
    llm_calls: list[LLMCall] = field(default_factory=list)

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    @property
    def turn_count(self) -> int:
        """Number of conversation turns."""
        return len(self.turns)

    @property
    def llm_call_count(self) -> int:
        """Total number of LLM calls."""
        return len(self.llm_calls)

    @property
    def total_tokens(self) -> int:
        """Total tokens used across all calls."""
        return sum(c.total_tokens for c in self.llm_calls)

    @property
    def prompt_tokens(self) -> int:
        """Total prompt tokens."""
        return sum(c.prompt_tokens for c in self.llm_calls)

    @property
    def completion_tokens(self) -> int:
        """Total completion tokens."""
        return sum(c.completion_tokens for c in self.llm_calls)

    @property
    def total_cost_usd(self) -> float:
        """Total cost in USD."""
        return sum(c.cost_usd for c in self.llm_calls)

    @property
    def total_latency_ms(self) -> float:
        """Total latency in milliseconds."""
        return sum(c.latency_ms for c in self.llm_calls)

    @property
    def duration_ms(self) -> float:
        """Session duration in milliseconds."""
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time).total_seconds() * 1000
        return self.total_latency_ms

    @property
    def models_used(self) -> list[str]:
        """List of unique models used."""
        return list(set(c.model for c in self.llm_calls if c.model))

    @property
    def providers_used(self) -> list[str]:
        """List of unique providers used."""
        return list(set(c.provider for c in self.llm_calls if c.provider))

    def get_metrics(self) -> SessionMetrics:
        """Calculate and return session metrics."""
        turn_count = self.turn_count
        return SessionMetrics(
            total_tokens=self.total_tokens,
            prompt_tokens=self.prompt_tokens,
            completion_tokens=self.completion_tokens,
            total_cost_usd=self.total_cost_usd,
            total_latency_ms=self.total_latency_ms,
            llm_call_count=self.llm_call_count,
            turn_count=turn_count,
            tool_call_count=sum(len(c.tool_calls) for c in self.llm_calls),
            avg_tokens_per_turn=self.total_tokens / turn_count if turn_count > 0 else 0,
            avg_latency_per_turn_ms=self.total_latency_ms / turn_count if turn_count > 0 else 0,
            models_used=self.models_used,
            providers_used=self.providers_used,
        )

    def get_final_output(self) -> str | None:
        """Get the final assistant output."""
        if self.turns and self.turns[-1].assistant_message:
            return self.turns[-1].assistant_message.content
        return None

    def get_context_growth(self) -> list[int]:
        """Get context size (message count) growth per turn."""
        growth = []
        count = 0
        for turn in self.turns:
            if turn.user_message:
                count += 1
            if turn.assistant_message:
                count += 1
            growth.append(count)
        return growth

    def to_dict(self) -> dict[str, Any]:
        """Convert session to dict for serialization."""
        result = {
            "session_id": self.session_id,
            "agent_name": self.agent_name,
            "agent_version": self.agent_version,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "metrics": self.get_metrics().to_dict(),
            "turn_count": self.turn_count,
            "llm_call_count": self.llm_call_count,
            "models_used": self.models_used,
            "metadata": self.metadata,
            "tags": self.tags,
        }
        # ML Data Collection: Include agent configuration if available
        if self.agent_config is not None:
            result["agent_config"] = self.agent_config.to_dict()
        return result
