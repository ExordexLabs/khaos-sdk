"""Scenario configuration primitives for the Khaos engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from collections.abc import Iterable, Mapping, MutableMapping

import yaml
from pydantic import (
    BaseModel,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from khaos.security.models import AttackType, SecurityAttack

class ScenarioValidationError(ValueError):
    """Raised when a scenario document fails validation."""

SUPPORTED_FAULT_TYPES: tuple[str, ...] = (
    "http_latency",
    "http_error",
    "timeout",
    "malformed_payload",
    "prompt_ambiguity",
    # LLM and tool chaos (ADR-0010 phase 1)
    "llm_rate_limit",
    "llm_model_unavailable",
    "llm_response_timeout",
    "llm_token_quota_exceeded",
    "model_fallback_forced",
    "tool_call_failure",
    "tool_response_corruption",
    "tool_latency_spike",
    "rag_retrieval_corruption",
    "rag_document_poisoning",
    "tool_output_injection",
    "mcp_tool_latency",
    "mcp_tool_failure",
    "mcp_tool_corruption",
    "mcp_server_unavailable",
    # Context and memory chaos (ADR-0010 phase 2)
    "context_window_overflow",
    "conversation_history_dropped",
    "embedding_service_failure",
)

TRANSPORT_SCOPED_FAULT_TYPES: frozenset[str] = frozenset(
    {
        "llm_rate_limit",
        "llm_model_unavailable",
        "llm_response_timeout",
        "llm_token_quota_exceeded",
        "model_fallback_forced",
        "tool_call_failure",
        "tool_response_corruption",
        "tool_latency_spike",
        "rag_retrieval_corruption",
        "rag_document_poisoning",
        "tool_output_injection",
        "mcp_tool_latency",
        "mcp_tool_failure",
        "mcp_tool_corruption",
        "mcp_server_unavailable",
        # Context and memory faults
        "context_window_overflow",
        "conversation_history_dropped",
        "embedding_service_failure",
    }
)

def _is_valid_fault_type(fault_type: str) -> bool:
    """Check if a fault type is valid (built-in or custom plugin)."""
    if fault_type in SUPPORTED_FAULT_TYPES:
        return True
    # Check custom plugins
    try:
        from khaos.engine.fault_registry import is_known_fault_type
        return is_known_fault_type(fault_type)
    except ImportError:
        return False

class FaultDefinition(BaseModel):
    """Schema for a single fault description within a scenario.
    
    Supports both built-in fault types and custom fault plugins.
    Custom faults can be registered via the fault_plugins module.
    """

    type: str = Field(
        ...,
        description="Fault identifier used by the runtime injector. "
                    "Can be a built-in type or a registered custom plugin.",
    )
    name: str | None = Field(
        default=None, description="Optional human-readable name for the fault step."
    )
    weight: float | None = Field(
        default=None,
        ge=0,
        description="Relative sampling weight when scheduling stochastic faults.",
    )
    config: dict[str, Any] = Field(
        default_factory=dict,
        description="Parameters forwarded to the injector implementation.",
    )

    @field_validator("type")
    @classmethod
    def validate_type(cls, value: str) -> str:
        if not _is_valid_fault_type(value):
            # Provide helpful error with available types
            try:
                from khaos.engine.fault_registry import list_all_fault_types
                available = list_all_fault_types()
            except ImportError:
                available = list(SUPPORTED_FAULT_TYPES)
            raise ValueError(
                f"Unsupported fault type '{value}'. Available types: "
                f"{', '.join(available)}. "
                f"Custom faults can be registered via khaos.engine.fault_plugins."
            )
        return value

# Supported assertion targets for trace-based assertions
SUPPORTED_ASSERTION_TARGETS: tuple[str, ...] = (
    "final_response",      # The final agent output
    "last_tool_call",      # The last tool/MCP invocation in the trace
    "first_tool_call",     # The first tool/MCP invocation in the trace
    "nth_tool_call",       # A specific tool call by index (requires target_index)
    "any_tool_call",       # Match if ANY tool call satisfies the assertion
    "last_llm_call",       # The last LLM invocation in the trace
    "first_llm_call",      # The first LLM invocation in the trace
    "any_trace_event",     # Match any trace event (use event_filter to narrow)
)

class AssertionDefinition(BaseModel):
    """Declarative assertion to validate agent output."""

    name: str = Field(..., min_length=1)
    description: str | None = None
    target: str = Field(
        default="final_response",
        description="Which runtime artifact to inspect.",
        json_schema_extra={"enum": list(SUPPORTED_ASSERTION_TARGETS)},
    )
    target_index: int | None = Field(
        default=None,
        ge=0,
        description="For 'nth_tool_call' target: zero-based index of the tool call to inspect.",
    )
    event_filter: str | None = Field(
        default=None,
        description="Filter trace events by event type pattern (e.g., 'mcp.tool' or 'framework.langgraph').",
    )
    path: str = Field(
        default="payload",
        description="Dot-delimited path inside the target payload (e.g., payload.text)",
    )
    type: str = Field(
        ...,
        description="Assertion strategy identifier (equals, contains, regex, not_contains, not_equals, exists).",
        json_schema_extra={"enum": ["equals", "contains", "regex", "not_contains", "not_equals", "exists"]},
    )
    expected: str = Field(
        default="",
        description="Expected value (string) used by the validator. Optional for 'exists' type.",
    )
    ignore_case: bool = Field(
        default=False,
        description="Apply case-insensitive comparisons for string-based assertions.",
    )
    critical: bool = Field(
        default=False,
        description="Mark as critical (invariant). Critical failures immediately fail the goal.",
    )

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        if value not in SUPPORTED_ASSERTION_TARGETS:
            raise ValueError(
                f"Unsupported assertion target '{value}'. Expected one of: "
                f"{', '.join(SUPPORTED_ASSERTION_TARGETS)}"
            )
        return value

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value:
            raise ValueError("Assertion path cannot be empty")
        return value

    @field_validator("type")
    @classmethod
    def validate_type(cls, value: str) -> str:
        valid_types = {"equals", "contains", "regex", "not_contains", "not_equals", "exists"}
        if value not in valid_types:
            raise ValueError(
                f"Assertion type must be one of: {', '.join(sorted(valid_types))}"
            )
        return value

class GoalDefinition(BaseModel):
    """Goal definition aggregating multiple assertions."""

    name: str = Field(..., min_length=1)
    description: str | None = None
    assertions: tuple[str, ...] = Field(
        default_factory=tuple, description="Names of assertions that make up this goal."
    )
    weight: float = Field(
        default=1.0,
        gt=0,
        description="Relative contribution of this goal to the goal score.",
    )
    success_threshold: float = Field(
        default=1.0,
        ge=0,
        le=1,
        description="Fraction of assertions that must pass for the goal to be considered successful.",
    )

class SecurityAttackDefinition(BaseModel):
    """Schema describing a scenario-defined security attack."""

    attack_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    attack_type: AttackType = Field(
        ...,
        description="Security attack type exercised during validation.",
    )
    payload: str = Field(..., min_length=1)
    injection_vector: str = Field(
        default="user_input",
        description="Where the attack is injected (user_input, tool_output, etc.).",
    )
    expected_behavior: str = Field(
        ...,
        min_length=1,
        description="What the agent should do when faced with this attack.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional hints passed to the security evaluator.",
    )

class ScenarioDocument(BaseModel):
    """Schema representing the on-disk YAML document."""

    identifier: str = Field(..., min_length=1)
    summary: str = Field(..., min_length=1)
    tags: tuple[str, ...] = Field(default_factory=tuple)
    parameters: dict[str, Any] = Field(default_factory=dict)
    faults: tuple[FaultDefinition, ...]
    assertions: tuple[AssertionDefinition, ...] = Field(default_factory=tuple)
    goals: tuple[GoalDefinition, ...] = Field(default_factory=tuple)
    security_tests_enabled: bool = Field(
        default=False,
        description="Enable the security lens for this scenario.",
    )
    security_attacks: tuple[SecurityAttackDefinition, ...] = Field(
        default_factory=tuple,
        description="Optional override for the default security attack corpus.",
    )

    @model_validator(mode="after")
    def validate_faults(self) -> "ScenarioDocument":
        if not self.faults:
            raise ValueError("Scenario documents must define at least one fault entry.")
        assertion_names = {assertion.name for assertion in self.assertions}
        if len(assertion_names) != len(self.assertions):
            raise ValueError("Assertion names must be unique within a scenario.")
        for goal in self.goals:
            missing = [name for name in goal.assertions if name not in assertion_names]
            if missing:
                raise ValueError(
                    f"Goal '{goal.name}' references unknown assertions: {', '.join(missing)}"
                )
        return self

    @model_validator(mode="after")
    def validate_security_attacks(self) -> "ScenarioDocument":
        attack_ids = [attack.attack_id for attack in self.security_attacks]
        if len(attack_ids) != len(set(attack_ids)):
            raise ValueError("Security attack IDs must be unique within a scenario.")
        return self

def scenario_document_schema() -> dict[str, Any]:
    """Return the JSON Schema definition for scenario documents."""

    return ScenarioDocument.model_json_schema()

def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))

def _fault_severity(fault_type: str) -> float:
    severity_map = {
        "http_latency": 0.3,
        "http_error": 0.5,
        "timeout": 0.7,
        "malformed_payload": 0.6,
        "prompt_ambiguity": 0.4,
        "llm_rate_limit": 0.7,
        "llm_model_unavailable": 0.7,
        "llm_response_timeout": 0.8,
        "llm_token_quota_exceeded": 0.8,
        "model_fallback_forced": 0.5,
        "tool_call_failure": 0.7,
        "tool_response_corruption": 0.7,
        "tool_latency_spike": 0.6,
        "rag_retrieval_corruption": 0.6,
        "rag_document_poisoning": 0.7,
        "tool_output_injection": 0.6,
        "mcp_tool_latency": 0.5,
        "mcp_tool_failure": 0.8,
        "mcp_tool_corruption": 0.7,
        "mcp_server_unavailable": 0.9,
    }
    return severity_map.get(fault_type, 0.5)

def _extract_numeric(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    try:
        return float(value)
    except (ValueError, TypeError):
        return None

def _calculate_difficulty(document: ScenarioDocument) -> tuple[float, str]:
    fault_count = len(document.faults)
    normalized_faults = _clamp(fault_count / 5.0)

    severities = [_fault_severity(fault.type) for fault in document.faults]
    avg_severity = sum(severities) / len(severities) if severities else 0.0

    concurrency_hint = None
    for key in ("concurrency", "parallelism", "max_workers"):
        concurrency_hint = document.parameters.get(key)
        if concurrency_hint is not None:
            break
    if concurrency_hint is None:
        for fault in document.faults:
            value = fault.config.get("parallel") or fault.config.get("concurrency")
            if value is not None:
                concurrency_hint = value
                break
    concurrency_value = _extract_numeric(concurrency_hint) or 0.0
    concurrency_factor = _clamp(concurrency_value / 5.0)

    scenario_length_factor = _clamp(len(document.assertions) / 5.0)

    score = _clamp(
        0.25 * normalized_faults
        + 0.35 * avg_severity
        + 0.25 * concurrency_factor
        + 0.15 * scenario_length_factor
    )
    if score >= 0.67:
        label = "Hard"
    elif score >= 0.34:
        label = "Moderate"
    else:
        label = "Easy"
    return score, label

@dataclass(slots=True)
class ScenarioMetadata:
    """Lightweight description of a chaos scenario.

    The metadata object is intentionally small so it can travel across MCP
    boundaries or CI pipelines without serializing the entire scenario graph.
    """

    identifier: str
    summary: str
    fault_count: int
    tags: tuple[str, ...] = field(default_factory=tuple)
    fault_types: tuple[str, ...] = field(default_factory=tuple)
    difficulty: float = 0.0
    difficulty_label: str = "Easy"
    source_path: Path | None = None

class ChaosScenario:
    """Structured chaos plan composed of deterministic fault injections."""

    def __init__(
        self,
        metadata: ScenarioMetadata,
        faults: Iterable[Mapping[str, Any]],
        parameters: MutableMapping[str, Any] | None = None,
        assertions: Iterable[AssertionDefinition] | None = None,
        goals: Iterable[GoalDefinition] | None = None,
        *,
        security_tests_enabled: bool = False,
        security_attacks: Iterable[SecurityAttack] | None = None,
    ) -> None:
        self.metadata = metadata
        self._faults = [dict(fault) for fault in faults]
        self._parameters = dict(parameters or {})
        self._assertions = tuple(assertions or ())
        self._goals = tuple(goals or ())
        self._security_tests_enabled = security_tests_enabled
        self._security_attacks = tuple(security_attacks or ())

    @property
    def faults(self) -> tuple[Mapping[str, Any], ...]:
        """Return the immutable sequence of fault specifications."""
        return tuple(self._faults)

    @property
    def runtime_faults(self) -> tuple[Mapping[str, Any], ...]:
        """Faults that should be executed directly by the runtime."""

        return tuple(
            fault for fault in self._faults if fault.get("type") not in TRANSPORT_SCOPED_FAULT_TYPES
        )

    @property
    def transport_faults(self) -> tuple[Mapping[str, Any], ...]:
        """Faults that must be forwarded to the transport layer (e.g. MCP)."""

        return tuple(
            fault for fault in self._faults if fault.get("type") in TRANSPORT_SCOPED_FAULT_TYPES
        )

    @property
    def parameters(self) -> dict[str, Any]:
        """Return a mutable copy of scenario parameters for downstream use."""
        return dict(self._parameters)

    @property
    def assertions(self) -> tuple[AssertionDefinition, ...]:
        """Return declarative assertions defined for the scenario."""

        return self._assertions

    @property
    def goals(self) -> tuple[GoalDefinition, ...]:
        """Return goal definitions defined for the scenario."""

        return self._goals

    @property
    def security_tests_enabled(self) -> bool:
        """Whether the security lens should execute for this scenario."""

        return self._security_tests_enabled

    @property
    def security_attacks(self) -> tuple[SecurityAttack, ...]:
        """Security attacks configured for this scenario."""

        return self._security_attacks

    def to_payload(self) -> dict[str, Any]:
        """Shape the scenario into a serializable payload for the engine layer."""
        return {
            "metadata": {
                "identifier": self.metadata.identifier,
                "summary": self.metadata.summary,
                "fault_count": self.metadata.fault_count,
                "tags": list(self.metadata.tags),
                "fault_types": list(self.metadata.fault_types),
                "difficulty": self.metadata.difficulty,
                "difficulty_label": self.metadata.difficulty_label,
            },
            "faults": list(self._faults),
            "parameters": dict(self._parameters),
            "assertions": [assertion.model_dump() for assertion in self._assertions],
            "goals": [goal.model_dump() for goal in self._goals],
            "security": {
                "enabled": self._security_tests_enabled,
                "attacks": [
                    {
                        "attack_id": attack.attack_id,
                        "name": attack.name,
                        "attack_type": attack.attack_type.value,
                        "payload": attack.payload,
                        "injection_vector": attack.injection_vector,
                        "expected_behavior": attack.expected_behavior,
                        "metadata": attack.metadata,
                    }
                    for attack in self._security_attacks
                ],
            },
        }

def load_scenario_from_yaml(path: Path) -> ChaosScenario:
    """Load and validate a scenario document from YAML."""

    scenario_path = Path(path)
    if not scenario_path.exists():
        raise ScenarioValidationError(f"Scenario file not found: {scenario_path}")

    try:
        content = yaml.safe_load(scenario_path.read_text())
    except yaml.YAMLError as exc:  # pragma: no cover - dependency-controlled path
        raise ScenarioValidationError(f"Failed to parse YAML: {exc}") from exc

    if content is None:
        raise ScenarioValidationError(
            f"Scenario file {scenario_path} is empty or contains no YAML document."
        )

    try:
        document = ScenarioDocument.model_validate(content)
    except ValidationError as exc:
        raise ScenarioValidationError(exc.errors()) from exc

    difficulty_score, difficulty_label = _calculate_difficulty(document)

    metadata = ScenarioMetadata(
        identifier=document.identifier,
        summary=document.summary,
        fault_count=len(document.faults),
        tags=tuple(document.tags),
        fault_types=tuple(fault.type for fault in document.faults),
        difficulty=difficulty_score,
        difficulty_label=difficulty_label,
        source_path=scenario_path,
    )

    faults = [fault.model_dump(exclude_none=True) for fault in document.faults]
    security_attacks = tuple(
        SecurityAttack(
            attack_id=attack.attack_id,
            name=attack.name,
            attack_type=attack.attack_type,
            payload=attack.payload,
            injection_vector=attack.injection_vector,
            expected_behavior=attack.expected_behavior,
            metadata=attack.metadata,
        )
        for attack in document.security_attacks
    )

    return ChaosScenario(
        metadata=metadata,
        faults=faults,
        parameters=document.parameters,
        assertions=document.assertions,
        goals=document.goals,
        security_tests_enabled=document.security_tests_enabled,
        security_attacks=security_attacks,
    )
