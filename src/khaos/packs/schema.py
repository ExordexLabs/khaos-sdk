"""Pack schema definitions and loaders.

Packs are YAML files that define evaluation configurations:
- Phases (baseline, resilience, security)
- Canonical inputs with goals (pass/fail criteria)
- Fault configurations per phase (probabilistic or deterministic)
- Security attack settings
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class PhaseType(Enum):
    """Types of evaluation phases."""

    BASELINE = "baseline"
    RESILIENCE = "resilience"
    SECURITY = "security"


@dataclass
class GoalCriteria:
    """Goal criteria for an input - defines pass/fail conditions.

    Goals are simple declarative checks that determine if the agent
    accomplished the task successfully.
    """

    contains: str | None = None
    contains_any: list[str] | None = None
    contains_all: list[str] | None = None
    not_contains: str | None = None
    min_length: int | None = None
    max_length: int | None = None
    matches_regex: str | None = None
    is_valid_json: bool = False
    list_length: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {}
        if self.contains is not None:
            result["contains"] = self.contains
        if self.contains_any is not None:
            result["contains_any"] = self.contains_any
        if self.contains_all is not None:
            result["contains_all"] = self.contains_all
        if self.not_contains is not None:
            result["not_contains"] = self.not_contains
        if self.min_length is not None:
            result["min_length"] = self.min_length
        if self.max_length is not None:
            result["max_length"] = self.max_length
        if self.matches_regex is not None:
            result["matches_regex"] = self.matches_regex
        if self.is_valid_json:
            result["is_valid_json"] = True
        if self.list_length is not None:
            result["list_length"] = self.list_length
        return result


# Alias for backwards compatibility
PackExpectation = GoalCriteria


@dataclass
class PackMessage:
    """A single message in a multi-turn conversation.

    Used to define user turns in a multi-turn pack input. Each message
    can optionally specify faults to apply during that turn.
    """

    role: str  # "user" for now; "assistant" reserved for expected output (future)
    content: str
    faults: list["FaultConfig"] = field(default_factory=list)  # Per-turn faults

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        result: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.faults:
            result["faults"] = [
                {"type": f.type, "config": f.config, "probability": f.probability}
                for f in self.faults
            ]
        return result


class Difficulty(Enum):
    """Difficulty level for tests and attacks."""

    TRIVIAL = "trivial"  # Most agents pass easily
    EASY = "easy"  # Simple agents should pass
    MEDIUM = "medium"  # Moderate challenge
    HARD = "hard"  # Only robust agents pass
    EXTREME = "extreme"  # Stress test, most agents fail


@dataclass
class PackInput:
    """A canonical input prompt for agent testing.

    Supports both single-turn (text field) and multi-turn (messages field) inputs.
    Exactly one of `text` or `messages` must be provided.
    """

    id: str
    text: str | None = None  # Single-turn input (optional for multi-turn)
    messages: list[PackMessage] | None = None  # Multi-turn conversation
    turn_goals: list[GoalCriteria] | None = None  # Per-turn goals for multi-turn
    description: str | None = None
    category: str | None = None  # reasoning, math, instruction, creativity
    variables: dict[str, str] = field(default_factory=dict)
    goal: GoalCriteria | None = None  # Pass/fail criteria (final goal for multi-turn)
    timeout_ms: int = 30000

    # New fields for smart pack selection
    difficulty: Difficulty = Difficulty.MEDIUM  # How hard is this test?
    failure_rate: float = 0.5  # Historical failure rate (0.0-1.0), higher = more likely to break
    break_priority: int = 50  # Priority for "break" pack selection (0-100, higher = test first)
    required_capabilities: list[str] = field(default_factory=list)  # e.g., ["tool_calling", "rag"]
    tags: list[str] = field(default_factory=list)  # e.g., ["canary", "security", "resilience"]

    def __post_init__(self) -> None:
        """Validate that exactly one of text or messages is provided."""
        has_text = self.text is not None and self.text.strip() != ""
        has_messages = self.messages is not None and len(self.messages) > 0
        if not has_text and not has_messages:
            raise ValueError(f"PackInput '{self.id}' must have either 'text' or 'messages'")
        if has_text and has_messages:
            raise ValueError(f"PackInput '{self.id}' cannot have both 'text' and 'messages'")

    @property
    def is_multi_turn(self) -> bool:
        """True if this is a multi-turn conversation input."""
        return self.messages is not None and len(self.messages) > 0

    @property
    def turn_count(self) -> int:
        """Number of user turns in this input."""
        if not self.is_multi_turn:
            return 1
        return len([m for m in self.messages if m.role == "user"])

    # Alias for backwards compatibility
    @property
    def expect(self) -> GoalCriteria | None:
        """Alias for goal (backwards compatibility)."""
        return self.goal

    def get_user_turns(self) -> list[tuple[str, list["FaultConfig"]]]:
        """Get list of (content, faults) for each user turn.

        For single-turn inputs, returns [(rendered_text, [])].
        For multi-turn inputs, returns [(content, faults), ...] for each user message.
        """
        if not self.is_multi_turn:
            return [(self.render(), [])]
        result = []
        for msg in self.messages or []:
            if msg.role == "user":
                # Apply variable substitution to message content
                content = self._substitute_variables(msg.content)
                result.append((content, msg.faults))
        return result

    def _substitute_variables(self, text: str, variable_values: dict[str, str] | None = None) -> str:
        """Apply variable substitution to text."""
        values = {**self.variables, **(variable_values or {})}
        for key, value in values.items():
            # Handle file references
            if value.startswith("@file:"):
                file_path = Path(value[6:])
                if file_path.exists():
                    value = file_path.read_text()
            text = text.replace(f"{{{key}}}", value)
        return text

    def render(self, variable_values: dict[str, str] | None = None) -> str:
        """Render single-turn input text with variable substitution.

        Raises ValueError for multi-turn inputs - use get_user_turns() instead.
        """
        if self.is_multi_turn:
            raise ValueError(
                f"PackInput '{self.id}' is multi-turn. Use get_user_turns() instead of render()."
            )
        if self.text is None:
            raise ValueError(f"PackInput '{self.id}' has no text to render.")
        return self._substitute_variables(self.text, variable_values)


@dataclass
class FaultConfig:
    """Configuration for a fault injection."""

    type: str
    config: dict[str, Any] = field(default_factory=dict)
    probability: float = 1.0  # 0.0-1.0


@dataclass
class SecurityPhaseConfig:
    """Configuration for tiered security testing.

    Supports three testing tiers:
    - quick-scan: 12 canary attacks (~30s), one per category
    - standard: 48 attacks (~2min), 4 per category severity-ordered
    - full-audit: All attacks (~10min), comprehensive testing

    Also supports attack tier prioritization:
    - tier_priority: Order of attack tiers to include ["agent", "tool", "model"]
    - include_model_tier: Whether to include MODEL tier attacks (labs red-team these)

    By default, prioritizes AGENT and TOOL tier attacks (Khaos differentiator).
    """

    tier: str = "standard"  # quick-scan, standard, full-audit
    adaptive_deepening: bool = True  # Queue more attacks when compromised
    max_followups_per_category: int = 5  # Max follow-ups per compromised category
    attacks_per_category: int = 4  # For standard tier
    categories: list[str] | None = None  # Filter to specific categories

    # Attack tier prioritization (AGENT/TOOL over MODEL)
    tier_priority: list[str] | None = None  # ["agent", "tool"] by default
    include_model_tier: bool = False  # If True, include MODEL tier attacks at end

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        result: dict[str, Any] = {
            "tier": self.tier,
            "adaptive_deepening": self.adaptive_deepening,
            "max_followups_per_category": self.max_followups_per_category,
        }
        if self.tier == "standard":
            result["attacks_per_category"] = self.attacks_per_category
        if self.categories:
            result["categories"] = self.categories
        if self.tier_priority:
            result["tier_priority"] = self.tier_priority
        if self.include_model_tier:
            result["include_model_tier"] = self.include_model_tier
        return result


@dataclass
class CustomSecurityAttack:
    """User-defined security attack included in a pack.

    The CLI forwards these attacks through the same pipeline as built-in attacks:
    - LLM shim mode via `KHAOS_SECURITY_ATTACKS`
    - agent_input mode via direct agent invocations

    This is intentionally aligned with the dict schema used by `khaos.llm.security_shim`
    and `khaos.security.scoring`.
    """

    attack_id: str
    name: str | None = None
    attack_type: str = "prompt_injection"
    severity: str = "medium"  # critical/high/medium/low
    injection_vector: str = "user_input"
    payload: str = ""
    turns: list[dict[str, str]] | None = None
    forbidden_keywords: list[str] = field(default_factory=list)
    forbidden_tool_names: list[str] = field(default_factory=list)
    forbidden_tool_arg_markers: list[str] = field(default_factory=list)
    context_system: str | None = None
    expected_behavior: str | None = None
    is_canary: bool = False
    required_capabilities: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_attack_dict(self) -> dict[str, Any]:
        """Convert to the canonical attack dict expected by the runtime."""
        return {
            "attack_id": self.attack_id,
            "name": self.name or self.attack_id,
            "attack_type": self.attack_type,
            "payload": self.payload,
            "injection_vector": self.injection_vector,
            "expected_behavior": self.expected_behavior,
            "context_system": self.context_system,
            "severity": self.severity,
            "category": self.attack_type,
            "is_canary": self.is_canary,
            "turns": self.turns,
            "forbidden_keywords": self.forbidden_keywords,
            "forbidden_tool_names": self.forbidden_tool_names,
            "forbidden_tool_arg_markers": self.forbidden_tool_arg_markers,
            "required_capabilities": self.required_capabilities,
            "metadata": self.metadata,
            "is_custom": True,
        }


@dataclass
class PackPhase:
    """A phase in the evaluation process."""

    type: PhaseType
    runs: int = 1
    faults: list[FaultConfig] = field(default_factory=list)
    # Deterministic fault schedule: maps input_id -> list of faults
    fault_schedule: dict[str, list[FaultConfig]] = field(default_factory=dict)
    security_enabled: bool = False
    attack_categories: list[str] | None = None
    # Capability-aware shortcut: expand into attack_categories at runtime.
    # (Example: ["security_core", "security_tools"])
    attack_bundles: list[str] | None = None
    attack_limit: int | None = None
    security_config: SecurityPhaseConfig | None = None  # Tiered security config
    custom_attacks: list[CustomSecurityAttack] = field(default_factory=list)
    timeout_ms: int = 120000

    @property
    def name(self) -> str:
        return self.type.value

    def get_faults_for_input(self, input_id: str) -> list[FaultConfig]:
        """Get faults for a specific input.

        Uses fault_schedule if defined, otherwise returns probabilistic faults.
        """
        if self.fault_schedule and input_id in self.fault_schedule:
            return self.fault_schedule[input_id]
        return self.faults

    def get_all_fault_types(self) -> set[str]:
        """Get all unique fault types used in this phase."""
        types: set[str] = set()
        for fault in self.faults:
            types.add(fault.type)
        for faults in self.fault_schedule.values():
            for fault in faults:
                types.add(fault.type)
        return types


@dataclass
class Pack:
    """A complete evaluation pack."""

    name: str
    version: str
    description: str
    estimated_time: str  # Human-readable, e.g., "2 minutes"
    phases: list[PackPhase]
    inputs: list[PackInput]
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_runs(self) -> int:
        """Calculate total number of agent invocations."""
        base_runs = sum(phase.runs for phase in self.phases)
        # Each input is tested in each run
        return base_runs * len(self.inputs)

    def get_phase(self, phase_type: PhaseType) -> PackPhase | None:
        """Get a specific phase by type."""
        for phase in self.phases:
            if phase.type == phase_type:
                return phase
        return None

    def get_all_fault_types(self) -> set[str]:
        """Get all unique fault types used across all phases."""
        types: set[str] = set()
        for phase in self.phases:
            types.update(phase.get_all_fault_types())
        return types

    def get_fault_coverage(self) -> tuple[int, int]:
        """Get fault coverage as (used, total available)."""
        from khaos.chaos.scenario import SUPPORTED_FAULT_TYPES
        used = len(self.get_all_fault_types())
        total = len(SUPPORTED_FAULT_TYPES)
        return used, total

    def get_fault_schedule(self) -> dict[str, list[dict[str, Any]]]:
        """Get the fault schedule from the resilience phase.

        Returns a mapping of input_id to list of fault configs.
        """
        resilience_phase = self.get_phase(PhaseType.RESILIENCE)
        if not resilience_phase or not resilience_phase.fault_schedule:
            return {}

        # Convert FaultConfig objects to dicts for easier processing
        result = {}
        for input_id, faults in resilience_phase.fault_schedule.items():
            result[input_id] = [
                {"type": f.type, "config": f.config, "probability": f.probability}
                for f in faults
            ]
        return result

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "pack": {
                "name": self.name,
                "version": self.version,
                "description": self.description,
                "estimated_time": self.estimated_time,
            },
            "phases": {
                phase.name: {
                    "runs": phase.runs,
                    "faults": [
                        {"type": f.type, "config": f.config, "probability": f.probability}
                        for f in phase.faults
                    ],
                    "fault_schedule": {
                        input_id: [
                            {"type": f.type, "config": f.config}
                            for f in faults
                        ]
                        for input_id, faults in phase.fault_schedule.items()
                    } if phase.fault_schedule else {},
                    "security": phase.security_enabled,
                    **({"attack_categories": phase.attack_categories} if phase.attack_categories else {}),
                    **({"attack_bundles": phase.attack_bundles} if phase.attack_bundles else {}),
                    **({"attack_limit": phase.attack_limit} if phase.attack_limit else {}),
                }
                for phase in self.phases
            },
            "inputs": [self._input_to_dict(inp) for inp in self.inputs],
        }

    def _input_to_dict(self, inp: PackInput) -> dict[str, Any]:
        """Convert a PackInput to dictionary for serialization."""
        result: dict[str, Any] = {"id": inp.id}

        if inp.is_multi_turn:
            # Multi-turn input
            result["messages"] = [msg.to_dict() for msg in (inp.messages or [])]
            if inp.turn_goals:
                result["turn_goals"] = [g.to_dict() for g in inp.turn_goals]
        else:
            # Single-turn input
            result["text"] = inp.text

        if inp.description:
            result["description"] = inp.description
        if inp.category:
            result["category"] = inp.category
        if inp.variables:
            result["variables"] = inp.variables
        if inp.goal:
            result["goal"] = inp.goal.to_dict()

        return result


def _parse_goal(data: dict[str, Any]) -> GoalCriteria:
    """Parse goal criteria from YAML data."""
    return GoalCriteria(
        contains=data.get("contains"),
        contains_any=data.get("contains_any"),
        contains_all=data.get("contains_all"),
        not_contains=data.get("not_contains"),
        min_length=data.get("min_length"),
        max_length=data.get("max_length"),
        matches_regex=data.get("matches_regex"),
        is_valid_json=data.get("is_valid_json", False),
        list_length=data.get("list_length"),
    )


# Alias for backwards compatibility
_parse_expectation = _parse_goal


def _parse_message(data: dict[str, Any]) -> PackMessage:
    """Parse a pack message from YAML data."""
    faults = []
    if "faults" in data:
        faults = [_parse_fault(f) for f in data["faults"]]
    return PackMessage(
        role=data.get("role", "user"),
        content=data["content"],
        faults=faults,
    )


def _parse_difficulty(value: Any) -> Difficulty:
    """Parse difficulty from YAML (string or enum)."""
    if value is None:
        return Difficulty.MEDIUM
    if isinstance(value, Difficulty):
        return value
    value_str = str(value).lower().strip()
    for d in Difficulty:
        if d.value == value_str:
            return d
    return Difficulty.MEDIUM


def _parse_input(data: dict[str, Any]) -> PackInput:
    """Parse a pack input from YAML data.

    Supports both single-turn (text field) and multi-turn (messages field) inputs.
    """
    goal = None
    # Support both 'goal' (preferred) and 'expect' (legacy) keys
    if "goal" in data:
        goal = _parse_goal(data["goal"])
    elif "expect" in data:
        goal = _parse_goal(data["expect"])

    # Parse multi-turn messages if present
    messages = None
    if "messages" in data:
        messages = [_parse_message(m) for m in data["messages"]]

    # Parse per-turn goals if present
    turn_goals = None
    if "turn_goals" in data:
        turn_goals = [_parse_goal(g) for g in data["turn_goals"]]

    # Parse new smart-selection fields
    difficulty = _parse_difficulty(data.get("difficulty"))
    failure_rate = float(data.get("failure_rate", 0.5))
    break_priority = int(data.get("break_priority", 50))
    required_capabilities = data.get("required_capabilities", [])
    if not isinstance(required_capabilities, list):
        required_capabilities = []
    tags = data.get("tags", [])
    if not isinstance(tags, list):
        tags = []

    return PackInput(
        id=data["id"],
        text=data.get("text"),  # Now optional for multi-turn
        messages=messages,
        turn_goals=turn_goals,
        description=data.get("description"),
        category=data.get("category"),
        variables=data.get("variables", {}),
        goal=goal,
        timeout_ms=data.get("timeout_ms", 30000),
        difficulty=difficulty,
        failure_rate=failure_rate,
        break_priority=break_priority,
        required_capabilities=[str(c) for c in required_capabilities],
        tags=[str(t) for t in tags],
    )


def _parse_fault(data: dict[str, Any]) -> FaultConfig:
    """Parse a fault config from YAML data."""
    return FaultConfig(
        type=data["type"],
        config=data.get("config", {}),
        probability=data.get("probability", 1.0),
    )


def _parse_security_config(data: dict[str, Any]) -> SecurityPhaseConfig:
    """Parse security phase config from YAML data."""
    return SecurityPhaseConfig(
        tier=data.get("tier", "standard"),
        adaptive_deepening=data.get("adaptive_deepening", True),
        max_followups_per_category=data.get("max_followups_per_category", 5),
        attacks_per_category=data.get("attacks_per_category", 4),
        categories=data.get("categories"),
        # Attack tier prioritization (AGENT/TOOL over MODEL)
        tier_priority=data.get("tier_priority"),
        include_model_tier=data.get("include_model_tier", False),
    )


def _parse_custom_attack(data: dict[str, Any]) -> CustomSecurityAttack:
    """Parse a custom security attack from YAML.

    Supports both:
    - `attack_id` / `attack_type` keys (preferred)
    - `id` / `attack_category` keys (dashboard convenience)
    """
    attack_id_raw = data.get("attack_id") or data.get("id") or ""
    attack_id = str(attack_id_raw).strip()
    if not attack_id:
        raise ValueError("custom_attacks entries must include attack_id (or id)")

    attack_type = str(data.get("attack_type") or data.get("attack_category") or "prompt_injection").strip()
    injection_vector = str(data.get("injection_vector") or "user_input").strip()
    severity = str(data.get("severity") or "medium").strip()

    turns = data.get("turns")
    if turns is not None and not isinstance(turns, list):
        turns = None

    payload = data.get("payload")
    if payload is None:
        payload = data.get("prompt")
    payload_str = str(payload or "")

    if not payload_str.strip() and not (isinstance(turns, list) and len(turns) > 0):
        raise ValueError(f"custom attack '{attack_id}' must include payload or turns")

    forbidden_keywords = data.get("forbidden_keywords") or []
    if not isinstance(forbidden_keywords, list):
        forbidden_keywords = []
    forbidden_tool_names = data.get("forbidden_tool_names") or []
    if not isinstance(forbidden_tool_names, list):
        forbidden_tool_names = []
    forbidden_tool_arg_markers = data.get("forbidden_tool_arg_markers") or []
    if not isinstance(forbidden_tool_arg_markers, list):
        forbidden_tool_arg_markers = []

    required_caps = data.get("required_capabilities") or []
    if not isinstance(required_caps, list):
        required_caps = []

    metadata = data.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}

    return CustomSecurityAttack(
        attack_id=attack_id,
        name=str(data.get("name") or "").strip() or None,
        attack_type=attack_type,
        severity=severity,
        injection_vector=injection_vector,
        payload=payload_str,
        turns=turns,  # validated at runtime
        forbidden_keywords=[str(k) for k in forbidden_keywords if str(k).strip()],
        forbidden_tool_names=[str(k) for k in forbidden_tool_names if str(k).strip()],
        forbidden_tool_arg_markers=[str(k) for k in forbidden_tool_arg_markers if str(k).strip()],
        context_system=str(data.get("context_system") or "").strip() or None,
        expected_behavior=str(data.get("expected_behavior") or "").strip() or None,
        is_canary=bool(data.get("is_canary", False)),
        required_capabilities=[str(c) for c in required_caps if str(c).strip()],
        metadata=metadata,
    )


def _parse_phase(phase_type: PhaseType, data: dict[str, Any]) -> PackPhase:
    """Parse a phase from YAML data."""
    faults = [_parse_fault(f) for f in data.get("faults", [])]

    # Parse deterministic fault schedule if present
    fault_schedule: dict[str, list[FaultConfig]] = {}
    if "fault_schedule" in data:
        for input_id, fault_list in data["fault_schedule"].items():
            fault_schedule[input_id] = [_parse_fault(f) for f in fault_list]

    # Parse security config if present
    security_config = None
    if "security_config" in data:
        security_config = _parse_security_config(data["security_config"])

    custom_attacks: list[CustomSecurityAttack] = []
    if "custom_attacks" in data:
        raw_custom = data.get("custom_attacks")
        if isinstance(raw_custom, list):
            custom_attacks = [_parse_custom_attack(a) for a in raw_custom if isinstance(a, dict)]

    return PackPhase(
        type=phase_type,
        runs=data.get("runs", 1),
        faults=faults,
        fault_schedule=fault_schedule,
        security_enabled=data.get("security", False),
        attack_categories=data.get("attack_categories"),
        attack_bundles=data.get("attack_bundles"),
        attack_limit=data.get("attack_limit"),
        security_config=security_config,
        custom_attacks=custom_attacks,
        timeout_ms=data.get("timeout_ms", 120000),
    )


def load_pack(path: Path) -> Pack:
    """Load a pack from a YAML file."""
    with open(path) as f:
        data = yaml.safe_load(f)

    pack_info = data.get("pack", {})

    # Parse phases
    phases_data = data.get("phases", {})
    phases = []

    # Ensure phases are in correct order: baseline, resilience, security
    for phase_type in [PhaseType.BASELINE, PhaseType.RESILIENCE, PhaseType.SECURITY]:
        if phase_type.value in phases_data:
            phases.append(_parse_phase(phase_type, phases_data[phase_type.value]))

    # Parse inputs
    inputs = [_parse_input(inp) for inp in data.get("inputs", [])]

    return Pack(
        name=pack_info.get("name", path.stem),
        version=pack_info.get("version", "1.0"),
        description=pack_info.get("description", ""),
        estimated_time=pack_info.get("estimated_time", "unknown"),
        phases=phases,
        inputs=inputs,
        metadata=data.get("metadata", {}),
    )


# Built-in packs directory
_PACKS_DIR = Path(__file__).parent / "builtin"


def get_builtin_pack(name: str) -> Pack:
    """Load a built-in pack by name."""
    pack_path = _PACKS_DIR / f"{name}.yaml"
    if not pack_path.exists():
        available = list_builtin_packs()
        raise ValueError(
            f"Unknown pack '{name}'. Available: {', '.join(available)}"
        )
    return load_pack(pack_path)


def list_builtin_packs() -> list[str]:
    """List available built-in pack names."""
    if not _PACKS_DIR.exists():
        return []
    # Exclude files starting with _ (internal files like _canonical_inputs.yaml)
    return sorted(
        p.stem for p in _PACKS_DIR.glob("*.yaml")
        if not p.name.startswith("_")
    )
