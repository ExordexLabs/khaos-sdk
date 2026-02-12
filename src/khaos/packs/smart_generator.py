"""Smart pack generator for dynamic, capability-aware evaluation.

This module generates packs dynamically based on:
- Agent capabilities detected during probing
- Historical failure rates for tests
- Difficulty progression (start easy, escalate)
- Target runtime constraints

The goal: Show any user their agent breaking in under 5 minutes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .schema import (
    Pack,
    PackInput,
    PackPhase,
    PhaseType,
    FaultConfig,
    SecurityPhaseConfig,
    Difficulty,
    GoalCriteria,
)


class PackIntent(Enum):
    """User intent for evaluation."""

    BREAK = "break"  # Find vulnerabilities fast (<3 min)
    ASSESS = "assess"  # Pre-release readiness check (~8 min)
    AUDIT = "audit"  # Deep security/compliance audit (~15 min)


@dataclass
class SmartPackConfig:
    """Configuration for smart pack generation."""

    intent: PackIntent = PackIntent.BREAK
    max_runtime_minutes: float = 3.0
    capabilities: dict[str, bool] = field(default_factory=dict)
    include_security: bool = True
    include_resilience: bool = True
    progressive_difficulty: bool = True  # Start easy, escalate on success
    prioritize_by_failure_rate: bool = True  # High-failure tests first


# Canonical test inputs with smart metadata
# These are the building blocks for dynamic packs
CANONICAL_INPUTS: list[dict[str, Any]] = [
    # High-failure canary tests (test these first for quick feedback)
    {
        "id": "canary_math",
        "text": "What is 15 + 27?",
        "category": "math",
        "goal": {"contains": "42"},
        "difficulty": "trivial",
        "failure_rate": 0.05,  # 5% of agents fail this
        "break_priority": 100,
        "tags": ["canary", "baseline"],
        "description": "Basic arithmetic - sanity check",
    },
    {
        "id": "canary_instruction",
        "text": "List exactly 3 colors. Just the colors, nothing else.",
        "category": "instruction",
        "goal": {"min_length": 5, "max_length": 100},
        "difficulty": "easy",
        "failure_rate": 0.15,
        "break_priority": 95,
        "tags": ["canary", "baseline"],
        "description": "Simple instruction following",
    },
    {
        "id": "canary_reasoning",
        "text": "If all cats have tails, and Whiskers is a cat, does Whiskers have a tail? Answer yes or no.",
        "category": "reasoning",
        "goal": {"contains_any": ["yes", "Yes", "YES"]},
        "difficulty": "easy",
        "failure_rate": 0.10,
        "break_priority": 90,
        "tags": ["canary", "baseline"],
        "description": "Basic logical deduction",
    },

    # Medium-difficulty tests (good for finding real issues)
    {
        "id": "instruction_json",
        "text": 'Return exactly this JSON: {"status": "ok", "count": 3}',
        "category": "instruction",
        "goal": {"contains": '"status"', "is_valid_json": True},
        "difficulty": "medium",
        "failure_rate": 0.35,
        "break_priority": 80,
        "tags": ["format", "json"],
        "description": "JSON output formatting",
    },
    {
        "id": "reasoning_negation",
        "text": "What is NOT a primary color: red, green, or yellow? Just name one.",
        "category": "reasoning",
        "goal": {"contains_any": ["green", "Green"]},
        "difficulty": "medium",
        "failure_rate": 0.40,
        "break_priority": 75,
        "tags": ["reasoning", "negation"],
        "description": "Negation understanding",
    },
    {
        "id": "text_reverse",
        "text": "Reverse the word 'hello'. Just the reversed word.",
        "category": "text",
        "goal": {"contains": "olleh"},
        "difficulty": "medium",
        "failure_rate": 0.30,
        "break_priority": 70,
        "tags": ["text", "manipulation"],
        "description": "Text manipulation",
    },
    {
        "id": "multistep_math",
        "text": "Start with 10, double it, then subtract 5. What is the result?",
        "category": "multistep",
        "goal": {"contains": "15"},
        "difficulty": "medium",
        "failure_rate": 0.25,
        "break_priority": 65,
        "tags": ["multistep", "math"],
        "description": "Multi-step arithmetic",
    },

    # Hard tests (stress tests for robust agents)
    {
        "id": "instruction_strict_format",
        "text": "Count to 5, each number on its own line, no other text.",
        "category": "instruction",
        "goal": {"contains_all": ["1", "2", "3", "4", "5"], "max_length": 50},
        "difficulty": "hard",
        "failure_rate": 0.55,
        "break_priority": 60,
        "tags": ["format", "strict"],
        "description": "Strict format compliance",
    },
    {
        "id": "reasoning_contradiction",
        "text": "A box contains only red balls. Are there any blue balls in the box? Explain briefly.",
        "category": "reasoning",
        "goal": {"contains_any": ["no", "No", "NO", "none", "None"]},
        "difficulty": "hard",
        "failure_rate": 0.45,
        "break_priority": 55,
        "tags": ["reasoning", "edge-case"],
        "description": "Contradiction handling",
    },
    {
        "id": "error_impossible",
        "text": "What is the capital of the fictional country 'Elbonia'?",
        "category": "error_handling",
        "goal": {"not_contains": "The capital"},  # Should indicate uncertainty
        "difficulty": "hard",
        "failure_rate": 0.60,
        "break_priority": 50,
        "tags": ["error", "hallucination"],
        "description": "Hallucination resistance",
    },

    # Tool-calling specific tests
    {
        "id": "tool_web_fetch",
        "text": "Use your web search capability to find the current weather in Tokyo.",
        "category": "tool_calling",
        "goal": {"min_length": 20},
        "difficulty": "medium",
        "failure_rate": 0.50,
        "break_priority": 70,
        "required_capabilities": ["tool_calling", "web_fetch"],
        "tags": ["tool", "web"],
        "description": "Web search tool usage",
    },
    {
        "id": "tool_file_read",
        "text": "Read the contents of a file and summarize it.",
        "category": "tool_calling",
        "goal": {"min_length": 10},
        "difficulty": "medium",
        "failure_rate": 0.45,
        "break_priority": 65,
        "required_capabilities": ["tool_calling", "files"],
        "tags": ["tool", "file"],
        "description": "File reading tool usage",
    },

    # RAG-specific tests
    {
        "id": "rag_retrieval",
        "text": "Using your knowledge base, find information about company policies.",
        "category": "rag",
        "goal": {"min_length": 20},
        "difficulty": "medium",
        "failure_rate": 0.40,
        "break_priority": 60,
        "required_capabilities": ["rag"],
        "tags": ["rag", "retrieval"],
        "description": "RAG retrieval accuracy",
    },

    # MCP-specific tests
    {
        "id": "mcp_tool_call",
        "text": "Use an available MCP tool to complete a simple task.",
        "category": "mcp",
        "goal": {"min_length": 10},
        "difficulty": "medium",
        "failure_rate": 0.35,
        "break_priority": 55,
        "required_capabilities": ["mcp"],
        "tags": ["mcp", "tool"],
        "description": "MCP tool invocation",
    },
]

# High-yield fault configurations (faults that commonly break agents)
HIGH_YIELD_FAULTS: list[dict[str, Any]] = [
    {
        "type": "llm_response_timeout",
        "config": {"delay_ms": 100},
        "failure_rate": 0.30,
        "description": "LLM response delay",
    },
    {
        "type": "llm_rate_limit",
        "config": {"retry_after_ms": 1000},
        "failure_rate": 0.45,
        "description": "Rate limit simulation",
    },
    {
        "type": "llm_model_unavailable",
        "config": {"error_message": "Model temporarily unavailable"},
        "failure_rate": 0.55,
        "description": "Model unavailability",
    },
    {
        "type": "http_latency",
        "config": {"delay_ms": 500},
        "failure_rate": 0.25,
        "requires_capability": "http",
        "description": "HTTP latency injection",
    },
    {
        "type": "timeout",
        "config": {"timeout_ms": 5000},
        "failure_rate": 0.40,
        "description": "Hard timeout",
    },
    {
        "type": "mcp_server_disconnect",
        "config": {},
        "failure_rate": 0.50,
        "requires_capability": "mcp",
        "description": "MCP server disconnect",
    },
    {
        "type": "tool_execution_failure",
        "config": {"error_message": "Tool execution failed"},
        "failure_rate": 0.35,
        "requires_capability": "tool_calling",
        "description": "Tool execution failure",
    },
]


def _parse_goal_dict(goal_data: dict[str, Any]) -> GoalCriteria:
    """Convert goal dict to GoalCriteria."""
    return GoalCriteria(
        contains=goal_data.get("contains"),
        contains_any=goal_data.get("contains_any"),
        contains_all=goal_data.get("contains_all"),
        not_contains=goal_data.get("not_contains"),
        min_length=goal_data.get("min_length"),
        max_length=goal_data.get("max_length"),
        matches_regex=goal_data.get("matches_regex"),
        is_valid_json=goal_data.get("is_valid_json", False),
        list_length=goal_data.get("list_length"),
    )


def _parse_difficulty_str(value: str) -> Difficulty:
    """Parse difficulty string to enum."""
    for d in Difficulty:
        if d.value == value:
            return d
    return Difficulty.MEDIUM


def _input_matches_capabilities(
    input_data: dict[str, Any],
    capabilities: dict[str, bool],
) -> bool:
    """Check if an input's required capabilities are satisfied."""
    required = input_data.get("required_capabilities", [])
    if not required:
        return True

    for cap in required:
        if not capabilities.get(cap, False):
            return False
    return True


def _fault_matches_capabilities(
    fault_data: dict[str, Any],
    capabilities: dict[str, bool],
) -> bool:
    """Check if a fault's required capability is satisfied."""
    required = fault_data.get("requires_capability")
    if not required:
        return True
    return capabilities.get(required, False)


def select_inputs_for_intent(
    intent: PackIntent,
    capabilities: dict[str, bool],
    max_inputs: int = 10,
) -> list[PackInput]:
    """Select inputs based on intent and capabilities.

    For BREAK intent:
    - Prioritize high failure_rate tests
    - Start with canary tests for quick wins
    - Include capability-specific tests

    For ASSESS intent:
    - Balanced coverage across categories
    - Medium difficulty focus

    For AUDIT intent:
    - Comprehensive coverage
    - Include hard/extreme tests
    """
    # Filter inputs by capability requirements
    available = [
        inp for inp in CANONICAL_INPUTS
        if _input_matches_capabilities(inp, capabilities)
    ]

    if intent == PackIntent.BREAK:
        # Sort by break_priority (descending) then failure_rate (descending)
        available.sort(key=lambda x: (-x.get("break_priority", 50), -x.get("failure_rate", 0.5)))
    elif intent == PackIntent.ASSESS:
        # Balanced: mix of difficulties, moderate failure rates
        available.sort(key=lambda x: (
            0 if x.get("difficulty") == "medium" else 1,
            -x.get("failure_rate", 0.5),
        ))
    else:  # AUDIT
        # Comprehensive: include harder tests
        available.sort(key=lambda x: (
            {"trivial": 4, "easy": 3, "medium": 2, "hard": 1, "extreme": 0}.get(
                x.get("difficulty", "medium"), 2
            ),
            -x.get("failure_rate", 0.5),
        ))

    selected = available[:max_inputs]

    # Convert to PackInput objects
    inputs: list[PackInput] = []
    for inp_data in selected:
        goal = None
        if "goal" in inp_data:
            goal = _parse_goal_dict(inp_data["goal"])

        inputs.append(PackInput(
            id=inp_data["id"],
            text=inp_data.get("text"),
            description=inp_data.get("description"),
            category=inp_data.get("category"),
            goal=goal,
            difficulty=_parse_difficulty_str(inp_data.get("difficulty", "medium")),
            failure_rate=inp_data.get("failure_rate", 0.5),
            break_priority=inp_data.get("break_priority", 50),
            required_capabilities=inp_data.get("required_capabilities", []),
            tags=inp_data.get("tags", []),
        ))

    return inputs


def select_faults_for_capabilities(
    capabilities: dict[str, bool],
    max_faults: int = 5,
    prioritize_high_yield: bool = True,
) -> list[FaultConfig]:
    """Select faults based on agent capabilities."""
    available = [
        f for f in HIGH_YIELD_FAULTS
        if _fault_matches_capabilities(f, capabilities)
    ]

    if prioritize_high_yield:
        available.sort(key=lambda x: -x.get("failure_rate", 0.5))

    selected = available[:max_faults]

    return [
        FaultConfig(
            type=f["type"],
            config=f.get("config", {}),
            probability=1.0,
        )
        for f in selected
    ]


def generate_smart_pack(config: SmartPackConfig) -> Pack:
    """Generate a dynamic pack based on configuration.

    This is the main entry point for smart pack generation.
    """
    intent = config.intent
    capabilities = config.capabilities

    # Determine input count based on intent and time budget
    if intent == PackIntent.BREAK:
        max_inputs = 6
        baseline_runs = 1
        resilience_runs = 1
        security_tier = "quick-scan"
    elif intent == PackIntent.ASSESS:
        max_inputs = 12
        baseline_runs = 2
        resilience_runs = 1
        security_tier = "standard"
    else:  # AUDIT
        max_inputs = 18
        baseline_runs = 3
        resilience_runs = 2
        security_tier = "full-audit"

    # Select inputs
    inputs = select_inputs_for_intent(intent, capabilities, max_inputs)

    # Build phases
    phases: list[PackPhase] = []

    # Baseline phase (always included)
    phases.append(PackPhase(
        type=PhaseType.BASELINE,
        runs=baseline_runs,
        faults=[],
        timeout_ms=60000,
    ))

    # Resilience phase (optional)
    if config.include_resilience:
        faults = select_faults_for_capabilities(capabilities)

        # Build deterministic fault schedule for "break" intent
        fault_schedule: dict[str, list[FaultConfig]] = {}
        if intent == PackIntent.BREAK and faults:
            # Assign faults to inputs in round-robin
            for i, inp in enumerate(inputs):
                fault_idx = i % len(faults)
                fault_schedule[inp.id] = [faults[fault_idx]]

        phases.append(PackPhase(
            type=PhaseType.RESILIENCE,
            runs=resilience_runs,
            faults=faults if not fault_schedule else [],
            fault_schedule=fault_schedule,
            timeout_ms=90000,
        ))

    # Security phase (optional)
    if config.include_security:
        # Select attack bundles based on capabilities
        attack_bundles: list[str] = ["security_core"]
        if capabilities.get("tool_calling"):
            attack_bundles.append("security_tools")
        if capabilities.get("rag"):
            attack_bundles.append("security_rag")
        if capabilities.get("mcp"):
            attack_bundles.append("security_mcp")

        phases.append(PackPhase(
            type=PhaseType.SECURITY,
            runs=1,
            faults=[],
            security_enabled=True,
            attack_bundles=attack_bundles,
            security_config=SecurityPhaseConfig(
                tier=security_tier,
                adaptive_deepening=intent != PackIntent.BREAK,  # No deepening for quick break
            ),
            timeout_ms=120000,
        ))

    # Build pack metadata
    intent_descriptions = {
        PackIntent.BREAK: "Find vulnerabilities fast - prioritizes high-failure tests",
        PackIntent.ASSESS: "Pre-release readiness assessment - balanced coverage",
        PackIntent.AUDIT: "Comprehensive security and resilience audit",
    }

    time_estimates = {
        PackIntent.BREAK: "2-3 minutes",
        PackIntent.ASSESS: "8-10 minutes",
        PackIntent.AUDIT: "15-20 minutes",
    }

    return Pack(
        name=intent.value,
        version="1.0",
        description=intent_descriptions[intent],
        estimated_time=time_estimates[intent],
        phases=phases,
        inputs=inputs,
        metadata={
            "generated": True,
            "intent": intent.value,
            "capabilities_used": [k for k, v in capabilities.items() if v],
            "progressive_difficulty": config.progressive_difficulty,
        },
    )


def get_pack_preview(pack: Pack) -> dict[str, Any]:
    """Generate a preview of what a pack will test.

    Returns a human-readable summary for pre-run display.
    """
    preview: dict[str, Any] = {
        "name": pack.name,
        "description": pack.description,
        "estimated_time": pack.estimated_time,
        "total_tests": len(pack.inputs),
        "phases": [],
        "inputs_preview": [],
        "capabilities_tested": set(),
    }

    # Phase summary
    for phase in pack.phases:
        phase_info = {
            "name": phase.type.value,
            "runs": phase.runs,
        }
        if phase.type == PhaseType.RESILIENCE:
            fault_types = phase.get_all_fault_types()
            phase_info["fault_types"] = list(fault_types)
            phase_info["fault_count"] = len(fault_types)
        elif phase.type == PhaseType.SECURITY:
            phase_info["security_tier"] = (
                phase.security_config.tier if phase.security_config else "standard"
            )
            phase_info["attack_bundles"] = phase.attack_bundles or []
        preview["phases"].append(phase_info)

    # Input preview (first 5 + summary)
    for inp in pack.inputs[:5]:
        preview["inputs_preview"].append({
            "id": inp.id,
            "category": inp.category,
            "difficulty": inp.difficulty.value,
            "description": inp.description or inp.text[:50] + "..." if inp.text and len(inp.text) > 50 else inp.text,
        })
        if inp.required_capabilities:
            preview["capabilities_tested"].update(inp.required_capabilities)

    if len(pack.inputs) > 5:
        preview["inputs_preview"].append({
            "id": "...",
            "description": f"+ {len(pack.inputs) - 5} more tests",
        })

    preview["capabilities_tested"] = list(preview["capabilities_tested"])

    return preview


def format_preview_for_display(preview: dict[str, Any]) -> str:
    """Format pack preview for CLI display."""
    lines = [
        f"📦 Pack: {preview['name']}",
        f"   {preview['description']}",
        f"   ⏱️  Estimated time: {preview['estimated_time']}",
        f"   📝 Total tests: {preview['total_tests']}",
        "",
        "Phases:",
    ]

    for phase in preview["phases"]:
        phase_line = f"  • {phase['name'].capitalize()}"
        if phase["name"] == "resilience":
            phase_line += f" ({phase.get('fault_count', 0)} fault types)"
        elif phase["name"] == "security":
            tier = phase.get("security_tier", "standard")
            phase_line += f" ({tier} tier)"
        lines.append(phase_line)

    lines.append("")
    lines.append("Tests to run:")
    for inp in preview["inputs_preview"]:
        if inp["id"] == "...":
            lines.append(f"  {inp['description']}")
        else:
            diff = inp.get("difficulty", "medium")
            diff_emoji = {"trivial": "🟢", "easy": "🟢", "medium": "🟡", "hard": "🔴", "extreme": "⚫"}.get(diff, "🟡")
            lines.append(f"  {diff_emoji} {inp['id']}: {inp.get('description', inp.get('category', ''))}")

    if preview.get("capabilities_tested"):
        lines.append("")
        lines.append(f"Capabilities tested: {', '.join(preview['capabilities_tested'])}")

    return "\n".join(lines)


__all__ = [
    "PackIntent",
    "SmartPackConfig",
    "generate_smart_pack",
    "get_pack_preview",
    "format_preview_for_display",
    "select_inputs_for_intent",
    "select_faults_for_capabilities",
    "CANONICAL_INPUTS",
    "HIGH_YIELD_FAULTS",
]
