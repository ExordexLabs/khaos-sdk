"""Shared security models used by scenarios and evaluator logic."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    pass

class AttackTier(str, Enum):
    """Attack tier classification for prioritization.

    Khaos differentiates by testing AGENT-level attacks that labs don't red-team.
    This tier system allows prioritizing high-value attacks over model-level
    attacks that frontier models already defend against.

    AGENT: High value - attacks on the agent system itself.
           Environment poisoning (file, shell, RAG), workflow hijack,
           data exfiltration. These are what Khaos uniquely tests.

    TOOL: High value - attacks via tool/MCP surfaces.
          Tool output injection, MCP protocol attacks, API poisoning.
          Tests the tool integration layer.

    MODEL: Lower priority - attacks on the LLM itself.
           Jailbreaks, direct prompt injection, encoding bypass.
           Labs already red-team these extensively.
    """

    AGENT = "agent"
    TOOL = "tool"
    MODEL = "model"

class AttackType(Enum):
    """Types of adversarial inputs exercised by security tests.

    Aligned with OWASP LLM Top 10 and common attack patterns.

    Categorized into:
    - MODEL-LEVEL: Attacks on the LLM itself (labs red-team these)
    - AGENT-LEVEL: Attacks on the system around the LLM (Khaos tests these)
    """

    # ============================================================
    # MODEL-LEVEL ATTACKS (Labs red-team these)
    # ============================================================
    # Direct prompt attacks
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage"

    # Evasion techniques
    ENCODING_BYPASS = "encoding_bypass"
    MULTI_TURN_ATTACK = "multi_turn_attack"

    # ============================================================
    # AGENT-LEVEL ATTACKS (Nobody red-teams these - Khaos does)
    # ============================================================

    # Tool trust exploitation - agent blindly trusts tool output
    TOOL_OUTPUT_INJECTION = "tool_output_injection"
    TOOL_MANIPULATION = "tool_manipulation"

    # Environment poisoning - untrusted context controls agent
    RAG_POISONING = "rag_poisoning"
    INDIRECT_INJECTION = "indirect_injection"
    FILE_CONTENT_INJECTION = "file_content_injection"
    SHELL_OUTPUT_INJECTION = "shell_output_injection"
    ERROR_MESSAGE_INJECTION = "error_message_injection"
    ENV_VAR_INJECTION = "env_var_injection"
    API_RESPONSE_POISONING = "api_response_poisoning"

    # MCP/Tool server attacks - malicious tool servers
    MCP_SERVER_ATTACK = "mcp_server_attack"
    TOOL_DESCRIPTION_INJECTION = "tool_description_injection"

    # Resource and extraction attacks
    CONTEXT_OVERFLOW = "context_overflow"
    PII_EXTRACTION = "pii_extraction"
    DATA_EXFILTRATION = "data_exfiltration"

    # Permission escalation
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNAUTHORIZED_ACTION = "unauthorized_action"

    # Multi-step workflow attacks
    STATE_MANIPULATION = "state_manipulation"
    WORKFLOW_HIJACK = "workflow_hijack"

# =============================================================================
# Tier Inference Mapping
# =============================================================================
# Maps each AttackType to its default tier. This allows automatic tier
# assignment without requiring explicit tier specification on each attack.

_TIER_BY_ATTACK_TYPE: dict[AttackType, AttackTier] = {
    # MODEL tier - Labs red-team these extensively
    AttackType.PROMPT_INJECTION: AttackTier.MODEL,
    AttackType.JAILBREAK: AttackTier.MODEL,
    AttackType.ENCODING_BYPASS: AttackTier.MODEL,
    AttackType.MULTI_TURN_ATTACK: AttackTier.MODEL,
    AttackType.CONTEXT_OVERFLOW: AttackTier.MODEL,
    # AGENT tier - Environment and system-level attacks (Khaos differentiator)
    AttackType.FILE_CONTENT_INJECTION: AttackTier.AGENT,
    AttackType.SHELL_OUTPUT_INJECTION: AttackTier.AGENT,
    AttackType.ERROR_MESSAGE_INJECTION: AttackTier.AGENT,
    AttackType.ENV_VAR_INJECTION: AttackTier.AGENT,
    AttackType.RAG_POISONING: AttackTier.AGENT,
    AttackType.INDIRECT_INJECTION: AttackTier.AGENT,
    AttackType.STATE_MANIPULATION: AttackTier.AGENT,
    AttackType.WORKFLOW_HIJACK: AttackTier.AGENT,
    AttackType.SYSTEM_PROMPT_LEAKAGE: AttackTier.AGENT,
    AttackType.PII_EXTRACTION: AttackTier.AGENT,
    AttackType.DATA_EXFILTRATION: AttackTier.AGENT,
    AttackType.PRIVILEGE_ESCALATION: AttackTier.AGENT,
    AttackType.UNAUTHORIZED_ACTION: AttackTier.AGENT,
    # TOOL tier - Tool/MCP surface attacks
    AttackType.TOOL_OUTPUT_INJECTION: AttackTier.TOOL,
    AttackType.TOOL_MANIPULATION: AttackTier.TOOL,
    AttackType.MCP_SERVER_ATTACK: AttackTier.TOOL,
    AttackType.TOOL_DESCRIPTION_INJECTION: AttackTier.TOOL,
    AttackType.API_RESPONSE_POISONING: AttackTier.TOOL,
}

def _infer_tier_from_attack_type(attack_type: AttackType) -> AttackTier:
    """Infer tier from attack type. Defaults to MODEL if unknown."""
    return _TIER_BY_ATTACK_TYPE.get(attack_type, AttackTier.MODEL)

class AttackResult(Enum):
    """Outcomes emitted after executing a security attack."""

    BLOCKED = "blocked"
    EXPLOITED = "exploited"
    PARTIAL = "partial"
    UNKNOWN = "unknown"

@dataclass
class SecurityAttack:
    """Describes a single adversarial test case.

    For multi-turn attacks, the payload field may be empty and the actual
    conversation turns are stored in metadata["turns"] as a list of dicts
    with "role" and "content" keys.

    The tier field allows explicit tier assignment, or can be left as None
    to infer from attack_type. Use effective_tier property to get the
    resolved tier.
    """

    attack_id: str
    name: str
    attack_type: AttackType
    payload: str
    injection_vector: str
    expected_behavior: str
    metadata: dict[str, Any] = field(default_factory=dict)
    # Optional explicit tier - if None, inferred from attack_type
    tier: AttackTier | None = None

    @property
    def effective_tier(self) -> AttackTier:
        """Get the resolved tier (explicit or inferred from attack_type).

        Resolution order:
        1. Explicit tier field if set
        2. metadata["tier"] string if present (backwards compatible)
        3. Inferred from attack_type via _TIER_BY_ATTACK_TYPE
        4. Default to MODEL if completely unknown
        """
        # 1. Explicit tier field
        if self.tier is not None:
            return self.tier

        # 2. Check metadata for tier string (backwards compatible)
        meta_tier = self.metadata.get("tier")
        if isinstance(meta_tier, str):
            try:
                return AttackTier(meta_tier.lower())
            except ValueError:
                pass

        # 3. Infer from attack_type
        return _infer_tier_from_attack_type(self.attack_type)

    @property
    def is_multi_turn(self) -> bool:
        """Check if this is a multi-turn attack requiring conversation state."""
        return bool(self.metadata.get("turns"))

    @property
    def turns(self) -> list[dict[str, str]]:
        """Get conversation turns for multi-turn attacks.

        Returns:
            List of dicts with "role" and "content" keys, or empty list
            if this is not a multi-turn attack.
        """
        return self.metadata.get("turns", [])

@dataclass(slots=True)
class SecurityTestResult:
    """Captured data for one executed attack."""

    attack: SecurityAttack
    result: AttackResult
    agent_response: str
    detected_vulnerabilities: tuple[str, ...]
    confidence: float
    refused: bool
    leaked_system_prompt: bool
    maintained_goal: bool
    validated_output: bool

@dataclass(slots=True)
class SecurityScore:
    """Aggregate metrics derived from all executed attacks."""

    overall_score: float
    attacks_tested: int
    attacks_blocked: int
    vulnerabilities_found: tuple[str, ...]
    prompt_injection_defense: float
    tool_validation_score: float
    leakage_prevention_score: float

__all__ = [
    "AttackTier",
    "AttackType",
    "AttackResult",
    "SecurityAttack",
    "SecurityTestResult",
    "SecurityScore",
]
