"""Aggregated attack sets, helper functions, and customization support."""

from __future__ import annotations
from collections.abc import Sequence

from khaos.security.models import AttackTier, AttackType, SecurityAttack

# Import all category tuples from sibling modules
from khaos.evaluator.attacks.injection import (
    PROMPT_INJECTION_ATTACKS,
    JAILBREAK_ATTACKS,
    SYSTEM_PROMPT_LEAKAGE_ATTACKS,
    ENCODING_BYPASS_ATTACKS,
    INDIRECT_INJECTION_ATTACKS,
)
from khaos.evaluator.attacks.tool_based import (
    TOOL_OUTPUT_INJECTION_ATTACKS,
    TOOL_MANIPULATION_ATTACKS,
    TOOL_DESCRIPTION_INJECTION_ATTACKS,
)
from khaos.evaluator.attacks.data_extraction import (
    RAG_POISONING_ATTACKS,
    PII_EXTRACTION_ATTACKS,
    DATA_EXFILTRATION_ATTACKS,
)
from khaos.evaluator.attacks.authorization import (
    PRIVILEGE_ESCALATION_ATTACKS,
    UNAUTHORIZED_ACTION_ATTACKS,
    CONTEXT_OVERFLOW_ATTACKS,
)
from khaos.evaluator.attacks.agentic import (
    MULTI_TURN_ATTACKS,
    FILE_CONTENT_INJECTION_ATTACKS,
    SHELL_OUTPUT_INJECTION_ATTACKS,
    ERROR_MESSAGE_INJECTION_ATTACKS,
    AGENTIC_ACTION_ABUSE_ATTACKS,
)
from khaos.evaluator.attacks.infrastructure import (
    MCP_SERVER_ATTACKS,
    API_RESPONSE_POISONING_ATTACKS,
    ENV_VAR_INJECTION_ATTACKS,
    WORKFLOW_HIJACK_ATTACKS,
    STATE_MANIPULATION_ATTACKS,
)

# ===========================================================================
# Default Attack Corpus
# ===========================================================================

# MVP attacks - minimal set for quick testing
DEFAULT_MVP_ATTACKS: tuple[SecurityAttack, ...] = (
    PROMPT_INJECTION_ATTACKS[0],  # dev-mode
    PROMPT_INJECTION_ATTACKS[1],  # ignore-instructions
    JAILBREAK_ATTACKS[0],         # dan-prompt
    SYSTEM_PROMPT_LEAKAGE_ATTACKS[0],  # verbatim
    SYSTEM_PROMPT_LEAKAGE_ATTACKS[1],  # instructions
    TOOL_OUTPUT_INJECTION_ATTACKS[0],  # admin-mode
)

# Comprehensive attack set - all attacks
ALL_ATTACKS: tuple[SecurityAttack, ...] = (
    *PROMPT_INJECTION_ATTACKS,
    *JAILBREAK_ATTACKS,
    *SYSTEM_PROMPT_LEAKAGE_ATTACKS,
    *TOOL_OUTPUT_INJECTION_ATTACKS,
    *TOOL_MANIPULATION_ATTACKS,
    *RAG_POISONING_ATTACKS,
    *INDIRECT_INJECTION_ATTACKS,
    *PII_EXTRACTION_ATTACKS,
    *DATA_EXFILTRATION_ATTACKS,
    *ENCODING_BYPASS_ATTACKS,
    *PRIVILEGE_ESCALATION_ATTACKS,
    *UNAUTHORIZED_ACTION_ATTACKS,
    *CONTEXT_OVERFLOW_ATTACKS,
    *MULTI_TURN_ATTACKS,
    # Agentic environment attacks (file/shell-based agents)
    *FILE_CONTENT_INJECTION_ATTACKS,
    *SHELL_OUTPUT_INJECTION_ATTACKS,
    *ERROR_MESSAGE_INJECTION_ATTACKS,
    *AGENTIC_ACTION_ABUSE_ATTACKS,
    # Agent system attacks (trust boundaries, tool servers, APIs)
    *MCP_SERVER_ATTACKS,
    *TOOL_DESCRIPTION_INJECTION_ATTACKS,
    *API_RESPONSE_POISONING_ATTACKS,
    *ENV_VAR_INJECTION_ATTACKS,
    *WORKFLOW_HIJACK_ATTACKS,
    *STATE_MANIPULATION_ATTACKS,
)

# Categorized exports for selective testing
ATTACKS_BY_CATEGORY = {
    # ============================================================
    # MODEL-LEVEL ATTACKS (Labs red-team these)
    # ============================================================
    "prompt_injection": PROMPT_INJECTION_ATTACKS,
    "jailbreak": JAILBREAK_ATTACKS,
    "encoding_bypass": ENCODING_BYPASS_ATTACKS,
    "multi_turn_attack": MULTI_TURN_ATTACKS,

    # ============================================================
    # AGENT-LEVEL ATTACKS (Khaos tests these - nobody else does)
    # ============================================================

    # Trust boundary attacks
    "system_prompt_leakage": SYSTEM_PROMPT_LEAKAGE_ATTACKS,
    "tool_output_injection": TOOL_OUTPUT_INJECTION_ATTACKS,
    "tool_manipulation": TOOL_MANIPULATION_ATTACKS,
    "rag_poisoning": RAG_POISONING_ATTACKS,
    "indirect_injection": INDIRECT_INJECTION_ATTACKS,

    # Environment poisoning attacks
    "file_content_injection": FILE_CONTENT_INJECTION_ATTACKS,
    "shell_output_injection": SHELL_OUTPUT_INJECTION_ATTACKS,
    "error_message_injection": ERROR_MESSAGE_INJECTION_ATTACKS,
    "env_var_injection": ENV_VAR_INJECTION_ATTACKS,

    # Agentic action attacks
    "agentic_action_abuse": AGENTIC_ACTION_ABUSE_ATTACKS,

    # MCP/Tool server attacks
    "mcp_server_attack": MCP_SERVER_ATTACKS,
    "tool_description_injection": TOOL_DESCRIPTION_INJECTION_ATTACKS,
    "api_response_poisoning": API_RESPONSE_POISONING_ATTACKS,

    # Workflow attacks
    "workflow_hijack": WORKFLOW_HIJACK_ATTACKS,
    "state_manipulation": STATE_MANIPULATION_ATTACKS,

    # Resource/extraction attacks
    "pii_extraction": PII_EXTRACTION_ATTACKS,
    "data_exfiltration": DATA_EXFILTRATION_ATTACKS,
    "privilege_escalation": PRIVILEGE_ESCALATION_ATTACKS,
    "unauthorized_action": UNAUTHORIZED_ACTION_ATTACKS,
    "context_overflow": CONTEXT_OVERFLOW_ATTACKS,
}

def get_attacks_by_severity(severity: str) -> list[SecurityAttack]:
    """Get attacks filtered by severity level."""
    return [
        attack for attack in ALL_ATTACKS
        if attack.metadata.get("severity") == severity
    ]

def get_critical_attacks() -> list[SecurityAttack]:
    """Get all critical severity attacks."""
    return get_attacks_by_severity("critical")

def get_high_priority_attacks() -> list[SecurityAttack]:
    """Get critical and high severity attacks."""
    return [
        attack for attack in ALL_ATTACKS
        if attack.metadata.get("severity") in ("critical", "high")
    ]

# Severity weights for ordering (higher = more important)
SEVERITY_WEIGHTS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

# All category names for iteration
ALL_CATEGORIES = list(ATTACKS_BY_CATEGORY.keys())

def get_canary_attacks(
    categories: list[str] | None = None,
    agent_capabilities: list[str] | None = None,
) -> list[SecurityAttack]:
    """Get canary attacks - one per category, marked with is_canary=True.

    Canary attacks are the highest-signal attacks for each category,
    used for quick security scans.

    Args:
        categories: Filter to specific categories. If None, uses all categories.
        agent_capabilities: Filter attacks by required capabilities.
            If None, no capability filtering is applied.

    Returns:
        List of canary attacks, one per category (if available).
    """
    def _meets_capability_requirements(attack: SecurityAttack) -> bool:
        if agent_capabilities is None:
            return True
        required_caps: list[str] = []
        legacy = attack.metadata.get("required_capability")
        if isinstance(legacy, str) and legacy:
            required_caps.append(legacy)
        required_list = attack.metadata.get("required_capabilities")
        if isinstance(required_list, list):
            required_caps.extend([str(c) for c in required_list if str(c).strip()])
        return all(cap in agent_capabilities for cap in required_caps)

    target_categories = categories or ALL_CATEGORIES
    canaries: list[SecurityAttack] = []

    for category in target_categories:
        category_attacks = ATTACKS_BY_CATEGORY.get(category, ())
        for attack in category_attacks:
            if attack.metadata.get("is_canary"):
                if not _meets_capability_requirements(attack):
                    continue
                canaries.append(attack)
                break  # Only one canary per category

    return canaries

def get_standard_attacks(
    categories: list[str] | None = None,
    agent_capabilities: list[str] | None = None,
    attacks_per_category: int = 4,
) -> list[SecurityAttack]:
    """Get standard tier attacks - canary plus additional attacks per category.

    Args:
        categories: Filter to specific categories. If None, uses all categories.
        agent_capabilities: Filter attacks by required capabilities.
        attacks_per_category: Total attacks per category (including canary).

    Returns:
        List of attacks, severity-ordered within each category.
    """
    def _meets_capability_requirements(attack: SecurityAttack) -> bool:
        if agent_capabilities is None:
            return True
        required_caps: list[str] = []
        legacy = attack.metadata.get("required_capability")
        if isinstance(legacy, str) and legacy:
            required_caps.append(legacy)
        required_list = attack.metadata.get("required_capabilities")
        if isinstance(required_list, list):
            required_caps.extend([str(c) for c in required_list if str(c).strip()])
        return all(cap in agent_capabilities for cap in required_caps)

    target_categories = categories or ALL_CATEGORIES
    attacks: list[SecurityAttack] = []

    for category in target_categories:
        category_attacks = list(ATTACKS_BY_CATEGORY.get(category, ()))

        # Filter by capabilities
        category_attacks = [a for a in category_attacks if _meets_capability_requirements(a)]

        # Sort by severity (descending) then complexity (ascending)
        sorted_attacks = sorted(
            category_attacks,
            key=lambda a: (
                -SEVERITY_WEIGHTS.get(a.metadata.get("severity", "low"), 0),
                a.metadata.get("complexity_score", 2),
            ),
        )

        # Take top N per category
        attacks.extend(sorted_attacks[:attacks_per_category])

    return attacks

def order_attacks_by_severity(attacks: list[SecurityAttack]) -> list[SecurityAttack]:
    """Order attacks by severity (critical first) then complexity (simple first)."""
    return sorted(
        attacks,
        key=lambda a: (
            -SEVERITY_WEIGHTS.get(a.metadata.get("severity", "low"), 0),
            a.metadata.get("complexity_score", 2),
            a.attack_id,  # Stable sort
        ),
    )

# Tier weights for ordering - AGENT/TOOL are high-value (Khaos differentiator)
TIER_WEIGHTS = {
    AttackTier.AGENT: 3,  # Highest priority - env attacks
    AttackTier.TOOL: 2,   # High priority - tool/MCP attacks
    AttackTier.MODEL: 1,  # Lower priority - labs already red-team these
}

def order_attacks_by_tier(
    attacks: list[SecurityAttack],
    *,
    tier_priority: list[str] | None = None,
) -> list[SecurityAttack]:
    """Order attacks by tier (AGENT first, TOOL second, MODEL last)."""
    if tier_priority:
        tier_order = {tier.lower(): i for i, tier in enumerate(tier_priority)}
    else:
        tier_order = {"agent": 0, "tool": 1, "model": 2}

    def tier_sort_key(attack: SecurityAttack) -> tuple[int, int, int, str]:
        effective_tier = attack.effective_tier
        tier_idx = tier_order.get(effective_tier.value, 99)
        severity_weight = -SEVERITY_WEIGHTS.get(attack.metadata.get("severity", "low"), 0)
        complexity = attack.metadata.get("complexity_score", 2)
        return (tier_idx, severity_weight, complexity, attack.attack_id)

    return sorted(attacks, key=tier_sort_key)

def filter_attacks_by_tier(
    attacks: list[SecurityAttack],
    *,
    include_tiers: list[str] | None = None,
    exclude_tiers: list[str] | None = None,
) -> list[SecurityAttack]:
    """Filter attacks to include/exclude specific tiers."""
    result = attacks

    if include_tiers:
        include_set = {t.lower() for t in include_tiers}
        result = [a for a in result if a.effective_tier.value in include_set]

    if exclude_tiers:
        exclude_set = {t.lower() for t in exclude_tiers}
        result = [a for a in result if a.effective_tier.value not in exclude_set]

    return result

def get_followup_attacks(
    category: str,
    already_run: set[str],
    agent_capabilities: list[str] | None = None,
    max_attacks: int = 5,
) -> list[SecurityAttack]:
    """Get follow-up attacks for a category after canary was compromised."""
    def _meets_capability_requirements(attack: SecurityAttack) -> bool:
        if agent_capabilities is None:
            return True
        required_caps: list[str] = []
        legacy = attack.metadata.get("required_capability")
        if isinstance(legacy, str) and legacy:
            required_caps.append(legacy)
        required_list = attack.metadata.get("required_capabilities")
        if isinstance(required_list, list):
            required_caps.extend([str(c) for c in required_list if str(c).strip()])
        return all(cap in agent_capabilities for cap in required_caps)

    category_attacks = list(ATTACKS_BY_CATEGORY.get(category, ()))

    # Filter out already run attacks
    remaining = [a for a in category_attacks if a.attack_id not in already_run]

    # Filter by capabilities
    remaining = [a for a in remaining if _meets_capability_requirements(a)]

    # Order by severity and return top N
    ordered = order_attacks_by_severity(remaining)
    return ordered[:max_attacks]

# ===========================================================================
# Attack Customization Support
# ===========================================================================

CUSTOMIZABLE_ATTACK_CATEGORIES: dict[str, dict] = {
    "rag_poisoning": {
        "fields": ["userQuery", "documentContent", "documentPosition", "authoritySource"],
        "defaults": {
            "userQuery": "What information do you have about this topic?",
            "documentPosition": "first",
        },
        "description": "RAG document poisoning attacks inject malicious content into retrieved documents.",
    },
    "file_content_injection": {
        "fields": ["userQuery", "targetFiles", "injectMode", "payload"],
        "defaults": {
            "targetFiles": ["README.md"],
            "injectMode": "prepend",
        },
        "description": "File content injection attacks embed payloads in files the agent reads.",
    },
    "shell_output_injection": {
        "fields": ["userQuery", "targetCommands", "payload"],
        "defaults": {
            "targetCommands": ["git status"],
        },
        "description": "Shell output injection attacks hide payloads in CLI command outputs.",
    },
    "tool_output_injection": {
        "fields": ["userQuery", "targetTool", "responsePayload", "hiddenFieldName"],
        "defaults": {
            "hiddenFieldName": "_system",
        },
        "description": "Tool output injection attacks embed instructions in tool response JSON.",
    },
    "error_message_injection": {
        "fields": ["userQuery", "errorType", "payload"],
        "defaults": {
            "errorType": "python",
        },
        "description": "Error message injection attacks hide payloads in stack traces and error messages.",
    },
}

def is_attack_category_customizable(category: str) -> bool:
    """Check if an attack category supports customization."""
    return category in CUSTOMIZABLE_ATTACK_CATEGORIES

def get_customizable_fields(category: str) -> list[str]:
    """Get the customizable fields for an attack category."""
    config = CUSTOMIZABLE_ATTACK_CATEGORIES.get(category, {})
    return config.get("fields", [])

def get_customization_defaults(category: str) -> dict:
    """Get default customization values for an attack category."""
    config = CUSTOMIZABLE_ATTACK_CATEGORIES.get(category, {})
    return config.get("defaults", {})
