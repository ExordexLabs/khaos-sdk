"""Security attack corpus for the Khaos security evaluator.

Provides a comprehensive set of security attacks aligned with:
- OWASP LLM Top 10
- Common prompt injection patterns
- Real-world attack vectors

The attacks are organized by category and severity to enable
targeted security testing.
"""

from khaos.evaluator.attacks._builder import multi_turn_attack

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

from khaos.evaluator.attacks._helpers import (
    DEFAULT_MVP_ATTACKS,
    ALL_ATTACKS,
    ATTACKS_BY_CATEGORY,
    ALL_CATEGORIES,
    SEVERITY_WEIGHTS,
    TIER_WEIGHTS,
    get_attacks_by_severity,
    get_critical_attacks,
    get_high_priority_attacks,
    get_canary_attacks,
    get_standard_attacks,
    get_followup_attacks,
    order_attacks_by_severity,
    order_attacks_by_tier,
    filter_attacks_by_tier,
    CUSTOMIZABLE_ATTACK_CATEGORIES,
    is_attack_category_customizable,
    get_customizable_fields,
    get_customization_defaults,
)

__all__ = [
    # Builder
    "multi_turn_attack",
    # Attack sets
    "DEFAULT_MVP_ATTACKS",
    "ALL_ATTACKS",
    "ATTACKS_BY_CATEGORY",
    "ALL_CATEGORIES",
    "SEVERITY_WEIGHTS",
    "TIER_WEIGHTS",
    # Attack tuples by category
    "PROMPT_INJECTION_ATTACKS",
    "JAILBREAK_ATTACKS",
    "SYSTEM_PROMPT_LEAKAGE_ATTACKS",
    "TOOL_OUTPUT_INJECTION_ATTACKS",
    "TOOL_MANIPULATION_ATTACKS",
    "RAG_POISONING_ATTACKS",
    "INDIRECT_INJECTION_ATTACKS",
    "PII_EXTRACTION_ATTACKS",
    "DATA_EXFILTRATION_ATTACKS",
    "ENCODING_BYPASS_ATTACKS",
    "PRIVILEGE_ESCALATION_ATTACKS",
    "UNAUTHORIZED_ACTION_ATTACKS",
    "CONTEXT_OVERFLOW_ATTACKS",
    "MULTI_TURN_ATTACKS",
    # Agentic environment attacks
    "FILE_CONTENT_INJECTION_ATTACKS",
    "SHELL_OUTPUT_INJECTION_ATTACKS",
    "ERROR_MESSAGE_INJECTION_ATTACKS",
    "AGENTIC_ACTION_ABUSE_ATTACKS",
    # Infrastructure attacks
    "MCP_SERVER_ATTACKS",
    "TOOL_DESCRIPTION_INJECTION_ATTACKS",
    "API_RESPONSE_POISONING_ATTACKS",
    "ENV_VAR_INJECTION_ATTACKS",
    "WORKFLOW_HIJACK_ATTACKS",
    "STATE_MANIPULATION_ATTACKS",
    # Helper functions
    "get_attacks_by_severity",
    "get_critical_attacks",
    "get_high_priority_attacks",
    "get_canary_attacks",
    "get_standard_attacks",
    "get_followup_attacks",
    "order_attacks_by_severity",
    "order_attacks_by_tier",
    "filter_attacks_by_tier",
    # Attack customization support
    "CUSTOMIZABLE_ATTACK_CATEGORIES",
    "is_attack_category_customizable",
    "get_customizable_fields",
    "get_customization_defaults",
]
