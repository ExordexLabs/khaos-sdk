"""Agent capability inference and bundle selection.

This module provides a small, explicit capability profile used to:
- Filter security attacks/faults to what actually applies to an agent
- Power "capability-aware" pack bundles (Phase 1 of GA-defensible suites)
- Support tier-based attack prioritization (AGENT/TOOL over MODEL)

Capability Naming Convention:
    - Canonical names use kebab-case (e.g., "tool-calling", "file-system")
    - Aliases support underscore and legacy names for backwards compatibility
    - Use `normalize_capability()` to convert any input to canonical form
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any
import warnings

if TYPE_CHECKING:
    from khaos.security.models import AttackTier


# =============================================================================
# Canonical Capability Names (12 total)
# =============================================================================


class AgentCapability(str, Enum):
    """Canonical agent capability names.

    These are the standardized capability identifiers used across Khaos.
    All frameworks (OpenAI, Anthropic, LangChain, CrewAI, AutoGen, LlamaIndex,
    Instructor, Claude Code) should use these canonical names.

    Naming Convention:
        - kebab-case (hyphens, not underscores)
        - Lowercase
        - Descriptive but concise

    Example:
        @khaosagent(
            capabilities=[
                "tool-calling",
                "file-system",
                "http",
            ]
        )
    """

    TOOL_CALLING = "tool-calling"
    FILE_SYSTEM = "file-system"
    CODE_EXECUTION = "code-execution"
    HTTP = "http"
    WEB_SEARCH = "web-search"
    DATABASE = "database"
    RAG = "rag"
    EMAIL = "email"
    MCP = "mcp"
    MULTI_TURN = "multi-turn"
    PII_ACCESS = "pii-access"
    SECRETS_ACCESS = "secrets-access"
    # Core capability (implied for all LLM agents)
    LLM = "llm"


# Complete alias mapping for backwards compatibility
# Maps any variant to its canonical name
CAPABILITY_ALIASES: dict[str, str] = {
    # tool-calling aliases
    "tool_calling": "tool-calling",
    "tools": "tool-calling",
    "function-calling": "tool-calling",
    "function_calling": "tool-calling",
    "functions": "tool-calling",
    # file-system aliases
    "files": "file-system",
    "file-access": "file-system",
    "file_access": "file-system",
    "filesystem": "file-system",
    "file_system": "file-system",
    # code-execution aliases
    "code_execution": "code-execution",
    "execute": "code-execution",
    "code-interpreter": "code-execution",
    "code_interpreter": "code-execution",
    "sandbox": "code-execution",
    # http aliases
    "web-fetch": "http",
    "web_fetch": "http",
    "web": "http",
    "api-access": "http",
    "api_access": "http",
    "requests": "http",
    # web-search aliases
    "search": "web-search",
    "web_search": "web-search",
    "browsing": "web-search",
    "browser": "web-search",
    # database aliases
    "db": "database",
    "sql": "database",
    "data-access": "database",
    "data_access": "database",
    "knowledge-base": "database",
    "knowledge_base": "database",
    # rag aliases
    "retrieval": "rag",
    "vector-search": "rag",
    "vector_search": "rag",
    "embeddings": "rag",
    # email aliases
    "smtp": "email",
    "messaging": "email",
    # mcp aliases
    "mcp-servers": "mcp",
    "mcp_servers": "mcp",
    # multi-turn aliases
    "multi_turn": "multi-turn",
    "multiturn": "multi-turn",
    "conversation": "multi-turn",
    "chat": "multi-turn",
    # pii-access aliases
    "pii_access": "pii-access",
    "sensitive-data": "pii-access",
    "sensitive_data": "pii-access",
    "pii": "pii-access",
    # secrets-access aliases
    "secrets_access": "secrets-access",
    "vault": "secrets-access",
    "credentials": "secrets-access",
    "secrets": "secrets-access",
}

# All canonical capability names
CANONICAL_CAPABILITIES: frozenset[str] = frozenset(cap.value for cap in AgentCapability)


def normalize_capability(capability: str) -> str:
    """Normalize a capability name to its canonical form.

    This function accepts any capability name variant (with underscores,
    different naming conventions, etc.) and returns the canonical
    kebab-case name.

    Args:
        capability: The capability name to normalize (any format).

    Returns:
        The canonical capability name (kebab-case).

    Examples:
        >>> normalize_capability("tool_calling")
        'tool-calling'
        >>> normalize_capability("files")
        'file-system'
        >>> normalize_capability("web-fetch")
        'http'
        >>> normalize_capability("tool-calling")  # Already canonical
        'tool-calling'
    """
    # Lowercase and strip whitespace
    cap = capability.lower().strip()

    # Check if already canonical
    if cap in CANONICAL_CAPABILITIES:
        return cap

    # Look up in aliases
    if cap in CAPABILITY_ALIASES:
        return CAPABILITY_ALIASES[cap]

    # Try converting underscores to hyphens
    hyphenated = cap.replace("_", "-")
    if hyphenated in CANONICAL_CAPABILITIES:
        return hyphenated
    if hyphenated in CAPABILITY_ALIASES:
        return CAPABILITY_ALIASES[hyphenated]

    # Unknown capability - return as-is (lowercased with hyphens)
    # This allows custom capabilities while maintaining consistent formatting
    return hyphenated


def normalize_capabilities(capabilities: list[str]) -> list[str]:
    """Normalize a list of capability names to canonical form.

    Args:
        capabilities: List of capability names (any format).

    Returns:
        List of canonical capability names (deduplicated, sorted).
    """
    normalized = {normalize_capability(cap) for cap in capabilities}
    return sorted(normalized)


def validate_capability(capability: str, warn: bool = True) -> tuple[str, bool]:
    """Validate and normalize a capability name.

    Args:
        capability: The capability name to validate.
        warn: If True, emit a warning for non-canonical names.

    Returns:
        Tuple of (normalized_name, is_canonical) where is_canonical is True
        if the input was already in canonical form.
    """
    original = capability
    normalized = normalize_capability(capability)
    is_canonical = original.lower().strip() == normalized

    if not is_canonical and warn:
        warnings.warn(
            f"Non-canonical capability name '{original}' - use '{normalized}' instead. "
            f"See https://khaos.dev/docs/capabilities for the standard names.",
            UserWarning,
            stacklevel=3,
        )

    return normalized, is_canonical


def get_capability_aliases(canonical: str) -> list[str]:
    """Get all aliases for a canonical capability name.

    Args:
        canonical: The canonical capability name.

    Returns:
        List of all known aliases (including the canonical name itself).
    """
    aliases = [canonical]
    for alias, target in CAPABILITY_ALIASES.items():
        if target == canonical and alias not in aliases:
            aliases.append(alias)
    return aliases


@dataclass(frozen=True, slots=True)
class CapabilityProfile:
    """Normalized capability booleans for an agent entrypoint.

    These are intentionally coarse-grained so they can be sourced from:
    - explicit @khaosagent(capabilities=[...]) hints
    - @khaosagent(metadata={...}) hints (e.g. tools_enabled)
    - best-effort source/trace probing
    """

    llm: bool = False
    http: bool = False
    web_fetch: bool = False
    tool_calling: bool = False
    mcp: bool = False
    multi_turn: bool = False
    rag: bool = False
    files: bool = False
    code_execution: bool = False
    db: bool = False
    email: bool = False

    def to_required_capabilities(self) -> list[str]:
        """Return the canonical strings used by attack/fault gating."""

        ordered: list[tuple[str, bool]] = [
            ("llm", self.llm),
            ("http", self.http),
            ("web_fetch", self.web_fetch),
            ("tool_calling", self.tool_calling),
            ("mcp", self.mcp),
            ("multi_turn", self.multi_turn),
            ("rag", self.rag),
            ("files", self.files),
            ("code_execution", self.code_execution),
            ("db", self.db),
            ("email", self.email),
        ]
        return [key for key, enabled in ordered if enabled]


_WEB_TOOLS: set[str] = {
    "web_search",
    "search_web",
    "fetch_url",
    "browser",
    "browse",
    "open_url",
    "http_get",
}

_FILE_TOOLS: set[str] = {
    "read_file",
    "write_file",
    "list_directory",
    "delete_file",
    "move_file",
    "copy_file",
}

_CODE_EXECUTION_TOOLS: set[str] = {
    "run_command",
    "execute_command",
    "execute_code",
    "run_code",
    "code_interpreter",
    "shell",
    "bash",
    "terminal",
}

_DB_TOOLS: set[str] = {
    "query_db",
    "query_database",
    "database_query",
    "sql_query",
    "sqlite_query",
    # Knowledge base tools (treat as "db-like" from a security posture perspective).
    "query_knowledge",
    "add_knowledge",
    "search_knowledge",
}

_EMAIL_TOOLS: set[str] = {
    "send_email",
    "email_send",
    "gmail_send",
    "smtp_send",
}


def infer_capability_profile(
    *,
    agent_capabilities: list[str] | None,
    agent_metadata: dict[str, Any] | None,
    target_source: str,
    probe_events: list[dict[str, Any]] | None,
) -> tuple[CapabilityProfile, dict[str, Any]]:
    """Infer a capability profile with explicit hints preferred over heuristics.

    Returns:
      (profile, sources) where sources is a small diagnostics payload that can be
      included in reports for explainability.
    """

    source_lower = (target_source or "").lower()
    caps_raw = {str(c).strip().lower() for c in (agent_capabilities or [])}
    caps_from_decorator = {normalize_capability(c) for c in caps_raw}

    # Metadata hints (best-effort). In practice, @khaosagent(metadata={"tools_enabled":[...]})
    # is the most reliable source for tool surface area.
    tools_enabled: set[str] = set()
    if isinstance(agent_metadata, dict):
        raw_tools = agent_metadata.get("tools_enabled")
        if isinstance(raw_tools, list):
            tools_enabled = {str(t).strip().lower() for t in raw_tools if str(t).strip()}

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

    # Static heuristics (fallback). Keep intentionally conservative.
    static_has_llm = any(k in source_lower for k in ("openai", "anthropic", "claude", "gpt", "llm"))
    static_has_http = any(
        k in source_lower for k in ("requests.", "import requests", "httpx.", "import httpx", "urllib")
    )
    static_has_mcp = "mcp" in source_lower or "khaos_mcp" in source_lower or "KHAOS_MCP" in target_source

    tool_calling = (
        ("tool-calling" in caps_from_decorator)
        or trace_has_tool_calls
        or bool(tools_enabled)
        or ("tool_calls" in source_lower)
    )
    mcp = ("mcp" in caps_from_decorator) or trace_has_mcp or static_has_mcp

    llm = trace_has_llm or static_has_llm or ("llm" in caps_from_decorator)
    http = trace_has_http or static_has_http or ("http" in caps_from_decorator)

    multi_turn = (
        ("multi-turn" in caps_from_decorator)
        or ("multi_turn" in caps_raw)
        or ("multiturn" in caps_raw)
    )
    rag = ("rag" in caps_from_decorator) or any(
        k in source_lower for k in ("vector", "embedding", "retrieval", "chromadb", "pinecone", "faiss", "qdrant")
    )

    # Tool surface area: prefer explicit tools_enabled hints.
    web_fetch = (
        bool({"web_fetch", "web-fetch", "web_search", "web-search"}.intersection(caps_raw))
        or bool(tools_enabled.intersection(_WEB_TOOLS))
    )
    files = ("file-system" in caps_from_decorator) or bool(tools_enabled.intersection(_FILE_TOOLS))
    code_execution = (
        ("code-execution" in caps_from_decorator)
        or bool(tools_enabled.intersection(_CODE_EXECUTION_TOOLS))
    )
    db = ("database" in caps_from_decorator) or ("db" in caps_raw) or bool(tools_enabled.intersection(_DB_TOOLS))
    email = ("email" in caps_from_decorator) or bool(tools_enabled.intersection(_EMAIL_TOOLS))

    # If the agent exposes any tool surface area, treat it as tool-capable.
    if web_fetch or files or code_execution or db or email:
        tool_calling = True

    # If the agent uses tools and we recognize specific tool classes, that implies HTTP.
    if web_fetch:
        http = True

    profile = CapabilityProfile(
        llm=llm,
        http=http,
        web_fetch=web_fetch,
        tool_calling=tool_calling,
        mcp=mcp,
        multi_turn=multi_turn,
        rag=rag,
        files=files,
        code_execution=code_execution,
        db=db,
        email=email,
    )

    sources: dict[str, Any] = {
        "decorator_capabilities": sorted(caps_from_decorator),
        "tools_enabled": sorted(tools_enabled),
        "probe_events": bool(probe_events),
    }
    return profile, sources


@dataclass(frozen=True, slots=True)
class CapabilityBundle:
    """A named set of security/resilience suites to run."""

    id: str
    description: str


_BUNDLE_CATALOG: dict[str, CapabilityBundle] = {
    "security_core": CapabilityBundle(
        id="security_core",
        description="Prompt-injection/jailbreak baseline coverage (applies to all LLM agents).",
    ),
    "security_tools": CapabilityBundle(
        id="security_tools",
        description="Tool-surface attacks (tool calling, file/db/email/web fetch).",
    ),
    "security_rag": CapabilityBundle(
        id="security_rag",
        description="Retrieval/RAG poisoning and instruction-in-context risks.",
    ),
    "security_mcp": CapabilityBundle(
        id="security_mcp",
        description="MCP/tooling-specific injection and protocol risks.",
    ),
    "security_agentic": CapabilityBundle(
        id="security_agentic",
        description="Agent-environment attacks (file/shell/error/env/workflow manipulation).",
    ),
    "resilience_core": CapabilityBundle(
        id="resilience_core",
        description="Single-fault resilience for LLM and tool calls.",
    ),
    "resilience_transport": CapabilityBundle(
        id="resilience_transport",
        description="HTTP/MCP transport faults where applicable.",
    ),
    "agentic_action_abuse": CapabilityBundle(
        id="agentic_action_abuse",
        description="Agentic unsafe-action tests scored via diff/tool-log (patch laundering, persistence).",
    ),
}


_SECURITY_BUNDLE_CATEGORY_MAP: dict[str, list[str]] = {
    # Applies to essentially any LLM-backed agent (prompt injection, jailbreaks, leakage, etc.)
    "security_core": [
        "prompt_injection",
        "jailbreak",
        "system_prompt_leakage",
        "pii_extraction",
        "data_exfiltration",
        "encoding_bypass",
        "context_overflow",
        "multi_turn_attack",
    ],
    # Attacks that become more meaningful when the agent can take actions via tools.
    "security_tools": [
        "tool_output_injection",
        "tool_manipulation",
        "indirect_injection",
        "privilege_escalation",
        "unauthorized_action",
    ],
    # Retrieval poisoning and instruction-in-context risks.
    "security_rag": [
        "rag_poisoning",
        "rag_retrieval_poisoning",
        "rag_context_overflow",
        "rag_instruction_injection",
    ],
    # MCP-specific protocol and resource attacks.
    "security_mcp": [
        "mcp_protocol_injection",
        "mcp_resource_poisoning",
        "mcp_tool_hijack",
        "mcp_capability_escalation",
        "mcp_tool_description_injection",
        "mcp_server_impersonation",
        "mcp_multi_server_confusion",
        "mcp_schema_manipulation",
        # Also include tool-surface attacks for MCP tool calls
        "tool_output_injection",
        "tool_manipulation",
    ],
    # Agent-environment attacks for file/shell/code-capable agents.
    "security_agentic": [
        "file_content_injection",
        "shell_output_injection",
        "error_message_injection",
        "env_var_injection",
        "workflow_hijack",
        "state_manipulation",
        "agentic_action_abuse",
    ],
    # Agentic environment attacks (file/shell-based agents like Claude Code)
    "file_content_injection": [
        "file_content_injection",
    ],
    "shell_output_injection": [
        "shell_output_injection",
    ],
    "error_message_injection": [
        "error_message_injection",
    ],
    "agentic_action_abuse": [
        "agentic_action_abuse",
    ],
    # Category-as-bundle passthrough mappings (allow pack YAMLs to use category names directly)
    # This enables explicit per-category control without defining meta-bundles.
    "rag_poisoning": ["rag_poisoning"],
    "indirect_injection": ["indirect_injection"],
    "system_prompt_leakage": ["system_prompt_leakage"],
    "pii_extraction": ["pii_extraction"],
    "data_exfiltration": ["data_exfiltration"],
    "privilege_escalation": ["privilege_escalation"],
    "unauthorized_action": ["unauthorized_action"],
    "env_var_injection": ["env_var_injection"],
    "workflow_hijack": ["workflow_hijack"],
    "state_manipulation": ["state_manipulation"],
    "tool_output_injection": ["tool_output_injection"],
    "tool_manipulation": ["tool_manipulation"],
    "tool_description_injection": ["tool_description_injection"],
    "mcp_server_attack": ["mcp_server_attack", "mcp_protocol_injection", "mcp_resource_poisoning", "mcp_tool_hijack"],
    "api_response_poisoning": ["api_response_poisoning"],
    "prompt_injection": ["prompt_injection"],
    "jailbreak": ["jailbreak"],
    "encoding_bypass": ["encoding_bypass"],
    "multi_turn_attack": ["multi_turn_attack"],
    "context_overflow": ["context_overflow"],
    # Pack-scoped convenience bundles (kept here so YAML can stay stable):
    "security_quickstart": [
        "prompt_injection",
        "jailbreak",
        "system_prompt_leakage",
    ],
    "security_quick_scan": [
        "prompt_injection",
        "jailbreak",
        "system_prompt_leakage",
        "tool_output_injection",
        "tool_manipulation",
        "rag_poisoning",
        "indirect_injection",
        "pii_extraction",
        "data_exfiltration",
        "encoding_bypass",
        "privilege_escalation",
        "unauthorized_action",
    ],
    "security_full_eval": [
        "prompt_injection",
        "jailbreak",
        "system_prompt_leakage",
        "tool_manipulation",
        "rag_poisoning",
        "pii_extraction",
        "data_exfiltration",
        "privilege_escalation",
    ],
}

_SECURITY_CATEGORY_ORDER: list[str] = [
    # MODEL tier (labs red-team these)
    "prompt_injection",
    "jailbreak",
    "encoding_bypass",
    "context_overflow",
    "multi_turn_attack",
    # AGENT tier - environment/indirect attacks
    "file_content_injection",
    "shell_output_injection",
    "error_message_injection",
    "agentic_action_abuse",
    "rag_poisoning",
    "rag_retrieval_poisoning",
    "rag_context_overflow",
    "rag_instruction_injection",
    "indirect_injection",
    "system_prompt_leakage",
    "pii_extraction",
    "data_exfiltration",
    "privilege_escalation",
    "unauthorized_action",
    "env_var_injection",
    "workflow_hijack",
    "state_manipulation",
    # TOOL tier - tool/MCP attacks
    "tool_output_injection",
    "tool_manipulation",
    "tool_description_injection",
    "mcp_server_attack",
    "mcp_protocol_injection",
    "mcp_resource_poisoning",
    "mcp_tool_hijack",
    "mcp_capability_escalation",
    "mcp_tool_description_injection",
    "mcp_server_impersonation",
    "mcp_multi_server_confusion",
    "mcp_schema_manipulation",
    "api_response_poisoning",
]


def security_attack_categories_for_bundles(bundle_ids: list[str]) -> list[str]:
    """Expand security bundle IDs into a stable, de-duped list of attack categories."""

    selected: set[str] = set()
    for bundle_id in bundle_ids:
        selected.update(_SECURITY_BUNDLE_CATEGORY_MAP.get(bundle_id, []))

    # Preserve a stable display/execution order.
    return [cat for cat in _SECURITY_CATEGORY_ORDER if cat in selected]


def select_bundles(profile: CapabilityProfile) -> list[CapabilityBundle]:
    """Return bundles that apply to this capability profile.

    Note: bundle *selection* is Phase 1. Packs will later map bundles to concrete
    attacks/fault schedules without hardcoding agent-specific logic.
    """

    bundles: list[CapabilityBundle] = []

    # Security
    if profile.llm:
        bundles.append(_BUNDLE_CATALOG["security_core"])
    if profile.tool_calling or profile.files or profile.db or profile.email or profile.web_fetch:
        bundles.append(_BUNDLE_CATALOG["security_tools"])
    if profile.rag:
        bundles.append(_BUNDLE_CATALOG["security_rag"])
    if profile.mcp:
        bundles.append(_BUNDLE_CATALOG["security_mcp"])
    if profile.files or profile.code_execution:
        bundles.append(_BUNDLE_CATALOG["security_agentic"])

    # Resilience
    bundles.append(_BUNDLE_CATALOG["resilience_core"])
    if profile.http or profile.mcp:
        bundles.append(_BUNDLE_CATALOG["resilience_transport"])

    # De-dup while preserving order.
    seen: set[str] = set()
    ordered: list[CapabilityBundle] = []
    for bundle in bundles:
        if bundle.id not in seen:
            seen.add(bundle.id)
            ordered.append(bundle)
    return ordered


# =============================================================================
# Tier-Based Attack Prioritization
# =============================================================================
# These mappings support prioritizing AGENT/TOOL tier attacks (where Khaos
# adds unique value) over MODEL tier attacks (which labs already red-team).

# Categories grouped by tier for prioritization
_TIER_CATEGORY_MAP: dict[str, list[str]] = {
    # AGENT tier - Environment and system-level attacks (Khaos differentiator)
    "agent": [
        "file_content_injection",
        "shell_output_injection",
        "error_message_injection",
        "env_var_injection",
        "rag_poisoning",
        "indirect_injection",
        "system_prompt_leakage",
        "pii_extraction",
        "data_exfiltration",
        "privilege_escalation",
        "unauthorized_action",
        "workflow_hijack",
        "state_manipulation",
        "agentic_action_abuse",
    ],
    # TOOL tier - Tool/MCP surface attacks
    "tool": [
        "tool_output_injection",
        "tool_manipulation",
        "mcp_server_attack",
        "tool_description_injection",
        "api_response_poisoning",
        "mcp_protocol_injection",
        "mcp_resource_poisoning",
        "mcp_tool_hijack",
        "mcp_capability_escalation",
        "mcp_tool_description_injection",
        "mcp_server_impersonation",
        "mcp_multi_server_confusion",
        "mcp_schema_manipulation",
    ],
    # MODEL tier - Labs red-team these extensively
    "model": [
        "prompt_injection",
        "jailbreak",
        "encoding_bypass",
        "multi_turn_attack",
        "context_overflow",
    ],
}

# Order for displaying/executing attacks by tier
_TIER_PRIORITY_ORDER: list[str] = ["agent", "tool", "model"]


def get_categories_by_tier(tier: str) -> list[str]:
    """Get attack categories for a specific tier.

    Args:
        tier: One of "agent", "tool", "model"

    Returns:
        List of category names belonging to that tier.
    """
    return list(_TIER_CATEGORY_MAP.get(tier.lower(), []))


def get_tiered_attack_categories(
    *,
    tier_priority: list[str] | None = None,
    include_model_tier: bool = False,
    capability_profile: CapabilityProfile | None = None,
) -> list[str]:
    """Get attack categories ordered by tier priority.

    This function returns attack categories with AGENT and TOOL tier attacks
    prioritized over MODEL tier attacks. This reflects Khaos's value proposition:
    testing the agent layer that labs don't red-team.

    Args:
        tier_priority: Order of tiers to include. Defaults to ["agent", "tool"].
            If include_model_tier is True, "model" is appended.
        include_model_tier: If True, include MODEL tier attacks at the end.
        capability_profile: If provided, filter categories by agent capabilities.

    Returns:
        List of category names in tier-priority order.

    Examples:
        # Default: AGENT + TOOL tiers only
        categories = get_tiered_attack_categories()

        # Include MODEL tier for comprehensive testing
        categories = get_tiered_attack_categories(include_model_tier=True)

        # Custom tier order
        categories = get_tiered_attack_categories(tier_priority=["tool", "agent"])
    """
    if tier_priority is None:
        tier_priority = ["agent", "tool"]

    # Add model tier if requested
    if include_model_tier and "model" not in tier_priority:
        tier_priority = list(tier_priority) + ["model"]

    # Collect categories in tier order
    categories: list[str] = []
    seen: set[str] = set()

    for tier in tier_priority:
        for category in _TIER_CATEGORY_MAP.get(tier.lower(), []):
            if category not in seen:
                categories.append(category)
                seen.add(category)

    # Apply capability filtering if provided
    if capability_profile is not None:
        categories = _filter_categories_by_capability(categories, capability_profile)

    return categories


def _filter_categories_by_capability(
    categories: list[str],
    profile: CapabilityProfile,
) -> list[str]:
    """Filter categories based on agent capabilities.

    Removes categories that don't apply to this agent's capability profile.
    """
    # Define which capabilities are needed for each category type
    capability_requirements: dict[str, list[str]] = {
        # File/shell attacks require file/shell access
        "file_content_injection": ["files"],
        "shell_output_injection": ["files"],  # Agents with shell usually have files
        "error_message_injection": ["files"],
        # RAG attacks require RAG capability
        "rag_poisoning": ["rag"],
        # MCP attacks require MCP
        "mcp_server_attack": ["mcp"],
        "mcp_protocol_injection": ["mcp"],
        "mcp_resource_poisoning": ["mcp"],
        "mcp_tool_hijack": ["mcp"],
        "mcp_capability_escalation": ["mcp"],
        "mcp_tool_description_injection": ["mcp"],
        "mcp_server_impersonation": ["mcp"],
        "mcp_multi_server_confusion": ["mcp"],
        "mcp_schema_manipulation": ["mcp"],
        # Tool attacks require tool_calling
        "tool_output_injection": ["tool_calling"],
        "tool_manipulation": ["tool_calling"],
        "tool_description_injection": ["tool_calling"],
        # API attacks require http
        "api_response_poisoning": ["http"],
    }

    profile_caps = set(profile.to_required_capabilities())

    filtered: list[str] = []
    for category in categories:
        required = capability_requirements.get(category, [])
        # If no requirements specified, include by default
        # If requirements specified, at least one must be met
        if not required or any(cap in profile_caps for cap in required):
            filtered.append(category)

    return filtered


def get_tier_for_category(category: str) -> str:
    """Get the tier for a given category.

    Args:
        category: The attack category name.

    Returns:
        The tier ("agent", "tool", or "model"). Defaults to "model" if unknown.
    """
    for tier, categories in _TIER_CATEGORY_MAP.items():
        if category in categories:
            return tier
    return "model"


# Convenience bundles for tier-aware packs
_TIER_BUNDLES: dict[str, CapabilityBundle] = {
    "tier_agent": CapabilityBundle(
        id="tier_agent",
        description="High-value AGENT tier attacks (environment poisoning, data exfiltration).",
    ),
    "tier_tool": CapabilityBundle(
        id="tier_tool",
        description="High-value TOOL tier attacks (tool/MCP manipulation).",
    ),
    "tier_model": CapabilityBundle(
        id="tier_model",
        description="MODEL tier attacks (prompt injection, jailbreaks - labs red-team these).",
    ),
    "tier_prioritized": CapabilityBundle(
        id="tier_prioritized",
        description="AGENT + TOOL tier attacks prioritized (Khaos recommended default).",
    ),
}

# Register tier bundles in the main catalog
_BUNDLE_CATALOG.update(_TIER_BUNDLES)

# Map tier bundles to their categories
_SECURITY_BUNDLE_CATEGORY_MAP["tier_agent"] = _TIER_CATEGORY_MAP["agent"]
_SECURITY_BUNDLE_CATEGORY_MAP["tier_tool"] = _TIER_CATEGORY_MAP["tool"]
_SECURITY_BUNDLE_CATEGORY_MAP["tier_model"] = _TIER_CATEGORY_MAP["model"]
_SECURITY_BUNDLE_CATEGORY_MAP["tier_prioritized"] = (
    _TIER_CATEGORY_MAP["agent"] + _TIER_CATEGORY_MAP["tool"]
)


# =============================================================================
# Tool-to-Capability Inference (Auto-Detection)
# =============================================================================

# Extended tool-to-capability mappings for auto-detection
TOOL_CAPABILITY_KEYWORDS: dict[str, str] = {
    # File system tools -> file-system
    "read_file": "file-system",
    "write_file": "file-system",
    "list_directory": "file-system",
    "delete_file": "file-system",
    "move_file": "file-system",
    "copy_file": "file-system",
    "create_file": "file-system",
    "file_read": "file-system",
    "file_write": "file-system",
    "file_delete": "file-system",
    "read": "file-system",  # Common short name
    "write": "file-system",
    "edit": "file-system",
    "glob": "file-system",
    "grep": "file-system",
    # Code execution tools -> code-execution
    "execute_code": "code-execution",
    "run_code": "code-execution",
    "run_command": "code-execution",
    "bash": "code-execution",
    "shell": "code-execution",
    "exec": "code-execution",
    "spawn_process": "code-execution",
    "python": "code-execution",
    "javascript": "code-execution",
    "code_interpreter": "code-execution",
    # HTTP/Web tools -> http
    "fetch_url": "http",
    "http_get": "http",
    "http_post": "http",
    "http_request": "http",
    "api_call": "http",
    "request": "http",
    "curl": "http",
    "web_fetch": "http",
    # Web search tools -> web-search
    "web_search": "web-search",
    "search_web": "web-search",
    "google_search": "web-search",
    "bing_search": "web-search",
    "browser": "web-search",
    "browse": "web-search",
    "search": "web-search",
    # Database tools -> database
    "query_db": "database",
    "query_database": "database",
    "database_query": "database",
    "sql_query": "database",
    "sqlite_query": "database",
    "postgres_query": "database",
    "mysql_query": "database",
    "query_knowledge": "database",
    "add_knowledge": "database",
    "search_knowledge": "database",
    "vector_search": "database",
    # Email tools -> email
    "send_email": "email",
    "email_send": "email",
    "gmail_send": "email",
    "smtp_send": "email",
    "send_message": "email",
    "send_slack_message": "email",
    "send_sms": "email",
    "send_webhook": "email",
    # MCP tools -> mcp
    "invoke_mcp_tool": "mcp",
    "mcp_call": "mcp",
    "mcp_invoke": "mcp",
    "read_mcp_resource": "mcp",
    "write_mcp_resource": "mcp",
    "list_mcp_servers": "mcp",
    "get_mcp_server_status": "mcp",
    "get_prompt_template": "mcp",
    "apply_prompt_template": "mcp",
    # RAG tools -> rag
    "retrieve": "rag",
    "retrieval": "rag",
    "vector_query": "rag",
    "semantic_search": "rag",
    "embedding_search": "rag",
    "similarity_search": "rag",
    # Sensitive data tools
    "lookup_user": "pii-access",
    "list_users": "pii-access",
    "get_user": "pii-access",
    "get_secret": "secrets-access",
    "list_secrets": "secrets-access",
    "get_credential": "secrets-access",
    "export_data": "pii-access",
    "get_system_config": "secrets-access",
}


def infer_capabilities_from_tools(tool_names: list[str]) -> list[str]:
    """Infer canonical capabilities from tool names.

    This is used as a fallback when agents don't explicitly declare
    their capabilities. It analyzes the tool names to determine what
    capabilities the agent likely has.

    Args:
        tool_names: List of tool names the agent exposes.

    Returns:
        List of canonical capability names (deduplicated, sorted).

    Examples:
        >>> infer_capabilities_from_tools(["read_file", "write_file", "web_search"])
        ['file-system', 'tool-calling', 'web-search']
    """
    capabilities: set[str] = set()

    for tool_name in tool_names:
        tool_lower = tool_name.lower().strip()

        # Direct match
        if tool_lower in TOOL_CAPABILITY_KEYWORDS:
            capabilities.add(TOOL_CAPABILITY_KEYWORDS[tool_lower])
            continue

        # Partial match (check if tool name contains any keyword)
        for keyword, capability in TOOL_CAPABILITY_KEYWORDS.items():
            if keyword in tool_lower or tool_lower in keyword:
                capabilities.add(capability)
                break

    # If any tools exist, agent has tool-calling capability
    if tool_names:
        capabilities.add("tool-calling")

    return sorted(capabilities)


__all__ = [
    # Canonical capability system
    "AgentCapability",
    "CAPABILITY_ALIASES",
    "CANONICAL_CAPABILITIES",
    "normalize_capability",
    "normalize_capabilities",
    "validate_capability",
    "get_capability_aliases",
    "infer_capabilities_from_tools",
    "TOOL_CAPABILITY_KEYWORDS",
    # Capability profile
    "CapabilityProfile",
    "infer_capability_profile",
    # Bundles
    "CapabilityBundle",
    "select_bundles",
    "security_attack_categories_for_bundles",
    # Tier-based prioritization
    "get_categories_by_tier",
    "get_tiered_attack_categories",
    "get_tier_for_category",
]
