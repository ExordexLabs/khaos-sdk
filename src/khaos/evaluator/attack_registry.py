"""Attack registry for discoverability and documentation.

Provides programmatic access to all attacks with rich metadata
for CLI listing, documentation generation, and smart selection.

Usage:
    from khaos.evaluator.attack_registry import get_attack_registry

    registry = get_attack_registry()

    # List all attacks
    for attack in registry.all():
        print(attack.attack_id, attack.tier)

    # Filter by tier
    agent_attacks = registry.by_tier(AttackTier.AGENT)

    # Filter by category
    fci_attacks = registry.by_category("file_content_injection")

    # Search
    results = registry.search("readme")

    # Statistics
    stats = registry.stats()
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from collections.abc import Iterator

from khaos.capabilities import normalize_capability
from khaos.security.models import AttackTier, AttackType, SecurityAttack

@dataclass(frozen=True, slots=True)
class AttackMetadata:
    """Rich metadata for a registered attack.

    This is a lightweight view of a SecurityAttack for registry queries,
    without carrying the full payload which can be large.
    """

    attack_id: str
    name: str
    attack_type: str
    tier: AttackTier
    category: str
    severity: str
    injection_vector: str
    is_canary: bool
    is_multi_turn: bool
    required_capabilities: tuple[str, ...]
    description: str

    # Documentation fields
    owasp_mapping: str | None = None  # e.g., "LLM01:2023"
    research_reference: str | None = None  # e.g., "arXiv:2306.05499"
    tags: tuple[str, ...] = ()

class AttackRegistry:
    """Central registry for all security attacks.

    Provides indexed access to attacks by tier, category, severity,
    and full-text search. The registry is lazily populated from the
    default attack corpus on first access.

    Thread Safety:
        The registry is read-only after initialization and safe for
        concurrent access from multiple threads.
    """

    def __init__(self) -> None:
        self._attacks: dict[str, AttackMetadata] = {}
        self._by_tier: dict[AttackTier, list[str]] = {
            AttackTier.AGENT: [],
            AttackTier.TOOL: [],
            AttackTier.MODEL: [],
        }
        self._by_category: dict[str, list[str]] = {}
        self._by_severity: dict[str, list[str]] = {}

    def register(self, attack: SecurityAttack) -> None:
        """Register an attack with computed metadata.

        Args:
            attack: The SecurityAttack to register.
        """
        meta = self._compute_metadata(attack)
        self._attacks[meta.attack_id] = meta

        # Index by tier
        self._by_tier[meta.tier].append(meta.attack_id)

        # Index by category
        self._by_category.setdefault(meta.category, []).append(meta.attack_id)

        # Index by severity
        self._by_severity.setdefault(meta.severity, []).append(meta.attack_id)

    def all(self) -> Iterator[AttackMetadata]:
        """Iterate all registered attacks.

        Returns:
            Iterator over all AttackMetadata objects.
        """
        return iter(self._attacks.values())

    def by_tier(self, tier: AttackTier) -> list[AttackMetadata]:
        """Get attacks by tier.

        Args:
            tier: The AttackTier to filter by.

        Returns:
            List of AttackMetadata for attacks in the specified tier.
        """
        ids = self._by_tier.get(tier, [])
        return [self._attacks[attack_id] for attack_id in ids]

    def by_category(self, category: str) -> list[AttackMetadata]:
        """Get attacks by category.

        Args:
            category: The category name (e.g., "file_content_injection").

        Returns:
            List of AttackMetadata for attacks in the specified category.
        """
        ids = self._by_category.get(category, [])
        return [self._attacks[attack_id] for attack_id in ids]

    def by_severity(self, severity: str) -> list[AttackMetadata]:
        """Get attacks by severity.

        Args:
            severity: The severity level ("critical", "high", "medium", "low").

        Returns:
            List of AttackMetadata for attacks with the specified severity.
        """
        ids = self._by_severity.get(severity.lower(), [])
        return [self._attacks[attack_id] for attack_id in ids]

    def get(self, attack_id: str) -> AttackMetadata | None:
        """Get attack by ID.

        Args:
            attack_id: The unique attack identifier.

        Returns:
            AttackMetadata if found, None otherwise.
        """
        return self._attacks.get(attack_id)

    def search(self, query: str) -> list[AttackMetadata]:
        """Search attacks by ID, name, or description.

        Performs case-insensitive substring matching against attack_id,
        name, and description fields.

        Args:
            query: The search query string.

        Returns:
            List of AttackMetadata matching the query.
        """
        query_lower = query.lower()
        results = []
        for meta in self._attacks.values():
            if (
                query_lower in meta.attack_id.lower()
                or query_lower in meta.name.lower()
                or query_lower in meta.description.lower()
            ):
                results.append(meta)
        return results

    def stats(self) -> dict[str, Any]:
        """Get registry statistics.

        Returns:
            Dictionary with counts by tier, category, severity, etc.
        """
        return {
            "total_attacks": len(self._attacks),
            "by_tier": {tier.value: len(ids) for tier, ids in self._by_tier.items()},
            "by_category": {cat: len(ids) for cat, ids in self._by_category.items()},
            "by_severity": {sev: len(ids) for sev, ids in self._by_severity.items()},
            "categories": sorted(self._by_category.keys()),
            "tiers": [tier.value for tier in AttackTier],
        }

    def categories(self) -> list[str]:
        """Get all registered categories.

        Returns:
            Sorted list of category names.
        """
        return sorted(self._by_category.keys())

    def __len__(self) -> int:
        """Return the number of registered attacks."""
        return len(self._attacks)

    def __contains__(self, attack_id: str) -> bool:
        """Check if an attack ID is registered."""
        return attack_id in self._attacks

    @staticmethod
    def _normalize_cap(cap: str) -> str:
        """Normalize capability names to canonical form.

        This uses the centralized normalize_capability function from
        khaos.capabilities to ensure consistent alias resolution across
        the entire system.

        Examples:
            - "tool_calling" -> "tool-calling"
            - "files" -> "file-system"
            - "web-fetch" -> "http"
        """
        return normalize_capability(cap)

    @staticmethod
    def _compute_metadata(attack: SecurityAttack) -> AttackMetadata:
        """Compute rich metadata from SecurityAttack.

        Args:
            attack: The SecurityAttack to extract metadata from.

        Returns:
            AttackMetadata with all computed fields.
        """
        meta = attack.metadata or {}

        # Extract required capabilities (handle both single string and list)
        # Normalize capability names to canonical form (e.g., "files" -> "file-system")
        required_caps: list[str] = []
        if "required_capability" in meta:
            cap = meta["required_capability"]
            if isinstance(cap, str):
                required_caps.append(AttackRegistry._normalize_cap(cap))
            elif isinstance(cap, list):
                required_caps.extend(AttackRegistry._normalize_cap(str(c)) for c in cap)
        if "required_capabilities" in meta:
            caps = meta["required_capabilities"]
            if isinstance(caps, list):
                required_caps.extend(AttackRegistry._normalize_cap(str(c)) for c in caps)

        # Extract tags
        tags = meta.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]

        return AttackMetadata(
            attack_id=attack.attack_id,
            name=attack.name,
            attack_type=attack.attack_type.value,
            tier=attack.effective_tier,
            category=attack.attack_type.value,
            severity=str(meta.get("severity", "medium")).lower(),
            injection_vector=attack.injection_vector,
            is_canary=bool(meta.get("is_canary", False)),
            is_multi_turn=attack.is_multi_turn,
            required_capabilities=tuple(required_caps),
            description=attack.expected_behavior,
            owasp_mapping=meta.get("owasp_mapping"),
            research_reference=meta.get("research_reference"),
            tags=tuple(str(t) for t in tags),
        )

    @classmethod
    def default(cls) -> "AttackRegistry":
        """Create registry with all built-in attacks.

        This lazily loads the attack corpus from security_attacks.py
        and registers all attacks.

        Returns:
            AttackRegistry populated with all built-in attacks.
        """
        from khaos.evaluator.security_attacks import ALL_ATTACKS

        registry = cls()
        for attack in ALL_ATTACKS:
            registry.register(attack)
        return registry

# =============================================================================
# Singleton access
# =============================================================================

_DEFAULT_REGISTRY: AttackRegistry | None = None

def get_attack_registry() -> AttackRegistry:
    """Get the default attack registry (lazy-loaded singleton).

    The registry is created on first access and cached for subsequent calls.
    This provides efficient access to attack metadata without reloading
    the attack corpus each time.

    Returns:
        The default AttackRegistry with all built-in attacks.
    """
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = AttackRegistry.default()
    return _DEFAULT_REGISTRY

def reset_attack_registry() -> None:
    """Reset the default registry singleton (for testing)."""
    global _DEFAULT_REGISTRY
    _DEFAULT_REGISTRY = None

__all__ = [
    "AttackMetadata",
    "AttackRegistry",
    "get_attack_registry",
    "reset_attack_registry",
]
