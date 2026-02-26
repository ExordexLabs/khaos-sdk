"""Attack registry helpers for the testing API.

Thin convenience layer around :mod:`khaos.evaluator.attack_registry`
for filtering and retrieving attacks by tier, category, or severity.
"""

from __future__ import annotations

from typing import Any

from khaos.evaluator.attack_registry import (
    AttackMetadata,
    AttackRegistry,
    get_attack_registry,
)
from khaos.security.models import AttackTier, SecurityAttack


def get_attacks(
    *,
    tier: str | AttackTier | None = None,
    category: str | None = None,
    severity: str | None = None,
    ids: list[str] | None = None,
) -> list[AttackMetadata]:
    """Query the attack registry with optional filters.

    Returns a list of :class:`AttackMetadata` matching ALL supplied filters.
    If no filters are given, returns all registered attacks.
    """
    registry = get_attack_registry()

    if ids is not None:
        results = []
        for aid in ids:
            meta = registry.get(aid)
            if meta is not None:
                results.append(meta)
        return results

    # Start with all attacks and narrow down
    candidates = list(registry.all())

    if tier is not None:
        if isinstance(tier, str):
            tier = AttackTier(tier.lower())
        candidates = [a for a in candidates if a.tier == tier]

    if category is not None:
        candidates = [a for a in candidates if a.category == category]

    if severity is not None:
        candidates = [a for a in candidates if a.severity == severity]

    return candidates


def attack_ids(
    *,
    tier: str | AttackTier | None = None,
    category: str | None = None,
    severity: str | None = None,
) -> list[str]:
    """Return just the IDs of matching attacks.

    Intended for use with ``@khaostest(attacks=[...])``.
    """
    return [a.attack_id for a in get_attacks(tier=tier, category=category, severity=severity)]


__all__ = ["get_attacks", "attack_ids"]
