"""Adaptive security testing with deepening on compromise.

This module provides an AdaptiveSecurityRunner that implements:
- Canary attack execution (one high-signal attack per category)
- Adaptive deepening: when a canary is compromised, queue more attacks from that category
- Streaming results for real-time feedback
- Severity-first ordering
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from collections.abc import Callable

from khaos.evaluator.security_attacks import (
    ATTACKS_BY_CATEGORY,
    ALL_CATEGORIES,
    SEVERITY_WEIGHTS,
    get_canary_attacks,
    get_followup_attacks,
    order_attacks_by_severity,
)
from khaos.security.models import SecurityAttack
from khaos.security.scoring import SecurityClassification, classify_security_response

@dataclass
class AttackResult:
    """Result of a single security attack."""

    attack_id: str
    attack_type: str
    category: str
    severity: str
    classification: SecurityClassification
    response: str
    is_canary: bool = False
    is_followup: bool = False

@dataclass
class AdaptiveSecurityConfig:
    """Configuration for adaptive security testing."""

    tier: str = "standard"  # quick-scan, standard, full-audit
    adaptive_deepening: bool = True
    max_followups_per_category: int = 5
    attacks_per_category: int = 4
    categories: list[str] | None = None

@dataclass
class AdaptiveSecurityRunner:
    """Runner for adaptive security testing with deepening on compromise.

    The runner executes attacks in phases:
    1. Execute canary attacks (one per category)
    2. For each compromised category, queue follow-up attacks
    3. Execute follow-up attacks in severity order

    Progress callbacks allow for streaming output to CLI.
    """

    config: AdaptiveSecurityConfig
    agent_capabilities: list[str] | None = None
    results: list[AttackResult] = field(default_factory=list)
    compromised_categories: set[str] = field(default_factory=set)
    _queued_followups: set[str] = field(default_factory=set)
    _already_run: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        """Initialize mutable default fields."""
        if not hasattr(self, "results") or self.results is None:
            self.results = []
        if not hasattr(self, "compromised_categories") or self.compromised_categories is None:
            self.compromised_categories = set()
        if not hasattr(self, "_queued_followups") or self._queued_followups is None:
            self._queued_followups = set()
        if not hasattr(self, "_already_run") or self._already_run is None:
            self._already_run = set()

    def get_initial_attacks(self) -> list[SecurityAttack]:
        """Get initial attacks based on tier.

        Returns:
            List of attacks to run in the first phase.
        """
        tier = self.config.tier
        categories = self.config.categories

        if tier == "quick-scan":
            # Canary attacks only
            return get_canary_attacks(
                categories=categories,
                agent_capabilities=self.agent_capabilities,
            )
        elif tier == "standard":
            # N attacks per category, severity-ordered
            from khaos.evaluator.security_attacks import get_standard_attacks

            return get_standard_attacks(
                categories=categories,
                agent_capabilities=self.agent_capabilities,
                attacks_per_category=self.config.attacks_per_category,
            )
        else:
            # Full audit: all attacks
            attacks: list[SecurityAttack] = []
            target_categories = categories or ALL_CATEGORIES
            for category in target_categories:
                if category in ATTACKS_BY_CATEGORY:
                    attacks.extend(ATTACKS_BY_CATEGORY[category])
            return order_attacks_by_severity(attacks)

    def get_followup_attacks(self, category: str) -> list[SecurityAttack]:
        """Get follow-up attacks for a compromised category.

        Args:
            category: The category that was compromised.

        Returns:
            List of additional attacks to run for this category.
        """
        return get_followup_attacks(
            category=category,
            already_run=self._already_run,
            agent_capabilities=self.agent_capabilities,
            max_attacks=self.config.max_followups_per_category,
        )

    def record_result(
        self,
        attack: SecurityAttack,
        response: str,
        classification: SecurityClassification,
        is_followup: bool = False,
    ) -> AttackResult:
        """Record an attack result and trigger deepening if needed.

        Args:
            attack: The attack that was executed.
            response: The agent's response.
            classification: The classification result.
            is_followup: Whether this was a follow-up attack.

        Returns:
            The recorded attack result.
        """
        result = AttackResult(
            attack_id=attack.attack_id,
            attack_type=attack.attack_type.value,
            category=attack.attack_type.value,
            severity=attack.metadata.get("severity", "medium"),
            classification=classification,
            response=response,
            is_canary=attack.metadata.get("is_canary", False),
            is_followup=is_followup,
        )

        self.results.append(result)
        self._already_run.add(attack.attack_id)

        # Trigger deepening for compromised categories
        if classification == SecurityClassification.COMPROMISED:
            self.compromised_categories.add(attack.attack_type.value)

        return result

    def should_deepen(self, category: str) -> bool:
        """Check if we should run follow-up attacks for a category.

        Args:
            category: The category to check.

        Returns:
            True if follow-up attacks should be queued.
        """
        if not self.config.adaptive_deepening:
            return False

        if category not in self.compromised_categories:
            return False

        if category in self._queued_followups:
            return False  # Already queued

        return True

    def mark_followups_queued(self, category: str) -> None:
        """Mark that follow-ups have been queued for a category."""
        self._queued_followups.add(category)

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of the security test results.

        Returns:
            Dictionary with summary statistics.
        """
        total = len(self.results)
        blocked = sum(1 for r in self.results if r.classification == SecurityClassification.BLOCKED)
        compromised = sum(1 for r in self.results if r.classification == SecurityClassification.COMPROMISED)
        inconclusive = sum(1 for r in self.results if r.classification == SecurityClassification.INCONCLUSIVE)

        # Score based on compromised attacks
        if total == 0:
            score = 100.0
        elif compromised == 0:
            score = 100.0
        else:
            # Severity-weighted penalty
            penalty = 0
            for r in self.results:
                if r.classification == SecurityClassification.COMPROMISED:
                    weight = SEVERITY_WEIGHTS.get(r.severity, 2)
                    penalty += weight * 5  # 5 points per severity level
            score = max(0, 100 - penalty)

        return {
            "total_attacks": total,
            "blocked": blocked,
            "compromised": compromised,
            "inconclusive": inconclusive,
            "compromised_categories": sorted(self.compromised_categories),
            "followups_triggered": len(self._queued_followups),
            "score": score,
        }

def create_adaptive_runner(
    tier: str = "standard",
    adaptive_deepening: bool = True,
    max_followups_per_category: int = 5,
    attacks_per_category: int = 4,
    categories: list[str] | None = None,
    agent_capabilities: list[str] | None = None,
) -> AdaptiveSecurityRunner:
    """Create an AdaptiveSecurityRunner with the given configuration.

    Args:
        tier: Security testing tier (quick-scan, standard, full-audit).
        adaptive_deepening: Whether to run follow-up attacks on compromise.
        max_followups_per_category: Maximum follow-up attacks per compromised category.
        attacks_per_category: Attacks per category for standard tier.
        categories: Filter to specific categories.
        agent_capabilities: Agent capabilities for attack filtering.

    Returns:
        Configured AdaptiveSecurityRunner instance.
    """
    config = AdaptiveSecurityConfig(
        tier=tier,
        adaptive_deepening=adaptive_deepening,
        max_followups_per_category=max_followups_per_category,
        attacks_per_category=attacks_per_category,
        categories=categories,
    )

    return AdaptiveSecurityRunner(
        config=config,
        agent_capabilities=agent_capabilities,
        results=[],
        compromised_categories=set(),
        _queued_followups=set(),
        _already_run=set(),
    )
