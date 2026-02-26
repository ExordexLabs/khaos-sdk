"""Unit tests for khaos.testing.attacks."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from khaos.testing.attacks import attack_ids, get_attacks


def _mock_registry():
    """Create a mock attack registry with some test data."""
    from khaos.evaluator.attack_registry import AttackMetadata
    from khaos.security.models import AttackTier

    attacks = [
        AttackMetadata(
            attack_id="pi-001",
            name="Basic Injection",
            attack_type="prompt_injection",
            tier=AttackTier.MODEL,
            category="prompt_injection",
            severity="high",
            injection_vector="user_input",
            is_canary=False,
            is_multi_turn=False,
            required_capabilities=(),
            description="Basic prompt injection",
        ),
        AttackMetadata(
            attack_id="toi-001",
            name="Tool Output Injection",
            attack_type="tool_output_injection",
            tier=AttackTier.AGENT,
            category="tool_output_injection",
            severity="critical",
            injection_vector="tool_output",
            is_canary=False,
            is_multi_turn=False,
            required_capabilities=(),
            description="Tool output injection",
        ),
        AttackMetadata(
            attack_id="jb-001",
            name="Jailbreak Attempt",
            attack_type="jailbreak",
            tier=AttackTier.MODEL,
            category="jailbreak",
            severity="medium",
            injection_vector="user_input",
            is_canary=False,
            is_multi_turn=False,
            required_capabilities=(),
            description="Jailbreak attempt",
        ),
    ]

    registry = MagicMock()
    registry.all.return_value = iter(attacks)
    registry.get.side_effect = lambda aid: next(
        (a for a in attacks if a.attack_id == aid), None
    )
    registry.by_tier.side_effect = lambda t: [a for a in attacks if a.tier == t]
    registry.by_category.side_effect = lambda c: [a for a in attacks if a.category == c]
    registry.by_severity.side_effect = lambda s: [a for a in attacks if a.severity == s]
    return registry


class TestGetAttacks:
    @patch("khaos.testing.attacks.get_attack_registry")
    def test_all(self, mock_get_registry):
        mock_get_registry.return_value = _mock_registry()
        results = get_attacks()
        assert len(results) == 3

    @patch("khaos.testing.attacks.get_attack_registry")
    def test_by_tier(self, mock_get_registry):
        mock_get_registry.return_value = _mock_registry()
        results = get_attacks(tier="agent")
        assert len(results) == 1
        assert results[0].attack_id == "toi-001"

    @patch("khaos.testing.attacks.get_attack_registry")
    def test_by_severity(self, mock_get_registry):
        mock_get_registry.return_value = _mock_registry()
        results = get_attacks(severity="critical")
        assert len(results) == 1
        assert results[0].attack_id == "toi-001"

    @patch("khaos.testing.attacks.get_attack_registry")
    def test_by_category(self, mock_get_registry):
        mock_get_registry.return_value = _mock_registry()
        results = get_attacks(category="jailbreak")
        assert len(results) == 1
        assert results[0].attack_id == "jb-001"

    @patch("khaos.testing.attacks.get_attack_registry")
    def test_by_ids(self, mock_get_registry):
        mock_get_registry.return_value = _mock_registry()
        results = get_attacks(ids=["pi-001", "jb-001"])
        assert len(results) == 2

    @patch("khaos.testing.attacks.get_attack_registry")
    def test_combined_filters(self, mock_get_registry):
        mock_get_registry.return_value = _mock_registry()
        results = get_attacks(tier="model", severity="high")
        assert len(results) == 1
        assert results[0].attack_id == "pi-001"


class TestAttackIds:
    @patch("khaos.testing.attacks.get_attack_registry")
    def test_returns_ids(self, mock_get_registry):
        mock_get_registry.return_value = _mock_registry()
        ids = attack_ids(tier="model")
        assert isinstance(ids, list)
        assert "pi-001" in ids
        assert "jb-001" in ids
