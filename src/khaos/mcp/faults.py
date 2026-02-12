"""Fault controller utilities for MCP transports."""

from __future__ import annotations

import logging
import random
from copy import deepcopy
from dataclasses import dataclass
from typing import Any
from collections.abc import Iterable

logger = logging.getLogger("khaos.mcp.faults")

@dataclass(slots=True)
class MCPFaultRule:
    type: str
    config: dict[str, Any]

@dataclass(slots=True)
class MCPFaultEffect:
    delay_ms: float = 0.0
    failure: dict[str, Any] | None = None
    corruption: dict[str, Any] | None = None

    def has_effect(self) -> bool:
        return bool(self.delay_ms or self.failure or self.corruption)

class MCPFaultController:
    """Evaluates MCP fault rules for transports."""

    def __init__(
        self,
        rules: Iterable[dict[str, Any]] | None = None,
        *,
        rng: random.Random | None = None,
    ) -> None:
        self._raw_rules = [dict(rule) for rule in (rules or [])]
        self._rules = [
            MCPFaultRule(type=str(rule.get("type", "")).lower(), config=rule.get("config", {}))
            for rule in self._raw_rules
        ]
        self._rng = rng or random.Random()
        
        if self._rules:
            logger.debug(
                "MCPFaultController initialized with %d rules: %s",
                len(self._rules),
                [r.type for r in self._rules],
            )

    def servers_marked_unavailable(self) -> set[str]:
        down: set[str] = set()
        for rule in self._rules:
            if rule.type != "mcp_server_unavailable":
                continue
            server = rule.config.get("server_name")
            if server:
                down.add(str(server))
        return down

    def describe_rules(self) -> dict[str, Any]:
        return {rule.type: rule.config for rule in self._rules}

    def raw_rules(self) -> list[dict[str, Any]]:
        return [dict(rule) for rule in self._raw_rules]

    def get_description_injections(self) -> dict[str, str]:
        """Get tool description injection payloads, keyed by tool name or '*' for all.

        Returns dict mapping tool_name (or '*') to injection payload string.
        Used by the proxy to modify tool descriptions in tools/list responses.
        """
        injections: dict[str, str] = {}
        for rule in self._rules:
            if rule.type != "mcp_tool_description_injection":
                continue
            tool = rule.config.get("tool_name", "*")
            payload = rule.config.get("payload", "")
            inject_mode = rule.config.get("inject_mode", "append")
            if payload:
                injections[str(tool)] = payload
                logger.info(
                    "MCP description injection configured: tool=%s mode=%s payload_len=%d",
                    tool, inject_mode, len(payload),
                )
        return injections

    def evaluate(
        self,
        *,
        tool_name: str,
        server_name: str,
        payload: dict[str, Any] | None = None,
    ) -> MCPFaultEffect | None:
        effect = MCPFaultEffect()
        triggered_rules: list[str] = []
        
        for rule in self._rules:
            if rule.type in ("mcp_server_unavailable", "mcp_tool_description_injection"):
                continue
            if not self._matches(rule, tool_name, server_name):
                logger.debug(
                    "Rule %s skipped: no match for tool=%s server=%s",
                    rule.type, tool_name, server_name,
                )
                continue
            if not self._should_trigger(rule.config.get("probability")):
                logger.debug(
                    "Rule %s skipped: probability check failed",
                    rule.type,
                )
                continue
            
            triggered_rules.append(rule.type)
            if rule.type == "mcp_tool_latency":
                delay = self._build_latency(rule.config)
                effect.delay_ms += delay
                logger.info(
                    "MCP fault triggered: latency +%.1fms on %s/%s",
                    delay, server_name, tool_name,
                )
            elif rule.type == "mcp_tool_failure" and effect.failure is None:
                effect.failure = self._build_failure(rule.config)
                logger.info(
                    "MCP fault triggered: failure on %s/%s - %s",
                    server_name, tool_name, effect.failure.get("failure_mode"),
                )
            elif rule.type == "mcp_tool_corruption" and effect.corruption is None:
                effect.corruption = self._build_corruption_spec(rule.config)
                logger.info(
                    "MCP fault triggered: corruption on %s/%s - %s",
                    server_name, tool_name, effect.corruption.get("corruption_type"),
                )
        
        if not effect.has_effect():
            logger.debug("No MCP faults applied to %s/%s", server_name, tool_name)
            return None
        
        logger.debug(
            "MCP fault evaluation complete for %s/%s: %s",
            server_name, tool_name, triggered_rules,
        )
        return effect

    def _matches(self, rule: MCPFaultRule, tool_name: str, server_name: str) -> bool:
        cfg = rule.config
        rule_tool = cfg.get("tool_name")
        if rule_tool and rule_tool not in {"*", tool_name}:
            return False
        rule_server = cfg.get("server_name")
        if rule_server and rule_server != server_name:
            return False
        return True

    def _should_trigger(self, probability: Any) -> bool:
        if probability is None:
            return True
        try:
            prob = float(probability)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            prob = 1.0
        prob = max(0.0, min(1.0, prob))
        return self._rng.random() <= prob

    def _build_latency(self, config: dict[str, Any]) -> float:
        base = float(config.get("delay_ms", 0.0))
        jitter = float(config.get("jitter_ms", 0.0))
        if jitter:
            delta = self._rng.uniform(-jitter, jitter)
        else:
            delta = 0.0
        return max(0.0, base + delta)

    def _build_failure(self, config: dict[str, Any]) -> dict[str, Any]:
        return {
            "failure_mode": config.get("failure_mode", "execution_error"),
            "error_message": config.get("error_message", "Injected MCP failure"),
            "status_code": config.get("status_code"),
        }

    def _build_corruption_spec(self, config: dict[str, Any]) -> dict[str, Any]:
        corruption_type = str(config.get("corruption_type", "schema_violation"))
        spec: dict[str, Any] = {"corruption_type": corruption_type}
        if corruption_type == "schema_violation":
            drop_keys = config.get("drop_keys")
            if isinstance(drop_keys, list):
                spec["drop_keys"] = list(drop_keys)
        elif corruption_type == "partial_response":
            spec["keep_fields"] = int(config.get("keep_fields", 1))
        elif corruption_type == "incorrect_data":
            spec["mutation"] = config.get("incorrect_data_mutation", "negate")
        return spec

def apply_corruption(payload: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    """Return a corrupted copy of the payload according to the spec."""
    corruption_type = spec.get("corruption_type", "schema_violation")
    logger.debug(
        "Applying corruption type=%s to payload with %d keys",
        corruption_type, len(payload),
    )

    cloned = deepcopy(payload)
    if corruption_type == "schema_violation":
        drop_keys = spec.get("drop_keys")
        if drop_keys is None:
            drop_keys = list(cloned.keys())[::2]
        for key in drop_keys:
            cloned.pop(key, None)
    elif corruption_type == "partial_response":
        keep = max(1, int(spec.get("keep_fields", max(1, len(cloned) // 2))))
        new_payload: dict[str, Any] = {}
        for idx, (key, value) in enumerate(cloned.items()):
            if idx >= keep:
                break
            new_payload[key] = value
        cloned = new_payload
    elif corruption_type == "incorrect_data":
        mutation = spec.get("mutation", "negate")
        _mutate_incorrect_data(cloned, mutation)
    return cloned

def _mutate_incorrect_data(value: Any, mutation: str) -> Any:
    if isinstance(value, dict):
        for key, inner in value.items():
            value[key] = _mutate_incorrect_data(inner, mutation)
        return value
    if isinstance(value, list):
        return [_mutate_incorrect_data(item, mutation) for item in value]
    if isinstance(value, (int, float)):
        if mutation == "randomize":
            return random.random() * 100
        return -value
    if isinstance(value, str):
        return f"CORRUPTED_{value}"
    return value
