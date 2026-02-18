"""Pack-based agent evaluation.

Executes agent with evaluation packs (baseline, quickstart, full-eval, security).
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import typer
from rich.console import Group
from rich.live import Live
from rich.text import Text

from khaos.packs import (
    get_builtin_pack,
    list_builtin_packs,
    PackRunner,
    Pack,
    load_pack,
    PhaseType,
    PackInput,
    TurnResult,
    RunResult,
)
from khaos.evaluator.security_attacks import (
    ATTACKS_BY_CATEGORY,
    ALL_ATTACKS,
    get_canary_attacks,
    get_standard_attacks,
    order_attacks_by_severity,
    order_attacks_by_tier,
    filter_attacks_by_tier,
)
from khaos.security.models import SecurityAttack

# Import consolidated security scoring (single source of truth)

from .formatting import print_pack_results
from ..utils.config import merge_env_for_subprocess
from ..console import get_console

# Import refactored modules
from .capability_probe import (
    detect_agent_metadata,
    detect_agent_security_mode,
    infer_agent_capabilities,
    extract_capabilities_list,
    CAPABILITY_PROBE_INPUT_ID,
    CAPABILITY_PROBE_PROMPT,
)
from .security_runner import (
    filter_attacks_for_capabilities,
    run_agent_input_security_tests,
    evaluate_security_events,
    execute_multi_turn_attack,
    get_risk_explanation,
)
from .trace_collector import (
    extract_messages_from_events,
    build_pack_trace_from_events,
    hash_messages,
    normalize_for_hash,
)

# New class-based invokers (cleaner architecture)
from .invokers import (
    InvokerConfig,
    InvokerContext,
    create_single_turn_invoker,
    create_multi_turn_invoker as create_multi_turn_invoker_v2,
    categorize_fault,
)

# Agent discovery imports
from khaos.agent import AgentMetadata

# Sync imports
from khaos.state import get_state_dir
from khaos.cloud.queue import UploadJob, enqueue_job

# Logger for this module
logger = logging.getLogger(__name__)

# Get shared console
console = get_console()


# Backward compatibility aliases - these now call the refactored module functions
_detect_agent_metadata = detect_agent_metadata
_detect_agent_security_mode = detect_agent_security_mode
_get_risk_explanation = get_risk_explanation
_filter_attacks_for_capabilities = filter_attacks_for_capabilities
_infer_agent_capabilities = infer_agent_capabilities
_capability_dict_to_list = extract_capabilities_list


# ---------------------------------------------------------------------------
# Security event collection context (scoped per run, not module-level).
# ---------------------------------------------------------------------------

@dataclass
class _SecurityContext:
    """Thread-safe container for security event collection during a pack run."""

    events: list[dict[str, Any]] = field(default_factory=list)
    attack_configs: dict[str, dict[str, Any]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def clear(self) -> None:
        with self._lock:
            self.events = []
            self.attack_configs = {}

    def add_events(self, new_events: list[dict[str, Any]]) -> None:
        with self._lock:
            self.events.extend(new_events)

    def set_attack_config(self, attack_id: str, config: dict[str, Any]) -> None:
        with self._lock:
            self.attack_configs[attack_id] = config


# Module-level instance — reset at the start of each run via .clear().
_security_ctx = _SecurityContext()


def _clear_security_events() -> None:
    """Clear collected security events and attack configs for a new run."""
    _security_ctx.clear()


def _get_security_events() -> list[dict[str, Any]]:
    """Get the list of collected security events."""
    return _security_ctx.events


def _get_attack_configs() -> dict[str, dict[str, Any]]:
    """Get the attack configs dictionary."""
    return _security_ctx.attack_configs


def _get_attacks_for_pack(
    attack_categories: list[str | None] = None,
    attack_limit: int | None = None,
    security_config: Any | None = None,
    agent_capabilities: list[str | None] = None,
) -> list[dict[str, Any]]:
    """Get attacks based on pack configuration with tiered selection support.

    Args:
        attack_categories: List of attack categories to include.
                          If None, uses all categories.
        attack_limit: Maximum number of attacks to return.
                     If None, returns all matching attacks.
        security_config: Optional SecurityPhaseConfig for tiered selection.
                        If provided, uses tier-based attack selection.
        agent_capabilities: Optional list of agent capabilities for filtering.

    Returns:
        List of attack dicts in the format expected by the security shim:
        {attack_id, attack_type, payload, forbidden_keywords}
    """
    attacks: list[SecurityAttack] = []

    # Extract tier priority settings from security_config
    tier_priority: list[str] | None = None
    include_model_tier: bool = True  # Default: include all tiers for backwards compat

    if security_config is not None:
        tier_priority = getattr(security_config, "tier_priority", None)
        include_model_tier = getattr(security_config, "include_model_tier", True)

        # If tier_priority is set but doesn't include "model", respect include_model_tier
        if tier_priority and "model" not in tier_priority and include_model_tier:
            tier_priority = list(tier_priority) + ["model"]

    # Check for tiered selection via security_config
    if security_config is not None:
        tier = getattr(security_config, "tier", None) or "standard"
        config_categories = getattr(security_config, "categories", None)
        attacks_per_category = getattr(security_config, "attacks_per_category", 4)

        # Use config categories if specified, otherwise use attack_categories
        categories = config_categories or attack_categories or None

        # If tier_priority is set and no explicit categories, use tier-based categories
        if tier_priority and not categories:
            from khaos.capabilities import get_tiered_attack_categories
            categories = get_tiered_attack_categories(
                tier_priority=tier_priority,
                include_model_tier=include_model_tier,
            )

        if tier == "quick-scan":
            # Canary attacks only (one per category)
            attacks = get_canary_attacks(
                categories=categories,
                agent_capabilities=agent_capabilities,
            )
        elif tier == "standard":
            # Standard tier: N attacks per category, severity-ordered
            attacks = get_standard_attacks(
                categories=categories,
                agent_capabilities=agent_capabilities,
                attacks_per_category=attacks_per_category,
            )
        else:
            # full-audit or unknown: all attacks
            if categories:
                for category in categories:
                    if category in ATTACKS_BY_CATEGORY:
                        attacks.extend(ATTACKS_BY_CATEGORY[category])
            else:
                attacks = list(ALL_ATTACKS)
    else:
        # Legacy behavior: use categories and limit
        if attack_categories:
            # Get attacks from specified categories
            for category in attack_categories:
                if category in ATTACKS_BY_CATEGORY:
                    attacks.extend(ATTACKS_BY_CATEGORY[category])
        else:
            # Use all attacks
            attacks = list(ALL_ATTACKS)

    # Filter by tier if tier_priority excludes MODEL and include_model_tier is False
    if tier_priority and not include_model_tier:
        attacks = filter_attacks_by_tier(
            attacks,
            include_tiers=tier_priority,
        )

    # Order by tier (AGENT > TOOL > MODEL) if tier_priority is set
    # This ensures high-value attacks run first even with attack_limit
    if tier_priority:
        attacks = order_attacks_by_tier(attacks, tier_priority=tier_priority)
    else:
        # Order by severity (critical first) if not already ordered
        attacks = order_attacks_by_severity(attacks)

    # Apply limit if specified (after tier ordering so AGENT/TOOL attacks survive)
    if attack_limit and len(attacks) > attack_limit:
        attacks = attacks[:attack_limit]

    # Convert to shim format (dict with forbidden_keywords for detection)
    result = []
    for attack in attacks:
        required_caps: list[str] = []
        legacy_required = attack.metadata.get("required_capability")
        if isinstance(legacy_required, str) and legacy_required:
            required_caps.append(legacy_required)
        required_list = attack.metadata.get("required_capabilities")
        if isinstance(required_list, list):
            required_caps.extend([str(c) for c in required_list if str(c).strip()])
        required_caps = sorted(set(required_caps))

        result.append({
            "attack_id": attack.attack_id,
            "attack_type": attack.attack_type.value,
            "payload": attack.payload,
            "injection_vector": attack.injection_vector,
            "forbidden_keywords": attack.metadata.get("forbidden_keywords", []),
            "forbidden_tool_names": attack.metadata.get("forbidden_tool_names", []),
            "forbidden_tool_arg_markers": attack.metadata.get("forbidden_tool_arg_markers", []),
            "context_system": attack.metadata.get("context_system"),
            "severity": attack.metadata.get("severity", "medium"),
            "category": attack.attack_type.value,
            "is_canary": attack.metadata.get("is_canary", False),
            # Multi-turn attack support
            "turns": attack.metadata.get("turns"),
            # Injection vector (where the attack is delivered)
            "injection_vector": attack.injection_vector,
            # Agentic injection metadata (used by security_runner for file/command targeting)
            "target_files": attack.metadata.get("target_files"),
            "target_commands": attack.metadata.get("target_commands"),
            "inject_mode": attack.metadata.get("inject_mode"),
            # Action-based assertions (diff/tool-log verifiable)
            "action_assertions": attack.metadata.get("action_assertions"),
            # Optional per-attack agent prompt override (for realistic multi-step tasks)
            "agent_prompt": attack.metadata.get("agent_prompt"),
            # Capability gating (legacy + new)
            "required_capability": attack.metadata.get("required_capability"),
            "required_capabilities": required_caps,
        })

    return result


def _get_custom_attacks_for_phase(security_phase: Any, attack_configs: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Return custom security attacks configured in the pack phase.

    Pack schema stores these as dataclasses (`CustomSecurityAttack`) but older
    YAML drafts may contain raw dicts. This helper normalizes to the canonical
    attack dict format used by the security shim and scoring code.
    """
    raw = getattr(security_phase, "custom_attacks", None)
    if not isinstance(raw, list) or not raw:
        return []

    attacks: list[dict[str, Any]] = []
    used_ids: set[str] = set()

    for item in raw:
        attack_dict: dict[str, Any] | None = None
        if hasattr(item, "to_attack_dict") and callable(getattr(item, "to_attack_dict")):
            try:
                attack_dict = item.to_attack_dict()
            except Exception as e:
                logger.debug("Failed to convert attack to dict: %s", e)
                attack_dict = None
        elif isinstance(item, dict):
            # Accept already-normalized dicts.
            attack_dict = dict(item)

        if not attack_dict:
            continue

        attack_id = str(attack_dict.get("attack_id") or attack_dict.get("id") or "").strip()
        if not attack_id:
            continue

        # Avoid collisions with built-in IDs and other custom attacks.
        configs = attack_configs or {}
        resolved_id = attack_id
        if resolved_id in used_ids or resolved_id in configs:
            resolved_id = f"custom:{attack_id}"
        if resolved_id in used_ids or resolved_id in configs:
            # Last-resort: deterministic suffix.
            resolved_id = f"{resolved_id}:{len(used_ids) + 1}"

        used_ids.add(resolved_id)

        attack_dict["attack_id"] = resolved_id
        attack_dict.setdefault("name", attack_dict.get("attack_id"))
        attack_dict.setdefault("attack_type", attack_dict.get("category") or "prompt_injection")
        attack_dict.setdefault("payload", "")
        attack_dict.setdefault("severity", "medium")
        attack_dict.setdefault("category", attack_dict.get("attack_type"))
        attack_dict.setdefault("injection_vector", "user_input")
        attack_dict.setdefault("is_custom", True)

        # Normalize optional lists used by scoring/classification.
        for key in ("forbidden_keywords", "forbidden_tool_names", "forbidden_tool_arg_markers", "required_capabilities"):
            if not isinstance(attack_dict.get(key), list):
                attack_dict[key] = []

        attacks.append(attack_dict)

    return attacks

# Note: REFUSAL_PATTERNS, LEAK_MARKERS, and COMPROMISED_INDICATORS are now
# imported from khaos.security.scoring (single source of truth)

# Fault categorization constants
_LLM_FAULT_EXTRAS = {"model_fallback_forced", "prompt_ambiguity"}
_HTTP_FAULT_EXTRAS = {"timeout", "malformed_payload"}


def _fault_category(fault_type: str) -> str:
    """Categorize a fault type for capability-based filtering."""
    if fault_type.startswith("mcp_"):
        return "mcp"
    if fault_type.startswith("llm_") or fault_type in _LLM_FAULT_EXTRAS:
        return "llm"
    if (
        fault_type.startswith("tool_")
        or fault_type.startswith("rag_")
        or fault_type.startswith("http_")
        or fault_type in _HTTP_FAULT_EXTRAS
    ):
        return "http"
    return "llm"


def _resolve_attack_categories(
    *,
    attack_categories: list[str] | None,
    attack_bundles: list[str] | None,
    capabilities: dict[str, Any] | None,
) -> list[str] | None:
    """Resolve security attack categories from explicit config or capability-aware bundles."""

    if attack_categories:
        return list(attack_categories)

    from khaos.capabilities import security_attack_categories_for_bundles

    bundle_ids: list[str] = []
    if attack_bundles:
        bundle_ids = [str(b).strip() for b in attack_bundles if str(b).strip()]
    else:
        # Default behavior for packs that don't specify categories: be capability-aware.
        caps = capabilities or {}
        inferred = caps.get("bundles")
        if isinstance(inferred, list):
            bundle_ids = [str(b).strip() for b in inferred if str(b).strip()]

    if not bundle_ids:
        return None

    categories = security_attack_categories_for_bundles(bundle_ids)
    return categories or None


def _normalize_attack_ids(attack_ids: list[str] | None) -> list[str]:
    """Normalize attack IDs passed via CLI flags."""
    if not attack_ids:
        return []
    parsed: list[str] = []
    seen: set[str] = set()
    for raw in attack_ids:
        for token in str(raw).split(","):
            attack_id = token.strip()
            if not attack_id or attack_id in seen:
                continue
            seen.add(attack_id)
            parsed.append(attack_id)
    return parsed


def _filter_attacks_by_ids(
    attacks: list[dict[str, Any]],
    attack_ids: list[str] | None,
) -> tuple[list[dict[str, Any]], set[str]]:
    """Filter attack dicts by attack_id while preserving order."""
    requested = set(_normalize_attack_ids(attack_ids))
    if not requested:
        return list(attacks), set()

    filtered: list[dict[str, Any]] = []
    matched: set[str] = set()
    for attack in attacks:
        attack_id = str(attack.get("attack_id", "")).strip()
        if not attack_id or attack_id not in requested:
            continue
        filtered.append(attack)
        matched.add(attack_id)
    return filtered, matched


def _prepare_security_selection(
    *,
    pack: Pack,
    capabilities: dict[str, Any],
    attack_ids: list[str] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any] | None]:
    """Build security attack selection metadata and prefiltered attacks."""
    security_phase = None
    for p in pack.phases:
        if p.type.value == "security":
            security_phase = p
            break

    if security_phase is None:
        return [], [], None

    resolved_categories_safe: list[str] | None = None
    requested_bundles: list[str] = []
    tier: str | None = None

    caps_list = _capability_dict_to_list(capabilities)
    resolved_categories = _resolve_attack_categories(
        attack_categories=security_phase.attack_categories,
        attack_bundles=getattr(security_phase, "attack_bundles", None),
        capabilities=capabilities,
    )
    if isinstance(resolved_categories, list):
        resolved_categories_safe = [str(c) for c in resolved_categories if str(c).strip()]

    raw_bundles = getattr(security_phase, "attack_bundles", None)
    if isinstance(raw_bundles, list):
        requested_bundles = [str(b) for b in raw_bundles if str(b).strip()]

    if getattr(security_phase, "security_config", None) is not None:
        tier = getattr(security_phase.security_config, "tier", None)

    attacks = _get_attacks_for_pack(
        attack_categories=resolved_categories,
        attack_limit=security_phase.attack_limit,
        security_config=security_phase.security_config,
        agent_capabilities=caps_list if caps_list else None,
    )
    attacks.extend(_get_custom_attacks_for_phase(security_phase))
    attacks_candidate = list(attacks)

    filtered_attacks, matched_ids = _filter_attacks_by_ids(attacks, attack_ids)
    requested_ids = _normalize_attack_ids(attack_ids)
    missing_ids = sorted(set(requested_ids) - matched_ids)
    if missing_ids:
        available = sorted(
            {
                str(a.get("attack_id", "")).strip()
                for a in attacks_candidate
                if str(a.get("attack_id", "")).strip()
            }
        )
        sample = ", ".join(available[:10])
        suffix = "..." if len(available) > 10 else ""
        raise typer.BadParameter(
            f"Unknown attack ID(s): {', '.join(missing_ids)}. "
            f"Available attack IDs: {sample}{suffix}"
        )

    selected_attacks, skipped_attacks = _filter_attacks_for_capabilities(
        filtered_attacks,
        capabilities=capabilities,
    )
    skipped_by_reason: dict[str, int] = {}
    for item in skipped_attacks:
        reason = str(item.get("reason", "unknown"))
        skipped_by_reason[reason] = skipped_by_reason.get(reason, 0) + 1

    summary: dict[str, Any] = {
        "attack_bundles": requested_bundles,
        "resolved_categories": resolved_categories_safe,
        "tier": tier,
        "attacks_candidate": len(attacks_candidate),
        "attacks_selected": len(selected_attacks),
        "skipped_attacks": len(skipped_attacks),
        "skipped_by_reason": skipped_by_reason,
    }
    if requested_ids:
        summary["requested_attack_ids"] = requested_ids

    return selected_attacks, skipped_attacks, summary


@dataclass
class TestResult:
    """Result of a single test within a phase."""
    input_id: str
    passed: bool
    latency_ms: float = 0.0
    error: str | None = None


@dataclass
class PhaseProgress:
    """Track progress for a phase."""
    name: str
    total: int
    completed: int = 0
    started: bool = False
    finished: bool = False
    results: list[TestResult] = field(default_factory=list)


# Backward compatibility aliases - now use security_runner functions
_execute_multi_turn_security_attack = execute_multi_turn_attack
_run_agent_input_security_tests = run_agent_input_security_tests
_evaluate_security_events = evaluate_security_events
_get_risk_explanation = get_risk_explanation


def run_with_pack(
    target: str,
    pack_name: str,
    python: str,
    extra_env: dict[str, str],
    timeout: float,
    json_output: bool,
    verbose: bool,
    quiet: bool,
    custom_inputs: list[PackInput | None] = None,
    custom_inputs_source: str | None = None,
    sync_cloud: bool = False,
    name: str | None = None,
    test_filter: str | None = None,
    baseline_repeat: int | None = None,
    attack_ids: list[str] | None = None,
    pack_override: Pack | None = None,
) -> Any:
    """Run agent with an evaluation.

    Args:
        target: Path to agent entrypoint.
        pack_name: Name of the evaluation to run (e.g., 'quickstart', 'full-eval').
        python: Python interpreter to use.
        extra_env: Additional environment variables.
        timeout: Maximum execution time in seconds.
        json_output: Output results as JSON.
        verbose: Show verbose output.
        quiet: Minimal output.
        custom_inputs: Optional custom inputs to override eval's built-in inputs.
        custom_inputs_source: Source description for custom inputs.
        sync_cloud: Sync results to cloud dashboard.
        name: Name for this run.
        test_filter: Optional test ID to filter to a single test.
        baseline_repeat: Optional number of baseline runs for consistency analysis.
        attack_ids: Optional list of security attack IDs to run (filters security phase).
        pack_override: Optional in-memory pack override. When provided, this pack is run
            directly instead of loading by name/path.
    """
    # JSON output implies quiet mode (suppress all human-readable output)
    if json_output:
        quiet = True

    attack_ids = _normalize_attack_ids(attack_ids)

    # Clear any previously collected security events
    _clear_security_events()

    # Detect agent metadata from @khaosagent decorator (used for naming + capability hints).
    # If a specific handler is selected, prefer that agent's metadata for name/version.
    agent_metadata = _detect_agent_metadata(target, handler_name=extra_env.get("KHAOS_AGENT_HANDLER"))

    # Detect security mode from agent decorator
    security_mode = _detect_agent_security_mode(target)

    # Load the eval configuration (internally still called "pack")
    if pack_override is not None:
        pack = pack_override
    else:
        pack = _load_pack(pack_name)

    has_pack_security_phase = any(p.type.value == "security" for p in pack.phases)
    if attack_ids and not has_pack_security_phase and security_mode != "agent_input":
        raise typer.BadParameter(
            "--attack-id requires an evaluation with a security phase "
            "(or an agent configured with security_mode='agent_input')."
        )

    # Override baseline phase runs if --baseline-repeat is specified
    if baseline_repeat is not None and baseline_repeat >= 1:
        from khaos.packs.schema import PackPhase
        new_phases = []
        for phase in pack.phases:
            if phase.type.value == "baseline":
                # Create a new phase with updated runs count
                new_phase = PackPhase(
                    type=phase.type,
                    runs=baseline_repeat,
                    faults=phase.faults,
                    fault_schedule=phase.fault_schedule,
                    attack_categories=phase.attack_categories,
                    attack_limit=phase.attack_limit,
                    attack_bundles=getattr(phase, "attack_bundles", None),
                    security_config=phase.security_config,
                    custom_attacks=getattr(phase, "custom_attacks", None),
                )
                new_phases.append(new_phase)
                if not quiet:
                    console.print(f"[dim]Baseline repeat: {baseline_repeat} runs (for consistency analysis)[/dim]")
            else:
                new_phases.append(phase)
        pack = replace(pack, phases=new_phases)

    # Apply test filter if specified (--test flag)
    if test_filter is not None:
        matching_inputs = [inp for inp in pack.inputs if inp.id == test_filter]
        if not matching_inputs:
            available_ids = [inp.id for inp in pack.inputs]
            raise typer.BadParameter(
                f"Test '{test_filter}' not found in eval '{pack_name}'. "
                f"Available tests: {', '.join(available_ids)}"
            )
        pack = replace(pack, inputs=matching_inputs)
        if not quiet:
            console.print(f"[dim]Running single test: {test_filter}[/dim]")

    if custom_inputs is not None:
        pack = replace(pack, inputs=custom_inputs)

        if not quiet:
            source = custom_inputs_source or "custom inputs"
            console.print(f"[dim]Using custom inputs ({len(custom_inputs)}): {source}[/dim]")

        # Warn about deterministic fault schedules that won't match overridden input IDs.
        resilience_phase = None
        for phase in pack.phases:
            if phase.type.value == "resilience":
                resilience_phase = phase
                break
        if resilience_phase and resilience_phase.fault_schedule:
            scheduled_ids = set(resilience_phase.fault_schedule.keys())
            provided_ids = {getattr(inp, "id", "") for inp in custom_inputs}
            overlap = scheduled_ids.intersection(provided_ids)
            if not overlap:
                console.print(
                    "[yellow]Note:[/yellow] This pack defines a deterministic resilience fault_schedule keyed to canonical input IDs; "
                    "your custom input IDs don't match, so scheduled faults will be skipped and the phase's global faults will be used."
                )

    if not quiet:
        console.print(f"\n[bold cyan]Running eval:[/bold cyan] {pack.name} v{pack.version}")
        console.print(f"[dim]{pack.description}[/dim]")
        console.print(f"[dim]Estimated time: {pack.estimated_time}[/dim]\n")

    # In agent-input security mode, security attacks are executed after the pack run.
    # Remove the pack "security" phase from PackRunner to avoid confusing double-reporting
    # (a 1/1 "passed" placeholder phase + the real multi-attack security suite).
    pack_for_runner = pack
    if security_mode == "agent_input":
        phases = []
        for phase in pack.phases:
            phase_type = getattr(getattr(phase, "type", None), "value", None)
            if phase_type == "security":
                continue
            phases.append(phase)
        pack_for_runner = replace(pack, phases=phases)

    # Progress tracking with phase awareness for zero-code fault injection
    current_phase = [""]
    current_progress = [0, 0]
    current_input_id = [""]  # Track current input for fault_schedule lookup
    trace_events: list[dict[str, Any]] = []
    trace_lock = threading.Lock()
    probe_events: list[dict[str, Any]] = []

    # Shared state for real-time test results (thread-safe)
    test_results_lock = threading.Lock()
    test_results: dict[str, list[TestResult]] = {}  # phase -> results

    def on_progress(phase: str, current: int, total: int) -> None:
        current_phase[0] = phase
        current_progress[0] = current
        current_progress[1] = total

    def on_result(phase: str, input_id: str, passed: bool, latency_ms: float, error: str | None) -> None:
        """Callback for individual test results."""
        with test_results_lock:
            if phase not in test_results:
                test_results[phase] = []
            test_results[phase].append(TestResult(
                input_id=input_id,
                passed=passed,
                latency_ms=latency_ms,
                error=error,
            ))

    # Create phase-aware agent invoker using new class-based architecture
    target_source = Path(target).read_text() if Path(target).exists() else ""
    capabilities = _infer_agent_capabilities(agent_metadata, target_source, probe_events=None)

    # Build invoker configuration and context (shared across single/multi-turn)
    invoker_config = InvokerConfig(
        target=target,
        python=python,
        extra_env=extra_env,
        timeout=timeout,
        pack=pack,
        security_mode=security_mode,
        capabilities=capabilities,
    )
    invoker_context = InvokerContext(
        current_phase=current_phase,
        current_input_id=current_input_id,
        trace_events=trace_events,
        trace_lock=trace_lock,
        probe_events=probe_events,
        security_events=_security_ctx.events,
        attack_configs=_security_ctx.attack_configs,
    )

    def _get_attacks_for_pack_filtered(
        *,
        attack_categories: list[str | None] = None,
        attack_limit: int | None = None,
        security_config: Any | None = None,
        agent_capabilities: list[str | None] = None,
    ) -> list[dict[str, Any]]:
        attacks = _get_attacks_for_pack(
            attack_categories=attack_categories,
            attack_limit=attack_limit,
            security_config=security_config,
            agent_capabilities=agent_capabilities,
        )
        filtered, _ = _filter_attacks_by_ids(attacks, attack_ids)
        return filtered

    def _get_custom_attacks_for_phase_filtered(
        security_phase: Any,
        attack_configs: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        attacks = _get_custom_attacks_for_phase(
            security_phase,
            attack_configs=attack_configs,
        )
        filtered, _ = _filter_attacks_by_ids(attacks, attack_ids)
        return filtered

    # Create initial invoker for capability probing
    invoker = create_single_turn_invoker(
        invoker_config,
        invoker_context,
        get_attacks_fn=_get_attacks_for_pack_filtered,
        get_custom_attacks_fn=_get_custom_attacks_for_phase_filtered,
        filter_attacks_fn=_filter_attacks_for_capabilities,
        resolve_categories_fn=_resolve_attack_categories,
        capability_to_list_fn=_capability_dict_to_list,
    )

    # Capability probe (best-effort). Runs once, then rehydrates invoker with runtime signals.
    try:
        current_phase[0] = "baseline"
        current_input_id[0] = CAPABILITY_PROBE_INPUT_ID
        invoker(CAPABILITY_PROBE_PROMPT)
    except Exception:
        logger.debug("Capability probe failed", exc_info=True)
    finally:
        capabilities = _infer_agent_capabilities(agent_metadata, target_source, probe_events=probe_events)

    preselected_security_attacks, preselected_skipped_attacks, security_selection_summary = _prepare_security_selection(
        pack=pack,
        capabilities=capabilities,
        attack_ids=attack_ids,
    )
    if security_selection_summary is not None:
        capabilities["security_selection"] = security_selection_summary

    # Rebuild config and invoker with final capability profile
    invoker_config = InvokerConfig(
        target=target,
        python=python,
        extra_env=extra_env,
        timeout=timeout,
        pack=pack,
        security_mode=security_mode,
        capabilities=capabilities,
    )
    invoker = create_single_turn_invoker(
        invoker_config,
        invoker_context,
        get_attacks_fn=_get_attacks_for_pack_filtered,
        get_custom_attacks_fn=_get_custom_attacks_for_phase_filtered,
        filter_attacks_fn=_filter_attacks_for_capabilities,
        resolve_categories_fn=_resolve_attack_categories,
        capability_to_list_fn=_capability_dict_to_list,
    )

    # Callback to track current input for fault_schedule lookup
    def on_input_start(input_id: str) -> None:
        current_input_id[0] = input_id

    agent_name = agent_metadata.name if agent_metadata else Path(target).stem
    agent_version = agent_metadata.version if agent_metadata else "1.0.0"

    # Check if pack has any multi-turn inputs and create multi-turn invoker if needed
    has_multi_turn = any(inp.is_multi_turn for inp in pack_for_runner.inputs)
    multi_turn_invoker = None
    if has_multi_turn:
        multi_turn_invoker = create_multi_turn_invoker_v2(invoker_config, invoker_context)

    # Create runner with detected agent metadata
    runner = PackRunner(
        agent_invoker=invoker,
        agent_name=agent_name,
        agent_version=agent_version,
        agent_source=target_source,
        on_progress=on_progress,
        on_input_start=on_input_start,
        on_result=on_result,
        multi_turn_invoker=multi_turn_invoker,
    )

    # Run with progress display
    if quiet:
        eval_result = runner.run_pack(pack_for_runner)
    else:
        eval_result = _run_with_progress(
            runner, pack_for_runner, current_phase, current_progress,
            test_results, test_results_lock,
        )

    # Post-process: Run security testing based on mode
    security_events = _get_security_events()

    if security_mode == "agent_input":
        # Agent-input mode: Run attacks as direct agent inputs
        # This tests the full security stack including any input filtering
        attacks = list(preselected_security_attacks)
        skipped_attacks = list(preselected_skipped_attacks)

        has_security_phase = any(p.type.value == "security" for p in pack.phases)
        if not has_security_phase:
            candidate_attacks = _get_attacks_for_pack(attack_limit=6)
            attacks, matched_ids = _filter_attacks_by_ids(candidate_attacks, attack_ids)
            if attack_ids:
                missing_ids = sorted(set(attack_ids) - matched_ids)
                if missing_ids:
                    available = sorted(
                        {
                            str(a.get("attack_id", "")).strip()
                            for a in candidate_attacks
                            if str(a.get("attack_id", "")).strip()
                        }
                    )
                    sample = ", ".join(available[:10])
                    suffix = "..." if len(available) > 10 else ""
                    raise typer.BadParameter(
                        f"Unknown attack ID(s): {', '.join(missing_ids)}. "
                        f"Available attack IDs: {sample}{suffix}"
                    )
            attacks, skipped_attacks = _filter_attacks_for_capabilities(
                attacks,
                capabilities=capabilities,
            )

        if skipped_attacks:
            eval_result.report.skipped.setdefault("security_attacks", [])
            eval_result.report.skipped["security_attacks"].extend(skipped_attacks)

        # Store attack configs for evaluation
        for attack in attacks:
            _security_ctx.set_attack_config(attack["attack_id"], attack)

        # Run agent-input security tests with trace event capture
        agent_input_events = _run_agent_input_security_tests(
            target=target,
            python=python,
            extra_env=extra_env,
            timeout=timeout,
            attacks=attacks,
            quiet=quiet,
            trace_events=trace_events,  # Captures LLM telemetry for security tests
            trace_lock=trace_lock,
        )
        security_events.extend(agent_input_events)

    # Evaluate security events and update report (even if empty, so the dashboard can show "not run").
    has_security_phase = any(p.type.value == "security" for p in pack.phases)
    if has_security_phase or security_mode == "agent_input":
        eval_result.report.security = evaluate_security_events(
            security_events, attack_configs=_get_attack_configs()
        )
        eval_result.report.overall_score = eval_result.report.compute_overall_score()

    # Aggregate skipped faults from per-run metadata (capability gating).
    resilience = eval_result.phases.get(PhaseType.RESILIENCE)
    if resilience is not None:
        for run in resilience.runs:
            meta = run.metadata if isinstance(run.metadata, dict) else {}
            skipped_faults = meta.get("skipped_faults")
            if isinstance(skipped_faults, list) and skipped_faults:
                eval_result.report.skipped.setdefault("resilience_faults", [])
                eval_result.report.skipped["resilience_faults"].extend(
                    [sf for sf in skipped_faults if isinstance(sf, dict)]
                )

    security = eval_result.phases.get(PhaseType.SECURITY)
    if security is not None:
        for run in security.runs:
            meta = run.metadata if isinstance(run.metadata, dict) else {}
            skipped_attacks = meta.get("skipped_attacks")
            if isinstance(skipped_attacks, list) and skipped_attacks:
                eval_result.report.skipped.setdefault("security_attacks", [])
                eval_result.report.skipped["security_attacks"].extend(
                    [sa for sa in skipped_attacks if isinstance(sa, dict)]
                )

    # Output results
    # Always persist local artifacts so users can export/debug even without --sync.
    trace_path, metrics_path = _persist_pack_artifacts(
        eval_result.report,
        trace_events=trace_events,
        security_trace_events=None,
    )

    if json_output:
        eval_result.report.capabilities = capabilities
        from khaos.cloud.links import dashboard_evaluation_url
        from khaos.cloud.config import load_cloud_config

        payload = eval_result.report.to_dict()
        payload["artifact_paths"] = {"trace": str(trace_path), "metrics": str(metrics_path)}
        payload["dashboard_url"] = dashboard_evaluation_url(
            load_cloud_config(),
            run_id=eval_result.report.run_id,
            name=getattr(eval_result.report, "name", None),
            pack_name=eval_result.report.pack_name,
            scenario_identifier=eval_result.report.pack_name,
            agent_name=(eval_result.report.agent.name if eval_result.report.agent else None),
            agent_version=(eval_result.report.agent.version if eval_result.report.agent else None),
        )
        typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        eval_result.report.capabilities = capabilities
        print_pack_results(eval_result, verbose=verbose)

    # Save and enqueue for sync if requested
    if sync_cloud:
        _save_and_enqueue_for_sync(
            eval_result,
            target,
            quiet or json_output,
            trace_events=trace_events,
            handler_name=extra_env.get("KHAOS_AGENT_HANDLER"),
            run_name=name,
            sync_now=True,
            trace_path=trace_path,
            metrics_path=metrics_path,
        )

    return eval_result


def _infer_agent_capabilities(
    agent_metadata: AgentMetadata | None,
    target_source: str,
    *,
    probe_events: list[dict[str, Any | None]],
) -> dict[str, Any]:
    """Infer agent capabilities from decorator hints + best-effort probing."""

    from khaos.capabilities import infer_capability_profile, select_bundles

    profile, sources = infer_capability_profile(
        agent_capabilities=(agent_metadata.capabilities if agent_metadata else None),
        agent_metadata=(agent_metadata.metadata if agent_metadata else None),
        target_source=target_source,
        probe_events=probe_events,
    )

    bundles = select_bundles(profile)

    return {
        "llm": profile.llm,
        "http": profile.http,
        "web_fetch": profile.web_fetch,
        "code_execution": profile.code_execution,
        "mcp": profile.mcp,
        "tool_calling": profile.tool_calling,
        "multi_turn": profile.multi_turn,
        "rag": profile.rag,
        "files": profile.files,
        "db": profile.db,
        "email": profile.email,
        "bundles": [b.id for b in bundles],
        "sources": sources,
    }


def _save_and_enqueue_for_sync(
    eval_result: Any,
    target: str,
    quiet: bool,
    *,
    trace_events: list[dict[str, Any]],
    security_trace_events: list[dict[str, Any]] | None = None,
    handler_name: str | None = None,
    run_name: str | None = None,
    sync_now: bool = False,
    trace_path: Path | None = None,
    metrics_path: Path | None = None,
) -> None:
    """Save evaluation report to disk and enqueue for cloud sync.

    Args:
        eval_result: Complete evaluation result with phases and report
        target: Path to agent script
        quiet: If True, suppress console output
        trace_events: LLM telemetry events from all phases
        security_trace_events: Optional security test trace events to merge
    """
    report = eval_result.report
    agent_metadata = _detect_agent_metadata(target, handler_name=handler_name)
    run_id = report.run_id

    if trace_path is None or metrics_path is None:
        trace_path, metrics_path = _persist_pack_artifacts(
            report,
            trace_events=trace_events,
            security_trace_events=security_trace_events,
        )

    # Create and enqueue upload job
    agent_meta_payload: dict[str, Any] = {}
    if report.agent is not None:
        agent_meta_payload.update(getattr(report.agent, "metadata", {}) or {})
        if getattr(report.agent, "framework", None):
            agent_meta_payload.setdefault("framework", report.agent.framework)
        if getattr(report.agent, "entrypoint", None):
            agent_meta_payload.setdefault("entrypoint", report.agent.entrypoint)

    if agent_metadata is not None:
        if getattr(agent_metadata, "description", ""):
            agent_meta_payload.setdefault("description", agent_metadata.description)
        if getattr(agent_metadata, "function_name", ""):
            agent_meta_payload.setdefault("function_name", agent_metadata.function_name)
        if getattr(agent_metadata, "framework", None):
            agent_meta_payload.setdefault("framework", agent_metadata.framework)
        if getattr(agent_metadata, "entrypoint", ""):
            agent_meta_payload.setdefault("entrypoint", agent_metadata.entrypoint)

    job = UploadJob(
        run_id=run_id,
        scenario_id=report.pack_name or "pack",
        trace_path=str(trace_path),
        metrics_path=str(metrics_path),
        stderr_path=None,
        project_id=None,  # Will be set during upload
        created_at=datetime.utcnow().isoformat(),
        attempts=0,
        agent_name=report.agent.name if report.agent else "agent",
        agent_version=report.agent.version if report.agent else "0.0.0",
        agent_code_hash=report.agent.code_hash if report.agent else "",
        agent_metadata=agent_meta_payload,
        agent_category=(
            agent_metadata.category.value
            if agent_metadata is not None
            and getattr(agent_metadata, "category", None) is not None
            and hasattr(agent_metadata.category, "value")
            else (str(agent_metadata.category) if agent_metadata is not None else None)
        ),
        agent_capabilities=list(getattr(agent_metadata, "capabilities", []) or []),
        agent_signals=list(getattr(agent_metadata, "signals", []) or []),
        pack_name=report.pack_name,
        pack_version=report.pack_version,
        evaluation_report=report.to_dict(),
        # Evaluation primitive fields for grouping pack runs
        evaluation_id=report.evaluation_id,
        scenario_order=report.scenario_order,
        name=(
            run_name
            if run_name
            else " · ".join(
                [
                    report.pack_name or "Pack",
                    f"{report.agent.name if report.agent else 'agent'} v{report.agent.version if report.agent else '0.0.0'}",
                    run_id[-8:],
                ]
            )
        ),
    )

    if sync_now:
        from khaos.cloud.syncing import enqueue_and_sync

        if not quiet:
            console.print(f"\n[dim]Syncing {run_id} to dashboard...[/dim]", end=" ")
        attempt = enqueue_and_sync(job)
        if attempt.success:
            if not quiet:
                console.print("[green]done[/green]")
                if attempt.dashboard_url:
                    console.print(f"[green]✓[/green] View in dashboard: {attempt.dashboard_url}")
                export_path = Path.cwd() / f"{run_id}.json"
                console.print(f"[dim]Export artifacts:[/dim] khaos export {run_id} --out {export_path}")
                console.print(f"[dim]Local artifacts:[/dim] {trace_path}  {metrics_path}")
            return
        if not quiet:
            console.print("[yellow]upload failed; queued for retry[/yellow]")
            if attempt.error:
                console.print(f"[dim]{attempt.error}[/dim]")
    else:
        enqueue_job(job)

    if not quiet:
        console.print(f"\n[green]✓[/green] Run queued for sync: {run_id}")
        console.print("[dim]Run 'khaos sync' to upload to dashboard[/dim]")
        from khaos.cloud.links import dashboard_evaluation_url_for_job
        from khaos.cloud import load_cloud_config

        url = dashboard_evaluation_url_for_job(load_cloud_config(), job)
        if url:
            console.print(f"[dim]View in dashboard (after upload):[/dim] {url}")
        export_path = Path.cwd() / f"{run_id}.json"
        console.print(f"[dim]Export artifacts:[/dim] khaos export {run_id} --out {export_path}")
        console.print(f"[dim]Local artifacts:[/dim] {trace_path}  {metrics_path}")


def _persist_pack_artifacts(
    report: Any,
    *,
    trace_events: list[dict[str, Any]],
    security_trace_events: list[dict[str, Any]] | None,
) -> tuple[Path, Path]:
    """Persist pack trace + metrics locally regardless of sync."""
    run_id = report.run_id
    runs_dir = get_state_dir() / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    all_trace_events = list(trace_events)
    if security_trace_events:
        all_trace_events.extend(security_trace_events)

    security_attack_results = None
    try:
        security_attack_results = getattr(getattr(report, "security", None), "attack_results", None)
    except Exception:
        logger.debug("Failed to extract security attack results from report", exc_info=True)
        security_attack_results = None

    pack_trace = _build_pack_trace_from_events(
        all_trace_events,
        pack_name=report.pack_name,
        pack_version=report.pack_version,
        run_id=run_id,
        input_results=report.input_results,
        security_attack_results=security_attack_results,
    )
    trace_path = runs_dir / f"trace-{run_id}.json"
    trace_path.write_text(json.dumps(pack_trace, indent=2), encoding="utf-8")

    artifacts: list[dict[str, Any]] = []
    try:
        from khaos.evaluator.trace import TraceStatsEvaluator

        llm_stats = TraceStatsEvaluator()._llm_stats(trace_events)
        artifacts.extend(
            [
                {
                    "name": artifact.name,
                    "value": artifact.value,
                    "unit": artifact.unit,
                    "details": artifact.details,
                }
                for artifact in llm_stats.get("artifacts", [])
            ]
        )
    except Exception:
        logger.debug("Failed to extract LLM artifacts", exc_info=True)
        artifacts = []

    metrics_path = runs_dir / f"metrics-{run_id}.json"
    metrics_payload = {
        "run_id": run_id,
        "scenario": report.pack_name or "pack",
        "seed": report.seed,
        "scenario_difficulty": None,
        "scenario_difficulty_label": None,
        "resilience_report": None,
        "artifacts": artifacts,
    }

    # Add pack-level scores/counts so downstream tools (e.g. `khaos gate`) can
    # gate on modern pack runs as well as legacy scenario runs.
    try:
        metrics_payload["overall_score"] = float(getattr(report, "overall_score", 0.0) or 0.0)
    except Exception:
        metrics_payload["overall_score"] = 0.0

    security = getattr(report, "security", None)
    if security is not None:
        metrics_payload["security_score"] = getattr(security, "score", None)
        metrics_payload["security"] = {
            "percent": getattr(security, "score", None),
            "defended": getattr(security, "attacks_blocked", 0),
            "total": getattr(security, "attacks_tested", 0),
            "inconclusive": getattr(security, "attacks_inconclusive", 0),
        }

    resilience = getattr(report, "resilience", None)
    if resilience is not None:
        metrics_payload["resilience_score"] = getattr(resilience, "score", None)
        # Gate expects recovery_component in [0,1] in the older format.
        metrics_payload["resilience"] = {
            "score": getattr(resilience, "score", None),
            "recovery_component": getattr(resilience, "recovery_rate", None),
            "runs": getattr(resilience, "runs", 0),
        }

        # GA: persist resilience components so the dashboard can render the 40/30/30 breakdown.
        #
        # For pack runs, we may not have the full trace-driven evaluator components.
        # Instead, we compute a stable set of components from the pack resilience metrics:
        # - goal_component: goal recovery under faults (if available) else success recovery rate
        # - recovery_component: success recovery rate
        # - stability_component: blends latency degradation + error rate into a 0..1 stability ratio
        #
        # This allows the UI to render a consistent breakdown and compute a deterministic
        # component-based score for cross-run comparisons.
        try:
            recovery_rate = float(getattr(resilience, "recovery_rate", 0.0) or 0.0)
        except Exception:
            recovery_rate = 0.0
        try:
            error_rate = float(getattr(resilience, "error_rate", 0.0) or 0.0)
        except Exception:
            error_rate = 0.0
        try:
            degradation_percent = float(getattr(resilience, "degradation_percent", 0.0) or 0.0)
        except Exception:
            degradation_percent = 0.0

        goal_recovery_rate = getattr(resilience, "goal_recovery_rate", None)
        try:
            goal_recovery = float(goal_recovery_rate) if goal_recovery_rate is not None else None
        except Exception:
            goal_recovery = None

        goal_component = max(0.0, min(1.0, goal_recovery if goal_recovery is not None else recovery_rate))
        recovery_component = max(0.0, min(1.0, recovery_rate))

        # Latency degradation penalty is capped at 20 points in the pack resilience score.
        latency_penalty_points = min(max(0.0, degradation_percent), 20.0)
        latency_stability = max(0.0, min(1.0, 1.0 - (latency_penalty_points / 20.0)))
        error_stability = max(0.0, min(1.0, 1.0 - error_rate))

        # Blend: emphasize latency stability but still account for outright error rate.
        stability_component = max(0.0, min(1.0, 0.7 * latency_stability + 0.3 * error_stability))

        resilience_score_components = (0.4 * goal_component + 0.3 * recovery_component + 0.3 * stability_component) * 100.0

        artifacts.extend(
            [
                {
                    "name": "resilience.goal_component",
                    "value": goal_component,
                    "unit": "ratio",
                    "details": {
                        "source": "pack_report",
                        "goal_recovery_rate": goal_recovery,
                        "goals_met_under_faults": getattr(resilience, "goals_met_under_faults", 0),
                        "goals_total_under_faults": getattr(resilience, "goals_total_under_faults", 0),
                    },
                },
                {
                    "name": "resilience.recovery_component",
                    "value": recovery_component,
                    "unit": "ratio",
                    "details": {
                        "source": "pack_report",
                        "recovery_rate": recovery_rate,
                    },
                },
                {
                    "name": "resilience.stability_component",
                    "value": stability_component,
                    "unit": "ratio",
                    "details": {
                        "source": "pack_report",
                        "degradation_percent": degradation_percent,
                        "error_rate": error_rate,
                        "latency_penalty_points": latency_penalty_points,
                        "latency_stability": round(latency_stability, 4),
                        "error_stability": round(error_stability, 4),
                        "formula": "stability = clamp(0.7*(1-penalty/20) + 0.3*(1-error_rate))",
                    },
                },
                {
                    "name": "resilience.score",
                    "value": resilience_score_components,
                    "unit": "points",
                    "details": {
                        "source": "pack_report_components",
                        "formula": "100 * (0.4*goal_component + 0.3*recovery_component + 0.3*stability_component)",
                        "goal_component": goal_component,
                        "recovery_component": recovery_component,
                        "stability_component": stability_component,
                    },
                },
            ]
        )

    metrics_path.write_text(json.dumps(metrics_payload, indent=2), encoding="utf-8")
    return trace_path, metrics_path


def _load_pack(pack_name: str) -> Any:
    """Load pack by name or path."""
    available_packs = list_builtin_packs()
    if pack_name not in available_packs:
        # Check if it's a path to a pack file
        pack_path = Path(pack_name)
        if pack_path.exists() and pack_path.suffix in {".yaml", ".yml"}:
            return load_pack(pack_path)
        else:
            console.print(f"[red]Pack '{pack_name}' not found.[/red]")
            console.print(f"[dim]Available packs: {', '.join(available_packs)}[/dim]")
            raise typer.Exit(code=1)
    return get_builtin_pack(pack_name)


# Backward compatibility aliases - now use trace_collector functions
_normalize_for_hash = normalize_for_hash
_hash_messages = hash_messages
_extract_messages_from_events = extract_messages_from_events
_build_pack_trace_from_events = build_pack_trace_from_events


# Old invoker functions removed - now using invokers.py module

def _build_progress_display(
    phases: dict[str, PhaseProgress],
    spinner_frames: list[str],
    frame_idx: int,
) -> Group:
    """Build a beautiful progress display with real-time test results."""
    from khaos.ui import render_progress_bar

    elements = []

    for phase_name, phase in phases.items():
        # Phase header with status indicator
        if phase.finished:
            passed = sum(1 for r in phase.results if r.passed)
            failed = len(phase.results) - passed
            if failed == 0:
                status = "[bold green]✓[/bold green]"
            else:
                status = "[bold yellow]![/bold yellow]"
            pct = (passed / len(phase.results) * 100) if phase.results else 100
            header = Text()
            header.append(f" {status} ", style="bold")
            header.append(f"{phase_name.capitalize()}", style="bold cyan")
            header.append(f"  {passed}/{len(phase.results)} passed ({pct:.0f}%)", style="dim")
        elif phase.started:
            spinner = spinner_frames[frame_idx % len(spinner_frames)]
            pct = (phase.completed / phase.total * 100) if phase.total > 0 else 0
            header = Text()
            header.append(f" {spinner} ", style="bold cyan")
            header.append(f"{phase_name.capitalize()}", style="bold cyan")
            header.append("  ")
            header.append_text(render_progress_bar(phase.completed, phase.total))
        else:
            header = Text()
            header.append("   ", style="dim")
            header.append(f"{phase_name.capitalize()}", style="dim")
            header.append("  waiting...", style="dim")

        elements.append(header)

        # Show test results for active or completed phases
        if phase.started and phase.results:
            # Show last few results (most recent first, limit to 4)
            results_to_show = phase.results[-4:]
            for result in results_to_show:
                # Format test name nicely
                test_name = result.input_id
                if len(test_name) > 35:
                    test_name = test_name[:32] + "..."

                latency_str = f"{result.latency_ms:.0f}ms" if result.latency_ms > 0 else ""

                line = Text()
                line.append("     ")
                if result.passed:
                    line.append("✓", style="green")
                else:
                    line.append("✗", style="red")
                line.append(" ")
                line.append(f"{test_name}", style="white")
                if latency_str:
                    line.append(f" {latency_str}", style="dim")
                if result.error:
                    line.append(f" {result.error[:30]}", style="red dim")

                elements.append(line)

        elements.append(Text(""))  # Spacing between phases

    return Group(*elements)


def _run_with_progress(
    runner: PackRunner,
    pack: Any,
    current_phase: list[str],
    current_progress: list[int],
    test_results: dict[str, list[TestResult]],
    test_results_lock: threading.Lock,
) -> Any:
    """Run pack with beautiful real-time progress display."""
    # Initialize phase progress tracking
    phases: dict[str, PhaseProgress] = {}
    for phase in pack.phases:
        total = phase.runs * len(pack.inputs)
        phases[phase.type.value] = PhaseProgress(
            name=phase.type.value,
            total=total,
        )

    # Spinner frames
    spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    frame_idx = [0]

    # Run the pack in a thread
    result_holder = [None]
    error_holder = [None]

    def run_pack_thread():
        try:
            result_holder[0] = runner.run_pack(pack)
        except Exception as e:
            error_holder[0] = e

    thread = threading.Thread(target=run_pack_thread)
    thread.start()

    # Live display
    with Live(console=console, refresh_per_second=10, transient=True) as live:
        prev_phase = ""

        while thread.is_alive():
            # Update phase status
            phase_name = current_phase[0]
            completed = current_progress[0]
            total = current_progress[1]

            if phase_name and phase_name in phases:
                phase = phases[phase_name]

                # Mark phase as started
                if not phase.started:
                    phase.started = True

                phase.completed = completed

                # Copy test results for this phase (thread-safe)
                with test_results_lock:
                    if phase_name in test_results:
                        phase.results = test_results[phase_name].copy()

                # Mark previous phase as finished
                if prev_phase and prev_phase != phase_name and prev_phase in phases:
                    phases[prev_phase].finished = True
                    # Final copy of previous phase results
                    with test_results_lock:
                        if prev_phase in test_results:
                            phases[prev_phase].results = test_results[prev_phase].copy()

                prev_phase = phase_name

            # Update display
            frame_idx[0] += 1
            display = _build_progress_display(phases, spinner_frames, frame_idx[0])
            live.update(display)

            thread.join(timeout=0.1)

        # Mark all phases as finished and copy final results
        for phase_name, phase in phases.items():
            if phase.started:
                phase.finished = True
                phase.completed = phase.total
                with test_results_lock:
                    if phase_name in test_results:
                        phase.results = test_results[phase_name].copy()

        # Final display update
        display = _build_progress_display(phases, spinner_frames, frame_idx[0])
        live.update(display)

    # Print final summary outside of Live context
    console.print()
    for phase_name, phase in phases.items():
        if phase.started:
            passed = sum(1 for r in phase.results if r.passed)
            total_results = len(phase.results)
            if total_results == 0:
                total_results = phase.total
                passed = phase.total  # Assume all passed if no results
            if passed == total_results:
                console.print(f"[green]✓[/green] [bold]{phase_name.capitalize()}[/bold]: {passed}/{total_results} passed")
            else:
                console.print(f"[yellow]![/yellow] [bold]{phase_name.capitalize()}[/bold]: {passed}/{total_results} passed")
    console.print()

    if error_holder[0]:
        raise error_holder[0]

    return result_holder[0]
