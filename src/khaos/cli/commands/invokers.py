"""Agent invoker classes for pack evaluation.

Provides clean, class-based invokers replacing nested closure functions:
- SingleTurnInvoker: For standard single-turn agent execution
- MultiTurnInvoker: For multi-turn conversation execution

These classes encapsulate:
- Environment setup and subprocess management
- Fault injection configuration
- Telemetry event collection
- Security attack injection (LLM mode)
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Callable

from khaos.packs import PackInput, TurnResult, RunResult

from ..utils.config import merge_env_for_subprocess
from .capability_probe import CAPABILITY_PROBE_INPUT_ID

# Fault type categorization helpers
_LLM_FAULT_EXTRAS = {"model_fallback_forced", "prompt_ambiguity"}
_HTTP_FAULT_EXTRAS = {"timeout", "malformed_payload"}

def categorize_fault(fault_type: str) -> str:
    """Categorize a fault type into llm, http, or mcp."""
    if fault_type.startswith("llm_") or fault_type in _LLM_FAULT_EXTRAS:
        return "llm"
    if fault_type.startswith("mcp_"):
        return "mcp"
    if (
        fault_type.startswith("tool_")
        or fault_type.startswith("rag_")
        or fault_type.startswith("http_")
        or fault_type in _HTTP_FAULT_EXTRAS
    ):
        return "http"
    return "llm"  # Default to LLM

@dataclass
class InvokerConfig:
    """Configuration for agent invokers."""

    target: str
    python: str
    extra_env: dict[str, str]
    timeout: float
    pack: Any
    security_mode: str = "agent_input"
    capabilities: dict[str, Any] | None = None

@dataclass
class InvokerContext:
    """Mutable context shared during invocation."""

    current_phase: list[str] = field(default_factory=lambda: [""])
    current_input_id: list[str] = field(default_factory=lambda: [""])
    trace_events: list[dict[str, Any]] | None = None
    trace_lock: threading.Lock | None = None
    probe_events: list[dict[str, Any]] | None = None
    security_events: list[dict[str, Any]] | None = None
    attack_configs: dict[str, dict[str, Any]] | None = None

@dataclass
class InvocationMetadata:
    """Metadata from a single invocation."""

    applied_faults: list[str] = field(default_factory=list)
    skipped_faults: list[dict[str, Any]] = field(default_factory=list)
    skipped_attacks: list[dict[str, Any]] = field(default_factory=list)
    khaos_checks: dict[str, Any] = field(default_factory=lambda: {"passed": True, "errors": []})
    khaos_skip: bool = False
    khaos_skip_reason: str | None = None

class SingleTurnInvoker:
    """Invoker for single-turn agent execution.

    Handles:
    - Environment setup with auto-wrap shim
    - Fault injection (LLM, HTTP, MCP)
    - Security attack injection (LLM mode)
    - Telemetry event collection
    """

    def __init__(
        self,
        config: InvokerConfig,
        context: InvokerContext,
        *,
        get_attacks_fn: Callable[..., list[dict[str, Any]]] | None = None,
        get_custom_attacks_fn: Callable[..., list[dict[str, Any]]] | None = None,
        filter_attacks_fn: Callable[..., tuple[list, list]] | None = None,
        resolve_categories_fn: Callable[..., list[str]] | None = None,
        capability_to_list_fn: Callable[..., list[str] | None] | None = None,
    ):
        self.config = config
        self.context = context
        self._get_attacks_fn = get_attacks_fn
        self._get_custom_attacks_fn = get_custom_attacks_fn
        self._filter_attacks_fn = filter_attacks_fn
        self._resolve_categories_fn = resolve_categories_fn
        self._capability_to_list_fn = capability_to_list_fn
        self._last_metadata: InvocationMetadata | None = None

    @property
    def last_metadata(self) -> dict[str, Any]:
        """Get metadata from last invocation as dict."""
        if self._last_metadata is None:
            return {}
        return {
            "applied_faults": self._last_metadata.applied_faults,
            "skipped_faults": self._last_metadata.skipped_faults,
            "skipped_attacks": self._last_metadata.skipped_attacks,
            "khaos_checks": self._last_metadata.khaos_checks,
            "khaos_skip": self._last_metadata.khaos_skip,
            "khaos_skip_reason": self._last_metadata.khaos_skip_reason,
        }

    def __call__(self, input_text: str) -> str:
        """Invoke the agent with input text."""
        return self.invoke(input_text)

    def invoke(self, input_text: str) -> str:
        """Invoke agent script with input and return output."""
        # Reset metadata
        self._last_metadata = InvocationMetadata()

        # Build environment
        env = self._build_environment(input_text)
        event_file = env["KHAOS_LLM_EVENT_FILE"]

        phase_name = self.context.current_phase[0]
        is_probe = self.context.current_input_id[0] == CAPABILITY_PROBE_INPUT_ID

        # Configure faults
        faults_to_apply, skipped_faults = self._configure_faults(env, phase_name, is_probe)
        self._last_metadata.skipped_faults = skipped_faults

        if faults_to_apply is None:
            # Skip signal - no applicable faults
            return ""

        # Configure security attacks (LLM mode)
        skipped_attacks = self._configure_security_attacks(env, phase_name, is_probe)
        self._last_metadata.skipped_attacks = skipped_attacks

        # Execute agent
        response_text, run_error, captured_events = self._execute_agent(env, input_text, event_file)

        # Process captured events
        self._process_events(captured_events, faults_to_apply, phase_name, is_probe)

        # Run dependency checks
        check_errors = self._run_dependency_checks(faults_to_apply, captured_events)
        self._last_metadata.khaos_checks = {
            "passed": len(check_errors) == 0,
            "errors": check_errors,
        }

        # Set applied faults in metadata
        self._last_metadata.applied_faults = [
            str(getattr(f, "type", "") or "") for f in faults_to_apply
        ] if faults_to_apply else []

        if run_error is not None:
            raise run_error

        return response_text

    def _build_environment(self, input_text: str) -> dict[str, str]:
        """Build environment variables for agent execution."""
        target_path = Path(self.config.target).resolve()
        env = merge_env_for_subprocess(target_path, self.config.extra_env)
        env["KHAOS_AGENT_INPUT"] = input_text
        env["KHAOS_AUTO_WRAP"] = "1"
        env["KHAOS_LLM_SHIM"] = "1"

        # Create event file for telemetry
        event_fd, event_file = tempfile.mkstemp(suffix=".jsonl", prefix="khaos_events_")
        os.close(event_fd)
        env["KHAOS_LLM_EVENT_FILE"] = event_file

        return env

    def _get_phase_config(self, phase_name: str) -> Any:
        """Get phase configuration from pack."""
        for p in self.config.pack.phases:
            if p.type.value == phase_name:
                return p
        return None

    def _configure_faults(
        self,
        env: dict[str, str],
        phase_name: str,
        is_probe: bool,
    ) -> tuple[list[Any] | None, list[dict[str, Any]]]:
        """Configure fault injection. Returns (faults_to_apply, skipped_faults) or (None, skipped) for skip."""
        phase = self._get_phase_config(phase_name)

        caps = self.config.capabilities or {}
        has_llm = bool(caps.get("llm"))
        has_http = bool(caps.get("http"))
        has_mcp = bool(caps.get("mcp"))

        # Get faults from fault_schedule or global faults
        faults_to_apply = []
        if phase:
            input_id = self.context.current_input_id[0]
            if phase.fault_schedule and input_id in phase.fault_schedule:
                faults_to_apply = phase.fault_schedule[input_id]
            elif phase.faults:
                faults_to_apply = phase.faults

        skipped_faults: list[dict[str, Any]] = []
        applied_faults: list[Any] = []

        if faults_to_apply:
            for fault in faults_to_apply:
                fault_type = str(getattr(fault, "type", "") or "")
                category = categorize_fault(fault_type)
                if category == "llm" and not has_llm:
                    skipped_faults.append({"fault_type": fault_type, "reason": "agent_has_no_llm"})
                    continue
                if category == "http" and not has_http:
                    skipped_faults.append({"fault_type": fault_type, "reason": "agent_has_no_http"})
                    continue
                if category == "mcp" and not has_mcp:
                    skipped_faults.append({"fault_type": fault_type, "reason": "agent_has_no_mcp"})
                    continue
                applied_faults.append(fault)

            faults_to_apply = applied_faults

            # Skip if resilience phase has no applicable faults
            if phase_name == "resilience" and not faults_to_apply and not is_probe:
                self._last_metadata.khaos_skip = True
                self._last_metadata.khaos_skip_reason = "no_applicable_faults_for_agent"
                return None, skipped_faults

        # Set fault environment variables
        if faults_to_apply:
            llm_faults, http_faults, mcp_faults = self._categorize_faults(faults_to_apply)
            if llm_faults:
                env["KHAOS_LLM_FAULTS"] = json.dumps(llm_faults)
            if http_faults:
                env["KHAOS_HTTP_FAULTS"] = json.dumps(http_faults)
            if mcp_faults:
                env["KHAOS_MCP_FAULTS"] = json.dumps(mcp_faults)

        return faults_to_apply, skipped_faults

    def _categorize_faults(self, faults: list[Any]) -> tuple[list, list, list]:
        """Categorize faults into LLM, HTTP, and MCP."""
        llm_faults = []
        http_faults = []
        mcp_faults = []

        for fault in faults:
            fault_config = {**fault.config, "probability": fault.probability}
            fault_dict = {"type": fault.type, "config": fault_config}

            category = categorize_fault(fault.type)
            if category == "llm":
                llm_faults.append(fault_dict)
            elif category == "mcp":
                mcp_faults.append(fault_dict)
            else:
                http_faults.append(fault_dict)

        return llm_faults, http_faults, mcp_faults

    def _configure_security_attacks(
        self,
        env: dict[str, str],
        phase_name: str,
        is_probe: bool,
    ) -> list[dict[str, Any]]:
        """Configure security attacks for LLM mode. Returns skipped attacks."""
        skipped_attacks: list[dict[str, Any]] = []

        if phase_name != "security" or self.config.security_mode != "llm" or is_probe:
            return skipped_attacks

        if not all([self._get_attacks_fn, self._get_custom_attacks_fn, self._filter_attacks_fn]):
            return skipped_attacks

        security_phase = self._get_phase_config("security")
        if not security_phase:
            return skipped_attacks

        # Resolve attack categories
        resolved_categories = []
        if self._resolve_categories_fn:
            resolved_categories = self._resolve_categories_fn(
                attack_categories=security_phase.attack_categories,
                attack_bundles=getattr(security_phase, "attack_bundles", None),
                capabilities=self.config.capabilities,
            )

        caps_list = None
        if self._capability_to_list_fn:
            caps_list = self._capability_to_list_fn(self.config.capabilities)

        attacks = self._get_attacks_fn(
            attack_categories=resolved_categories,
            attack_limit=security_phase.attack_limit,
            security_config=security_phase.security_config,
            agent_capabilities=caps_list,
        )
        attacks.extend(self._get_custom_attacks_fn(security_phase))

        attacks, skipped_attacks = self._filter_attacks_fn(attacks, capabilities=self.config.capabilities)

        # Store attack configs for evaluation
        if self.context.attack_configs is not None:
            for attack in attacks:
                self.context.attack_configs[attack["attack_id"]] = attack

        if attacks:
            env["KHAOS_SECURITY_ATTACKS"] = json.dumps(attacks)
            env["KHAOS_SECURITY_ATTACK_MODE"] = "interleave"

        return skipped_attacks

    def _execute_agent(
        self,
        env: dict[str, str],
        input_text: str,
        event_file: str,
    ) -> tuple[str, Exception | None, list[dict[str, Any]]]:
        """Execute agent subprocess. Returns (response, error, captured_events)."""
        target_path = Path(self.config.target).resolve()
        command = [self.config.python, "-m", "khaos.agent_runner", "--script", str(target_path)]

        response_text = ""
        run_error: Exception | None = None
        captured: list[dict[str, Any]] = []
        result = None

        try:
            result = subprocess.run(
                command,
                env=env,
                capture_output=True,
                text=True,
                input=json.dumps({"name": "input", "payload": {"text": input_text}}) + "\n",
                timeout=self.config.timeout,
                cwd=Path(self.config.target).parent,
            )
            if result.returncode != 0:
                if result.stderr:
                    raise RuntimeError(result.stderr[:500])
                raise RuntimeError(f"Agent exited with code {result.returncode}")
            response_text = (result.stdout or "").strip()
        except subprocess.TimeoutExpired:
            run_error = RuntimeError(f"Agent timed out after {self.config.timeout}s")
        except Exception as e:
            run_error = e
        finally:
            # Read events from file
            try:
                event_path = Path(event_file)
                if event_path.exists():
                    now = datetime.now(timezone.utc).isoformat()
                    captured.append({"event": "transport.send", "ts": now, "payload": {"content": input_text}})
                    if result is not None:
                        stdout = (result.stdout or "").strip()
                        captured.append({"event": "transport.receive", "ts": now, "payload": {"content": stdout}})

                    with event_path.open("r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                event = json.loads(line)
                                if isinstance(event, dict) and "event" in event:
                                    captured.append(event)
                            except json.JSONDecodeError:
                                pass
            except OSError:
                pass

            # Clean up event file
            try:
                os.unlink(event_file)
            except OSError:
                pass

        return response_text, run_error, captured

    def _process_events(
        self,
        captured: list[dict[str, Any]],
        faults_to_apply: list[Any],
        phase_name: str,
        is_probe: bool,
    ) -> None:
        """Process captured events: add context, store traces."""
        input_id = self.context.current_input_id[0] or "unknown"
        fault_types: list[str] = []
        if faults_to_apply:
            fault_types = [
                getattr(fault, "type", "") for fault in faults_to_apply if getattr(fault, "type", None)
            ]

        context_payload = {
            "phase": phase_name or "unknown",
            "input_id": input_id,
            "faults": fault_types,
            "security_mode": self.config.security_mode if (phase_name or "").lower() == "security" else None,
        }

        for item in captured:
            if isinstance(item, dict):
                if "context" not in item:
                    item["context"] = context_payload
                # Collect security events
                if (
                    not is_probe
                    and item.get("event") == "security.attack"
                    and phase_name == "security"
                    and self.context.security_events is not None
                ):
                    self.context.security_events.append(item)

        if is_probe:
            if self.context.probe_events is not None:
                self.context.probe_events.extend([e for e in captured if isinstance(e, dict)])
        else:
            if self.context.trace_events is not None:
                if self.context.trace_lock is None:
                    self.context.trace_events.extend(captured)
                else:
                    with self.context.trace_lock:
                        self.context.trace_events.extend(captured)

    def _run_dependency_checks(
        self,
        faults_to_apply: list[Any],
        captured: list[dict[str, Any]],
    ) -> list[str]:
        """Run dependency enforcement checks."""
        errors: list[str] = []
        if not faults_to_apply or not captured:
            return errors

        fault_types = [str(getattr(f, "type", "") or "") for f in faults_to_apply]
        event_names = [str(e.get("event", "")) for e in captured if isinstance(e, dict)]

        requires_llm = any(categorize_fault(ft) == "llm" for ft in fault_types)
        requires_http = any(categorize_fault(ft) == "http" for ft in fault_types)
        requires_mcp = any(categorize_fault(ft) == "mcp" for ft in fault_types)

        if requires_llm and "llm.call" not in event_names:
            errors.append(
                "Expected at least one LLM call (llm.call) for the injected LLM fault(s), but none were observed."
            )
        if requires_http and not any(name == "http.request" for name in event_names):
            errors.append(
                "Expected at least one HTTP/tool request (http.request) for the injected HTTP/tool/RAG fault(s), but none were observed."
            )
        if requires_mcp and not any(name.startswith("mcp.") for name in event_names):
            errors.append(
                "Expected at least one MCP tool call (mcp.*) for the injected MCP fault(s), but none were observed."
            )

        return errors

class MultiTurnInvoker:
    """Invoker for multi-turn agent execution.

    Uses SubprocessTransport to maintain agent process across turns.
    """

    def __init__(
        self,
        config: InvokerConfig,
        context: InvokerContext,
    ):
        self.config = config
        self.context = context

    def __call__(self, inp: PackInput, phase: str, run_index: int) -> RunResult:
        """Execute a multi-turn conversation."""
        return self.invoke(inp, phase, run_index)

    def invoke(self, inp: PackInput, phase: str, run_index: int) -> RunResult:
        """Execute a multi-turn conversation and return result."""
        from khaos.transport.subprocess import SubprocessTransport, SubprocessConfig
        from khaos.transport.base import TransportMessage

        target_path = Path(self.config.target).resolve()

        # Get phase configuration
        phase_config = self._get_phase_config(phase)

        # Build environment
        env = self._build_environment(target_path)
        event_file = env["KHAOS_LLM_EVENT_FILE"]

        # Build command
        command = self._build_command(target_path)

        config = SubprocessConfig(
            command=command,
            working_dir=target_path.parent,
            env=env,
            read_timeout=self.config.timeout,
        )

        transport = SubprocessTransport(config)
        loop = asyncio.new_event_loop()

        # Initialize tracking
        turn_results: list[TurnResult] = []
        total_latency = 0.0
        final_response = ""
        run_error: str | None = None
        skipped_faults: list[dict[str, Any]] = []
        applied_phase_faults: list[Any] = []
        khaos_check_errors: list[str] = []

        try:
            loop.run_until_complete(transport._ensure_started())

            # Get user turns
            user_turns = inp.get_user_turns()
            has_turn_faults = any(bool(faults) for _, faults in user_turns)

            # Configure phase-level faults
            applied_phase_faults, skipped_faults, skip_result = self._configure_phase_faults(
                phase_config, inp, phase, run_index, has_turn_faults
            )
            if skip_result is not None:
                return skip_result

            # Execute turns
            for turn_idx, (content, turn_faults) in enumerate(user_turns):
                turn_result = self._execute_turn(
                    loop, transport, TransportMessage, turn_idx, content,
                    turn_faults, applied_phase_faults, inp
                )
                turn_results.append(turn_result)
                total_latency += turn_result.latency_ms

                if turn_result.response:
                    final_response = turn_result.response

                if turn_result.error:
                    run_error = turn_result.error
                    break

        except Exception as e:
            run_error = str(e)
        finally:
            # Cleanup
            try:
                loop.run_until_complete(transport.close())
            except Exception:
                pass
            loop.close()

            # Process events
            emitted_for_checks = self._process_events_from_file(
                event_file, turn_results, phase, inp
            )

            # Clean up event file
            try:
                os.unlink(event_file)
            except OSError:
                pass

        # Run dependency checks
        khaos_check_errors = self._run_dependency_checks(
            applied_phase_faults, turn_results, emitted_for_checks
        )

        # Check final goal
        final_goal_met = None
        if inp.goal and final_response:
            from khaos.packs.runner import _check_goal
            final_goal_met = _check_goal(final_response, inp.goal)

        success = run_error is None and all(t.error is None for t in turn_results)
        checks_met = (
            len(khaos_check_errors) == 0
            if (applied_phase_faults or any(t.faults_applied for t in turn_results))
            else None
        )

        fault_types = self._collect_fault_types(applied_phase_faults, turn_results)

        return RunResult(
            input_id=inp.id,
            success=success,
            latency_ms=total_latency,
            response=final_response,
            tokens_in=0,
            tokens_out=0,
            error=run_error,
            goal_met=final_goal_met,
            checks_met=checks_met,
            check_errors=list(khaos_check_errors),
            is_multi_turn=True,
            turn_count=len(turn_results),
            turns=turn_results,
            metadata={
                "phase": phase,
                "run_index": run_index,
                "is_multi_turn": True,
                "applied_faults": sorted({str(ft) for ft in fault_types if ft}),
                "skipped_faults": skipped_faults,
                "khaos_checks": {"passed": len(khaos_check_errors) == 0, "errors": khaos_check_errors},
            },
        )

    def _get_phase_config(self, phase: str) -> Any:
        """Get phase configuration from pack."""
        for p in self.config.pack.phases:
            if getattr(p, "type", None) and getattr(p.type, "value", None) == phase:
                return p
        return None

    def _build_environment(self, target_path: Path) -> dict[str, str]:
        """Build environment for multi-turn execution."""
        env = merge_env_for_subprocess(target_path, self.config.extra_env)
        env["KHAOS_AUTO_WRAP"] = "1"
        env["KHAOS_LLM_SHIM"] = "1"
        env["KHAOS_MULTI_TURN"] = "1"

        event_fd, event_file = tempfile.mkstemp(suffix=".jsonl", prefix="khaos_mt_")
        os.close(event_fd)
        env["KHAOS_LLM_EVENT_FILE"] = event_file

        return env

    def _build_command(self, target_path: Path) -> list[str]:
        """Build command for agent execution."""
        return [
            self.config.python,
            "-c",
            (
                "import sys, runpy, khaos.auto_wrap_shim; "
                f"sys.argv=['khaos.agent_runner','--script',{str(target_path)!r}]; "
                "runpy.run_module('khaos.agent_runner', run_name='__main__')"
            ),
        ]

    def _configure_phase_faults(
        self,
        phase_config: Any,
        inp: PackInput,
        phase: str,
        run_index: int,
        has_turn_faults: bool,
    ) -> tuple[list[Any], list[dict[str, Any]], RunResult | None]:
        """Configure phase-level faults. Returns (applied, skipped, skip_result)."""
        faults_to_apply = []
        if phase_config is not None:
            if getattr(phase_config, "fault_schedule", None) and inp.id in phase_config.fault_schedule:
                faults_to_apply = list(phase_config.fault_schedule[inp.id])
            elif getattr(phase_config, "faults", None):
                faults_to_apply = list(phase_config.faults)

        caps = self.config.capabilities or {}
        has_llm = bool(caps.get("llm"))
        has_http = bool(caps.get("http"))
        has_mcp = bool(caps.get("mcp"))

        skipped_faults: list[dict[str, Any]] = []
        applied_faults: list[Any] = []

        if faults_to_apply:
            for fault in faults_to_apply:
                fault_type = str(getattr(fault, "type", "") or "")
                category = categorize_fault(fault_type)
                if category == "llm" and not has_llm:
                    skipped_faults.append({"fault_type": fault_type, "reason": "agent_has_no_llm"})
                    continue
                if category == "http" and not has_http:
                    skipped_faults.append({"fault_type": fault_type, "reason": "agent_has_no_http"})
                    continue
                if category == "mcp" and not has_mcp:
                    skipped_faults.append({"fault_type": fault_type, "reason": "agent_has_no_mcp"})
                    continue
                applied_faults.append(fault)

            # Skip if no applicable faults
            if phase == "resilience" and not applied_faults and not has_turn_faults:
                return [], skipped_faults, RunResult(
                    input_id=inp.id,
                    success=True,
                    latency_ms=0.0,
                    response="",
                    error=None,
                    goal_met=None,
                    checks_met=True,
                    check_errors=[],
                    is_multi_turn=True,
                    turn_count=inp.turn_count,
                    turns=[],
                    metadata={
                        "phase": phase,
                        "run_index": run_index,
                        "khaos_skip": True,
                        "khaos_skip_reason": "no_applicable_faults_for_agent",
                        "applied_faults": [],
                        "skipped_faults": skipped_faults,
                        "khaos_checks": {"passed": True, "errors": []},
                        "is_multi_turn": True,
                    },
                )

        return applied_faults, skipped_faults, None

    def _execute_turn(
        self,
        loop: asyncio.AbstractEventLoop,
        transport: Any,
        TransportMessage: type,
        turn_idx: int,
        content: str,
        turn_faults: list[Any] | None,
        applied_phase_faults: list[Any],
        inp: PackInput,
    ) -> TurnResult:
        """Execute a single turn."""
        turn_start = time.perf_counter()

        payload: dict[str, Any] = {"text": content}
        combined_faults = list(applied_phase_faults)
        if turn_faults:
            combined_faults.extend(list(turn_faults))

        if combined_faults:
            payload["khaos_faults"] = [
                {"type": f.type, "config": f.config, "probability": f.probability}
                for f in combined_faults
            ]

        msg = TransportMessage(name="user.message", payload=payload)

        async def _send_receive():
            await transport.send(msg)
            return await transport.receive()

        try:
            response_msg = loop.run_until_complete(_send_receive())
            turn_latency = (time.perf_counter() - turn_start) * 1000

            response_payload = response_msg.payload if isinstance(response_msg.payload, dict) else {}
            response_text = response_payload.get("text", "")

            turn_goal_met = None
            if inp.turn_goals and turn_idx < len(inp.turn_goals):
                from khaos.packs.runner import _check_goal
                turn_goal_met = _check_goal(response_text, inp.turn_goals[turn_idx])

            return TurnResult(
                turn_index=turn_idx,
                user_input=content,
                response=response_text,
                latency_ms=turn_latency,
                goal_met=turn_goal_met,
                faults_applied=[f.type for f in combined_faults] if combined_faults else [],
            )

        except Exception as e:
            turn_latency = (time.perf_counter() - turn_start) * 1000
            return TurnResult(
                turn_index=turn_idx,
                user_input=content,
                response="",
                latency_ms=turn_latency,
                error=str(e),
                faults_applied=[f.type for f in combined_faults] if combined_faults else [],
            )

    def _process_events_from_file(
        self,
        event_file: str,
        turn_results: list[TurnResult],
        phase: str,
        inp: PackInput,
    ) -> list[dict[str, Any]]:
        """Read and process events from event file."""
        captured: list[dict[str, Any]] = []

        try:
            event_path = Path(event_file)
            if not event_path.exists():
                return captured

            raw_events: list[dict[str, Any]] = []
            with event_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        if isinstance(event, dict) and "event" in event:
                            raw_events.append(event)
                    except json.JSONDecodeError:
                        pass

            # Group events by turn
            events_by_turn: dict[int, list[dict[str, Any]]] = {}
            active_turn: int | None = None

            for event in raw_events:
                etype = str(event.get("event") or "")
                payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}

                if etype == "turn.start":
                    turn_index = payload.get("turn_index")
                    if isinstance(turn_index, int):
                        active_turn = turn_index
                        events_by_turn.setdefault(active_turn, []).append(event)
                    continue

                if active_turn is not None:
                    events_by_turn.setdefault(active_turn, []).append(event)
                    if etype == "turn.end":
                        active_turn = None

            # Build captured events with context
            for t in turn_results:
                segment = events_by_turn.get(t.turn_index, [])
                start_ts = segment[0].get("ts") if segment else None
                end_ts = segment[-1].get("ts") if segment else None

                if not isinstance(start_ts, str):
                    start_ts = datetime.now(timezone.utc).isoformat()
                if not isinstance(end_ts, str):
                    end_ts = datetime.now(timezone.utc).isoformat()

                context_payload = {
                    "phase": phase,
                    "input_id": inp.id,
                    "faults": list(t.faults_applied or []),
                    "security_mode": self.config.security_mode if (phase or "").lower() == "security" else None,
                    "is_multi_turn": True,
                    "turn_index": t.turn_index,
                    "turn_count": len(turn_results),
                }

                captured.append({
                    "event": "transport.send",
                    "ts": start_ts,
                    "payload": {"content": t.user_input},
                    "context": context_payload,
                })

                for item in segment:
                    if isinstance(item, dict) and "context" not in item:
                        item["context"] = context_payload
                    captured.append(item)

                captured.append({
                    "event": "transport.receive",
                    "ts": end_ts,
                    "payload": {"content": t.response},
                    "context": context_payload,
                })

            # Store in trace events
            if self.context.trace_events is not None:
                if self.context.trace_lock is None:
                    self.context.trace_events.extend(captured)
                else:
                    with self.context.trace_lock:
                        self.context.trace_events.extend(captured)

        except OSError:
            pass

        return captured

    def _run_dependency_checks(
        self,
        applied_phase_faults: list[Any],
        turn_results: list[TurnResult],
        captured: list[dict[str, Any]],
    ) -> list[str]:
        """Run dependency checks for fault coverage."""
        errors: list[str] = []

        fault_types = [str(getattr(f, "type", "") or "") for f in applied_phase_faults if getattr(f, "type", None)]
        for t in turn_results:
            fault_types.extend(list(t.faults_applied or []))
        fault_types = [ft for ft in fault_types if ft]

        if not fault_types or not captured:
            return errors

        event_names = [str(e.get("event", "")) for e in captured if isinstance(e, dict)]

        requires_llm = any(categorize_fault(ft) == "llm" for ft in fault_types)
        requires_http = any(categorize_fault(ft) == "http" for ft in fault_types)
        requires_mcp = any(categorize_fault(ft) == "mcp" for ft in fault_types)

        if requires_llm and "llm.call" not in event_names:
            errors.append(
                "Expected at least one LLM call (llm.call) for the injected LLM fault(s), but none were observed."
            )
        if requires_http and not any(name == "http.request" for name in event_names):
            errors.append(
                "Expected at least one HTTP/tool request (http.request) for the injected HTTP/tool/RAG fault(s), but none were observed."
            )
        if requires_mcp and not any(name.startswith("mcp.") for name in event_names):
            errors.append(
                "Expected at least one MCP tool call (mcp.*) for the injected MCP fault(s), but none were observed."
            )

        return errors

    def _collect_fault_types(
        self,
        applied_phase_faults: list[Any],
        turn_results: list[TurnResult],
    ) -> list[str]:
        """Collect all fault types from phase and turns."""
        fault_types = [str(getattr(f, "type", "") or "") for f in applied_phase_faults]
        for t in turn_results:
            fault_types.extend(list(t.faults_applied or []))
        return [ft for ft in fault_types if ft]

def create_single_turn_invoker(
    config: InvokerConfig,
    context: InvokerContext,
    **kwargs: Any,
) -> Callable[[str], str]:
    """Create a single-turn invoker function.

    Returns a callable that can be used with PackRunner.
    """
    invoker = SingleTurnInvoker(config, context, **kwargs)

    def invoke(input_text: str) -> str:
        result = invoker(input_text)
        # Attach metadata for PackRunner
        invoke.__khaos_last_metadata__ = invoker.last_metadata
        return result

    invoke.__khaos_last_metadata__ = {}
    return invoke

def create_multi_turn_invoker(
    config: InvokerConfig,
    context: InvokerContext,
) -> Callable[[PackInput, str, int], RunResult]:
    """Create a multi-turn invoker function.

    Returns a callable that can be used with PackRunner.
    """
    invoker = MultiTurnInvoker(config, context)
    return invoker

__all__ = [
    "InvokerConfig",
    "InvokerContext",
    "InvocationMetadata",
    "SingleTurnInvoker",
    "MultiTurnInvoker",
    "create_single_turn_invoker",
    "create_multi_turn_invoker",
    "categorize_fault",
]
