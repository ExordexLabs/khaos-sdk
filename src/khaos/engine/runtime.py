"""Engine skeleton that will coordinate chaos injections and evaluation."""

from __future__ import annotations

import logging
from dataclasses import dataclass
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Mapping

import json
import time

logger = logging.getLogger(__name__)
from rich.markup import escape

from khaos.chaos import ChaosScenario
from khaos.output import extract_output_text
from khaos.transport import AgentTransport, TransportMessage
from khaos.transport import TransportEvent as MCPTransportEvent
from khaos.evaluator import (
    EvaluationContext,
    Evaluator,
    GoalEvaluator,
    SecurityEvaluator,
    TraceStatsEvaluator,
)
from khaos.evaluator.security_attacks import DEFAULT_MVP_ATTACKS
from khaos.security.models import SecurityAttack
from khaos.state import get_state_dir
from khaos.telemetry import clear_runtime_emitter, set_runtime_emitter
from khaos.contract import validate_envelope
from khaos.artifacts import RunManifest, write_manifest
from khaos.llm_trace import build_llm_trace

from .scheduler import SchedulerConfig, SeededScheduler
from .trace import TraceEvent
from .fault_registry import get_fault_handler

@dataclass
class EngineSettings:
    """Configuration knobs for the runtime."""

    max_concurrency: int = 1
    timeout_seconds: int = 600
    enable_tracing: bool = True
    strict_contract: bool = False

class ChaosRuntime:
    """Coordinates execution of scenarios against a target agent."""

    def __init__(
        self,
        settings: EngineSettings | None = None,
        evaluators: list[Evaluator] | None = None,
    ) -> None:
        self.settings = settings or EngineSettings()
        self.evaluators = evaluators or [TraceStatsEvaluator(), GoalEvaluator()]

    async def execute(
        self,
        agent: AgentTransport,
        scenario: ChaosScenario,
        *,
        run_id: str,
        seed: int,
    ) -> dict[str, Any]:
        """Run the supplied scenario against the target agent."""

        scheduler = SeededScheduler(SchedulerConfig(seed=seed))
        trace: list[TraceEvent] = []
        final_response: TransportMessage | None = None
        fault_records: list[dict[str, Any]] = []
        security_responses: dict[str, str] = {}
        transport_warnings: list[str] = []

        def _emit_framework(event: str, envelope: dict) -> None:
            envelope_dict = envelope if isinstance(envelope, dict) else {}
            try:
                # Always validate framework envelopes so telemetry never silently corrupts traces.
                validate_envelope(envelope_dict)
            except ValueError as exc:
                raise ValueError(f"Invalid framework envelope for event '{event}': {exc}") from exc
            payload = envelope_dict.get("payload") if isinstance(envelope_dict, dict) else {}
            trace.append(
                TraceEvent.create(
                    run_id=run_id,
                    agent_id=getattr(agent, "agent_id", "agent"),
                    event=event,
                    payload=payload or {},
                    meta={"scenario_id": scenario.metadata.identifier, "seed": seed},
                )
            )

        set_runtime_emitter(_emit_framework)

        try:
            self._record_transport_faults(
                scenario=scenario,
                trace=trace,
                run_id=run_id,
                scenario_id=scenario.metadata.identifier,
                seed=seed,
                agent_id=getattr(agent, "agent_id", "agent"),
                agent=agent,
                fault_records=fault_records,
            )

            # Configure security attacks for zero-code injection at LLM level.
            # This enables security testing without requiring transport protocol.
            if scenario.security_tests_enabled:
                attacks = scenario.security_attacks or DEFAULT_MVP_ATTACKS
                self._configure_security_attacks(agent, list(attacks))

            for idx, fault in enumerate(scenario.runtime_faults, start=1):
                await self._apply_fault(
                    fault=fault,
                    scheduler=scheduler,
                    trace=trace,
                    run_id=run_id,
                    scenario_id=scenario.metadata.identifier,
                    seed=seed,
                    agent_id=getattr(agent, "agent_id", "agent"),
                )

                payload = fault.get("config") or fault.get("payload", {})
                message = TransportMessage(
                    name=fault.get("name", fault.get("type", "fault")),
                    payload=payload,
                )
                fault_start = time.perf_counter()
                fault_timestamp = datetime.now(timezone.utc).isoformat()
                await scheduler.run_with_timeout(agent.send(message))
                trace.append(
                    TraceEvent.create(
                        run_id=run_id,
                        agent_id=getattr(agent, "agent_id", "agent"),
                        event="transport.send",
                        payload={"message": message.name},
                        meta={"scenario_id": scenario.metadata.identifier, "seed": seed},
                    )
                )
                self._flush_transport_events(agent, trace)

                response = await scheduler.run_with_timeout(agent.receive(), timeout=None)
                final_response = response
                elapsed_ms = (time.perf_counter() - fault_start) * 1000.0
                if self.settings.strict_contract:
                    self._validate_transport_response(response)
                else:
                    self._lint_transport_response(response, transport_warnings)
                trace.append(
                    TraceEvent.create(
                        run_id=run_id,
                        agent_id=getattr(agent, "agent_id", "agent"),
                        event="transport.receive",
                        payload={"message": response.name},
                        meta={"scenario_id": scenario.metadata.identifier, "seed": seed},
                    )
                )
                self._flush_transport_events(agent, trace)
                fault_records.append(
                    {
                        "fault_id": fault.get("id") or f"fault-{idx:04d}",
                        "fault_type": fault.get("type", "fault"),
                        "timestamp": fault_timestamp,
                        "phase": fault.get("phase", "execution"),
                        "config": payload,
                        "impact": {
                            "agent_recovered": response is not None,
                            "recovery_time_ms": round(elapsed_ms, 3),
                        },
                    }
                )

            if scenario.security_tests_enabled:
                # First try to get security responses from file-based injection.
                # This is the zero-code path where security_shim injects attacks
                # at the LLM API level and writes responses to the event file.
                security_responses = self._ingest_security_events(agent)

                # Fall back to transport-based security testing if no file events.
                # This maintains backward compatibility with protocol-aware agents.
                if not security_responses:
                    security_responses = await self._run_security_attacks(
                        agent=agent,
                        scheduler=scheduler,
                        trace=trace,
                        run_id=run_id,
                        scenario_id=scenario.metadata.identifier,
                        seed=seed,
                        attacks=scenario.security_attacks or DEFAULT_MVP_ATTACKS,
                    )

            await agent.close()
            self._flush_transport_events(agent, trace)
        finally:
            clear_runtime_emitter()
        llm_records, llm_warnings = self._ingest_llm_events(
            agent=agent,
            run_id=run_id,
            scenario_id=scenario.metadata.identifier,
            seed=seed,
            trace=trace,
        )
        event_dicts = [self._event_to_dict(event) for event in trace]
        llm_trace_payload = self._build_llm_trace(llm_records)
        mcp_servers = getattr(agent, "server_manifest", None)

        artifacts = []
        metadata = {
            "trace": event_dicts,
            "scenario_assertions": [
                assertion.model_dump() for assertion in scenario.assertions
            ],
            "scenario_goals": [goal.model_dump() for goal in scenario.goals],
            "final_response": self._serialize_message(final_response),
            "scenario_difficulty": scenario.metadata.difficulty,
            "scenario_difficulty_label": scenario.metadata.difficulty_label,
        }
        if scenario.security_tests_enabled:
            metadata["security_tests_enabled"] = True
            metadata["security_attacks"] = [
                self._security_attack_to_dict(attack) for attack in (scenario.security_attacks or DEFAULT_MVP_ATTACKS)
            ]
            metadata["security_responses"] = dict(security_responses)
        if llm_warnings:
            metadata["llm_warnings"] = llm_warnings
        if transport_warnings:
            metadata["transport_warnings"] = transport_warnings
        context = EvaluationContext(
            run_identifier=run_id,
            scenario_identifier=scenario.metadata.identifier,
            metadata=metadata,
        )

        active_evaluators = list(self.evaluators)
        if scenario.security_tests_enabled:
            attack_limit_env = os.environ.get("KHAOS_SECURITY_ATTACK_LIMIT")
            attack_limit = int(attack_limit_env) if attack_limit_env else None
            active_evaluators.append(
                SecurityEvaluator(
                    attack_corpus=scenario.security_attacks or DEFAULT_MVP_ATTACKS,
                    attack_limit=attack_limit,
                )
            )

        for evaluator in active_evaluators:
            artifacts.extend(await evaluator.evaluate(context))

        report_dict = None
        for artifact in artifacts:
            if artifact.name == "resilience.report":
                report_dict = artifact.details.get("report")
                break

        result = {
            "trace": event_dicts,
            "run_id": run_id,
            "seed": seed,
            "scenario": scenario.metadata.identifier,
            "artifacts": artifacts,
            "resilience_report": report_dict,
            "scenario_difficulty": scenario.metadata.difficulty,
            "scenario_difficulty_label": scenario.metadata.difficulty_label,
        }
        if llm_warnings:
            result["llm_warnings"] = llm_warnings
        if transport_warnings:
            result["transport_warnings"] = transport_warnings
        if scenario.security_tests_enabled:
            result["security_attacks"] = metadata.get("security_attacks", [])
            result["security_responses"] = dict(security_responses)
        if mcp_servers:
            result["mcp_servers"] = mcp_servers
            if report_dict is not None:
                if isinstance(report_dict, dict):
                    report_dict.setdefault("mcp_servers", mcp_servers)
            else:
                report_dict = {"mcp_servers": mcp_servers}
                result["resilience_report"] = report_dict
        if llm_trace_payload:
            result["llm_trace"] = llm_trace_payload
            if report_dict is None:
                report_dict = {}
                result["resilience_report"] = report_dict
            if isinstance(report_dict, dict):
                report_dict["llm_trace"] = llm_trace_payload

        result["faults_injected"] = fault_records
        if isinstance(report_dict, dict):
            report_dict.setdefault("faults_injected", fault_records)
        elif fault_records:
            result.setdefault("resilience_report", {})
            if isinstance(result["resilience_report"], dict):
                result["resilience_report"]["faults_injected"] = fault_records

        if self.settings.enable_tracing:
            self._persist_trace(event_dicts, run_id)
            self._persist_metrics(
                run_id=run_id,
                scenario_id=scenario.metadata.identifier,
                seed=seed,
                artifacts=artifacts,
                report=report_dict,
                mcp_servers=mcp_servers,
                scenario_difficulty=scenario.metadata.difficulty,
                scenario_difficulty_label=scenario.metadata.difficulty_label,
            )
            # Write unified manifest
            manifest = RunManifest(
                run_id=run_id,
                execution_mode="scenario",
                seed=seed,
                scenario_id=scenario.metadata.identifier,
                artifacts=[
                    f"trace-{run_id}.json",
                    f"metrics-{run_id}.json",
                ],
            )
            write_manifest(manifest)
        return result

    def _event_to_dict(self, event: TraceEvent) -> dict[str, Any]:
        return {
            "ts": event.ts.isoformat(),
            "run_id": event.run_id,
            "agent_id": event.agent_id,
            "event": event.event,
            "payload": event.payload,
            "meta": event.meta,
        }

    def _ingest_llm_events(
        self,
        *,
        agent: AgentTransport,
        run_id: str,
        scenario_id: str,
        seed: int,
        trace: list[TraceEvent],
    ) -> tuple[list[dict[str, Any]], list[str]]:
        llm_path = getattr(agent, "llm_event_path", None)
        if not llm_path:
            return [], []
        try:
            path = Path(llm_path)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            return [], []
        if not path.exists():
            return [], []
        records: list[dict[str, Any]] = []
        warnings: list[str] = []
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    event_name = record.get("event", "llm.call")
                    payload = record.get("payload", {}) or {}
                    meta = record.get("meta", {}) or {}
                    idx = len(records) + 1

                    def _warn(msg: str) -> None:
                        interaction_id = meta.get("interaction_id") or payload.get("interaction_id")
                        label = f"LLM event {idx} ('{event_name}')"
                        if interaction_id:
                            label = f"{label} [interaction_id={interaction_id}]"
                        else:
                            label = f"{label} [interaction_id=unknown]"
                        warnings.append(f"{escape(label)} ignored: {msg}")
                    if not isinstance(payload, dict):
                        _warn("payload must be an object.")
                        continue
                    tokens_field = payload.get("tokens", {})
                    if tokens_field is not None and tokens_field != {} and not isinstance(tokens_field, dict):
                        _warn("tokens must be an object.")
                        continue
                    cost = payload.get("cost_usd")
                    latency = payload.get("latency_ms")
                    provider = payload.get("provider")
                    model = payload.get("model")
                    if cost is not None and not isinstance(cost, (int, float)):
                        _warn("cost_usd must be numeric.")
                        continue
                    if latency is not None and not isinstance(latency, (int, float)):
                        _warn("latency_ms must be numeric.")
                        continue
                    if provider is not None and not isinstance(provider, str):
                        _warn("provider must be a string.")
                        continue
                    if model is not None and not isinstance(model, str):
                        _warn("model must be a string.")
                        continue
                    records.append(record)
                    trace.append(
                        TraceEvent.create(
                            run_id=run_id,
                            agent_id=getattr(agent, "agent_id", "agent"),
                            event=event_name,
                            payload=payload,
                            meta={
                                "scenario_id": scenario_id,
                                "seed": seed,
                                **({"ts": record.get("ts")} if record.get("ts") else {}),
                                **meta,
                            },
                        )
                    )
        except OSError:  # pragma: no cover - best effort
            return [], warnings
        finally:
            try:
                path.unlink(missing_ok=True)
            except OSError:  # pragma: no cover - best effort
                pass
        return records, warnings

    def _validate_transport_response(self, response: TransportMessage | None) -> None:
        if response is None:
            raise ValueError("Agent returned no response; strict contract requires a TransportMessage.")
        if not isinstance(response.name, str) or not response.name:
            raise ValueError("Agent response must include a non-empty 'name' field.")
        payload = response.payload
        if payload is None:
            raise ValueError("Agent response payload cannot be None under strict contract.")
        if not isinstance(payload, dict):
            raise ValueError("Agent response payload must be a mapping under strict contract.")

    def _lint_transport_response(self, response: TransportMessage | None, warnings: list[str]) -> None:
        """Best-effort schema lint for non-strict mode."""

        if response is None:
            warnings.append("Agent returned no response message; payload skipped.")
            return
        if not isinstance(response.name, str) or not response.name:
            warnings.append("Agent response missing non-empty 'name'; event recorded with fallback.")
        if response.payload is None:
            warnings.append("Agent response payload was None; replaced with empty object.")
            response.payload = {}
        elif not isinstance(response.payload, dict):
            warnings.append("Agent response payload must be an object; replaced with empty object.")
            response.payload = {}

    def _build_llm_trace(self, records: list[dict[str, Any]]) -> dict[str, Any] | None:
        return build_llm_trace(records)

    def _persist_trace(self, events: list[dict[str, Any]], run_id: str) -> None:
        """Persist trace events to the cache manifest for reuse."""

        trace_path = get_state_dir() / "runs" / f"trace-{run_id}.json"
        trace_path.parent.mkdir(parents=True, exist_ok=True)
        trace_path.write_text(json.dumps(events, indent=2))

    def _persist_metrics(
        self,
        *,
        run_id: str,
        scenario_id: str,
        seed: int,
        artifacts: list,
        report: dict[str, Any] | None,
        mcp_servers: list[dict[str, Any]] | None,
        scenario_difficulty: float | None,
        scenario_difficulty_label: str | None,
    ) -> None:
        metrics_path = get_state_dir() / "runs" / f"metrics-{run_id}.json"

        payload = {
            "run_id": run_id,
            "scenario": scenario_id,
            "seed": seed,
            "scenario_difficulty": scenario_difficulty,
            "scenario_difficulty_label": scenario_difficulty_label,
            "resilience_report": report,
            "artifacts": [
                {
                    "name": artifact.name,
                    "value": artifact.value,
                    "unit": artifact.unit,
                    "details": artifact.details,
                }
                for artifact in artifacts
            ],
        }
        if mcp_servers:
            payload["mcp_servers"] = mcp_servers

        metrics_path.write_text(json.dumps(payload, indent=2))

    async def _apply_fault(
        self,
        *,
        fault: dict[str, Any],
        scheduler: SeededScheduler,
        trace: list[TraceEvent],
        run_id: str,
        scenario_id: str,
        seed: int,
        agent_id: str,
    ) -> None:
        fault_type = fault.get("type", "unknown")
        config = fault.get("config", {})

        handler = get_fault_handler(fault_type)
        if handler:
            extra = await handler(config, scheduler)
        else:
            extra = {"note": f"unhandled fault type: {fault_type}"}

        payload: dict[str, Any] = {"type": fault_type, "config": config}
        payload.update(extra)

        trace.append(
            TraceEvent.create(
                run_id=run_id,
                agent_id=agent_id,
                event="injector.action",
                payload=payload,
                meta={"scenario_id": scenario_id, "seed": seed},
            )
        )

    def _flush_transport_events(self, agent: AgentTransport, trace: list[TraceEvent]) -> None:
        drain = getattr(agent, "drain_events", None)
        if not callable(drain):
            return
        events = drain()
        if not events:
            return
        for event in events:
            if not isinstance(event, MCPTransportEvent):
                continue
            trace.append(
                TraceEvent(
                    ts=event.ts,
                    run_id=event.run_id,
                    agent_id=event.agent_id,
                    event=event.event,
                    payload=event.payload,
                    meta=event.meta,
                )
            )

    def _record_transport_faults(
        self,
        *,
        scenario: ChaosScenario,
        trace: list[TraceEvent],
        run_id: str,
        scenario_id: str,
        seed: int,
        agent_id: str,
        agent: AgentTransport,
        fault_records: list[dict[str, Any]],
    ) -> None:
        faults = list(scenario.transport_faults)
        if not faults:
            return
        self._configure_transport_faults(agent, faults, seed=seed)
        for idx, fault in enumerate(faults, start=1):
            payload = {
                "type": fault.get("type", "unknown"),
                "config": fault.get("config", {}),
                "scope": "transport",
            }
            trace.append(
                TraceEvent.create(
                    run_id=run_id,
                    agent_id=agent_id,
                    event="injector.action",
                    payload=payload,
                    meta={"scenario_id": scenario_id, "seed": seed},
                )
            )
            fault_records.append(
                {
                    "fault_id": fault.get("id") or f"transport-{idx:04d}",
                    "fault_type": fault.get("type", "transport_fault"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "phase": "transport",
                    "config": fault.get("config", {}),
                    "impact": {
                        "agent_recovered": True,
                        "recovery_time_ms": 0.0,
                    },
                }
            )

    def _configure_transport_faults(
        self,
        agent: AgentTransport,
        faults: list[Mapping[str, Any]],
        seed: int | None = None,
    ) -> None:
        setter = getattr(agent, "configure_transport_faults", None)
        if not callable(setter):
            return
        normalized = [dict(fault) for fault in faults]
        try:
            setter(normalized, seed=seed)
        except TypeError:
            setter(normalized)

    def _configure_security_attacks(
        self,
        agent: AgentTransport,
        attacks: list[SecurityAttack],
        *,
        attack_mode: str = "interleave",
    ) -> None:
        """Configure security attacks for zero-code injection at LLM level.

        This enables security testing without requiring agents to implement
        the transport message protocol.
        """
        setter = getattr(agent, "configure_security_attacks", None)
        if not callable(setter):
            return
        normalized = [
            {
                "attack_id": attack.attack_id,
                "attack_type": attack.attack_type.value,
                "payload": attack.payload,
                "name": attack.name,
                "injection_vector": attack.injection_vector,
                "expected_behavior": attack.expected_behavior,
            }
            for attack in attacks
        ]
        try:
            setter(normalized, attack_mode=attack_mode)
        except TypeError:
            setter(normalized)

    def _ingest_security_events(
        self,
        agent: AgentTransport,
    ) -> dict[str, str]:
        """Read security attack responses from LLM event file.

        This is the zero-code alternative to _run_security_attacks which
        requires transport protocol. Security events are written by the
        security_shim when it executes attacks at the LLM API level.
        """
        responses: dict[str, str] = {}
        llm_path = getattr(agent, "llm_event_path", None)
        if not llm_path:
            return responses
        try:
            path = Path(llm_path)
        except (TypeError, ValueError):
            return responses
        if not path.exists():
            return responses
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if record.get("event") != "security.attack":
                        continue
                    payload = record.get("payload", {}) or {}
                    attack_id = payload.get("attack_id")
                    response = payload.get("response", "")
                    if attack_id:
                        responses[attack_id] = response
        except OSError:
            pass
        return responses

    async def _run_security_attacks(
        self,
        *,
        agent: AgentTransport,
        scheduler: SeededScheduler,
        trace: list[TraceEvent],
        run_id: str,
        scenario_id: str,
        seed: int,
        attacks: Iterable[SecurityAttack],
    ) -> dict[str, str]:
        responses: dict[str, str] = {}
        attack_list = list(attacks)
        if not attack_list:
            return responses
        for attack in attack_list:
            payload = {
                "attack_id": attack.attack_id,
                "attack_type": attack.attack_type.value,
                "injection_vector": attack.injection_vector,
                # Duplicate across common prompt keys so generic Python agents can route this
                # through their normal "user message" path without bespoke handling.
                "message": attack.payload,
                "text": attack.payload,
                "prompt": attack.payload,
                "input": attack.payload,
                "content": attack.payload,
            }
            trace.append(
                TraceEvent.create(
                    run_id=run_id,
                    agent_id=getattr(agent, "agent_id", "agent"),
                    event="security.attack",
                    payload=payload,
                    meta={"scenario_id": scenario_id, "seed": seed},
                )
            )
            message = TransportMessage(name="security.attack", payload=payload)
            try:
                await scheduler.run_with_timeout(agent.send(message))
                response = await scheduler.run_with_timeout(agent.receive(), timeout=None)
                responses[attack.attack_id] = self._extract_security_text(response)
                trace.append(
                    TraceEvent.create(
                        run_id=run_id,
                        agent_id=getattr(agent, "agent_id", "agent"),
                        event="security.response",
                        payload=self._serialize_message(response) or {},
                        meta={"scenario_id": scenario_id, "seed": seed},
                    )
                )
            except Exception:
                logger.debug("Security attack %s failed during execution", attack.attack_id, exc_info=True)
                responses[attack.attack_id] = ""
        return responses

    def _security_attack_to_dict(self, attack: SecurityAttack) -> dict[str, Any]:
        return {
            "attack_id": attack.attack_id,
            "name": attack.name,
            "attack_type": attack.attack_type.value,
            "payload": attack.payload,
            "injection_vector": attack.injection_vector,
            "expected_behavior": attack.expected_behavior,
            "metadata": attack.metadata,
        }

    def _serialize_message(self, message: TransportMessage | None) -> dict[str, Any] | None:
        if message is None:
            return None
        return {
            "name": message.name,
            "payload": message.payload,
            "metadata": message.metadata,
        }

    def _extract_security_text(self, message: TransportMessage | None) -> str:
        """Extract text from a security response using the unified helper."""
        if message is None:
            return ""
        # Try payload first
        text = extract_output_text(message.payload)
        if text:
            return text
        # Fall back to metadata message
        if isinstance(message.metadata, dict):
            note = message.metadata.get("message")
            if isinstance(note, str):
                return note
        return ""
