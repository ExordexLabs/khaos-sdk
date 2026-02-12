"""Runtime discovery hooks for popular agent frameworks."""

from __future__ import annotations

import importlib
import logging
import os
import time
from pathlib import Path
from typing import Any
from collections.abc import Callable

logger = logging.getLogger(__name__)

from .agent import (
    AgentCapability,
    AgentCategory,
    AgentMetadata,
    calculate_code_hash,
    register_discovered_agent,
)
from .contract import make_envelope, normalize_payload
from .telemetry import get_runtime_emitter

RUNTIME_ENV_FLAG = "KHAOS_RUNTIME_DISCOVERY"
ENTRYPOINT_ENV = "KHAOS_AGENT_ENTRYPOINT"

_STATE: dict[str, Any] = {
    "entrypoint": None,
    "installed": False,
    "langgraph": False,
    "crewai": False,
    "prefect": False,
    "airflow": False,
    "dagster": False,
    "autogen": False,
}

_REGISTERED_KEYS: set[tuple[int, str]] = set()
AUTO_WRAP_ENV = "KHAOS_AUTO_WRAP"

def _auto_wrap_enabled() -> bool:
    value = os.environ.get(AUTO_WRAP_ENV, "1").strip().lower()
    return value not in {"0", "false", "no", "off"}

def install_runtime_discovery(entrypoint: Path | None = None) -> None:
    """Enable runtime agent discovery hooks for supported frameworks."""

    if os.environ.get("KHAOS_DISABLE_FRAMEWORK_HOOKS") == "1":
        return

    if entrypoint is not None:
        _STATE["entrypoint"] = str(entrypoint)
    elif os.environ.get(ENTRYPOINT_ENV):
        _STATE["entrypoint"] = os.environ.get(ENTRYPOINT_ENV)

    if _STATE["installed"]:
        return

    _STATE["installed"] = True
    _hook_langgraph()
    _hook_crewai()
    _hook_prefect()
    _hook_airflow()
    _hook_dagster()
    _hook_autogen()

def _hook_langgraph() -> None:
    if _STATE["langgraph"]:
        return
    try:
        module = importlib.import_module("langgraph.graph.graph")
    except ModuleNotFoundError:
        return

    compiled_cls = getattr(module, "CompiledGraph", None)
    if not isinstance(compiled_cls, type):
        return

    def _make_wrapper(method_name: str) -> Callable:
        original = getattr(compiled_cls, method_name, None)
        if not callable(original):
            return lambda self, *args, **kwargs: original(self, *args, **kwargs)  # type: ignore[misc]

        def wrapper(self, *args, **kwargs):  # type: ignore[override]
            emitter = get_runtime_emitter()
            start = time.perf_counter()
            if emitter:
                emitter(
                    "framework.langgraph.invoke",
                    make_envelope(
                        "framework.langgraph.invoke",
                        {"status": "running", "kwargs": kwargs},
                    ),
                )
            if _auto_wrap_enabled() and not getattr(self, "__khaos_wrapped__", False):
                try:
                    from khaos.adapters.langgraph import wrap_langgraph  # type: ignore

                    wrapped = wrap_langgraph(self, emit=emitter or (lambda *_: None))
                    setattr(wrapped, "__khaos_wrapped__", True)
                    setattr(self, "__khaos_wrapped__", True)
                    self = wrapped  # type: ignore
                except Exception:
                    logger.debug("Runtime hook wrapping failed", exc_info=True)
            _register_runtime_agent(
                name=str(getattr(self, "name", "langgraph-agent")),
                framework="langgraph",
                category=AgentCategory.ORCHESTRATED,
                capabilities=[AgentCapability.ORCHESTRATION.value],
                metadata={"signal": "runtime:langgraph"},
                once_key=(id(self), method_name),
            )
            result = original(self, *args, **kwargs)
            if emitter:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                emitter(
                    "framework.langgraph.invoke",
                    make_envelope("framework.langgraph.invoke", {"status": "ok", "elapsed_ms": elapsed_ms}),
                )
                # best-effort richer telemetry mirroring wrap_langgraph
                try:
                    from khaos.adapters.langgraph import _emit_result_telemetry  # type: ignore

                    _emit_result_telemetry(emitter, result)
                except Exception:
                    logger.debug("Runtime hook wrapping failed", exc_info=True)
            return result

        return wrapper

    for method_name in ("invoke", "astream", "stream", "ainvoke"):
        if hasattr(compiled_cls, method_name):
            setattr(compiled_cls, method_name, _make_wrapper(method_name))

    _STATE["langgraph"] = True

def _hook_crewai() -> None:
    if _STATE["crewai"]:
        return
    try:
        module = importlib.import_module("crewai.crew")
    except ModuleNotFoundError:
        return

    crew_cls = getattr(module, "Crew", None)
    if not isinstance(crew_cls, type):
        return

    def _wrap(method_name: str) -> None:
        original = getattr(crew_cls, method_name, None)
        if not callable(original):
            return

        def wrapper(self, *args, **kwargs):  # type: ignore[override]
            emitter = get_runtime_emitter()
            start = time.perf_counter()
            if emitter:
                emitter("framework.crewai.run", make_envelope("framework.crewai.run", {"status": "running", "kwargs": kwargs}))
            if _auto_wrap_enabled() and not getattr(self, "__khaos_wrapped__", False):
                try:
                    from khaos.adapters.crewai import wrap_crewai  # type: ignore

                    wrapped = wrap_crewai(self, emit=emitter or (lambda *_: None))
                    setattr(wrapped, "__khaos_wrapped__", True)
                    setattr(self, "__khaos_wrapped__", True)
                    self = wrapped  # type: ignore
                except Exception:
                    logger.debug("Runtime hook wrapping failed", exc_info=True)
            _register_runtime_agent(
                name=str(getattr(self, "name", "crewai-agent")),
                framework="crewai",
                category=AgentCategory.ORCHESTRATED,
                capabilities=[AgentCapability.ORCHESTRATION.value],
                metadata={"signal": "runtime:crewai"},
                once_key=(id(self), method_name),
            )
            result = original(self, *args, **kwargs)
            if emitter:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                emitter("framework.crewai.run", make_envelope("framework.crewai.run", {"status": "ok", "elapsed_ms": elapsed_ms}))
            return result

        setattr(crew_cls, method_name, wrapper)

    for method in ("kickoff", "kickoff_async", "run"):
        _wrap(method)

    _STATE["crewai"] = True

def _hook_prefect() -> None:
    if _STATE["prefect"]:
        return
    try:
        module = importlib.import_module("prefect.flows")
    except ModuleNotFoundError:
        return

    flow_cls = getattr(module, "Flow", None)
    if not isinstance(flow_cls, type):
        return

    original_call = getattr(flow_cls, "__call__", None)
    if not callable(original_call):
        return

    def wrapper(self, *args, **kwargs):  # type: ignore[override]
        emitter = get_runtime_emitter()
        start = time.perf_counter()
        if emitter:
            emitter("framework.prefect.run", make_envelope("framework.prefect.run", {"status": "running", "kwargs": kwargs}))
        if _auto_wrap_enabled() and not getattr(self, "__khaos_wrapped__", False):
                try:
                    from khaos.adapters.prefect import wrap_prefect  # type: ignore

                    wrapped = wrap_prefect(self, emit=emitter or (lambda *_: None))
                    setattr(wrapped, "__khaos_wrapped__", True)
                    setattr(self, "__khaos_wrapped__", True)
                    self = wrapped  # type: ignore
                except Exception:
                    logger.debug("Runtime hook wrapping failed", exc_info=True)
        _register_runtime_agent(
            name=str(getattr(self, "name", "prefect-flow")),
            framework="prefect",
            category=AgentCategory.WORKFLOW,
            capabilities=[AgentCapability.WORKFLOW.value],
            metadata={"signal": "runtime:prefect"},
            once_key=(id(self), "prefect_flow"),
        )
        result = original_call(self, *args, **kwargs)
        if emitter:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            emitter("framework.prefect.run", make_envelope("framework.prefect.run", {"status": "ok", "elapsed_ms": elapsed_ms}))
        return result

    setattr(flow_cls, "__call__", wrapper)
    _STATE["prefect"] = True

def _hook_airflow() -> None:
    if _STATE["airflow"]:
        return
    try:
        module = importlib.import_module("airflow.models.dag")
    except ModuleNotFoundError:
        return

    dag_cls = getattr(module, "DAG", None)
    if not isinstance(dag_cls, type):
        return

    original_run = getattr(dag_cls, "run", None)
    if not callable(original_run):
        return

    def wrapper(self, *args, **kwargs):  # type: ignore[override]
        emitter = get_runtime_emitter()
        start = time.perf_counter()
        if emitter:
            emitter("framework.airflow.run", make_envelope("framework.airflow.run", {"status": "running", "kwargs": kwargs}))
        if _auto_wrap_enabled() and not getattr(self, "__khaos_wrapped__", False):
                try:
                    from khaos.adapters.airflow import wrap_airflow  # type: ignore

                    wrapped = wrap_airflow(self, emit=emitter or (lambda *_: None))
                    setattr(wrapped, "__khaos_wrapped__", True)
                    setattr(self, "__khaos_wrapped__", True)
                    self = wrapped  # type: ignore
                except Exception:
                    logger.debug("Runtime hook wrapping failed", exc_info=True)
        _register_runtime_agent(
            name=str(getattr(self, "dag_id", "airflow-dag")),
            framework="airflow",
            category=AgentCategory.WORKFLOW,
            capabilities=[AgentCapability.WORKFLOW.value],
            metadata={"signal": "runtime:airflow"},
            once_key=(id(self), "airflow_dag"),
        )
        result = original_run(self, *args, **kwargs)
        if emitter:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            emitter("framework.airflow.run", make_envelope("framework.airflow.run", {"status": "ok", "elapsed_ms": elapsed_ms}))
        return result

    setattr(dag_cls, "run", wrapper)
    _STATE["airflow"] = True

def _hook_dagster() -> None:
    if _STATE["dagster"]:
        return
    try:
        module = importlib.import_module("dagster._core.definitions.job_definition")
    except ModuleNotFoundError:
        return

    job_cls = getattr(module, "JobDefinition", None)
    if not isinstance(job_cls, type):
        return

    original_execute = getattr(job_cls, "execute_in_process", None)
    if not callable(original_execute):
        return

    def wrapper(self, *args, **kwargs):  # type: ignore[override]
        emitter = get_runtime_emitter()
        start = time.perf_counter()
        if emitter:
            emitter("framework.dagster.run", make_envelope("framework.dagster.run", {"status": "running", "kwargs": kwargs}))
        if _auto_wrap_enabled() and not getattr(self, "__khaos_wrapped__", False):
                try:
                    from khaos.adapters.dagster import wrap_dagster  # type: ignore

                    wrapped = wrap_dagster(self, emit=emitter or (lambda *_: None))
                    setattr(wrapped, "__khaos_wrapped__", True)
                    setattr(self, "__khaos_wrapped__", True)
                    self = wrapped  # type: ignore
                except Exception:
                    logger.debug("Runtime hook wrapping failed", exc_info=True)
        _register_runtime_agent(
            name=str(getattr(self, "name", "dagster-job")),
            framework="dagster",
            category=AgentCategory.WORKFLOW,
            capabilities=[AgentCapability.WORKFLOW.value],
            metadata={"signal": "runtime:dagster"},
            once_key=(id(self), "dagster_job"),
        )
        result = original_execute(self, *args, **kwargs)
        if emitter:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            emitter("framework.dagster.run", make_envelope("framework.dagster.run", {"status": "ok", "elapsed_ms": elapsed_ms}))
        return result

    setattr(job_cls, "execute_in_process", wrapper)
    _STATE["dagster"] = True

def _hook_autogen() -> None:
    if _STATE["autogen"]:
        return
    try:
        module = importlib.import_module("autogen.agentchat.conversable_agent")
    except ModuleNotFoundError:
        return

    agent_cls = getattr(module, "ConversableAgent", None)
    if not isinstance(agent_cls, type):
        return

    def _wrap(method_name: str) -> None:
        original = getattr(agent_cls, method_name, None)
        if not callable(original):
            return

        def wrapper(self, *args, **kwargs):  # type: ignore[override]
            _register_runtime_agent(
                name=str(getattr(self, "name", "autogen-agent")),
                framework="autogen",
                category=AgentCategory.ORCHESTRATED,
                capabilities=[AgentCapability.ORCHESTRATION.value],
                metadata={"signal": "runtime:autogen"},
                once_key=(id(self), f"autogen-{method_name}"),
            )
            emitter = get_runtime_emitter()
            start = time.perf_counter()
            if emitter:
                emitter("framework.autogen.run", make_envelope("framework.autogen.run", {"status": "running", "kwargs": kwargs}))
            if _auto_wrap_enabled() and not getattr(self, "__khaos_wrapped__", False):
                try:
                    from khaos.adapters.autogen import wrap_autogen  # type: ignore

                    wrapped = wrap_autogen(self, emit=emitter or (lambda *_: None))
                    setattr(wrapped, "__khaos_wrapped__", True)
                    setattr(self, "__khaos_wrapped__", True)
                    self = wrapped  # type: ignore
                except Exception:
                    logger.debug("Runtime hook wrapping failed", exc_info=True)
            result = original(self, *args, **kwargs)
            if emitter:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                emitter("framework.autogen.run", make_envelope("framework.autogen.run", {"status": "ok", "elapsed_ms": elapsed_ms}))
            return result

        setattr(agent_cls, method_name, wrapper)

    for method in ("send", "receive", "initiate_chat"):
        if hasattr(agent_cls, method):
            _wrap(method)

    _STATE["autogen"] = True

def _register_runtime_agent(
    *,
    name: str,
    framework: str,
    category: AgentCategory,
    capabilities: list[str],
    metadata: dict[str, Any],
    once_key: tuple[int, str] | None = None,
) -> None:
    if once_key is not None and once_key in _REGISTERED_KEYS:
        return
    if once_key is not None:
        _REGISTERED_KEYS.add(once_key)

    entrypoint = _STATE.get("entrypoint") or os.environ.get(ENTRYPOINT_ENV)
    code_hash = ""
    entrypoint_str = ""
    if entrypoint:
        entry_path = Path(entrypoint)
        entrypoint_str = str(entry_path)
        if entry_path.exists():
            try:
                code_hash = calculate_code_hash(entry_path)
            except OSError:
                code_hash = ""

    agent_metadata = AgentMetadata(
        name=name,
        version="runtime",
        code_hash=code_hash,
        metadata=metadata,
        entrypoint=entrypoint_str,
        framework=framework,
        category=category,
        capabilities=capabilities,
        detection_source="runtime",
        confidence=0.9,
    )
    signals = set(agent_metadata.signals or [])
    signals.add(agent_metadata.detection_source or "runtime")
    agent_metadata.signals = sorted(signals)
    register_discovered_agent(agent_metadata)

if os.environ.get(RUNTIME_ENV_FLAG):
    install_runtime_discovery()

__all__ = ["install_runtime_discovery"]
