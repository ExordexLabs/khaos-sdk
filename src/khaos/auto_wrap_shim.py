"""Preload shim to auto-wrap supported frameworks before user code runs.

This module is automatically loaded by Khaos when running agents. It enables:
1. LLM telemetry auto-capture (OpenAI, Anthropic) - zero-code telemetry
2. Security attack injection (prompt injection, system prompt leakage) - zero-code security
3. LLM fault injection (rate limits, timeouts, model unavailable)
4. HTTP fault injection (latency, errors)
5. Framework adapters (LangGraph, CrewAI)

Users get automatic telemetry capture and security testing with no code changes required.
"""

from __future__ import annotations

import importlib
import logging
import os

from khaos.llm.faults import enable_llm_fault_shim
from khaos.llm.security_shim import enable_security_shim
from khaos.llm.shim import enable_llm_shim
from khaos.http.faults import enable_http_fault_shim
from khaos.filesystem.shim import enable_filesystem_shim
from khaos.subprocess.shim import enable_subprocess_shim

logger = logging.getLogger(__name__)

AUTO_WRAP_ENV = "KHAOS_AUTO_WRAP"
DISABLE_HOOKS_ENV = "KHAOS_DISABLE_FRAMEWORK_HOOKS"


def _enabled() -> bool:
    val = os.environ.get(AUTO_WRAP_ENV, "1").strip().lower()
    if val in {"0", "false", "no", "off"}:
        return False
    if os.environ.get(DISABLE_HOOKS_ENV, "0").strip() in {"1", "true", "True"}:
        return False
    return True


def _wrap_safe(import_path: str, wrap_fn_path: str, attr_name: str) -> None:
    try:
        module = importlib.import_module(import_path)
    except Exception:
        logger.debug("Failed to import module '%s' for auto-wrapping", import_path, exc_info=True)
        return
    target = getattr(module, attr_name, None)
    if target is None:
        return
    if getattr(target, "__khaos_wrapped__", False):
        return
    try:
        wrap_parts = wrap_fn_path.rsplit(".", 1)
        wrap_mod = importlib.import_module(wrap_parts[0])
        wrap_fn = getattr(wrap_mod, wrap_parts[1])
        wrapped = wrap_fn(target)
        setattr(wrapped, "__khaos_wrapped__", True)
        # ensure idempotent replace; if already wrapped at module level, skip
        if getattr(module, attr_name, None) is target:
            setattr(module, attr_name, wrapped)
    except Exception:
        logger.debug("Failed to wrap '%s.%s'", import_path, attr_name, exc_info=True)
        return


def apply_auto_wrap() -> None:
    if not _enabled():
        return
    # LLM telemetry shim: auto-capture OpenAI/Anthropic calls (zero-code telemetry).
    # Must be applied BEFORE other shims so telemetry is captured for all calls.
    enable_llm_shim()
    # Security attack shim: auto-inject security attacks (zero-code security testing).
    # Executes attacks in parallel with agent's normal LLM calls.
    enable_security_shim()
    # LLM faults (ADR-0010 phase 1) must be configured before user code executes.
    enable_llm_fault_shim()
    # Tool/RAG HTTP faults (ADR-0010 phase 1).
    enable_http_fault_shim()
    # Filesystem faults for file content injection (agentic environments).
    enable_filesystem_shim()
    # Subprocess faults for shell output injection (agentic environments).
    enable_subprocess_shim()
    # langgraph: compiled graph class
    _wrap_safe("langgraph.graph.graph", "khaos.adapters.langgraph.wrap_langgraph", "CompiledGraph")
    # crewai: Crew class
    _wrap_safe("crewai.crew", "khaos.adapters.crewai.wrap_crewai", "Crew")
    # prefect: Flow is callable; skip at module import (handled via runtime hook); no-op here
    # airflow: DAG runs via runtime hook; skip
    # dagster: JobDefinition execute covered by runtime hook; skip
    # autogen: no safe wrapper yet; skip


apply_auto_wrap()
