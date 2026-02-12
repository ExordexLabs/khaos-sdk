"""Shared constants for the Khaos CLI."""

from __future__ import annotations

import os
from pathlib import Path

from khaos.state import get_state_dir

# Authentication scopes
VALID_SCOPES = ("ingest:write", "runs:read", "runs:write")
DEFAULT_SCOPE = "ingest:write"

# Dashboard settings
DEFAULT_DASHBOARD_URL = os.environ.get("KHAOS_DASHBOARD_URL", "https://dashboard.khaos.dev")

# LLM content handling modes
LLM_CONTENT_MODES = ("redact", "mask", "raw")

# Path constants
MODULE_ROOT = Path(__file__).resolve().parent.parent  # Points to khaos/
PROJECT_ROOT = MODULE_ROOT.parent.parent  # Points to sdk/

# State directories
STATE_RUNS_DIR = get_state_dir() / "runs"

# Fault type descriptions for help text
FAULT_TYPE_DESCRIPTIONS = {
    "llm_rate_limit": "Simulates rate limiting from the LLM provider",
    "llm_model_unavailable": "Returns model unavailable error",
    "llm_response_timeout": "Delays LLM responses beyond timeout threshold",
    "llm_token_quota_exceeded": "Simulates quota exhaustion",
    "model_fallback_forced": "Forces use of specified fallback model",
    "tool_call_failure": "Causes tool/function calls to fail",
    "tool_response_corruption": "Mutates tool responses (schema violation, incorrect data, partial payload)",
    "tool_latency_spike": "Adds heavy latency to tool calls",
    "rag_retrieval_corruption": "Corrupts retrieved documents to test validation paths",
    "rag_document_poisoning": "Injects malicious content into retrieved documents",
    "tool_output_injection": "Appends injected instructions to tool outputs",
}


def resolve_data_dir(name: str) -> Path:
    """Prefer packaged assets but fall back to repo files during development."""
    packaged = MODULE_ROOT / name
    if packaged.exists():
        return packaged
    repo_candidate = PROJECT_ROOT / name
    if repo_candidate.exists():
        return repo_candidate
    sdk_candidate = PROJECT_ROOT / "sdk" / name
    if sdk_candidate.exists():
        return sdk_candidate
    return packaged


# Asset directories
EXAMPLES_ROOT = resolve_data_dir("examples")
SCENARIOS_ROOT = resolve_data_dir("scenarios")


def _env_flag(key: str, default: bool) -> bool:
    """Get a boolean flag from environment."""
    val = os.environ.get(key)
    if val is None:
        return default
    return val.lower() in ("1", "true", "yes")


# Auto-sync defaults (from environment)
AUTO_SYNC_DEFAULT = _env_flag("KHAOS_AUTO_SYNC", False)
AUTO_SYNC_CLEANUP_DEFAULT = _env_flag("KHAOS_AUTO_SYNC_CLEANUP", False)
AUTO_SYNC_CLEANUP_LOGS_DEFAULT = _env_flag("KHAOS_AUTO_SYNC_CLEANUP_LOGS", False)
