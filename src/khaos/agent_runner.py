"""Subprocess runner for @khaosagent decorated Python agents.

This is the standard agent execution runtime:

- Users write a Python handler (sync or async) decorated with `@khaosagent`.
- Khaos automatically detects entry points and runs agents in a subprocess.
- All telemetry capture, fault injection, and security testing is handled automatically.

The @khaosagent decorator is the only supported agent interface.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import inspect
import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections.abc import Callable

logger = logging.getLogger(__name__)

# Import output utilities - use local fallback if khaos package not fully loaded
try:
    from khaos.output import extract_output_text, extract_input_text
except ImportError:
    # Minimal fallback implementation for bootstrap scenarios
    def extract_output_text(payload: Any) -> str:
        if payload is None:
            return ""
        if isinstance(payload, str):
            return payload
        if isinstance(payload, dict):
            for key in ("content", "text", "message", "value", "result", "response", "output"):
                val = payload.get(key)
                if isinstance(val, str) and val.strip():
                    return val
            try:
                return json.dumps(payload)
            except Exception:
                return str(payload)
        return str(payload)

    def extract_input_text(message: dict) -> str:
        if not isinstance(message, dict):
            return str(message) if message else ""
        payload = message.get("payload", {})
        if isinstance(payload, dict):
            for key in ("text", "prompt", "input", "message", "content", "query", "value"):
                val = payload.get(key)
                if isinstance(val, str) and val.strip():
                    return val
        try:
            return json.dumps(payload)
        except Exception:
            return str(payload)

@dataclass(frozen=True, slots=True)
class _RunnerArgs:
    script: Path
    handler: str | None

def _parse_args(argv: list[str]) -> _RunnerArgs:
    parser = argparse.ArgumentParser(prog="khaos.agent-runner")
    parser.add_argument("--script", required=True, help="Path to the user agent Python script.")
    parser.add_argument(
        "--handler",
        required=False,
        default=None,
        help="Optional handler name (module attribute). If omitted, a @khaos_agent handler is required.",
    )
    ns = parser.parse_args(argv)
    return _RunnerArgs(script=Path(ns.script), handler=ns.handler)

def _load_module_from_script(script: Path) -> Any:
    if not script.exists():
        raise FileNotFoundError(f"Agent script not found: {script}")
    spec = importlib.util.spec_from_file_location("khaos_user_agent", script)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"Failed to import script: {script}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["khaos_user_agent"] = module
    spec.loader.exec_module(module)
    return module

def _is_khaos_agent_handler(value: Any) -> bool:
    return callable(value) and bool(getattr(value, "__khaos_agent__", False))

def _select_handler(module: Any, *, handler_name: str | None) -> Callable[[dict[str, Any]], Any]:
    """Select handler from module by name (function name or agent name).

    The handler_name can be either:
    - A function/attribute name (e.g., "my_handler")
    - An agent name from @khaosagent(name="agent-name")

    Priority:
    1. Exact attribute name match
    2. Agent name match (__khaos_name__ attribute)
    3. Single decorated handler (if no name specified)
    """
    # Collect all decorated handlers for potential matching
    decorated: list[Callable[[dict[str, Any]], Any]] = []
    for attr_name, value in vars(module).items():
        if _is_khaos_agent_handler(value):
            decorated.append(value)

    if handler_name:
        # First try: exact attribute name match
        candidate = getattr(module, handler_name, None)
        if callable(candidate):
            return candidate

        # Second try: match by agent name (__khaos_name__)
        for fn in decorated:
            agent_name = getattr(fn, "__khaos_name__", None)
            if agent_name == handler_name:
                return fn

            # Also check the function name for backwards compatibility
            if getattr(fn, "__name__", "") == handler_name:
                return fn

        raise ValueError(f"Handler '{handler_name}' not found in {module.__file__}")

    # No handler specified - auto-select if single decorated handler exists
    if len(decorated) == 1:
        return decorated[0]
    if len(decorated) > 1:
        # Collect both function names and agent names for helpful error message
        candidates = []
        for fn in decorated:
            func_name = getattr(fn, "__name__", "<handler>")
            agent_name = getattr(fn, "__khaos_name__", None)
            if agent_name and agent_name != func_name:
                candidates.append(f"{func_name} (name='{agent_name}')")
            else:
                candidates.append(func_name)
        raise ValueError(
            "Multiple @khaosagent handlers found. Give each agent a unique "
            "@khaosagent(name=...) and run by agent name.\n"
            f"Candidates: {', '.join(candidates)}"
        )
    raise ValueError(
        "No @khaosagent handler found. Add `@khaosagent(name=..., version=...)` to an agent handler function."
    )

def _normalize_response(result: Any) -> dict[str, Any]:
    if result is None:
        return {"name": "agent.response", "payload": {}}

    if isinstance(result, dict) and "name" in result and "payload" in result:
        name = result.get("name") or "agent-response"
        payload = result.get("payload") if isinstance(result.get("payload"), dict) else {}
        return {"name": name, "payload": payload}

    if isinstance(result, tuple) and len(result) == 2:
        name, payload = result
        return {
            "name": str(name or "agent-response"),
            "payload": payload if isinstance(payload, dict) else {"value": payload},
        }

    if isinstance(result, dict):
        return {"name": "agent.response", "payload": result}

    return {"name": "agent.response", "payload": {"value": result}}

def _extract_prompt_from_message(message: dict[str, Any]) -> str:
    """Extract prompt text from a message using the unified helper."""
    return extract_input_text(message)

def _call_user_callable(fn: Callable[..., Any], message: dict[str, Any]) -> Any:
    """Invoke user callable with a best-effort signature adapter (zero-decision UX)."""

    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):  # pragma: no cover - C-callables etc.
        return fn(message)

    params = list(sig.parameters.values())
    if not params:
        return fn()

    if len(params) == 1:
        param = params[0]
        # If the handler looks like it wants a prompt/text string, provide that.
        if param.annotation is str or param.name.lower() in {"prompt", "text", "message", "input", "content"}:
            return fn(_extract_prompt_from_message(message))
        return fn(message)

    # For multi-arg callables, provide (name, payload) as a pragmatic default.
    name = message.get("name", "")
    payload = message.get("payload") if isinstance(message.get("payload"), dict) else {}
    return fn(name, payload)

async def _call_handler(handler: Callable[[dict[str, Any]], Any], message: dict[str, Any]) -> dict[str, Any]:
    try:
        # Normalize security probes into a "user-like" message for framework-agnostic agents.
        if message.get("name") == "security.attack":
            prompt = _extract_prompt_from_message(message)
            payload = dict(message.get("payload") if isinstance(message.get("payload"), dict) else {})
            payload.setdefault("text", prompt)
            payload.setdefault("prompt", prompt)
            payload.setdefault("input", prompt)
            payload.setdefault("content", prompt)
            message = {
                "name": "user.message",
                "payload": payload,
                "metadata": {"original_name": "security.attack"},
            }

        result = _call_user_callable(handler, message)
        if inspect.isawaitable(result):
            result = await result
        return _normalize_response(result)
    except Exception as exc:
        # Preserve protocol: return an error envelope rather than crashing the transport.
        return {
            "name": "agent.response",
            "payload": {
                "status": "error",
                "error": str(exc),
            },
        }

def _apply_turn_faults(payload: dict[str, Any]) -> None:
    """Apply per-turn faults from message payload.

    Multi-turn packs can specify faults per-turn in the message payload.
    This updates the active fault rules before the handler processes the message.
    """
    turn_faults = payload.get("khaos_faults")
    if turn_faults and isinstance(turn_faults, list):
        try:
            from khaos.llm.faults import update_active_rules as update_llm_rules
            from khaos.http.faults import update_active_rules as update_http_rules

            # Both shims ignore unsupported rule types; safe to pass the full list.
            update_llm_rules(turn_faults)
            update_http_rules(turn_faults)
        except ImportError:
            pass  # Faults module not available

def _clear_turn_faults() -> None:
    """Clear per-turn faults after handling a message."""
    try:
        from khaos.llm.faults import clear_active_rules as clear_llm_rules
        from khaos.http.faults import clear_active_rules as clear_http_rules

        clear_llm_rules()
        clear_http_rules()
    except ImportError:
        pass

def _emit_turn_event(turn_index: int, input_preview: str, event_type: str = "turn.start") -> None:
    """Emit a turn boundary event for tracing.

    This helps the trace builder group events by turn within a multi-turn case.
    """
    from datetime import datetime, timezone

    event_file = os.environ.get("KHAOS_LLM_EVENT_FILE")
    if not event_file:
        return

    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        "payload": {
            "turn_index": turn_index,
            "input_preview": input_preview[:100] if input_preview else "",
        },
        "meta": {},
    }

    try:
        from pathlib import Path
        out_path = Path(event_file)
        with out_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except Exception:
        logger.debug("Failed to write turn event to event file", exc_info=True)

async def _run_loop(args: _RunnerArgs) -> int:
    # Apply auto-wrap shims (LLM telemetry + faults + security) before importing user code.
    # This is the backbone of the "no plumbing" decorator flow.
    try:
        import khaos.auto_wrap_shim  # noqa: F401
    except Exception:
        logger.debug("Failed to load auto_wrap_shim", exc_info=True)

    module = _load_module_from_script(args.script)
    handler_name = args.handler or os.environ.get("KHAOS_AGENT_HANDLER")
    handler = _select_handler(module, handler_name=handler_name)

    turn_index = 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            incoming = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(incoming, dict):
            continue
        name = str(incoming.get("name", ""))
        payload = incoming.get("payload")
        if not isinstance(payload, dict):
            payload = {}

        # Apply per-turn faults from message payload (multi-turn support)
        _apply_turn_faults(payload)

        # Emit turn start event for tracing
        input_text = _extract_prompt_from_message({"payload": payload})
        _emit_turn_event(turn_index, input_text, "turn.start")

        message = {"name": name, "payload": payload, "metadata": {}}
        response = await _call_handler(handler, message)

        # Emit turn end event
        response_text = response.get("payload", {}).get("text", "")
        _emit_turn_event(turn_index, response_text, "turn.end")

        # Clear per-turn faults after handling
        _clear_turn_faults()

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()

        turn_index += 1

    return 0

def main(argv: list[str] | None = None) -> int:
    args = _parse_args(list(argv) if argv is not None else sys.argv[1:])
    try:
        return asyncio.run(_run_loop(args))
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    except Exception as exc:
        # If the runner cannot even start (import error, no handler, etc.),
        # emit a single protocol message so callers can surface a clean error.
        error_envelope = {
            "name": "agent.response",
            "payload": {"status": "error", "error": str(exc)},
        }
        try:
            sys.stdout.write(json.dumps(error_envelope) + "\n")
            sys.stdout.flush()
        except Exception:
            logger.debug("Failed to write error envelope to stdout", exc_info=True)
        return 1

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
