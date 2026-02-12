"""Subprocess stdio transport adapter."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import shlex
import sys
import time
import uuid

logger = logging.getLogger(__name__)
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TYPE_CHECKING

from .base import (
    AgentTransport,
    TransportError,
    TransportExit,
    TransportMessage,
    TransportProtocolError,
    TransportTimeout,
)

if TYPE_CHECKING:  # pragma: no cover - used for type checking only
    from .registry import TransportContext


@dataclass(slots=True)
class SubprocessConfig:
    command: list[str]
    working_dir: Path
    env: dict[str, str]
    startup_timeout: float = 10.0
    read_timeout: float = 30.0
    inherit_env: bool = False
    stderr_path: Path | None = None
    allow_env: set[str] | None = None
    deny_env: set[str] | None = None
    stderr_mode: Literal["file", "inherit", "discard"] = "file"
    stderr_max_lines: int = 200


class SubprocessTransport(AgentTransport):
    """Transport adapter that communicates with an agent via stdio."""

    def __init__(self, config: SubprocessConfig) -> None:
        self.config = config
        self._process: asyncio.subprocess.Process | None = None
        self._agent_id = f"subprocess://{uuid.uuid4()}"
        self._stderr_task: asyncio.Task | None = None
        self._stderr_lines: list[str] = []
        self._env_snapshot: dict[str, str] = {}
        self.llm_event_path: Path | None = None
        raw_llm_path = self.config.env.get("KHAOS_LLM_EVENT_FILE")
        if raw_llm_path:
            try:
                self.llm_event_path = Path(raw_llm_path).expanduser()
            except Exception:  # pragma: no cover - defensive
                self.llm_event_path = None

    @property
    def agent_id(self) -> str:
        return self._agent_id

    async def _ensure_started(self) -> None:
        if self._process is not None:
            return

        self.config.working_dir.mkdir(parents=True, exist_ok=True)
        allowlist_env = self.config.allow_env or set()
        denylist_env = self.config.deny_env or set()
        env: dict[str, str] = {}
        if self.config.inherit_env:
            env.update(os.environ)
        else:
            env.update({k: v for k, v in os.environ.items() if k.startswith("KHAOS_")})
            for allowed in allowlist_env.union({"PATH", "PYTHONPATH", "PYTHONHOME"}):
                if allowed in os.environ:
                    env.setdefault(allowed, os.environ[allowed])
        env.update(self.config.env)
        for denied in denylist_env:
            env.pop(denied, None)
        self._env_snapshot = env.copy()

        command = list(self.config.command)
        # Run decorator-based agents via `khaos.agent_runner` so users never have to
        # implement the stdio transport protocol manually.
        if os.environ.get("KHAOS_AUTO_WRAP", "1").lower() not in {"0", "false", "no", "off"}:
            if len(command) >= 2 and Path(command[1]).exists():
                python_cmd = command[0]
                target_script = str(Path(command[1]).resolve())
                command = [python_cmd, "-m", "khaos.agent_runner", "--script", target_script]

        self._process = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(self.config.working_dir),
            env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await self._start_stderr_task()

    async def send(self, message: TransportMessage) -> None:
        await self._ensure_started()
        if self._process is None or self._process.stdin is None:
            raise RuntimeError("Subprocess transport not started or stdin unavailable")
        if self._process.returncode is not None:
            raise TransportExit(f"Agent exited with code {self._process.returncode}")
        payload = json.dumps({"name": message.name, "payload": message.payload}) + "\n"
        self._process.stdin.write(payload.encode("utf-8"))
        await self._process.stdin.drain()

    async def receive(self, timeout: float | None = None) -> TransportMessage:
        await self._ensure_started()
        if self._process is None or self._process.stdout is None:
            raise RuntimeError("Subprocess transport not started or stdout unavailable")
        if self._process.returncode is not None:
            return await self._handle_process_exit()
        read_timeout = timeout or self.config.read_timeout
        try:
            line = await asyncio.wait_for(self._process.stdout.readline(), timeout=read_timeout)
        except asyncio.TimeoutError as exc:
            # If the process has already exited, surface that instead of a timeout.
            if self._process.returncode is not None:
                return await self._handle_process_exit()
            stderr_tail = "\n".join(self._stderr_lines[-10:]) if self._stderr_lines else "(no stderr captured)"
            error_msg = (
                f"Agent did not respond within {read_timeout:.0f} seconds.\n\n"
                f"Possible causes:\n"
                f"  1. Agent is stuck in an infinite loop\n"
                f"  2. Agent is waiting for user input\n"
                f"  3. LLM API call is taking too long\n"
                f"  4. Agent crashed silently\n\n"
                f"Agent stderr (last 10 lines):\n{stderr_tail}\n\n"
                f"Debugging:\n"
                f"  - Increase timeout: khaos run <agent-name> --timeout 120\n"
                f"  - Ensure your agent is decorated and discovered: khaos discover"
            )
            raise TransportTimeout(error_msg) from exc

        if not line:
            return await self._handle_process_exit()

        try:
            data = json.loads(line.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raw_output = line.decode("utf-8", errors="ignore").strip()
            # Truncate long output for readability
            display_output = raw_output[:200] + "..." if len(raw_output) > 200 else raw_output

            error_msg = (
                f"Agent printed text instead of JSON protocol.\n\n"
                f"Your agent output: \"{display_output}\"\n\n"
                f"This usually means your agent isn't running via the Khaos protocol runner.\n\n"
                f"Solutions:\n"
                f"  1. Add the @khaosagent decorator to your agent handler.\n"
                f"  2. Run `khaos discover`, then run by name: khaos run <agent-name>"
            )
            raise TransportProtocolError(error_msg) from exc

        return TransportMessage(name=data.get("name", ""), payload=data.get("payload", {}))

    async def _handle_process_exit(self) -> TransportMessage:
        if self._process is None:
            raise RuntimeError("Cannot handle exit: subprocess not started")
        returncode = await self._process.wait()
        stderr_output = ""
        if self._stderr_task is not None:
            await self._stderr_task
            stderr_output = "\n".join(self._stderr_lines)
        elif self._process.stderr is not None:
            stderr_output = (
                await self._process.stderr.read()
            ).decode("utf-8", errors="ignore")

        # Build a helpful error message with suggestions
        error_parts = [f"Agent exited with code {returncode}."]

        # Detect common error patterns and provide targeted suggestions
        stderr_lower = stderr_output.lower()
        suggestions: list[str] = []

        # API key errors
        if any(p in stderr_lower for p in ["api key", "api_key", "apikey", "authentication", "401", "unauthorized"]):
            if "openai" in stderr_lower or "gpt" in stderr_lower:
                suggestions.append(
                    "Missing OpenAI API key?\n"
                    "  Fix: khaos run <agent-name> --env OPENAI_API_KEY=sk-xxx"
                )
            elif "anthropic" in stderr_lower or "claude" in stderr_lower:
                suggestions.append(
                    "Missing Anthropic API key?\n"
                    "  Fix: khaos run <agent-name> --env ANTHROPIC_API_KEY=sk-ant-xxx"
                )
            else:
                suggestions.append(
                    "API authentication failed.\n"
                    "  Pass API keys with: --env API_KEY=xxx"
                )

        # Rate limit errors
        if any(p in stderr_lower for p in ["rate limit", "rate_limit", "429", "too many requests"]):
            suggestions.append(
                "Rate limited by API provider.\n"
                "  Wait a moment and try again, or check your API quota."
            )

        # Module/import errors
        if any(p in stderr_lower for p in ["modulenotfounderror", "importerror", "no module named"]):
            suggestions.append(
                "Missing Python dependency.\n"
                "  Install requirements: pip install -r requirements.txt"
            )

        # Timeout errors
        if any(p in stderr_lower for p in ["timeout", "timed out"]):
            suggestions.append(
                "API request timed out.\n"
                "  Try increasing timeout: --transport-option read_timeout=120"
            )

        # Add stderr excerpt
        if stderr_output:
            # Show last 15 lines of stderr
            stderr_lines = stderr_output.strip().split("\n")
            if len(stderr_lines) > 15:
                stderr_excerpt = "\n".join(stderr_lines[-15:])
                error_parts.append(f"\nStderr (last 15 lines):\n{stderr_excerpt}")
            else:
                error_parts.append(f"\nStderr:\n{stderr_output.strip()}")

        # Add suggestions
        if suggestions:
            error_parts.append("\nPossible solutions:")
            for suggestion in suggestions:
                error_parts.append(f"  - {suggestion}")
        else:
            # Generic suggestions for unknown errors
            error_parts.append(
                "\nDebugging tips:\n"
                "  - Run agent directly: python your_agent.py\n"
                "  - Check API keys: --env KEY=VALUE\n"
                "  - For vanilla agents: khaos observe agent.py"
            )

        raise TransportExit("\n".join(error_parts))

    async def close(self) -> None:
        if self._process is None:
            return
        if self._process.stdin:
            self._process.stdin.close()
        try:
            await asyncio.wait_for(self._process.wait(), timeout=5)
        except asyncio.TimeoutError:
            self._process.kill()
            await self._process.wait()
        if self._stderr_task is not None:
            self._stderr_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._stderr_task
            self._stderr_task = None
        self._process = None

    def configure_transport_faults(self, faults: list[dict[str, Any]], *, seed: int | None = None) -> None:
        """Propagate transport-scoped faults to the child process via environment.

        This enables ADR-0010 LLM interception by passing rules to the LLM shim so it
        can patch SDK clients directly (OpenAI/Anthropic). MCP transports handle their
        own fault wiring separately.
        """

        if not faults:
            return
        llm_faults = [
            fault
            for fault in faults
            if fault.get("type")
            in {
                "llm_rate_limit",
                "llm_model_unavailable",
                "llm_response_timeout",
                "llm_token_quota_exceeded",
                "model_fallback_forced",
            }
        ]
        http_faults = [
            fault
            for fault in faults
            if fault.get("type")
            in {
                "tool_call_failure",
                "tool_response_corruption",
                "tool_latency_spike",
                "rag_retrieval_corruption",
                "rag_document_poisoning",
                "tool_output_injection",
            }
        ]
        if not http_faults and not llm_faults:
            return
        env = dict(self.config.env or {})
        if llm_faults:
            env["KHAOS_LLM_FAULTS"] = json.dumps(llm_faults)
        if http_faults:
            env["KHAOS_HTTP_FAULTS"] = json.dumps(http_faults)
        if seed is not None:
            env.setdefault("KHAOS_FAULT_SEED", str(seed))
        env.setdefault("KHAOS_LLM_SHIM", env.get("KHAOS_LLM_SHIM", "1"))
        self.config.env = env

    def configure_security_attacks(
        self,
        attacks: list[dict[str, Any]],
        *,
        attack_mode: str = "interleave",
    ) -> None:
        """Propagate security attacks to the child process via environment.

        This enables zero-code security testing by passing attack configurations to
        the security shim, which injects attacks at the LLM API level.

        Args:
            attacks: List of security attack configurations with attack_id, attack_type, payload
            attack_mode: Injection mode - "interleave" (parallel calls), "prepend", "append", "replace"
        """
        if not attacks:
            return
        env = dict(self.config.env or {})
        env["KHAOS_SECURITY_ATTACKS"] = json.dumps(attacks)
        env["KHAOS_SECURITY_ATTACK_MODE"] = attack_mode
        self.config.env = env

    async def _start_stderr_task(self) -> None:
        if self._process is None:
            raise RuntimeError("Cannot start stderr task: subprocess not started")
        if self._process.stderr is None:
            return
        mode = self.config.stderr_mode
        store_lines = mode != "discard"
        max_lines = max(1, self.config.stderr_max_lines)
        self._stderr_lines = []

        async def _pump() -> None:
            stream = self._process.stderr
            file_handle = None
            open_file = self.config.stderr_path is not None and mode in {"file", "inherit"}
            if open_file:
                path = self.config.stderr_path
                if path is None:
                    raise RuntimeError("stderr_path is required when stderr_mode is 'file' or 'inherit'")
                path.parent.mkdir(parents=True, exist_ok=True)
                file_handle = path.open("a", encoding="utf-8")
            try:
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    text = line.decode("utf-8", errors="ignore")
                    if store_lines:
                        self._stderr_lines.append(text.rstrip())
                        if len(self._stderr_lines) > max_lines:
                            self._stderr_lines = self._stderr_lines[-max_lines:]
                    if file_handle:
                        file_handle.write(text)
                        file_handle.flush()
                    if mode == "inherit":
                        sys.stderr.write(text)
                        sys.stderr.flush()
            finally:
                if file_handle:
                    file_handle.close()

        self._stderr_task = asyncio.create_task(_pump())

    @property
    def environment(self) -> dict[str, str]:
        """Expose the effective environment (primarily for testing)."""

        return dict(self._env_snapshot)


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return bool(value) if value is not None else default


def _coerce_float(value: Any, default: float) -> float:
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _coerce_list(value: Any) -> set[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        items = [part.strip() for part in value.split(",") if part.strip()]
        return set(items) if items else None
    if isinstance(value, (list, tuple, set)):
        return {str(item).strip() for item in value if str(item).strip()}
    return None


def build_subprocess_transport(
    context: "TransportContext", options: dict[str, Any] | None = None
) -> SubprocessTransport:
    """Factory function registered with the transport registry."""

    opts = options or {}
    python_path = str(opts.get("python") or context.python_path)
    raw_command = opts.get("command")
    if raw_command:
        if isinstance(raw_command, str):
            command = shlex.split(raw_command)
        elif isinstance(raw_command, (list, tuple)):
            command = [str(part) for part in raw_command]
        else:
            raise ValueError("command option must be a string or list")
    else:
        command = [python_path, context.target]

    working_dir = Path(opts.get("working_dir", context.working_dir)).expanduser()
    working_dir.mkdir(parents=True, exist_ok=True)

    stderr_mode = str(opts.get("stderr_mode", "file")).strip().lower()
    if stderr_mode not in {"file", "inherit", "discard"}:
        raise ValueError("stderr_mode must be one of: file, inherit, discard")
    stderr_max_lines = int(opts.get("stderr_max_lines", 200))
    stderr_path_value = opts.get("stderr_path", context.stderr_path)
    stderr_path = None
    if stderr_path_value is not None and stderr_mode in {"file", "inherit"}:
        stderr_path = Path(stderr_path_value).expanduser()
        stderr_path.parent.mkdir(parents=True, exist_ok=True)

    env = dict(context.env)
    extra_env = opts.get("env")
    if isinstance(extra_env, dict):
        env.update({str(k): str(v) for k, v in extra_env.items()})

    inherit_env = _coerce_bool(opts.get("inherit_env"), False)
    allow_env = _coerce_list(opts.get("allow_env"))
    deny_env = _coerce_list(opts.get("deny_env"))
    startup_timeout = _coerce_float(opts.get("startup_timeout"), 10.0)
    read_timeout = _coerce_float(opts.get("read_timeout"), 30.0)

    config = SubprocessConfig(
        command=command,
        working_dir=working_dir,
        env=env,
        stderr_path=stderr_path,
        inherit_env=inherit_env,
        allow_env=allow_env,
        deny_env=deny_env,
        stderr_mode=stderr_mode,
        stderr_max_lines=stderr_max_lines,
        startup_timeout=startup_timeout,
        read_timeout=read_timeout,
    )
    return SubprocessTransport(config)
