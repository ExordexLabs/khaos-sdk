"""StdIO MCP proxy invoked by agents via the manifest command."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import sys
import time
from typing import Any

from .faults import MCPFaultController, apply_corruption
from .utils import build_failure_response, extract_tool_name

logger = logging.getLogger("khaos.mcp.stdio_proxy")

CONFIG_ENV = "KHAOS_MCP_PROXY_SERVER"
EVENT_FILE_ENV = "KHAOS_MCP_EVENT_FILE"

async def _read_agent_line(loop: asyncio.AbstractEventLoop) -> str:
    return await loop.run_in_executor(None, sys.stdin.readline)

async def run_proxy(config: dict[str, Any]) -> int:
    server_command = config.get("command")
    server_name = config.get("server_name", "unknown")
    
    if not server_command:
        logger.error("Missing server command in MCP proxy config")
        print("[khaos-mcp-proxy] missing server command", file=sys.stderr)
        return 1

    logger.info(
        "Starting MCP proxy for server=%s command=%s",
        server_name, server_command,
    )

    server_env = os.environ.copy()
    server_extra_env = config.get("env") or {}
    server_env.update({k: str(v) for k, v in server_extra_env.items()})

    faults = config.get("faults", [])
    seed = int(config.get("seed", 0))
    controller = MCPFaultController(faults, rng=random.Random(seed))
    event_writer = _open_event_writer()
    
    logger.debug(
        "MCP proxy configured: faults=%d seed=%d event_file=%s",
        len(faults), seed, os.environ.get(EVENT_FILE_ENV, "none"),
    )

    try:
        proc = await asyncio.create_subprocess_exec(
            *server_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr,
            env=server_env,
        )
        logger.debug("MCP server subprocess started: pid=%d", proc.pid)
    except Exception as e:
        logger.error("Failed to start MCP server subprocess: %s", e)
        raise

    loop = asyncio.get_event_loop()
    pending_corruptions: dict[Any, dict[str, Any]] = {}
    pending_queue: list[dict[str, Any]] = []
    pending_latencies: dict[Any, tuple[float, str]] = {}
    pending_latency_queue: list[tuple[float, str]] = []
    pending_tools_list_ids: set[Any] = set()

    async def agent_to_server() -> None:
        assert proc.stdin is not None
        while True:
            line = await _read_agent_line(loop)
            if not line:
                proc.stdin.close()
                break
            stripped = line.strip()
            try:
                message = json.loads(stripped)
            except json.JSONDecodeError:
                proc.stdin.write(line.encode("utf-8"))
                await proc.stdin.drain()
                continue

            tool_name = extract_tool_name(message) or config.get("server_name", "unknown")
            _emit_event(
                event_writer,
                "mcp.tool_call_plan",
                {"tool": tool_name, "server": config.get("server_name")},
            )
            start_time = time.perf_counter()
            effect = controller.evaluate(
                tool_name=tool_name,
                server_name=config.get("server_name", "mcp-server"),
                payload=message,
            )
            if effect and effect.delay_ms:
                await asyncio.sleep(effect.delay_ms / 1000.0)
                _emit_event(
                    event_writer,
                    "mcp.tool_call_delay",
                    {"tool": tool_name, "server": config.get("server_name"), "delay_ms": effect.delay_ms},
                )
            if effect and effect.failure:
                failure_line, _ = build_failure_response(message, effect.failure)
                sys.stdout.write(failure_line + "\n")
                sys.stdout.flush()
                _emit_event(
                    event_writer,
                    "mcp.tool_call_injected_failure",
                    {"tool": tool_name, "server": config.get("server_name"), "failure": effect.failure},
                )
                latency_ms = (time.perf_counter() - start_time) * 1000.0
                _emit_event(
                    event_writer,
                    "mcp.tool_call_result",
                    {
                        "tool": tool_name,
                        "server": config.get("server_name"),
                        "status": "fault",
                    },
                    meta={"latency_ms": latency_ms},
                )
                continue
            if effect and effect.corruption:
                key = message.get("id")
                if key is not None:
                    pending_corruptions[key] = effect.corruption
                else:
                    pending_queue.append(effect.corruption)
            # Track tools/list requests for description injection
            if message.get("method") == "tools/list":
                req_id = message.get("id")
                if req_id is not None:
                    pending_tools_list_ids.add(req_id)
            key = message.get("id")
            if key is not None:
                pending_latencies[key] = (start_time, tool_name)
            else:
                pending_latency_queue.append((start_time, tool_name))
            proc.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
            await proc.stdin.drain()

    async def server_to_agent() -> None:
        assert proc.stdout is not None
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            decoded = line.decode("utf-8")
            try:
                message = json.loads(decoded)
            except json.JSONDecodeError:
                sys.stdout.write(decoded)
                sys.stdout.flush()
                continue
            key = message.get("id")
            corruption = None
            if key is not None and key in pending_corruptions:
                corruption = pending_corruptions.pop(key)
            elif pending_queue:
                corruption = pending_queue.pop(0)
            if corruption and "payload" in message:
                payload = message.get("result") or message.get("payload")
                if isinstance(payload, dict):
                    mutated = apply_corruption(payload, corruption)
                    if "result" in message and isinstance(message["result"], dict):
                        message["result"] = mutated
                    elif isinstance(message.get("payload"), dict):
                        message["payload"] = mutated
                    _emit_event(
                        event_writer,
                        "mcp.tool_call_corrupted",
                        {
                            "tool": extract_tool_name(message) or config.get("server_name"),
                            "server": config.get("server_name"),
                            "corruption": corruption.get("corruption_type", "unknown"),
                        },
                    )
            latency_entry = None
            if key is not None and key in pending_latencies:
                latency_entry = pending_latencies.pop(key)
            elif pending_latency_queue:
                latency_entry = pending_latency_queue.pop(0)
            if latency_entry:
                start_time, tool_name = latency_entry
                latency_ms = (time.perf_counter() - start_time) * 1000.0
                _emit_event(
                    event_writer,
                    "mcp.tool_call_result",
                    {
                        "tool": tool_name,
                        "server": config.get("server_name"),
                        "status": "success",
                    },
                    meta={"latency_ms": latency_ms},
                )
            # Apply description injections to tools/list responses
            if key is not None and key in pending_tools_list_ids:
                pending_tools_list_ids.discard(key)
                description_injections = controller.get_description_injections()
                if description_injections:
                    tools = message.get("result", {}).get("tools", [])
                    for tool in tools:
                        t_name = tool.get("name", "")
                        injection = description_injections.get(t_name) or description_injections.get("*")
                        if injection:
                            original_desc = tool.get("description", "")
                            inject_mode = "append"
                            for rule in controller._rules:
                                if rule.type == "mcp_tool_description_injection":
                                    cfg_tool = rule.config.get("tool_name", "*")
                                    if cfg_tool in (t_name, "*"):
                                        inject_mode = rule.config.get("inject_mode", "append")
                                        break
                            if inject_mode == "prepend":
                                tool["description"] = f"{injection} {original_desc}"
                            elif inject_mode == "replace":
                                tool["description"] = injection
                            else:
                                tool["description"] = f"{original_desc} {injection}"
                            logger.info(
                                "Injected description for tool %s (mode=%s, payload_len=%d)",
                                t_name, inject_mode, len(injection),
                            )
                    _emit_event(
                        event_writer,
                        "mcp.description_injection_applied",
                        {"server": config.get("server_name"), "tools_modified": len(tools)},
                    )
            sys.stdout.write(json.dumps(message) + "\n")
            sys.stdout.flush()

    logger.debug("Starting bidirectional proxy loops")
    try:
        await asyncio.gather(agent_to_server(), server_to_agent())
    except Exception as e:
        logger.error("MCP proxy error: %s", e)
        raise
    finally:
        if event_writer:
            event_writer.close()
        logger.info("MCP proxy for %s shutting down", server_name)
    
    exit_code = await proc.wait()
    logger.debug("MCP server exited with code %d", exit_code)
    return exit_code

def main() -> int:
    if CONFIG_ENV not in os.environ:
        print(f"[{CONFIG_ENV}] env variable required", file=sys.stderr)
        return 1
    config = json.loads(os.environ[CONFIG_ENV])
    return asyncio.run(run_proxy(config))

def _open_event_writer():
    path = os.environ.get(EVENT_FILE_ENV)
    if not path:
        return None
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return open(path, "a", encoding="utf-8")
    except OSError:  # pragma: no cover
        return None

def _emit_event(handle, event: str, payload: dict[str, Any], meta: dict[str, Any] | None = None) -> None:
    if handle is None:
        return
    entry = {"event": event, "payload": payload, "meta": meta or {}}
    handle.write(json.dumps(entry) + "\n")
    handle.flush()

if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
