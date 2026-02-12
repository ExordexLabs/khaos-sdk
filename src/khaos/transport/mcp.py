"""MCP transport adapters with telemetry and config plumbing."""

from __future__ import annotations

import hashlib
import json
import logging
import random
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

from khaos.mcp.events import MCPEventBuffer
from khaos.mcp.faults import MCPFaultController, MCPFaultEffect, apply_corruption
from khaos.mcp.http_proxy import MCPHTTPProxy
from khaos.mcp.inspect import load_tools_via_http, load_tools_via_stdio
from ..agent import (
    AgentCapability,
    AgentCategory,
    AgentMetadata,
    discover_agent_metadata,
    register_discovered_agent,
)
from .base import AgentTransport, TransportMessage
from .registry import TransportContext
from .subprocess import SubprocessTransport, build_subprocess_transport

@dataclass
class MCPServerDefinition:
    """Describes an MCP server the agent will interact with."""

    name: str
    transport: str = "stdio"
    command: list[str] | None = None
    url: str | None = None
    env: dict[str, str] | None = None

class MCPStdIOTransport(AgentTransport):
    """Wrapper that delegates to a subprocess transport while tracking MCP config."""

    def __init__(
        self,
        context: TransportContext,
        agent_transport: SubprocessTransport,
        servers: list[MCPServerDefinition],
        options: dict[str, Any] | None = None,
    ) -> None:
        self._context = context
        self._agent = agent_transport
        self._servers = servers
        self._agent_id = f"mcp-stdio://{self._agent.agent_id}"
        self._event_buffer = MCPEventBuffer(context.run_id, self._agent_id)
        fault_rules = (options or {}).get("faults") or []
        self._fault_rules_raw = [dict(rule) for rule in fault_rules]
        self._fault_seed = int(
            hashlib.sha256(context.run_id.encode("utf-8")).hexdigest()[:8], 16
        )
        self._faults = MCPFaultController(
            self._fault_rules_raw, rng=random.Random(self._fault_seed)
        )
        self._servers_env_applied = False
        self._server_manifest: list[dict[str, Any]] = []
        self._http_proxies: list[MCPHTTPProxy] = []
        self._proxy_event_files: dict[str, tuple[Path, int]] = {}
        self._runtime_registered = False

    def configure_transport_faults(self, faults: list[dict[str, Any]], *, seed: int | None = None) -> None:
        """Allow the runtime to append additional MCP fault rules."""

        additions = [dict(rule) for rule in (faults or []) if rule]
        new_added = False
        for rule in additions:
            if rule not in self._fault_rules_raw:
                self._fault_rules_raw.append(rule)
                new_added = True
        llm_faults = [
            rule
            for rule in additions
            if rule.get("type")
            in {
                "llm_rate_limit",
                "llm_model_unavailable",
                "llm_response_timeout",
                "llm_token_quota_exceeded",
                "model_fallback_forced",
            }
        ]
        http_faults = [
            rule
            for rule in additions
            if rule.get("type")
            in {
                "tool_call_failure",
                "tool_response_corruption",
                "tool_latency_spike",
                "rag_retrieval_corruption",
                "rag_document_poisoning",
                "tool_output_injection",
            }
        ]
        if llm_faults or http_faults:
            env_copy = dict(self._agent.config.env or {})
            if llm_faults:
                env_copy["KHAOS_LLM_FAULTS"] = json.dumps(llm_faults)
            if http_faults:
                env_copy["KHAOS_HTTP_FAULTS"] = json.dumps(http_faults)
            if seed is not None:
                env_copy.setdefault("KHAOS_FAULT_SEED", str(seed))
            env_copy.setdefault("KHAOS_LLM_SHIM", env_copy.get("KHAOS_LLM_SHIM", "1"))
            self._agent.config.env = env_copy
        if not new_added:
            return
        self._faults = MCPFaultController(
            self._fault_rules_raw,
            rng=random.Random(self._fault_seed),
        )
        self._reset_environment()

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def servers(self) -> list[MCPServerDefinition]:
        return list(self._servers)

    async def send(self, message: TransportMessage) -> None:
        self._ensure_environment()
        await self._agent.send(message)

    async def receive(self, timeout: float | None = None) -> TransportMessage:
        self._ensure_environment()
        return await self._agent.receive(timeout)

    async def close(self) -> None:
        await self._agent.close()
        for proxy in self._http_proxies:
            proxy.close()
        self._http_proxies = []

    def drain_events(self):
        self._ensure_environment()
        self._collect_proxy_events()
        return self._event_buffer.drain()

    @property
    def server_manifest(self) -> list[dict[str, Any]]:
        self._ensure_environment()
        return list(self._server_manifest)

    def apply_tool_faults(
        self,
        *,
        tool_name: str,
        server_name: str,
        payload: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any] | None, MCPFaultEffect | None]:
        """Plan a tool call and return mutated payload/effect (for future wrappers)."""

        self._ensure_environment()
        payload = payload or {}
        self._event_buffer.emit(
            "mcp.tool_call_plan",
            {"tool": tool_name, "server": server_name},
        )
        effect = self._faults.evaluate(
            tool_name=tool_name,
            server_name=server_name,
            payload=payload,
        )
        if effect is None:
            return payload, None

        if effect.delay_ms:
            self._event_buffer.emit(
                "mcp.tool_call_delay",
                {
                    "tool": tool_name,
                    "server": server_name,
                    "delay_ms": effect.delay_ms,
                },
            )
        if effect.failure:
            self._event_buffer.emit(
                "mcp.tool_call_injected_failure",
                {
                    "tool": tool_name,
                    "server": server_name,
                    "failure": effect.failure,
                },
            )
        mutated_payload = payload
        if effect.corruption:
            mutated_payload = apply_corruption(payload, effect.corruption)
            self._event_buffer.emit(
                "mcp.tool_call_corrupted",
                {
                    "tool": tool_name,
                    "server": server_name,
                    "corruption": effect.corruption.get("corruption_type", "unknown"),
                },
            )
        return mutated_payload, effect

    def _ensure_environment(self) -> None:
        if self._servers_env_applied:
            return
        manifest = self._prepare_servers()
        env_copy = dict(self._agent.config.env or {})
        if manifest:
            env_copy["KHAOS_MCP_SERVERS"] = json.dumps(manifest)
        if self._fault_rules_raw:
            env_copy["KHAOS_MCP_FAULTS"] = json.dumps(self._fault_rules_raw)
        self._agent.config.env = env_copy
        self._servers_env_applied = True
        self._server_manifest = manifest
        self._register_runtime_agent(manifest)

    def _prepare_servers(self) -> list[dict[str, Any]]:
        manifest: list[dict[str, Any]] = []
        unavailable = self._faults.servers_marked_unavailable()
        for server in self._servers:
            if server.name in unavailable:
                descriptor = self._base_descriptor(server)
                self._event_buffer.emit(
                    "mcp.server_unavailable",
                    descriptor,
                    meta={"reason": "fault"},
                )
                continue

            if server.transport == "stdio" and server.command:
                descriptor = self._wrap_stdio_server(server)
            elif server.transport == "http" and server.url:
                descriptor = self._wrap_http_server(server)
            else:
                descriptor = self._base_descriptor(server)

            manifest.append(descriptor)
            self._event_buffer.emit(
                "mcp.server_registered",
                descriptor,
                meta={"working_dir": str(self._context.working_dir)},
            )
        return manifest

    def _reset_environment(self) -> None:
        if self._servers_env_applied:
            for proxy in self._http_proxies:
                proxy.close()
            self._http_proxies = []
            self._proxy_event_files.clear()
            self._server_manifest = []
            self._servers_env_applied = False

    def _register_runtime_agent(self, manifest: list[dict[str, Any]]) -> None:
        if self._runtime_registered or not manifest:
            return

        entrypoint_path = Path(self._context.target).expanduser()
        metadata: AgentMetadata | None = None
        if entrypoint_path.exists():
            try:
                metadata = discover_agent_metadata(entrypoint_path)
            except Exception:
                logger.debug("Failed to discover agent metadata from %s", entrypoint_path, exc_info=True)
                metadata = None
        if metadata is None:
            name = entrypoint_path.stem if entrypoint_path.name else _slug(self._context.target)
            metadata = AgentMetadata(
                name=name,
                version="runtime",
                code_hash="",
                entrypoint=str(entrypoint_path) if entrypoint_path.exists() else self._context.target,
            )

        metadata.category = metadata.category or AgentCategory.TOOL_AGENT
        capabilities = set(metadata.capabilities or [])
        capabilities.update(
            [
                AgentCapability.TOOL_CALLING.value,
                AgentCapability.MCP.value,
            ]
        )
        metadata.capabilities = sorted(capabilities)
        metadata.metadata.setdefault("mcp_servers", manifest)
        detection_signal = "runtime:mcp"
        metadata.detection_source = metadata.detection_source or detection_signal
        signals = set(metadata.signals or [])
        signals.add(detection_signal)
        metadata.signals = sorted(signals)
        metadata.confidence = max(metadata.confidence or 0.0, 0.8)
        register_discovered_agent(metadata)
        self._runtime_registered = True

    def _base_descriptor(self, server: MCPServerDefinition) -> dict[str, Any]:
        descriptor = {"name": server.name, "transport": server.transport}
        if server.command is not None:
            descriptor["command"] = list(server.command)
        if server.url is not None:
            descriptor["url"] = server.url
        if server.env is not None:
            descriptor["env"] = dict(server.env)
        return descriptor

    def _collect_proxy_events(self) -> None:
        for path_str, (path, offset) in list(self._proxy_event_files.items()):
            if not path.exists():
                continue
            try:
                with path.open("r", encoding="utf-8") as handle:
                    handle.seek(offset)
                    lines = handle.readlines()
                    offset = handle.tell()
            except OSError:  # pragma: no cover - transient IO
                continue
            self._proxy_event_files[path_str] = (path, offset)
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event_name = payload.get("event")
                if not isinstance(event_name, str):
                    continue
                event_payload = payload.get("payload", {})
                meta = payload.get("meta", {})
                self._event_buffer.emit(event_name, event_payload, meta)

    def _wrap_stdio_server(self, server: MCPServerDefinition) -> dict[str, Any]:
        descriptor = self._base_descriptor(server)
        proxy_env = dict(server.env or {})
        event_file = self._context.working_dir / f"mcp-events-{server.name}.log"
        proxy_env["KHAOS_MCP_EVENT_FILE"] = str(event_file)
        proxy_env["KHAOS_MCP_PROXY_SERVER"] = json.dumps(
            {
                "name": server.name,
                "command": server.command,
                "env": server.env or {},
                "faults": self._fault_rules_raw,
                "seed": self._fault_seed,
                "server_name": server.name,
            }
        )
        descriptor["command"] = [sys.executable, "-m", "khaos.mcp.stdio_proxy"]
        descriptor["env"] = proxy_env
        descriptor["proxy"] = {"kind": "stdio"}
        self._proxy_event_files[str(event_file)] = (event_file, 0)
        descriptor["tools"] = self._load_stdio_tools(server)
        return descriptor

    def _wrap_http_server(self, server: MCPServerDefinition) -> dict[str, Any]:
        proxy = MCPHTTPProxy(
            server_name=server.name,
            target_url=server.url or "",
            faults=self._fault_rules_raw,
            seed=self._fault_seed,
            event_callback=self._event_buffer.emit,
        )
        proxy.start()
        self._http_proxies.append(proxy)
        descriptor = self._base_descriptor(server)
        descriptor["url"] = proxy.url
        descriptor["proxy"] = {"kind": "http", "target_url": server.url}
        descriptor["tools"] = self._load_http_tools(server)
        return descriptor

    def _load_stdio_tools(self, server: MCPServerDefinition) -> list[dict[str, Any]]:
        if not server.command:
            return []
        try:
            return load_tools_via_stdio(server.command, server.env or {})
        except Exception:
            logger.debug("Failed to load tools via stdio for %s", server.name, exc_info=True)
            return []

    def _load_http_tools(self, server: MCPServerDefinition) -> list[dict[str, Any]]:
        if not server.url:
            return []
        try:
            return load_tools_via_http(server.url)
        except Exception:
            logger.debug("Failed to load tools via HTTP for %s", server.name, exc_info=True)
            return []

def _normalize_server(entry: Any) -> MCPServerDefinition:
    if isinstance(entry, str):
        return MCPServerDefinition(name=entry)
    if not isinstance(entry, dict):
        raise ValueError("Each MCP server definition must be a string or object.")
    if "name" not in entry:
        raise ValueError("MCP server definition requires a 'name' field.")
    name = str(entry["name"])
    transport_kind = str(entry.get("transport", "stdio")).lower()
    command_value = entry.get("command")
    command = None
    if isinstance(command_value, str):
        command = shlex.split(command_value)
    elif isinstance(command_value, (list, tuple)):
        command = [str(part) for part in command_value]
    url = entry.get("url")
    env = entry.get("env") if isinstance(entry.get("env"), dict) else None
    return MCPServerDefinition(
        name=name,
        transport=transport_kind,
        command=command,
        url=url,
        env=env,
    )

def _slug(value: str) -> str:
    sanitized = [ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in value]
    slug = "".join(sanitized).strip("-")
    return slug or "agent"

def build_mcp_stdio_transport(
    context: TransportContext, options: dict[str, Any] | None = None
) -> MCPStdIOTransport:
    return _build_mcp_transport(context, options, MCPStdIOTransport)

class MCPHTTPTransport(MCPStdIOTransport):
    """HTTP transport wrapper (reuses stdio plumbing for now)."""

def build_mcp_http_transport(
    context: TransportContext, options: dict[str, Any] | None = None
) -> MCPHTTPTransport:
    return _build_mcp_transport(context, options, MCPHTTPTransport)

TTransport = TypeVar("TTransport", bound=MCPStdIOTransport)

def _build_mcp_transport(
    context: TransportContext,
    options: dict[str, Any] | None,
    transport_cls: type[TTransport],
) -> TTransport:
    opts = options or {}
    servers_raw = opts.get("servers", [])
    if isinstance(servers_raw, dict):
        servers_raw = [servers_raw]
    servers = [_normalize_server(entry) for entry in servers_raw]
    agent_options = opts.get("agent", {})
    agent_transport = build_subprocess_transport(context, agent_options)
    return transport_cls(context, agent_transport, servers, opts)
