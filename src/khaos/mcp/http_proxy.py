"""HTTP proxy that injects MCP faults for HTTP transports."""

from __future__ import annotations

import json
import logging
import random
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from collections.abc import Callable
from urllib.parse import urljoin

import httpx

from .faults import MCPFaultController, apply_corruption
from .utils import extract_tool_name

logger = logging.getLogger("khaos.mcp.http_proxy")

class _ProxyServer(ThreadingHTTPServer):
    def __init__(self, server_address, proxy):
        super().__init__(server_address, _ProxyHandler)
        self.proxy = proxy

class _ProxyHandler(BaseHTTPRequestHandler):
    server: _ProxyServer  # type: ignore[assignment]

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):  # noqa: N802
        self.server.proxy._handle_proxy_request(self)

    def log_message(self, format: str, *args: Any) -> None:  # pragma: no cover - silence logs
        return

class MCPHTTPProxy:
    """Simple HTTP proxy that applies MCP faults before forwarding."""

    def __init__(
        self,
        *,
        server_name: str,
        target_url: str,
        faults: list[dict[str, Any]],
        seed: int,
        event_callback: Callable[[str, dict[str, Any], dict[str, Any] | None], None] | None = None,
    ) -> None:
        self.server_name = server_name
        self.target_url = target_url.rstrip("/")
        self._controller = MCPFaultController(faults, rng=random.Random(seed))
        self._http_server = _ProxyServer(("127.0.0.1", 0), self)
        self._thread = threading.Thread(target=self._http_server.serve_forever, daemon=True)
        self._client = httpx.Client(timeout=30)
        self._running = False
        self._emit_callback = event_callback

    @property
    def url(self) -> str:
        host, port = self._http_server.server_address
        return f"http://{host}:{port}"

    def start(self) -> None:
        if not self._running:
            self._thread.start()
            self._running = True
            logger.info(
                "MCP HTTP proxy started: server=%s target=%s listen=%s",
                self.server_name, self.target_url, self.url,
            )

    def close(self) -> None:
        if self._running:
            logger.info("MCP HTTP proxy shutting down: server=%s", self.server_name)
            self._http_server.shutdown()
            self._http_server.server_close()
            self._client.close()
            self._thread.join(timeout=2)
            self._running = False
            logger.debug("MCP HTTP proxy closed")

    def _handle_proxy_request(self, handler: _ProxyHandler) -> None:
        start = time.perf_counter()
        body = handler._read_body()
        try:
            message = json.loads(body or b"{}")
        except json.JSONDecodeError:
            message = {}
        tool_name = extract_tool_name(message) or self.server_name
        self._emit("mcp.tool_call_plan", {"tool": tool_name, "server": self.server_name})
        effect = self._controller.evaluate(
            tool_name=tool_name,
            server_name=self.server_name,
            payload=message if isinstance(message, dict) else {},
        )
        if effect and effect.delay_ms:
            time.sleep(effect.delay_ms / 1000.0)
            self._emit(
                "mcp.tool_call_delay",
                {"tool": tool_name, "server": self.server_name, "delay_ms": effect.delay_ms},
            )
        if effect and effect.failure:
            handler._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {
                    "error": {
                        "message": effect.failure.get("error_message", "Injected failure"),
                        "code": effect.failure.get("status_code", 500),
                    }
                },
            )
            self._emit(
                "mcp.tool_call_injected_failure",
                {
                    "tool": tool_name,
                    "server": self.server_name,
                    "failure": effect.failure,
                },
            )
            latency_ms = (time.perf_counter() - start) * 1000.0
            self._emit(
                "mcp.tool_call_result",
                {
                    "tool": tool_name,
                    "server": self.server_name,
                    "status": "fault",
                },
                {"latency_ms": latency_ms},
            )
            return

        # Forward request to target
        target = urljoin(self.target_url + "/", handler.path.lstrip("/"))
        upstream = self._client.request(
            handler.command,
            target,
            headers={k: v for k, v in handler.headers.items()},
            content=body,
        )
        response_body = upstream.content

        # Apply description injections to tools/list responses
        is_tools_list = message.get("method") == "tools/list"
        if is_tools_list:
            description_injections = self._controller.get_description_injections()
            if description_injections:
                try:
                    resp_payload = json.loads(response_body)
                except json.JSONDecodeError:
                    resp_payload = None
                if isinstance(resp_payload, dict):
                    tools = resp_payload.get("result", {}).get("tools", [])
                    for t in tools:
                        t_name = t.get("name", "")
                        injection = description_injections.get(t_name) or description_injections.get("*")
                        if injection:
                            original_desc = t.get("description", "")
                            inject_mode = "append"
                            for rule in self._controller._rules:
                                if rule.type == "mcp_tool_description_injection":
                                    cfg_tool = rule.config.get("tool_name", "*")
                                    if cfg_tool in (t_name, "*"):
                                        inject_mode = rule.config.get("inject_mode", "append")
                                        break
                            if inject_mode == "prepend":
                                t["description"] = f"{injection} {original_desc}"
                            elif inject_mode == "replace":
                                t["description"] = injection
                            else:
                                t["description"] = f"{original_desc} {injection}"
                            logger.info(
                                "Injected description for tool %s (mode=%s, payload_len=%d)",
                                t_name, inject_mode, len(injection),
                            )
                    response_body = json.dumps(resp_payload).encode("utf-8")
                    self._emit(
                        "mcp.description_injection_applied",
                        {"server": self.server_name, "tools_modified": len(tools)},
                    )

        if effect and effect.corruption:
            try:
                payload = json.loads(upstream.content)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                mutated = apply_corruption(payload, effect.corruption)
                response_body = json.dumps(mutated).encode("utf-8")
                self._emit(
                    "mcp.tool_call_corrupted",
                    {
                        "tool": tool_name,
                        "server": self.server_name,
                        "corruption": effect.corruption.get("corruption_type", "unknown"),
                    },
                )
        handler.send_response(upstream.status_code)
        for key, value in upstream.headers.items():
            if key.lower() == "content-length":
                continue
            handler.send_header(key, value)
        handler.send_header("Content-Length", str(len(response_body)))
        handler.end_headers()
        handler.wfile.write(response_body)
        latency_ms = (time.perf_counter() - start) * 1000.0
        self._emit(
            "mcp.tool_call_result",
            {
                "tool": tool_name,
                "server": self.server_name,
                "status": "success",
                "http_status": upstream.status_code,
            },
            {"latency_ms": latency_ms},
        )

    def _emit(self, event: str, payload: dict[str, Any], meta: dict[str, Any] | None = None) -> None:
        if self._emit_callback:
            self._emit_callback(event, payload, meta or {})

