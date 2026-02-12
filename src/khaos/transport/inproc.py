"""In-process transport adapters for testing and synchronous agents."""

from __future__ import annotations

import asyncio
from typing import Any, TYPE_CHECKING
from collections.abc import Awaitable, Callable

from .base import AgentTransport, TransportMessage, TransportProtocolError, TransportTimeout

if TYPE_CHECKING:  # pragma: no cover - typing helper
    from .registry import TransportContext

AsyncMessageHandler = Callable[[TransportMessage], Awaitable[TransportMessage]]

class InProcessTransport(AgentTransport):
    """Adapter that routes messages to an in-process async handler."""

    def __init__(
        self,
        handler: AsyncMessageHandler,
        *,
        agent_id: str = "inproc",
    ) -> None:
        self._handler = handler
        self._responses: asyncio.Queue[TransportMessage | Exception] = asyncio.Queue()
        self._closed = False
        self._tasks: set[asyncio.Task[None]] = set()
        self.agent_id = agent_id

    async def send(self, message: TransportMessage) -> None:
        if self._closed:
            raise RuntimeError("Transport already closed")
        task = asyncio.create_task(self._handle(message))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def receive(self, timeout: float | None = None) -> TransportMessage:
        if self._closed:
            raise RuntimeError("Transport already closed")
        try:
            if timeout is not None:
                item = await asyncio.wait_for(self._responses.get(), timeout)
            else:
                item = await self._responses.get()
        except asyncio.TimeoutError as exc:  # pragma: no cover - simple mapping
            raise TransportTimeout("Timed out waiting for transport response") from exc

        if isinstance(item, Exception):
            if isinstance(item, TransportTimeout):
                raise item
            raise TransportProtocolError("In-process handler failed") from item
        return item

    async def close(self) -> None:
        self._closed = True
        for task in list(self._tasks):
            task.cancel()
        while not self._responses.empty():
            self._responses.get_nowait()

    async def _handle(self, message: TransportMessage) -> None:
        try:
            response = await self._handler(message)
        except Exception as exc:  # pragma: no cover - error propagation path
            await self._responses.put(exc)
            return
        await self._responses.put(response)

def wrap_sync_handler(handler: Callable[[TransportMessage], TransportMessage]) -> AsyncMessageHandler:
    """Wrap a synchronous handler so it can be used with the async transport."""

    async def _async_adapter(message: TransportMessage) -> TransportMessage:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, handler, message)

    return _async_adapter

def build_inproc_transport(
    context: "TransportContext", options: dict[str, Any] | None = None
) -> AgentTransport:
    """Factory registered with the transport registry.

    Requires a handler to be supplied in options; primarily useful for tests or
    bespoke embeddings. The CLI does not expose this transport directly yet.
    """

    opts = options or {}
    handler = opts.get("handler")
    if handler is None:
        raise ValueError("In-process transport requires a 'handler' callable")
    agent_id = str(opts.get("agent_id", "inproc"))
    return InProcessTransport(handler, agent_id=agent_id)
