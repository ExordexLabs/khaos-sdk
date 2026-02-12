"""Transport abstractions and adapters for the Khaos runtime."""

from .base import (
    AgentTransport,
    TransportError,
    TransportExit,
    TransportMessage,
    TransportProtocolError,
    TransportTimeout,
    TransportEvent,
)
from .inproc import InProcessTransport, build_inproc_transport, wrap_sync_handler
from .mcp import (
    MCPHTTPTransport,
    MCPStdIOTransport,
    build_mcp_http_transport,
    build_mcp_stdio_transport,
)
from .registry import (
    TransportContext,
    TransportRegistry,
    create_transport,
    get_transport_registry,
    register_transport,
)
from .subprocess import SubprocessConfig, SubprocessTransport, build_subprocess_transport

# Register default transports
register_transport("subprocess", build_subprocess_transport)
register_transport("inproc", build_inproc_transport)
register_transport("mcp-stdio", build_mcp_stdio_transport)
register_transport("mcp-http", build_mcp_http_transport)

__all__ = [
    "AgentTransport",
    "TransportError",
    "TransportTimeout",
    "TransportProtocolError",
    "TransportExit",
    "TransportMessage",
    "TransportEvent",
    "InProcessTransport",
    "wrap_sync_handler",
    "SubprocessConfig",
    "SubprocessTransport",
    "MCPStdIOTransport",
    "MCPHTTPTransport",
    "TransportContext",
    "TransportRegistry",
    "create_transport",
    "get_transport_registry",
    "register_transport",
]
