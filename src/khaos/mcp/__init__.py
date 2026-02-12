"""MCP integration layer for Khaos."""

from .service import MCPServiceDescriptor, build_mcp_routes

# re-export configuration helpers lazily to avoid circular imports while
# keeping backwards compatibility for ``from khaos.mcp import config``.

def _load_config_module():
    import importlib

    return importlib.import_module("khaos.mcp.config")


config = _load_config_module()

__all__ = ["MCPServiceDescriptor", "build_mcp_routes", "config"]
