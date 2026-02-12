"""Agent execution sandboxing for enhanced security.

SECURITY FIX: Provides optional isolation for untrusted agent code.

Supports:
- Docker-based isolation (recommended for production)
- Network isolation (block outbound except allowlisted hosts)
- Resource limits (CPU, memory, disk)
- Filesystem isolation (read-only mounts, tmpfs)

Usage:
    from khaos.sandbox import SandboxConfig, DockerSandbox

    # Configure sandbox
    config = SandboxConfig(
        enabled=True,
        network_mode="none",  # No network access
        memory_limit="512m",
        cpu_limit=1.0,
    )

    # Run agent in sandbox
    sandbox = DockerSandbox(config)
    result = await sandbox.execute(command, env=env)
"""

from .config import (
    SandboxConfig,
    SandboxMode,
    NetworkMode,
    get_default_config,
    is_sandbox_available,
)
from .docker_sandbox import DockerSandbox

__all__ = [
    "SandboxConfig",
    "SandboxMode",
    "NetworkMode",
    "DockerSandbox",
    "get_default_config",
    "is_sandbox_available",
]
