"""Sandbox configuration and detection utilities."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from enum import Enum


class SandboxMode(Enum):
    """Sandbox execution mode."""
    DISABLED = "disabled"    # No sandboxing (default)
    DOCKER = "docker"        # Docker container isolation
    SUBPROCESS = "subprocess"  # Subprocess with resource limits only


class NetworkMode(Enum):
    """Network isolation mode."""
    NONE = "none"            # No network access (most secure)
    HOST = "host"            # Host network (least secure)
    BRIDGE = "bridge"        # Docker bridge (default)
    ALLOWLIST = "allowlist"  # Only allow specific hosts


@dataclass
class SandboxConfig:
    """Configuration for sandbox execution.

    Attributes:
        enabled: Whether sandboxing is enabled
        mode: Sandbox mode (docker, subprocess, or disabled)
        network_mode: Network isolation level
        memory_limit: Memory limit (e.g., "512m", "1g")
        cpu_limit: CPU limit (e.g., 1.0 = 1 core, 0.5 = half core)
        timeout_seconds: Maximum execution time
        read_only_root: Mount root filesystem as read-only
        working_dir: Working directory inside sandbox
        mount_paths: List of (host_path, container_path, mode) tuples
        env_allowlist: Environment variables to pass through
        env_denylist: Environment variables to block
        allowed_hosts: Hosts to allow when network_mode is ALLOWLIST
        docker_image: Docker image to use (default: python:3.11-slim)
        user: User to run as inside container (e.g., "1000:1000")
        capabilities_drop: Linux capabilities to drop
        seccomp_profile: Path to seccomp profile (or "default")
    """

    enabled: bool = False
    mode: SandboxMode = SandboxMode.DISABLED
    network_mode: NetworkMode = NetworkMode.NONE
    memory_limit: str = "512m"
    cpu_limit: float = 1.0
    timeout_seconds: int = 300
    read_only_root: bool = True
    working_dir: str = "/workspace"
    mount_paths: list[tuple[str, str, str]] = field(default_factory=list)
    env_allowlist: set[str] = field(default_factory=lambda: {
        "PATH", "PYTHONPATH", "HOME", "USER", "LANG", "LC_ALL",
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
        "KHAOS_RUN_ID", "KHAOS_SCENARIO_ID", "KHAOS_LLM_EVENT_FILE",
    })
    env_denylist: set[str] = field(default_factory=lambda: {
        "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "NPM_TOKEN",
        "DATABASE_URL", "REDIS_URL", "SSH_AUTH_SOCK",
    })
    allowed_hosts: list[str] = field(default_factory=lambda: [
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
    ])
    docker_image: str = "python:3.11-slim"
    user: str | None = None  # Run as current user if None
    capabilities_drop: list[str] = field(default_factory=lambda: [
        "ALL"  # Drop all capabilities by default
    ])
    seccomp_profile: str = "default"


def _is_docker_available() -> bool:
    """Check if Docker is available and running."""
    if shutil.which("docker") is None:
        return False

    # Try a simple docker command
    import subprocess
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def is_sandbox_available(mode: SandboxMode = SandboxMode.DOCKER) -> bool:
    """Check if the specified sandbox mode is available.

    Args:
        mode: The sandbox mode to check

    Returns:
        True if the sandbox mode is available
    """
    if mode == SandboxMode.DISABLED:
        return True
    if mode == SandboxMode.DOCKER:
        return _is_docker_available()
    if mode == SandboxMode.SUBPROCESS:
        return True  # Always available
    return False


def get_default_config() -> SandboxConfig:
    """Get the default sandbox configuration from environment.

    Environment variables:
        KHAOS_SANDBOX_ENABLED: Enable sandbox (1, true, yes)
        KHAOS_SANDBOX_MODE: Sandbox mode (docker, subprocess)
        KHAOS_SANDBOX_NETWORK: Network mode (none, host, bridge, allowlist)
        KHAOS_SANDBOX_MEMORY: Memory limit (e.g., 512m, 1g)
        KHAOS_SANDBOX_CPU: CPU limit (e.g., 1.0, 0.5)
        KHAOS_SANDBOX_TIMEOUT: Timeout in seconds
        KHAOS_SANDBOX_IMAGE: Docker image
    """
    config = SandboxConfig()

    # Check if enabled
    enabled_str = os.getenv("KHAOS_SANDBOX_ENABLED", "").strip().lower()
    config.enabled = enabled_str in ("1", "true", "yes", "on")

    # Mode
    mode_str = os.getenv("KHAOS_SANDBOX_MODE", "docker").strip().lower()
    try:
        config.mode = SandboxMode(mode_str)
    except ValueError:
        config.mode = SandboxMode.DOCKER if config.enabled else SandboxMode.DISABLED

    # Network mode
    network_str = os.getenv("KHAOS_SANDBOX_NETWORK", "none").strip().lower()
    try:
        config.network_mode = NetworkMode(network_str)
    except ValueError:
        config.network_mode = NetworkMode.NONE

    # Resource limits
    memory = os.getenv("KHAOS_SANDBOX_MEMORY", "").strip()
    if memory:
        config.memory_limit = memory

    cpu_str = os.getenv("KHAOS_SANDBOX_CPU", "").strip()
    if cpu_str:
        try:
            config.cpu_limit = float(cpu_str)
        except ValueError:
            pass

    timeout_str = os.getenv("KHAOS_SANDBOX_TIMEOUT", "").strip()
    if timeout_str:
        try:
            config.timeout_seconds = int(timeout_str)
        except ValueError:
            pass

    # Docker image
    image = os.getenv("KHAOS_SANDBOX_IMAGE", "").strip()
    if image:
        config.docker_image = image

    return config
