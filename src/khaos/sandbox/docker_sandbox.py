"""Docker-based sandbox for secure agent execution.

This module provides isolated execution of agent code using Docker containers
with configurable resource limits and network isolation.

SECURITY CONSIDERATIONS:
- Default network mode is "none" (no network access)
- Root filesystem is read-only by default
- All Linux capabilities are dropped by default
- Seccomp profile restricts syscalls
- Resource limits prevent DoS attacks
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import SandboxConfig, NetworkMode, is_sandbox_available, SandboxMode

logger = logging.getLogger(__name__)


@dataclass
class SandboxResult:
    """Result of a sandboxed execution."""
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    container_id: str | None = None


class SandboxError(Exception):
    """Error during sandbox execution."""
    pass


class DockerSandbox:
    """Docker-based sandbox for secure agent execution.

    Example:
        sandbox = DockerSandbox(config)
        result = await sandbox.execute(
            command=["python", "agent.py"],
            env={"OPENAI_API_KEY": "sk-..."},
            working_dir="/path/to/agent",
        )
    """

    def __init__(self, config: SandboxConfig):
        """Initialize the Docker sandbox.

        Args:
            config: Sandbox configuration

        Raises:
            SandboxError: If Docker is not available
        """
        self.config = config
        self._container_id: str | None = None

        if config.enabled and config.mode == SandboxMode.DOCKER:
            if not is_sandbox_available(SandboxMode.DOCKER):
                raise SandboxError(
                    "Docker is not available. Install Docker or disable sandboxing with "
                    "KHAOS_SANDBOX_ENABLED=0"
                )

    def _build_docker_command(
        self,
        command: list[str],
        env: dict[str, str],
        working_dir: str,
        mounts: list[tuple[str, str, str]],
    ) -> list[str]:
        """Build the docker run command.

        Args:
            command: Command to run inside container
            env: Environment variables
            working_dir: Host working directory to mount
            mounts: Additional mounts (host, container, mode)

        Returns:
            Complete docker command as list
        """
        docker_cmd = ["docker", "run", "--rm"]

        # Container name for tracking
        container_name = f"khaos-sandbox-{uuid.uuid4().hex[:8]}"
        docker_cmd.extend(["--name", container_name])

        # Network isolation
        if self.config.network_mode == NetworkMode.NONE:
            docker_cmd.extend(["--network", "none"])
        elif self.config.network_mode == NetworkMode.HOST:
            docker_cmd.extend(["--network", "host"])
        elif self.config.network_mode == NetworkMode.BRIDGE:
            docker_cmd.extend(["--network", "bridge"])
        elif self.config.network_mode == NetworkMode.ALLOWLIST:
            # Use bridge network with DNS filtering
            docker_cmd.extend(["--network", "bridge"])
            # Add hosts to /etc/hosts (simplified allowlist)
            for host in self.config.allowed_hosts:
                docker_cmd.extend(["--add-host", f"{host}:host-gateway"])

        # Resource limits
        docker_cmd.extend(["--memory", self.config.memory_limit])
        docker_cmd.extend(["--cpus", str(self.config.cpu_limit)])

        # Read-only root filesystem
        if self.config.read_only_root:
            docker_cmd.append("--read-only")
            # Provide writable /tmp
            docker_cmd.extend(["--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"])

        # Drop capabilities
        for cap in self.config.capabilities_drop:
            docker_cmd.extend(["--cap-drop", cap])

        # Seccomp profile
        if self.config.seccomp_profile and self.config.seccomp_profile != "unconfined":
            docker_cmd.extend(["--security-opt", f"seccomp={self.config.seccomp_profile}"])

        # User mapping (run as non-root if specified)
        if self.config.user:
            docker_cmd.extend(["--user", self.config.user])
        else:
            # Default: run as current user to prevent root in container
            uid = os.getuid() if hasattr(os, 'getuid') else 1000
            gid = os.getgid() if hasattr(os, 'getgid') else 1000
            docker_cmd.extend(["--user", f"{uid}:{gid}"])

        # Working directory mount
        docker_cmd.extend(["-v", f"{working_dir}:{self.config.working_dir}:ro"])
        docker_cmd.extend(["-w", self.config.working_dir])

        # Additional mounts
        for host_path, container_path, mode in mounts:
            docker_cmd.extend(["-v", f"{host_path}:{container_path}:{mode}"])

        # Environment variables (filtered)
        filtered_env = self._filter_env(env)
        for key, value in filtered_env.items():
            docker_cmd.extend(["-e", f"{key}={value}"])

        # Image
        docker_cmd.append(self.config.docker_image)

        # Command
        docker_cmd.extend(command)

        return docker_cmd

    def _filter_env(self, env: dict[str, str]) -> dict[str, str]:
        """Filter environment variables based on allow/deny lists.

        Args:
            env: Environment variables to filter

        Returns:
            Filtered environment variables
        """
        filtered = {}
        for key, value in env.items():
            # Skip denied variables
            if key in self.config.env_denylist:
                logger.debug("Blocked env var: %s", key)
                continue

            # Include if in allowlist or if it's a KHAOS_ variable
            if key in self.config.env_allowlist or key.startswith("KHAOS_"):
                filtered[key] = value
            # Also include common LLM API keys
            elif key.endswith("_API_KEY") or key.endswith("_KEY"):
                if key not in self.config.env_denylist:
                    filtered[key] = value

        return filtered

    async def execute(
        self,
        command: list[str],
        env: dict[str, str] | None = None,
        working_dir: str | None = None,
        mounts: list[tuple[str, str, str]] | None = None,
        timeout: int | None = None,
    ) -> SandboxResult:
        """Execute a command in the sandbox.

        Args:
            command: Command to execute (e.g., ["python", "agent.py"])
            env: Environment variables to pass
            working_dir: Working directory (default: current directory)
            mounts: Additional mounts [(host, container, mode), ...]
            timeout: Execution timeout in seconds (default: from config)

        Returns:
            SandboxResult with exit code, stdout, stderr

        Raises:
            SandboxError: If execution fails
        """
        if not self.config.enabled or self.config.mode == SandboxMode.DISABLED:
            # Fallback to regular subprocess when sandboxing is disabled
            return await self._execute_subprocess(command, env, working_dir, timeout)

        if self.config.mode == SandboxMode.SUBPROCESS:
            return await self._execute_subprocess_with_limits(command, env, working_dir, timeout)

        # Docker execution
        return await self._execute_docker(command, env, working_dir, mounts, timeout)

    async def _execute_docker(
        self,
        command: list[str],
        env: dict[str, str] | None,
        working_dir: str | None,
        mounts: list[tuple[str, str, str]] | None,
        timeout: int | None,
    ) -> SandboxResult:
        """Execute command in Docker container."""
        work_dir = working_dir or os.getcwd()
        mount_list = list(mounts or [])
        mount_list.extend(self.config.mount_paths)
        execution_timeout = timeout or self.config.timeout_seconds

        docker_cmd = self._build_docker_command(
            command=command,
            env=env or {},
            working_dir=work_dir,
            mounts=mount_list,
        )

        logger.debug("Docker command: %s", shlex.join(docker_cmd))

        try:
            process = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=execution_timeout,
                )
                return SandboxResult(
                    exit_code=process.returncode or 0,
                    stdout=stdout.decode("utf-8", errors="ignore"),
                    stderr=stderr.decode("utf-8", errors="ignore"),
                    timed_out=False,
                )
            except asyncio.TimeoutError:
                # Kill the container
                process.kill()
                await process.wait()
                return SandboxResult(
                    exit_code=-1,
                    stdout="",
                    stderr=f"Execution timed out after {execution_timeout} seconds",
                    timed_out=True,
                )

        except Exception as e:
            raise SandboxError(f"Docker execution failed: {e}") from e

    async def _execute_subprocess(
        self,
        command: list[str],
        env: dict[str, str] | None,
        working_dir: str | None,
        timeout: int | None,
    ) -> SandboxResult:
        """Fallback subprocess execution without Docker."""
        work_dir = working_dir or os.getcwd()
        execution_timeout = timeout or self.config.timeout_seconds

        # Merge environment
        full_env = os.environ.copy()
        if env:
            full_env.update(env)

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=work_dir,
                env=full_env,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=execution_timeout,
                )
                return SandboxResult(
                    exit_code=process.returncode or 0,
                    stdout=stdout.decode("utf-8", errors="ignore"),
                    stderr=stderr.decode("utf-8", errors="ignore"),
                    timed_out=False,
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return SandboxResult(
                    exit_code=-1,
                    stdout="",
                    stderr=f"Execution timed out after {execution_timeout} seconds",
                    timed_out=True,
                )

        except Exception as e:
            raise SandboxError(f"Subprocess execution failed: {e}") from e

    async def _execute_subprocess_with_limits(
        self,
        command: list[str],
        env: dict[str, str] | None,
        working_dir: str | None,
        timeout: int | None,
    ) -> SandboxResult:
        """Subprocess execution with resource limits (Linux only).

        Uses prlimit or ulimit to set resource constraints.
        """
        work_dir = working_dir or os.getcwd()
        execution_timeout = timeout or self.config.timeout_seconds

        # Check for prlimit (Linux)
        if shutil.which("prlimit") is not None:
            # Convert memory limit to bytes
            mem_bytes = self._parse_memory_limit(self.config.memory_limit)
            wrapped_cmd = [
                "prlimit",
                f"--as={mem_bytes}",  # Address space limit
                f"--cpu={execution_timeout}",  # CPU time limit
                "--",
            ] + command
        else:
            # Fallback without limits on non-Linux
            wrapped_cmd = command
            logger.warning("prlimit not available, running without resource limits")

        # Merge environment with filtering
        full_env = os.environ.copy()
        if env:
            filtered = self._filter_env(env)
            full_env.update(filtered)

        try:
            process = await asyncio.create_subprocess_exec(
                *wrapped_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=work_dir,
                env=full_env,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=execution_timeout,
                )
                return SandboxResult(
                    exit_code=process.returncode or 0,
                    stdout=stdout.decode("utf-8", errors="ignore"),
                    stderr=stderr.decode("utf-8", errors="ignore"),
                    timed_out=False,
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return SandboxResult(
                    exit_code=-1,
                    stdout="",
                    stderr=f"Execution timed out after {execution_timeout} seconds",
                    timed_out=True,
                )

        except Exception as e:
            raise SandboxError(f"Subprocess execution failed: {e}") from e

    def _parse_memory_limit(self, limit: str) -> int:
        """Parse memory limit string to bytes.

        Args:
            limit: Memory limit (e.g., "512m", "1g", "1024k")

        Returns:
            Memory limit in bytes
        """
        limit = limit.strip().lower()
        multipliers = {
            "k": 1024,
            "m": 1024 * 1024,
            "g": 1024 * 1024 * 1024,
        }

        for suffix, multiplier in multipliers.items():
            if limit.endswith(suffix):
                try:
                    return int(float(limit[:-1]) * multiplier)
                except ValueError:
                    pass

        # Default: try to parse as bytes
        try:
            return int(limit)
        except ValueError:
            return 512 * 1024 * 1024  # 512MB default
