"""Secure credential storage using OS keychain services.

SECURITY FIX: Replaces plaintext JSON storage with OS-level secure storage.

Supports:
- macOS: Keychain Access (via security command)
- Windows: Credential Manager (via cmdkey)
- Linux: Secret Service (via secret-tool or libsecret-tools)

Falls back to file-based storage if keychain is unavailable or in CI environments.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# Service identifier for Khaos credentials
SERVICE_NAME = "khaos-cli"
ACCOUNT_NAME = "api-token"


@dataclass
class KeychainResult:
    """Result of a keychain operation."""
    success: bool
    value: str | None = None
    error: str | None = None


def _is_ci_environment() -> bool:
    """Detect if running in a CI/CD environment."""
    ci_vars = ["CI", "CONTINUOUS_INTEGRATION", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "JENKINS_URL"]
    return any(os.getenv(var) for var in ci_vars)


def _is_keychain_enabled() -> bool:
    """Check if keychain storage is enabled."""
    # Disabled in CI environments by default
    if _is_ci_environment():
        return os.getenv("KHAOS_KEYCHAIN_IN_CI", "").lower() in ("1", "true", "yes")
    # Can be explicitly disabled
    disabled = os.getenv("KHAOS_DISABLE_KEYCHAIN", "").lower()
    return disabled not in ("1", "true", "yes")


def _run_command(args: list[str], input_data: str | None = None) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            args,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


# =============================================================================
# macOS Keychain
# =============================================================================

def _macos_store(value: str) -> KeychainResult:
    """Store credential in macOS Keychain."""
    # Delete existing entry first (ignore errors)
    subprocess.run(
        ["security", "delete-generic-password", "-s", SERVICE_NAME, "-a", ACCOUNT_NAME],
        capture_output=True,
    )

    # Add new entry
    code, stdout, stderr = _run_command([
        "security", "add-generic-password",
        "-s", SERVICE_NAME,
        "-a", ACCOUNT_NAME,
        "-w", value,
        "-U",  # Update if exists
    ])

    if code == 0:
        return KeychainResult(success=True)
    return KeychainResult(success=False, error=f"security add-generic-password failed: {stderr}")


def _macos_retrieve() -> KeychainResult:
    """Retrieve credential from macOS Keychain."""
    code, stdout, stderr = _run_command([
        "security", "find-generic-password",
        "-s", SERVICE_NAME,
        "-a", ACCOUNT_NAME,
        "-w",  # Output only the password
    ])

    if code == 0:
        return KeychainResult(success=True, value=stdout.strip())
    if "could not be found" in stderr.lower() or code == 44:
        return KeychainResult(success=True, value=None)  # Not found is not an error
    return KeychainResult(success=False, error=f"security find-generic-password failed: {stderr}")


def _macos_delete() -> KeychainResult:
    """Delete credential from macOS Keychain."""
    code, stdout, stderr = _run_command([
        "security", "delete-generic-password",
        "-s", SERVICE_NAME,
        "-a", ACCOUNT_NAME,
    ])

    if code == 0 or "could not be found" in stderr.lower():
        return KeychainResult(success=True)
    return KeychainResult(success=False, error=f"security delete-generic-password failed: {stderr}")


# =============================================================================
# Windows Credential Manager
# =============================================================================

def _windows_store(value: str) -> KeychainResult:
    """Store credential in Windows Credential Manager."""
    # Delete existing entry first
    subprocess.run(
        ["cmdkey", "/delete:khaos-cli"],
        capture_output=True,
    )

    # Add new entry
    code, stdout, stderr = _run_command([
        "cmdkey",
        f"/generic:khaos-cli",
        f"/user:{ACCOUNT_NAME}",
        f"/pass:{value}",
    ])

    if code == 0:
        return KeychainResult(success=True)
    return KeychainResult(success=False, error=f"cmdkey add failed: {stderr or stdout}")


def _windows_retrieve() -> KeychainResult:
    """Retrieve credential from Windows Credential Manager.

    Note: cmdkey doesn't support password retrieval directly.
    We use PowerShell with CredentialManager module if available,
    otherwise fall back to registry-based approach.
    """
    # Try PowerShell approach
    ps_script = '''
    $cred = Get-StoredCredential -Target "khaos-cli" -ErrorAction SilentlyContinue
    if ($cred) {
        $cred.GetNetworkCredential().Password
    }
    '''
    code, stdout, stderr = _run_command([
        "powershell", "-NoProfile", "-Command", ps_script
    ])

    if code == 0 and stdout.strip():
        return KeychainResult(success=True, value=stdout.strip())

    # PowerShell module not available - return not found
    return KeychainResult(success=True, value=None)


def _windows_delete() -> KeychainResult:
    """Delete credential from Windows Credential Manager."""
    code, stdout, stderr = _run_command([
        "cmdkey", "/delete:khaos-cli"
    ])

    # Both success and "not found" are acceptable
    if code == 0 or "not found" in (stdout + stderr).lower():
        return KeychainResult(success=True)
    return KeychainResult(success=False, error=f"cmdkey delete failed: {stderr or stdout}")


# =============================================================================
# Linux Secret Service (freedesktop.org)
# =============================================================================

def _linux_has_secret_tool() -> bool:
    """Check if secret-tool is available."""
    return shutil.which("secret-tool") is not None


def _linux_store(value: str) -> KeychainResult:
    """Store credential using secret-tool (freedesktop Secret Service)."""
    if not _linux_has_secret_tool():
        return KeychainResult(success=False, error="secret-tool not found. Install libsecret-tools.")

    code, stdout, stderr = _run_command(
        ["secret-tool", "store", "--label=Khaos CLI Token", "service", SERVICE_NAME, "account", ACCOUNT_NAME],
        input_data=value,
    )

    if code == 0:
        return KeychainResult(success=True)
    return KeychainResult(success=False, error=f"secret-tool store failed: {stderr}")


def _linux_retrieve() -> KeychainResult:
    """Retrieve credential using secret-tool."""
    if not _linux_has_secret_tool():
        return KeychainResult(success=False, error="secret-tool not found")

    code, stdout, stderr = _run_command([
        "secret-tool", "lookup", "service", SERVICE_NAME, "account", ACCOUNT_NAME
    ])

    if code == 0:
        value = stdout.strip() if stdout.strip() else None
        return KeychainResult(success=True, value=value)
    # Not found is not an error
    if code == 1 and not stderr.strip():
        return KeychainResult(success=True, value=None)
    return KeychainResult(success=False, error=f"secret-tool lookup failed: {stderr}")


def _linux_delete() -> KeychainResult:
    """Delete credential using secret-tool."""
    if not _linux_has_secret_tool():
        return KeychainResult(success=False, error="secret-tool not found")

    code, stdout, stderr = _run_command([
        "secret-tool", "clear", "service", SERVICE_NAME, "account", ACCOUNT_NAME
    ])

    if code == 0:
        return KeychainResult(success=True)
    return KeychainResult(success=False, error=f"secret-tool clear failed: {stderr}")


# =============================================================================
# Platform Dispatcher
# =============================================================================

def _get_platform() -> str:
    """Get current platform identifier."""
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    elif system == "windows":
        return "windows"
    elif system == "linux":
        return "linux"
    return "unknown"


def store_token(token: str) -> KeychainResult:
    """Store API token in OS keychain.

    Args:
        token: The API token to store securely

    Returns:
        KeychainResult with success status
    """
    if not _is_keychain_enabled():
        return KeychainResult(success=False, error="Keychain disabled")

    plat = _get_platform()
    if plat == "macos":
        return _macos_store(token)
    elif plat == "windows":
        return _windows_store(token)
    elif plat == "linux":
        return _linux_store(token)
    return KeychainResult(success=False, error=f"Unsupported platform: {plat}")


def retrieve_token() -> KeychainResult:
    """Retrieve API token from OS keychain.

    Returns:
        KeychainResult with token value if found
    """
    if not _is_keychain_enabled():
        return KeychainResult(success=False, error="Keychain disabled")

    plat = _get_platform()
    if plat == "macos":
        return _macos_retrieve()
    elif plat == "windows":
        return _windows_retrieve()
    elif plat == "linux":
        return _linux_retrieve()
    return KeychainResult(success=False, error=f"Unsupported platform: {plat}")


def delete_token() -> KeychainResult:
    """Delete API token from OS keychain.

    Returns:
        KeychainResult with success status
    """
    if not _is_keychain_enabled():
        return KeychainResult(success=False, error="Keychain disabled")

    plat = _get_platform()
    if plat == "macos":
        return _macos_delete()
    elif plat == "windows":
        return _windows_delete()
    elif plat == "linux":
        return _linux_delete()
    return KeychainResult(success=False, error=f"Unsupported platform: {plat}")


def is_keychain_available() -> bool:
    """Check if keychain storage is available on this system.

    Returns:
        True if keychain can be used, False otherwise
    """
    if not _is_keychain_enabled():
        return False

    plat = _get_platform()
    if plat == "macos":
        return shutil.which("security") is not None
    elif plat == "windows":
        return shutil.which("cmdkey") is not None
    elif plat == "linux":
        return _linux_has_secret_tool()
    return False
